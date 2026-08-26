package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/semver"
)

// Crate-source download bounds. A build.rs is a few KB; these caps exist only to
// keep a hostile or corrupt archive from exhausting memory (mirroring the PyPI
// sdist fetcher's discipline).
const (
	maxCrateSize    int64 = 50 * 1024 * 1024 // whole .crate download, buffered once for digest
	maxBuildRSBytes int64 = 2 * 1024 * 1024  // a single extracted build.rs
)

// CrateSourceClient fetches a crate's build.rs from static.crates.io — the same
// public artifact `cargo` downloads — verifying it against the SHA-256 crates.io
// publishes. It exists for the yank-lure enrichment (OPU-26): the introduced
// build-dependency's build.rs is the payload location, and it is not in the
// resolved graph, so its source is fetched on demand for the (rare) flagged deps.
// Reading a build script's TEXT is static analysis, not execution (D-04).
type CrateSourceClient struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// NewCrateSource returns a CrateSourceClient with sensible defaults.
func NewCrateSource(cache *datasource.Cache, offline bool) *CrateSourceClient {
	return &CrateSourceClient{
		HTTP: &http.Client{
			Timeout: 60 * time.Second,
			// The download URL is fixed (static.crates.io); refuse any redirect so a
			// tampered index cannot steer the fetch off-host (mirrors the sdist gate).
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Cache:   cache,
		Offline: offline,
		Now:     time.Now,
	}
}

// Name identifies this source in coverage reports.
func (*CrateSourceClient) Name() string { return "cargo-source" }

// ResolveBuildRS resolves req to a concrete published version of crate name, then
// returns that version's build.rs text (found=false when the crate ships none).
// The selected version is the highest non-yanked version satisfying req, or the
// highest non-yanked version when req cannot be evaluated — never a yanked one,
// which is not what a build would pull.
func (c *CrateSourceClient) ResolveBuildRS(ctx context.Context, name, req string) (buildRS []byte, version string, found bool, err error) {
	version, cksum, ok, err := c.resolveVersion(ctx, name, req)
	if err != nil || !ok {
		return nil, "", false, err
	}
	b, found, err := c.buildRS(ctx, name, version, cksum)
	return b, version, found, err
}

// BuildRSAt returns the build.rs of the EXACT published version given, or
// found=false when that version ships none.
//
// This is deliberately not ResolveBuildRS with the version as its req.
// ResolveBuildRS answers "what would a build pull for this requirement", so it
// skips yanked versions — right for the yank-lure enrichment it was written
// for, wrong for analyzing a LOCKED dependency. A lockfile may legitimately pin
// a version that was yanked afterwards (a stale lock is common), and that
// pinned version is exactly what the build installs and what its build.rs will
// run. Resolving it through the req path would find no satisfying non-yanked
// version and silently return nothing for precisely those crates.
//
// The published SHA-256 is still looked up and verified, so exactness costs no
// integrity checking.
func (c *CrateSourceClient) BuildRSAt(ctx context.Context, name, version string) (buildRS []byte, found bool, err error) {
	cksum, ok, err := c.checksumOf(ctx, name, version)
	if err != nil || !ok {
		return nil, false, err
	}
	return c.buildRS(ctx, name, version, cksum)
}

// checksumOf returns the published SHA-256 for an exact version, yanked or not.
func (c *CrateSourceClient) checksumOf(ctx context.Context, name, version string) (cksum string, ok bool, err error) {
	raw, err := c.getJSON(ctx, "https://crates.io/api/v1/crates/"+url.PathEscape(name)+"/versions", "cargo-source-versions|"+name)
	if err != nil {
		return "", false, err
	}
	var resp crateVersionsResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", false, fmt.Errorf("cargo-source: parsing versions for %s: %w", name, err)
	}
	for _, v := range resp.Versions {
		if v.Num == version && v.Checksum != "" {
			return v.Checksum, true, nil
		}
	}
	return "", false, nil
}

type crateVersionsResp struct {
	Versions []struct {
		Num      string `json:"num"`
		Yanked   bool   `json:"yanked"`
		Checksum string `json:"checksum"`
	} `json:"versions"`
}

// resolveVersion picks the highest non-yanked version of name satisfying req and
// returns it with its SHA-256 checksum.
func (c *CrateSourceClient) resolveVersion(ctx context.Context, name, req string) (version, cksum string, ok bool, err error) {
	raw, err := c.getJSON(ctx, "https://crates.io/api/v1/crates/"+url.PathEscape(name)+"/versions", "cargo-source-versions|"+name)
	if err != nil {
		return "", "", false, err
	}
	var resp crateVersionsResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", "", false, fmt.Errorf("cargo-source: parsing versions for %s: %w", name, err)
	}
	best, bestCk := "", ""
	for _, v := range resp.Versions {
		if v.Yanked || v.Checksum == "" {
			continue
		}
		if sat, evaluable := semver.Satisfies(req, v.Num); req != "" && evaluable && !sat {
			continue
		}
		if best == "" || semver.Parse(best).Compare(semver.Parse(v.Num)) < 0 {
			best, bestCk = v.Num, v.Checksum
		}
	}
	if best == "" {
		return "", "", false, nil
	}
	return best, bestCk, true, nil
}

// buildRS downloads name@version's .crate, verifies it against wantSHA, and
// extracts build.rs. found=false means the crate ships no build.rs (not an error).
func (c *CrateSourceClient) buildRS(ctx context.Context, name, version, wantSHA string) (buildRS []byte, found bool, err error) {
	key := "cargo-source|" + name + "@" + version
	if raw, fresh, ok := c.Cache.GetRaw(key); ok && (fresh || c.Offline) {
		// Cached: an empty payload records "fetched, no build.rs".
		return raw, len(raw) > 0, nil
	}
	if c.Offline {
		return nil, false, fmt.Errorf("cargo-source: %s@%s not in cache (offline)", name, version)
	}
	c.Stats.Queried++

	rawURL := "https://static.crates.io/crates/" + url.PathEscape(name) + "/" + url.PathEscape(name+"-"+version+".crate")
	u, perr := url.Parse(rawURL)
	if perr != nil || u.Scheme != "https" || u.Host != "static.crates.io" {
		c.Stats.Gaps++
		return nil, false, fmt.Errorf("cargo-source: refusing non-allowlisted URL %q", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "depsnort (supply-chain IDS)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.Stats.Gaps++
		return nil, false, fmt.Errorf("cargo-source: %s@%s: %w", name, version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Stats.Gaps++
		return nil, false, fmt.Errorf("cargo-source: %s@%s: HTTP %d", name, version, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCrateSize+1))
	if err != nil {
		c.Stats.Gaps++
		return nil, false, err
	}
	if int64(len(raw)) > maxCrateSize {
		c.Stats.Gaps++
		return nil, false, fmt.Errorf("cargo-source: %s@%s over %d bytes", name, version, maxCrateSize)
	}
	// Integrity is REQUIRED: an absent or wrong digest fails closed.
	sum := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(wantSHA)) {
		c.Stats.Gaps++
		return nil, false, fmt.Errorf("cargo-source: %s@%s checksum mismatch", name, version)
	}

	buildRS, found, err = extractBuildRS(raw)
	if err != nil {
		c.Stats.Gaps++
		return nil, false, err
	}
	c.Stats.FromNet++
	now := c.Now
	if now == nil {
		now = time.Now
	}
	_ = c.Cache.PutRaw(key, buildRS, now()) // empty payload caches "no build.rs"
	return buildRS, found, nil
}

// extractBuildRS gunzips and untars a .crate, returning the top-level build.rs
// (the layout is always <name>-<version>/build.rs). Path traversal is refused,
// and a single file is bounded by maxBuildRSBytes.
func extractBuildRS(rawCrate []byte) (buildRS []byte, found bool, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(rawCrate))
	if err != nil {
		return nil, false, fmt.Errorf("cargo-source: gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("cargo-source: untar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := path.Clean(hdr.Name)
		if strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") {
			continue // refuse absolute or traversing paths
		}
		// Match "<crate-dir>/build.rs" (exactly one directory deep).
		if base := path.Base(clean); base == "build.rs" && strings.Count(clean, "/") == 1 {
			b, err := io.ReadAll(io.LimitReader(tr, maxBuildRSBytes))
			if err != nil {
				return nil, false, err
			}
			return b, true, nil
		}
	}
	return nil, false, nil
}

// getJSON is a small cached GET for the versions metadata.
func (c *CrateSourceClient) getJSON(ctx context.Context, rawURL, cacheKey string) ([]byte, error) {
	key := "cargo-source-meta|" + cacheKey
	if raw, fresh, ok := c.Cache.GetRaw(key); ok && (fresh || c.Offline) {
		return raw, nil
	}
	if c.Offline {
		return nil, fmt.Errorf("cargo-source: %s not in cache (offline)", cacheKey)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "depsnort (supply-chain IDS)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cargo-source: %s: HTTP %d", rawURL, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	_ = c.Cache.PutRaw(key, raw, now())
	return raw, nil
}
