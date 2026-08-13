package pypi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// depsnort intentionally processes attacker-controlled package material, so the
// sdist path must treat every byte as hostile (finding F-05). These bounds cap
// each dimension a malicious or corrupt sdist can abuse. They are vars, not
// consts, purely so hostile-input tests can shrink a threshold and exercise it
// without allocating a real bomb; production never mutates them.
var (
	maxSdistSize     int64 = 50 * 1024 * 1024  // compressed download cap
	maxDecompressed  int64 = 100 * 1024 * 1024 // total DEcompressed bytes across all tar entries (bomb guard)
	maxFileSize      int64 = 2 * 1024 * 1024   // per extracted file
	maxTarEntries          = 20000             // tar entry count cap (entry-flood guard)
	maxPthFiles            = 64                // retained .pth file count cap
	maxPthTotalBytes int64 = 1 * 1024 * 1024   // cumulative retained .pth bytes
)

// Hostile-input failures. Each is a COVERAGE GAP, not a clean result: the caller
// turns a returned error into an install-surface gap so a truncated or abusive
// sdist can never read as "analyzed and clean" (finding F-05 -> F-02).
var (
	ErrSdistCorrupt        = errors.New("sdist tar stream is truncated or corrupt")
	ErrSdistTooLarge       = errors.New("sdist exceeds size limit")
	ErrSdistTooManyEntries = errors.New("sdist tar entry count exceeds limit")
	ErrSdistDigestMismatch = errors.New("sdist sha256 does not match PyPI metadata")
	// ErrSdistNoDigest means the index supplied no usable SHA-256. Verification
	// is not optional: an absent digest previously DISABLED integrity checking
	// silently, which is the weakest possible behavior at exactly the moment the
	// metadata looks wrong (finding R-02).
	ErrSdistNoDigest = errors.New("sdist metadata carries no valid sha256 digest")
	// ErrSdistDisallowedHost means the download URL pointed somewhere other than
	// a PyPI content host. The redirect guard only ever saw redirects; the
	// INITIAL url comes from index metadata and was trusted unchecked (R-02).
	ErrSdistDisallowedHost = errors.New("sdist url host is not a PyPI content host")
	// ErrSdistRetentionExceeded means .pth material was found beyond the
	// retention caps. Silently discarding it produced a clean-looking partial
	// result over content that was never analyzed (R-02).
	ErrSdistRetentionExceeded = errors.New("sdist .pth retention limit exceeded; content unexamined")
)

// sha256Hex matches a syntactically valid lowercase-or-uppercase SHA-256.
var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// countingReader tallies the bytes pulled through it, so the tar loop can bound
// TOTAL decompressed volume even when individual entries are within the per-file
// cap (a thousand 2 MB files is still a bomb).
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// SdistFetcher retrieves and caches source distributions from PyPI.
type SdistFetcher struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
}

// Doer is the minimal HTTP surface; injectable so tests never touch a network.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewSdistFetcher returns a fetcher with sensible defaults.
func NewSdistFetcher(cache *datasource.Cache, offline bool) *SdistFetcher {
	return &SdistFetcher{
		HTTP: &http.Client{
			Timeout: 60 * time.Second,
			// Constrain redirect destinations (F-05): PyPI serves sdists from a
			// small set of hosts. A redirect chain that tries to bounce us to an
			// arbitrary host — to smuggle SSRF or a surprise payload origin — is
			// refused rather than followed.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("pypi-sdist: too many redirects")
				}
				if !allowedSdistHost(req.URL.Host) {
					return fmt.Errorf("pypi-sdist: redirect to disallowed host %q", req.URL.Host)
				}
				return nil
			},
		},
		Cache:   cache,
		Offline: offline,
		Now:     time.Now,
	}
}

// allowedSdistHost reports whether host is a PyPI content host we will follow a
// redirect to. Matches the apex and any subdomain of the known hosts.
func allowedSdistHost(host string) bool {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i] // strip any :port
	}
	host = strings.ToLower(host)
	for _, ok := range []string{"pypi.org", "pythonhosted.org"} {
		if host == ok || strings.HasSuffix(host, "."+ok) {
			return true
		}
	}
	return false
}

// sdistFiles holds the install-time files extracted from an sdist.
type sdistFiles struct {
	SetupPy       string            `json:"setup_py,omitempty"`
	PyprojectToml string            `json:"pyproject_toml,omitempty"`
	PthFiles      map[string]string `json:"pth_files,omitempty"`
	WheelOnly     bool              `json:"wheel_only,omitempty"`
}

// sdistSemantics versions the MEANING of a cached extraction result, not just
// its shape. Entries written by an earlier build were produced under fail-open
// rules — a silently truncated setup.py, .pth content dropped past the retention
// cap, an unverified digest, or an oversized sdist recorded as WheelOnly. Reusing
// those after an upgrade would let the old weaker analysis survive as a cached
// clean result, so bumping this invalidates them wholesale.
//
// Bump this whenever a change alters what a cached record is allowed to mean.
const sdistSemantics = "v2"

func sdistCacheKey(name, version string) string {
	return "pypi-sdist|" + sdistSemantics + "|" + name + "|" + version
}

// Fetch retrieves the install-time files for a package@version. It checks the
// cache first, then queries PyPI's JSON API, downloads the sdist, and extracts
// only the files needed for analysis. If only wheels are available, it returns
// a result with WheelOnly=true.
func (f *SdistFetcher) Fetch(ctx context.Context, name, version string) (*sdistFiles, error) {
	key := sdistCacheKey(name, version)

	// Cache check.
	if raw, fresh, ok := f.Cache.GetRaw(key); ok && (fresh || f.Offline) {
		var files sdistFiles
		if err := json.Unmarshal(raw, &files); err == nil {
			return &files, nil
		}
	}
	if f.Offline {
		return nil, fmt.Errorf("pypi-sdist: %s@%s not in cache (offline)", name, version)
	}

	// Query PyPI JSON API for distribution URLs.
	// NB: named wantSHA, not sha256Hex — that would shadow the package-level
	// validation regexp of the same name.
	sdistURL, wantSHA, err := f.findSdistURL(ctx, name, version)
	if err != nil {
		return nil, err
	}

	var files sdistFiles
	if sdistURL == "" {
		files.WheelOnly = true
	} else {
		extracted, err := f.downloadAndExtract(ctx, sdistURL, wantSHA)
		if err != nil {
			return nil, fmt.Errorf("pypi-sdist: extracting %s@%s: %w", name, version, err)
		}
		files = *extracted
	}

	// Cache the result.
	raw, _ := json.Marshal(files)
	now := f.Now
	if now == nil {
		now = time.Now
	}
	_ = f.Cache.PutRaw(key, raw, now())

	return &files, nil
}

// pypiVersionInfo is the subset of the PyPI JSON API response we need.
type pypiVersionInfo struct {
	URLs []pypiURL `json:"urls"`
}

type pypiURL struct {
	PackageType string      `json:"packagetype"`
	URL         string      `json:"url"`
	Size        int64       `json:"size"`
	Digests     pypiDigests `json:"digests"`
}

type pypiDigests struct {
	SHA256 string `json:"sha256"`
}

// findSdistURL queries the PyPI JSON API and returns the sdist download URL and
// its expected SHA-256 digest. Returns "", "" if only wheels are available.
func (f *SdistFetcher) findSdistURL(ctx context.Context, name, version string) (string, string, error) {
	endpoint := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("pypi-sdist: querying %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("pypi-sdist: %s returned %d", endpoint, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", "", err
	}

	var info pypiVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", "", fmt.Errorf("pypi-sdist: parsing response for %s@%s: %w", name, version, err)
	}

	// "No sdist exists" and "an sdist exists but we declined to fetch it" are
	// different facts and must not collapse (finding R-02, follow-up). The size
	// filter previously skipped an oversized sdist and fell through to the
	// wheel-only return, so Fetch recorded WheelOnly=true — a benign, expected
	// state — CACHED it, and reported no gap. An attacker need only DECLARE a
	// large size in index metadata to make their install surface invisible while
	// the scan looks clean.
	var sawOversize bool
	for _, u := range info.URLs {
		if u.PackageType != "sdist" {
			continue
		}
		if u.Size > maxSdistSize {
			sawOversize = true
			continue
		}
		return u.URL, u.Digests.SHA256, nil
	}
	if sawOversize {
		return "", "", fmt.Errorf("%w: every candidate sdist for %s@%s declares a size over %d bytes; "+
			"install surface unexamined", ErrSdistTooLarge, name, version, maxSdistSize)
	}
	return "", "", nil // genuinely wheel-only: no sdist was published
}

// downloadAndExtract fetches an sdist tarball and extracts the install-time
// files we need: setup.py, pyproject.toml, and any .pth files.
func (f *SdistFetcher) downloadAndExtract(ctx context.Context, rawURL, wantSHA string) (*sdistFiles, error) {
	// Validate the ORIGIN before the request, not just redirect targets. This URL
	// comes from index metadata, so an attacker who can influence that response
	// could otherwise steer the fetch to any host (finding R-02).
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSdistDisallowedHost, err)
	}
	if u.Scheme != "https" || !allowedSdistHost(u.Host) {
		return nil, fmt.Errorf("%w: %s", ErrSdistDisallowedHost, rawURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", rawURL, resp.StatusCode)
	}

	// Read the compressed artifact into memory ONCE (bounded by the size cap),
	// so the digest is computed over exactly the bytes PyPI served. Streaming the
	// hash through gzip would miss trailing bytes the tar reader never pulls.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSdistSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxSdistSize {
		return nil, fmt.Errorf("%w: compressed sdist over %d bytes", ErrSdistTooLarge, maxSdistSize)
	}

	// Integrity: the digest is REQUIRED. Treating an absent one as "skip
	// verification" fails open exactly when metadata is missing or tampered.
	wantSHA = strings.TrimSpace(wantSHA)
	if !sha256Hex.MatchString(wantSHA) {
		return nil, fmt.Errorf("%w (got %q)", ErrSdistNoDigest, wantSHA)
	}
	sum := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), wantSHA) {
		return nil, ErrSdistDigestMismatch
	}

	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSdistCorrupt, err)
	}
	defer gz.Close()

	return extractFromTar(gz)
}

// extractFromTar reads a tar stream and extracts the install-time files.
// Only files at depth 1 (inside the top-level directory) are considered.
func extractFromTar(r io.Reader) (*sdistFiles, error) {
	cr := &countingReader{r: r}
	tr := tar.NewReader(cr)
	files := &sdistFiles{}
	var (
		entries  int
		pthBytes int64
	)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A truncated or malformed tar is a COVERAGE GAP, not a clean result
			// (F-05). Returning the partial files with a nil error would let a
			// corrupt or deliberately truncated sdist read as fully analyzed.
			return nil, fmt.Errorf("%w: %v", ErrSdistCorrupt, err)
		}
		entries++
		if entries > maxTarEntries {
			return nil, ErrSdistTooManyEntries
		}
		if cr.n > maxDecompressed {
			return nil, fmt.Errorf("%w: decompressed over %d bytes", ErrSdistTooLarge, maxDecompressed)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Sdist structure: {name}-{version}/setup.py
		// We want files at depth 1 only.
		name := path.Clean(hdr.Name)
		parts := strings.SplitN(name, "/", 3)
		if len(parts) < 2 {
			continue
		}
		basename := parts[1]
		// Also check for .pth files at any depth within the package.
		if len(parts) == 3 {
			basename = parts[2]
		}

		var target *string
		switch {
		case len(parts) == 2 && parts[1] == "setup.py":
			target = &files.SetupPy
		case len(parts) == 2 && parts[1] == "pyproject.toml":
			target = &files.PyprojectToml
		case strings.HasSuffix(basename, ".pth"):
			// .pth files can be at various depths
		default:
			continue
		}

		// Read ONE BYTE PAST the cap so an oversized file is detected rather than
		// silently truncated (finding R-02). The old form returned exactly
		// maxFileSize bytes with no error, so an attacker could pad setup.py with
		// 2 MiB of comments and place the payload after the cut — the analyzer
		// would scan a clean prefix and report nothing.
		content, err := io.ReadAll(io.LimitReader(tr, maxFileSize+1))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSdistCorrupt, err)
		}
		if int64(len(content)) > maxFileSize {
			return nil, fmt.Errorf("%w: %s is over %d bytes; content unexamined",
				ErrSdistTooLarge, name, maxFileSize)
		}
		if cr.n > maxDecompressed {
			return nil, fmt.Errorf("%w: decompressed over %d bytes", ErrSdistTooLarge, maxDecompressed)
		}

		if target != nil {
			*target = string(content)
		} else if strings.HasSuffix(basename, ".pth") {
			// Cap both the COUNT and the CUMULATIVE SIZE of retained .pth files:
			// a persistence payload can splinter across thousands of tiny .pth
			// entries. Exceeding a cap is a COVERAGE GAP, not a silent discard —
			// dropping .pth content quietly is dropping the exact artifact the
			// pypi-pth-persistence fixture exists to catch.
			if len(files.PthFiles) >= maxPthFiles || pthBytes+int64(len(content)) > maxPthTotalBytes {
				return nil, fmt.Errorf("%w (%s)", ErrSdistRetentionExceeded, name)
			}
			if files.PthFiles == nil {
				files.PthFiles = map[string]string{}
			}
			files.PthFiles[basename] = string(content)
			pthBytes += int64(len(content))
		}
	}
	// The loop checks the decompressed total on the NEXT iteration, so a final
	// oversized entry would slip out through EOF unchecked (R-02).
	if cr.n > maxDecompressed {
		return nil, fmt.Errorf("%w: decompressed over %d bytes", ErrSdistTooLarge, maxDecompressed)
	}
	return files, nil
}
