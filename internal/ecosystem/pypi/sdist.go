package pypi

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// maxSdistSize caps the download of a single sdist to prevent abuse.
const maxSdistSize = 50 * 1024 * 1024 // 50 MB

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
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		Cache:   cache,
		Offline: offline,
		Now:     time.Now,
	}
}

// sdistFiles holds the install-time files extracted from an sdist.
type sdistFiles struct {
	SetupPy       string            `json:"setup_py,omitempty"`
	PyprojectToml string            `json:"pyproject_toml,omitempty"`
	PthFiles      map[string]string `json:"pth_files,omitempty"`
	WheelOnly     bool              `json:"wheel_only,omitempty"`
}

func sdistCacheKey(name, version string) string {
	return "pypi-sdist|" + name + "|" + version
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
	sdistURL, err := f.findSdistURL(ctx, name, version)
	if err != nil {
		return nil, err
	}

	var files sdistFiles
	if sdistURL == "" {
		files.WheelOnly = true
	} else {
		extracted, err := f.downloadAndExtract(ctx, sdistURL)
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
	PackageType string `json:"packagetype"`
	URL         string `json:"url"`
	Size        int64  `json:"size"`
}

// findSdistURL queries the PyPI JSON API and returns the sdist download URL.
// Returns "" if only wheels are available.
func (f *SdistFetcher) findSdistURL(ctx context.Context, name, version string) (string, error) {
	endpoint := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("pypi-sdist: querying %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pypi-sdist: %s returned %d", endpoint, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", err
	}

	var info pypiVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("pypi-sdist: parsing response for %s@%s: %w", name, version, err)
	}

	for _, u := range info.URLs {
		if u.PackageType == "sdist" && u.Size <= maxSdistSize {
			return u.URL, nil
		}
	}
	return "", nil
}

// downloadAndExtract fetches an sdist tarball and extracts the install-time
// files we need: setup.py, pyproject.toml, and any .pth files.
func (f *SdistFetcher) downloadAndExtract(ctx context.Context, url string) (*sdistFiles, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxSdistSize))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	return extractFromTar(gz)
}

// extractFromTar reads a tar stream and extracts the install-time files.
// Only files at depth 1 (inside the top-level directory) are considered.
func extractFromTar(r io.Reader) (*sdistFiles, error) {
	tr := tar.NewReader(r)
	files := &sdistFiles{}
	const maxFileSize = 2 * 1024 * 1024 // 2 MB per extracted file

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return files, nil // partial extraction is better than nothing
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

		content, err := io.ReadAll(io.LimitReader(tr, maxFileSize))
		if err != nil {
			continue
		}

		if target != nil {
			*target = string(content)
		} else if strings.HasSuffix(basename, ".pth") {
			if files.PthFiles == nil {
				files.PthFiles = map[string]string{}
			}
			files.PthFiles[basename] = string(content)
		}
	}
	return files, nil
}
