package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// ---------- PyPI ----------
// GET /pypi/<package>/json → {releases: {"1.0": [{upload_time_iso_8601}]}}.

func NewPyPI(cache *datasource.Cache, offline bool) *Client {
	return New(Spec{
		SourceName: "pypi-registry",
		Eco:        "pypi",
		CacheTag:   "pypi",
		Endpoint:   "https://pypi.org",
		BuildURL: func(endpoint, name string) string {
			return endpoint + "/pypi/" + url.PathEscape(name) + "/json"
		},
		Parse: parsePyPIVersions,
	}, cache, offline)
}

type pypiResponse struct {
	Releases map[string][]pypiFile `json:"releases"`
}

type pypiFile struct {
	UploadTime string `json:"upload_time_iso_8601"`
	Yanked     bool   `json:"yanked"`
}

func parsePyPIVersions(name string, raw []byte) (*datasource.ReleaseHistory, error) {
	var resp pypiResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("pypireg: parsing versions for %s: %w", name, err)
	}
	h := &datasource.ReleaseHistory{Package: name, Ecosystem: "pypi"}
	for version, files := range resp.Releases {
		if len(files) == 0 {
			continue
		}
		// Use the earliest upload timestamp among the files for this version, and
		// treat the version as YANKED when EVERY file is yanked (PEP 592 yank-lure
		// substrate, OPU-26). Yanking is per-file; while any file remains live, pip
		// can still resolve the version, so it is not effectively withdrawn.
		var earliest time.Time
		allYanked := true
		for _, f := range files {
			if !f.Yanked {
				allYanked = false
			}
			if f.UploadTime == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, f.UploadTime)
			if err != nil {
				continue
			}
			if earliest.IsZero() || t.Before(earliest) {
				earliest = t
			}
		}
		if !earliest.IsZero() {
			h.Releases = append(h.Releases, datasource.Release{Version: version, Published: earliest, Yanked: allYanked})
		}
	}
	h.Sort()
	return h, nil
}

// ---------- RubyGems ----------
// GET /api/v1/versions/<gem>.json → JSON array of {number, created_at}.

func NewGem(cache *datasource.Cache, offline bool) *Client {
	return New(Spec{
		SourceName: "rubygems-registry",
		Eco:        "gem",
		CacheTag:   "gem",
		Endpoint:   "https://rubygems.org",
		BuildURL: func(endpoint, name string) string {
			return endpoint + "/api/v1/versions/" + url.PathEscape(name) + ".json"
		},
		Parse: parseGemVersions,
	}, cache, offline)
}

type gemVersion struct {
	Number    string `json:"number"`
	CreatedAt string `json:"created_at"`
}

func parseGemVersions(name string, raw []byte) (*datasource.ReleaseHistory, error) {
	var versions []gemVersion
	if err := json.Unmarshal(raw, &versions); err != nil {
		return nil, fmt.Errorf("gemreg: parsing versions for %s: %w", name, err)
	}
	h := &datasource.ReleaseHistory{Package: name, Ecosystem: "gem"}
	for _, v := range versions {
		t, err := time.Parse(time.RFC3339, v.CreatedAt)
		if err != nil {
			continue
		}
		h.Releases = append(h.Releases, datasource.Release{Version: v.Number, Published: t})
	}
	h.Sort()
	return h, nil
}

// ---------- Cargo (crates.io) ----------
// GET /api/v1/crates/<crate>/versions → {versions: [{num, created_at}]}.

func NewCargo(cache *datasource.Cache, offline bool) *Client {
	return New(Spec{
		SourceName: "cargo-registry",
		Eco:        "cargo",
		CacheTag:   "cargo",
		Endpoint:   "https://crates.io",
		BuildURL: func(endpoint, name string) string {
			return endpoint + "/api/v1/crates/" + url.PathEscape(name) + "/versions"
		},
		SetHeaders: func(req *http.Request) {
			req.Header.Set("User-Agent", "depsnort (supply-chain IDS)")
		},
		Parse: parseCargoVersions,
	}, cache, offline)
}

type cargoResponse struct {
	Versions []cargoVersion `json:"versions"`
}

type cargoVersion struct {
	Num       string `json:"num"`
	CreatedAt string `json:"created_at"`
	// Yanked is crates.io's per-version withdrawal flag. crates.io is the only
	// registry of the six that exposes it in the metadata depsnort fetches; it is
	// the substrate of the yank-lure signal (VC-012, OPU-26).
	Yanked bool `json:"yanked"`
	// PublishedBy is crates.io's per-version publisher. It is the second of
	// the six ecosystems to expose one (npm is the other), and the only reason
	// the actor axis can be evaluated for Rust at all (D-40).
	PublishedBy *cargoPublisher `json:"published_by"`
}

type cargoPublisher struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

func parseCargoVersions(name string, raw []byte) (*datasource.ReleaseHistory, error) {
	var resp cargoResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("cargoreg: parsing versions for %s: %w", name, err)
	}
	h := &datasource.ReleaseHistory{Package: name, Ecosystem: "cargo"}
	for _, v := range resp.Versions {
		t, err := time.Parse(time.RFC3339, v.CreatedAt)
		if err != nil {
			continue
		}
		h.Releases = append(h.Releases, datasource.Release{Version: v.Num, Published: t, Yanked: v.Yanked})
		// published_by is null for releases predating crates.io recording it,
		// and for versions published by a token whose owner was since deleted.
		// Absent stays absent: an unknown publisher must never be filled in.
		if v.PublishedBy == nil || (v.PublishedBy.Login == "" && v.PublishedBy.ID == 0) {
			continue
		}
		if h.Publishers == nil {
			h.Publishers = map[string]datasource.Publisher{}
		}
		id := v.PublishedBy.Login
		if v.PublishedBy.ID != 0 {
			// Prefer the numeric account ID: logins can be renamed and reused,
			// and an identity that changes when a name changes would report a
			// publisher transition that never happened.
			id = strconv.FormatInt(v.PublishedBy.ID, 10)
		}
		h.Publishers[v.Num] = datasource.Publisher{
			ID:     id,
			Name:   firstNonEmpty(v.PublishedBy.Login, v.PublishedBy.Name),
			Source: "crates.published_by",
		}
	}
	h.Sort()
	return h, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- Composer (Packagist) ----------
// GET /p2/<vendor>/<package>.json → {packages: {"<vendor>/<package>": [{version, time}]}}.

func NewComposer(cache *datasource.Cache, offline bool) *Client {
	return New(Spec{
		SourceName: "composer-registry",
		Eco:        "composer",
		CacheTag:   "composer",
		Endpoint:   "https://repo.packagist.org",
		BuildURL: func(endpoint, name string) string {
			// Packagist v2: /p2/<vendor>/<package>.json — name is already vendor/package.
			return endpoint + "/p2/" + name + ".json"
		},
		Parse: parseComposerVersions,
	}, cache, offline)
}

type packagistResponse struct {
	Packages map[string][]packagistVersion `json:"packages"`
}

type packagistVersion struct {
	Version string `json:"version"`
	Time    string `json:"time"`
}

func parseComposerVersions(name string, raw []byte) (*datasource.ReleaseHistory, error) {
	var resp packagistResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("composerreg: parsing versions for %s: %w", name, err)
	}
	h := &datasource.ReleaseHistory{Package: name, Ecosystem: "composer"}
	for _, v := range resp.Packages[name] {
		if v.Time == "" || strings.HasPrefix(v.Version, "dev-") {
			continue
		}
		t, err := time.Parse(time.RFC3339, v.Time)
		if err != nil {
			continue
		}
		h.Releases = append(h.Releases, datasource.Release{Version: v.Version, Published: t})
	}
	h.Sort()
	return h, nil
}

// ---------- NuGet ----------
// GET /v3-flatcontainer/<id-lower>/index.json → {versions: ["1.0.0", ...]}.
// Publish timestamps come from the catalog:
// GET /v3/registration5-gz-semver2/<id-lower>/<version>.json → {catalogEntry: {published}}.
//
// NuGet's flat container gives version lists but no timestamps. The registration
// index gives timestamps but requires paging through catalog pages. We use the
// registration index: one request per package returns all versions with publish
// dates in the catalog leaf entries.

func NewNuGet(cache *datasource.Cache, offline bool) *Client {
	return New(Spec{
		SourceName: "nuget-registry",
		Eco:        "nuget",
		CacheTag:   "nuget",
		Endpoint:   "https://api.nuget.org",
		BuildURL: func(endpoint, name string) string {
			lower := strings.ToLower(name)
			return endpoint + "/v3/registration5-gz-semver2/" + lower + "/index.json"
		},
		Parse: parseNuGetVersions,
	}, cache, offline)
}

// nugetRegIndex is the NuGet registration index response.
type nugetRegIndex struct {
	Items []nugetRegPage `json:"items"`
}

type nugetRegPage struct {
	Items []nugetRegLeaf `json:"items"`
}

type nugetRegLeaf struct {
	CatalogEntry nugetCatalogEntry `json:"catalogEntry"`
}

type nugetCatalogEntry struct {
	Version   string `json:"version"`
	Published string `json:"published"`
	Listed    *bool  `json:"listed,omitempty"`
}

func parseNuGetVersions(name string, raw []byte) (*datasource.ReleaseHistory, error) {
	var idx nugetRegIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("nugetreg: parsing index for %s: %w", name, err)
	}
	h := &datasource.ReleaseHistory{Package: name, Ecosystem: "nuget"}
	for _, page := range idx.Items {
		for _, leaf := range page.Items {
			ce := leaf.CatalogEntry
			if ce.Listed != nil && !*ce.Listed {
				continue
			}
			if ce.Published == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, ce.Published)
			if err != nil {
				continue
			}
			h.Releases = append(h.Releases, datasource.Release{Version: ce.Version, Published: t})
		}
	}
	h.Sort()
	return h, nil
}
