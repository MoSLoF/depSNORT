package registry

import (
	"testing"
)

func TestParseGemVersions(t *testing.T) {
	raw := `[
		{"number":"1.0.0","created_at":"2020-01-15T10:00:00+00:00"},
		{"number":"1.1.0","created_at":"2020-06-20T12:00:00+00:00"},
		{"number":"2.0.0","created_at":"2021-03-01T08:30:00+00:00"}
	]`
	h, err := parseGemVersions("nokogiri", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if h.Ecosystem != "gem" {
		t.Errorf("ecosystem = %q, want gem", h.Ecosystem)
	}
	if len(h.Releases) != 3 {
		t.Fatalf("releases = %d, want 3", len(h.Releases))
	}
	if h.Releases[0].Version != "1.0.0" {
		t.Errorf("first version = %q, want 1.0.0", h.Releases[0].Version)
	}
	if h.Releases[2].Version != "2.0.0" {
		t.Errorf("last version = %q, want 2.0.0", h.Releases[2].Version)
	}
}

func TestParseCargoVersions(t *testing.T) {
	// Shape mirrors the real crates.io /api/v1/crates/<crate>/versions response,
	// including the per-version `yanked` flag depsnort now parses (OPU-26).
	raw := `{
		"versions": [
			{"num":"0.1.0","created_at":"2019-05-01T00:00:00+00:00","yanked":false},
			{"num":"0.2.0","created_at":"2019-11-15T00:00:00+00:00","yanked":true},
			{"num":"1.0.0","created_at":"2020-08-20T00:00:00+00:00","yanked":false}
		]
	}`
	h, err := parseCargoVersions("serde", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if h.Ecosystem != "cargo" {
		t.Errorf("ecosystem = %q, want cargo", h.Ecosystem)
	}
	if len(h.Releases) != 3 {
		t.Fatalf("releases = %d, want 3", len(h.Releases))
	}
	if h.Releases[0].Version != "0.1.0" {
		t.Errorf("first = %q, want 0.1.0", h.Releases[0].Version)
	}
	// The yanked flag must survive parsing — it is the substrate of VC-012.
	yank := map[string]bool{}
	for _, r := range h.Releases {
		yank[r.Version] = r.Yanked
	}
	if !yank["0.2.0"] {
		t.Error("0.2.0 should be parsed as yanked")
	}
	if yank["0.1.0"] || yank["1.0.0"] {
		t.Error("0.1.0 and 1.0.0 should be live (not yanked)")
	}
}

func TestParseComposerVersions(t *testing.T) {
	raw := `{
		"packages": {
			"psr/log": [
				{"version":"1.0.0","time":"2018-01-10T09:00:00+00:00"},
				{"version":"dev-main","time":"2024-01-01T00:00:00+00:00"},
				{"version":"3.0.0","time":"2022-12-01T00:00:00+00:00"}
			]
		}
	}`
	h, err := parseComposerVersions("psr/log", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if h.Ecosystem != "composer" {
		t.Errorf("ecosystem = %q, want composer", h.Ecosystem)
	}
	// dev-main should be skipped
	if len(h.Releases) != 2 {
		t.Fatalf("releases = %d, want 2 (dev-main skipped)", len(h.Releases))
	}
	if h.Releases[0].Version != "1.0.0" {
		t.Errorf("first = %q, want 1.0.0", h.Releases[0].Version)
	}
}

func TestParseNuGetVersions(t *testing.T) {
	f := false
	_ = f
	raw := `{
		"items": [{
			"items": [
				{"catalogEntry":{"version":"12.0.3","published":"2019-11-27T00:00:00+00:00"}},
				{"catalogEntry":{"version":"13.0.1","published":"2021-06-16T00:00:00+00:00"}},
				{"catalogEntry":{"version":"13.0.0-beta1","published":"2021-01-01T00:00:00+00:00","listed":false}}
			]
		}]
	}`
	h, err := parseNuGetVersions("Newtonsoft.Json", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if h.Ecosystem != "nuget" {
		t.Errorf("ecosystem = %q, want nuget", h.Ecosystem)
	}
	// listed=false entry should be skipped
	if len(h.Releases) != 2 {
		t.Fatalf("releases = %d, want 2 (unlisted skipped)", len(h.Releases))
	}
	if h.Releases[0].Version != "12.0.3" {
		t.Errorf("first = %q, want 12.0.3", h.Releases[0].Version)
	}
}

func TestParseNuGetUnlisted(t *testing.T) {
	raw := `{
		"items": [{
			"items": [
				{"catalogEntry":{"version":"1.0.0","published":"2020-01-01T00:00:00+00:00","listed":false}},
				{"catalogEntry":{"version":"2.0.0","published":"2021-01-01T00:00:00+00:00"}}
			]
		}]
	}`
	h, err := parseNuGetVersions("Test.Package", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Releases) != 1 {
		t.Fatalf("releases = %d, want 1", len(h.Releases))
	}
	if h.Releases[0].Version != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", h.Releases[0].Version)
	}
}

func TestParsePyPIVersions(t *testing.T) {
	raw := `{
		"releases": {
			"1.0.0": [{"upload_time_iso_8601":"2019-03-10T12:00:00Z"}],
			"2.0.0": [
				{"upload_time_iso_8601":"2021-07-20T08:00:00Z"},
				{"upload_time_iso_8601":"2021-07-20T09:00:00Z"}
			],
			"3.0.0rc1": []
		}
	}`
	h, err := parsePyPIVersions("requests", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if h.Ecosystem != "pypi" {
		t.Errorf("ecosystem = %q, want pypi", h.Ecosystem)
	}
	// 3.0.0rc1 has no files → skipped
	if len(h.Releases) != 2 {
		t.Fatalf("releases = %d, want 2", len(h.Releases))
	}
	if h.Releases[0].Version != "1.0.0" {
		t.Errorf("first = %q, want 1.0.0", h.Releases[0].Version)
	}
	// 2.0.0 should use earliest upload time (08:00)
	if h.Releases[1].Published.Hour() != 8 {
		t.Errorf("2.0.0 hour = %d, want 8 (earliest)", h.Releases[1].Published.Hour())
	}
}

// A PyPI version is yanked (PEP 592) only when EVERY file is yanked; while any
// file remains live, pip can still resolve the version, so it is not withdrawn.
func TestParsePyPIVersionsYanked(t *testing.T) {
	raw := `{
		"releases": {
			"1.0.0": [{"upload_time_iso_8601":"2019-03-10T12:00:00Z","yanked":true}],
			"1.1.0": [
				{"upload_time_iso_8601":"2020-01-01T00:00:00Z","yanked":true},
				{"upload_time_iso_8601":"2020-01-01T01:00:00Z","yanked":false}
			],
			"1.2.0": [{"upload_time_iso_8601":"2021-01-01T00:00:00Z","yanked":false}]
		}
	}`
	h, err := parsePyPIVersions("soup", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	yank := map[string]bool{}
	for _, r := range h.Releases {
		yank[r.Version] = r.Yanked
	}
	if !yank["1.0.0"] {
		t.Error("1.0.0 (all files yanked) should be yanked")
	}
	if yank["1.1.0"] {
		t.Error("1.1.0 (one live file) must NOT be yanked — pip can still resolve it")
	}
	if yank["1.2.0"] {
		t.Error("1.2.0 (no yanked files) must be live")
	}
}

func TestParsePyPIBadJSON(t *testing.T) {
	_, err := parsePyPIVersions("bad", []byte(`not json`))
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestParseGemBadJSON(t *testing.T) {
	_, err := parseGemVersions("bad", []byte(`not json`))
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestParseCargoBadJSON(t *testing.T) {
	_, err := parseCargoVersions("bad", []byte(`{invalid`))
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestParseComposerBadJSON(t *testing.T) {
	_, err := parseComposerVersions("bad", []byte(`{invalid`))
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestParseNuGetBadJSON(t *testing.T) {
	_, err := parseNuGetVersions("bad", []byte(`not json`))
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestGemSkipsBadTimestamp(t *testing.T) {
	raw := `[
		{"number":"1.0.0","created_at":"not-a-date"},
		{"number":"2.0.0","created_at":"2020-01-01T00:00:00+00:00"}
	]`
	h, err := parseGemVersions("test", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Releases) != 1 {
		t.Fatalf("releases = %d, want 1", len(h.Releases))
	}
}
