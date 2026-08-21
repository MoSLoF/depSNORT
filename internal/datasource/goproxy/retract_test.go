package goproxy

import (
	"context"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

func TestParseRetract(t *testing.T) {
	cases := []struct {
		name string
		mod  string
		want []retractSpec
	}{
		{
			name: "single line",
			mod:  "module m\n\ngo 1.21\n\nretract v1.0.1\n",
			want: []retractSpec{{exact: "v1.0.1"}},
		},
		{
			name: "single-line range",
			mod:  "module m\nretract [v1.1.0, v1.3.0]\n",
			want: []retractSpec{{lo: "v1.1.0", hi: "v1.3.0"}},
		},
		{
			name: "block form, mixed, with comments",
			mod: "module m\n\nretract (\n" +
				"\tv1.0.0 // buggy\n" +
				"\t[v1.1.0, v1.2.0] // account takeover\n" +
				"\tv1.3.0\n" +
				")\n",
			want: []retractSpec{{exact: "v1.0.0"}, {lo: "v1.1.0", hi: "v1.2.0"}, {exact: "v1.3.0"}},
		},
		{
			name: "trailing rationale on single line is stripped",
			mod:  "retract v2.0.0 // do not use\n",
			want: []retractSpec{{exact: "v2.0.0"}},
		},
		{
			name: "retract as a prefix of another token is ignored",
			// a line that STARTS with "retract" but is not the directive (no space,
			// bracket, or paren after it) must not be read as `retract foo`.
			mod:  "module m\nretractfoo\n",
			want: nil,
		},
		{
			name: "no retract directive",
			mod:  "module m\n\ngo 1.21\n\nrequire example.com/x v1.0.0\n",
			want: nil,
		},
	}
	for _, tc := range cases {
		got := parseRetract([]byte(tc.mod))
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %d specs %+v, want %d %+v", tc.name, len(got), got, len(tc.want), tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: spec %d = %+v, want %+v", tc.name, i, got[i], tc.want[i])
			}
		}
	}
}

func TestIsRetracted(t *testing.T) {
	specs := []retractSpec{{exact: "v1.0.0"}, {lo: "v1.2.0", hi: "v1.4.0"}}
	cases := []struct {
		version string
		want    bool
	}{
		{"v1.0.0", true},  // exact
		{"v0.9.0", false}, // below everything
		{"v1.1.0", false}, // between exact and range
		{"v1.2.0", true},  // range lower bound (inclusive)
		{"v1.3.0", true},  // inside range
		{"v1.4.0", true},  // range upper bound (inclusive)
		{"v1.5.0", false}, // above range
		// semver ordering, not lexical: v1.2.10 is inside [v1.2.0, v1.4.0]; a
		// string compare would place "v1.2.10" < "v1.2.9" and could mis-bound it.
		{"v1.2.10", true},
	}
	for _, tc := range cases {
		if got := isRetracted(tc.version, specs); got != tc.want {
			t.Errorf("isRetracted(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestHighestVersion(t *testing.T) {
	// semver-highest, not lexical-highest: v0.3.10 > v0.3.9 though it sorts lower
	// as a string. A non-semver tag is skipped, never chosen.
	got := highestVersion([]string{"v0.3.9", "v0.3.10", "v0.3.2", "not-a-version"})
	if got != "v0.3.10" {
		t.Errorf("highestVersion = %q, want v0.3.10", got)
	}
	if highestVersion([]string{"junk", "also-junk"}) != "" {
		t.Errorf("highestVersion of no-semver list should be empty")
	}
}

// TestHistoriesMarksRetracted proves the end-to-end wiring: retractions declared in
// the HIGHEST version's go.mod flow through to Release.Yanked on the matching
// versions, and the resulting shape is the retract-lure YankLureShape reads (OPU-26).
func TestHistoriesMarksRetracted(t *testing.T) {
	const mod = "github.com/foo/bar"
	f := &histFake{
		list: map[string][]string{mod: {"v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0"}},
		infos: map[string]string{
			mod + "@v1.0.0": "2020-01-01T00:00:00Z",
			mod + "@v1.1.0": "2021-01-01T00:00:00Z",
			mod + "@v1.2.0": "2022-01-01T00:00:00Z",
			mod + "@v1.3.0": "2023-01-01T00:00:00Z",
		},
		// go.mod of the highest version (v1.3.0) retracts the two below it.
		mods: map[string]string{
			mod + "@v1.3.0": "module github.com/foo/bar\n\nretract (\n\tv1.1.0\n\tv1.2.0\n)\n",
		},
	}
	c := New(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = f
	h, err := c.Histories(context.Background(), []string{mod})
	if err != nil {
		t.Fatal(err)
	}
	rh := h[mod]
	if rh == nil {
		t.Fatal("no history")
	}
	want := map[string]bool{"v1.0.0": false, "v1.1.0": true, "v1.2.0": true, "v1.3.0": false}
	for _, r := range rh.Releases {
		if r.Yanked != want[r.Version] {
			t.Errorf("%s yanked = %v, want %v", r.Version, r.Yanked, want[r.Version])
		}
	}
	// The two retracted versions sit contiguously beneath the live newest: the
	// retract-lure shape VC-012 elevates on.
	newest, run, ok := rh.YankLureShape()
	if !ok || newest != "v1.3.0" || run != 2 {
		t.Errorf("YankLureShape = (%q, %d, %v), want (v1.3.0, 2, true)", newest, run, ok)
	}
}

// TestHistoriesNoModNoRetract proves that when the proxy has no go.mod for the
// highest version (404), history is still built and nothing is marked yanked —
// disclosed as absence, not error.
func TestHistoriesNoModNoRetract(t *testing.T) {
	const mod = "github.com/foo/bar"
	f := &histFake{
		list:  map[string][]string{mod: {"v1.0.0", "v1.1.0"}},
		infos: map[string]string{mod + "@v1.0.0": "2020-01-01T00:00:00Z", mod + "@v1.1.0": "2021-01-01T00:00:00Z"},
		// no mods served -> .mod 404s
	}
	c := New(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = f
	h, err := c.Histories(context.Background(), []string{mod})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range h[mod].Releases {
		if r.Yanked {
			t.Errorf("%s marked yanked with no retract data", r.Version)
		}
	}
}
