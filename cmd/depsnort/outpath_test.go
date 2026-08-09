package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fixed instant in a named zone, so the DTG is deterministic under test.
// 2026-08-07 13:26 CDT is the worked example from the naming convention.
var (
	cdt      = time.FixedZone("CDT", -5*60*60)
	fixedNow = time.Date(2026, 8, 7, 13, 26, 0, 0, cdt)
)

func TestReportDTGCarriesZoneAbbreviation(t *testing.T) {
	if got := reportDTG(fixedNow); got != "202608071326CDT" {
		t.Errorf("reportDTG(local) = %q, want 202608071326CDT", got)
	}
	if got := reportDTG(fixedNow.UTC()); got != "202608071826UTC" {
		t.Errorf("reportDTG(UTC) = %q, want 202608071826UTC", got)
	}
}

func TestReportRelPathLayout(t *testing.T) {
	got := reportRelPath("pdf", fixedNow)
	want := filepath.Join("20260807", "Report-202608071326CDT.pdf") // reportRelPath itself does not convert
	if got != want {
		t.Errorf("reportRelPath = %q, want %q", got, want)
	}
}

func TestReportRelPathExtensionPerFormat(t *testing.T) {
	for format, ext := range map[string]string{
		"json": ".json", "dot": ".dot", "cypher": ".cypher",
		"sarif": ".sarif", "pdf": ".pdf",
	} {
		got := reportRelPath(format, fixedNow)
		if !strings.HasSuffix(got, "Report-202608071326CDT"+ext) {
			t.Errorf("reportRelPath(%q) = %q, want suffix %q", format, got, ext)
		}
	}
}

func TestResolveOutPathStdout(t *testing.T) {
	got, err := resolveOutPath("", "pdf", false, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("empty spec should mean stdout, got %q", got)
	}
}

// UTC is the DEFAULT: passing local=false must produce a UTC stamp regardless
// of the machine's zone.
func TestResolveOutPathDefaultsToUTC(t *testing.T) {
	root := t.TempDir()
	got, err := resolveOutPath(root, "pdf", false, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "20260807", "Report-202608071826UTC.pdf")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// The dated subdirectory must exist by the time the caller writes into it.
	if info, err := os.Stat(filepath.Join(root, "20260807")); err != nil || !info.IsDir() {
		t.Error("dated subdirectory was not created")
	}
}

// Regression (D-16 era): `-o ./reports` where ./reports does not exist yet must
// become the output ROOT, not a file literally named "reports".
func TestResolveOutPathBareNameIsRoot(t *testing.T) {
	base := t.TempDir()
	spec := filepath.Join(base, "reports")
	got, err := resolveOutPath(spec, "pdf", false, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(spec, "20260807", "Report-202608071826UTC.pdf")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if info, err := os.Stat(spec); err != nil || !info.IsDir() {
		t.Errorf("%q should have been created as a directory", spec)
	}
}

func TestResolveOutPathExplicitFileSkipsTree(t *testing.T) {
	got, err := resolveOutPath("out/custom.pdf", "pdf", false, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if got != "out/custom.pdf" {
		t.Errorf("an explicit filename must be used verbatim with no dated tree, got %q", got)
	}
}

func TestResolveOutPathExistingFileWins(t *testing.T) {
	base := t.TempDir()
	spec := filepath.Join(base, "myreport") // no extension, but IS a file
	if err := os.WriteFile(spec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveOutPath(spec, "pdf", false, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if got != spec {
		t.Errorf("existing file should be used verbatim, got %q", got)
	}
}

func TestLocalFlagOptsBackIntoWallClock(t *testing.T) {
	root := t.TempDir()
	got, err := resolveOutPath(root, "pdf", true, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "20260807", "Report-202608071326CDT.pdf")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Converting to UTC must move BOTH the folder and the stamp, or a late-evening
// scan lands in the wrong day's directory.
func TestUTCRollsTheDateFolder(t *testing.T) {
	root := t.TempDir()
	late := time.Date(2026, 8, 7, 22, 30, 0, 0, cdt) // 03:30 UTC on the 8th
	got, err := resolveOutPath(root, "json", false, late)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "20260808", "Report-202608080330UTC.json")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// The same instant in local mode stays on the 7th.
	local, err := resolveOutPath(t.TempDir(), "json", true, late)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(local, filepath.Join("20260807", "Report-202608072230CDT")) {
		t.Errorf("local mode should stay on the 7th, got %q", local)
	}
}

// The DST hazard UTC exists to avoid: on the fall-back night the same wall
// clock happens twice, so two distinct scans collide in local mode but stay
// distinct in UTC.
func TestUTCSurvivesDSTFallBackCollision(t *testing.T) {
	cst := time.FixedZone("CST", -6*60*60)
	// 01:30 CDT and 01:30 CST on 2026-11-01 are an hour apart in real time.
	first := time.Date(2026, 11, 1, 1, 30, 0, 0, cdt)
	second := time.Date(2026, 11, 1, 1, 30, 0, 0, cst)

	if reportDTG(first.UTC()) == reportDTG(second.UTC()) {
		t.Error("UTC stamps must stay distinct across the DST repeat")
	}
	// Same local wall clock, differing only by zone abbreviation — which is the
	// sole thing preventing an outright filename collision locally.
	if first.Format("200601021504") != second.Format("200601021504") {
		t.Fatal("fixture is wrong: these should share a wall clock")
	}
}

func TestSameMinuteCollidesLaterMinuteDoesNot(t *testing.T) {
	a := reportRelPath("pdf", fixedNow)
	b := reportRelPath("pdf", fixedNow.Add(30*time.Second))
	if a != b {
		t.Error("scans within the same minute should share a name (minute resolution)")
	}
	c := reportRelPath("pdf", fixedNow.Add(time.Minute))
	if a == c {
		t.Error("scans a minute apart must produce distinct names")
	}
}

func TestSanitizeStampHandlesNumericOffsetZones(t *testing.T) {
	// Zones with no abbreviation format as a numeric offset; the result must
	// still be filename-safe.
	kathmandu := time.FixedZone("", 5*60*60+45*60)
	stamp := reportDTG(time.Date(2026, 8, 7, 13, 26, 0, 0, kathmandu))
	for _, bad := range []string{":", " ", "/", "\\"} {
		if strings.Contains(stamp, bad) {
			t.Errorf("stamp %q contains unsafe character %q", stamp, bad)
		}
	}
	if !strings.HasPrefix(stamp, "202608071326") {
		t.Errorf("stamp %q lost its date-time prefix", stamp)
	}
}
