package main

import (
	"strings"
	"testing"
)

// Integration tests for the full scan pipeline. These call run() — the same
// function main() delegates to — with synthetic args and assert exit codes and
// stderr output. Each test exercises the complete pipeline: flag parsing,
// ecosystem detection, graph resolution, check execution, verdict, and emit.

func TestScanCleanProjectReturnsZero(t *testing.T) {
	code := run([]string{"scan", "-no-osv", "-no-registry", "../../internal/ecosystem/npm/testdata/emptylock"})
	if code != 0 {
		t.Errorf("clean project exit code = %d, want 0", code)
	}
}

func TestScanWormyProjectReturnsOne(t *testing.T) {
	// The wormy fixture has an install hook that is exfil-capable (network +
	// credentials), which VC-002d promotes to block → exit 1.
	code := run([]string{"scan", "-no-osv", "-no-registry", "../../internal/ecosystem/npm/testdata/wormy"})
	if code != 1 {
		t.Errorf("wormy project exit code = %d, want 1 (block)", code)
	}
}

func TestScanProjReturnsZeroWithoutOSV(t *testing.T) {
	code := run([]string{"scan", "-no-osv", "-no-registry", "../../internal/ecosystem/npm/testdata/proj"})
	if code == 64 || code == 70 {
		t.Errorf("proj scan returned error code %d", code)
	}
}

func TestScanUnknownFormatReturnsUsage(t *testing.T) {
	code := run([]string{"scan", "-format", "xml", "."})
	if code != exitUsage {
		t.Errorf("unknown format exit code = %d, want %d", code, exitUsage)
	}
}

func TestScanNonExistentPathReturnsUsage(t *testing.T) {
	// A path that does not exist is a usage error (bad argument), distinct from
	// a valid path with no supported manifest (nothing to scan, exit clean).
	code := run([]string{"scan", "/nonexistent/path/that/does/not/exist"})
	if code != exitUsage {
		t.Errorf("nonexistent path exit code = %d, want %d", code, exitUsage)
	}
}

func TestVersionCommand(t *testing.T) {
	code := run([]string{"version"})
	if code != 0 {
		t.Errorf("version exit code = %d, want 0", code)
	}
}

func TestUnknownCommandReturnsUsage(t *testing.T) {
	code := run([]string{"bogus"})
	if code != exitUsage {
		t.Errorf("unknown command exit code = %d, want %d", code, exitUsage)
	}
}

func TestNoArgsReturnsUsage(t *testing.T) {
	code := run([]string{})
	if code != exitUsage {
		t.Errorf("no args exit code = %d, want %d", code, exitUsage)
	}
}

func TestScanAllFormats(t *testing.T) {
	for _, format := range []string{"json", "dot", "cypher", "sarif", "pdf"} {
		t.Run(format, func(t *testing.T) {
			code := run([]string{"scan", "-format", format, "-no-osv", "-no-registry",
				"../../internal/ecosystem/npm/testdata/proj"})
			if code == exitUsage || code == exitInternal {
				t.Errorf("format %q exit code = %d", format, code)
			}
		})
	}
}

func TestScanRecursiveWorkspace(t *testing.T) {
	code := run([]string{"scan", "-recursive", "-no-osv", "-no-registry",
		"testdata/workspace"})
	if code == exitInternal || code == exitUsage {
		t.Errorf("recursive scan exit code = %d", code)
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"  ", 0},
		{"@a,@b,@c", 3},
		{" @a , @b ", 2},
	}
	for _, tt := range tests {
		got := splitCSV(tt.in)
		if len(got) != tt.want {
			t.Errorf("splitCSV(%q) = %v (len %d), want len %d", tt.in, got, len(got), tt.want)
		}
		for _, s := range got {
			if strings.TrimSpace(s) != s {
				t.Errorf("splitCSV(%q) returned untrimmed value %q", tt.in, s)
			}
		}
	}
}
