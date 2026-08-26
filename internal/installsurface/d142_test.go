package installsurface

import (
	"fmt"
	"strings"
	"testing"
)

// D-142: AnalyzeLoadTime followed at most maxLoadTimeRefs distinct sibling
// modules and then stopped with a bare break. The unread siblings were reported
// as nothing at all, so a package that split its payload across seventeen files
// looked exactly like one whose entry module was clean. Surface.Truncated now
// carries the bound out to the adapters, which turn it into a coverage gap.
//
// These live in package installsurface rather than beside the npm tests because
// the bound is unexported here; asserting against a copy of the number in
// another package would let the two drift apart silently.

func d142Refs(n int) string {
	var b strings.Builder
	b.WriteString("const cp = require('child_process');\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "require('./mod%d.js');\n", i)
	}
	return b.String()
}

func d142Read(string) ([]byte, bool) { return []byte("x"), true }

// TestD142LoadTimeRefCapDisclosed: more distinct siblings than the bound allows
// leaves some unread, and that must be said out loud.
func TestD142LoadTimeRefCapDisclosed(t *testing.T) {
	s := AnalyzeLoadTime("index.js", d142Refs(maxLoadTimeRefs+10), d142Read)
	if len(s.Truncated) == 0 {
		t.Fatal("exceeding the sibling-reference bound must be disclosed")
	}
	joined := strings.Join(s.Truncated, " ")
	if !strings.Contains(joined, "sibling refs") || !strings.Contains(joined, "index.js") {
		t.Errorf("disclosure should name the bound and the entry, got %v", s.Truncated)
	}
}

// TestD142LoadTimeExactCapIsNotTruncation is the false-positive boundary: an
// entry with exactly the bound's worth of siblings was read in full, so
// reporting it as truncated would attach a coverage gap to a complete analysis.
func TestD142LoadTimeExactCapIsNotTruncation(t *testing.T) {
	s := AnalyzeLoadTime("index.js", d142Refs(maxLoadTimeRefs), d142Read)
	if len(s.Truncated) != 0 {
		t.Errorf("exactly-at-bound is complete coverage, not truncation; got %v", s.Truncated)
	}
}

// TestD142LoadTimeDuplicateRefsAreNotTruncation: the same sibling mentioned many
// times is read once, so repetition alone must never trip the bound. This is the
// case that forced the check to sit after the empty/duplicate filters rather than
// at the top of the loop.
func TestD142LoadTimeDuplicateRefsAreNotTruncation(t *testing.T) {
	var b strings.Builder
	b.WriteString("const cp = require('child_process');\n")
	for i := 0; i < 200; i++ {
		b.WriteString("require('./same.js');\n")
	}
	s := AnalyzeLoadTime("index.js", b.String(), d142Read)
	if len(s.Truncated) != 0 {
		t.Errorf("repeated references to one sibling are not truncation, got %v", s.Truncated)
	}
}

// TestD142OrdinaryEntryDisclosesNothing: a handful of siblings, the real-world
// shape, must carry no truncation.
func TestD142OrdinaryEntryDisclosesNothing(t *testing.T) {
	s := AnalyzeLoadTime("index.js", d142Refs(3), d142Read)
	if len(s.Truncated) != 0 {
		t.Errorf("did not expect truncation for an ordinary entry, got %v", s.Truncated)
	}
}
