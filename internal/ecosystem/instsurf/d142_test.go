package instsurf

import (
	"strings"
	"testing"
)

// TestD142GapStringCarriesDetail: D-142 gave GapTruncated messages that name the
// specific bound that stopped ("go source files capped at 5000", "exports
// nesting capped at depth 8"). Gap.String dropped Detail, so every one of those
// messages reached the report as the bare reason word — the operator learned
// that SOME bound fired but not which, which is barely more actionable than the
// silence D-142 set out to remove.
func TestD142GapStringCarriesDetail(t *testing.T) {
	g := Gap{
		Package: "pkg:npm/x@1.0.0",
		Path:    "index.js",
		Reason:  GapTruncated,
		Detail:  "load-time sibling refs capped at 16 for index.js",
	}
	got := g.String()
	for _, want := range []string{string(GapTruncated), "pkg:npm/x@1.0.0", "index.js", "capped at 16"} {
		if !strings.Contains(got, want) {
			t.Errorf("Gap.String() = %q, missing %q", got, want)
		}
	}
}

// TestD142GapStringWithoutDetailIsUnchanged: a gap carrying no underlying error
// text must not grow a trailing separator.
func TestD142GapStringWithoutDetailIsUnchanged(t *testing.T) {
	g := Gap{Package: "pkg:npm/x@1.0.0", Path: "a.js", Reason: GapUnreadable}
	if got, want := g.String(), string(GapUnreadable)+": pkg:npm/x@1.0.0 (a.js)"; got != want {
		t.Errorf("Gap.String() = %q, want %q", got, want)
	}
}
