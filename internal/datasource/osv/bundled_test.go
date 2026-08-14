package osv

import "testing"

// The shipped bundled_snapshot.json starts empty (this repo has no live
// network access to seed it honestly) — confirm the loader handles that
// cleanly rather than panicking or fabricating a hit.
func TestBundledLookupOnEmptyDataset(t *testing.T) {
	adv, _, ok := BundledLookup("npm|left-pad|1.3.0")
	if ok {
		t.Errorf("BundledLookup on the empty shipped dataset returned ok=true, adv=%+v", adv)
	}
}
