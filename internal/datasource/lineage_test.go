package datasource

import (
	"testing"
	"time"
)

func history(t *testing.T, versions ...string) *ReleaseHistory {
	t.Helper()
	h := &ReleaseHistory{Package: "acme-widget", Ecosystem: "npm"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, v := range versions {
		h.Releases = append(h.Releases, Release{Version: v, Published: base.AddDate(0, i, 0)})
	}
	h.Sort()
	return h
}

func TestPublisherKeyPrefersStableID(t *testing.T) {
	if got := (Publisher{ID: "3618", Name: "dtolnay"}).Key(); got != "3618" {
		t.Errorf("Key() = %q, want the stable ID: logins can be renamed and reused", got)
	}
	if got := (Publisher{Name: "stevemao"}).Key(); got != "stevemao" {
		t.Errorf("Key() = %q, want the login when no ID exists", got)
	}
	if !(Publisher{}).IsZero() {
		t.Error("an empty Publisher must report IsZero")
	}
}

func TestPublisherAtRequiresRealData(t *testing.T) {
	h := history(t, "1.0.0", "1.0.1")
	if _, ok := h.PublisherAt("1.0.0"); ok {
		t.Error("a history with no publishers must not report one")
	}

	h.Publishers = map[string]Publisher{
		"1.0.0": {ID: "alice", Name: "alice", Source: "npm._npmUser"},
		"1.0.1": {}, // present-but-empty must read as absent, not as an identity
	}
	if p, ok := h.PublisherAt("1.0.0"); !ok || p.Key() != "alice" {
		t.Errorf("PublisherAt(1.0.0) = (%+v, %v), want alice", p, ok)
	}
	if _, ok := h.PublisherAt("1.0.1"); ok {
		t.Error("an empty Publisher entry must read as absent")
	}
	if _, ok := (*ReleaseHistory)(nil).PublisherAt("1.0.0"); ok {
		t.Error("a nil history must not report a publisher")
	}
}

// TestPriorPublisherCoverageIsThreeStates is the DS-REV-04 guard. "No prior
// data", "partially recorded", and "fully recorded" are three different
// evidential positions, and the check that consumes this must be able to tell
// them apart — the middle one used to be reported as the last one.
func TestPriorPublisherCoverageIsThreeStates(t *testing.T) {
	h := history(t, "1.0.0", "1.0.1", "1.0.2")

	// None recorded: nothing can be said.
	got := h.PriorPublishers("1.0.2")
	if got.Evaluable() || got.Complete() {
		t.Errorf("no publisher data: Evaluable=%v Complete=%v, want both false",
			got.Evaluable(), got.Complete())
	}

	// Only the current version recorded: still nothing PRIOR to compare with.
	h.Publishers = map[string]Publisher{"1.0.2": {ID: "mallory"}}
	got = h.PriorPublishers("1.0.2")
	if got.Evaluable() || got.Recorded != 0 || got.Unrecorded != 2 {
		t.Errorf("got %+v, want no recorded priors and two unrecorded", got)
	}

	// Partially recorded: evaluable, but NOT complete. This is the case the
	// review found being treated as conclusive — the unknown 1.0.1 release
	// could have been mallory's.
	h.Publishers["1.0.0"] = Publisher{ID: "alice"}
	got = h.PriorPublishers("1.0.2")
	if !got.Evaluable() {
		t.Error("one recorded prior publisher must be evaluable")
	}
	if got.Complete() {
		t.Error("a history with an unrecorded prior release must NOT be complete")
	}
	if got.Recorded != 1 || got.Unrecorded != 1 {
		t.Errorf("got Recorded=%d Unrecorded=%d, want 1 and 1", got.Recorded, got.Unrecorded)
	}
	if !got.Seen("alice") || got.Seen("mallory") {
		t.Errorf("Keys = %v, want just alice", got.Keys)
	}

	// Fully recorded: only now does "never published before" hold.
	h.Publishers["1.0.1"] = Publisher{ID: "alice"}
	got = h.PriorPublishers("1.0.2")
	if !got.Complete() || got.Unrecorded != 0 {
		t.Errorf("got %+v, want a complete prior history", got)
	}

	// A version absent from the timeline cannot be positioned in it.
	if got := h.PriorPublishers("9.9.9"); got.Evaluable() {
		t.Error("an unknown version must not be evaluable")
	}
}

// TestPriorPublishersUsesTimelineOrderNotMapOrder: the answer must depend on
// publish time, not on Go map iteration.
func TestPriorPublishersUsesTimelineOrder(t *testing.T) {
	h := history(t, "1.0.0", "1.0.1", "1.0.2")
	h.Publishers = map[string]Publisher{
		"1.0.0": {ID: "alice"},
		"1.0.1": {ID: "bob"},
		"1.0.2": {ID: "carol"},
	}
	for range 20 {
		got := h.PriorPublishers("1.0.1")
		if !got.Evaluable() || len(got.Keys) != 1 || !got.Seen("alice") {
			t.Fatalf("prior publishers of 1.0.1 = %+v, want exactly {alice}", got)
		}
	}
}
