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

// TestPriorPublishersKnownFlag is the guard that keeps the actor axis honest:
// a package whose earlier releases carry no publisher data cannot support the
// claim "this publisher is new".
func TestPriorPublishersKnownFlag(t *testing.T) {
	h := history(t, "1.0.0", "1.0.1", "1.0.2")

	if _, known := h.PriorPublishers("1.0.2"); known {
		t.Error("no publisher data at all must report known=false")
	}

	// Only the CURRENT version has a publisher: nothing to compare against.
	h.Publishers = map[string]Publisher{"1.0.2": {ID: "mallory"}}
	if keys, known := h.PriorPublishers("1.0.2"); known || len(keys) != 0 {
		t.Errorf("keys=%v known=%v; history with no prior publishers must be unevaluable", keys, known)
	}

	h.Publishers["1.0.0"] = Publisher{ID: "alice"}
	h.Publishers["1.0.1"] = Publisher{ID: "alice"}
	keys, known := h.PriorPublishers("1.0.2")
	if !known {
		t.Fatal("history with prior publishers must be evaluable")
	}
	if len(keys) != 1 || !keys["alice"] {
		t.Errorf("prior publishers = %v, want {alice}", keys)
	}
	if keys["mallory"] {
		t.Error("the version under test must not be included in its own prior set")
	}

	// A version absent from the timeline cannot be positioned in it.
	if _, known := h.PriorPublishers("9.9.9"); known {
		t.Error("an unknown version must report known=false")
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
		keys, known := h.PriorPublishers("1.0.1")
		if !known || len(keys) != 1 || !keys["alice"] {
			t.Fatalf("prior publishers of 1.0.1 = %v (known=%v), want exactly {alice}", keys, known)
		}
	}
}
