package registry

import "testing"

// TestParseCargoVersionsCapturesPublishedBy: crates.io is one of the two
// registries in the six-ecosystem pool that states who published each version.
func TestParseCargoVersionsCapturesPublishedBy(t *testing.T) {
	raw := []byte(`{"versions": [
	  {"num": "1.0.2", "created_at": "2026-03-01T00:00:00Z",
	   "published_by": {"id": 3618, "login": "dtolnay", "name": "David Tolnay"}},
	  {"num": "1.0.1", "created_at": "2026-02-01T00:00:00Z",
	   "published_by": {"id": 99, "login": "someone-else"}},
	  {"num": "1.0.0", "created_at": "2026-01-01T00:00:00Z", "published_by": null}
	]}`)

	h, err := parseCargoVersions("serde-like", raw)
	if err != nil {
		t.Fatalf("parseCargoVersions: %v", err)
	}
	if len(h.Releases) != 3 {
		t.Fatalf("releases = %d, want 3", len(h.Releases))
	}

	// The numeric account ID is the identity, not the login: crates.io logins
	// can be renamed, and a rename must not read as a publisher transition.
	p, ok := h.PublisherAt("1.0.2")
	if !ok {
		t.Fatal("1.0.2 has a published_by block but no publisher was recorded")
	}
	if p.ID != "3618" {
		t.Errorf("ID = %q, want the numeric account id 3618", p.ID)
	}
	if p.Name != "dtolnay" {
		t.Errorf("Name = %q, want the login", p.Name)
	}
	if p.Source != "crates.published_by" {
		t.Errorf("Source = %q, want the origin of the identity to be recorded", p.Source)
	}

	// null published_by — real, and common on older releases. Absent must stay
	// absent rather than being filled in from a neighbouring version.
	if _, ok := h.PublisherAt("1.0.0"); ok {
		t.Error("a null published_by must record no publisher")
	}

	prior := h.PriorPublishers("1.0.2")
	if !prior.Evaluable() {
		t.Fatal("history with a prior publisher must be evaluable")
	}
	if len(prior.Keys) != 1 || !prior.Seen("99") {
		t.Errorf("prior publishers = %v, want {99} (1.0.0 has none)", prior.Keys)
	}
	// 1.0.0 carries no published_by, so the history is PARTIAL: this is the
	// crates.io shape the review flagged, where most releases predate the field.
	if prior.Complete() {
		t.Error("a history with an unrecorded prior release must not report complete")
	}
	if prior.Unrecorded != 1 {
		t.Errorf("Unrecorded = %d, want 1", prior.Unrecorded)
	}
}

// TestOtherRegistriesRecordNoPublisher: RubyGems, Packagist, NuGet and PyPI
// expose no per-version uploader. The parsers must leave the map nil so the
// absence reads as coverage, never as continuity.
func TestOtherRegistriesRecordNoPublisher(t *testing.T) {
	gem, err := parseGemVersions("rake-like", []byte(
		`[{"number": "13.0.6", "created_at": "2026-01-01T00:00:00Z"}]`))
	if err != nil {
		t.Fatalf("parseGemVersions: %v", err)
	}
	if len(gem.Publishers) != 0 {
		t.Errorf("rubygems recorded publishers %v; the API exposes none", gem.Publishers)
	}
	if gem.PriorPublishers("13.0.6").Evaluable() {
		t.Error("a history with no publisher data must not be evaluable")
	}
}
