package datasource

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestImportSnapshotRoundTrips(t *testing.T) {
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "snapshot.json")

	entries := []SnapshotEntry{
		{
			Ecosystem: "npm", Name: "left-pad", Version: "1.3.0",
			Advisories: []Advisory{{ID: "MAL-2026-1", Malicious: true, Source: "osv"}},
		},
		{
			Ecosystem: "pypi", Name: "requests", Version: "2.31.0",
			Advisories: []Advisory{{ID: "CVE-2026-1", Summary: "example", Source: "osv"}},
		},
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshotPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	cache := NewCache(filepath.Join(dir, "cache"), 24*time.Hour)
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	// The import stamps entries with `now`, so the freshness read must use the
	// same clock. Without this the entry is written at a fixed date but judged
	// against the wall clock, so the test passed only while real time happened
	// to be within TTL of that date and began failing for good once it was not
	// — exactly the race Cache.Now exists to prevent.
	cache.Now = func() time.Time { return now }
	n, err := ImportSnapshot(cache, snapshotPath, now)
	if err != nil {
		t.Fatalf("ImportSnapshot: %v", err)
	}
	if n != 2 {
		t.Fatalf("imported %d entries, want 2", n)
	}

	adv, fresh, ok := cache.Get(Coord{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}.Key())
	if !ok {
		t.Fatal("left-pad@1.3.0 not found in cache after import")
	}
	if !fresh {
		t.Error("imported entry should be fresh under the cache's TTL")
	}
	if len(adv) != 1 || adv[0].ID != "MAL-2026-1" || !adv[0].Malicious {
		t.Errorf("left-pad advisories = %+v, want one malicious MAL-2026-1", adv)
	}

	adv2, _, ok := cache.Get(Coord{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}.Key())
	if !ok || len(adv2) != 1 || adv2[0].ID != "CVE-2026-1" {
		t.Errorf("requests advisories = %+v, want one CVE-2026-1", adv2)
	}
}

func TestImportSnapshotRejectsOversized(t *testing.T) {
	dir := t.TempDir()

	// A sparse file: fast to create (no real I/O for the payload), but its
	// logical size — what os.Stat reports and what the size guard checks —
	// is genuinely over the cap.
	hugePath := filepath.Join(dir, "huge.json")
	f, err := os.Create(hugePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSnapshotBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if _, err := ImportSnapshot(NewCache(dir, time.Hour), hugePath, time.Now()); err == nil {
		t.Error("expected an error importing a snapshot over the size cap")
	}

	if _, err := ImportSnapshot(NewCache(dir, time.Hour), filepath.Join(dir, "missing.json"), time.Now()); err == nil {
		t.Error("expected an error importing a nonexistent snapshot file")
	}

	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportSnapshot(NewCache(dir, time.Hour), badPath, time.Now()); err == nil {
		t.Error("expected an error importing malformed JSON")
	}
}

func TestImportSnapshotEmptyArray(t *testing.T) {
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(snapshotPath, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := ImportSnapshot(NewCache(filepath.Join(dir, "cache"), time.Hour), snapshotPath, time.Now())
	if err != nil {
		t.Fatalf("ImportSnapshot: %v", err)
	}
	if n != 0 {
		t.Errorf("imported %d entries from an empty array, want 0", n)
	}
}
