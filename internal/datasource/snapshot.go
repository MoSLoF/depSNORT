package datasource

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// maxSnapshotBytes bounds a snapshot file read. A snapshot legitimately
// carries many packages' advisories (unlike a single repo-derived file), so
// the cap is generous headroom against a malformed or hostile file rather
// than a tight per-record limit — 64 MiB of advisory JSON is tens of
// thousands of packages' worth.
const maxSnapshotBytes = 64 << 20

// SnapshotEntry is one coordinate's advisories in a portable, offline-import
// format. It exists so a caller — a CI runner or sandboxed container image
// with no path to api.osv.dev — can bootstrap the on-disk Cache that
// -offline reads from, without hand-constructing the cache's internal
// sha256-keyed file layout.
type SnapshotEntry struct {
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Advisories []Advisory `json:"advisories"`
}

// ImportSnapshot reads a JSON array of SnapshotEntry from path and writes
// each into c, stamped with now. It returns the number of entries imported.
//
// This is metadata import, not package execution — consistent with the
// zero-execution ethos (Decision D-04) the same way fetching from OSV is.
// The imported records are indistinguishable, once written, from ones a
// live OSV query would have produced: -offline reads the same cache either
// way (Decision D-09).
func ImportSnapshot(c *Cache, path string, now time.Time) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("datasource: snapshot %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("datasource: snapshot %s: not a regular file", path)
	}
	if info.Size() > maxSnapshotBytes {
		return 0, fmt.Errorf("datasource: snapshot %s: %d bytes exceeds %d byte limit", path, info.Size(), maxSnapshotBytes)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("datasource: snapshot %s: %w", path, err)
	}

	var entries []SnapshotEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return 0, fmt.Errorf("datasource: snapshot %s: %w", path, err)
	}

	for _, e := range entries {
		coord := Coord{Ecosystem: e.Ecosystem, Name: e.Name, Version: e.Version}
		if err := c.Put(coord.Key(), e.Advisories, now); err != nil {
			return 0, fmt.Errorf("datasource: snapshot %s: writing %s: %w", path, coord.Key(), err)
		}
	}
	return len(entries), nil
}
