package osv

import (
	_ "embed"
	"encoding/json"
	"sync"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// bundled_snapshot.json ships INSIDE the binary itself — the last tier of the
// OSV lookup chain (cache -> live query -> this -> gap), consulted only when
// neither a cached nor a live answer exists. It exists so a scan in a
// network-restricted sandbox or CI runner gets real known-malicious-package
// coverage on a first run, not an empty cache and a silent gap.
//
// It carries no assumed freshness: BundledLookup returns the dataset's own
// generation time alongside every hit, and the caller (Client.QueryBatch) is
// required to surface that on datasource.Stats.BundledDatasetAt whenever it's
// used, so a bundled-sourced finding is never mistaken for a live check. A
// real, non-malicious package does not become "checked clean" by appearing
// here — it is simply not present, and falls through to a normal gap like
// any other coordinate this dataset doesn't cover.
//
// Regenerate with scripts/refresh-bundled-snapshot.sh (needs live network —
// see docs/RELEASING.md). This file starts EMPTY; it is not populated by
// this session, which has no path to a live advisory source to seed it from
// honestly.
//
//go:embed bundled_snapshot.json
var bundledSnapshotRaw []byte

// bundledFile is the embedded dataset's on-disk shape: the same
// datasource.SnapshotEntry records -osv-snapshot imports, wrapped with a
// generation timestamp.
type bundledFile struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	Entries     []datasource.SnapshotEntry `json:"entries"`
}

var (
	bundledOnce sync.Once
	bundledMeta bundledFile
	bundledIdx  map[string][]datasource.Advisory
)

func loadBundled() {
	bundledOnce.Do(func() {
		bundledIdx = map[string][]datasource.Advisory{}
		if err := json.Unmarshal(bundledSnapshotRaw, &bundledMeta); err != nil {
			// A malformed embed is a build-time defect (this file is compiled
			// into the binary, not read from a hostile checkout) — fail
			// closed to "no fallback available" rather than let a bad build
			// panic on every scan.
			return
		}
		for _, e := range bundledMeta.Entries {
			coord := datasource.Coord{Ecosystem: e.Ecosystem, Name: e.Name, Version: e.Version}
			bundledIdx[coord.Key()] = e.Advisories
		}
	})
}

// BundledLookup returns the compiled-in fallback advisories for key and the
// dataset's generation time, when key is present in the embedded dataset.
func BundledLookup(key string) (adv []datasource.Advisory, generatedAt time.Time, ok bool) {
	loadBundled()
	adv, ok = bundledIdx[key]
	return adv, bundledMeta.GeneratedAt, ok
}
