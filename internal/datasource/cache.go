package datasource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Cache is a simple content-addressed on-disk advisory cache. It is what makes
// a scan deterministic and air-gap-capable (Decision D-09): a populated cache
// plus offline mode yields identical verdicts with no network.
type Cache struct {
	Dir string
	TTL time.Duration // entries older than TTL are stale (still usable offline)
	// Now supplies the clock for freshness checks. Injected so that staleness is
	// deterministic under test — writes and reads must agree on "now", or a
	// cache-hit test becomes a race against the wall clock.
	Now func() time.Time
}

// now returns the cache's clock, defaulting to time.Now.
func (c *Cache) now() time.Time {
	if c != nil && c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// entry is the on-disk record for one coordinate.
type entry struct {
	FetchedAt  time.Time  `json:"fetched_at"`
	Advisories []Advisory `json:"advisories"`
}

// NewCache returns a cache rooted at dir. dir is created lazily on Put.
func NewCache(dir string, ttl time.Duration) *Cache {
	return &Cache{Dir: dir, TTL: ttl}
}

func (c *Cache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.Dir, hex.EncodeToString(sum[:])+".json")
}

// Get returns the cached advisories for key. fresh reports whether the entry is
// within TTL. ok reports whether any entry exists.
func (c *Cache) Get(key string) (adv []Advisory, fresh, ok bool) {
	if c == nil || c.Dir == "" {
		return nil, false, false
	}
	raw, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false, false
	}
	var e entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false, false
	}
	fresh = c.TTL <= 0 || c.now().Sub(e.FetchedAt) < c.TTL
	return e.Advisories, fresh, true
}

// rawEntry is the on-disk record for an arbitrary cached document (e.g. an npm
// packument). Kept distinct from entry so the two cache users cannot collide on
// shape; their keys are already disjoint.
type rawEntry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Data      json.RawMessage `json:"data"`
}

// GetRaw returns a cached raw document for key.
func (c *Cache) GetRaw(key string) (data []byte, fresh, ok bool) {
	if c == nil || c.Dir == "" {
		return nil, false, false
	}
	b, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false, false
	}
	var e rawEntry
	if err := json.Unmarshal(b, &e); err != nil || len(e.Data) == 0 {
		return nil, false, false
	}
	fresh = c.TTL <= 0 || c.now().Sub(e.FetchedAt) < c.TTL
	return e.Data, fresh, true
}

// PutRaw writes a raw document for key, stamping the fetch time.
func (c *Cache) PutRaw(key string, data []byte, now time.Time) error {
	if c == nil || c.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(rawEntry{FetchedAt: now, Data: json.RawMessage(data)})
	if err != nil {
		return err
	}
	return os.WriteFile(c.path(key), b, 0o644)
}

// Put writes advisories for key, stamping the fetch time. now is injected so
// callers stay testable/deterministic.
func (c *Cache) Put(key string, adv []Advisory, now time.Time) error {
	if c == nil || c.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(entry{FetchedAt: now, Advisories: adv})
	if err != nil {
		return err
	}
	return os.WriteFile(c.path(key), raw, 0o644)
}
