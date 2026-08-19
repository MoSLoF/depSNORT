package registry

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// coordFetcher is the per-coordinate metadata plumbing shared by the deps
// clients (PyPI requires_dist, Cargo dependencies): cache-first, then
// bounded-parallel network, with deterministic error selection (D-13) and
// Stats accounting. Each client supplies only what differs — its cache key, its
// URL fetch, and how to parse a response — so the concurrency and the
// coverage bookkeeping live in exactly one place.
type coordFetcher struct {
	cache    *datasource.Cache
	offline  bool
	now      func() time.Time
	cacheKey func(datasource.Coord) string
	fetch    func(context.Context, datasource.Coord) ([]byte, error)
}

// fetchCoords resolves each coordinate and parses it with parse, which also
// reports a per-response count of entries it could not read (an edge silently
// missing from the graph — kept in Stats.UnparsedEntries, D-24). It returns the
// per-coord results keyed by Coord.Key(), the updated Stats, and the
// deterministically-chosen first error if any coordinate hard-failed.
func fetchCoords[T any](f coordFetcher, ctx context.Context, coords []datasource.Coord, parse func([]byte) ([]T, int, error)) (map[string][]T, datasource.Stats, error) {
	now := f.now
	if now == nil {
		now = time.Now
	}
	out := make(map[string][]T, len(coords))
	stats := datasource.Stats{Queried: len(coords), Offline: f.offline}

	var misses []datasource.Coord
	for _, coord := range coords {
		if raw, fresh, ok := f.cache.GetRaw(f.cacheKey(coord)); ok && (fresh || f.offline) {
			if items, unparsed, err := parse(raw); err == nil {
				out[coord.Key()] = items
				stats.FromCache++
				stats.UnparsedEntries += unparsed
				continue
			}
		}
		if f.offline {
			stats.Gaps++
			continue
		}
		misses = append(misses, coord)
	}
	if len(misses) == 0 {
		return out, stats, nil
	}

	type result struct {
		coord    datasource.Coord
		items    []T
		unparsed int
		raw      []byte
		err      error
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		errsBy  = map[string]error{}
		sem     = make(chan struct{}, concurrency)
		results = make([]result, len(misses))
	)
	for i, coord := range misses {
		wg.Add(1)
		go func(i int, coord datasource.Coord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			raw, err := f.fetch(ctx, coord)
			if err != nil {
				results[i] = result{coord: coord, err: err}
				return
			}
			items, unparsed, err := parse(raw)
			results[i] = result{coord: coord, items: items, unparsed: unparsed, raw: raw, err: err}
		}(i, coord)
	}
	wg.Wait()

	for _, r := range results {
		if r.err != nil {
			if errors.Is(r.err, ErrNotFound) {
				stats.NotFound++
				continue
			}
			stats.Gaps++
			mu.Lock()
			errsBy[r.coord.Key()] = r.err
			mu.Unlock()
			continue
		}
		out[r.coord.Key()] = r.items
		stats.FromNet++
		stats.UnparsedEntries += r.unparsed
		_ = f.cache.PutRaw(f.cacheKey(r.coord), r.raw, now())
	}
	if len(errsBy) > 0 {
		sorted := make([]string, 0, len(errsBy))
		for k := range errsBy {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		return out, stats, errsBy[sorted[0]]
	}
	return out, stats, nil
}
