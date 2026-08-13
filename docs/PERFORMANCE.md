# Performance baselines

Recorded so that "is this change slower?" has an answer. Without a committed
baseline, performance regressions are only ever noticed by the person whose
CI job started timing out.

Reproduce with:

```
go test ./cmd/depsnort/ ./internal/ecosystem/npm/ -run=XXX -bench=. -benchmem
```

## Method

The committed fixtures are deliberately small (the npm `realworld` lockfile is
69 lines), so benchmarking against them would measure nothing a real monorepo
would recognize. The benchmarks synthesize graphs instead:

- **Parse** — a generated `package-lock.json` of N packages, each fanning out to
  the next three, with `hasInstallScript` on ~1 in 17.
- **Check pipeline / verdict / emit** — a graph of N packages where ~1 in 17
  declares an install hook carrying capabilities, each hook hanging a fetched
  artifact (and ~1 in 51 a credential sink) off itself, so risk propagation has
  a real install-time subgraph to walk.

Numbers below are from a 2-core Linux x86-64 container, Go 1.24, `CGO_ENABLED=0`.
**Treat the ratios as the signal, not the absolute nanoseconds** — those move
with hardware. A change that moves a ratio by more than ~20% deserves a look.

## Baseline (v0.7.3)

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `ParseLock100` | 997,281 | 319,689 | 5,062 |
| `ParseLock1000` | 14,276,145 | 3,719,960 | 50,591 |
| `ParseLock5000` | 70,913,611 | 19,017,608 | 252,841 |
| `Coverage1000` | 764,500 | 157,912 | 24 |
| `CheckPipeline100` | 3,118,701 | 1,512,315 | 25,988 |
| `CheckPipeline1000` | 38,069,071 | 17,897,833 | 281,799 |
| `CheckPipeline5000` | 180,914,790 | 93,907,224 | 1,346,375 |
| `Verdict1000` | 1,493,961 | 434,954 | 386 |
| `EmitJSON1000` | 9,583,681 | 4,276,595 | 6,546 |
| `EmitSARIF1000` | 700,335 | 346,167 | 1,451 |
| `EmitPDF1000` | 2,923,333 | 766,133 | 8,858 |
| `ScanPipeline1000` | 51,131,513 | 23,338,538 | 288,762 |

Scaling is roughly linear in package count across all stages — parse 1000→5000
is 5.0x for 5x the packages, checks 1000→5000 is 4.8x. Nothing degrades
quadratically, which is the property actually worth guarding.

## What the first baseline found

Profiling `CheckPipeline1000` put `osaDistance` — the edit-distance function
behind typosquat detection (VC-006) — at **~71% of the entire check pipeline's
CPU**, allocating a rune slice per call. VC-006 compares every package name
against the whole popular-name corpus but only ever acts on distance 1 or 2, so
the full matrix was computed and discarded for nearly every comparison. (The
function's own doc comment claimed a "bounded early-exit" that was never
implemented.)

`osaDistanceBounded` adds a ceiling: two names whose lengths differ by more than
the ceiling cannot be within it, since each edit changes length by at most one —
decided without allocating a matrix or even a rune slice. Measured effect:

| Benchmark | before | after | change |
|---|---:|---:|---|
| `CheckPipeline1000` | 66,380,004 ns | 38,069,071 ns | **1.74x faster** |
| `CheckPipeline1000` allocs | 460,192 | 281,799 | **39% fewer** |
| `CheckPipeline1000` memory | 32.9 MB | 17.9 MB | **46% less** |
| `CheckPipeline5000` | 322,388,224 ns | 180,914,790 ns | **1.78x faster** |
| `ScanPipeline1000` (end to end) | 87,551,483 ns | 51,131,513 ns | **1.71x faster** |

The optimization is behavior-preserving, and that claim is tested rather than
asserted: `FuzzBoundedMatchesExact` is a differential fuzz target holding the
bounded implementation against the exact one (1.18M executions clean), plus a
table test over the real near-miss pairs the corpus tests care about
(`lodash`/`lodahs`, `commands`/`commander`, `password`/`passport`).

`EmitJSON` costing ~13x `EmitSARIF` is expected, not a defect: the JSON emitter
renders the entire graph including every node attribute, while SARIF carries
only findings.
