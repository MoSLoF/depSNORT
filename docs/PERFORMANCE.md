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

Numbers below are from a 4-core Intel Xeon @ 2.80GHz Linux x86-64 container,
Go 1.24.7, `CGO_ENABLED=0`.
**Treat the ratios as the signal, not the absolute nanoseconds** — those move
with hardware. A change that moves a ratio by more than ~20% deserves a look.

> The v0.7.3 baseline this replaces was measured on a 2-core container, so the
> ns/op columns are **not** comparable across the two releases. The `allocs/op`
> and `B/op` columns are hardware-independent and are the honest cross-release
> comparison — see "What the re-baseline confirmed" below.

## Baseline (v0.7.5)

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `ParseLock100` | 922,900 | 319,689 | 5,062 |
| `ParseLock1000` | 10,632,029 | 3,719,831 | 50,591 |
| `ParseLock5000` | 58,923,841 | 18,979,733 | 252,838 |
| `Coverage1000` | 669,865 | 157,912 | 24 |
| `CheckPipeline100` | 2,625,814 | 1,512,330 | 25,987 |
| `CheckPipeline1000` | 38,548,497 | 17,898,368 | 281,800 |
| `CheckPipeline5000` | 173,263,783 | 93,907,982 | 1,346,377 |
| `Verdict1000` | 1,376,273 | 434,955 | 386 |
| `EmitJSON1000` | 9,005,785 | 4,198,933 | 6,542 |
| `EmitSARIF1000` | 695,035 | 347,832 | 1,453 |
| `EmitPDF1000` | 2,861,856 | 768,042 | 8,858 |
| `ScanPipeline1000` | 49,551,105 | 23,340,239 | 288,759 |

Scaling is roughly linear in package count across all stages — parse 1000→5000
is 5.5x for 5x the packages, checks 1000→5000 is 4.5x. Nothing degrades
quadratically, which is the property actually worth guarding.

## What the re-baseline confirmed

Thirteen commits landed between v0.7.3 and v0.7.5, including PyPI transitive-depth
reconstruction, PEP 517 build-backend analysis, wheel `.pth` recovery, tiered OSV
fallback, and the SARIF coverage block. The allocation profile is the evidence
that none of it regressed these paths: `allocs/op` is **within 3 allocations of
the v0.7.3 baseline on every single benchmark**, and identical on five of the
twelve. Since allocation counts do not move with hardware, that is a real
cross-release comparison in a way the timings are not.

The one deliberate, visible change is `EmitSARIF1000`: +2 allocs/op and
+1,665 B/op. That is the `invocations[].toolExecutionNotifications` block added
so a SARIF-only consumer can tell a degraded scan from a clean one — the cost of
emitting coverage facts SARIF previously dropped. It is the intended trade.

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
