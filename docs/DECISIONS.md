# depSNORT — Decision Log

Mirrors the project design brief. Each decision is
load-bearing; the code is annotated with the `D-0x` tags below so the rationale
travels with the implementation.

| ID | Decision |
|----|----------|
| **D-01** | **Resolution:** lockfile-first; consume deps.dev for manifest-only inputs; do **not** reimplement per-ecosystem resolvers. (Reimplementing npm/PyPI resolvers is a multi-year SAT sinkhole.) |
| **D-02** | **Dual-tree model:** an install hook is an undeclared manifest; extract and graph the hook subgraph as a **peer** of the declared tree. Node kinds and edge types for both trees exist from day one. |
| **D-03** | **Extraction vs judgment seam:** adapters emit graph **facts** (nodes/edges); checks emit **judgments** (Findings). The graph is immutable from a check's perspective; only `verdict` writes risk state. |
| **D-04** | **Static-only / zero-execution:** never install, never run a lifecycle hook. Detect hook presence + indirection, not payload semantics — detecting obfuscation is itself the finding. |
| **D-05** | **Typed verdicts:** FLAG vs WARN separated at the type level; every Finding carries `gate_class ∈ {block, gate-eligible, advisory}`. Node **color** (RiskState) and exit-code **semantics** (GateClass) are distinct axes. |
| **D-06** | **Proximity ⇒ advisory-WARN, never gates** — a structural guarantee enforced in `verdict.Evaluate`, not a config default. High recall in the report; high precision at the gate. |
| **D-07** | **Neo4j = emitter,** not a runtime dependency. The scanner stays a standalone, dependency-light static binary; the graph is an output artifact. |
| **D-08** | **Ecosystem abstraction** (`ecosystem.Adapter`) in place from day one. npm first, PyPI second to prove the seam, then RubyGems/Cargo/Composer/NuGet to cover all major install-time attack surfaces. |
| **D-09** | **CLI is the primitive;** CI-gate and pre-commit are thin wrappers. Exit contract: `0` clean/advisory-only · `1` block · `2` gate-eligible-if-opted-in · `64` usage · `70` internal. Output is deterministic. |
| **D-10** | **Language: Go** — the toolchain executes no package-authored code at build time, and it produces a single hash-pinned, zero-install-hook static binary. The tool embodies its own thesis. |

## Notes carried into code

- `internal/finding` — the `GateClass` type and `Finding.Score` (severity ×
  confidence × recency_decay) implement D-05 and the false-positive discipline.
- `internal/graph` — `NodeKind` and `EdgeType` enumerate both trees (D-02).
- `internal/ecosystem` — the `Adapter` contract's doc comment is the D-04 /
  D-03 guarantee in prose; `InstallSurfaceExtractor` is the stable step-5 seam.
- `internal/verdict` — the `switch` that derives the exit code is the D-06
  never-gate guarantee. It is covered by `TestAdvisoryNeverGates`.
- `internal/installsurface` — D-02 and D-04 in code: hooks and the files they
  reference become graph facts; capability classification stops at "what can
  this chain touch", never "what does the payload mean".

## D-11 — one heuristic is promoted to block-class

Added at step 5. `block` is otherwise reserved for deterministic set-membership
(D-05), but **VC-002d** — an install hook that references *named* credentials
**and** has network egress — is promoted to `block`. It is the ChainDrop
credential-harvesting signature, and no legitimate install hook needs registry
or cloud secrets.

The precision that earns the promotion is upstream: bare `process.env` is
classified as the weaker `env` capability, never `credentials`, so native-build
hooks (which legitimately read env and fetch prebuilt binaries) cannot reach
this rule. `TestAnalyzeBenignNativeBuildIsNotCredentialed` and the `depsnort-fixture-native`
fixture guard that boundary; if either ever fails, the promotion is unsafe and
VC-002d should drop to `gate-eligible` until precision is restored.

## D-12 — recency decay governs gating, not just ranking

Added after the first live run. Scanning ten real outdated packages surfaced a
genuine release burst in `tar@4.4.13` — four releases in two days against a
four-day cadence. Factually correct, and a benign 2019 security patch wave.

Its decay was ~0, so it *scored* zero — but its gate-class was still
`gate-eligible`, meaning `-fail-on-eligible` would break a build today over
seven-year-old news. Decay governed ranking but not gating.

`verdict.applyRecencyDemotion` closes that: a temporal finding whose
`RecencyDecay` falls below `StaleFloor` (0.15, ≈2.7 half-lives) is demoted to
`advisory`. It is **demoted, never dropped** — it stays in the report with the
demotion recorded in its evidence, because silent suppression is the same sin as
a silent cap. `block` findings are never demoted: a poisoned release does not
become safe with age.

## D-13 — determinism is enforced, not hoped for

Also from the live run. Two offline scans of identical data produced different
bytes, violating the reproducible-CI-gate requirement (D-09). Two causes, both
now fixed and both covered by tests:

1. **Map iteration order.** A lockfile's `packages` object decodes into a Go
   map, whose iteration order is deliberately randomized. Ranging it directly
   leaked that randomness into edge insertion order. The npm resolver now walks
   sorted keys, and `graph.SortedEdges()` is the emit-layer guarantee — emitters
   must use it rather than raw `Edges`.
2. **False precision in decay.** `RecencyDecay` derives from `time.Now()`, so
   consecutive scans differed in the 9th decimal. `Decay` now quantizes age to
   whole days: with a 90-day half-life, sub-day resolution is meaningless, and
   quantizing makes a scan stable for the whole day.

`TestResolveIsDeterministic` runs the resolver twelve times and byte-compares;
`TestDecayIsQuantizedToWholeDays` pins the quantization.

## D-14 — findings aggregate per package, not per advisory

The same live run produced 67 findings across ten packages — 25 on `axios` alone
— burying every supply-chain signal under CVE noise. The gate was unaffected
(vuln findings are advisory and never gate), but a report nobody can read is its
own failure mode.

VC-008 now emits one finding per package with the advisory count in the title and
the IDs in the evidence, capped at 8 listed with the remainder disclosed as
`+N more`. Same data, 67 findings down to 11.

## D-15 — the ecosystem seam, verified (and re-verified)

D-08 claimed the ecosystem abstraction was in place "from day one". Adding PyPI
tested that claim. Result: the graph model, PURL identity, check contract,
verdict engine, and all four emitters were reused **unchanged**. Only a parser
and name normalization were new. A live cross-ecosystem run resolved 90 real OSV
advisories against a Python tree, and the npm-registry source correctly sat out
(queried 0) because it filters on ecosystem.

Adding four more ecosystems (RubyGems, Cargo, Composer, NuGet) re-confirmed
this at scale. Each adapter needed only a lockfile parser — the capability
scanner, VC-002 check family, verdict engine, and emitters worked unchanged.
Composer additionally implements `InstallSurfaceExtractor` with on-disk
analysis from `vendor/`, proving the seam works for both remote-fetch (PyPI
sdist) and local-read (npm node_modules, Composer vendor) strategies.

Two leaks were found and closed rather than papered over:

- **Identity.** PyPI names must be normalized per PEP 503 before becoming a
  PURL, or `Flask_SQLAlchemy` and `flask-sqlalchemy` become two nodes and the
  transitive dedupe silently fails. NuGet names are lowercased for the same
  reason. Composer uses vendor/package as a namespace/name split.
- **Ecosystem-blind checks.** VC-006 scored every package against the npm
  typosquat corpus. Left alone it would have compared Python names to JavaScript
  names and produced confident nonsense. The corpus is now selected per
  ecosystem via `corpusFor`, and a package in an ecosystem with no corpus is
  skipped rather than mis-scored. Same principle applies to VC-007 (npm-only):
  it declines when it lacks data.

VC-004/VC-005 are now ecosystem-agnostic: a shared `registry.Client` extracts
the cache/fetch/concurrency machinery, and each ecosystem plugs in a `Spec`
(endpoint URL, URL builder, response parser). npm uses its own packument client
(the `time` map requires custom handling); the other four — RubyGems, crates.io,
Packagist, NuGet — share the generic client with per-ecosystem parse functions.

The general rule this establishes: a check that reads ecosystem-specific data
must dispatch on `Node.Ecosystem` and **decline** when it has no basis to judge.
Silence is correct; guessing is not.

## D-16 — fixture names must be verified non-existent

Found when a user's live scan of the `wormy` fixture reported **two** block
findings instead of one. The extra was `VC-001: known-malicious release
(MAL-2026-6374)` against `evil-pkg@1.0.0` — the fixture's own package name.

`evil-pkg` turned out to be a **real npm package carrying a real malware
advisory**, published 2026-06-23 with six versions. The synthetic fixture had
silently collided with live registry and OSV data, so its results depended on
external state: different online vs offline, and liable to change again if that
package is ever unpublished. A fixture whose behaviour is a function of the
internet is not a fixture.

Fixture packages are now `depsnort-fixture-*`, verified 404 on both the npm
registry and OSV at the time of writing, and the lockfile records the incident so
the constraint is not lost. Any new fixture name must be checked the same way.

Worth keeping in view, though: the collision was also the tool's **first true
positive against live malware data**. VC-001 matched a genuine `MAL-` advisory
end to end, through the real OSV path, with no seeding. The detection logic was
right; only the test data was wrong.

## D-17 — VC-006 calibrated against real-world false positives

The first scan of a real 58-repo workspace (5,370 packages) produced **43 VC-006
findings, every one a false positive**: `preact`, `color`, `through`, `tslint`,
`scapy`, `@vitest/utils` and similar. A check with a 100% FP rate is worse than
no check — it trains the operator to ignore the report.

Three failure modes, all now closed, with the observed output pinned at zero by
`TestVC006NoFalsePositivesOnRealWorkspace`:

1. **Scoped packages were scored on their bare name.** `@vitest/utils` was
   compared to `util`. A scoped package is not impersonating an unscoped one —
   the scope is explicit provenance. Scoped names are now skipped. This alone
   accounted for roughly 20 of the 43. Scope-squatting (`@babeI/core` for
   `@babel/core`) is a genuine but *different* attack requiring scope-to-scope
   comparison; it is left uncovered rather than covered badly.
2. **Legitimate near-neighbours.** Real packages that genuinely sit one edit from
   a popular name. Handled by an evidence-driven allowlist in `legitimate.go` —
   entries come from observed false positives, never from speculation.
3. **Distance-2 on short-ish names.** `commands`/`commander` and
   `password`/`passport` are unrelated words two edits apart. The minimum length
   for a distance-2 match rose from 8 to 10.

A fourth rule was added from first principles: **provenance by association**. A
typosquat is something a human mistypes into a manifest, so it arrives as a
direct dependency. A package pulled in *by* an established package is vouched
for — nobody typos their way into someone else's transitive tree.

The general lesson: a heuristic check cannot be calibrated against fixtures
alone. This one looked fine on synthetic data and was useless on real data, and
only a scan of a genuine workspace revealed it.

## D-18 — root devDependencies are part of the tree

A scan of a real 59-repo workspace reported **2,687 of 5,371 packages at depth
0** — unreachable from any root. Inspection showed ~100 orphaned nodes with no
inbound edge, 86% of them marked `direct`, and every sample was a devDependency:
`@angular/cli`, `@playwright/test`, `@biomejs/biome`.

The npm resolver built edges from `dependencies` and `optionalDependencies` only.
Root devDependencies therefore got nodes but no edges, and each stranded its
entire transitive subtree — roughly half the graph.

Correct npm semantics, now implemented: the **root project's** devDependencies
are installed and produce edges; a **dependency's** devDependencies are never
installed downstream and must not. Both directions are pinned by tests. The
lockfile's own `dev` marker is additionally recorded as `npm.dev` on the node, so
a consumer can weight dev-only exposure differently from runtime without the
resolver making that policy call.

Why it mattered beyond cosmetics: depth was wrong for half the graph, and the
provenance-by-association rule added in D-17 depends on inbound edges — a
stranded subtree cannot be vouched for by its parent, so the fix also restores
that check's accuracy.

**Follow-on, same root cause.** The devDeps fix took orphans from 100 to 14, and
the survivors named the next gap: `konva` beside `react-konva`,
`@react-three/fiber` beside `drei`, `monaco-editor`. All **peerDependencies** —
which npm 7+ installs automatically, making them real edges. That field was not
parsed either. Now it is, for every entry rather than the root alone, since a
peer is required wherever it is declared.

The pattern across D-18: edge completeness cannot be verified against small
fixtures. Every missing relation type looks fine until a real tree exposes an
unreachable subtree. The standing check is orphan count — any non-root package
with no inbound edge is a resolver gap until proven otherwise.

## D-19 — VC-005 recalibrated: a burst alone is advisory

The first full network run over a real 59-repo workspace produced **176
gate-eligible VC-005 findings**, dominated by ordinary release trains:
`@angular/*` ships ~20 packages together several times a week, and `vite`,
`undici`, `picomatch` release on similar cadences. With `-fail-on-eligible` set,
a build would have failed because Angular shipped a patch.

The original anomaly test was `median > 24h` — a bar nearly every maintained
package clears. Two corrections:

1. **A burst only matters on a slow package.** The cadence floor rose from 24h
   to 7 days, and the cluster must additionally reach 3x the release count that
   cadence predicts for the window. A package shipping weekly or faster is
   expected to cluster, so the observation carries no information.
2. **A burst ALONE is advisory, never gating.** This is the design brief's own
   composition principle applied honestly: release bursts are common and benign;
   what is not benign is a burst on a package that *also runs install-time code*.
   Gate-eligible is now earned only by that composition.

The general lesson, and the third instance of it in this project: a temporal
heuristic cannot be calibrated against synthetic history. Real registry data is
far burstier than intuition suggests.

## D-20 — the report caps advisory volume, and says so

The same run produced 1,460 findings across a **224-page PDF**. Correct, and
unreadable — which is its own failure mode (see D-14, the same lesson at smaller
scale).

The report now prints a by-check summary line before the detail, shows **every**
block and gate-eligible finding (those are actionable and are never capped), and
lists only the highest-scoring advisory findings, disclosing the remainder:
"*N further advisory finding(s) are not listed here … the complete set is in the
JSON output*". The JSON emitter is never capped.

Capping without disclosure would be exactly the silent truncation this tool
treats as a defect elsewhere; the cap is therefore stated in the artifact rather
than left for the reader to infer from a page count.

## D-21 — VC-004 is bounded by recency, not just by gap length

The second full workspace run fired VC-004 **687 times** — roughly a fifth of
every package with registry data. The thresholds were not the problem; the scope
was. The check flagged any gap over a year *anywhere* in a package's release
history, including gaps that closed half a decade ago.

That is climate history, not weather. A mature library that sat still for two
years and then shipped a maintenance release in 2019 is evidence of stability.
If you are pinned to that release, the awakening is long since settled and
nothing about it is a signal today.

VC-004 now applies a recency floor of `dormancyMinDecay = 0.15`, deliberately
equal to `verdict.StaleFloor`. D-12 says a stale temporal finding loses the right
to gate; D-21 applies the same reasoning one step earlier and says it is not a
finding at all. The axis is "recent-compromise weather" (brief §4) — an old
awakening is out of scope by definition rather than suppressed after the fact.

## D-22 — the package risk table lists risk, not inventory

The PACKAGE RISK table rendered a row per package. On a 5,371-package workspace
that is ~80 pages of the word CLEAN, and it buried the 34 rows a reader actually
needed.

The table now lists only packages carrying at least one finding, states the
count of clean packages it omitted, and caps the at-risk rows with the same
disclosure discipline as D-20. Inventory belongs in the JSON and the graph
export; the PDF is a briefing document and should read like one.

## D-23 — VC-005 inherits the D-21 recency floor

The v0.3.1 run still produced 92 VC-005 findings. Parsing the publish dates back
out of the evidence strings showed why: **82 of the 92 described bursts that had
already decayed out of relevance** — 38 aged one to three years, 37 older than
three years, and the oldest, `commondir@1.0.1`, a release cluster from **June
2015** being reported as supply-chain weather in August 2026.

This is D-21's defect in a different file. Writing a fix for VC-004 and not
carrying it to the other check on the same axis is exactly the kind of omission
a modular check design invites, so it is recorded rather than quietly patched.

`burstMinDecay` is 0.15 — the same value as `dormancyMinDecay` and
`verdict.StaleFloor`. One constant, three checks, one meaning: below it, a
temporal event is history rather than weather. The floor sits UPSTREAM of the
install-hook escalation, so a decade-old burst on a hooked package cannot reach
gate-eligible by composition. 92 findings become 10.

A false hypothesis is worth recording too: the first theory was that `@types/*`
packages were driving the count via DefinitelyTyped's batch publisher. Measured,
`@types` was 22 of 92 (24%) and 2 of 37 VC-004 hits. The theory was plausible,
specific, and wrong, and checking it cost one script.

## D-24 — resolution coverage is a first-class verdict axis

`redtiger-tools` declares 33 dependencies in an unpinned `requirements.txt`.
depSNORT resolved one node — the root — ran zero checks against zero
packages, and printed **`PASSED`, exit 0, zero findings**. The PyPI adapter had
recorded the gap honestly in a node attribute; the verdict layer never read it.

This is the inverse of the failure mode the brief warns about, and it is worse.
A tool that cries wolf gets muted. A tool that cries all-clear over something it
never read gets *trusted*. `browser-cookie3` and `keyboard`, unpinned, is exactly
the shape a supply-chain IDS exists to have an opinion about.

Coverage is therefore promoted to a second axis alongside risk, carrying the same
separation of concerns as D-05: what we saw and what we could not see are
different questions with different answers.

- Adapters record coverage as ECOSYSTEM-NEUTRAL graph facts
  (`depsnort.unresolved`, `depsnort.unresolved_count`, `depsnort.flat_resolution`),
  so the verdict layer reads them without knowing which resolver ran. Extraction
  still never judges (D-03).
- `Coverage.Degraded` — we failed to see something we should have — is distinct
  from `Coverage.Complete`. A flat lockfile format is a limitation of the format,
  not a resolver defect; treating every `Pipfile.lock` as degraded would be its
  own warning tax.
- The report banner states `INCOMPLETE` and the count before anything else, and
  the CLI warns on stderr regardless of exit code. `RESOLUTION COVERAGE` renders
  above the findings, because what the scan could not see bounds every conclusion
  under it.
- Exit code 3 exists but requires `-fail-on-incomplete`. Coverage is always
  reported and gates only on opt-in — the same discipline advisory findings get
  under D-06. Precedence is block, then gate, then coverage: act on what was
  found before acting on what was missed.

## D-22 (corrected) — the risk table orders by actionability

D-22 excluded clean packages but left the survivors in alphabetical order. On the
real workspace that meant 394 at-risk rows capped at 60, and the 60 that
survived were dominated by eighteen `@types/d3-*` entries while `esbuild`,
`sharp`, `bcrypt` and `ssh2` — every one of them named as gate-eligible in the
findings section on page one — fell past the cut, purely because `e` sorts after
`@t`.

A cap over an arbitrary ordering is not a summary; it is a coin flip with a
disclosure attached. Rows now sort by gate class, then risk state, then composed
score descending, with name as the tiebreak only.

The same run exposed a smaller asymmetry: the PDF ranked and capped by
`Finding.Score()` while the JSON omitted it, so a consumer had to reconstruct the
report's own ordering from severity, confidence and prose. `Finding` now
marshals `score` alongside its inputs. The uncapped record must carry the key it
was ordered by.

## D-25 — the hook scanner reads code, not documentation, and obfuscation must be assembly

The first real-`node_modules` run pointed VC-002 at `esbuild@0.21.5` — the
canonical sketchy-but-legitimate installer: it downloads a prebuilt binary and
execs it. Two false signals came back.

**VC-002b cited comment URLs.** The finding's conclusion was correct (esbuild
does `fetch()` the npm registry), but three of the four hosts it "reached" —
`snapcraft.io`, `nodejs.org/dist/`, a github issue link — were scraped out of a
comment block explaining the Snap Store sandbox. The npm path harvested URLs
with `urlRe` over the raw file; the Python path had already learned to strip
documentation, the npm path never did. A finding that names `snapcraft.io` as
egress when it lives in a comment is the kind of sloppiness that gets a tool
muted, and in a malicious package an attacker could bury a real C2 under a pile
of innocent comment URLs. Referenced-file source is now run through
`stripCodeComments` (block + line, with the `://` guard so URL schemes survive)
before any marker or URL scan.

**VC-002e fired on one incidental `String.fromCharCode`.** The whole obfuscation
verdict rested on a bare-substring marker, and esbuild uses `fromCharCode` once,
to format a single dash. That is not obfuscation. `fromCharCode` is removed from
the substring table and replaced with `charCodeAssemblyRe`, which requires
ASSEMBLY — `.apply`, three-or-more literal codes, or a map/reduce over
`fromCharCode` — the shape of a payload being built, not a byte being formatted.
The structural decode detectors (`decodeRe`, `blobRe`, obfuscated-scheme,
wildcard-exe) were already the real teeth; this aligns the weak marker with them.

Both are the same lesson every heuristic in this project has taught: fixtures are
clean, and the first genuinely legitimate-but-scary package finds the loose
match. The regression test pins esbuild's exact shape from both sides — no
obfuscation, no comment URLs in the remotes, but the real registry fetch and the
real exec still detected — plus a char-code-assembly-into-eval control so the
fix cannot quietly become a blind spot.

## D-26 — install-surface extraction is wired for every ecosystem, not just npm/pypi/composer

Validating v0.5.1 against a real adversarial corpus — before adding features —
exposed the worst class of defect this tool can have. Six planted fixtures were
scanned; **four produced zero findings**: `cargo-buildrs-exfil`,
`gem-extconf-payload`, and (latent, untested) any NuGet install script. The
dependency trees resolved fine. The install-time code was simply never read.

The cause was not a weak heuristic — it was no heuristic at all. `AnalyzeRust`,
`AnalyzeRuby`, and `AnalyzeDotNet` existed in `installsurface`, with the cargo
and gem adapters even *documenting* the `build.rs` / `extconf.rb` attack vector
in their package comments — but no adapter ever called them. Three of six
ecosystems implemented `ExtractInstallSurface`; the other three did not, so the
engine's interface assertion skipped them and their install surface went
unexamined. Dead code that reads as coverage is a false all-clear, which is
exactly the failure the brief forbids (§6): a scanner that stays silent on a
crate's `build.rs` is worse than no scan, because silence reads as "clean."

The fix wires the three orphaned analyzers into their adapters:

- cargo reads the root crate's `build.rs`; gem reads `extconf.rb` (root and
  `ext/*/`) plus the gemspec; nuget reads `install.ps1` / `init.ps1`.
- Scope is the root package, matching npm/pypi: transitive crates and gems are
  not on disk in a source checkout, so their scripts are left unrepresented
  rather than guessed at.
- A new shared `instsurf.AddToGraph` materializes the surface, ending the
  copy-paste of npm's ~60-line wiring block. npm/pypi/composer predate it and
  keep their inline copies; everything after D-26 goes through the helper.

The false-positive discipline is preserved structurally: a `build.rs` or
`extconf.rb` with no network / credential / obfuscation capability produces no
finding, because native builds are ordinary and flagging every one is the tax
that gets a tool muted. Only the composed capabilities gate.

The regression corpus (`instsurf/wiring_test.go`) now scans a
credential-plus-network hook in each of the three ecosystems and asserts it
BLOCKS, plus an ordinary build script that must stay silent — so no future
refactor can let one of these ecosystems go quiet again without failing CI.

Two narrower gaps the same run surfaced remain open and tracked separately:
`composer-plugin-cradle` resolves through `AnalyzePHP` (which reads only the
composer.json scripts map and package type, not plugin PHP source), and
`pypi-pth-persistence` has no `.pth` on disk in a source checkout (only in
installed site-packages). Both are documented limitations, not silent misses.

## D-27 — composer reads the root manifest and the plugin entrypoint

`composer-plugin-cradle` was the last real attack shape the adversarial corpus
left silent. On inspection it was silent for a blunter reason than "we can't
read PHP": the composer adapter returned early from all install-surface
extraction whenever `vendor/` was absent — so on any un-installed checkout it
never opened the root project's own `composer.json`, and the fixture's payload
(a `certutil -urlcache` download cradle in `post-install-cmd`) was never seen.
The vendor guard, meant to skip *transitive* source that only exists after
`composer install`, was skipping the *root* too.

The fix has two parts:

  1. The root project's `composer.json` is now always read from the project
     directory, independent of `vendor/` — mirroring how npm and pypi handle
     their root. Transitive packages still require `vendor/` to be present,
     because their source genuinely is not on disk until installed. This alone
     moves the fixture from silent to VC-002b (the cradle's network egress).

  2. A composer-plugin's declared entrypoint (`extra.class`) is now resolved
     through the package's PSR-4 autoload map and its PHP source is scanned like
     any other hook body. A plugin's `activate()` runs on every Composer
     operation, so it is install-time code even when no lifecycle script is
     declared — and a cradle that hides its fetch-and-run in the plugin class,
     rather than in a script, is now caught. `AnalyzePHP` gained a
     `pluginSource` parameter; when the source cannot be resolved the bare
     CapExec fallback stands, so a plugin is recorded as "present, source
     unread" rather than downgraded to clean. PHP source is comment-stripped
     before scanning, per D-25.

False-positive discipline holds structurally: an ordinary composer-plugin with
a benign entrypoint and no scripts exhibits only CapExec, which no VC-002 check
gates on. Only composed capabilities — network, credentials, obfuscation —
produce a finding.

Corpus result: the adversarial set is down to a single silence,
`pypi-pth-persistence`, which is the documented boundary from D-26 (a `.pth`
file exists only in installed site-packages, never in a source checkout) rather
than a defect. The certutil cradle lands as VC-002b (network) rather than a
block because it is ingress-and-execute, not credential exfil; promoting
fetch-then-execute download cradles to a higher gate is a separate calibration,
noted but not made here.

## D-28 — a download cradle blocks; an ordinary binary download does not

The composer cradle exposed a gap in the gate model: `certutil -urlcache … &&
payload.exe` was landing at gate-eligible VC-002b, the same tier as esbuild
fetching a prebuilt binary. Those are not the same act. esbuild pulls a *shipped*
binary from a known host; a cradle fetches code off the network and runs it in
the same breath — the initial-access primitive.

VC-002f promotes the cradle to block-class, but only on a signal narrow enough
that esbuild never trips it: a fetch piped straight into an interpreter
(`curl … | sh`, `iex (New-Object Net.WebClient).DownloadString(…)`), or a LOLBin
pull (`certutil -urlcache`, `bitsadmin /transfer`). Plain `network + exec` is
deliberately NOT the trigger — that is esbuild's shape and stays advisory. The
new `CapCradle` capability carries the signal; VC-002b defers to VC-002f when it
is present, so a cradle produces one authoritative block, not a block plus a
redundant network warning.

## D-29 — VC-003: the operator's IOC ledger is a first-class, block-class source

VC-003 was reserved from the brief for the operator's own indicator ledger and
was the last unbuilt check. It is not a heuristic: an entry is the operator
saying "I have confirmed this is bad," so a match blocks with confidence 1.0.
The value the tool adds is fan-out — one confirmed indicator, matched across an
entire transitive tree where a human would never catch it by eye.

Rather than couple depsnort to a proprietary ledger format, the seam is an
exported feed: a stable, documented JSON schema (`docs/ioc-ledger.example.json`)
that the operator points `-ioc` at. Matching is by most-specific identity — exact
PURL, then ecosystem+name+version, then ecosystem+name (any version) — so the
ledger can pin a single poisoned release or condemn a package outright. The feed
is loaded and matched onto the graph by the orchestrator; the check reads the
result. No ledger supplied → VC-003 is silent.

## D-30 — the CI gate and pre-commit hook are thin wrappers, as promised

D-09 declared the CI gate and pre-commit hook thin wrappers over the CLI's
exit-code contract; D-30 delivers them and keeps that promise — no logic lives in
them that the CLI does not already own. `scripts/depsnort-ci-gate.sh` emits SARIF
for a CI security tab and an optional dated PDF, and exits on the depsnort
contract (1 block, 2 gate-eligible with opt-in, 3 incomplete with opt-in).
`scripts/depsnort-pre-commit.sh` hard-fails a commit only on block by default, so
day-to-day work is not held hostage by advisory CVE noise, with
`FAIL_ON_ELIGIBLE=1` to tighten and `--no-verify` as the documented escape.
`scripts/github-actions.example.yml` wires it into Actions with SARIF upload.
Both honor `-ioc`, so the operator's ledger gates every pipeline run.

## D-31 — a front door: banner + pip install

Cosmetic, and deliberately so — a tool people are meant to run should announce
itself. `depsnort`, `depsnort version`, and `depsnort banner` now print a
bright-red block-letter "depSNORT" (figlet "block" font — dashes, per the house
style) over the purple-team intent line `$global:Intent = 'Purple'`. Color is
emitted only to a terminal and suppressed under NO_COLOR, so `scan` output —
JSON, SARIF, the report tree — never gets escape codes. The banner is a Go
concern (single source of truth); no other code path prints it.

`pip install depSNORT` now works via a thin packaging shim (`pyproject.toml` +
`setup.py`): a setuptools build hook compiles the static Go binary (D-10) into
the wheel, and a `depsnort` console script execs it unchanged. The engine stays
Go; Python is only a launcher, so there is one implementation, not two. The Go
toolchain is a build-time requirement — consistent with a project whose whole
identity is a single dependency-free static binary.

## D-32 — external technical review (v0.6.1): six findings remediated

An independent architecture / security-boundary review of the public v0.6.1
repository raised six findings (two Critical, three High, one Moderate). All six
were confirmed against the code and fixed; each fix ships with regression tests
that fail on the old behavior.

**F-01 (Critical) — the pre-commit gate did not gate.** `depsnort-pre-commit.sh`
ran the scanner as an `if` condition and read `$?` *after* `fi`. A completed
if-statement with a false condition and no else returns 0, so a block-class
finding (scanner exit 1) was captured as 0 and the commit sailed through. Fixed
with the direct `rc=0; scanner || rc=$?` form the CI gate already used, plus a
`FAIL_ON_INCOMPLETE` pass-through. `scripts/wrapper_test.sh` stubs the scanner at
each exit code (0/1/2/3/64/70) and asserts the block-vs-pass mapping on sh, bash,
and dash.

**F-02 (Critical) — incomplete-coverage gated on graph facts only.** The verdict
received `graph.Coverage()`, whose `Degraded` flag is derived solely from
unresolved dependencies and orphaned nodes. An empty OSV cache, a failed
registry source, an unreadable install surface, or a workspace project that never
resolved were all warned to stderr and dropped — none could reach exit 3, so
`-fail-on-incomplete` could still return a clean 0 over a scan that barely
looked. That directly contradicted the README's own guarantee. Fixed by
extending `graph.Coverage` with scan-level gap fields
(`DataSourceGaps`/`ExtractorGaps`/`FailedProjects`) and an `Incomplete()` method
that folds them in with graph resolution; the CLI populates them and calls the
new `verdict.EvaluateWithCoverage`, which gates on `Incomplete()`. Precedence is
unchanged and central: block > gate-eligible > incomplete. The PDF verdict banner
and the stderr warning now report every gap class, so reports and exit codes
agree. Proven end-to-end: an offline empty OSV cache returns exit 0 with a
warning by default and exit 3 under `-fail-on-incomplete`.

**F-03 (High) — local reads could cross the repository boundary.** The npm
adapter did lexical `..`/absolute containment but never resolved symlinks;
Composer built `vendor/` and PSR-4 paths from untrusted lockfile / composer.json
content with no canonical check; the other adapters read via bare path joins. A
hostile checkout could steer a read out of the scan root through a symlink or a
crafted name. Fixed with one primitive, `internal/securefs`: it rejects absolute
and traversal inputs, resolves symlinks and re-checks containment on the
canonical path, refuses non-regular files, and caps per-file size. Every
ecosystem's install-surface read (npm, PyPI, RubyGems, Cargo, Composer, NuGet)
now routes through it. Regression fixtures cover `..` escapes, absolute paths,
and file/directory symlink escapes — rejected — while contained symlinks and
legitimate in-tree reads still succeed.

**F-04 (High) — the wheel was mislabeled platform-independent.** `setup.py`
compiles an OS/arch-specific Go binary into the wheel but declared no native
code, so setuptools produced a `py3-none-any` wheel that an index would offer to
incompatible platforms. Fixed with a `bdist_wheel` override that marks the
distribution impure and pins the platform tag while keeping the Python tag broad
(`py3-none-<platform>`) — the launcher is interpreter-agnostic, the binary is
not. Verified: the built wheel is `...-py3-none-linux_x86_64.whl`,
`Root-Is-Purelib: false`, and the embedded binary runs.

**F-05 (High) — sdist processing lacked cumulative hostile-input controls.** The
PyPI sdist path capped compressed size and per-file size but did not verify the
PyPI-declared SHA-256, cap total decompressed bytes, cap tar entry count, or cap
retained `.pth` count/size, and it returned partial extraction as success on a
malformed tar. Fixed: the artifact is read once and its SHA-256 verified before
any byte is trusted; decompressed-total, entry-count, and `.pth` count/size caps
are enforced; a truncated or corrupt tar is now a returned error (a coverage gap
via F-02), never a clean partial. Redirect destinations are constrained to PyPI
content hosts. Fixtures cover bomb, entry-flood, truncation, digest mismatch, and
the `.pth` caps.

**F-06 (Moderate) — CI, versioning, and disclosure maturity.** Added
`.github/workflows/ci.yml` (gofmt, vet, `go test -race`, static build, the
zero-dependency dogfood check, the pre-commit wrapper contract on sh+bash,
cross-platform build matrix, and a wheel-tag assertion) and `release.yml`
(checksummed cross-platform binaries on a tag). Actions are patch-pinned and
tracked by `.github/dependabot.yml`. The version is single-sourced from
`pyproject.toml` — the Makefile and `setup.py` read it and inject it via
`-ldflags`, and `main.version` defaults to `dev` so an un-injected build never
claims a release number. `SECURITY.md` now documents a private disclosure
channel (GitHub private vulnerability reporting) and response expectations.

Remaining, by the reviewer's own sequencing (production-adoption tail, needs
operator decisions): signed provenance / Sigstore attestation, a published SBOM,
parser fuzzing, and performance baselines.

## D-33 — closing the production-adoption tail: fuzzing, baselines, SBOM, provenance

The v0.6.1 review (D-32) left a 60–90 day tail — parser fuzzing, performance
baselines, a published SBOM, and signed provenance. Taken together they are the
difference between "the tests we thought to write pass" and "we went looking for
what we did not think of." Two of the four found real defects, which is the
argument for doing them rather than deferring them again.

**Fuzzing found two identity bugs.** Sixteen native Go fuzz targets now cover all
six lockfile parsers, the PURL identity layer, semver, the five install-surface
analyzers, the sdist tar reader, and path containment. Two genuine defects
surfaced in `internal/purl`, which matters more than it first sounds: node
identity across the entire tool IS the PURL string — the graph dedupes on it,
IOC ledger entries key on it, and cross-repo blast radius is computed by merging
equal ones.

  1. *Normalization drifted.* `Parse` consumed a trailing `@` as a version
     separator even with no version after it, and `String` never re-emitted it,
     so `pkg:npm/@@@@@@@` lost one character per round trip. A value that is
     supposed to be a stable identity was not a fixed point.
  2. *A crafted name could forge structure.* Because `@` was written raw, a
     package literally named `lodash@4.17.21` with no version rendered the exact
     PURL of the real `lodash@4.17.21` — an identity collision a hostile lockfile
     could mint deliberately, and equally a way to slip past an IOC ledger entry
     keyed on a PURL. `/` could likewise forge a namespace segment, and an
     invalid type (`pkg:0@/@`) produced a PURL that would not re-parse at all.

  Fixed by percent-encoding the structural characters (`@`, `/`, `%`) within each
  component, decoding on parse in a single left-to-right pass so `%2540` decodes
  to `%40` and never to `@`, refusing to treat a trailing `@` as a separator, and
  validating the type against the spec's charset. Canonical output for real
  packages is unchanged — npm scopes live in the namespace and Composer vendors
  are split off, so no legitimate name contains these characters — and the
  existing round-trip and scope tests still pass untouched. `TestCraftedName*`
  pins the injection cases.

  The containment fuzzer is the one worth keeping honest about: it asserts a
  security property, not the absence of a panic. A sentinel file and a symlink to
  it are planted outside the scan root, and any input that causes a read to
  return that sentinel fails the test. 1.2M executions clean.

**Performance baselines found the hot spot.** `docs/PERFORMANCE.md` records
committed numbers for parse, checks, verdict, and every emitter, measured against
synthesized graphs at 100/1000/5000 packages, because benchmarking against a
69-line fixture measures nothing real. Profiling put `osaDistance` — the edit
distance behind typosquat detection — at ~71% of the entire check pipeline's CPU.
VC-006 compares every package name against the whole popular-name corpus but only
ever acts on distance 1 or 2, so a full matrix was computed and thrown away for
nearly every comparison. (Its doc comment had claimed a "bounded early-exit" that
was never implemented — the comment was aspirational.)

  `osaDistanceBounded` takes a ceiling and exploits the fact that each edit
  changes length by at most one, so two names whose lengths differ by more than
  the ceiling cannot be within it — decided without allocating a matrix or even a
  rune slice. The row-minimum early exit deliberately requires TWO consecutive
  rows above the ceiling, because an OSA transposition advances two rows at once
  and can skip one; checking a single row would be unsound. Result: the check
  pipeline is **1.74x faster** with 46% less memory, and an end-to-end scan
  **1.71x faster**. Behavior-preservation is tested, not asserted:
  `FuzzBoundedMatchesExact` is a differential target holding the optimized form
  against the reference one (1.18M executions clean).

**The SBOM is self-describing.** `depsnort sbom` emits CycloneDX 1.5 built from
`runtime/debug.BuildInfo` — the module graph the linker actually embedded — so it
cannot drift from the binary the way a maintained manifest would. It is also the
machine-checkable form of the dogfood invariant (D-10): the `components` array is
empty, and CI fails if a third-party dependency ever appears. No timestamp and a
name-based UUIDv5 serial keep it byte-reproducible per D-13, so two people can
independently rebuild a tag and diff the result.

**Provenance is keyless.** Releases are signed with Sigstore through the
workflow's GitHub OIDC identity and attested with SLSA build provenance, binding
each artifact digest to the repository, workflow, and commit that produced it.
There is no long-lived key for a solo maintainer to protect or rotate, and the
attestation lands in the public Rekor transparency log; consumers verify with
`gh attestation verify`. The release workflow also refuses to publish a tag whose
version disagrees with `pyproject.toml`, which is the drift F-06 warned about
made impossible rather than merely discouraged.

Version single-sourcing is now complete: `pyproject.toml` is the one place, and
the Makefile, `setup.py`, the Go binary, the wheel tag, the SBOM, and
`py/depsnort/__init__.py` (via installed distribution metadata) all derive from
it. Released as v0.7.0 — the `sbom` command is new surface, and D-32's exit-3
behavior plus this PURL canonicalization are behavior changes that a patch bump
would have understated.

## D-34 — follow-up review: refusals and caps must fail closed

The follow-up review of the v0.7.0 candidate confirmed F-01 through F-04 closed
and F-06 substantially addressed, and raised three residual findings. Two were
the same defect wearing different clothes, and it is the defect this project
exists to prevent: **a safety mechanism that protects the process while quietly
discarding evidence.**

A correction to D-32's framing first, because the reviewer was right to call it
out: that entry read as though the remediation was complete. It was not. F-05 was
partial — the bounds were added, but several of them failed OPEN — and F-03
closed the filesystem boundary without closing the accounting behind it. The
disposition below is the accurate one.

**R-01 — a containment refusal was indistinguishable from an absent file.** The
adapters consumed securefs errors with the same `if err == nil` they use for a
file that is legitimately not on disk. So the refusal was correct and invisible:
the unsafe read did not happen, and neither did any record of it. Reproduced end
to end before fixing — an npm package whose directory is a symlink pointing out
of the repo, containing a `curl … | sh` plus `.npmrc` read, produced
`complete: true`, zero findings, **exit 0 under -fail-on-incomplete**, and a
silent stderr. That is attacker-triggerable invisibility: an attacker who cannot
make depsnort read outside the scan root can instead make the evidence
unreadable, and be rewarded with a clean bill of health.

  Fixed with typed gaps (`internal/ecosystem/instsurf/gaps.go`). `os.ErrNotExist`
  remains an ordinary absence — a pre-install tree has no `node_modules` and most
  crates ship no `build.rs`, so gating on that would make the signal worthless.
  Everything else (`ErrOutsideRoot`, `ErrNotRegular`, `ErrTooLarge`, parse
  failure, other I/O) becomes a `Gap` carrying package, path, and reason. All six
  adapters record them; the CLI counts each one, summarizes by reason, and
  carries a bounded detail sample into the report — the COUNT is never capped,
  only the per-item list. The same fixture now exits 3 and says
  `containment-refusal x1` with the path.

**R-02 — hostile-input caps converted attacks into clean partial results.** Most
serious was the per-file read: `io.LimitReader(tr, maxFileSize)` returns exactly
the cap with NO error, so an oversized `setup.py` was silently truncated. Pad
2 MiB of comments, put the payload after the cut, and the analyzer scans a clean
prefix and reports nothing — a direct detection bypass. Now the reader takes
`maxFileSize+1` and fails on overflow. Alongside it: the sdist origin URL comes
from index metadata and was fetched unchecked (only redirects were validated), an
absent digest DISABLED verification rather than failing, `.pth` content past the
retention caps was silently dropped, and a final oversized entry escaped the
decompression guard through EOF. All five now fail closed as coverage gaps.

**R-03 — release trust metadata.** Actions are moving to immutable commit SHAs
with the version kept as a trailing comment; `scripts/pin-actions.sh` resolves
them through the GitHub API (never a hardcoded table, which would go stale) and
`--check` fails CI if any reference regresses to a mutable tag. The release SBOM
is now generated with `sbom -release`, which omits host-specific GOOS/GOARCH and
declares its scope: only one of five platform binaries can be executed to produce
an SBOM, so stamping its platform onto a document that accompanies the other four
was a misstatement. The dependency graph is identical across targets, and that is
what the document now describes.

**On the tests themselves.** The reviewer noted the F-02 coverage tests injected
a prebuilt `graph.Coverage` and asserted the exit code — which proves the policy
but not the plumbing, and therefore could never have caught R-01. There are now
end-to-end tests that build real hostile checkouts on disk, run the real CLI, and
assert the process exit code and emitted JSON: symlink escape, special file,
oversize manifest, and unparseable manifest each reach `complete: false` and exit
3, an absent optional package stays clean at exit 0, a gap is reported but does
not gate without opt-in, and a block still outranks a gap.

Counts corrected while here: there are **19** fuzz targets, not the 16 D-33
claimed, and CI actively fuzzes **9** of them; the performance baseline is
labelled v0.7.0.

## D-35 — the last fail-open path, and fewer things to trust

Third review pass. R-01 confirmed closed; R-02 and R-03 partially. Both residuals
were the same shape one more time, which is worth naming: **every remaining
defect in this project has been a bound that protected the process while quietly
discarding evidence.** Not one has been a missing check. They have all been
checks that, on failing, returned something that looked like good news.

**The declared-oversize sdist.** `findSdistURL` selected an sdist only when its
metadata size was at or below the cap. An sdist that existed but declared a
larger size was skipped, the loop fell through to the wheel-only return, and
`Fetch` recorded `WheelOnly=true` — an ordinary, expected, entirely benign state
— then CACHED it and reported no gap. An attacker did not even need to publish a
large file; declaring a large size in index metadata was enough to make their
install surface invisible behind a clean result.

  "No sdist exists" and "an sdist exists but we declined to fetch it" are
  different facts and no longer collapse. If every candidate exceeds the cap the
  fetch returns `ErrSdistTooLarge`, which the adapter aggregates as a gap and the
  CLI turns into exit 3. A package that genuinely publishes only wheels still
  reports wheel-only and stays clean, and a listing containing both an oversized
  and a usable sdist still analyzes the usable one — tested, because a fix that
  gates on ordinary wheel-only packages would be worse than the bug.

**Cache semantics are versioned.** The sdist cache key now carries a semantics
version. Records written by an earlier build were produced under fail-open rules
— a silently truncated `setup.py`, `.pth` content dropped past the retention cap,
an unverified digest, an oversized sdist stored as wheel-only — and reusing them
after an upgrade would let the old weaker analysis survive as a cached clean
result. The bump invalidates them wholesale. It is bumped whenever a change
alters what a cached record is allowed to MEAN, not merely its shape.

**Fewer things to trust, rather than more things labelled trusted.** The action
pinning finding had an answer better than pinning: the release publish step now
uses the preinstalled `gh` CLI instead of a third-party action, so no external
code runs with `contents: write` in the workflow that builds and signs releases.
There is nothing left to pin there because there is nothing left. Every remaining
reference is GitHub first-party `actions/*`, `make pin` resolves them through the
GitHub API, and CI fails on any that regress to a mutable tag.

Two SHAs were resolved and applied here (`actions/checkout`,
`actions/setup-python`); `actions/setup-go` and `actions/attest-build-provenance`
were left as tags because the API could not be reached to verify them at the time
of writing. That is deliberate: a plausible-looking but unverified SHA in the
workflow that signs releases is worse than an honest tag, because it manufactures
confidence instead of stating a gap. `make pin` closes it in one command against
the live API.

**Refusal tests now cover every adapter, not just npm.** The end-to-end CLI
fixtures remain npm-focused; each other ecosystem gets an adapter-level pair —
a planted symlink where its install-time file belongs must produce a
containment gap, and an ordinary absence must not. Writing them immediately paid
for itself: the new containment check on RubyGems' `ext/` enumeration treated a
NONEXISTENT `ext/` as a refusal, which would have gated every clean Ruby project.
The absence-vs-refusal distinction is easy to state and easy to get backwards,
which is exactly why both halves are asserted per ecosystem.

## D-36 — R-03 closed: every action pinned, and a drift guard so it stays that way

The fourth review pass accepted the R-01/R-02 remediation outright and left a
single blocker: two workflow actions (`setup-go`, `attest-build-provenance`) were
still mutable tags, so the repository's own `pin-check` failed. This closes it.

All four workflow actions are now pinned to immutable commit SHAs with version
comments:

  - `actions/checkout@11bd719…` (v4.2.2)
  - `actions/setup-go@0a12ed9…` (v5.0.2)
  - `actions/setup-python@f67713…` (v5.2.0)
  - `actions/attest-build-provenance@1c608d1…` (v1.4.3)

A note on how those SHAs were obtained, because the principle running through
this whole engagement is *never put an unverified SHA in the workflow that signs
releases*: the container's egress to GitHub's API was rate-limited, so rather
than pin from memory — which manufactures confidence — each SHA was resolved
against GitHub's own `git/ref` API (with a Gitea mirror as an independent
cross-check for setup-go, which agreed byte-for-byte). `make pin` re-resolves
them against the authenticated API on any maintainer's machine, and a wrong SHA
would fail the workflow loudly on first run rather than silently. There is also
no third-party publisher left to trust: the release step uses the runner's `gh`
CLI, so nothing external runs with `contents: write`.

The pin invariant is now enforced two ways that cannot drift apart (R-03 P2):
`scripts/pin-actions.sh --check` runs as a CI job, and
`internal/ciactions/pin_test.go` runs in `go test ./...` — it parses every
workflow, asserts each action reference is a 40-char SHA with a `# vX` comment,
and fails vacuously-empty matches. Writing it immediately earned its place by
pointing at the one remaining tag before it was fixed.

Two more P2 items landed. The adapter refusal matrix now covers three securefs
reasons per ecosystem, not just symlink escape: `TestAdapterNonRegularInstallFileIsAGap`
plants a directory where each adapter expects its install-time file and asserts a
`not-a-regular-file` gap, and the JSON adapters get a parse-failure gap case — an
adapter could plausibly handle one refusal reason and swallow another, so each is
asserted independently. And `docs/RELEASING.md` writes the release sequence down,
including the rule that is easiest to forget because it has no immediate symptom:
bump `sdistSemantics` whenever a change alters what a cached extraction record is
allowed to MEAN.

Released as v0.7.3 — the completed hardened release. Every original finding
(F-01…F-06) and every residual (R-01…R-03) is closed and covered by a test that
fails if it regresses.

## D-37 — one registry, or the corpus lies

The v0.7.3 reconciliation turned up a failing adversarial test that had been
failing for several releases: `TestAttack_ComposerPluginCradle` reported **zero**
findings against a `certutil -urlcache -split -f … && payload.exe` install hook —
a textbook LOLBin download cradle, and exactly the shape D-28 says must block.

Nothing was wrong with the detection. `AnalyzePHP` set `cradle` correctly, and the
shipping binary blocked the attack with VC-002f at critical/block. The corpus was
blind: `runChecks` in `testdata/adversarial` hand-rolled its own five-check
registry, written before VC-002f existed and never updated. And because VC-002b
*deliberately* stands down when the cradle capability is present — D-28's
"report it once, at the higher gate class" rule — removing VC-002f from the
registry removed the finding entirely rather than downgrading it. The two
mechanisms combined to convert a correct block into a silent miss, and then the
test asserted `VC-002b`, an ID that by construction can only appear when the
cradle is NOT detected. The assertion could only ever pass on a regression.

Two registries is the bug. `builtin.Default()` is now the single registration
point; `checkRegistry()` in the CLI and `runChecks` in the corpus both call it.
`TestDefaultRegistersEveryCheck` parses this package's own source, finds every
type with a `Meta()` method, and fails if one is not registered — the same
source-walking drift guard as `internal/ciactions/pin_test.go`, applied to
checks. Adding a check is now one step, and forgetting is loud.

The general lesson is worth stating plainly, because it will recur: a regression
corpus that constructs its own copy of production wiring is not testing
production. It is testing a replica that decays.

## D-38 — the public tree is generated, not maintained

The sterile repo published to `github.com/MoSLoF/depSNORT` was produced by hand
from this working tree. That worked exactly once. By v0.7.3 the two trees had
drifted in nine files, the v0.7.0–v0.7.3 work existed only as loose archives with
no commit behind it, and a `v0.7.3` tag had been created pointing at the v0.6.1
commit. Two of the archives that were reviewed and approved as release candidates
did not compile — each had dropped a different subset of files during
repackaging, and the review that blessed them was performed against a
reconstruction rather than a repo.

The public tree is now **generated**: `scripts/make-public.sh` copies this tree
minus `publish/exclude.txt`, resolves `PRIVATE` / `PUBLIC:` line sentinels,
applies `publish/redact.txt`, overlays `publish/overlay/`, and then refuses to
finish if any pattern in `publish/forbidden.txt` survives in the output. It
earned its keep on the first run by catching an internal designation in the
`source` field of `docs/ioc-ledger.example.json` — a marker the manual process
had missed and that was live in the public repo. It is now handled by a
substitution rule rather than by remembering.

The sentinel pair is the mechanism that avoids a second copy of any file. A line
tagged `PRIVATE` never ships; a line tagged `PUBLIC:` is inert here and
uncommented there. Only files that diverge structurally — `NOTICE.md`, `LICENSE`,
`SECURITY.md` — live in `publish/overlay/`.

The rule that follows: **never edit the public repo.** It is build output. Change
this tree, re-run the script, and commit what it produces.

One correction during review, worth recording because it is the same class of
mistake the script exists to prevent. `gofmt` was invoked as
`command -v gofmt && gofmt -w "$OUT" || true` — optional, and failure-swallowing.
It is neither. Unwrapping a `// PUBLIC:` line preserves that line's own
indentation, which sits one tab deeper than the statement it replaces, because
gofmt indents a continuation comment to match its continuation. gofmt is what
puts it back. A reviewer generating on a machine without the Go toolchain got a
tree that passed the leak check, reported success, and differed from the reviewed
candidate by two indentation characters in `internal/emit/pdf.go`.

A reproducibility tool that degrades quietly when a dependency is missing is
worse than no tool, because it launders an unverified artifact as a verified one.
The script now refuses to start without gofmt, treats a gofmt failure as fatal,
asserts `gofmt -l` is empty afterwards, and prints the toolchain version into the
generation log so the evidence records what produced the tree.

## D-39 — v0.7.5: the release the version file already claimed

Two releases' worth of work shipped under one version number, because the tag
and the version literal drifted apart without anything noticing.

`pyproject.toml` was bumped to `0.7.4` and a lightweight `v0.7.4` tag was created
locally on the PR #13 merge. The tag was never pushed. `release.yml` only fires
on a pushed `v*` tag, so no Release was ever built, no attestation signed, and no
binary published — while thirteen further commits landed on `main`. The repo
spent that entire stretch claiming to be `0.7.4` in every report header and SBOM,
with the only published artifact still `v0.7.3`.

Nothing was wrong with the single-source mechanism (D-33 / F-06): the version
genuinely does derive from `pyproject.toml` into the binary, the wheel, and the
SBOM. What was missing is that **a version literal and a published release are
different facts, and only one of them had a guard.** `release.yml` verifies the
tag matches `pyproject.toml`; nothing verifies that the version in
`pyproject.toml` was ever released at all.

v0.7.5 is cut from current `main` and carries the accumulated work: `-osv-export`
round-trip snapshots, the tiered OSV fallback (cache → live → bundled → gap),
PyPI transitive-depth reconstruction from `requires_dist`, PEP 517 build-backend
recursive analysis, wheel-only `.pth` recovery, the SARIF coverage-notification
block, the composer depth fix, and the PEP 508 compound-specifier parser rewrite.
`v0.7.4` is left in place as a historical marker rather than moved, since moving
a tag to cover a gap is how the gap becomes invisible.

Two process corrections came out of this, both in `docs/RELEASING.md`:

**The single-source claim was false.** Step 1 stated "nothing else carries a
version literal." `README.md` carries two — the baked-in-version note and the
`gh attestation verify` example — and no test or CI job checks either. A document
that tells you a checklist is unnecessary is worse than one that omits it, so the
step now names both sites and gives the grep that finds them.

**`git push --tags` is now forbidden in the procedure.** It was the documented
command. With an abandoned local tag present it would have pushed `v0.7.4` too,
and the consistency gate would have *passed* — that commit's `pyproject.toml` did
read `0.7.4` — publishing a fully signed Release built from thirteen-commit-old
code. The gate compares a tag to the version at the commit it points to, which
protects against a mislabelled release and not at all against publishing the
wrong commit. Pushing one tag by name is what protects against that.

## D-40 — state transition is a first-class axis, and it never blocks

Every check that existed before this release evaluates a version as an isolated
event. VC-002 judges a hook by what it can do. VC-005 judges a burst against the
package's own cadence. VC-001 judges a coordinate against a feed. None of them
can answer the question an operator actually asks during a dependency update:
*did anything security-relevant change?*

An external market review named the same gap from the outside, calling
version-to-version capability drift the clearest competitive difference between
depSNORT and the tools it sits beside. It also named the two things drift needs
to be more than a diff: version-level publisher identity, and a persistent
known-good record to compare against.

Four pieces, and a deliberate boundary on each.

**`internal/profile` — the comparable form of a package@version.** Capabilities,
the hooks carrying them, remote hosts reached, credential sinks touched,
publisher, source class, and a digest of direct dependencies. It is built from
the install-time subgraph the scan already materialized, so a profile costs
nothing beyond the scan. Two properties are load-bearing and both have tests
that fail loudly if they regress:

*Determinism.* Every slice is sorted and nothing derives from wall-clock or map
order, because a baseline is meant to be committed — and a profile that varies
between runs would report phantom drift on every scan until the file was
ignored. Remote artifacts contribute their HOST rather than their URL for the
same reason: a cache-busting query string changing between releases is not a
security event, a new destination is.

*Unobserved is not empty.* A profile built over an install surface that could
not be read records that fact. Without it, a baseline captured under degraded
coverage would launder itself into a known-good record asserting "this package
has no capabilities" — the exact all-clear-over-nothing failure the coverage
model exists to prevent (D-24), one layer up.

**Publisher lineage.** `ReleaseHistory.Maintainers` answers "who *can* publish
this package today?" and reads identically before and after a stolen token
pushes a release, so it could never anchor an actor signal. npm's packument
carries `_npmUser` per version and crates.io's versions endpoint carries
`published_by`; both are inside documents the temporal axis already fetches and
caches, so lineage costs no extra request and works offline. The other four
registries expose nothing, and where that is true `PriorPublishers` returns a
`known: false` flag rather than an empty set — because "we cannot see who
published the earlier versions" cannot support "this publisher is new", and a
check that conflated those two would be confidently wrong exactly where data is
thinnest.

**Baselines are files, not inferences.** The obvious alternative — take the
previous version from the registry and diff against that — fails on its own
premise: it means trusting whatever the registry serves right now, which is
precisely what is under suspicion when an account is compromised, and it makes
the verdict depend on network state instead of on something a human approved. A
committed file is reviewable, diffable, signable, and identical on every runner
including air-gapped ones. Nothing promotes itself; `baseline create` writes what
you point it at, and warns when it is recording over incomplete coverage,
because a capability that was never read must not be baselined as absent.

**Drift never blocks.** This is the substantive judgement of the four. Block
class belongs to checks that judge a shape directly on its own evidence: a known
malicious release (VC-001), the operator's own confirmed indicator (VC-003), a
credential-exfiltration or download-cradle install path (VC-002d/f). A drift
finding rests on a *comparison*, and the baseline side of that comparison is a
file depSNORT cannot verify — it may have been recorded over an unread install
surface, or promoted from a version that was already compromised. Gate-eligible
is the honest ceiling for a conclusion resting on an operator-supplied input.
Nothing is lost by the restraint: if the drifted capability really is a
block-class shape, VC-002d/f reaches that verdict independently and blocks on its
own evidence.

The weighting is the package's own version number, because a version is a claim
about how much should have changed. A major release that adds network access is
doing what major releases do; the same addition in a patch release contradicts
the claim the release itself made, and that contradiction — not the capability —
is the signal.

VC-011 gets the same restraint for the same reason. Handovers, co-maintainer
first releases, and CI token migrations all produce a first-time publisher, so
actor change alone stays advisory and escalates only alongside an install hook or
an ended dormancy. A check that gated on new publishers would be muted within a
week, including for the case it exists for.

The composition is the deliverable. One VC-010 finding now states the capability
change, the actor change, and the temporal context together — "1.6.3 gained a
credential sink and network egress relative to 1.6.2 in a patch release,
published by an account that has never published this package, after 420 days of
dormancy" — rather than three findings an operator has to assemble by
cross-referencing.

## D-41 — a dependency's source is coverage state, not a footnote

A field review of a Rust project (`psmux`, 246 lockfile nodes) had to
reconstruct by hand something depSNORT already parsed and then discarded: which
dependencies came from a registry. That single classification carried the whole
risk picture. 243 crates were routine advisory work; the two vendored forks were
the only ones worth reading, and they are precisely the ones no advisory feed has
ever indexed.

Every adapter had the fact and threw it away. Cargo read `source` into an
ecosystem-private attribute nothing consumed — and a crate with *no* source line,
which is exactly how Cargo encodes a vendored path dependency, was
indistinguishable from crates.io. Bundler states a gem's origin outright by
grouping specs under `GEM`/`GIT`/`PATH`; the parser tracked the section header and
dropped it. npm's `resolved` was stored raw and read only by VC-007.

So an OSV lookup for a vendored fork returned nothing, and nothing rendered as
clean. That is the one thing this tool promises not to do (D-24), and it had a
blind spot in it the entire time.

Provenance is now recorded on ecosystem-neutral node attributes, for the same
reason the coverage keys are ecosystem-neutral: verifiability is a property of
the scan, and the verdict layer must read it without knowing which adapter
produced the graph. A non-registry package raises VC-009 *and* degrades scan
coverage, so it can reach exit 3 under `-fail-on-incomplete` — the finding names
what could not be verified, the coverage axis makes it gate.

**VC-009 is advisory alone, deliberately.** The field report argued that
vendoring those two crates in-tree was a *stronger* posture than git
dependencies would have been: pinned, in-repo, reviewable in the same pull
request as everything else, and immune to an upstream force-push swapping code
underneath a build. That argument is correct, and a check that called it a risk
would be wrong. What is not defensible is a clean report that cannot be told
apart from one over packages nothing could have checked. It escalates to
gate-eligible only when the same package also carries install-time code: a
mutable upstream plus a mechanism to act on the change is the composed shape,
not either half.

Two false-positive guards, both inherited from how D-24 already handles this
class of problem:

**Roots are never charged.** The project being scanned is local source by
definition, and Cargo records no `source` for it. Charging that would flag every
scan of every project on day one.

**A class is recorded only on positive evidence.** An npm v1 lockfile carries no
`resolved` field on nested entries; recording those as "unknown" would
manufacture a scan-wide gap for every legacy project, which is the same mistake
as reporting a flat lockfile format as a resolver defect. A private or mirrored
registry URL stays registry-class for the same reason — it still has a
name@version a feed can answer about, and flagging every enterprise Artifactory
mirror would be exactly the warning tax that gets a detector muted.

PyPI needed no adapter change: a PEP 508 direct reference is already unpinned and
already degrades coverage through that path, and adding a second signal for the
same fact would double-count it.

## D-42 — external code validation (post-update): five findings, and what they have in common

An external technical validation of the merged state returned CONDITIONAL FAIL
with three High-severity correctness defects and two Medium validation gaps. All
five were reproduced against the code before any of them were fixed, and two of
the three blockers were mine, introduced with the state-transition work in D-40.

They are worth recording together because four of the five are the same mistake
in different clothes: **a mechanism that reported success based on whether it
had DONE something, rather than on whether what it did answered the question.**

**DS-REV-01 — the fallback tier measured presence, not coverage.** The
compiled-in dataset held 156 advisories, zero of them malicious, and three
coordinates with no advisories at all. Any hit incremented `FromBundled` and
suppressed the gap, so an offline scan of a bundled coordinate returned clean,
exit 0, even under `-fail-on-incomplete`. The tier is documented and gated as
the offline stand-in for a live VC-001 check; the data could not serve that, and
the accounting could not tell.

The data was wrong by construction, not by accident. `refresh-bundled-snapshot.sh`
seeded the dataset by scanning this repo's `realworld` fixtures — real popular
packages pinned to deliberately VULNERABLE versions — which yields GHSA records
and can never yield a MAL-* one. The generator's inputs guaranteed the output
could not do its job, and nothing in the pipeline compared the two.

Both halves are fixed, and both are needed: the accounting now requires a
malicious advisory before a hit counts as coverage, and the generator now pulls
MAL-* records from OSV's per-ecosystem exports and fails closed on zero
malicious records or fewer than two ecosystems. The cap counts COORDINATES
rather than advisories — capping advisories let NuGet contribute 4411
coordinates against crates.io's 11, which is not ecosystem diversity.

On freshness, the review asked for an invariant test. A test asserting "newer
than N days" fails on an untouched repository and must be edited to stay green:
the hardcoded-date time bomb this project already removed once. Freshness
remains a runtime disclosure — `BundledDatasetAt` rides every bundled hit and
the CLI prints its age — and the test guards the field's integrity instead of
the calendar.

**DS-REV-02 — the Cargo parser discarded the disambiguation Cargo added.**
Cargo.lock qualifies a dependency with its version precisely when several
versions are present. The parser kept the name and resolved edges by name, so
the over-connection happened exactly in the case the qualification exists to
prevent. Resolution is now most-specific-first and never widens; an ambiguous
bare name is disclosed through the existing unresolved-coverage keys instead of
guessed, because a guessed edge is indistinguishable from a real one once it is
in the graph.

Writing the fixture surfaced a second defect: two entries with the same
name@version from different sources collapsed into one node whose source class
was whichever was parsed last. That was first deferred and then closed in the
same series — see D-43, which also explains why the deferral was the right call
for about an hour and the wrong one after that.

**DS-REV-03 — "deterministic" is not "correct".** `baseline.Index` kept one
profile per package by PURL order and my comment called that deterministic. It
was. It also selected 2.0.0 over 10.0.0, because PURL order is lexicographic —
and fixing the ordering would not have fixed the defect. When two projects in a
workspace have legitimately approved different versions, the right profile
depends on WHICH PROJECT the candidate came from, and no ordering of versions
answers that. The index now keeps every approved version and VC-010 declines
when the answer is not determined, visibly: an informational finding, a stderr
warning at load time, and a coverage entry that can reach exit 3.

**DS-REV-04 — a partial history is not a complete one.** `PriorPublishers`
returned `known=true` on the first prior identity it found, so alice / unknown /
mallory supported "mallory has never published this package" — when the unknown
release could have been mallory's. Measuring live crates.io while building the
feature, serde carries `published_by` on 142 of 316 versions: partial is the
normal shape there, so the check made its strongest claim exactly where its
evidence was thinnest. Three states are now distinguished, and a partial history
produces a qualified claim at reduced confidence that never gates however it
composes. Composition multiplies confidence; there was none here to multiply.

**DS-REV-05 — a guard that cannot fail.** Go tooling ignores `testdata`
directories, so `go test ./...` never ran the adversarial corpus, while the CI
comment asserted that it did. The companion shell harness counted failures,
printed a tally, and exited 0 regardless — and two of its seven fixtures had
been failing that way silently: one had no lockfile so no adapter matched, and
one scanned clean because of a path defect in the Composer extractor.

That defect is the sharpest thing the review produced indirectly. Paths were
joined with the scan root before being handed to `securefs`, which joins
relative paths onto its own root. An absolute scan path was unaffected; a
relative one was joined twice, escaped, and was refused. `depsnort scan ./path`
therefore skipped the root project's own manifest while `depsnort scan
/abs/path` read it and blocked on the cradle inside. The refusal WAS disclosed
as a coverage gap, which is the only reason this was a lost detection rather
than a silent all-clear — the coverage model did its job while the analysis did
not.

The corpus now runs as its own CI step, the harness fails on a missed detection
or an incomplete tally, and expectations are matched through a subsumption rule
so a stronger classification satisfies a weaker expectation. Without that, every
rule tightening breaks the harness and the pressure lands on loosening the rule.
Both suites are kept: the Go corpus builds graphs in memory and cannot catch a
fixture that never scans, and the shell harness drives the shipped binary and
found both fixtures that didn't.

**The common thread, and the standing rule.** Coverage accounting (D-24) is
already the answer to "did we look?", and D-41 extended it to "could this lookup
have answered?". These findings extend it once more: a mechanism must be judged
by what it PROVIDES, not by whether it ran. A dataset that contains records, an
index that returns a profile, a history that has an entry, a test job that
executed — each reported success while answering nothing. Where a component
cannot answer, the honest outputs are a disclosed gap and a refusal to conclude,
and every one of these fixes is one of those two.


## D-43 — a package's origin is part of its identity

D-42 deferred half of DS-REV-02: a registry crate and a git fork of it at the
same name@version stayed one node, because node identity across this tool is
the PURL string and a PURL carried no origin. The graph kept whichever entry
the parser reached first, and the other silently overwrote its provenance. A
registry package could report as git-sourced; a fork could be masked as
registry and never reach VC-009 at all. That one attribute decides whether the
advisory lookup for a package meant anything, so the node was answering a
question it had no basis to answer — the D-42 pattern, one layer down.

The deferral was correct while three release blockers were open and this was a
fourth thing to change underneath them. It stopped being correct the moment
they were closed, because the same defect was then confirmed in npm: a registry
copy hoisted at the top of a tree and a git fork nested under a dependency that
pinned it share a name@version, and `resolved` distinguishes them while the
identity did not. A mechanism that fixes a proven bug in two adapters is not
follow-up work.

**Non-registry origins are qualified; registry ones are not.** A fork renders as
`pkg:cargo/name@1.0.0?source=git&source_ref=<origin>`. A registry package keeps
its bare coordinate, and that asymmetry is the whole design: qualifying registry
packages would change the identity of essentially every package in every tree —
breaking transitive dedupe, committed baselines, and IOC ledgers — to fix a case
that does not exist, because a registry coordinate is already globally unique.
The blast radius is confined to exactly the packages that had the bug.

Two custom qualifier keys rather than the spec's `vcs_url` and `download_url`:
one rule ("a non-registry package carries its class, and its origin when the
lockfile records one") is easier to hold than three keys chosen per class, and
these strings are internal identity rather than an interop surface.

**What the fuzzer found, immediately.** Giving `?` and `#` meaning in a PURL
made them structural, and `encodeSegment` did not escape them — so a package
named `a?source=git` rendered a PURL that parsed back with a FORGED qualifier,
letting a hostile lockfile mint the identity of a differently-sourced package.
That is precisely the identity-forging shape D-33 closed for name and version
segments, reopened by extending the grammar. FuzzParse produced it in under
twenty seconds, alongside a second bug where unpadded hex made one string
render two identities on successive passes.

The lesson is narrower than "fuzzing is good": **every time the identity grammar
gains a character, every encoder that writes into it becomes wrong until proven
otherwise.** The invariant is not "escape these five characters", it is "no
value may render structure it does not own", and the fuzz target is what makes
that invariant enforceable rather than aspirational.

**One consequence, closed in the same change.** Baseline lookup keys on
ecosystem+name, so a baseline can now hold a registry package and its fork at
the same name AND version — identical on every field except identity. Lookup
tries the full PURL first, and a version collision among several candidates
resolves to nothing rather than to a guess: the same refusal DS-REV-03
installed, arriving by a new route.

What remains genuinely indistinguishable is two path crates, because Cargo.lock
records no path for them. They keep the ambiguity disclosure. The rule holds:
where the lockfile can tell two artifacts apart, so does the identity; where it
cannot, nothing pretends otherwise.

## D-44 — expansion looks past the manifest by default, and grades what it finds

A lockfile-first scan sees exactly one layer below a flat pin. `requirements.txt`
with `totallyInnocent==0.11.2` resolved one node; whatever it dragged in — the
layers an attacker would rather stayed unread — was nowhere in the file, and the
scan said `PASSED`. D-24 made that gap VISIBLE (coverage degrades, the banner
reads INCOMPLETE). It did not close it. A supply-chain IDS that only reads what
the operator already listed is not doing the job the name claims.

The walk closes it: from each versioned node it reads that package's own
published dependencies and descends, layer after layer, per root. It is on by
default (`-expand`, default true), because looking only at face value defeats
the tool. `-no-expand` (or `-expand=false`) restores the manifest-only posture
for an operator who wants nothing in the graph a file did not state, and
`-expand-depth=N` stops after N layers so the tree can be stepped through one
layer at a time.

**Why this is not the resolver D-01 refused.** A dependency is declared as a
NAME and a CONSTRAINT (`requests>=2.0`), never a version. To put a node in the
graph the walk presumes one: the highest published version satisfying the
constraints its dependents accumulated. That is a filter and a sort — no
backtracking, no marker evaluation, no conflict search — and it is what pip,
npm, and cargo actually do absent a conflict, so it is right in the common case
and wrong in a knowable direction. It is not a resolver, and the tool never
presents its output as observed fact.

**The version is a truth axis, the way risk, coverage, and origin already are
(D-05/D-06, D-24, D-41).** `depsnort.version_truth` grades every node: OBSERVED
(a lockfile said so), PRESUMED (this tool chose it), ASSERTED (an external
resolved-graph service supplied it — the D-01-sanctioned deps.dev path, not yet
built), CONTESTED (constraints admit nothing, or could not be evaluated — no
version assigned, walk stops). Grading the claim is what makes depth safe:
before it, the only honest walk was a shallow one.

**Presumed nodes never gate.** `verdict.applyPresumedDemotion` demotes every
finding on a presumed node to advisory, enforced beside the recency demotion so
no check can opt out. A block on a version nobody installed is a false positive
with a build failure attached, and one of those teaches an operator to disable
expansion permanently — costing every true finding the deeper layers would have
surfaced. It demotes block class where recency demotion refuses to, and the
difference is the premise: recency acts on an OBSERVED release, where severity
still stands; a presumed node's version was never observed, so a block about it
is a confident claim about a coordinate that may not be in the build. Demoted,
never dropped — a typosquat found four layers down stays in the report, which is
the whole reason for walking that deep.

**What it costs, disclosed not hidden.** The walk stops at a FRONTIER — a node
whose dependencies it could not read — for three distinct reasons it keeps
apart: the `-expand-depth` cap (a limit the operator chose), a contested version
(the data would not resolve), and an unread coordinate (a fetch that did not
happen). Only the last degrades coverage, surfacing as the `pypi-expand` data
source going degraded, exactly as a failed OSV lookup does. An offline scan
therefore now reports INCOMPLETE where before it silently attempted nothing —
the more honest answer, and the one D-24 demands: a walk that could not see the
deep layers must say so, not imply an all-clear.

**Scope today.** The engine (`internal/expand`) and the truth axis
(`internal/graph`) are ecosystem-neutral; the per-ecosystem surface is one seam
— declare, index versions, judge a constraint — and each ecosystem implements
all three on one struct, so one walk spans several. PyPI reads requires_dist and
judges with PEP 440 (`internal/pep440`); npm reads the packument's per-version
`dependencies` and judges with a semver-range evaluator in `internal/semver`
(caret, tilde, x-ranges, hyphen ranges, AND/OR); Cargo reads the crates.io
per-version dependencies endpoint and judges with `SatisfiesCargo`, which shares
that evaluator's caret/tilde math but flips two defaults — a bare requirement is
caret, not exact, and AND is a comma. NuGet reads dependency groups from the
registration index (the one document that also carries the version list) and
judges with `internal/nugetver`, a separate version model because NuGet needs
what semver cannot give: four-part versions (`1.2.3.4`) and interval ranges
(`[1.0,2.0)`), where a bare version is a MINIMUM, not exact and not caret. All
reuse the registry clients VC-004/VC-005 already run; the per-coordinate deps
clients share one `coordFetcher` for the cache/concurrency/coverage plumbing.

NuGet also forced the walk to stop assuming a universal selection direction. npm,
PyPI, and Cargo install the HIGHEST version satisfying a constraint; NuGet
installs the LOWEST. Presuming the highest for NuGet would model a restore no
client performs, so an ecosystem now declares its direction through the optional
`LowestResolver` interface, and the walk sorts candidates accordingly — highest
by default, lowest when the declarer says so. The selection is the installer's,
not the tool's.

RubyGems and Composer completed the set with no engine change — grammar only.
Their `~>` (Ruby) and `~` (Composer) are the SAME "pessimistic" operator
(`~> 1.2` and `~1.2` both mean `>=1.2.0 <2.0.0`), distinct from npm's tilde
(`~1.2` = `<1.3.0`), so `internal/semver` grew one shared `pessimistic` helper
and two entry points over the existing caret/comparator machinery. RubyGems
reads runtime dependencies per version from the v2 API (development
dependencies excluded, like npm devDeps); Composer reads the `require` map from
the Packagist p2 document (which, like the npm packument and the NuGet
registration index, carries every version's dependencies in one fetch, so its
deps client batches by name), filtering platform requirements — php, ext-*,
lib-* — that name the runtime rather than an installable package. With these
two, expansion covers every ecosystem depSNORT resolves. Cargo also keeps build-dependencies (they
run build.rs at compile time — the install-time subgraph's own subject, D-02)
and drops dev-dependencies, which Cargo never compiles transitively. The other
three ecosystems expand as each grows its own range grammar; until one does, its
nodes stay at the frontier rather than being presumed wrongly, the D-15
decline-when-you-lack-a-basis rule.

**One guard the Cargo fixture forced, applying to every ecosystem.** The walk
descends from versioned nodes, and a vendored crate is a versioned node — but
one the lockfile recorded as path- or git-sourced (D-41). Querying a registry
for that name would answer with whatever real package happens to share it, and
graft that package's dependency tree onto the local fork: the exact
name-confusion the source class exists to prevent. The walk therefore queries a
registry only for registry-origin and unqualified nodes (D-43 qualifies only
non-registry origins, so an ordinary registry package carries no source
attribute), and leaves an explicitly non-registry node at the frontier.

npm forced one design choice the single-ecosystem sketch hid: the walker cannot
hold one global version index, because npm and PyPI resolve versions through
different clients. A declarer that also indexes its own versions (both
`WalkSource`s do) is therefore preferred per-ecosystem, and the global index is
only a fallback. That in turn surfaced a containment subtlety worth recording:
with presuming on, a declared package is created by identity graph-wide, so if
root A presumes the same coordinate root B observed, they legitimately share one
node — dedup, not borrowing, because A presumed it independently from the
registry. The guarantee that survives is narrower and correct: A's resolution is
never SWAYED by B's pin. When B has pinned a version A's constraint excludes, A
presumes its own and the two do not touch.

**Surfacing, once the walk shipped.** A presumed version that renders
identically to an observed one re-creates the very confusion the truth axis
exists to prevent, so every emitter now distinguishes them. JSON promotes
`version_truth` to a first-class node field, emitted only when not observed, so
its absence still means "from a lockfile". SARIF tags a finding whose subject is
presumed with `versionTruth`/`presumedVersion` properties, so a code-scanning
dashboard can deprioritize a finding about a coordinate that may not be in any
build — the same reason verdict already demoted it. DOT gives presumed and
contested nodes a dashed outline and a `(presumed)`/`(contested)` label. The PDF
risk table marks a presumed version `~` and a contested one `?`, with a note
that findings on them are advisory. Cypher promotes `version_truth` to a
queryable property. The rule is one line across all five: an observed node is a
fact from a lockfile and a presumed one is this tool's best guess, and they must
never look the same.
