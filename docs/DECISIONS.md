# dependaSNORT — Decision Log

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
dependaSNORT resolved one node — the root — ran zero checks against zero
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
