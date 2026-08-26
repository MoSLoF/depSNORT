# depSNORT

**A pre-install IDS for the dependency supply chain.**

Dependabot tells you what is outdated. Traditional SCA tells you what is already
known to be vulnerable. Package malware scanners inspect artifacts for suspicious
code. Repository firewalls control what may enter an organization.

depSNORT asks a different question:

> Has this dependency, release, or install path deviated in a way that is
> consistent with supply-chain compromise — **before package code executes**?

It resolves dependency trees, enriches them with threat intelligence and release
history, reconstructs install-time behavior statically, compares the result
against a known-good baseline where one exists, and runs everything through a
modular pack of vector checks. The output is an explainable verdict: **advisory,
gate-eligible, block, or incomplete coverage**.

> Design rationale and the full decision log live in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Why depSNORT exists

No single supply-chain signal is enough.

- A new release is not malicious because it is new.
- An install hook is not malicious because it reaches the network.
- A dormant package is not compromised because it woke up.
- A new publisher is not an attacker because they are new.
- A CVE does not mean a release is part of an active supply-chain attack.

The useful signal appears when evidence **composes**.

```
lockfiles / manifests
        |
        v
declared dependency graph
        |
        +--------------------+--------------------+
        |                    |                    |
        v                    v                    v
threat intelligence    release lineage      known-good baseline
OSV / IOC ledger       cadence / dormancy   capability profile
                       publisher identity   publisher / topology
        |                    |                    |
        +--------------------+--------------------+
                             |
                             v
                  static install surface
              hooks -> exec -> fetch -> sinks
                             |
                             v
                   modular vector checks
                             |
                             v
           advisory / gate / block / coverage gap
```

That is the IDS analogy: depSNORT treats dependency state and package releases as
security events, correlates them against deterministic rules and context, and
reports the evidence that produced the verdict.

## What depSNORT is — and is not

**depSNORT is:**

- a local, pre-install dependency IDS;
- a static install-surface analyzer;
- a release-lineage and publisher-lineage anomaly detector;
- a state-transition detector: what changed since you approved this tree;
- a dependency-graph correlation engine;
- a CI gating primitive;
- an explainable rules engine that can operate offline.

**depSNORT is not:**

- a replacement for SCA or vulnerability management;
- a dynamic malware sandbox;
- a repository proxy/firewall;
- a proof that a package is safe;
- an ML classifier that hides its reasoning behind a score.

The project is intentionally narrow: detect supply-chain intrusion indicators
before dependency code gets a chance to run.

## Current coverage

Seven ecosystems share the same graph, check, verdict, and output model:

| Ecosystem | Lockfile(s) / manifest | PURL type | Install-time surface |
|-----------|-------------|-----------|----------------------|
| **npm** | `package-lock.json` (v1–v3), `yarn.lock` (v1 + Berry), `pnpm-lock.yaml`, `bun.lock`, or `package.json` | `pkg:npm/` | `preinstall`/`postinstall`, related lifecycle scripts, and load-time (import-time) execution |
| **PyPI** | `requirements*.txt` (incl. dev/test siblings), `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml` (PEP 751), `Pipfile`/`Pipfile.lock`, `pyproject.toml`, `setup.py` | `pkg:pypi/` | `setup.py`, PEP 517 build backends, `.pth` files |
| **RubyGems** | `Gemfile.lock`, or `Gemfile` | `pkg:gem/` | `extconf.rb` / native-extension install paths |
| **Cargo** | `Cargo.lock` | `pkg:cargo/` | `build.rs` and compile-time code paths |
| **Composer** | `composer.lock`, or `composer.json` | `pkg:composer/` | scripts, plugin packages, plugin entrypoints |
| **NuGet** | `packages.lock.json`, `packages.config`, `paket.lock`, or the modern declared surface — `PackageReference` (`.csproj`/`.vbproj`/`.fsproj`/`.vcxproj`), Central Package Management (`Directory.Packages.props`), `Directory.Build.props`, `.nuspec`, `.config/dotnet-tools.json`, `project.json`, `paket.dependencies` — with `project.assets.json` preferred when a restore is present (the one modern format with a real resolved tree) | `pkg:nuget/` | install/init scripts, package build assets, and local-tool manifests |
| **Go** | `go.mod` | `pkg:golang/` | `go:generate` directives, cgo `#cgo` build-flag injection, build-tag-gated `init()` evasion, the `go run module@version` package runner, and per-dependency vendor/module-cache attribution |

A lockfile gives a fully-resolved tree; a bare manifest (an unpinned
`requirements.txt`, a `pyproject.toml`, a lockless `package.json`, `go.mod`)
declares dependencies without pinning every version, and transitive expansion
resolves the rest — see [Transitive expansion](#transitive-expansion) below.

The built-in pack currently covers:

- **VC-001** — known malicious releases: OSV malicious-package advisories;
- **VC-002 family** — install-surface behavior: network egress, named credential
  access, decode/execute indirection, credential-exfiltration shapes,
  download/execute cradles, persistence (startup-folder / LaunchAgents /
  LaunchDaemons / cron-shaped hooks), cgo `#cgo` build-flag injection,
  build-tag-gated `init()` evasion, load-time (import-time) execution, and
  self-propagation (a hook that publishes to a package registry);
- **VC-003** — operator IOC ledger: explicit package/version indicators supplied
  by the operator (an [example Miasma/Hades feed](docs/ioc-miasma-hades.json)
  ships in the repo — see [Threat-intelligence tiers](#threat-intelligence-tiers));
- **VC-004** — dormancy: a recent release cluster following prolonged inactivity;
- **VC-005** — anomalous release burst: release density measured against the
  package's own historical cadence;
- **VC-006** — typosquatting: calibrated near-name detection;
- **VC-007** — dependency confusion: internal names/scopes resolving from a
  public registry;
- **VC-008** — disclosed CVEs: vulnerability context that remains advisory by
  design, optionally enriched with FIRST.org EPSS exploit-probability scores
  (`-epss`) and ranked/gated by them (`-epss-gate`);
- **VC-009** — unverifiable dependency source: a package resolved from a git URL,
  a local path, or a direct artifact URL, which no advisory feed indexes;
- **VC-010** — capability drift: install-time capability gained relative to a
  known-good baseline, weighted by what the version number claimed;
- **VC-011** — publisher lineage: a version published by an account with no
  prior release of that package;
- **VC-012** — yank-lure: a version pinned to a since-yanked/retracted release,
  live-newest enrichment introducing a new dependency or build-time payload
  shaped like a lure.

`./depsnort checks` prints the live registry — it is generated from the same
single registration point the adversarial corpus builds from (D-37), so the list
cannot drift from what actually runs.

## The differentiator: correlation, not a single detector

Individual signals in depSNORT are not claimed to be unique. The differentiator
is their combination in one pre-install model:

```
release lineage  +  install-time capability  +  state transition since known-good
                 +  dependency-graph context +  known threat intelligence
                 +  explicit coverage state
                 =  explainable supply-chain verdict
```

Three examples illustrate the model.

**Dormancy is context, not guilt.** VC-004 identifies a release published after
prolonged dormancy, but dormancy alone stays advisory. It becomes gate-eligible
when the awakening release also declares an install hook. The check walks
backward through a rapid release cluster to find the actual dormancy boundary, so
a short sequence of patch releases after the dormant period does not erase the
signal.

**A burst is only anomalous relative to its own package.** VC-005 does not use a
global rule such as "three releases in 24 hours is suspicious." It calculates the
package's own median inter-release interval and asks whether the cluster around
the pinned version is abnormal *for that package*. A package that normally ships
several times a day is not penalized for doing so.

**Drift is a claim about change, not about capability.** VC-002 asks what a
package can do. VC-010 asks what it can do that it could not do when you approved
it — and weights the answer by the package's own version number, because a
version is a claim about how much should have changed. A composed drift finding
reads:

```
depsnort-fixture-drift gained install-time capability since 1.6.2 (patch release)
  1.6.2 -> 1.6.3 (patch): new capabilit(ies): credentials, network;
  new credential sink(s): NPM_TOKEN; new remote host(s): telemetry.example.invalid;
  published by mallory, where the baseline version was published by alice;
  the drifted release also arrived after 420 days of dormancy
```

That is one claim an operator can act on, not three findings they have to
assemble themselves.

## Zero execution is a design invariant

depSNORT **never** runs a package manager and never intentionally executes
package code.

It parses lockfiles and manifests, reads registry metadata, and statically
examines install-time source and package assets. The objective is to characterize
the path that *would* execute before allowing that path to execute.

This intentionally differs from dynamic package-analysis systems. Dynamic
sandboxes answer "what did this package do when detonated?" depSNORT answers
"what install-time behavior is exposed, and is the release context consistent
with compromise?" The two approaches are complementary.

## The dual-tree model

A lockfile describes the tree the developer selected. Install-time code can
create a second, undeclared execution graph. depSNORT models both:

```
declared graph
  package -> depends-on -> package

install-time graph
  package -> declares-hook -> hook
  hook    -> execs         -> artifact
  hook    -> fetches       -> URL
  hook    -> reads-env     -> credential sink
```

Both subgraphs are populated when the relevant source or package assets are
available. Risk propagates through the install-time path that explains the
finding — the hook, the files it executes, the URLs it reaches, the sinks it
touches — but it does **not** flow across ordinary `depends-on` edges. A bad
dependency does not turn its entire transitive tree red.

## Install-surface extraction

The VC-002 family scores *where an install path reaches*:

- **VC-002b** — network egress → gate-eligible;
- **VC-002c** — named credential access → gate-eligible;
- **VC-002e** — decode-and-execute indirection → gate-eligible;
- **VC-002d** — named credentials **plus** network egress → **block**;
- **VC-002f** — download-and-execute cradle (`curl … | sh`,
  `iex (…).DownloadString`, `certutil -urlcache`, and kin) → **block**;
- **VC-002g** — persistence: a startup-folder drop, a LaunchAgent/LaunchDaemon
  plist, or a cron-shaped hook installed at install time → gate-eligible;
- **VC-002h** — Go: a `#cgo` directive that injects build flags (`LDFLAGS`,
  `CFLAGS`) reachable from a build/generate hook → gate-eligible;
- **VC-002i** — Go: an `init()` gated behind a non-default build tag, proven
  reachable via `go/ast` closure over the package's own build directives →
  gate-eligible;
- **VC-002j** — npm: an entry module that spawns a bundled native binary at
  import time, with no lifecycle hook involved → gate-eligible;
- **VC-002k** — self-propagation: the hook publishes to a package registry
  (`npm publish`, a `npm version` bump, `libnpmpublish`) → **block**. This is
  the worm step — the phase that turns one compromised package into many — and
  it also draws a `republish` edge from the hook back to its own package, so
  the loop is visible in a graph view. An explicit `--dry-run` rehearsal and
  the `prepublish`/`postpublish` hook *names* are not publishes. Where
  credential access is present on the same hook, the finding names the full
  loop, because the operator's next action is rotating registry tokens.

When a cradle is present, VC-002b defers to VC-002f so the reach is reported
once, at the higher gate class, rather than twice.

Precision matters more than reach here. Broad environment access
(`process.env`, `os.environ`, `ENV[]`) is deliberately *not* a credential signal
— it is recorded as the weaker `env` capability — because legitimate native-build
hooks read environment variables and download prebuilt binaries constantly.
Treating that as exfiltration would flag `sharp`, `bcrypt`, and `sqlite3`, and
earn the tool a mute. Only *named* secrets (`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`,
`GEM_HOST_API_KEY`, `.npmrc`, `AWS_SECRET_ACCESS_KEY`, `id_rsa`, …) count. A
fixture pair locks this in: a worm-shaped package that must flag, and a benign
native-build package that must not.

```
./depsnort scan -no-osv internal/ecosystem/npm/testdata/wormy
```

The bundled adversarial fixture produces the full install-time subgraph and a
block verdict without executing the package.

## Release-lineage telemetry

A lockfile pins one version; it contains no release history. depSNORT therefore
reads publish metadata from ecosystem registries and builds a `ReleaseHistory`
for each package. Registry metadata supplies:

- version publish timestamps;
- package-specific release cadence;
- dormancy boundaries;
- release-burst clustering;
- recency decay;
- **per-version publisher identity**, where the registry exposes it.

Only metadata is fetched for the temporal axis — never a tarball, never an
install. Results are cached; `-offline` uses the cache exclusively and
`-no-registry` disables registry enrichment entirely.

**Transitive expansion.** A lockfile-first scan sees one layer below a flat pin;
whatever that layer drags in is nowhere in the file. By default depSNORT walks
past it — reading each package's own published dependencies and descending layer
by layer — so a single `requirements.txt` line is scanned to the depth an
attacker actually hides at. A declared dependency is a name and a *constraint*,
not a version, so the walk presumes one (the highest published version
satisfying the accumulated constraints) and labels it: every node carries
`version_truth` ∈ {`observed`, `asserted`, `presumed`, `contested`}. Presumed
(and asserted) nodes are
reported but **never gate** — a block on a version nobody installed is a false
positive with a build failure attached. With `-depsdev` (opt-in, reaches an
external service) the walk first consults deps.dev for a REAL resolved version
of each dependency — the *asserted* tier, `version_truth = asserted` — and only
presumes what deps.dev cannot resolve; asserted versions are stronger than a
guess but still never gate, since they are not this build's lockfile.
`-no-expand` restores the manifest-only posture; `-expand-depth=N` steps
through the tree one layer at a time. Expansion covers all seven ecosystems: PyPI (PEP 440), npm (semver ranges),
Cargo (crates.io, where a bare requirement means caret), NuGet (interval
ranges like `[1.0,2.0)`, a bare version is a minimum, and the resolver picks
the LOWEST satisfying version), RubyGems (the `~>` pessimistic operator), Composer
(npm-family semver whose `~` is pessimistic, not npm’s tilde), and Go (module
requires are minimum versions; MVS selects the lowest satisfying, read from
`go.mod` and the module proxy). Each
reads only the registry metadata the tool already fetches for the temporal
axis; a dependency the lockfile records as git-, path-, or url-sourced is
never walked against a registry, since its name could collide with a real
package. A dependency the lockfile records as git-, path-, or
url-sourced is never walked against a registry — its name could collide with a
real package, and grafting that package’s tree onto a local fork is the
confusion the source class exists to prevent.

Temporal findings use exponential recency decay with a 90-day half-life:
`score = severity × confidence × recency_decay`. "Recent" is a curve rather than
a cliff, so a three-year-old dormancy event scores near zero instead of shouting
as loudly as one from last week.

**Publisher lineage.** A package-level maintainer list answers "who *can* publish
this today?" — it reads identically before and after a stolen token pushes a
release. VC-011 needs the other question: who published version N versus N+1. Two
of the seven registries state it (npm's `_npmUser`, crates.io's `published_by`),
both inside documents the temporal axis already fetches and caches. Where a
registry exposes nothing, depSNORT records the absence as coverage state and the
check does not fire — "we cannot see who published the earlier versions" cannot
support "this publisher is new".

## Known-good baselines and capability drift

A baseline is a file you commit and review, not an inferred "last good version".
Inferring it from a registry would mean trusting whatever that registry served
most recently — precisely the thing under suspicion when an account is
compromised — and would make the verdict depend on network state instead of on
something an operator approved.

```
# record what the tree looks like now, having decided it is good
./depsnort baseline create -o depsnort-baseline.json .

# later: what changed, and does the change fit what the version claimed?
./depsnort scan -baseline depsnort-baseline.json .
```

Each profile records the package's install-time capabilities, the hooks carrying
them, the remote hosts they reach, the credential sinks they touch, its publisher
identity, its source class, and a digest of its direct dependencies. Profiles are
byte-stable, so two `baseline create` runs over an unchanged tree differ only in
their `created` line and a committed baseline does not generate diff churn.

Drift weighting follows the version number: a patch or minor release that gains
credential access, a cradle, or obfuscation is gate-eligible and high severity; a
major release making the same addition is advisory, because a major release makes
no claim that nothing structural changed. **VC-010 never blocks.** Block class
belongs to checks that judge a shape on its own evidence; a drift finding rests
on a comparison whose baseline side is a file depSNORT cannot verify.

Without `-baseline` the drift axis is simply inactive, and the run says so on
stderr. A scan that could not have reported drift should not read like one that
looked and found none.

The same rule applies per package. A baseline can legitimately hold several
approved versions of one package — two projects in a workspace pinning
differently — and no ordering of versions can say which one a candidate belongs
to. Rather than pick, depSNORT declines: drift for that package is reported as
**unevaluated**, named in the scan output and on stderr, and counted as missing
coverage so `-fail-on-incomplete` can gate on it. A candidate is never compared
against another project's approved version.

## Dependency source provenance

A lockfile records not only which version was selected but **where it came
from**, and the two carry very different amounts of verifiability. A crate pinned
to crates.io has a global coordinate an advisory feed can answer about. A crate
vendored in-tree as a path dependency, or pulled from a git URL, has no such
coordinate — an OSV lookup for it can only ever return nothing.

Every adapter now classifies that fact (`registry` / `git` / `path` / `url`) from
evidence its own lockfile already carries, and a non-registry package both raises
**VC-009** and degrades scan coverage. Vendoring is not a smell — it is often a
*stronger* posture than a git dependency, being pinned, in-repo, and immune to an
upstream force-push. What is not acceptable is a clean report that cannot be
distinguished from one over packages nothing could have checked.

VC-009 is advisory alone and escalates to gate-eligible when the same package
also declares install-time code: a mutable upstream *plus* a mechanism that runs
on install is the composed shape, not either half.

A non-registry package also carries its origin in its **identity**, not just in
its attributes:

```
pkg:cargo/some-crate@1.0.0                                   # registry
pkg:cargo/some-crate@1.0.0?source=git&source_ref=git+https…  # a fork of it
```

They are different code, so they are different nodes. Registry packages keep the
bare coordinate — that is already globally unique, and qualifying it would
change the identity of nearly every package in every tree for no gain. Where a
lockfile genuinely cannot tell two artifacts apart (two Cargo path crates, which
the lock records no path for), the ambiguity is disclosed rather than guessed.

## Threat-intelligence tiers

Every resolved `package@version` can be cross-checked against OSV. depSNORT
separates malicious-package intelligence from ordinary vulnerability context:
**VC-001** known-malicious releases can block; **VC-008** ordinary CVEs remain
advisory and cannot fail a build by themselves.

The OSV path is tiered:

```
on-disk cache -> live OSV -> bundled malicious-package snapshot -> typed gap
```

The bundled snapshot exists so a first scan in a sandbox or air-gapped runner
still has meaningful malicious-package coverage rather than an empty cache and a
silent gap. It holds **only `MAL-*` records** — the most recent malicious
coordinates per ecosystem, across all seven — because that is the one question
this tier exists to answer offline. A hit is real coverage (a known-malicious
package does not stop being malicious because the data is a few weeks old), and
its age and use are disclosed in output, never mistaken for a live check:

```json
{"name": "osv", "stats": {"from_bundled": 1, "bundled_dataset_generated_at": "2026-08-18T00:00:00Z"}}
```

**A hit counts as coverage only if it carries a malicious advisory.** An entry
holding nothing but ordinary CVEs returns that CVE context — it is real and
worth having — but still records a gap, because nothing checked that coordinate
for malware. Reporting it as covered would be an all-clear from a dataset that
never looked, which is exactly what an earlier revision of this tier did.

`-no-osv-bundled` disables the tier entirely. The dataset is regenerated with
`make refresh-bundled-snapshot` (see [`docs/RELEASING.md`](docs/RELEASING.md)),
which fails closed rather than writing a dataset with no malicious records or
fewer than two ecosystems. Embedding the entire OSV corpus is not feasible;
embedding the bounded, high-signal malicious-package feed is.

For disconnected environments, a connected system can export a snapshot:

```
# once, with network access
./depsnort scan -osv-export advisories-snapshot.json .

# everywhere else: bootstrap from that file, zero network calls
./depsnort scan -osv-snapshot advisories-snapshot.json -offline .
```

`-osv-export` needs a live query to have anything to export, so it is rejected
alongside `-offline`/`-no-osv` rather than silently writing an empty file, and a
live query that fails partway through skips the export instead of writing a
snapshot that looks complete but is not.

The OSV client honors `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`, so a sandboxed
or corporate runner can reach `api.osv.dev` through an egress proxy with no
depSNORT-specific configuration.

**Exploit-probability ranking (opt-in).** `-epss` enriches every VC-008 finding
with its peak [FIRST.org EPSS](https://www.first.org/epss/) score — the
probability a CVE is exploited in the wild in the next 30 days — turning a flat
"96 vulnerable packages" list into a ranked one. Advisory IDs that OSV's
querybatch path returns with no CVE alias (a GHSA- or GO- primary advisory) are
resolved through a cached, deduplicated `osv.CVEAliases` call so EPSS — which is
CVE-keyed — can still score them. `-epss-gate <threshold>` escalates a finding
whose peak score is at or above the threshold from advisory to gate-eligible, so
`-fail-on-eligible` can fail a build on only the handful of vulnerabilities
actually being exploited, while ordinary CVE noise stays advisory. Both flags
need live network and are skipped `-offline` (EPSS has no bundled fallback).
The score appears in JSON, SARIF, and the PDF (a dedicated per-finding line and
a per-package peak column in the risk table).

## Coverage is part of the verdict

A scanner must not confuse *nothing found* with *nothing inspected*.

| Exit | Meaning |
|------|---------|
| `0`  | clean, or advisory-only findings |
| `1`  | block-class finding present |
| `2`  | gate-eligible finding present **and** `-fail-on-eligible` was requested |
| `3`  | coverage degraded **and** `-fail-on-incomplete` was requested |
| `64` | usage error |
| `70` | internal / operational error |

Unpinned specifiers, datasource failures, unreadable subtrees, offline cache
misses, failed workspace projects, partial install-surface extraction, and
non-registry package sources are all disclosed. So is a **recognized manifest no
adapter can resolve** — a `pom.xml`, a `.gemspec`/`.podspec`/`.cabal`/`.sbt`, a
`gradle.lockfile`, a `mix.exs`, a `.terraform.lock.hcl` — which degrades coverage
("manifest present, dependencies unread") rather than reading as "nothing to
scan". (A bare `.csproj`/`.vcxproj` with no lockfile and a `Pipfile` with no
`Pipfile.lock` are *not* in this category any more — both are now read
declared-only, flat, and disclosed as such — see the ecosystem table above.) As
a last-ditch net, any other unrecognized `*.lock` file is disclosed as an
unknown-ecosystem gap rather than skipped in silence. A partial run is never
silently promoted to clean. Precedence is:

```
block > gate-eligible > incomplete > advisory
```

**Advisory findings never change the exit code**, regardless of policy — a
structural guarantee enforced in `internal/verdict` (D-06), not a configurable
default.

**Adjudication, never exemption.** A finding on a test fixture or a demo
project is real noise in a self-scan, but the fix is never an allowlist — every
exemption is a place a real attack can hide. Instead, `-real-roots
<substring,…>` names the root(s) you actually build/ship; every finding is
stamped with the complete set of scan roots that reach it (`reachable_from_roots`
in JSON, over *any* edge type, not just `depends-on`), and one that no
designated root reaches is labeled `contained` with that reachability list as
its proof. The label changes nothing else — same severity, same gate class,
same exit code; a contained block still blocks. It is proof attached to an
otherwise untouched finding, not a suppression. See
[`tools/ihbv-repoguard.py`](tools/ihbv-repoguard.py)`--verify` for the
complementary tamper-adjudication mechanism, below.

## Repo-open execution surface (RepoGuard)

depSNORT answers "what happens when I *install* these dependencies?" Some
campaigns (Miasma/Hades, `Azure/durabletask`, 2026-06-05) skip installation
entirely and execute the moment a repo is *opened* in an editor or AI coding
agent — via checked-in configuration: a VS Code task set to
`"runOn": "folderOpen"`, a devcontainer `initializeCommand` (which runs on the
**host**, before the container exists), or `.claude`/`.cursor`/`.gemini` agent
hooks. No package is installed, so no dependency scanner — depSNORT included —
sees it. That surface is out of scope for the Go binary by construction, so a
companion ships instead:

```
python3 tools/ihbv-repoguard.py /path/to/freshly-cloned-repo
```

Read-only, stdlib-only Python; it never executes, installs, or imports
anything from the target, and discloses what it cannot read rather than
implying clean (the same D-04/D-24 discipline as the Go scanner). It flags
on-open surfaces (`.vscode/tasks.json`, devcontainer lifecycle commands, agent
hook files, `.envrc`, checked-in git hooks) and grades them by whether they
also reach the network or obfuscate their payload, plus a small table of
campaign-specific IOCs (Miasma/Hades, Shai-Hulud lineage markers).

`--verify authentic.sha256` takes a sha256sum-format manifest of known-good
files (`tools/ihbv-authentic.sha256` ships this repo's own). A hash match
adjudicates that file's findings **false** — printed with their evidence,
labeled with the proof, no longer counting toward the exit code. A hash
**mismatch** becomes a new CRITICAL `TAMPERED` finding: a file wearing a
known-authentic name with different content is precisely the planted-lookalike
threat, made the loudest thing in the report instead of an allowlisted blind
spot. Run *your* trusted copy of the script with *your* out-of-band manifest
against the quarantine clone — a manifest checked into the repo it verifies can
be tampered alongside the files it lists.

A ready-to-use IOC feed for the Miasma/Hades campaign ships at
[`docs/ioc-miasma-hades.json`](docs/ioc-miasma-hades.json) for the `-ioc` flag
above (VC-003).

Recommended workflow for an untrusted clone:

```
git clone <repo> /quarantine/path
python3 tools/ihbv-repoguard.py /quarantine/path --verify tools/ihbv-authentic.sha256
./depsnort scan -ioc docs/ioc-miasma-hades.json -real-roots <your-real-root> /quarantine/path
# only if both are acceptable: open in an editor or agent
```

## Quick start

Requires Go 1.24+.

```
go build -o depsnort ./cmd/depsnort      # Windows: depsnort.exe
./depsnort version
./depsnort checks
./depsnort sbom
./depsnort scan ./path/to/project
./depsnort scan -fail-on-eligible .
./depsnort scan -fail-on-incomplete .
./depsnort scan -offline .
./depsnort scan -no-osv .
./depsnort scan -internal-scopes @acme .
./depsnort baseline create -o depsnort-baseline.json .
./depsnort scan -baseline depsnort-baseline.json .
```

**Check which build you have.** `./depsnort version` and every report header
carry the baked-in version (`v0.8.0`). If a report header or the flag list does
not match what you expect, the source tree on disk is stale — re-extract before
debugging anything else.

Try it against the bundled fixtures:

```
# clean tree
./depsnort scan -no-osv -no-registry internal/ecosystem/npm/testdata/proj

# ChainDrop-shaped worm: blocks, exit 1, full install-time subgraph
./depsnort scan -no-osv -no-registry internal/ecosystem/npm/testdata/wormy

# vendored + git dependencies: no findings, but coverage says so
./depsnort scan -no-osv -no-registry internal/ecosystem/cargo/testdata/vendored

# real packages, real CVEs — hits live OSV + npm registry, then caches
./depsnort scan internal/ecosystem/npm/testdata/realworld
```

The `realworld` fixture pins ten genuine npm packages to genuine vulnerable
versions (none malicious — just outdated). A live run resolves ~66 real
advisories in about a second, then works entirely from cache with `-offline`.

## Static build

depSNORT is pure Go and has **zero third-party runtime/build dependencies** in
its module graph. Build with CGO disabled (`CGO_ENABLED=0`, already set in the
Makefile) for a static, no-libc binary — which also sidesteps the
missing-C-headers trap on minimal Linux/WSL.

```
make self-audit
./depsnort sbom
```

The CycloneDX SBOM generated from depSNORT's own embedded Go module graph should
contain an empty `components` array. CI fails if that ever stops being true: a
supply-chain-safety tool must pass its own audit.

## Workspace scanning (full-send by default)

A scan treats the path as a workspace root by default: it discovers **every**
project beneath it — every ecosystem in a directory (a dir with a `yarn.lock` and
a `Gemfile.lock` scans both), every depth, `dist/` build dirs included — and
merges them into one graph with multiple roots.

```
./depsnort scan -o ./reports /path/to/repo
# depsnort: discovered 23 project(s) under /path/to/repo
```

PURL identity deduplicates the same package/version across repositories, so one
flagged dependency exposes its blast radius across the whole workspace instead of
being rediscovered independently in each project.

Discovery prunes `node_modules`, `.git`, `vendor`, `venv`, `site-packages`, and
similar — installed/vendored copies of already-resolved trees, not projects. It
**descends `dist/`, `build/`, and `target/`** by default, because these hold real
dependency-bearing source too (a Docker build context's `requirements.txt`, a
.NET tooling project under `src/build/…`). The generated-artifact *subdirectories*
inside a `build/`/`target/` tree — Maven's `target/classes/META-INF/maven/…`,
cargo's `target/package/…` — are pruned path-contextually (a real source dir of
the same name *outside* a build tree is untouched), so exposing the real projects
never re-introduces the packaged-manifest copies. `-no-build-dirs` skips `build/`
and `target/` entirely (`dist/` still descends). There is no depth bound — a deep
monorepo is reached in full, protected from directory cycles by identity rather
than an arbitrary cap — and unreadable subtrees are skipped rather than aborting.
Two checkouts declaring the same `name@version` merge into a single root, and the
run says so explicitly rather than leaving an unexplained gap between the
discovered count and the root count.

`-no-recursive` (alias `-shallow`) restricts a scan to the given directory,
co-scanning every ecosystem in it but not descending; it then discloses the
subdirectory projects it did not reach as incomplete coverage.

## Output formats

```
./depsnort scan -format json   .
./depsnort scan -format sarif  .
./depsnort scan -format dot    . | dot -Tsvg -o tree.svg
./depsnort scan -format cypher . > load.cypher
./depsnort scan -format pdf    . > report.pdf
```

JSON is the default machine-readable output. SARIF targets CI/code-scanning
workflows. DOT and Cypher expose the graph. PDF renders a human-readable verdict
report — banner, scope, data-source coverage, findings ordered block →
gate-eligible → advisory and by score within each class, and a package risk
table — written by an in-tree PDF writer using base-14 fonts, because buying a
PDF dependency for a supply-chain-safety tool would undercut its own thesis
(D-10).

Output content is designed to remain deterministic. Timestamps live in generated
file paths rather than in report content, so identical scans of identical data
stay byte-comparable.

### Output files

By default output goes to stdout so it stays pipeable. `-o` (or `-out`) writes
files instead; point it at a root and reports land in a dated tree:

```
./depsnort scan -format pdf -o ./reports .
# -> reports/20260807/Report-202608071826UTC.pdf
```

The layout is `<root>/YYYYMMDD/Report-<DTG>.<ext>`. Stamps are **UTC by default**
and deliberately so: a local stamp alternates its abbreviation across daylight
saving (`CDT`/`CST`), which breaks lexical sorting, and on the fall-back night the
same wall-clock hour occurs twice, so two different scans can produce one filename
and silently overwrite each other. `-local` opts back into wall-clock stamps when
readability matters more than ordering. A path **with a file extension** bypasses
the tree and is used verbatim:

```
./depsnort scan -format pdf -o ./oneoff.pdf .   # -> ./oneoff.pdf
```

The written path is announced on stderr so stdout stays clean, and output is
rendered to a buffer before it touches disk — a failed emit leaves no truncated
report to be mistaken for a complete scan.

## CI integration

The CLI is the primitive; the CI gate and pre-commit hook in [`scripts/`](scripts/)
are thin wrappers over the exit-code contract, not a second implementation of it
(D-09/D-30):

```
scripts/depsnort-ci-gate.sh        # CI gate over the exit codes above
scripts/depsnort-pre-commit.sh     # local pre-commit hook
scripts/github-actions.example.yml # workflow example, actions pinned by digest
```

## Project layout

```
cmd/depsnort/                 CLI + exit-code contract
internal/finding/             severity / axis / gate class / risk state / reachable-root proof
internal/purl/                canonical package-url identity
internal/graph/               declared + install-time graph model, coverage, provenance
internal/ecosystem/           ecosystem adapters (incl. gomod) + conformance suite
internal/expand/              Nth-layer transitive walk + version-truth engine
internal/datasource/          OSV, EPSS, registry metadata, deps.dev, go-proxy, IOC, cache
internal/pep440/ pep508/ nugetver/ semver/   version/range models per ecosystem
internal/installsurface/      static install-time analysis
internal/securefs/            path-containment primitive (fuzzed)
internal/profile/             capability profiles and the deterministic drift engine
internal/baseline/            known-good baseline file format
internal/check/               vector-check contract + registry
internal/check/builtin/       built-in VC rules
internal/verdict/             findings -> node state + process exit + containment adjudication
internal/emit/                JSON / SARIF / DOT / Cypher / PDF
internal/versiondrift/        README/pyproject version-literal consistency guard
internal/ciactions/           workflow-action SHA-pin guard
tools/                        ihbv-repoguard.py (repo-open surface triage) + org/priority scan drivers
```

## Market position

depSNORT sits between several established security categories:

| Category | Primary question | depSNORT relationship |
|----------|------------------|-----------------------|
| SCA | "Is this dependency known to be vulnerable?" | consumes CVE context, but does not treat CVEs as its core detection model |
| Package malware scanner | "Does this artifact contain suspicious behavior?" | overlaps through static install-surface analysis |
| Behavioral package analysis | "What does this package do?" | complements dynamic systems with a zero-execution pre-install view |
| Release differential analysis | "What security-relevant behavior changed from N to N+1?" | baseline-relative capability drift (VC-010) |
| Repository firewall / curation | "Should this package be allowed into the organization?" | supplies a verdict; is not itself an enforcement proxy |
| Supply-chain IDS | "Does this dependency/release state match known or anomalous compromise patterns?" | depSNORT's intended operating model |

The project does not claim that individual heuristics are novel. Its
differentiation is the intersection of:

- package-specific release-history anomaly detection;
- static install-time attack-path reconstruction;
- state-transition analysis against an operator-promoted baseline;
- dependency-graph context;
- deterministic rule composition and gating;
- explicit incomplete-coverage semantics;
- local and air-gapped operation.

## Roadmap

**Completed foundations:**

- ✅ canonical graph model + PURL identity;
- ✅ CLI + verdict/exit-code contract;
- ✅ OSV malicious-package and CVE enrichment, with a compiled-in fallback tier;
- ✅ structural checks: typosquat and dependency confusion;
- ✅ temporal checks: dormancy and package-relative release bursts;
- ✅ static install-surface extraction and VC-002 attack paths;
- ✅ operator IOC ledger;
- ✅ JSON, SARIF, DOT, Cypher, and PDF emitters;
- ✅ seven ecosystem adapters;
- ✅ recursive workspace scanning and blast-radius graphing;
- ✅ dependency-source provenance as explicit coverage state (VC-009);
- ✅ capability profiles, persistent known-good baselines, and version-to-version
  capability drift (VC-010);
- ✅ version-level publisher lineage where registries expose it (VC-011);
- ✅ transitive expansion past the manifest across all seven ecosystems, with a
  graded version-truth axis (observed / asserted / presumed / contested) that
  never lets a presumed version gate;
- ✅ an optional deps.dev asserted tier and a cross-ecosystem conformance suite;
- ✅ `yarn.lock` (Yarn v1 classic and v2+ Berry) — resolved via the sibling
  `package.json` — plus `pnpm-lock.yaml` and `bun.lock`;
- ✅ the PyPI lockfile family: `uv.lock` (incl. rootless), `poetry.lock`,
  `pdm.lock`, `pylock.toml` (PEP 751), and `Pipfile`/`Pipfile.lock`;
- ✅ the modern .NET dependency surface: `PackageReference` (incl. Central
  Package Management and `Directory.Build.props`), `.nuspec`,
  `dotnet-tools.json`, `project.json`, `paket.dependencies`, and
  `project.assets.json`'s real resolved tree;
- ✅ install-surface persistence (VC-002g), Go cgo build-flag injection
  (VC-002h) and build-tag-gated init evasion (VC-002i, proven via `go/ast`
  reachability), npm load-time native execution (VC-002j), and self-propagation
  — an install hook that publishes to a registry (VC-002k), the Shai-Hulud worm
  step, drawn as a `republish` edge across all seven ecosystems;
- ✅ yank-lure detection (VC-012): a version pinned to a since-yanked/retracted
  release with a live-newest enrichment shaped like a lure, across
  Cargo/PyPI/Go;
- ✅ a post-expansion advisory pass so packages discovered by transitive
  expansion — and directs whose versions were only known after expansion — are
  OSV-checked too, closing a false-clean gap;
- ✅ opt-in FIRST.org EPSS exploit-probability enrichment (`-epss`), CVE-alias
  resolution for GHSA-/GO-primary advisories, and `-epss-gate` threshold
  escalation;
- ✅ adjudication mechanisms so a finding is proven true or false rather than
  exempted: `-real-roots` containment (complete root-reachability attribution)
  and the companion RepoGuard `--verify` tamper check.

**Current hardening:**

- 🟡 reduce URL-metadata and ecosystem-specific false positives;
- 🟡 expand calibrated typosquat corpora outside npm;
- 🟡 deepen candidate-package install-surface recovery where registries expose
  incomplete metadata.

**Planned, not implemented:**

- ⬜ drift without a baseline file: recovering a previous release's install
  surface directly from the registry, so a first scan can diff N against N-1
  (npm hook-level drift is already available from packument metadata; capability
  -level drift for other ecosystems needs artifact retrieval);
- ⬜ PR-native dependency delta: summarize only newly introduced dependencies,
  versions, capabilities, and gate changes in pull requests;
- ⬜ Maven/Gradle adapters (JVM ecosystems have no adapter at all yet — `pom.xml`
  and `gradle.lockfile` are disclosed as recognized-but-unresolved, not parsed);
- ⬜ policy-as-code for thresholds, allowlists, and approved publishers, over
  fixed safety invariants;
- ⬜ enforcement integrations: feed verdicts into artifact-manager, admission, or
  package-proxy policy without turning the core scanner into a mandatory service;
- ⬜ provenance/attestation verification of scanned dependencies as an additional
  integrity axis;
- ⬜ published precision/recall benchmarks against a public malicious-package
  corpus;
- ⬜ third-party rule-pack loading (deps.dev resolved-graph consumption is
  implemented as the opt-in asserted tier).

The long-term goal is not "more alerts." It is better stateful correlation:

```
known-good package profile
  |
  +-- normal cadence
  +-- publisher lineage
  +-- historical install capabilities
  +-- dependency topology
  +-- prior threat state
  |
  v
candidate release
  |
  v
security-relevant delta + temporal context
  |
  v
explainable IDS verdict
```

## Verifying a release

A supply-chain security tool that ships unverifiable binaries is arguing against
itself. Every tagged release carries a SHA-256 checksum, a CycloneDX SBOM, and a
**signed SLSA provenance attestation** binding the artifact to the exact
workflow, commit, and runner that built it. Signing is keyless (Sigstore via
GitHub OIDC), so there is no long-lived private key to steal or expire, and the
attestation is recorded in the public Rekor transparency log.

```
# 1. checksum
sha256sum -c SHA256SUMS --ignore-missing

# 2. provenance — proves THIS binary came from THIS repo's release workflow
gh attestation verify depsnort-v0.8.0-linux-amd64 --repo MoSLoF/depSNORT

# 3. what it is built from (the components array should be empty)
./depsnort sbom
```

Checksums and SBOM output are byte-reproducible for the same tag, so two people
can independently confirm they got the same artifact (D-13).

## Testing

```
go test ./...            # includes the fuzz seed corpora as regression tests
go vet ./...
gofmt -l .               # should print nothing
go test -race ./...
```

**Fuzzing.** The repository maintains native Go fuzz targets across the seven
lockfile parsers, the PURL identity layer, semver, the install-surface analyzers,
the edit-distance optimization, the sdist archive reader, and path containment.
They are not decoration — fuzzing found and fixed two real identity bugs in the
PURL parser (D-33). The `securefs` target asserts the security invariant
directly: no generated path may ever return content from outside the scan root.

Every seed corpus — including the crashers fuzzing already found — runs as an
ordinary regression test on `go test`. CI additionally spends a bounded budget
actively fuzzing the targets that consume untrusted input directly or guard an
invariant a silent regression would hide: the containment primitive, PURL, the
edit-distance differential, and the seven lockfile parsers.

```
go test ./internal/securefs -run=XXX -fuzz=FuzzReadFileContainment -fuzztime=60s
go test ./internal/purl     -run=XXX -fuzz=FuzzParse                -fuzztime=60s
```

**Performance.** Committed baselines and the profiling method live in
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

```
go test ./cmd/depsnort/ ./internal/ecosystem/npm/ -run=XXX -bench=. -benchmem
```

## Design principles

1. **Zero execution.** Analyze the install path without intentionally running it.
2. **Precision over alert volume.** A detector that operators mute is not a detector.
3. **Composition over single signals.** Weak indicators become useful when correlated.
4. **Unknown is not clean.** Coverage loss is explicit security state.
5. **Deterministic where possible.** Identical evidence should produce identical output.
6. **Sovereign rules.** The built-in vector pack is only the first pack; the rule
   contract is the product boundary.
7. **Dogfood the thesis.** depSNORT's own dependency footprint stays auditable and
   minimal.

---

depSNORT does not try to prove that software is safe. It tries to make suspicious
dependency state visible **before trust becomes execution**.
