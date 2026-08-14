# depSNORT

**An IDS for the dependency supply chain.** Dependabot tells you what's outdated;
Snort matches traffic against a rule pack. depSNORT does the second thing to
your dependency tree: it statically resolves everything a repo pulls in, then
runs it against a modular pack of vector checks — **before a single package is
installed.**

> Design rationale and the full decision log live in [`docs/DECISIONS.md`](docs/DECISIONS.md).

Six ecosystems (npm, PyPI, RubyGems, Cargo, Composer, NuGet); a modular pack of
vector checks spanning known-compromise advisories, install-hook capability
(network / credentials / obfuscation / download-cradle), temporal "weather"
(dormancy, release bursts), typosquatting, dependency confusion, an operator IOC
ledger, and disclosed CVEs; a static install-surface analyzer that reads
lifecycle hooks **without ever running them**; and Neo4j/Cypher, SARIF, DOT, and
PDF output. It compiles, it is tested against an adversarial fixture corpus, and
it does the thing it claims.

## Ethos (non-negotiable)

- **Zero execution.** depSNORT never runs a package manager and never fires a
  lifecycle hook. It parses lockfiles and manifests statically. The whole point
  is to see the tree *before* anything with a `preinstall`/`postinstall` runs.
- **Dogfooded footprint.** The tool has **zero third-party dependencies** — pure
  Go standard library. A supply-chain-safety tool must pass its own audit. Run
  `make self-audit` (or `go list -m all`) and confirm the list is one line, or
  `./depsnort sbom` for the machine-readable version: a CycloneDX SBOM generated
  from the module graph the linker actually embedded, whose `components` array is
  empty. CI fails if that ever stops being true.
- **Sovereign, modular ruleset.** Vector checks are plugins that implement one
  contract. The built-in pack is simply the first pack.

## Layout

```
cmd/depsnort/                 CLI entry + exit-code contract
internal/finding/             severity · axis · gate-class · risk-state · Finding
internal/purl/                canonical package-url identity
internal/graph/               the dual-tree graph model (declared + install-time)
internal/ecosystem/           Adapter seam (multi-ecosystem from day one)
internal/ecosystem/npm/       npm: package-lock.json resolver
internal/ecosystem/pypi/      PyPI: requirements.txt / Pipfile.lock resolver + sdist analysis
internal/ecosystem/rubygems/  RubyGems: Gemfile.lock resolver
internal/ecosystem/cargo/     Cargo: Cargo.lock resolver
internal/ecosystem/composer/  Composer: composer.lock resolver + vendor/ analysis
internal/ecosystem/nuget/     NuGet: packages.lock.json resolver
internal/datasource/registry/ shared registry-metadata client (RubyGems, Cargo, Composer, NuGet)
internal/installsurface/      static install-time capability analysis (all ecosystems)
internal/check/               vector-check plugin contract + registry
internal/check/builtin/       the v0 ruleset (VC-001 through VC-008)
internal/verdict/             findings -> node risk state + process exit code
internal/emit/                output emitters (JSON, SARIF, DOT, Cypher, PDF)
```

## Build & run

Requires Go 1.24+. No network needed (no external modules to fetch).

```
go build -o depsnort ./cmd/depsnort      # Windows: go build -o depsnort.exe ./cmd/depsnort
./depsnort checks                        # list registered vector checks
./depsnort sbom                          # emit depsnort's OWN CycloneDX SBOM
./depsnort scan ./path/to/project        # analyze; emits JSON to stdout
./depsnort scan -fail-on-eligible .      # let gate-eligible warnings fail CI
./depsnort scan -offline .               # OSV cache only; never touch the network
./depsnort scan -no-osv .                # skip the OSV data-source layer
./depsnort scan -internal-scopes @acme . # enable dependency-confusion (VC-007)
```

> **Check which build you have.** `./depsnort version` and every report header
> carry the baked-in version (`v0.7.4`). If a report header or the flag list does
> not match what you expect, the source tree on disk is stale — re-extract before
> debugging anything else.

> **Build with CGO disabled.** depSNORT is pure Go; build it as a static
> binary (`CGO_ENABLED=0`, already set in the Makefile). One-time for manual
> builds: `go env -w CGO_ENABLED=0`. This yields a no-libc static binary
> (Decision D-10) and sidesteps the missing-C-headers trap on minimal Linux/WSL.

### Structural checks (offline, no network)

Two checks need no data source at all. **VC-006** flags package names that are a
near-miss of a popular package — typosquats — as *advisory* (surfaced, never
gates). It is calibrated against real-world data: scoped packages are skipped
(a scope is explicit provenance, not impersonation), an evidence-driven
allowlist exonerates legitimate near-neighbours like `preact` and `scapy`,
distance-2 matches require a name of at least 10 characters, and a package
pulled in by an established parent is vouched for. See D-17. **VC-007** flags a dependency matching one of your
declared internal scopes/names (`-internal-scopes`, `-internal-names`) that
resolves from a *public* registry — a dependency-confusion substitution — as
*gate-eligible*. VC-007 is a no-op until you declare something internal, so it
raises zero false alarms by default.

### Data sources (OSV)

`scan` cross-checks every resolved `package@version` against OSV.dev, splitting
the result across the two axes: **VC-001** flags known-malicious releases
(`MAL-*` advisories → FLAG / block / exit 1), and **VC-008** reports ordinary
CVEs (advisory / never-gate, so vuln noise cannot fail the build). Advisories
are fetched once, up front, and **cached on disk** (`-osv-cache`, default under
your user cache dir); `-offline` runs entirely from that cache for
deterministic, air-gapped gating. Degraded coverage (offline misses, network
errors) is reported under `data_sources` in the JSON — a partial run is never
mistaken for a clean one.

The OSV client honors the standard `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`
environment variables (Go's default HTTP transport reads them), so a
sandboxed or corporate runner can reach `api.osv.dev` through an egress
proxy without any depSNORT-specific configuration — just allowlist the host
in your proxy policy.

When no network path to `api.osv.dev` exists at all — a fully air-gapped CI
runner or sandbox — `-osv-snapshot <file>` imports a JSON advisory snapshot
into the OSV cache before the scan runs, so `-offline` has real coverage on
a first run instead of an empty cache. The snapshot is a JSON array of
`{"ecosystem", "name", "version", "advisories": [...]}` records (the same
`Advisory` shape OSV itself returns); a container image or CI cache can ship
a periodically-refreshed snapshot file alongside the repo:

```
./depsnort scan -osv-snapshot advisories-snapshot.json -offline .
```

That snapshot file doesn't have to be hand-written. `-osv-export <file>` writes
the results of a NORMAL, network-connected scan out in the same format — run it
once somewhere with network access, then ship the resulting file to every
air-gapped environment that needs `-osv-snapshot`:

```
# once, with network access: scan and capture what OSV said
./depsnort scan -osv-export advisories-snapshot.json .

# everywhere else: bootstrap from that file, zero network calls
./depsnort scan -osv-snapshot advisories-snapshot.json -offline .
```

`-osv-export` requires a live OSV query to have something to export, so it's
rejected together with `-offline` or `-no-osv` (exit 64, usage error) rather
than silently writing an empty or stale file. If the live query itself fails
partway through, the export is skipped with a warning instead of writing a
snapshot that looks complete but isn't.

Try it against the bundled fixtures:

```
# clean tree
./depsnort scan -no-osv -no-registry internal/ecosystem/npm/testdata/proj

# ChainDrop-shaped worm: blocks, exit 1, full install-time subgraph
./depsnort scan -no-osv -no-registry internal/ecosystem/npm/testdata/wormy

# real packages, real CVEs — hits live OSV + npm registry, then caches
./depsnort scan internal/ecosystem/npm/testdata/realworld
```

The `realworld` fixture pins ten genuine npm packages to genuine vulnerable
versions (none malicious — just outdated). A live run resolves ~66 real
advisories in about a second and then works entirely from cache with `-offline`.

## Exit-code contract

The CLI is the primitive; a CI gate and a pre-commit hook are thin wrappers over
these codes (Decision D-09).

| code | meaning |
|------|---------|
| `0`  | clean, or only **advisory** findings present |
| `1`  | a **block**-class finding (FLAG) was present |
| `2`  | a **gate-eligible** finding was present **and** `-fail-on-eligible` was set |
| `3`  | resolution **coverage was degraded** **and** `-fail-on-incomplete` was set |
| `64` | usage error |
| `70` | internal / operational error |

**Advisory findings never change the exit code**, regardless of policy — this is
a structural guarantee enforced in `internal/verdict` (Decision D-06).

Exit `3` is coverage as a first-class verdict axis (D-24): *"we found nothing"*
and *"we could not look"* are different answers. When resolution degrades —
unpinned specifiers, an offline OSV miss, an unreadable subtree — the run reports
it under `data_sources`/`coverage` and, **only** if you opt in with
`-fail-on-incomplete`, gates on it. A partial scan is never silently promoted to
a clean one. Precedence when several apply is block > gate-eligible > incomplete.

### Install-surface extraction (the VC-002 family)

`scan` statically reads each package's install-time code — npm lifecycle hooks,
Python `setup.py`/`build-backend`/`.pth` files, Ruby `extconf.rb`, Rust
`build.rs`, PHP Composer scripts and plugin types, NuGet `install.ps1` — and
materializes the **install-time subgraph**: `install-hook`,
`referenced-artifact`, and `sink` nodes joined by `declares-hook`, `hook-execs`,
`hook-fetches`, and `hook-reads-env` edges. Nothing is executed: it reads text
and pattern-matches (Decision D-04). Hook source is read from on-disk trees,
fetched from package registries (PyPI sdists), or skipped when unavailable.

The family scores *where the chain reaches*: **VC-002b** network egress
(gate-eligible), **VC-002c** named credentials (gate-eligible), and **VC-002e**
decode-and-execute indirection (gate-eligible). Two shapes are promoted to
**block**: **VC-002d** — named credentials **plus** network egress, the
credential-harvesting shape — and **VC-002f**, a download-and-execute cradle
(`curl … | sh`, `iex (…).DownloadString`, `certutil -urlcache`, and kin) fetching
remote code from an install hook. When a cradle is present, VC-002b defers to
VC-002f so the reach is reported once, at the higher gate class, not twice.

Precision matters more than reach here. Broad env access (`process.env`,
`os.environ`, `ENV[]`) is deliberately *not* a credential signal (it is recorded
as the weaker `env` capability), because legitimate native-build hooks read env
vars and download prebuilt binaries; treating that as exfil would flag `sharp`,
`bcrypt`, `sqlite3` and earn the tool a mute. Only *named* secrets
(`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`, `GEM_HOST_API_KEY`, `.npmrc`,
`AWS_SECRET_ACCESS_KEY`, `id_rsa`, …) count. A fixture pair in `testdata/wormy`
locks this in: a worm-shaped package that must FLAG, and a benign native-build
package that must not.

Run `./depsnort scan -no-osv internal/ecosystem/npm/testdata/wormy` to see the
full install-time subgraph and a block verdict (exit 1).

### Ecosystems

Six ecosystems, each with its own lockfile parser and install-surface analysis:

| Ecosystem | Lockfile(s) | PURL type | Install-time vector |
|-----------|-------------|-----------|---------------------|
| **npm** | `package-lock.json` (v1–v3) | `pkg:npm/` | `preinstall`/`postinstall` scripts |
| **PyPI** | `requirements.txt`, `Pipfile.lock` | `pkg:pypi/` | `setup.py`, `build-backend`, `.pth` files |
| **RubyGems** | `Gemfile.lock` | `pkg:gem/` | `extconf.rb` (native extensions) |
| **Cargo** | `Cargo.lock` | `pkg:cargo/` | `build.rs` (build scripts) |
| **Composer** | `composer.lock` | `pkg:composer/` | `composer.json` scripts, plugin packages |
| **NuGet** | `packages.lock.json` | `pkg:nuget/` | `install.ps1`, `init.ps1` (legacy) |

All six share the same graph model, check contract, verdict engine, and emitters.
Adding an ecosystem requires only a lockfile parser and name normalization —
the VC-002 family fires on install-time subgraph nodes regardless of ecosystem.

**PyPI specifics.** Names are normalized per **PEP 503** (lowercase; runs of
`-`, `_`, `.` collapse to one `-`), so `Flask_SQLAlchemy` and
`flask-sqlalchemy` resolve to one node. pip-compile's `# via <parent>` comments
are parsed into real depends-on edges. Unpinned specifiers are **not** resolved
(D-01) but are disclosed as `pypi.unresolved` so partial coverage is never
hidden. `poetry.lock` and `uv.lock` are TOML; they wait for a minimal in-tree
reader (D-10).

**Composer specifics.** The **root** project's `composer.json` is always read
from the project directory — its own lifecycle scripts and `composer-plugin` type
(which auto-executes during every Composer operation) are examined even when no
`vendor/` tree is present (D-27). Transitive packages are read from
`vendor/<pkg>/composer.json` when installed. When a package is a plugin, its
resolved PHP entrypoint (PSR-4) is statically scanned for a download-cradle so an
auto-loaded plugin that fetches and runs a payload is caught (D-27/D-28).

**Cargo specifics.** Cargo.lock is parsed with a line-by-line scanner (no TOML
dependency, D-10). Multiple versions of the same crate are supported.

### The temporal axis (recent-compromise weather)

A lockfile pins one version and knows nothing about release history, so the
temporal checks read publish timestamps from each ecosystem's registry API
(metadata only — never a tarball, never an install). All five registries are
queried: npm (packument `time` map), RubyGems (`/api/v1/versions`), crates.io
(`/api/v1/crates/.../versions`), Packagist (`/p2/` metadata), and NuGet
(registration index with catalog entries). Results are cached to disk;
`-offline` serves the cache exclusively, and `-no-registry` disables all sources.

**VC-005** flags a release burst around the pinned version — the republish
signature, where a worm patch-bumps and republishes every package it infects.
The window is centered, not backward-looking, because the pinned version may be
anywhere in the cluster. Anomaly is judged against the package's **own** median
cadence: a package that ships three times a day is not suspicious for shipping
three times a day, while three releases in an hour from a package that normally
ships twice a year is. **VC-004** flags a version published after prolonged
dormancy — the account-takeover shape. It is *advisory* alone, because healthy
packages go quiet and then ship maintenance releases; it escalates to
gate-eligible only when the awakening release also declares an install hook.

Both are decay-scored: `score = severity × confidence × recency_decay`, with an
exponential 90-day half-life (`datasource.DefaultHalfLife`). "Recent" is a curve,
not a cliff — a three-year-old dormancy event scores near zero instead of
shouting as loudly as one from last week.

Confidence also **composes**: a burst on a package that declares an install hook
scores higher than either signal alone. That composition is what separates the
ChainDrop shape from ordinary release noise.

### Output formats

```
./depsnort scan -format json   .              # machine-readable (default)
./depsnort scan -format sarif  .              # CI dashboards / GitHub code scanning
./depsnort scan -format dot    . | dot -Tsvg -o tree.svg
./depsnort scan -format cypher . > load.cypher && cypher-shell -f load.cypher
./depsnort scan -format pdf    . > report.pdf   # human-readable report
```

### Workspace scanning

`-recursive` treats the path as a workspace root, discovers every supported
project beneath it, and merges them into **one graph with multiple roots**:

```
./depsnort scan -recursive -o ./reports /path/to/repos
# depsnort: discovered 23 project(s) under /path/to/repos
```

Because identity is the PURL, a package at the same version in two repos is one
node — so a flagged dependency shows its **blast radius across every project
that pulls it in**, rather than being rediscovered N times in N reports.

Discovery skips `node_modules`, `.git`, `vendor`, `venv`, `site-packages`,
`target` (Rust build output), and similar (a vendored lockfile is not a project),
caps depth at 8, and skips
unreadable subtrees rather than aborting. Two checkouts declaring the same
`name@version` merge into a single root; when that happens the run says so
explicitly rather than leaving a gap between the discovered count and the root
count.

### Output files

By default output goes to stdout so it stays pipeable. Pass `-o` (or `-out`) to
write files instead. Point it at an output **root** and reports land in a dated
tree using a stable naming convention:

```
./depsnort scan -format pdf -o ./reports .
# -> reports/20260807/Report-202608071826UTC.pdf
```

The layout is `<root>/YYYYMMDD/Report-<DTG>.<ext>`. The date folder groups a
day's scans; the DTG — `YYYYMMDDHHMM` plus timezone abbreviation — keeps each run
distinct and stays self-describing if the file is moved out of its folder.
Stamps are **UTC by default**, and deliberately so. A local stamp alternates its
abbreviation across daylight saving (`CDT`/`CST`), which breaks lexical sorting
of a report tree — and on the fall-back night the same wall-clock hour occurs
*twice*, so two genuinely different scans can produce an identical filename and
one silently overwrites the other. UTC has neither problem. `-local` opts back
into wall-clock stamps when readability matters more than ordering; note that
converting rolls the date folder too, so a 22:30 CDT scan correctly files under
the next UTC day.

A path **with a file extension** bypasses the tree and is used verbatim:

```
./depsnort scan -format pdf -o ./oneoff.pdf .   # -> ./oneoff.pdf
```

Resolution is minute-level, so two scans in the same minute share a name and the
second overwrites the first. Note where the timestamp lives: in the **path**,
never in the file. Report content stays byte-reproducible (D-13), so the tree
sorts chronologically while two scans of an unchanged tree still diff clean. The
written path is announced on stderr so stdout stays clean, and output is rendered
to a buffer before it touches disk — a failed emit leaves no truncated report to
be mistaken for a complete scan.

**PDF** renders the human-readable report: verdict banner, scope, data-source
coverage (including an explicit warning when coverage was incomplete, and a
separate `not-published` count for packages the registry has no record of),
findings
ordered block → gate-eligible → advisory and by score within each class, and a
package risk table. It is written by an in-tree PDF writer using base-14 fonts —
no third-party library, because buying a PDF dependency for a supply-chain-safety
tool would undercut its own thesis (D-10). The report carries **no timestamp**,
so two scans of identical data produce identical bytes (D-13).

Risk propagates through the install-time subgraph: when a package is flagged,
the hook, the files it executes, the URLs it reaches, and the credential sinks
it touches are flagged too, because they are the *reason* for the verdict. It
only ever raises, never softens, and it does **not** cross `depends-on` edges —
a bad package does not turn its whole transitive tree red.

## The dual-tree model

A lockfile is the tree the *developer* wrote. An install hook is the tree the
*attacker* wrote — an undeclared manifest. The graph models both from day one:
`depends-on` edges for the declared subgraph, and
`declares-hook / hook-execs / hook-fetches / hook-reads-env / exfil / republish`
for the install-time subgraph. v0 populates only the declared subgraph; the
install-time kinds and edges already exist so that install-surface extraction
(build-queue step 5) drops in without a schema change.

## Roadmap (prioritized build queue)

1. ✅ Canonical graph model + PURL + npm `package-lock` parser
2. ✅ CLI shell + exit-code contract + JSON emitter
3. ✅ Data-source layer: OSV (incl. malware) + local cache → VC-001, VC-008
4. ✅ Structural + temporal checks → VC-004 (dormancy), VC-005 (patch-burst), VC-006 (typosquat), VC-007 (dependency-confusion)
5. ✅ **Install-surface extraction + hook subgraph** → the VC-002 family (catches the ChainDrop shape before any feed)
6. ✅ Recent-compromise layer → registry metadata for all 6 ecosystems + decay scoring + **VC-003** (operator IOC-ledger match, `-ioc`, block-class)
7. ✅ Emitters: SARIF · DOT · Neo4j/Cypher · PDF
8. ✅ Six ecosystem adapters — npm, PyPI, RubyGems, Cargo, Composer, NuGet
9. 🟡 Fine-tuning: URL-metadata false positives, typosquat corpora for non-npm ecosystems
10. ⬜ deps.dev manifest resolution + third-party plugin loading

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
gh attestation verify depsnort-v0.7.4-linux-amd64 --repo MoSLoF/depSNORT

# 3. what it is built from (the components array should be empty)
./depsnort sbom
```

Checksums and the SBOM are byte-reproducible: rebuilding the same tag produces
identical bytes, so two people can independently confirm they got the same
artifact (D-13).

## Testing

```
go test ./...            # includes the fuzz seed corpora as regression tests
go vet ./...
gofmt -l .               # should print nothing
go test -race ./...
```

**Fuzzing.** There are **19** native Go fuzz targets covering the six lockfile
parsers, the PURL identity layer, semver, the five install-surface analyzers, the
edit-distance optimization, the sdist archive reader, and path containment. They
are not decoration — fuzzing found and fixed two real identity bugs in the PURL
parser (see D-33). The `securefs` target asserts the security invariant directly:
no generated path may ever return content from outside the scan root.

Every seed corpus — including the crashers fuzzing already found — runs as an
ordinary regression test on `go test`. CI additionally spends a bounded 25s
actively fuzzing **9** of the 19: the containment primitive, PURL, the
edit-distance differential, and the six lockfile parsers. Those are the targets
that consume untrusted input directly or guard an invariant a silent regression
would hide; the analyzer and semver targets are covered by their seeds in CI and
by out-of-band campaigns.

```
go test ./internal/securefs -run=XXX -fuzz=FuzzReadFileContainment -fuzztime=60s
go test ./internal/purl     -run=XXX -fuzz=FuzzParse                -fuzztime=60s
```

**Performance.** Committed baselines and the profiling method live in
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

```
go test ./cmd/depsnort/ ./internal/ecosystem/npm/ -run=XXX -bench=. -benchmem
```
