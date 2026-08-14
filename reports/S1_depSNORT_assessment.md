# S1 — depSNORT Supply-Chain Assessment

**Project:** TM-022 · Session 1 of 2 · **Date:** 2026-08-14
**Tool:** depSNORT (`ihbv.io/depsnort`), built from source at branch
`claude/tm022-wave1`, Go 1.24.7, `CGO_ENABLED=0`. Self-reported version: `dev`.
**Target:** `MoSLoF/impacket` @ `4c09897a` (dependency tree only; read-only).
**Scope:** static supply-chain analysis only. No impacket execution beyond the
pin-set build step noted below; no exploit construction; ccache subsystem left
to Session 2.

---

## Zero-execution: engine vs. pipeline (read this first)

depSNORT's **scan engine is zero-execution** — it parses manifests/lockfiles and
reads install hooks statically, never running a package manager or firing a
hook. That property is confirmed below.

The **pipeline around it in this session is not.** Building the Run-2 pin set
required `python3 -m venv` + `pip install -e .` of impacket into an isolated
venv, which **executed impacket's `setup.py` and downloaded and installed 20
third-party packages from PyPI** (Flask 3.1.3, cryptography 50.0.0,
pycryptodomex 3.23.0, …). That is real code execution and real network fetches.
It is reported here as a distinct, non-zero-execution step; the engine's
property does not extend to it.

---

## Part A — Build & self-audit

| Check | Result |
|---|---|
| `go build` (CGO off) | **clean**, no external modules fetched |
| `depsnort version` / `checks` | work; 13 checks VC-001…VC-008 registered |
| `go list -m all` | **one line** (`ihbv.io/depsnort`) — zero third-party deps |
| `depsnort sbom` → `components[]` | **empty** → SBOM clean |

The dogfood claim (Decision D-10, zero third-party dependencies) **holds**: a
supply-chain-safety tool passing its own audit. Confirmed two independent ways
(module graph + CycloneDX SBOM).

---

## Part B — Repo-state determination

Delivered separately in **`reports/S1_repo_state.md`** (factual patch-status
record). Summary: `impacket_0_13_1` tag **absent** in this fork (0 tags), so
0.13.1-baselined comparisons and the EC-01 determination are **indeterminate**
from a static vantage; latest `ccache.py` change on master is `243d64a6`.

---

## Part C — depSNORT runs (raw artifacts alongside this report)

### Run 1 — impacket as-shipped (unpinned)

impacket's `requirements.txt` is entirely unpinned (floors/exclusions only,
e.g. `pyasn1>=0.2.3`, `ldap3>=2.5,!=2.5.2,…`; no lockfile).

- 10 unresolved dependencies; **coverage degraded** (`complete:false`).
- stderr: *"coverage is incomplete: 10 unresolved dependenc(ies) … This report
  is NOT an all-clear."*
- Findings: 0 (nothing resolvable to check). Exit **0** plain; exit **3** under
  `-fail-on-incomplete`.
- This is **Decision D-01** working as designed — depSNORT refuses to resolve
  unpinned specifiers rather than guess. Correct behaviour, not a tool failure.
- Artifact: `scan-repo.json`.

### Run 2 — pinned snapshot (20 deps)

Pin set built from the installed venv (`pinned-requirements.txt`, 20 transitive
packages). Scanned **live** (registry reachable; OSV not).

- 32 nodes resolved (flat PyPI resolution), 0 unresolved.
- **1 finding — VC-004** (dormancy, advisory): `pkg:pypi/pyasn1@0.6.4` —
  *"0.6.4 published after 492d of dormancy."* Advisory only; does not gate.
- **VC-001 did NOT fire** — no known-malicious package in the tree. The tree is
  not poisoned; the assessment proceeds normally (no escalation triggered).
- No VC-002 (no install hooks surfaced on these wheels), no VC-007.
- Exit **0**. Artifacts: `scan-pinned.json`, `scan-pinned.sarif` (SARIF 2.1.0,
  1 run), `scan-pinned.pdf` (valid PDF, 1 page).

### Run 3 — CI gate simulation (pinned dir)

| Invocation | Exit | Meaning |
|---|---|---|
| `scan` (plain) | **0** | advisory-only + coverage gap does not fail a plain run |
| `scan -fail-on-incomplete` | **3** | OSV data-source gap = incomplete coverage |
| `scan -fail-on-eligible` | **0** | no gate-eligible findings (VC-004 is advisory) |
| `scan -fail-on-incomplete -fail-on-eligible` | **3** | incomplete asserted |

**Exit-code contract** (observed + source-confirmed): `0` clean · `1` block ·
`2` gate-eligible (with `-fail-on-eligible`) · `3` incomplete (with
`-fail-on-incomplete`) · `64` usage · `70` internal. Block outranks incomplete.
The contract was **reliable and consistent** across live and offline runs.

---

## Part D — Findings

```
FINDING: DEP-01 — impacket ships an entirely unpinned dependency manifest
TOOL/CHECK: depSNORT (Decision D-01, resolution refusal)
SEVERITY: informational (coverage)
EXIT CODE: 0 plain / 3 under -fail-on-incomplete
DESCRIPTION: requirements.txt carries only version floors/exclusions and no
  lockfile. depSNORT refuses to resolve unpinned specifiers, leaving 10 of the
  root's dependencies unresolved and coverage degraded. It says so explicitly
  ("NOT an all-clear") rather than returning a silent pass.
PACKAGE(S): impacket root (charset_normalizer, flask, ldap3, ldapdomaindump,
  pyOpenSSL, pyasn1, pyasn1_modules, pycryptodomex, setuptools, six)
OPERATIONAL NOTE: as-shipped, impacket cannot be supply-chain-gated with
  precision — any downstream consumer must pin (lockfile or hashes) before a
  meaningful scan is possible. A CI gate using -fail-on-incomplete would
  correctly fail this repo (exit 3).
```

```
FINDING: DEP-02 — pyasn1 0.6.4 published after prolonged dormancy
TOOL/CHECK: depSNORT VC-004 (weather / dormancy)
SEVERITY: advisory
EXIT CODE: 0 (advisory never gates)
DESCRIPTION: pyasn1 0.6.4 was released after 492 days of package dormancy — the
  account-takeover shape. Advisory alone. It would escalate to gate-eligible
  only if the awakening release also declared an install hook; it does not, so
  no compounding here.
PACKAGE(S): pkg:pypi/pyasn1@0.6.4
OPERATIONAL NOTE: pyasn1 is a mainstream, long-lived ASN.1 library; a dormancy
  gap is consistent with slow-moving maintenance and is not on its own a
  compromise signal. Worth a glance at the 0.6.4 release provenance, nothing
  more. No install-hook compounding observed.
```

```
FINDING: DEP-03 — OSV-backed checks (VC-001 / VC-008) uncovered this session
TOOL/CHECK: depSNORT OSV data source
SEVERITY: informational (coverage gap — honestly disclosed)
EXIT CODE: 3 under -fail-on-incomplete
DESCRIPTION: api.osv.dev is blocked by this session's egress policy (proxy
  CONNECT 403 — a policy denial, not routable around). The compiled-in bundled
  OSV fallback IS real, live-generated data (22 entries, 156 advisories,
  generated 2026-08-14) but is version-keyed to an OLD fixture set
  (flask 0.12.2, werkzeug 0.15.0, jinja2 2.10, …); none of impacket's MODERN
  pinned versions match, so all 20 OSV lookups fall through as GAPS. Critically,
  depSNORT treats an uncovered package as a GAP, never as "checked clean," and
  flags data_source_gaps:[osv] with an explicit "NOT an all-clear."
PACKAGE(S): all 20 pinned deps (OSV coverage), for both VC-001 (known-malicious)
  and VC-008 (CVEs)
OPERATIONAL NOTE: in this environment the two most security-relevant OSV checks
  could not run. VC-008 CVE count for the pinned tree is therefore UNKNOWN
  (not zero). To close this, an operator needs OSV reachability, a warmed
  --osv-cache, or an -osv-snapshot mirror import covering current versions.
  Absence of a VC-001 block is NOT evidence of a clean tree here — it is an
  uncovered dimension.
```

---

## Part E — depSNORT tool evaluation

```
TOOL: depSNORT (version "dev"; built from claude/tm022-wave1, Go 1.24.7)
BUILD: clean — zero external modules, CGO disabled
SBOM CLEAN: yes — components[] empty; go list -m all is one line
FINDINGS ON TARGET: 1 advisory (VC-004); 0 block; 0 gate-eligible;
  coverage degraded (unpinned in Run 1; OSV gap in Run 2)
COVERAGE: degraded — Run 1 (10 unresolved, unpinned); Run 2 (OSV/VC-001/VC-008
  uncovered). Registry-backed temporal checks (VC-004/005) DID run.
```

**STRENGTHS** (grounded in observed behaviour, not README claims)
- **Never a silent all-clear.** Every degraded run emitted a stderr warning
  *and* a machine-readable `data_source_gaps` / `coverage.complete:false`. The
  gap is a first-class output, not a footnote.
- **Version-keyed OSV avoids false-clean.** A package absent from the bundled
  snapshot falls through to a gap rather than being marked clean — the honest
  behaviour for a known-bad denylist, and it held exactly so on this target.
- **Exit-code contract is reliable and precise.** 0/1/2/3 behaved identically
  live and offline; `-fail-on-incomplete` correctly keyed on the OSV gap (exit
  3) while `-fail-on-eligible` correctly stayed 0 for an advisory-only result.
- **Dogfood is real.** Zero third-party deps confirmed two ways; the tool
  passes the audit it performs on others.
- **D-01 refusal is principled.** Declining to resolve unpinned specifiers
  (rather than guessing latest) is the right call for a security gate and is
  disclosed as degraded coverage, not hidden.
- **Multi-format emit works** on a real target: JSON, SARIF 2.1.0, and a valid
  1-page PDF all produced without error.

**GAPS** (specific, reproducible)
- **Bundled OSV snapshot has near-zero real-world coverage on a modern tree.**
  Its 12 PyPI entries are pinned to years-old versions; 6 overlap impacket's
  deps *by name* but 0 by version, so it contributed nothing here. In an
  egress-restricted sandbox this leaves VC-001/VC-008 effectively disabled.
  *Fix:* broaden the snapshot to a rolling window of current major versions, or
  document that bundled OSV is best-effort denylist coverage only and surface a
  clear "bundled snapshot did not cover N/N queried coordinates" line.
- **No offline CVE path that actually covers current packages.** `-osv-snapshot`
  exists but needs a pre-built mirror the operator must source live. *Fix:*
  ship/point to a documented mirror-warming workflow for air-gapped CI.
- **`version` prints `dev`** with no commit/build stamp. For a supply-chain
  provenance tool this is a self-provenance gap. *Fix:* embed build version +
  VCS commit via `-ldflags`/`debug.ReadBuildInfo`.

**UNTESTED SURFACE** (this session did not exercise)
- VC-001 **block** path and the poisoned-tree stop/escalate flow (no malicious
  package present).
- VC-002 family against a **legitimate** install-hook package — impacket's wheel
  deps surfaced no hooks, so the "correctly does NOT flag a legit hook" claim
  was **not** exercised on this target (only the adversarial fixtures showed
  VC-002a/b firing on a true-positive exfil hook).
- VC-003 (IOC ledger), VC-006 (typosquat), VC-007 (dependency confusion).
- Live OSV query path (blocked by policy); warmed `--osv-cache`.
- Ecosystems other than PyPI (npm/RubyGems/Cargo/Composer/NuGet).
- DOT and Cypher/Neo4j emitters (only JSON/SARIF/PDF exercised).

---

## Artifacts

| File | What |
|---|---|
| `scan-repo.json` | Run 1 — impacket as-shipped (unpinned), degraded |
| `scan-pinned.json` | Run 2 — pinned 20-dep snapshot, VC-004 advisory |
| `scan-pinned.sarif` | Run 2 — SARIF 2.1.0 |
| `pinned-requirements.txt` | resolved pin set (pipeline output, non-zero-execution step) |
| `reports/S1_repo_state.md` | factual impacket repo-state record |

*(`scan-pinned.pdf` produced and validated during the run; not committed as a
binary artifact.)*
