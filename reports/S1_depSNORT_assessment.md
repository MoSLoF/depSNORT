# S1 — depSNORT Supply-Chain Assessment + Tool Evaluation

**Project:** iHBV-TM-022 · Wave 1 · Session 1
**Target:** `MoSLoF/impacket` @ `4c09897a` (declared 0.14.0.dev)
**Tool:** depSNORT @ `c5465b2` (version string `dev`, 9 commits ahead of `v0.7.3`)
**Date:** 2026-08-14 (UTC) · **Scope:** static analysis only, zero exploit work

> **Zero-execution scoping (read first).** depSNORT's *engine* is
> zero-execution: it parses lockfiles/manifests and never runs a package
> manager or install hook. The *surrounding pipeline* in this session is not
> uniformly zero-execution — the intended pin-building step (`pip install -e .`)
> both executes the target fork's `setup.py` and reaches the network. That step
> was blocked by the environment classifier and replaced with a static hand-pin
> (see Coverage). The engine's zero-execution property does **not** extend to
> the pipeline, and nothing below should be read as if it did.

---

## Headline

- depSNORT builds clean with **zero third-party dependencies**; its own SBOM is
  empty. The self-audit thesis holds under inspection.
- **No VC finding fired** on either the as-shipped repo or the pinned set —
  **but coverage was degraded on every run**, so this is explicitly *not* an
  all-clear. VC-001/VC-008 never got real OSV coverage (403 in-sandbox).
- depSNORT's coverage disclosure is excellent in the **JSON** path and via
  **exit codes** (a `-fail-on-incomplete` gate correctly refuses the scan), but
  the **SARIF** path drops all coverage/degradation signal — a SARIF-only CI
  consumer would see a silent all-clear. Filed as FN-01 (field notes).

---

## Findings

### FINDING: DEP-01 — impacket ships an entirely unpinned requirements.txt
```
TOOL/CHECK:      depSNORT (resolution / coverage, Decision D-01)
SEVERITY:        informational (coverage-degrading, not a vector-check hit)
EXIT CODE:       0 (plain scan) · 3 (with -fail-on-incomplete)
DESCRIPTION:     All 10 root specifiers in impacket/requirements.txt are
                 unpinned (`six`, `flask>=1.0`, `pyasn1>=0.2.3`, ...).
                 depSNORT refuses to resolve unpinned specifiers (D-01) and
                 reports degraded coverage: verdict.coverage.complete=false,
                 unresolved_dependencies=10, with every name listed under
                 unresolved_names. This is correct, by-design behaviour — a
                 tool that guessed a version here would be inventing coverage.
PACKAGE(S):      charset_normalizer, flask, ldap3, ldapdomaindump, pyOpenSSL,
                 pyasn1, pyasn1_modules, pycryptodomex, setuptools, six
OPERATIONAL NOTE: impacket cannot be meaningfully supply-chain-scanned from its
                 repo alone; it requires a resolved/pinned environment (a lock,
                 or `pip freeze`) as the scan input. An unpinned tree is not a
                 depSNORT failure — it is a property of the target.
```

### FINDING: DEP-02 — VC-001 / VC-008 coverage is blind on this target
```
TOOL/CHECK:      depSNORT VC-001 (known-malicious), VC-008 (known-CVE) via OSV
SEVERITY:        informational (coverage gap — the finding is the ABSENCE of coverage)
EXIT CODE:       0 (plain) · 3 (-fail-on-incomplete)
DESCRIPTION:     Live OSV (api.osv.dev/v1/querybatch) returns HTTP 403 Forbidden
                 through the session proxy. Pinned scan: 9 queried / 0 advisories
                 / 9 gaps; verdict.coverage.data_source_gaps=["osv"],
                 coverage.complete=false. The compiled-in bundled OSV set (22
                 known advisories) can catch a KNOWN-bad package even offline but,
                 by design, does not certify a clean package as clean — absent
                 packages fall through to a gap.
PACKAGE(S):      all 9 pinned direct deps (see pinned-requirements.txt)
OPERATIONAL NOTE: "No block finding" here means "VC-001 was never really checked,"
                 not "tree is clean." This drives Operator Gate Check 2 → NOT
                 SATISFIED (see S1_repo_state.md). Session 2 must not claim
                 dependency-tree cleanliness on the strength of this scan.
```

### FINDING: DEP-03 — install-surface hooks present, all correctly classified clean
```
TOOL/CHECK:      depSNORT VC-002 family (install-hook capability analysis)
SEVERITY:        informational (precision confirmation — nothing gated)
EXIT CODE:       0
DESCRIPTION:     depSNORT extracted install-surface hooks as graph facts and
                 classified every one CLEAN. Hooks observed on the pinned set:
                   - charset-normalizer  setup.py module-level
                   - ldap3               setup.py module-level
                   - pycryptodomex       setup.py cmdclass.build_ext  (native C build)
                   - pycryptodomex       setup.py module-level
                   - pyopenssl           pyproject.toml build-backend + setup.py module-level
                   - six                 setup.py module-level
                 On the as-shipped repo it also saw impacket's own setup.py
                 module-level hook (the git-metadata versioning shim) and
                 classified it clean.
                 None reached the VC-002b (network) / VC-002c (named creds) /
                 VC-002d (exfil-capable = creds + egress, block-class) tiers.
                 pycryptodomex's native-build hook is exactly the benign
                 native-build case D-11 protects from mis-promotion.
PACKAGE(S):      as above
OPERATIONAL NOTE: This is the precision result the assessment was asked to
                 confirm: legitimate hooks (native builds, versioning shims,
                 build-backend declarations) are seen and NOT flagged. bare
                 process.env-style reads classify as the weaker `env` capability,
                 never `credentials`, so they cannot reach the block tier.
```

### Vector checks that did NOT fire (with coverage caveat)
| Check | Class | Fired? | Coverage note |
|---|---|---|---|
| VC-001 known-malicious | block | no | **blind** — OSV 403, bundled can't certify clean |
| VC-002a–f install hooks | gate/block | no | real — hooks seen, all clean (DEP-03) |
| VC-003 IOC ledger | block | no | real — no operator IOC ledger loaded |
| VC-004 dormancy | advisory | no | needs registry timestamps; PyPI reachable, none flagged |
| VC-005 release burst | advisory | no | as above — none flagged |
| VC-006 typosquat | advisory | no | real — names are exact, not near-miss |
| VC-007 dep-confusion | gate-eligible | no | real — all names resolve as expected public pkgs |
| VC-008 known-CVE | advisory | no | **blind** — OSV 403 (same as VC-001) |

No VC-001 block fired, so the Part D "stop and escalate" condition was **not**
triggered — subject to the DEP-02 caveat that VC-001 was never actually checked.

---

## Exit codes (recorded as findings, per Part C)

| Run | Command | Exit | Meaning |
|---|---|---|---|
| 1  | `scan -format json <impacket>` | **0** | clean/advisory-only (stderr: coverage incomplete, 10 unresolved) |
| 1b | `scan -fail-on-incomplete <impacket>` | **3** | degraded coverage (10 unpinned unresolved) |
| 2  | `scan -format json <pinned>` | **0** | resolved 9/9 via PyPI; OSV degraded (stderr warns) |
| 2s | `scan -format sarif <pinned>` | **0** | SARIF written; coverage signal absent (FN-01) |
| 2p | `scan -format pdf <pinned>` | **0** | valid PDF 1.4, 1 page, no external deps |
| 3a | `scan -fail-on-incomplete <pinned>` | **3** | OSV gap ⇒ incomplete ⇒ gate fails (correct) |
| 3b | `scan -fail-on-eligible <pinned>` | **0** | no gate-eligible findings |
| 3c | `scan -fail-on-incomplete -fail-on-eligible <pinned>` | **3** | incomplete dominates |

The contract is deterministic and matches `cmd/depsnort/main.go`'s documented
exit semantics (0 clean/advisory · 1 block · 2 gate-eligible-if-opted-in ·
3 incomplete-if-opted-in · 64 usage · 70 internal). Exit 3 on the pinned set —
zero findings, all pins resolved, yet the gate still fails on the OSV gap — is
the clearest demonstration of the "no silent all-clear" design working.

---

## Tool evaluation

```
TOOL:              depSNORT c5465b2 (version string: dev; 9 commits ahead of v0.7.3)
BUILD:             clean — CGO_ENABLED=0 go build, no module download, no go.sum
SBOM CLEAN:        yes — 0 components (self-audit passes)
FINDINGS ON TARGET: 0 vector-check hits; 3 informational coverage/precision findings (DEP-01..03)
COVERAGE:          degraded on every run — resolution complete on pinned set,
                   but OSV data-source blind (403); as-shipped repo unresolvable (unpinned)

STRENGTHS (grounded in observation):
  - Zero-dependency build is real: no go.sum, empty SBOM, builds with only the
    Go stdlib. The tool embodies its own thesis (D-10).
  - Coverage honesty in JSON is first-rate. It separates two axes that most
    scanners conflate: resolution coverage (did I resolve the tree?) vs
    data-source coverage (could I check what I resolved?). The pinned run reports
    resolution complete AND coverage NOT complete because OSV was a gap — an
    unusually precise disclosure.
  - Exit-code contract is reliable and deterministic across 8 invocations, and
    -fail-on-incomplete correctly fails a zero-finding scan when a data source
    was blind. The "partial scan is never silently all-clear" claim holds on the
    JSON/exit-code surface.
  - VC-002 precision is genuinely good: native C build hooks (pycryptodomex),
    versioning shims (impacket), and build-backend declarations (pyOpenSSL) are
    all seen and correctly NOT flagged. No false positives on legitimate hooks.
  - Bundled OSV fallback has honest semantics, confirmed in source: it can catch
    a known-bad package offline but explicitly refuses to certify clean packages,
    stamping bundled hits with the dataset's own generation time.
  - Self-identifies honestly: a plain (un-injected) build reports `dev` rather
    than claiming a release number — the honest answer for an unmarked build.
  - PDF/SARIF/JSON emitters all run with zero external libraries.

GAPS (specific, reproducible — see S1_depSNORT_field_notes.md):
  - FN-01: SARIF output carries NO coverage/degradation signal (no invocations,
    no notifications, results:null). A SARIF-only CI consumer gets a false
    all-clear on a scan the JSON path correctly flags as incomplete. This
    contradicts the tool's own anti-silent-all-clear thesis on its primary CI
    surface. Confirmed against internal/emit/sarif.go.
  - FN-02: SARIF `results` marshals to `null` (nil slice, no omitempty / no
    []-init) when there are no findings, conflating "scanned, found nothing"
    with "did not scan" and risking rejection by strict SARIF consumers.
  - (Operator-gate note, NOT a depSNORT defect) The prompt's Gate Check 2 script
    reads d['coverage']['complete'] and treats data_sources as a dict keyed by
    source. depSNORT's actual schema puts completeness at
    d['verdict']['coverage']['complete'] and emits data_sources as a LIST with an
    integer `gaps` count. The check as written would read complete=False always
    and crash on ds.get('osv',...). Corrected query is in the field notes.

UNTESTED SURFACE (this session did not exercise):
  - Live OSV coverage (403 in-sandbox) — VC-001/VC-008 never truly ran.
  - Transitive dependency resolution — the hand-pin lists only impacket's 9
    declared direct deps; flask/pyOpenSSL/etc. children were never in the graph.
  - Non-PyPI ecosystems (npm/rubygems/cargo/composer/nuget adapters) — target is
    pure-Python.
  - VC-003 IOC ledger, VC-004/005 temporal checks with a real burst/dormancy
    signal, VC-007 dependency-confusion with an internal-looking name.
  - The blocked live `pip install -e .` pipeline step (classifier-denied), so the
    real transitive lock and any install-time behaviour of the fork were not
    observed.
  - cypher/dot graph emitters; -recursive workspace mode; neo4j export.
```

## Field notes

Gaps **were** observed this session (FN-01, FN-02) — see
`reports/S1_depSNORT_field_notes.md`. Both are grounded in behaviour hit against
this target and confirmed against depSNORT source. The bundled-OSV
"can't-certify-clean" behaviour is **documented in source** and is therefore
recorded as *documented, not a gap*, not filed as a field note.

## Retest trigger

No new depSNORT tag shipped since the session build (`v0.7.3` exists but HEAD is
already 9 commits ahead of it; no tag newer than HEAD). No retest was run and
`S1_depSNORT_field_notes_retest.md` is intentionally not produced. If a future
tagged release addresses FN-01/FN-02, re-run only the pinned SARIF scan
(`scan -format sarif <pinned-dir>`) and diff for a coverage/notification signal.
