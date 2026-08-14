# S1 — Session Transcript (evidence trail)

**Project:** iHBV-TM-022 · Wave 1 · Session 1 · 2026-08-14 (UTC)
**Nature:** chronological record of what was requested, what was done, what was
found, and where it fell short. Not a summary — the synthesized deliverable is
`S1_depSNORT_assessment.md`; this is the evidence.

---

## 0. Environment discovery

- Working dir `/home/user/depSNORT` is itself the depSNORT repo (git HEAD
  `c5465b2778d33135170c57b1cb86637e1237df2a`, branch `claude/new-session-pjivze`).
- Toolchain present: `go1.24.7` (satisfies Go 1.24+), `python3 3.11.15`.
- Inspected source before building: `go.mod` declares `module ihbv.io/depsnort`,
  Go 1.24, **no `require` block** and there is **no `go.sum`** → zero third-party
  deps by construction. 13 vector checks under `internal/check/builtin/`.

## 1. Part A — build & validate depSNORT

```
CGO_ENABLED=0 go build -o depsnort ./cmd/depsnort     → BUILD EXIT 0
ls go.sum                                             → No such file (zero deps)
./depsnort version                                    → banner + "depSNORT dev"  (exit 0)
./depsnort checks                                     → 13 checks listed (exit 0)
./depsnort sbom | components                          → components: 0  → SBOM clean
```
- `go build` pulled no external modules (no network, no go.sum) → the
  "supply-chain-safe tool with no unaudited supply chain" claim verified.
- Version string is `dev`. Confirmed by `main.go` this is deliberate for an
  un-injected `go build` (release version is injected via `-ldflags` from
  `pyproject.toml`). Recorded as honest behaviour, not a defect.

Version/prior-run comparison:
```
git rev-parse HEAD          → c5465b2  (== origin/main)
git describe --exact-match  → untagged
git fetch --tags            → new tag v0.7.3 appeared
v0.7.3 commit               → 25d9b94  ; merge-base(HEAD,v0.7.3)=25d9b94
git merge-base --is-ancestor v0.7.3 HEAD → TRUE  (HEAD is 9 commits AHEAD of v0.7.3)
```
Conclusion: HEAD is a dev build ahead of the newest tag; no tag newer than HEAD
exists. **Not upgraded mid-session** (per Part A instruction). Flagged for
operator in repo_state.

## 2. Part B — repo state determination (impacket)

- impacket obtained read-only via the session git proxy (public repo); full
  clone to `/workspace/moslof/impacket`, HEAD `4c09897a`.
```
git tag | wc -l                          → 0   (fork carries NO tags at all)
grep VER_* setup.py                      → 0.14.0.dev
git log impacket_0_13_1..HEAD            → tag not present (no left anchor)
git log ... -- impacket/krb5/ccache.py   → tag not present
git log -1 -- impacket/krb5/ccache.py    → 243d64a6 "Fix IndexError in
                                            CCache.getCredential ... 3-part SPNs (#2242)"
```
- Every 0.13.1-anchored comparison is **indeterminate** because the baseline tag
  is absent — recorded as indeterminate, not "no," to avoid handing Session 2 a
  false "unchanged" assumption. Full determination block in `S1_repo_state.md`.
- Reviewed `setup.py` in full before any install: standard unmodified impacket
  setup — reads git metadata for versioning, declares standard `install_requires`
  (pyasn1, pycryptodomex, pyOpenSSL, six, ldap3, ldapdomaindump, flask,
  charset_normalizer; pyreadline3 on win32). No obfuscation, no unusual network
  fetch. requirements.txt is **entirely unpinned**.

## 3. Part C — depSNORT runs

### Run 1 — repo as-shipped
```
depsnort scan -format json <impacket>  > reports/scan-repo.json   → exit 0
  stderr: "WARNING - coverage is incomplete: 10 unresolved ... NOT an all-clear."
depsnort scan -fail-on-incomplete <impacket>                      → exit 3
```
- verdict.coverage: complete=false, degraded=true, unresolved_dependencies=10,
  all 10 names listed. 0 findings. depSNORT saw impacket's own setup.py
  module-level hook and classified it clean.
- Behaves exactly as D-01 predicts on an unpinned tree.

### Run 2 — pinned snapshot  (DEVIATION recorded)
- Intended step `python3 -m venv … && pip install -q -e .` was **blocked by the
  environment action classifier** (network install that also executes the fork's
  setup.py). Not overridden.
- Substituted a **representative hand-pin** of impacket's 9 declared direct deps
  at recent stable versions (`pinned-scan-dir/requirements.txt`, copied to
  `reports/pinned-requirements.txt`). This exercises depSNORT's pinned-resolution
  path but is **not** a live transitive lock — transitive children are out of
  coverage. Disclosed here, in the assessment, and in repo_state.
```
depsnort scan -format json  pinned-scan-dir/  > reports/scan-pinned.json   → exit 0
  stderr: "OSV coverage degraded: ... Post https://api.osv.dev/... : Forbidden"
depsnort scan -format sarif pinned-scan-dir/  > reports/scan-pinned.sarif  → exit 0
depsnort scan -format pdf   pinned-scan-dir/  > reports/scan-pinned.pdf    → exit 0 (PDF 1.4, 1 page)
```
Key JSON fields (scan-pinned.json):
- summary: 17 nodes / 16 edges (9 packages + 7 hook nodes + 1 root).
- pypi-registry: queried 9, from_network 9, gaps 0  → PyPI reachable, all pins resolved.
- osv: queried 9, advisories 0, **gaps 9**, error "…Forbidden".
- verdict.coverage: complete=**false**, degraded=false, unresolved_dependencies=0,
  flat_resolution_ecosystems=["pypi"], data_source_gaps=["osv"].
- verdict.counts: all zero. findings: [].
- Hook nodes (all classified clean): charset-normalizer, ldap3, pycryptodomex
  (cmdclass.build_ext + module-level), pyopenssl (pyproject build-backend +
  module-level), six.

Cross-check — forced offline (`-offline`): osv still 9 gaps (offline=true,
from_cache 9 on pypi). Inspected `bundled_snapshot.json` (22 entries) and
`bundled.go`: the bundled set catches known-bad offline but by design does NOT
certify clean packages → clean pins correctly fall through to gaps. Documented
behaviour, not a gap.

### Run 3 — CI gate simulation (pinned)
```
depsnort scan -fail-on-incomplete pinned-scan-dir/                  → exit 3
depsnort scan -fail-on-eligible   pinned-scan-dir/                  → exit 0
depsnort scan -fail-on-incomplete -fail-on-eligible pinned-scan-dir/ → exit 3
```
- Exit 3 on a zero-finding, fully-resolved pinned set (because OSV was a gap) is
  the clearest evidence of the "no silent all-clear" contract working on the
  exit-code surface.

## 4. Tool-evaluation observations (grounded)

- Zero-dep build / empty SBOM: verified (no go.sum, `sbom` components 0).
- Coverage disclosure JSON: dual-axis (resolution vs data-source) — resolution
  complete AND coverage incomplete reported simultaneously on the pinned run.
- Exit-code contract: deterministic across 8 invocations; matches main.go docs.
- VC-002 precision: native build (pycryptodomex), versioning shim (impacket),
  build-backend (pyOpenSSL) all seen, none flagged. No false positives.
- SARIF surface: inspected output and `internal/emit/sarif.go`. sarifRun =
  {Tool, Results} only; `Results` nil-slice → `results:null`; no invocations/
  notifications; no coverage/degraded/osv/gap text anywhere in the SARIF. →
  FN-01 and FN-02 filed. Confirmed against source, not inferred.

## 5. Coverage gaps — explicit

- **OSV (VC-001, VC-008): blind.** api.osv.dev → 403 in-sandbox; bundled set
  cannot certify clean. "No block finding" ≠ "clean." → Operator Gate Check 2
  NOT SATISFIED; waiver condition recorded in repo_state.
- **Transitive tree: uncovered.** Hand-pin lists only 9 direct deps; the live
  `pip install` that would have produced a real transitive lock was blocked.
- **Non-PyPI ecosystems, VC-003 IOC ledger, VC-004/005 with real temporal
  signal, VC-007 dep-confusion, cypher/dot/neo4j emitters, -recursive:** not
  exercised (out of target shape or scope).

## 6. Deviations & corrected paths

1. **Branch.** Prompt targets `claude/tm022-wave1` on the impacket repo; session
   authorization is `claude/new-session-pjivze` on `MoSLoF/depSNORT`, and
   impacket is read-only. Reports committed to the depSNORT branch under
   `reports/`; all six deliverables also delivered in chat. Session-2 handoff
   placement flagged to operator in repo_state.
2. **Pinned set method.** Live `pip install -e .` classifier-blocked → replaced
   with a static hand-pin (§3 Run 2). Transitive coverage lost; disclosed.
3. **Operator-gate script.** Prompt's Check 2 python reads the wrong JSON paths
   (`d['coverage']` and `data_sources['osv']`) vs actual
   (`d['verdict']['coverage']`, `data_sources` = list). Corrected query provided
   in the field notes' "Not filed" section. This is an operator-script defect,
   not a depSNORT defect.
4. **No retest.** No depSNORT tag newer than the built HEAD → no retest run,
   `*_field_notes_retest.md` intentionally absent.

## 7. Stop-condition check

VC-001 did not fire → the Part D "poisoned tree, stop and escalate" condition
was not triggered — **subject to** the DEP-02 caveat that VC-001 never received
real OSV coverage. No offensive/exploit action was taken; assessment is static
throughout. Session 2 (adversarial, Kerberos ccache) remains gated on the
operator per the OSV waiver.
