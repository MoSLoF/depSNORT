# S1 — depSNORT Field Notes (feedback for the tool author)

**Tool build:** depSNORT `c5465b2` (origin/main HEAD, 9 commits ahead of `v0.7.3`; version string `dev`)
**Session:** iHBV-TM-022 Wave 1 · Session 1 · target `MoSLoF/impacket`
**Scope of these notes:** only gaps hit during THIS session against THIS target,
confirmed against tool source where possible. Behaviour that is by-design
(D-01 unpinned refusal) or honestly documented (bundled-OSV can't-certify-clean)
is deliberately **not** filed here.

---

## GAP: FN-01 — SARIF output drops all coverage/degradation signal (silent all-clear on the CI surface)

```
OBSERVED:
  ./depsnort scan -format sarif pinned-scan-dir/   (exit 0)
  The emitted SARIF (2.1.0) contains: 1 run, driver depSNORT/dev, the rule
  catalogue, and results:null. It contains NO signal that coverage was degraded:
    - no `invocations` array
    - no `toolExecutionNotifications`
    - no result/notification mentioning osv, gap, degraded, incomplete, or
      "not an all-clear"
  Verified: json.dumps(sarif).lower() contains none of
    {degraded, incomplete, complete, forbidden, gap, all-clear}.
  The SAME scan on the JSON path correctly reports
    verdict.coverage.complete=false and data_source_gaps=["osv"], and stderr
    prints "WARNING - coverage is incomplete ... degraded data source(s): osv.
    This report is NOT an all-clear."

EXPECTED:
  depSNORT's stated thesis (README + main.go: "a partial scan is never silently
  all-clear") should hold on SARIF, its primary CI/dashboard surface (D-09).
  A consumer ingesting only the SARIF (e.g. GitHub code scanning) should be able
  to tell that OSV coverage was blind — via an invocation with
  executionSuccessful=false, a toolExecutionNotification, or a synthetic
  informational result.

EFFECT:
  On this session's pinned scan, a SARIF-only CI gate would show zero alerts and
  no warning — a false all-clear — for a run where VC-001/VC-008 never checked
  anything (OSV 403). The exit code (3 under -fail-on-incomplete) still protects
  a gate that watches exit codes, but any pipeline that consumes the SARIF file
  as its source of truth is misled. This is the exact failure mode the tool is
  built to prevent, on the surface where it matters most.

SUGGESTED TWEAK:
  In internal/emit/sarif.go, add an `invocations` entry to sarifRun populated
  from the verdict's coverage state:
    - invocations[0].executionSuccessful = coverage.complete
    - invocations[0].toolExecutionNotifications += one `warning`-level
      notification per data_source_gap and per incomplete root, reusing the
      same text the stderr/JSON paths already emit.
  This reuses data the emitter already receives (the function already imports
  and is handed the verdict) and closes the gap without new inputs.

UNTESTED:
  Confirmed against source (internal/emit/sarif.go): sarifRun has only
  {Tool, Results}; there is no field capable of expressing coverage, and no
  code path writes one. NOT inferred from behaviour alone.
```

---

## GAP: FN-02 — SARIF `results` serializes to `null` (not `[]`) when there are no findings

```
OBSERVED:
  With zero findings, the SARIF run object is: {"tool": {...}, "results": null}.
  (Go: `Results []sarifResult` is a nil slice with no `omitempty` and no
  initialization to an empty slice, so encoding/json emits null.)

EXPECTED:
  A tool that DID scan and found nothing should emit `results: []`. SARIF 2.1.0
  uses the presence of an empty array vs a null/absent `results` to distinguish
  "scanned, found nothing" from "did not scan / no data" — a distinction
  depSNORT otherwise cares about deeply. Strict SARIF validators and some
  ingestion pipelines reject or mis-handle `results: null`.

EFFECT:
  Minor on GitHub code scanning (tolerant), but (a) it's a latent
  interoperability paper-cut with stricter consumers, and (b) semantically it
  conflates the two states the rest of the tool works hard to keep separate.
  Compounds FN-01: `results:null` reads even more like "nothing here" than an
  explicit empty array would.

SUGGESTED TWEAK:
  Initialize `run.Results = []sarifResult{}` (or add `,omitempty` only if the
  intent is genuine absence). Prefer the empty array — it says "scanned, clean,"
  which paired with the FN-01 invocation notification gives an honest
  "scanned, clean, but coverage degraded."

UNTESTED:
  Confirmed against source (internal/emit/sarif.go line 28: `Results
  []sarifResult json:"results"`, no omitempty; append-only population). NOT
  inferred from behaviour alone.
```

---

## Not filed (recorded for completeness)

- **Bundled-OSV cannot certify clean packages.** In `-offline`, the 9 clean
  pinned packages report as 9 OSV gaps rather than "clean." This is **documented
  honestly** in `internal/datasource/osv/bundled.go` ("A real, non-malicious
  package does not become 'checked clean' by appearing here — it ... falls
  through to a normal gap"). Documented, not a gap.
- **D-01 refusal to resolve unpinned specifiers.** By design. Not a gap.
- **Live OSV 403 / `pip install` classifier denial.** Environment/pipeline
  constraints, not depSNORT behaviour. Recorded in the assessment and
  transcript, not filed against the tool.
- **Operator-gate Check 2 script vs actual JSON schema mismatch.** The prompt's
  gate script reads `d['coverage']['complete']` and `data_sources['osv']`;
  depSNORT actually emits completeness at `d['verdict']['coverage']['complete']`
  and `data_sources` as a LIST of `{name, stats:{...,gaps:int}}`. This is a
  defect in the *operator gate script*, not in depSNORT — the tool's schema is
  internally consistent. Corrected one-liner for the operator:
  ```python
  import json,sys; d=json.load(sys.stdin)
  cov=d['verdict']['coverage']
  gaps=cov.get('data_source_gaps',[])
  print('complete:', cov.get('complete')); print('osv gaps:', 'osv' in gaps)
  ```
