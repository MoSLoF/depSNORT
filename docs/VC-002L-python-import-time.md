# VC-002L — Python import-time module surface (design note)

Status: **analyzer prototype landed** (analyzer half only, no check / ecosystem
wiring — the same staging used for VC-013). The scope-boundary decision that
keeps this out of the shipped verdict until the spec is met is recorded as
[D-165](DECISIONS.md).

The trigger is a real sample: the **telnyx 4.87.1 / 4.87.2** compromise (TeamPCP
campaign). See [`ioc-teampcp.example.json`](ioc-teampcp.example.json).

**Prototype landed.** The static analyzer described in §4 exists as
`internal/installsurface/pyloadtime.go` (`AnalyzePythonLoadTime`), with a
table-driven corpus in `pyloadtime_test.go` covering the telnyx called-function
shape, the litellm module-level decode-exec shape, credential exfil, a named-secret
read, the reachability pair (same body detected when called, ignored when not),
seven benign false-positive controls (§6), and the disclosed module bound. It
produces facts only and is **not yet called by anything** — importing it into the
verdict is deliberately a separate change.

**What is NOT built yet:**

1. **Ecosystem wiring.** The pypi adapter does not enumerate a package's runtime
   `.py` modules. That requires the sdist fetcher (`internal/ecosystem/pypi/sdist.go`)
   to expose module files — itself a hostile-input surface (decompression,
   containment, count/size bounds) — and the adapter to select the import surface
   and call `AnalyzePythonLoadTime`. Until then the analyzer has no input in
   production.
2. **The check + its gate decision (§5).** This note originally said "no new
   check logic is required — a `module-load:` hook fires VC-002d/e." That conflicts
   with D-165's advisory-only ceiling: VC-002d/f/k are **block-class**, so letting
   `module-load:` hooks flow into the family unchanged would gate on a brand-new,
   broad, benign-heavy surface. The resolved design is a **dedicated `VC-002L`
   check at an advisory ceiling** that reads `module-load:` hooks, plus an
   exclusion of those hooks from the block/gate-eligible family members. That is a
   check-layer change and lands with the wiring, not here.

**Threshold refinement vs §5.** The prototype's emit gate (`loadTimeEscalates`)
requires a capability *combination* the family acts on — decode+exec,
credential+network, a cradle, or a named-credential read — and deliberately does
NOT fire on the bare `exec` or bare `network` that §5 lists as escalating, because
both are common and benign at import. The bare-signal thresholds are left to the
§7 corpus evaluation before any promotion.

---

## 1. One line

Malicious code injected into an **ordinary runtime module** (e.g. an SDK's own
`telnyx/_client.py`) that executes on `import` is a real activation surface the
tool does not currently assess. Assess it the way we already assess install
hooks — walk import-reachable modules, run `scanCaps`, emit synthetic hooks — but
**advisory-only** and behind a hard false-positive budget, because import-time
code is overwhelmingly benign.

## 2. The gap this closes

depSNORT's PyPI install-surface model reads exactly three entrypoints
(`AnalyzePython` in `internal/installsurface/analyze.go`): `setup.py`,
`pyproject.toml` build-backend, and `.pth` files. All three are **install- or
interpreter-startup** triggers. None of them is an ordinary module.

The telnyx attack sidesteps every one of them: the payload lives in
`telnyx/_client.py`, a normal SDK module, as module-level code that runs on
**`import telnyx`** — a *runtime* event, not an install event. depSNORT never
reads that file, so the compromise is invisible to static analysis today. This is
confirmed by the subsystem map: PyPI has no import-time module analyzer at all,
and npm's `AnalyzeLoadTime` (the OPU-31 RedC2 fix) only covers *declared entry
modules*, not arbitrary runtime modules.

This note does NOT propose reading every `.py` file in a package — that is a
false-positive catastrophe (import-time code is where packages legitimately load
config, register plugins, and run version checks). It proposes a **narrow,
capability-gated** analyzer.

## 3. Attack hypothesis

> An attacker who can publish a package version injects credential-harvesting or
> loader code into a module that the SDK's public API imports, so it runs on
> first `import` in any consuming application — no lifecycle hook, no `.pth`, no
> `setup.py` change that a hook scanner would see.

## 4. Detection design

New analyzer `AnalyzePythonLoadTime(entryModules, read)` mirroring npm's
`AnalyzeLoadTime`:

1. **Entry set, bounded.** Start from the package's declared public surface —
   the top-level package `__init__.py` and the modules it imports — not the whole
   tree. Follow intra-package imports to a bounded depth (reuse the
   `maxLoadTimeRefs = 16` cap), disclosing the bound via `Surface.Truncated` →
   `GapTruncated` exactly as the npm analyzer does. Never follow into
   dependencies.
2. **Module-level only.** Scan code that runs at import: top-level statements and
   the bodies of module-level calls — not function/method bodies that only a
   later call would reach.
3. **Reuse the capability model unchanged.** Run the existing `scanCaps`. Emit a
   synthetic `module-load:<relpath>` hook when the scanned code carries an
   **escalating** capability, never on bare presence of code.

The analyzer only produces facts; the existing VC-002 family judges. No new
check logic is required — a `module-load:` hook with `obfuscation+exec` fires
VC-002e, with `network+credentials` fires VC-002d, etc.

## 5. Evidence / confidence / gate

| Field | Value |
|---|---|
| Required evidence | module-level code reachable from the package's import surface with an escalating capability (`network`, `credentials`, `exec`, `obfuscation`, `cradle`) |
| Optional reinforcing | co-located with a version delta that ADDED the capability (VC-010), first-seen publisher (VC-011) |
| Excluded conditions | capability basis is a display-sink string, a docstring/comment, or a URL literal (reuse the D-25/D-160 stripping pipeline before scanning) |
| Severity ceiling | **advisory** on first ship, regardless of capability — see D-165 |
| Gate eligibility | **none initially.** Promotion to gate-eligible requires the corpus evaluation in §7 |
| Coverage prerequisite | the module tree was actually read; a truncated/unread walk is disclosed as a gap, never as "clean" |

Rationale for the advisory ceiling: import-time execution is a vastly broader and
more benign surface than install hooks. Blocking on it before a measured
false-positive rate would violate the gate-vs-severity discipline (§22 of the
contract). It ships in shadow, earns its gate class with evidence, or never gets
one.

## 6. Known false positives (the make-or-break set)

Legitimate packages routinely run capability-adjacent code at import:

- lazy config load that reads environment variables (`env`, never alone an
  escalation — `credentials` requires a NAMED secret);
- plugin registries that `importlib.import_module` by name (`exec`-adjacent);
- packages that shell out at import for capability detection (`subprocess` +
  version parse);
- vendored code that base64-decodes embedded data (fonts, certs) without
  executing it (`obfuscation` requires decode PAIRED with an exec sink).

The benign corpus MUST include these, harvested from real scans the way
`legitimate.go` was built. The FP rate on this set is the gating metric.

## 7. Promotion gate (corpus evaluation)

Before this analyzer feeds anything above advisory:

1. malicious corpus: the telnyx `_client.py` shape + synthetic variants
   (split strings, renamed funcs, indirection) — all detected;
2. benign corpus (§6): measured false-positive rate at or below the documented
   budget;
3. adversarial: added to `internal/ecosystem/conformance/`;
4. shadow run over a representative real project set, FP rate reported.

## 8. Test vectors

- **Positive:** module-level `os.environ['AWS_SECRET_ACCESS_KEY']` +
  `urllib.request.urlopen(...)` in a non-entry module → `module-load:` hook with
  `credentials+network` → VC-002d.
- **Positive:** the telnyx shape — base64 decode + `subprocess.Popen` at module
  level → `obfuscation+exec` → VC-002e.
- **Negative (FP control):** module-level `os.environ.get('MYAPP_DEBUG')` + a
  plugin-registry loop → no escalating capability → no hook.
- **Negative (FP control):** `base64.b64decode(EMBEDDED_FONT)` with no exec sink
  → no `obfuscation` → no hook.

## 9. What is explicitly NOT in scope

- Reading dependency modules (only the scanned package's own tree).
- Non-Python ecosystems (npm's entry-module case is already handled; other
  ecosystems are separate notes).
- Any gate-class outcome before §7 is satisfied.
