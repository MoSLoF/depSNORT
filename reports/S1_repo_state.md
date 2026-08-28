# S1 — Repo State Determination (handoff for Session 2)

**Project:** iHBV-TM-022 · Wave 1 · Session 1 (static supply-chain assessment)
**Produced:** 2026-08-14 (UTC)
**Consumed by:** Session 2 (adversarial assessment) — read this file first.

> Session 2 is out of scope for this session. This file records only the
> factual repo state and coverage limits Session 2 needs to gate on. It makes
> **no** exploitability determination — that is Session 2's territory.

---

## depSNORT build state (from Part A)

```
DEPSNORT BUILD STATE
commit:                              c5465b2778d33135170c57b1cb86637e1237df2a
tag:                                 untagged (HEAD == origin/main, 9 commits AHEAD of latest tag v0.7.3)
version string (./depsnort version): dev
newer tags on origin since build:    none — v0.7.3 exists but HEAD is ahead of it
build toolchain:                     go1.24.7 (Go 1.24+ satisfied)
build result:                        clean, CGO_ENABLED=0, no external module download
go.sum present:                      no (zero third-party dependencies — dogfood D-10 confirmed)
SBOM components:                     0 (self-audit clean)
```

The `dev` version string is expected and honest: a plain `go build`
(no `-ldflags -X main.version=...`) deliberately reports `dev` rather than
claiming a release number it may have drifted from (documented in
`cmd/depsnort/main.go`). The build is `origin/main` HEAD, which sits 9 commits
ahead of the newest tag `v0.7.3` — an untagged dev build, correctly labelled.
**Not silently upgraded.** Newer-release evaluation is left to the operator.

---

## Repo state determination (impacket)

```
REPO STATE DETERMINATION (for Session 2)
impacket source:                  https://github.com/MoSLoF/impacket (read-only clone)
impacket HEAD commit:             4c09897a8645818e873787f2c79ec1bce90c5777
impacket declared version:        0.14.0.dev  (setup.py: VER_MAJOR=0 MINOR=14 MAINT=0 PREREL="dev")
impacket_0_13_1 tag present:      no  — this fork carries ZERO git tags (git tag | wc -l = 0)
master ahead of 0.13.1:           indeterminate — baseline tag absent; cannot compute the delta
ccache.py changed since 0.13.1:   indeterminate — baseline tag absent
ccache.py last-touched commit:    243d64a67599e24a1c5dd7eb3ff8667d2d5bc2fc
                                   "Fix IndexError in CCache.getCredential when handling 3-part
                                    SPNs in multi domain forests ... (#2242)"
EC-01 fix status:                 indeterminate — the 0.13.1 baseline needed to anchor an
                                   EC-01 present/absent determination is not present in this
                                   fork. Session 2 must establish its own baseline before
                                   making any EC-01 claim.
```

### Why the determination is "indeterminate," not "no"

The prompt's Part B procedure keys every comparison off the `impacket_0_13_1`
tag. This fork (`MoSLoF/impacket`) has **no tags at all** — not just a missing
`0.13.1`. Every `git log <tag>..HEAD` therefore has no left-hand anchor and
returns nothing, which is the *absence of a baseline*, not evidence that
nothing changed. Recording these as "no" would be a false negative. They are
recorded as **indeterminate** so Session 2 does not inherit a phantom
"unchanged since 0.13.1" assumption.

The fork's declared version is `0.14.0.dev`, i.e. its master is a development
line past the 0.13.x series, so `ccache.py` has almost certainly moved since a
real 0.13.1 — but that cannot be *proven from this fork's own history* and is
left as indeterminate rather than asserted.

`impacket/krb5/ccache.py` exists and is live; its most recent change is #2242
(an IndexError fix in `CCache.getCredential` for 3-part SPNs). Full path and
commit are recorded above so Session 2 can anchor its own diff.

---

## OSV COVERAGE — OPERATOR GATE CHECK 2 STATUS: **NOT SATISFIED**

This is the gating fact for Session 2.

```
OSV live query (api.osv.dev):     BLOCKED — HTTP 403 Forbidden through the session proxy
OSV bundled fallback (offline):   present (22 known advisories compiled into the binary)
                                  — catches KNOWN-malicious/known-vuln only; a clean package
                                    is NOT certified clean by the bundled set, it falls through
                                    to a gap (documented in internal/datasource/osv/bundled.go)
pinned-scan OSV result:           9 queried / 0 advisories / 9 GAPS
verdict.coverage.complete:        false
verdict.coverage.data_source_gaps: ["osv"]
```

**Consequence for Session 2:** VC-001 (known-malicious) and VC-008 (known-CVE)
never received real coverage against the impacket dependency set. "No block
finding in this session" means **"VC-001 was never checked,"** not "the tree is
clean." Per the operator gate, Session 2 does **not** start on the strength of
this scan alone.

### Two paths forward (operator's choice)

1. **OSV snapshot pre-flight (preferred).** On a host with egress to
   `api.osv.dev` (e.g. iHBV-TUF), run
   `./depsnort scan -format json -osv-export osv-snapshot.json <pinned-dir>`,
   commit the snapshot, then re-run the pinned scan with
   `-osv-snapshot osv-snapshot.json -offline` and repeat Check 2. This gives
   VC-001/VC-008 real coverage.

2. **OPERATOR WAIVER (recorded here).** If OSV egress cannot be obtained,
   this record authorizes Session 2 to proceed **with the known gap**, on the
   binding condition that Session 2 makes **no cleanliness claim** about the
   impacket dependency tree — only *"unknown, OSV not available."* No
   statement equivalent to "the dependency tree is clean / free of known
   malicious or vulnerable packages" may be made downstream of this session.

> This session cannot obtain OSV egress (403 in-sandbox) and therefore cannot
> itself satisfy Check 2. It records the waiver condition above and leaves the
> choice between path 1 and path 2 to the operator.

---

## Handoff / delivery deviations (operator, please read)

- **Branch.** The prompt directs all output to `claude/tm022-wave1` on the
  impacket repo. This session's authorization scopes writes to
  `claude/new-session-pjivze` on `MoSLoF/depSNORT`, and impacket is available
  read-only (no push credential). All reports are therefore committed to
  `MoSLoF/depSNORT@claude/new-session-pjivze` under `reports/`, and all six
  deliverables are additionally delivered in chat under their `TM022-W1-S1-`
  names (the operator's actual review path). If Session 2 expects to `git show
  origin/claude/tm022-wave1:reports/S1_repo_state.md`, the operator must place
  this file there out-of-band, or point Session 2 at the depSNORT branch / the
  chat artifact.
- **Pinned set method.** The prompt builds the pin set from a live
  `pip install -e .`. That step (a network install that executes the fork's
  `setup.py`) was blocked by the environment's action classifier. The pinned
  set used here is a **representative hand-pin of impacket's nine declared
  direct dependencies at recent stable versions** — it exercises depSNORT's
  pinned-resolution path but is **not** a transitive lock from a live install.
  Transitive dependencies (e.g. flask→werkzeug/jinja2, pyOpenSSL→cryptography)
  are therefore out of coverage. See the assessment and transcript for detail.
