package builtin

import (
	"fmt"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// hookView is the install-time subgraph rooted at one hook, flattened into the
// facts the VC-002 family judges.
type hookView struct {
	Pkg      *graph.Node
	Hook     *graph.Node
	Caps     map[string]bool
	Remotes  []string
	Sinks    []string
	Evidence []string
}

// collectHooks walks declares-hook edges and, for each hook, unions the
// capabilities of the hook itself with everything it reaches (artifacts, sinks).
// This is pure graph reading — no mutation (Decision D-03).
func collectHooks(g *graph.Graph) []hookView {
	// Index outgoing edges by source.
	out := map[string][]graph.Edge{}
	for _, e := range g.Edges {
		out[e.From] = append(out[e.From], e)
	}

	var views []hookView
	for _, pkg := range g.SortedNodes() {
		if pkg.Kind != graph.KindPackage {
			continue
		}
		for _, e := range out[pkg.ID] {
			if e.Type != graph.EdgeDeclaresHook {
				continue
			}
			hook := g.Get(e.To)
			if hook == nil {
				continue
			}
			// Python import-time module hooks (VC-002L) are judged ONLY by their
			// own check, at an advisory ceiling (D-165): the block-class family
			// must not gate on a brand-new, benign-heavy runtime surface. npm's
			// "module-load:" entry-module hooks are deliberately NOT excluded —
			// VC-002j legitimately gates those (OPU-31).
			if strings.HasPrefix(hook.Name, "import-time:") {
				continue
			}
			v := hookView{Pkg: pkg, Hook: hook, Caps: map[string]bool{}}
			absorb := func(n *graph.Node) {
				for k, val := range n.Attr {
					if val == "true" && strings.HasPrefix(k, "cap.") {
						v.Caps[strings.TrimPrefix(k, "cap.")] = true
					}
				}
				if ev := n.Attr["hook.evidence"]; ev != "" {
					v.Evidence = append(v.Evidence, ev)
				}
				if ev := n.Attr["artifact.evidence"]; ev != "" {
					v.Evidence = append(v.Evidence, ev)
				}
			}
			absorb(hook)
			for _, he := range out[hook.ID] {
				target := g.Get(he.To)
				if target == nil {
					continue
				}
				switch target.Kind {
				case graph.KindReferencedArtifact:
					absorb(target)
					if target.Attr["artifact.remote"] == "true" {
						v.Remotes = append(v.Remotes, target.Name)
					}
				case graph.KindSink:
					v.Sinks = append(v.Sinks, target.Name)
				}
			}
			sort.Strings(v.Remotes)
			sort.Strings(v.Sinks)
			views = append(views, v)
		}
	}
	return views
}

func capList(caps map[string]bool) string {
	var ks []string
	for k := range caps {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, "+")
}

// ---- VC-002b: hook reaches the network -----------------------------------

// HookNetwork (VC-002b) reports an install hook with network egress. On its own
// this is common (prebuilt-binary downloads), so it is medium/gate-eligible —
// a multiplier, not an alarm.
type HookNetwork struct{}

func (HookNetwork) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002b", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevMedium, DefaultGate: finding.GateEligible,
		Description: "install hook reaches the network",
	}
}

func (HookNetwork) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !v.Caps["network"] || v.Caps["credentials"] || v.Caps["cradle"] {
			continue // credential case is VC-002d's, cradle is VC-002f's — don't double-report
		}
		ev := fmt.Sprintf("%s hook has network egress", v.Hook.Name)
		if len(v.Remotes) > 0 {
			ev += "; reaches " + strings.Join(v.Remotes, ", ")
		}
		out = append(out, finding.Finding{
			CheckID: "VC-002b", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevMedium, GateClass: finding.GateEligible,
			Confidence: 0.45, NodeID: v.Pkg.ID,
			Title:       fmt.Sprintf("install hook (%s) reaches the network", v.Hook.Name),
			Evidence:    ev,
			Remediation: "confirm the download is an expected prebuilt binary from a trusted host",
		})
	}
	return out
}

// ---- VC-002c: hook touches named credentials ------------------------------

// HookCredentials (VC-002c) reports an install hook that references NAMED
// secrets (NPM_TOKEN, .npmrc, AWS keys…). Without network egress it cannot
// exfiltrate directly, so it is high/gate-eligible rather than block.
type HookCredentials struct{}

func (HookCredentials) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002c", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevHigh, DefaultGate: finding.GateEligible,
		Description: "install hook references named credentials or secret files",
	}
}

func (HookCredentials) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !v.Caps["credentials"] || v.Caps["network"] {
			continue // network+creds is VC-002d
		}
		out = append(out, finding.Finding{
			CheckID: "VC-002c", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevHigh, GateClass: finding.GateEligible,
			Confidence: 0.6, NodeID: v.Pkg.ID,
			Title:    fmt.Sprintf("install hook (%s) references credentials", v.Hook.Name),
			Evidence: fmt.Sprintf("touches %s", strings.Join(v.Sinks, ", ")),
			Remediation: "an install hook has no legitimate need for registry or cloud credentials; " +
				"review before installing",
		})
	}
	return out
}

// ---- VC-002d: exfil-capable (network + credentials) -----------------------

// HookExfilCapable (VC-002d) is the ChainDrop signature: an install hook that
// BOTH references named credentials AND has network egress. That combination is
// the credential-harvesting shape and is the one heuristic in the v0 pack
// promoted to block-class (Decision D-05: block is otherwise deterministic).
//
// Precision comes from the credential marker being NAMED — broad process.env
// access is deliberately excluded upstream so that native-build hooks, which
// legitimately read env and download binaries, do not land here.
type HookExfilCapable struct{}

func (HookExfilCapable) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002d", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevCritical, DefaultGate: finding.GateBlock,
		Description: "install hook is exfil-capable: named credentials + network egress",
	}
}

func (HookExfilCapable) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !(v.Caps["network"] && v.Caps["credentials"]) {
			continue
		}
		conf := 0.85
		if v.Caps["obfuscation"] {
			conf = 0.95
		}
		ev := fmt.Sprintf("%s hook combines credential access (%s) with network egress",
			v.Hook.Name, strings.Join(v.Sinks, ", "))
		if len(v.Remotes) > 0 {
			ev += "; destinations: " + strings.Join(v.Remotes, ", ")
		}
		ev += fmt.Sprintf("; capabilities: %s", capList(v.Caps))
		out = append(out, finding.Finding{
			CheckID: "VC-002d", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevCritical, GateClass: finding.GateBlock,
			Confidence: conf, NodeID: v.Pkg.ID,
			Title:       fmt.Sprintf("install hook (%s) is exfil-capable", v.Hook.Name),
			Evidence:    ev,
			Remediation: "do not install; treat as an active credential-harvesting supply-chain compromise and rotate exposed tokens",
		})
	}
	return out
}

// ---- VC-002e: obfuscated install-time code --------------------------------

// HookObfuscated (VC-002e) reports an install chain that decodes and executes.
// Per the static ceiling (Decision D-04) we do not decode the payload —
// detecting the indirection IS the finding.
type HookObfuscated struct{}

func (HookObfuscated) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002e", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevHigh, DefaultGate: finding.GateEligible,
		Description: "install hook decodes and executes code (obfuscation/indirection)",
	}
}

func (HookObfuscated) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !(v.Caps["obfuscation"] && v.Caps["exec"]) {
			continue
		}
		out = append(out, finding.Finding{
			CheckID: "VC-002e", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevHigh, GateClass: finding.GateEligible,
			Confidence: 0.7, NodeID: v.Pkg.ID,
			Title: fmt.Sprintf("install hook (%s) decodes and executes code", v.Hook.Name),
			Evidence: fmt.Sprintf("obfuscation + exec in the install chain; markers: %s",
				strings.Join(dedupeStrings(v.Evidence), ", ")),
			Remediation: "inspect the decoded payload manually before installing",
		})
	}
	return out
}

// ---- VC-002f: download-and-execute cradle ---------------------------------

// HookDownloadCradle (VC-002f) reports an install hook that fetches remote code
// and executes it in one step — `curl … | sh`, `iex (DownloadString …)`, a
// certutil/bitsadmin LOLBin pull. This is the initial-access primitive, and
// unlike a prebuilt-binary download from a known host (esbuild), it is defined
// by the fetch-and-run idiom that legitimate installers do not use. It is
// block-class (Decision D-28): running code you just pulled off the network at
// install time is not a warning, it is the compromise.
type HookDownloadCradle struct{}

func (HookDownloadCradle) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002f", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevCritical, DefaultGate: finding.GateBlock,
		Description: "install hook fetches and executes remote code (download cradle)",
	}
}

func (HookDownloadCradle) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !v.Caps["cradle"] {
			continue
		}
		ev := fmt.Sprintf("%s hook fetches remote code and executes it in one step", v.Hook.Name)
		if len(v.Remotes) > 0 {
			ev += "; source: " + strings.Join(v.Remotes, ", ")
		}
		out = append(out, finding.Finding{
			CheckID: "VC-002f", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevCritical, GateClass: finding.GateBlock,
			Confidence: 0.9, NodeID: v.Pkg.ID,
			Title:       fmt.Sprintf("install hook (%s) is a download cradle", v.Hook.Name),
			Evidence:    ev,
			Remediation: "do not install; an install hook has no legitimate reason to pull and run code from the network",
		})
	}
	return out
}

// ---- VC-002g: install-hook persistence ------------------------------------

// HookPersistence (VC-002g) reports an install hook that writes to a persistence
// location — a shell profile, cron, a systemd/launchd service, the Windows Startup
// folder, the PowerShell $PROFILE. A library's install hook has no legitimate
// reason to establish boot/login persistence; that is an OS-package/admin action,
// not a build step (A.I.G SkillTrustBench T06 weights it as its own category).
//
// It gates on the PERSISTENCE subset of CapFilesystem only. Ordinary install
// writes — site-packages, .pth, gem dirs, locating the home directory — are also
// CapFilesystem but are excluded (installsurface.IsPersistenceMarker), so a normal
// install does not fire this. That precision is why it is gate-eligible/high
// (closer to VC-002c) rather than the common-and-benign VC-002b shape.
type HookPersistence struct{}

func (HookPersistence) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002g", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevHigh, DefaultGate: finding.GateEligible,
		Description: "install hook writes a boot/login persistence mechanism",
	}
}

func (HookPersistence) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !v.Caps["filesystem"] {
			continue
		}
		// Fire only when a PERSISTENCE marker fired — not a benign site-packages/.pth
		// write, which is also CapFilesystem. Evidence entries are comma-joined
		// marker strings, so split before testing each.
		var hits []string
		seen := map[string]bool{}
		for _, ev := range v.Evidence {
			for _, part := range strings.Split(ev, ",") {
				part = strings.TrimSpace(part)
				if part != "" && installsurface.IsPersistenceMarker(part) && !seen[part] {
					seen[part] = true
					hits = append(hits, part)
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		sort.Strings(hits)
		out = append(out, finding.Finding{
			CheckID: "VC-002g", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevHigh, GateClass: finding.GateEligible,
			Confidence: 0.6, NodeID: v.Pkg.ID,
			Title:    fmt.Sprintf("install hook (%s) establishes persistence", v.Hook.Name),
			Evidence: fmt.Sprintf("writes boot/login persistence location(s): %s", strings.Join(hits, ", ")),
			Remediation: "an install hook has no legitimate need to install a cron job, service, " +
				"shell-profile, or startup entry; review before installing",
		})
	}
	return out
}

// ---- VC-002h: build-flag code-execution injection -------------------------

// HookBuildFlagInjection (VC-002h) reports a build directive that injects a
// compiler/linker flag arranging CODE EXECUTION at build time — a cgo `#cgo`
// directive carrying a compiler/LLVM plugin load, a `-B` tool-search redirect, a
// GCC `-specs=` override, an `@file` response file, or a shell metacharacter
// (OPU-28 Increment 2). Unlike an ordinary install hook, this fires at `go build`
// itself.
//
// It gates on the cgo-injection subset of CapExec only (installsurface.
// IsCgoInjectionMarker). A cgo package with ordinary flags (-I/-L/-l/-D/pkg-config)
// carries no such marker and stays silent — the precision that keeps it off the
// very common benign cgo package. It is high/gate-eligible rather than a block:
// modern `go build` already rejects most such flags through its own cgo flag
// allowlist, so the finding flags a suspicious, review-worthy shape (older
// toolchains, CGO_*_ALLOW misconfig, or allowlist bypasses remain exposed) rather
// than asserting a guaranteed-live exploit.
type HookBuildFlagInjection struct{}

func (HookBuildFlagInjection) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002h", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevHigh, DefaultGate: finding.GateEligible,
		Description: "build directive injects a code-loading compiler/linker flag",
	}
}

func (HookBuildFlagInjection) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !v.Caps["exec"] {
			continue
		}
		var hits []string
		seen := map[string]bool{}
		for _, ev := range v.Evidence {
			for _, part := range strings.Split(ev, ",") {
				part = strings.TrimSpace(part)
				if installsurface.IsCgoInjectionMarker(part) && !seen[part] {
					seen[part] = true
					hits = append(hits, strings.TrimPrefix(part, "cgo-inject:"))
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		sort.Strings(hits)
		out = append(out, finding.Finding{
			CheckID: "VC-002h", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevHigh, GateClass: finding.GateEligible,
			Confidence: 0.6, NodeID: v.Pkg.ID,
			Title: fmt.Sprintf("build directive (%s) injects a code-loading flag", v.Hook.Name),
			Evidence: fmt.Sprintf("a #cgo directive carries a build-time code-execution flag shape (%s); "+
				"modern `go build` rejects most such flags via its cgo flag allowlist, but a published module has no legitimate reason to ship one",
				strings.Join(hits, ", ")),
			Remediation: "inspect the #cgo directive: a compiler-plugin load, tool-search redirect, specs override, " +
				"response file, or shell metacharacter in a build flag is an attempt at build-time code execution — do not build until reviewed",
		})
	}
	return out
}

// ---- VC-002i: build-constrained startup-code (init) evasion ---------------

// HookConstrainedInit (VC-002i) reports a package that auto-runs code at program
// STARTUP — an init() function or a blank-identifier var initializer — that is
// conditionally compiled behind a build constraint (a //go:build tag or a
// GOOS/GOARCH filename suffix) AND carries a network, download-cradle,
// decode-obfuscation, or credential capability (OPU-28 Increment 3).
//
// Unlike the rest of the family this is a RUNTIME shape — it runs when the
// consumer runs their program, not at install or build — so the extractor exposes
// no install-hook capability for it; the facts ride evidence markers that only this
// check reads (installsurface.IsInitEvasionMarker). The build constraint is the
// evasion: conditionally-compiled startup code is dormant on a reviewer's platform
// and skipped by tests/CI that run elsewhere, so a hidden runtime payload escapes
// default-build scrutiny. Bare init() and ordinary build-tagged platform files
// carry no such marker and stay silent. High/gate-eligible: a strong,
// review-worthy evasion shape rather than a proven-live install-time compromise.
type HookConstrainedInit struct{}

func (HookConstrainedInit) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002i", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevHigh, DefaultGate: finding.GateEligible,
		Description: "package auto-runs build-constrained startup code with a network/decode/credential capability",
	}
}

func (HookConstrainedInit) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		var caps, constraints []string
		seen := map[string]bool{}
		for _, ev := range v.Evidence {
			for _, part := range strings.Split(ev, ",") {
				part = strings.TrimSpace(part)
				switch {
				case installsurface.IsInitEvasionMarker(part):
					if r := strings.TrimPrefix(part, "init-cap:"); !seen[r] {
						seen[r] = true
						caps = append(caps, r)
					}
				case strings.HasPrefix(part, "init-constraint:"):
					constraints = append(constraints, strings.TrimPrefix(part, "init-constraint:"))
				}
			}
		}
		if len(caps) == 0 {
			continue
		}
		sort.Strings(caps)
		constraint := "a build constraint"
		if len(constraints) > 0 {
			constraint = strings.Join(constraints, ", ")
		}
		out = append(out, finding.Finding{
			CheckID: "VC-002i", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevHigh, GateClass: finding.GateEligible,
			Confidence: 0.6, NodeID: v.Pkg.ID,
			Title: fmt.Sprintf("package auto-runs build-constrained startup code (%s)", v.Hook.Name),
			Evidence: fmt.Sprintf("a conditionally-compiled file (%s) auto-runs startup code (init) exhibiting %s — "+
				"a shape used to hide a runtime payload from default-build review and testing",
				constraint, strings.Join(caps, ", ")),
			Remediation: "review the constrained startup code: conditionally-compiled init that reaches the network, " +
				"decodes a blob, or reads credentials is a runtime backdoor kept out of the default build",
		})
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part != "" && !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---- VC-002j: load-time execution of a bundled native binary --------------

// HookLoadTimeNativeExec (VC-002j) reports a package whose ENTRY MODULE runs at
// import (load-time-execution) and references a bundled NATIVE EXECUTABLE
// (ELF/Mach-O/PE). Unlike a lifecycle hook this fires on ANY import — even a
// transitive one — with no install script: the exact evasion used by the RedC2
// npm loader, whose dist/index.mjs marks a shipped binary executable and spawns
// it detached the instant the module loads. A legitimate prebuilt-binary
// package (esbuild, sharp) invokes its binary lazily through an API or loads a
// .node addon; it does not spawn a raw ELF at module-load, so this composition
// is high / gate-eligible rather than a bare warning.
type HookLoadTimeNativeExec struct{}

func (HookLoadTimeNativeExec) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002j", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevHigh, DefaultGate: finding.GateEligible,
		Description: "entry module executes a bundled native binary at import time",
	}
}

func (HookLoadTimeNativeExec) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !hookEvidenceHas(v, "load-time-execution") || !hookEvidenceHas(v, "bundled-native-executable") {
			continue
		}
		out = append(out, finding.Finding{
			CheckID: "VC-002j", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevHigh, GateClass: finding.GateEligible,
			Confidence: 0.7, NodeID: v.Pkg.ID,
			Title: fmt.Sprintf("%s spawns a bundled native binary at import time", v.Hook.Name),
			Evidence: fmt.Sprintf("entry module executes on import with no lifecycle hook and references a bundled native executable; markers: %s",
				strings.Join(dedupeStrings(v.Evidence), ", ")),
			Remediation: "treat as a load-time trojan loader unless the bundled binary and its import-time launch are both expected; inspect the package's dist/ tree for the native payload",
		})
	}
	return out
}

// ---- VC-002k: self-propagation (the worm step) ----------------------------

// HookSelfPropagation (VC-002k) reports an install hook that PUBLISHES to a
// package registry. This is the step that makes a worm a worm: a compromised
// package whose install hook publishes turns one victim into many, which is the
// propagation phase of the Shai-Hulud family.
//
// depSNORT modelled this in its graph vocabulary from the start —
// graph.EdgeRepublish is documented as the "worm loop back into the declared
// tree", is included in the verdict's install-time subgraph, and is rendered by
// the Cypher and DOT emitters — but until D-152 no detector ever created that
// edge, and no capability marked the act. The persistence phase (VC-002g,
// OPU-35/36) and the credential phase (VC-002c/d, OPU-19) were both detected;
// the propagation phase between them was not.
//
// It is CRITICAL and blocking. Unlike network egress (common and often benign)
// this has no legitimate reading: a library's install hook has no reason to
// publish a package. `npm publish --dry-run` — the release-rehearsal idiom — is
// excluded at the capability layer, so a careful CI script does not fire this.
type HookSelfPropagation struct{}

func (HookSelfPropagation) Meta() check.Meta {
	return check.Meta{
		ID: "VC-002k", Axis: finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevCritical, DefaultGate: finding.GateBlock,
		Description: "install hook publishes to a package registry (self-propagation)",
	}
}

func (HookSelfPropagation) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, v := range collectHooks(ctx.Graph) {
		if !v.Caps["propagate"] {
			continue
		}
		// Credential access alongside publishing is the complete worm loop:
		// steal a token, then use it to push. Said in the evidence rather than
		// split into another check — the propagation act alone already blocks.
		loop := ""
		if v.Caps["credentials"] {
			loop = "; combined with credential access this is the full worm loop (harvest a registry token, then publish with it)"
		}
		out = append(out, finding.Finding{
			CheckID: "VC-002k", Axis: finding.AxisKnownCompromise,
			Severity: finding.SevCritical, GateClass: finding.GateBlock,
			Confidence: 0.9, NodeID: v.Pkg.ID,
			Title: fmt.Sprintf("install hook (%s) publishes to a package registry", v.Hook.Name),
			Evidence: fmt.Sprintf("install-time publish from %s [caps: %s]; markers: %s%s",
				v.Hook.Name, capList(v.Caps), strings.Join(dedupeStrings(v.Evidence), ", "), loop),
			Remediation: "treat as a self-propagating worm: a package's install hook must never publish. Rotate every registry token reachable from this build, audit packages published by those tokens, and quarantine the dependency",
		})
	}
	return out
}

// hookEvidenceHas reports whether any of the hook's evidence strings contains
// the marker substring (evidence entries are comma-joined per source node).
func hookEvidenceHas(v hookView, marker string) bool {
	for _, ev := range v.Evidence {
		if strings.Contains(ev, marker) {
			return true
		}
	}
	return false
}
