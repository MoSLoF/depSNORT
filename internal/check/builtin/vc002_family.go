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
