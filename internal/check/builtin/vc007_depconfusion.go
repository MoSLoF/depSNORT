package builtin

import (
	"fmt"
	"net/url"
	"strings"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// DependencyConfusion (VC-007) flags a dependency that matches one of the
// operator's declared internal scopes/names but resolves from a PUBLIC registry
// — the substitution attack where a public package shadows a private one.
//
// Currently npm-only: the check relies on the npm.resolved URL to identify the
// source registry. Other ecosystems' lockfiles do not consistently record which
// registry a package was fetched from, so the check declines (D-15) rather than
// guessing. Expanding to PyPI/NuGet/etc. requires ecosystem-specific registry
// resolution fields.
//
// It is a no-op unless internal scopes/names are configured (Config), so it
// raises zero false alarms out of the box. A confirmed internal name resolving
// publicly is gate-eligible (a real substitution risk), not merely advisory.
type DependencyConfusion struct{}

// publicNpmHosts are registry hosts treated as public.
var publicNpmHosts = map[string]struct{}{
	"registry.npmjs.org":   {},
	"registry.yarnpkg.com": {},
}

// Meta implements check.Check.
func (DependencyConfusion) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-007",
		Axis:            finding.AxisWeather,
		DefaultSeverity: finding.SevHigh,
		DefaultGate:     finding.GateEligible,
		Description:     "internal-looking package resolves from a public registry (dependency confusion)",
	}
}

// resolvesPublic reports whether a resolved URL points at a known public host.
func resolvesPublic(resolved string) bool {
	if resolved == "" {
		return false
	}
	u, err := url.Parse(resolved)
	if err != nil {
		return false
	}
	_, ok := publicNpmHosts[strings.ToLower(u.Host)]
	return ok
}

// matchesInternal reports whether name is covered by the configured internal
// scopes or names.
func matchesInternal(name string, cfg check.Config) bool {
	for _, s := range cfg.InternalScopes {
		if s == "" {
			continue
		}
		if strings.HasPrefix(name, strings.TrimSuffix(s, "/")+"/") {
			return true
		}
	}
	for _, n := range cfg.InternalNames {
		if n != "" && name == n {
			return true
		}
	}
	return false
}

// Run implements check.Check.
func (DependencyConfusion) Run(ctx *check.Context) []finding.Finding {
	if len(ctx.Config.InternalScopes) == 0 && len(ctx.Config.InternalNames) == 0 {
		return nil // nothing declared internal -> no basis to judge
	}
	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "npm" {
			continue
		}
		if !matchesInternal(n.Name, ctx.Config) {
			continue
		}
		if !resolvesPublic(n.Attr["npm.resolved"]) {
			continue
		}
		out = append(out, finding.Finding{
			CheckID:     "VC-007",
			Axis:        finding.AxisWeather,
			Severity:    finding.SevHigh,
			GateClass:   finding.GateEligible,
			Confidence:  0.8,
			NodeID:      n.ID,
			Title:       "internal package resolved from a public registry",
			Evidence:    fmt.Sprintf("%s matches an internal scope/name but resolved from %s", n.Name, n.Attr["npm.resolved"]),
			Remediation: "pin to your internal registry and reserve the name publicly to block substitution",
		})
	}
	return out
}
