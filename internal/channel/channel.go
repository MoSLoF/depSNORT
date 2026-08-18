// Package channel records a package's ACQUISITION CHANNEL: not where the
// lockfile says a package came from (Decision D-41 answers that), but where
// this tree's resolver configuration would actually have fetched it from, and
// whether anything rewrote the coordinate on the way.
//
// # Why this is a separate seam from ecosystem.Adapter
//
// D-41 classifies a node's origin from the lockfile entry itself, which is the
// right source for that question. But two facts that decide whether a scan
// means anything are NOT in the lockfile:
//
//   - WHICH registry. `.npmrc`, `pip.conf`, `NuGet.config`, and
//     `.cargo/config.toml` can point a name — or one scope, or everything — at a
//     host the lockfile never mentions. The lockfile still records a bare
//     registry coordinate, so `graph.Verifiable` returns true, VC-009 stays
//     quiet, and the OSV lookup runs against a coordinate this build would
//     never have fetched. That is a confident all-clear over something the scan
//     did not read: the exact failure D-24 exists to prevent, one layer out.
//
//   - WHAT THE COORDINATE RESOLVES TO. npm `overrides`, yarn `resolutions`,
//     Cargo `[patch]`, and pip constraint files replace a package's content
//     while its name@version reads unchanged.
//
// Both live in files that are not lockfiles, are read hierarchically rather
// than per-package, and recur IDENTICALLY across all six ecosystems. Folding
// them into Adapter would mean six implementations of one vector class — the
// drift D-15 already caught twice (PEP 503 identity, ecosystem-blind VC-006).
//
// The shape here is the one D-15 established for VC-004/VC-005: a shared engine
// plus a per-ecosystem Spec. Extraction never judges (D-03): this package
// records facts on nodes and gaps on the result. Checks decide what they mean.
package channel

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
)

// Ecosystem-neutral channel facts, for the same reason the coverage (D-24) and
// provenance (D-41) keys are: the verdict layer must read them without knowing
// which resolver ran.
const (
	// AttrEndpoint is the host that this tree's configuration routes the
	// package to. Absent when no configuration was found, which is not a gap:
	// absence of config IS the canonical endpoint, by definition of every
	// package manager here.
	AttrEndpoint = "depsnort.channel_endpoint"
	// AttrEndpointClass is one of the Endpoint* constants below.
	AttrEndpointClass = "depsnort.channel_endpoint_class"
	// AttrRedirectedBy is the file:line that did the routing, so a report can
	// name the mechanism rather than assert the conclusion.
	AttrRedirectedBy = "depsnort.channel_redirected_by"
	// AttrSubstitution is what an override/resolution/patch replaced this
	// coordinate with, in the form "<what> -> <with>".
	AttrSubstitution = "depsnort.channel_substitution"
	// AttrSubstitutedBy is the file:line of that substitution.
	AttrSubstitutedBy = "depsnort.channel_substituted_by"
)

// Endpoint classes.
//
// Deliberately NOT a new graph.SourceClass. D-43 made non-registry origins
// qualify the PURL; reclassifying every package behind a corporate mirror would
// re-qualify an entire organization's node identities and silently miss every
// baseline (D-40) keyed to the old ones. Mirrors are the common LEGITIMATE
// case. So the endpoint is recorded orthogonally to identity, and the coverage
// layer reads both.
const (
	// EndpointCanonical: the ecosystem's public registry.
	EndpointCanonical = "canonical"
	// EndpointAlternate: a different host, declared in an in-tree config file.
	// Auditable and usually a corporate mirror — a posture question, not a
	// finding on its own (the VC-009 lesson: vendoring is not a smell).
	EndpointAlternate = "alternate"
	// EndpointUnknown: a config file exists and bears on this package, but
	// could not be read or parsed. Fails closed (D-34/D-35): unknown routing
	// degrades coverage rather than defaulting to canonical.
	EndpointUnknown = "unknown"
)

// Location is where a fact was found, so findings cite evidence.
type Location struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
}

func (l Location) String() string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	}
	return l.File
}

// Route sends packages matching Pattern to Endpoint.
type Route struct {
	// Pattern selects packages. "" matches everything (a default-registry
	// line); an ecosystem may also emit a scope ("@acme/") or a name prefix.
	// Matching is LONGEST-PATTERN-WINS and never widens — the DS-REV-02 rule,
	// applied to routing: a guessed route is indistinguishable from a real one
	// once it is on the node.
	Pattern  string
	Endpoint string // host, already normalized by the Spec
	Source   Location
}

// Substitution is a coordinate rewrite: overrides, resolutions, [patch],
// constraint pins.
type Substitution struct {
	Name    string // package name the rewrite targets
	Replace string // what it replaces (version range, or "" for any)
	With    string // what it resolves to instead
	Source  Location
}

// Config is one parsed resolver-configuration file.
type Config struct {
	Routes        []Route
	Substitutions []Substitution
}

// Spec is what one ecosystem must supply. It is DATA AND PARSING ONLY: no
// ecosystem decides what a route means, and none of these methods touch the
// graph.
type Spec interface {
	// Ecosystem matches graph.Node.Ecosystem.
	Ecosystem() string
	// ConfigPaths lists candidate resolver-config files for a tree rooted at
	// dir, MOST SPECIFIC FIRST. Per-project before per-user; callers stop at
	// the first that defines a given pattern.
	ConfigPaths(dir string) []string
	// ParseConfig extracts routes and substitutions from one config file.
	// Returning an error marks every package the file could bear on as
	// EndpointUnknown rather than assuming canonical.
	ParseConfig(path string, data []byte) (Config, error)
	// Canonical reports whether host is this ecosystem's public registry.
	Canonical(host string) bool
	// Match reports whether a route pattern applies to a package name, using
	// the ecosystem's own naming rules (npm scopes, NuGet's case folding).
	Match(pattern, name string) bool
}

// Reader supplies file bytes. Injected so the resolver stays testable and so
// reads go through internal/securefs at the call site rather than here.
type Reader func(path string) ([]byte, error)

// Gap is a config file that bears on routing and could not be read. Modeled on
// internal/ecosystem/instsurf/gaps.go: a typed gap, not a swallowed error.
type Gap struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Result is what a scan learned about channels, beyond the per-node facts.
type Result struct {
	// Alternate counts packages routed off the canonical registry.
	Alternate int `json:"alternate_endpoint_packages"`
	// Unknown counts packages whose routing could not be determined. This is
	// the number that must reach the coverage axis.
	Unknown int `json:"unknown_endpoint_packages"`
	// Substituted counts coordinates rewritten by an override/patch.
	Substituted int   `json:"substituted_packages"`
	Gaps        []Gap `json:"gaps,omitempty"`
}

// Resolver annotates graphs with channel facts.
type Resolver struct {
	specs map[string]Spec
	read  Reader
}

// NewResolver builds a resolver over the given specs.
func NewResolver(read Reader, specs ...Spec) *Resolver {
	m := make(map[string]Spec, len(specs))
	for _, s := range specs {
		m[s.Ecosystem()] = s
	}
	return &Resolver{specs: m, read: read}
}

// Annotate reads the resolver configuration under dir and records, on every
// package node, where this tree would actually have fetched it from.
//
// It runs AFTER Adapter.Resolve and BEFORE the check stage: it needs the graph
// to attach to, and the checks need the facts. It writes only Attr keys — never
// Risk, never Findings (D-03).
func (r *Resolver) Annotate(dir string, g *graph.Graph) (Result, error) {
	var res Result
	if g == nil {
		return res, nil
	}

	// Parse each ecosystem's config once per scan, not once per node.
	type parsed struct {
		cfg  Config
		bad  []Gap
		spec Spec
	}
	byEco := map[string]*parsed{}

	// Iterate specs in a fixed order: gaps and counters must not depend on map
	// iteration (D-13 — determinism is enforced, not hoped for).
	ecos := make([]string, 0, len(r.specs))
	for eco := range r.specs {
		ecos = append(ecos, eco)
	}
	sort.Strings(ecos)

	for _, eco := range ecos {
		spec := r.specs[eco]
		p := &parsed{spec: spec}
		for _, path := range spec.ConfigPaths(dir) {
			data, err := r.read(path)
			if err != nil {
				// A missing config file is the normal case and means
				// canonical. Only an existing-but-unreadable one is a gap;
				// the Reader distinguishes them by returning fs.ErrNotExist.
				if isNotExist(err) {
					continue
				}
				p.bad = append(p.bad, Gap{Path: path, Reason: err.Error()})
				continue
			}
			cfg, err := spec.ParseConfig(path, data)
			if err != nil {
				p.bad = append(p.bad, Gap{Path: path, Reason: err.Error()})
				continue
			}
			// Most-specific-first: earlier files win, so append and let the
			// stable sort below prefer longer patterns within equal specificity.
			p.cfg.Routes = append(p.cfg.Routes, cfg.Routes...)
			p.cfg.Substitutions = append(p.cfg.Substitutions, cfg.Substitutions...)
		}
		// Longest pattern first — never widen (DS-REV-02).
		sort.SliceStable(p.cfg.Routes, func(i, j int) bool {
			return len(p.cfg.Routes[i].Pattern) > len(p.cfg.Routes[j].Pattern)
		})
		byEco[eco] = p
		res.Gaps = append(res.Gaps, p.bad...)
	}

	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		p := byEco[n.Ecosystem]
		if p == nil {
			continue // no spec for this ecosystem: nothing claimed, nothing said
		}
		// A package with a non-registry origin is already outside registry
		// routing; D-41 has said what needs saying and re-labelling it here
		// would double-count it on the coverage axis.
		if class, _ := n.SourceOf(); class != graph.SourceRegistry {
			continue
		}

		if len(p.bad) > 0 {
			setAttr(n, AttrEndpointClass, EndpointUnknown)
			setAttr(n, AttrRedirectedBy, p.bad[0].Path)
			res.Unknown++
			continue
		}

		for _, rt := range p.cfg.Routes {
			if !p.spec.Match(rt.Pattern, n.Name) {
				continue
			}
			setAttr(n, AttrEndpoint, rt.Endpoint)
			setAttr(n, AttrRedirectedBy, rt.Source.String())
			if p.spec.Canonical(rt.Endpoint) {
				setAttr(n, AttrEndpointClass, EndpointCanonical)
			} else {
				setAttr(n, AttrEndpointClass, EndpointAlternate)
				res.Alternate++
			}
			break // longest match wins
		}

		for _, s := range p.cfg.Substitutions {
			if !strings.EqualFold(s.Name, n.Name) {
				continue
			}
			what := s.Replace
			if what == "" {
				what = "*"
			}
			setAttr(n, AttrSubstitution, what+" -> "+s.With)
			setAttr(n, AttrSubstitutedBy, s.Source.String())
			res.Substituted++
			break
		}
	}
	return res, nil
}

// Attestable reports whether an advisory lookup against this node's coordinate
// can mean anything. It is the channel-aware successor to graph.Verifiable, and
// exists for the same reason: "which packages did we actually scan" must be
// defined ONCE, where the coverage layer and the checks both read it.
//
// A registry package routed to an alternate host is still attestable in
// principle — a corporate mirror usually serves the same artifacts — but the
// advisory feed indexes the canonical coordinate, so the claim is weaker than
// the bare PURL suggests. Callers that gate must treat alternate as disclosed,
// not silent.
func Attestable(n *graph.Node) bool {
	if n == nil {
		return false
	}
	class, _ := n.SourceOf()
	if !graph.Verifiable(class) {
		return false
	}
	return n.Attr[AttrEndpointClass] != EndpointUnknown
}

func setAttr(n *graph.Node, k, v string) {
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	n.Attr[k] = v
}

// isNotExist distinguishes "no config here" (the overwhelmingly common case,
// and the definition of canonical routing) from "config exists and I could not
// read it" (a gap that must fail closed). The Reader contract is therefore
// load-bearing: it MUST wrap fs.ErrNotExist rather than returning a bare
// formatted error, or every missing .npmrc manufactures a scan-wide gap.
func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// join is a convenience for Spec implementations building ConfigPaths.
func join(parts ...string) string { return filepath.Join(parts...) }

var _ = join
