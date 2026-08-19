// Package ecosystem defines the adapter seam (Decision D-08): every supported
// package ecosystem implements Adapter, and the core never hard-wires one
// resolver's assumptions.
//
// Adapters: npm, pypi, gem (RubyGems), cargo (Rust), composer (PHP), nuget (.NET).
package ecosystem

import (
	"fmt"
	"sort"

	"ihbv.io/depsnort/internal/graph"
)

// Adapter parses a repo or manifest/lockfile set for one ecosystem and returns
// the resolved dependency graph.
//
// ZERO-EXECUTION CONTRACT (Decision D-04, and the whole ethos): Resolve MUST be
// purely static. It parses files. It never runs a package manager, never
// installs, and never executes a lifecycle hook. Any adapter that violates this
// is a bug, not a feature.
//
// Resolve emits FACTS ONLY. It must not set Node.Risk or append Findings — that
// is the job of the check stage (Decision D-03).
type Adapter interface {
	// Name is the ecosystem identifier, e.g. "npm".
	Name() string
	// Detect reports whether this adapter can handle the given path, which may
	// be a directory (repo root) or a specific lockfile.
	Detect(path string) bool
	// Resolve statically parses the tree at path into a graph.
	Resolve(path string) (*graph.Graph, error)
}

// InstallSurfaceExtractor is the optional step-5 capability: statically extract
// a package's install hooks into the install-time subgraph (hook/artifact/sink
// nodes and their edges). Adapters that do not yet implement this simply do not
// satisfy the interface; the engine treats install-surface as empty.
//
// Defined here now so the contract is stable before the implementation lands.
type InstallSurfaceExtractor interface {
	Adapter
	// ExtractInstallSurface reads hook source (package.json "scripts", setup.py,
	// etc.) WITHOUT executing it and adds install-time nodes/edges to g.
	ExtractInstallSurface(path string, g *graph.Graph) error
}

// Registry holds the set of known adapters.
type Registry struct {
	adapters []Adapter
}

// NewRegistry builds a registry from the given adapters.
func NewRegistry(adapters ...Adapter) *Registry {
	return &Registry{adapters: adapters}
}

// Detect returns the first adapter that claims the path.
func (r *Registry) Detect(path string) (Adapter, error) {
	for _, a := range r.adapters {
		if a.Detect(path) {
			return a, nil
		}
	}
	names := make([]string, 0, len(r.adapters))
	for _, a := range r.adapters {
		names = append(names, a.Name())
	}
	sort.Strings(names)
	return nil, fmt.Errorf("no ecosystem adapter matched %q (have: %v)", path, names)
}

// DetectAll returns EVERY adapter that claims the path, in registry
// (precedence) order — so the first is the one Detect would pick and the rest
// are the ecosystems a same-directory scan drops under the one-adapter-per-dir
// rule. Used to disclose that drop as incomplete coverage (OPU-12) rather than
// let a polyglot directory scan green on one ecosystem while the others go
// unmentioned.
func (r *Registry) DetectAll(path string) []Adapter {
	var out []Adapter
	for _, a := range r.adapters {
		if a.Detect(path) {
			out = append(out, a)
		}
	}
	return out
}

// Names lists registered adapter names.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a.Name())
	}
	return out
}
