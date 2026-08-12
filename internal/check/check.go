// Package check defines the vector-check plugin contract (Snort-rule parity,
// Decision D-02 / brief §2). Built-in checks implement the exact same Check
// interface that third-party plugins will (step 9); the v0 ruleset is simply
// the first pack.
package check

import (
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// Meta is a check's self-description. It is declared, not inferred, so the
// engine can reason about a check (its axis, its data needs) without running it.
type Meta struct {
	ID              string       // e.g. "VC-002a"
	Axis            finding.Axis // detection lens
	DefaultSeverity finding.Severity
	DefaultGate     finding.GateClass
	Description     string
	DataDeps        []string // named data sources this check needs (e.g. "osv")
}

// Config carries operator-supplied policy that some checks need — e.g. which
// scopes/names are internal, for dependency-confusion detection (VC-007).
type Config struct {
	InternalScopes []string // e.g. "@ihbv"
	InternalNames  []string // e.g. "ihbv-internal-utils"
}

// Context is what a check gets to look at. The graph is immutable from a
// check's perspective — checks read facts and return Findings; they do not
// mutate nodes (Decision D-03).
//
// Advisories are pre-fetched by the scan orchestration via the data-source
// layer and keyed by node ID (canonical PURL). Checks read them; they never
// fetch. DataSources remains a reserved slot for future feeds (the IOC ledger).
type Context struct {
	Graph      *graph.Graph
	Now        time.Time
	Advisories map[string][]datasource.Advisory
	// Releases is publish-time history keyed by node ID — the substrate of the
	// temporal axis. Empty when the registry source is disabled or offline with
	// a cold cache; temporal checks then simply do not fire.
	Releases    map[string]*datasource.ReleaseHistory
	Config      Config
	DataSources map[string]any // reserved for future feeds
}

// Check is the one method every vector check implements.
type Check interface {
	Meta() Meta
	Run(*Context) []finding.Finding
}

// Registry is an ordered set of checks. The built-in pack registers here; a
// plugin loader would register into the same structure.
type Registry struct {
	checks []Check
}

// NewRegistry builds a registry from the given checks.
func NewRegistry(checks ...Check) *Registry {
	return &Registry{checks: checks}
}

// Register appends a check.
func (r *Registry) Register(c Check) { r.checks = append(r.checks, c) }

// Metas returns every registered check's Meta, for `depsnort checks`.
func (r *Registry) Metas() []Meta {
	out := make([]Meta, 0, len(r.checks))
	for _, c := range r.checks {
		out = append(out, c.Meta())
	}
	return out
}

// RunAll executes every check against ctx and returns the aggregated findings.
func (r *Registry) RunAll(ctx *Context) []finding.Finding {
	var all []finding.Finding
	for _, c := range r.checks {
		all = append(all, c.Run(ctx)...)
	}
	return all
}
