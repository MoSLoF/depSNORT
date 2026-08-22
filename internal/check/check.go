// Package check defines the vector-check plugin contract (Snort-rule parity,
// Decision D-02 / brief §2). Built-in checks implement the exact same Check
// interface that third-party plugins will (step 9); the v0 ruleset is simply
// the first pack.
package check

import (
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/epss"
	"ihbv.io/depsnort/internal/datasource/ioc"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/profile"
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
	// EPSS maps a CVE ID to its FIRST.org exploit-prediction score. Populated
	// only when -epss is set and the network is reachable; empty otherwise, in
	// which case VC-008 simply omits the prioritization note.
	EPSS map[string]epss.Score
	// EPSSGate is the exploit-probability threshold (0..1) at or above which a
	// VC-008 finding escalates from advisory to gate-eligible — the difference
	// between "here are the CVEs" and "these are being exploited, fail the build".
	// 0 (the default) disables escalation, keeping VC-008 purely advisory. Set
	// only when -epss-gate is passed; meaningless without -epss (no scores to
	// compare). The escalation composes with -fail-on-eligible for the exit code
	// and is still subject to presumed-version demotion in the verdict.
	EPSSGate float64
	// Releases is publish-time history keyed by node ID — the substrate of the
	// temporal axis. Empty when the registry source is disabled or offline with
	// a cold cache; temporal checks then simply do not fire.
	Releases map[string]*datasource.ReleaseHistory
	Config   Config
	// IOC is the operator's indicator ledger, keyed by node ID (canonical PURL).
	// Populated by the orchestrator when -ioc is set; consumed by VC-003. Empty
	// when no ledger was supplied, in which case VC-003 simply does not fire.
	IOC map[string]ioc.Indicator
	// Baseline is the operator-promoted known-good record, keyed by
	// baseline.Key(ecosystem, name) — NOT by PURL, because the whole point is
	// to compare a candidate against a DIFFERENT version of the same package
	// (Decision D-40). Empty when no -baseline was supplied, in which case the
	// drift checks do not fire.
	//
	// The value is every approved version under that key, not one chosen for
	// the check (finding DS-REV-03). A baseline can legitimately hold several
	// versions of one package — two projects in a workspace approving
	// different pins — and picking between them by version order answers a
	// question nobody asked: the right profile depends on which project the
	// candidate came from. VC-010 refuses to conclude when the answer is not
	// determined.
	Baseline map[string][]profile.Profile
	// Profiles is the candidate side: one profile per resolved package in this
	// scan, keyed by PURL. Populated only when a baseline was supplied, since
	// nothing else reads it.
	Profiles    map[string]profile.Profile
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
