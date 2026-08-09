// Package verdict turns a graph plus a set of findings into (a) a risk state
// per node and (b) a single process exit code, per the gate-class contract
// (Decisions D-05/D-06/D-09).
//
// Exit-code contract:
//
//	0  clean, OR only advisory findings present
//	1  any block-class finding (FLAG)
//	2  a gate-eligible finding AND policy opted in
//	3  resolution coverage is incomplete AND policy opted in
//
// Advisory findings NEVER change the exit code, regardless of policy. That is a
// structural guarantee, enforced here.
//
// Coverage is a SECOND AXIS, independent of risk (Decision D-24). "We found
// nothing" and "we could not look" are different statements, and a detection
// tool that renders them identically is worse than one that cries wolf: a false
// alarm gets investigated, a false all-clear gets trusted.
package verdict

import (
	"fmt"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// Exit codes.
const (
	ExitClean      = 0
	ExitBlock      = 1
	ExitGate       = 2
	ExitIncomplete = 3
)

// Policy controls whether gate-eligible findings fail the run.
type Policy struct {
	// FailOnEligible, when true, makes gate-eligible findings return ExitGate.
	// Advisory findings are unaffected by this and can never gate.
	FailOnEligible bool
	// FailOnIncomplete, when true, makes partial resolution coverage return
	// ExitIncomplete. Off by default: incomplete coverage is always REPORTED,
	// but whether it stops a pipeline is a policy question, not a fact about
	// the dependency tree.
	FailOnIncomplete bool
}

// Counts summarizes findings by gate class.
type Counts struct {
	Block    int `json:"block"`
	Eligible int `json:"gate_eligible"`
	Advisory int `json:"advisory"`
	Total    int `json:"total"`
}

// Result is the outcome of evaluation.
type Result struct {
	ExitCode int                          `json:"exit_code"`
	Counts   Counts                       `json:"counts"`
	Coverage graph.Coverage               `json:"coverage"`
	Risk     map[string]finding.RiskState `json:"risk_by_node"`
	Findings []finding.Finding            `json:"findings"`
}

// installTimeEdges are the relations that make up the install-time subgraph.
var installTimeEdges = map[graph.EdgeType]bool{
	graph.EdgeDeclaresHook: true,
	graph.EdgeHookExecs:    true,
	graph.EdgeHookFetches:  true,
	graph.EdgeHookReadsEnv: true,
	graph.EdgeExfil:        true,
	graph.EdgeRepublish:    true,
}

// riskRank orders risk states so propagation can raise but never downgrade.
func riskRank(r finding.RiskState) int {
	switch r {
	case finding.RiskFlagged:
		return 2
	case finding.RiskWarned:
		return 1
	default:
		return 0
	}
}

// propagateInstallTime raises every node reachable from a non-clean package via
// install-time edges to that package's risk state. Traversal is breadth-first
// and cycle-safe; it only ever raises, so a node already flagged by its own
// finding is never softened.
func propagateInstallTime(g *graph.Graph, risk map[string]finding.RiskState) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if installTimeEdges[e.Type] {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	if len(adj) == 0 {
		return
	}
	for _, pkg := range g.SortedNodes() {
		if pkg.Kind != graph.KindPackage || riskRank(pkg.Risk) == 0 {
			continue
		}
		seen := map[string]bool{pkg.ID: true}
		queue := append([]string(nil), adj[pkg.ID]...)
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			if seen[id] {
				continue
			}
			seen[id] = true
			if n := g.Get(id); n != nil && riskRank(pkg.Risk) > riskRank(n.Risk) {
				n.Risk = pkg.Risk
				risk[id] = pkg.Risk
			}
			queue = append(queue, adj[id]...)
		}
	}
}

// StaleFloor is the recency-decay level below which a temporal finding may no
// longer fail a build. 0.15 is roughly 2.7 half-lives (~8 months at the default
// 90-day half-life).
const StaleFloor = 0.15

// applyRecencyDemotion downgrades stale temporal findings from gate-eligible to
// advisory (Decision D-12).
//
// Rationale, learned from a live run: a real release burst in `tar` from 2019
// is factually correct and scores ~0 after decay, but it was still gate-eligible
// — so `-fail-on-eligible` would break a build today over seven-year-old news.
// Decay governed ranking but not gating; that gap is closed here.
//
// The finding is DEMOTED, never dropped: it stays visible in the report with the
// demotion recorded in its evidence. Silent suppression would be the same sin as
// a silent cap. Block-class findings are never demoted — a poisoned release does
// not become safe with age.
func applyRecencyDemotion(findings []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		f := &out[i]
		if f.GateClass != finding.GateEligible || f.RecencyDecay <= 0 {
			continue
		}
		if f.RecencyDecay >= StaleFloor {
			continue
		}
		f.GateClass = finding.GateAdvisory
		note := fmt.Sprintf(" [demoted to advisory: recency decay %.3f is below the %.2f stale floor]",
			f.RecencyDecay, StaleFloor)
		f.Evidence += note
	}
	return out
}

// Evaluate attaches findings to their nodes, computes each node's risk state,
// and derives the exit code. It mutates the graph's nodes (Risk, Findings),
// which is the one place that is allowed to (verdict is downstream of all
// checks).
func Evaluate(g *graph.Graph, findings []finding.Finding, pol Policy) Result {
	// Stale temporal findings lose the right to gate before anything is counted.
	findings = applyRecencyDemotion(findings)

	res := Result{
		Coverage: g.Coverage(),
		Risk:     make(map[string]finding.RiskState),
		Findings: findings,
	}

	// Group findings by node.
	byNode := make(map[string][]finding.Finding)
	for _, f := range findings {
		byNode[f.NodeID] = append(byNode[f.NodeID], f)
		switch f.GateClass {
		case finding.GateBlock:
			res.Counts.Block++
		case finding.GateEligible:
			res.Counts.Eligible++
		case finding.GateAdvisory:
			res.Counts.Advisory++
		}
		res.Counts.Total++
	}

	// Default every known node to clean.
	for _, n := range g.SortedNodes() {
		n.Findings = nil
		n.Risk = finding.RiskClean
		res.Risk[n.ID] = finding.RiskClean
	}

	// Overlay findings and derive risk state:
	//   any block finding      -> flagged
	//   else any finding       -> warned
	//   else                   -> clean
	for id, fs := range byNode {
		state := finding.RiskWarned
		for _, f := range fs {
			if f.GateClass == finding.GateBlock {
				state = finding.RiskFlagged
				break
			}
		}
		res.Risk[id] = state
		if n := g.Get(id); n != nil {
			n.Findings = fs
			n.Risk = state
		}
	}

	// Propagate risk down the install-time subgraph. A hook, the files it
	// executes, the URLs it reaches, and the credential sinks it touches are
	// the REASON a package is flagged — they must render hot too, or a graph
	// view shows a red package hanging off a cool-looking worm chain.
	propagateInstallTime(g, res.Risk)

	// Exit code, honoring the never-gate guarantee for advisory findings.
	// Ordered most-severe-first: a block outranks a gate, which outranks a
	// coverage failure. Coverage is last because "we could not look" is only
	// actionable once "we looked and it is poisoned" has been ruled out.
	switch {
	case res.Counts.Block > 0:
		res.ExitCode = ExitBlock
	case pol.FailOnEligible && res.Counts.Eligible > 0:
		res.ExitCode = ExitGate
	case pol.FailOnIncomplete && res.Coverage.Degraded:
		res.ExitCode = ExitIncomplete
	default:
		res.ExitCode = ExitClean
	}
	return res
}
