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
	"sort"
	"strings"

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
	// RealRoots designates which scan roots the operator actually builds and
	// ships, as case-insensitive substrings matched against root node IDs
	// (-real-roots). When non-empty, every finding whose node is reachable
	// from NO designated root is labeled Contained — an adjudication with the
	// proof attached (ReachableRoots), never a suppression: the finding keeps
	// its severity, its gate class, and its effect on the exit code. Empty
	// (the default) labels nothing.
	RealRoots []string
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

// applyPresumedDemotion downgrades every finding on a node whose version this
// tool chose rather than observed, down to advisory.
//
// # Why this is structural and not each check's good behavior
//
// The Nth-layer walk reaches past what a manifest recorded by presuming a
// version — the highest published one satisfying the constraints its dependents
// declared. That is what an installer would most likely resolve, and it is not
// what one was observed to resolve. A node built on it may not exist in any
// real build of this project.
//
// Gating on that is the worst trade this tool can make. A block over a version
// nobody installed is a false positive with a build failure attached, and one
// of those teaches an operator to disable expansion permanently — costing every
// true finding the deeper layers would have produced. High recall in the
// report, high precision at the gate: the D-06 guarantee, applied to a second
// axis and enforced in the same place, so no future check can opt out of it.
//
// # Why block class is demoted here when recency demotion refuses to
//
// The two rules rest on different premises, and the difference is the node's
// existence rather than its severity. Recency demotion applies to a package the
// lockfile OBSERVED: the release is real, it is installed, and a poisoned one
// does not become safe with age — so block survives. A presumed node's version
// was never observed at all, so a block-class finding about it is a confident
// statement about a coordinate that may not be in the build. Severity cannot
// rescue a subject that might not be there.
//
// The finding is DEMOTED, never dropped. It stays in the report, on the node,
// with the reason in its evidence — a typosquatted name found four layers down
// is exactly the signal expansion exists to surface, and silently suppressing it
// would be the sin D-20 named for caps and D-24 named for coverage.
func applyPresumedDemotion(g *graph.Graph, findings []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		f := &out[i]
		if f.GateClass == finding.GateAdvisory {
			continue
		}
		n := g.Get(f.NodeID)
		if n == nil || !n.Presumed() {
			continue
		}
		was := f.GateClass
		f.GateClass = finding.GateAdvisory
		note := fmt.Sprintf(" [demoted to advisory from %s: this node's version is %s, not observed in a lockfile",
			was, n.VersionTruth())
		if c := n.Attr[graph.AttrVersionCandidates]; c != "" {
			note += fmt.Sprintf(" (%s candidate versions satisfied %q)", c, n.Attr[graph.AttrDeclaredConstraint])
		}
		f.Evidence += note + "]"
	}
	return out
}

// maxListedReachableRoots caps how many roots the containment evidence note
// spells out. The complete list is always on the finding (ReachableRoots); only
// the prose is capped, and the remainder is counted rather than hidden.
const maxListedReachableRoots = 3

// reachableRootsByNode computes, for every node, the sorted set of scan roots
// that reach it over ANY edge type. All edges count — a hook, a referenced
// artifact, or a sink is attributed to the root whose subtree declared it, even
// though no depends-on path exists. This is the complete attribution fact that
// DepPath (one shortest chain) cannot carry, and the substrate of the
// containment adjudication.
func reachableRootsByNode(g *graph.Graph) map[string][]string {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	byNode := map[string][]string{}
	roots := append([]string(nil), g.Roots...)
	sort.Strings(roots) // deterministic append order => sorted lists (D-13)
	for _, root := range roots {
		seen := map[string]bool{root: true}
		byNode[root] = append(byNode[root], root)
		queue := append([]string(nil), adj[root]...)
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			if seen[id] {
				continue
			}
			seen[id] = true
			byNode[id] = append(byNode[id], root)
			queue = append(queue, adj[id]...)
		}
	}
	return byNode
}

// applyContainment stamps every finding with its complete root attribution
// (ReachableRoots) and, when the policy designates real roots, adjudicates
// containment: a finding no designated root can reach is labeled Contained,
// with the proof in its evidence. Nothing is dropped, softened, or re-gated —
// the label rides on top of an otherwise unchanged finding (the counts and
// exit code computed later see exactly the same gate classes).
func applyContainment(g *graph.Graph, findings []finding.Finding, realRoots []string) []finding.Finding {
	if len(findings) == 0 {
		return findings
	}
	reach := reachableRootsByNode(g)
	out := make([]finding.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		f := &out[i]
		f.ReachableRoots = reach[f.NodeID]
		if len(realRoots) == 0 {
			continue
		}
		reachedByReal := false
		for _, root := range f.ReachableRoots {
			for _, want := range realRoots {
				if want != "" && strings.Contains(strings.ToLower(root), strings.ToLower(want)) {
					reachedByReal = true
					break
				}
			}
			if reachedByReal {
				break
			}
		}
		if reachedByReal {
			continue
		}
		f.Contained = true
		listed := f.ReachableRoots
		suffix := ""
		if len(listed) > maxListedReachableRoots {
			suffix = fmt.Sprintf(", +%d more", len(listed)-maxListedReachableRoots)
			listed = listed[:maxListedReachableRoots]
		}
		note := " [contained: no designated real root reaches this node"
		if len(listed) > 0 {
			note += "; reachable only from " + strings.Join(listed, ", ") + suffix
		} else {
			note += "; reachable from no root at all"
		}
		f.Evidence += note + "]"
	}
	return out
}

// Evaluate attaches findings to their nodes, computes each node's risk state,
// and derives the exit code, using ONLY the graph's own resolution coverage. It
// is EvaluateWithCoverage with no scan-level gaps folded in — the right entry
// point for a single-source caller or a test that has only a graph in hand.
func Evaluate(g *graph.Graph, findings []finding.Finding, pol Policy) Result {
	return EvaluateWithCoverage(g, findings, g.Coverage(), pol)
}

// EvaluateWithCoverage is Evaluate with an explicit scan-level coverage. It
// mutates the graph's nodes (Risk, Findings), which is the one place that is
// allowed to (verdict is downstream of all checks).
//
// The cov argument is the SCAN-level coverage (graph resolution PLUS data-source,
// install-surface, and workspace gaps), assembled by the caller — the verdict
// does not recompute it from the graph, because the graph cannot see a failed OSV
// lookup or an unreadable subtree (finding F-02).
func EvaluateWithCoverage(g *graph.Graph, findings []finding.Finding, cov graph.Coverage, pol Policy) Result {
	// Stale temporal findings lose the right to gate before anything is counted.
	findings = applyRecencyDemotion(findings)
	// So do findings about a version this tool presumed rather than observed.
	// Both run before counting, so the gate-class tallies the report prints are
	// the classes that actually govern the exit code.
	findings = applyPresumedDemotion(g, findings)
	// Every finding is stamped with its complete root attribution, and — when
	// the policy designates real roots — adjudicated for containment. Unlike
	// the two demotions above this NEVER changes a gate class: containment is a
	// label with a proof attached, and the counts below are identical with or
	// without it.
	findings = applyContainment(g, findings, pol.RealRoots)

	res := Result{
		Coverage: cov,
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
	case pol.FailOnIncomplete && res.Coverage.Incomplete():
		res.ExitCode = ExitIncomplete
	default:
		res.ExitCode = ExitClean
	}
	return res
}
