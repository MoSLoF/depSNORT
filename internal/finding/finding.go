// Package finding defines the vocabulary every vector-check speaks: severity,
// axis, gate-class, risk state, and the Finding record itself.
//
// This package is deliberately dependency-free and sits at the bottom of the
// import graph so that graph, check, verdict, and emit can all share these
// types without cycles.
//
// The gate-class model is the load-bearing design decision (D-05/D-06):
// node COLOR (RiskState) and exit-code SEMANTICS (GateClass) are separate axes.
// A finding can turn a node amber (RiskWarned) while never being allowed to
// fail a build (GateAdvisory). See docs/DECISIONS.md.
package finding

import "encoding/json"

// Severity is the "how bad if true" axis. It is independent of confidence.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// weight maps a severity to a numeric factor used by Finding.Score.
func (s Severity) weight() float64 {
	switch s {
	case SevCritical:
		return 1.0
	case SevHigh:
		return 0.8
	case SevMedium:
		return 0.5
	case SevLow:
		return 0.25
	default: // SevInfo / unknown
		return 0.1
	}
}

// Axis is the detection lens a check belongs to. Vuln is kept as its own axis
// (Decision, brief §5) so that ordinary CVE noise never drowns the
// supply-chain signal.
type Axis string

const (
	AxisKnownCompromise Axis = "known-compromise" // deterministic poison
	AxisWeather         Axis = "weather"          // recent-compromise, temporal
	AxisVuln            Axis = "vuln"             // ordinary disclosed CVEs
	AxisHygiene         Axis = "hygiene"          // provenance / attestation gaps
	// AxisDrift is state transition: what changed between a known-good release
	// and the candidate one (Decision D-40). Distinct from weather because the
	// subject is different — weather asks whether a release is anomalous for
	// this package's own history, drift asks whether the package still does
	// what it did when someone approved it. A finding on this axis is always
	// relative to a baseline, and says nothing at all without one.
	AxisDrift Axis = "drift"
)

// GateClass is the exit-code semantics of a finding — distinct from RiskState.
//
//	GateBlock     : always fails (exit 1). No policy can soften it.
//	GateEligible  : fails ONLY if the run policy opts in (exit 2).
//	GateAdvisory  : never touches the exit code, by construction (exit 0).
//
// Decision D-06: cluster/namespace proximity is GateAdvisory. This is a
// structural guarantee, not a config default — verdict.Evaluate must never
// gate on an advisory finding regardless of policy.
type GateClass string

const (
	GateBlock    GateClass = "block"
	GateEligible GateClass = "gate-eligible"
	GateAdvisory GateClass = "advisory"
)

// RiskState is the visual/graph state overlaid on a node.
type RiskState string

const (
	RiskClean   RiskState = "clean"
	RiskWarned  RiskState = "warned"
	RiskFlagged RiskState = "flagged"
)

// Finding is a single judgment emitted by a check about a single node.
//
// Extraction vs judgment (Decision D-03): adapters emit graph facts, checks
// emit Findings. A Finding is never produced by an adapter.
type Finding struct {
	CheckID      string    `json:"check_id"`
	Axis         Axis      `json:"axis"`
	Severity     Severity  `json:"severity"`
	GateClass    GateClass `json:"gate_class"`
	Confidence   float64   `json:"confidence"`              // 0..1
	RecencyDecay float64   `json:"recency_decay,omitempty"` // 0..1, weather axis only; 0 => treat as 1
	NodeID       string    `json:"node_id"`                 // canonical PURL of the subject
	Title        string    `json:"title"`
	Evidence     string    `json:"evidence,omitempty"`
	Remediation  string    `json:"remediation,omitempty"`
	// DepPath is the shortest dependency chain from a project root to the subject
	// node — [root, …, node] — so a deep transitive finding is traceable to why
	// it is present (OPU-12 D-3). Empty for a root or a node reachable by no
	// depends-on edge (e.g. an install-hook subject).
	DepPath []string `json:"dep_path,omitempty"`
}

// Score composes severity, confidence, and recency into a single ordering
// value (brief §5): score = severity_weight * confidence * recency_decay.
// This is the false-positive discipline in one line — a lone low-confidence
// signal scores low even at high severity.
func (f Finding) Score() float64 {
	decay := f.RecencyDecay
	if decay <= 0 {
		decay = 1
	}
	conf := f.Confidence
	if conf <= 0 {
		conf = 1
	}
	return f.Severity.weight() * conf * decay
}

// MarshalJSON emits the composed Score alongside its inputs.
//
// The PDF ranks and caps by Score, so a JSON consumer that could not see it had
// to reverse-engineer the ranking from severity, confidence and prose evidence
// to reproduce what the report did. The JSON is the uncapped record of
// authority; it must carry the ordering key it was ordered by.
func (f Finding) MarshalJSON() ([]byte, error) {
	type alias Finding // breaks the recursion into this method
	return json.Marshal(struct {
		alias
		Score float64 `json:"score"`
	}{alias(f), f.Score()})
}
