// Package emit renders an analyzed graph to an output format. JSON is the v0
// emitter; SARIF, DOT, and Neo4j/Cypher are step 7 (Decision D-07: the graph is
// an output artifact, never a runtime dependency).
package emit

import (
	"io"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// DataSourceCoverage reports what a data source actually covered, so degraded
// coverage is visible rather than silently passing (brief §6, "no silent caps").
type DataSourceCoverage struct {
	Name  string           `json:"name"`
	Stats datasource.Stats `json:"stats"`
	Error string           `json:"error,omitempty"`
	// Note is a non-error coverage caveat surfaced into the report — e.g. a
	// transitive closure built on presumed versions because the asserted tier
	// was not consulted (OPU-12 D-2). It degrades the reader's confidence in the
	// result without being a failure.
	Note string `json:"note,omitempty"`
}

// RuleInfo describes a registered check, so emitters that need a rule catalog
// (SARIF) can publish one without importing the check registry.
type RuleInfo struct {
	ID          string `json:"id"`
	Axis        string `json:"axis"`
	Severity    string `json:"severity"`
	GateClass   string `json:"gate_class"`
	Description string `json:"description"`
}

// RunInfo carries scan-level metadata into the emitter.
type RunInfo struct {
	DataSources []DataSourceCoverage `json:"data_sources,omitempty"`
	Rules       []RuleInfo           `json:"-"`
}

// Emitter renders a result to w.
type Emitter interface {
	Name() string
	Emit(w io.Writer, g *graph.Graph, res verdict.Result, info RunInfo) error
}

// ByName returns the emitter for a format name, or nil if unknown.
func ByName(name string) Emitter {
	switch name {
	case "", "json":
		return JSON{}
	case "dot":
		return DOT{}
	case "cypher":
		return Cypher{}
	case "sarif":
		return SARIF{}
	case "pdf":
		return PDF{}
	default:
		return nil
	}
}

// Formats lists the supported emitter names.
func Formats() []string { return []string{"json", "dot", "cypher", "sarif", "pdf"} }
