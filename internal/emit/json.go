package emit

import (
	"encoding/json"
	"io"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// JSON is the machine-readable emitter. Output is deterministic: nodes are
// emitted in ID-sorted order so a CI gate is reproducible (Decision D-09).
type JSON struct{}

// Name implements Emitter.
func (JSON) Name() string { return "json" }

type jsonNode struct {
	ID        string            `json:"id"`
	Kind      graph.NodeKind    `json:"kind"`
	Ecosystem string            `json:"ecosystem"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Direct    bool              `json:"direct"`
	Depth     int               `json:"depth"`
	Risk      string            `json:"risk"`
	Attr      map[string]string `json:"attr,omitempty"`
}

type jsonReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Summary struct {
		Nodes int      `json:"nodes"`
		Edges int      `json:"edges"`
		Roots []string `json:"roots"`
		// Orphans counts packages reachable from no root — a resolver gap, not a
		// security finding. Non-zero means a relation type is unparsed (D-18).
		Orphans int `json:"orphans"`
	} `json:"summary"`
	DataSources []DataSourceCoverage `json:"data_sources,omitempty"`
	Nodes       []jsonNode           `json:"nodes"`
	Edges       []graph.Edge         `json:"edges"`
	Verdict     verdict.Result       `json:"verdict"`
}

// Emit implements Emitter.
func (JSON) Emit(w io.Writer, g *graph.Graph, res verdict.Result, info RunInfo) error {
	var rep jsonReport
	rep.Tool = "dependaSNORT"
	rep.Version = Version
	rep.Summary.Nodes = g.Len()
	rep.Summary.Edges = len(g.Edges)
	rep.Summary.Roots = g.Roots
	rep.Summary.Orphans = len(g.Orphans())
	rep.DataSources = info.DataSources

	for _, n := range g.SortedNodes() {
		rep.Nodes = append(rep.Nodes, jsonNode{
			ID: n.ID, Kind: n.Kind, Ecosystem: n.Ecosystem, Name: n.Name,
			Version: n.Version, Direct: n.Direct, Depth: n.Depth,
			Risk: string(n.Risk), Attr: n.Attr,
		})
	}
	rep.Edges = g.SortedEdges()
	rep.Verdict = res

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// Version is stamped into emitted reports. Kept here so emit has no dependency
// on cmd. main sets it at startup.
var Version = "0.0.0-dev"
