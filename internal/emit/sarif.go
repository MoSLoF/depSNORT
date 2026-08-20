package emit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// SARIF emits SARIF 2.1.0 — the format GitHub code scanning and most CI
// dashboards ingest. This is the CI-gate surface from Decision D-09.
type SARIF struct{}

// Name implements Emitter.
func (SARIF) Name() string { return "sarif" }

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

// sarifInvocation carries the run-level facts SARIF-only consumers (FN-01)
// need to distinguish a genuine all-clear from an incomplete scan: results
// being an empty array is not, by itself, evidence the tree was fully seen.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"` // "warning" | "note"
	Message sarifText `json:"message"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifText         `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifText         `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// sarifLevel maps gate-class and severity onto SARIF levels. Gate-class leads:
// an advisory finding is "note" no matter how severe it sounds, because it can
// never fail the run (Decision D-06) and a CI dashboard should reflect that.
func sarifLevel(f finding.Finding) string {
	switch f.GateClass {
	case finding.GateBlock:
		return "error"
	case finding.GateEligible:
		return "warning"
	default:
		return "note"
	}
}

// coverageNotifications translates coverage facts the JSON report already
// carries (res.Coverage, info.DataSources) into SARIF notifications, so a
// SARIF-only consumer can tell an incomplete scan from a genuine all-clear
// (FN-01) instead of reading zero results as "nothing found".
func coverageNotifications(cov graph.Coverage, sources []DataSourceCoverage) []sarifNotification {
	var notes []sarifNotification

	if cov.Incomplete() {
		notes = append(notes, sarifNotification{
			Level:   "warning",
			Message: sarifText{Text: "depSNORT: " + cov.IncompleteSummary()},
		})
	}

	// Flat resolution is a lockfile-format limitation, not a scan failure
	// (coverage.go's own Degraded doc comment) — stderr deliberately never
	// warns on this alone, so this stays a "note", never a "warning".
	if len(cov.FlatEcosystems) > 0 {
		notes = append(notes, sarifNotification{
			Level: "note",
			Message: sarifText{Text: fmt.Sprintf(
				"depSNORT: flat lockfile resolution for %s — the lockfile format "+
					"records no inter-package relationships, so depth is one layer by "+
					"format, not by fact.",
				strings.Join(cov.FlatEcosystems, ", "))},
		})
	}

	for _, s := range sources {
		if s.Error == "" && s.Stats.Gaps == 0 {
			continue
		}
		msg := fmt.Sprintf("depSNORT: data source %q degraded: %d gap(s)", s.Name, s.Stats.Gaps)
		if s.Error != "" {
			msg += fmt.Sprintf(" (%s)", s.Error)
		}
		notes = append(notes, sarifNotification{Level: "warning", Message: sarifText{Text: msg}})
	}

	return notes
}

// Emit implements Emitter.
func (SARIF) Emit(w io.Writer, g *graph.Graph, res verdict.Result, info RunInfo) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "depSNORT",
			Version:        Version,
			InformationURI: "https://ihbv.io",
		}},
		Results: []sarifResult{},
		Invocations: []sarifInvocation{{
			// No code path reaches Emit after a hard failure — cmdScan returns
			// exitInternal before ever calling an emitter — so this is always true.
			ExecutionSuccessful:        true,
			ToolExecutionNotifications: coverageNotifications(res.Coverage, info.DataSources),
		}},
	}

	seen := map[string]bool{}
	for _, r := range info.Rules {
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               r.ID,
			Name:             r.ID,
			ShortDescription: sarifText{Text: r.Description},
			Properties: map[string]string{
				"axis":            r.Axis,
				"defaultSeverity": r.Severity,
				"gateClass":       r.GateClass,
			},
		})
	}

	for _, f := range res.Findings {
		msg := f.Title
		if f.Evidence != "" {
			msg = fmt.Sprintf("%s — %s", f.Title, f.Evidence)
		}
		props := map[string]string{
			"gateClass":  string(f.GateClass),
			"axis":       string(f.Axis),
			"severity":   string(f.Severity),
			"confidence": fmt.Sprintf("%.2f", f.Confidence),
			"score":      fmt.Sprintf("%.3f", f.Score()),
		}
		if f.Remediation != "" {
			props["remediation"] = f.Remediation
		}
		// The root→node dependency chain answers "why is this package here?" for a
		// deep transitive finding (OPU-12 D-3).
		if len(f.DepPath) > 1 {
			props["dep_path"] = strings.Join(f.DepPath, " → ")
		}
		// When the finding's subject is a node whose version this tool presumed
		// rather than observed (D-44), say so as a property. A code-scanning
		// dashboard can then deprioritize it: the finding is real, but the
		// coordinate it is about may not be in any actual build — which is
		// exactly why verdict demoted it to advisory and it can never gate.
		if n := g.Get(f.NodeID); n != nil && n.VersionTruth() != graph.TruthObserved {
			props["versionTruth"] = n.VersionTruth()
			if n.Presumed() {
				props["presumedVersion"] = "true"
			}
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:  f.CheckID,
			Level:   sarifLevel(f),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogical{{
					FullyQualifiedName: f.NodeID,
					Kind:               "package",
				}},
			}},
			Properties: props,
		})
	}

	out := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
