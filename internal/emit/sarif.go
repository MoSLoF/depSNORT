package emit

import (
	"encoding/json"
	"fmt"
	"io"

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
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
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

// Emit implements Emitter.
func (SARIF) Emit(w io.Writer, g *graph.Graph, res verdict.Result, info RunInfo) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "dependaSNORT",
			Version:        Version,
			InformationURI: "https://ihbv.io",
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
