// Package ioc loads an operator's indicator-of-compromise ledger — a local
// JSON feed the operator exports their own threat intelligence to — and matches
// resolved packages against it. This is the seam for VC-003 (Decision D-29):
// depsnort never reaches into a proprietary ledger's native format; the
// operator exports to this stable, documented schema and points -ioc at it.
//
// The feed is authoritative by construction: an entry here is the operator
// saying "I have confirmed this is bad." A match is therefore block-class, with
// full confidence — it is not a heuristic.
package ioc

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Indicator is one ledger entry. Matching is by the most specific identity
// present: an exact PURL wins, then ecosystem+name+version, then ecosystem+name
// (any version). An empty Ecosystem matches any ecosystem for that name.
type Indicator struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	PURL      string `json:"purl,omitempty"`
	Severity  string `json:"severity,omitempty"`  // critical | high | medium | low
	Category  string `json:"category,omitempty"`  // free text: malware, compromised-maintainer, ...
	Reference string `json:"reference,omitempty"` // operator's own ID, e.g. INC-2026-014
	Note      string `json:"note,omitempty"`
}

// Feed is a parsed IOC ledger with lookup indexes.
type Feed struct {
	Version    int         `json:"version"`
	Source     string      `json:"source,omitempty"`
	Generated  string      `json:"generated,omitempty"`
	Indicators []Indicator `json:"indicators"`

	byPURL map[string]*Indicator
	byNV   map[string]*Indicator // ecosystem/name@version
	byName map[string]*Indicator // ecosystem/name (any version)
}

// Load reads and indexes an IOC feed file.
func Load(path string) (*Feed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ioc: %w", err)
	}
	var f Feed
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("ioc: parsing %s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("ioc: unsupported feed version %d (want 1)", f.Version)
	}
	f.index()
	return &f, nil
}

func (f *Feed) index() {
	f.byPURL = map[string]*Indicator{}
	f.byNV = map[string]*Indicator{}
	f.byName = map[string]*Indicator{}
	for i := range f.Indicators {
		ind := &f.Indicators[i]
		if p := strings.TrimSpace(ind.PURL); p != "" {
			f.byPURL[p] = ind
		}
		if ind.Name == "" {
			continue
		}
		eco := strings.ToLower(ind.Ecosystem)
		name := strings.ToLower(ind.Name)
		if ind.Version != "" {
			f.byNV[eco+"/"+name+"@"+ind.Version] = ind
		} else {
			f.byName[eco+"/"+name] = ind
		}
	}
}

// Len reports the number of indicators loaded.
func (f *Feed) Len() int {
	if f == nil {
		return 0
	}
	return len(f.Indicators)
}

// Match returns the most specific indicator for a package, or nil. purl is the
// canonical PURL (the node ID); ecosystem/name/version are the resolved fields.
func (f *Feed) Match(purl, ecosystem, name, version string) *Indicator {
	if f == nil {
		return nil
	}
	if purl != "" {
		if ind := f.byPURL[purl]; ind != nil {
			return ind
		}
	}
	eco := strings.ToLower(ecosystem)
	nm := strings.ToLower(name)
	if ind := f.byNV[eco+"/"+nm+"@"+version]; ind != nil {
		return ind
	}
	// name-any-version, tried both with the ecosystem and ecosystem-agnostic.
	if ind := f.byName[eco+"/"+nm]; ind != nil {
		return ind
	}
	if ind := f.byName["/"+nm]; ind != nil {
		return ind
	}
	return nil
}
