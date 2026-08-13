package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"sort"
	"strings"
)

// CycloneDX 1.5 SBOM generation for depSNORT itself.
//
// A tool that audits other projects' dependency trees should be able to hand you
// its own, and the only honest source for that is the build itself. This reads
// runtime/debug.BuildInfo — the module graph the linker actually embedded — so
// the SBOM cannot drift from the binary the way a hand-maintained manifest
// would. It is also the machine-checkable form of the dogfood invariant (D-10):
// if a third-party dependency ever appears here, the zero-dependency claim is
// false and this file says so.
//
// Deliberately no timestamp and no random serial number: two builds of identical
// source produce byte-identical SBOMs, matching the report determinism rule
// (D-13). The serial number is a name-based UUIDv5 derived from the module path
// and version, so it is stable and still unique per release.

type cdxSBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

type cdxMetadata struct {
	Tools     cdxTools      `json:"tools"`
	Component cdxComponent  `json:"component"`
	Props     []cdxProperty `json:"properties,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	PURL       string        `json:"purl,omitempty"`
	Licenses   []cdxLicense  `json:"licenses,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxLicense struct {
	License cdxLicenseID `json:"license"`
}

type cdxLicenseID struct {
	ID string `json:"id"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// golangPURL renders a Go module coordinate as a package-url.
func golangPURL(path, ver string) string {
	if ver == "" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + ver
}

// stableSerial derives a name-based UUID (RFC 4122 v5) from the main module
// coordinate, so the serial is deterministic across rebuilds of the same source.
func stableSerial(name string) string {
	// A fixed namespace UUID for depSNORT SBOMs.
	ns := [16]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
		0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// buildSBOM assembles the CycloneDX document from embedded build info.
//
// releaseScope drops host-specific build settings (GOOS/GOARCH/GOAMD64). A
// release ships five platform binaries but only one can be executed to generate
// an SBOM, so attaching a linux/amd64-flavoured document to a darwin/arm64
// artifact would MISSTATE it (finding R-03). The dependency graph — the part an
// SBOM consumer actually needs — is identical across platforms because it is the
// same source tree, so the release-scoped document describes exactly that and
// says so, rather than implying a platform it did not inspect.
func buildSBOMScoped(bi *debug.BuildInfo, toolVersion string, releaseScope bool) cdxSBOM {
	mainPath := "ihbv.io/depsnort"
	if bi != nil && bi.Main.Path != "" {
		mainPath = bi.Main.Path
	}
	mainRef := golangPURL(mainPath, toolVersion)

	// Build settings (GOOS/GOARCH/VCS revision) describe WHICH artifact this is,
	// which is the part a consumer verifying provenance actually needs.
	var props []cdxProperty
	if releaseScope {
		// Say plainly what this document does and does not cover.
		props = append(props,
			cdxProperty{Name: "depsnort:sbom-scope", Value: "release (platform-neutral)"},
			cdxProperty{Name: "depsnort:applies-to", Value: "all release artifacts of this version"},
			cdxProperty{Name: "depsnort:note", Value: "host build settings omitted: the module graph is identical across target platforms"},
		)
	}
	if bi != nil {
		for _, s := range bi.Settings {
			switch s.Key {
			case "GOOS", "GOARCH", "GOARM", "GOAMD64":
				if releaseScope {
					continue // host-specific; would misstate the other four binaries
				}
				props = append(props, cdxProperty{Name: "go:" + s.Key, Value: s.Value})
			case "CGO_ENABLED", "vcs", "vcs.revision", "vcs.time", "vcs.modified", "-trimpath":
				// Platform-independent facts: the commit built and whether cgo
				// was on are true of every artifact in the release.
				props = append(props, cdxProperty{Name: "go:" + s.Key, Value: s.Value})
			}
		}
		if bi.GoVersion != "" {
			props = append(props, cdxProperty{Name: "go:version", Value: bi.GoVersion})
		}
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })

	main := cdxComponent{
		Type: "application", BOMRef: mainRef, Name: mainPath, Version: toolVersion,
		PURL:     mainRef,
		Licenses: []cdxLicense{{License: cdxLicenseID{ID: "MIT"}}},
	}

	// Every module the linker embedded, other than the main module.
	var comps []cdxComponent
	var refs []string
	if bi != nil {
		for _, d := range bi.Deps {
			if d == nil || d.Path == mainPath {
				continue
			}
			ver := d.Version
			if d.Replace != nil && d.Replace.Version != "" {
				ver = d.Replace.Version
			}
			ref := golangPURL(d.Path, ver)
			comps = append(comps, cdxComponent{
				Type: "library", BOMRef: ref, Name: d.Path, Version: ver, PURL: ref,
			})
			refs = append(refs, ref)
		}
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })
	sort.Strings(refs)
	if comps == nil {
		comps = []cdxComponent{} // render "[]" not "null": an empty SBOM is a claim
	}

	deps := []cdxDependency{{Ref: mainRef, DependsOn: refs}}
	if refs == nil {
		deps[0].DependsOn = []string{}
	}
	for _, r := range refs {
		deps = append(deps, cdxDependency{Ref: r, DependsOn: []string{}})
	}

	return cdxSBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: stableSerial(mainRef),
		Version:      1,
		Metadata: cdxMetadata{
			Tools:     cdxTools{Components: []cdxComponent{{Type: "application", BOMRef: mainRef, Name: "depsnort", Version: toolVersion}}},
			Component: main,
			Props:     props,
		},
		Components:   comps,
		Dependencies: deps,
	}
}

// buildSBOM assembles the host-scoped document (describes THIS binary).
func buildSBOM(bi *debug.BuildInfo, toolVersion string) cdxSBOM {
	return buildSBOMScoped(bi, toolVersion, false)
}

// emitSBOM writes the CycloneDX SBOM for this binary to w. When releaseScope is
// set, host-specific build settings are omitted so the document can honestly
// accompany every platform artifact of the release (R-03).
func emitSBOM(w io.Writer, releaseScope bool) error {
	bi, _ := debug.ReadBuildInfo()
	doc := buildSBOMScoped(bi, strings.TrimSpace(version), releaseScope)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
