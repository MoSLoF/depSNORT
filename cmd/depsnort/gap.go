package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ihbv.io/depsnort/internal/graph"
)

// A dependency manifest depsnort RECOGNIZES but cannot resolve to dependencies —
// an unsupported ecosystem (Maven, Gradle), or a supported one in an input shape
// the adapter does not read (a bare .csproj with no packages.lock.json; a
// Pipfile with no Pipfile.lock; a poetry.lock with no pyproject.toml). Its
// PRESENCE is the signal: a directory carrying one is a real dependency-bearing
// project, so reading it as "nothing to scan" at exit 0 is a silent false-clean
// — a green checkmark that means "did not look", not "found nothing" (D-59).
// The malice a supply-chain scanner exists to catch is rarely spelled out at the
// front door; a manifest it cannot read is exactly where it must say so.
//
// Supported manifests are deliberately absent from these tables: a directory
// carrying one is CLAIMED by an adapter's Detect and never reaches this path, so
// listing them here would only risk firing on a legitimately dependency-less one.
var gapManifestByName = map[string]string{
	"packages.config":  "nuget",
	"pom.xml":          "maven",
	"build.gradle":     "gradle",
	"build.gradle.kts": "gradle",
	"pnpm-lock.yaml":   "pnpm",
	"poetry.lock":      "pypi",
	"uv.lock":          "pypi",
	"Pipfile":          "pypi",
	"Gemfile":          "rubygems",
}

// gapManifestByExt covers the NuGet project files, which carry the project's
// name and so vary per project (Foo.csproj), matched by extension.
var gapManifestByExt = map[string]string{
	".csproj": "nuget",
	".fsproj": "nuget",
	".vbproj": "nuget",
}

// maxGapProjects bounds how many unread-manifest directories a recursive sweep
// discloses, so a large polyglot monorepo does not turn the report into a wall
// of gap entries. The cap itself is disclosed when hit.
const maxGapProjects = 50

// unreadManifest names one recognized-but-unresolved manifest and the ecosystem
// it belongs to.
type unreadManifest struct {
	File      string
	Ecosystem string
}

// recognizedGapManifests returns the recognized-but-unresolved dependency
// manifests directly inside path (not recursive). path may be a directory or a
// single manifest file pointed at directly.
func recognizedGapManifests(path string) []unreadManifest {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		if eco, ok := classifyGapManifest(filepath.Base(path)); ok {
			return []unreadManifest{{File: filepath.Base(path), Ecosystem: eco}}
		}
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var out []unreadManifest
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if eco, ok := classifyGapManifest(e.Name()); ok {
			out = append(out, unreadManifest{File: e.Name(), Ecosystem: eco})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func classifyGapManifest(name string) (string, bool) {
	if eco, ok := gapManifestByName[name]; ok {
		return eco, true
	}
	if eco, ok := gapManifestByExt[strings.ToLower(filepath.Ext(name))]; ok {
		return eco, true
	}
	return "", false
}

// discoverManifestGaps walks root (like discoverProjects) and returns a gap
// pseudo-project for every directory carrying a recognized-but-unresolved
// manifest that was NOT already claimed by a real adapter. Bounded by
// maxGapProjects.
func discoverManifestGaps(root string, claimed map[string]bool) []discovered {
	rootClean := filepath.Clean(root)
	rootDepth := strings.Count(rootClean, string(os.PathSeparator))

	var out []discovered
	_ = filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != rootClean {
			if skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".") {
				return fs.SkipDir
			}
		}
		if strings.Count(path, string(os.PathSeparator))-rootDepth > maxWalkDepth {
			return fs.SkipDir
		}
		if len(out) >= maxGapProjects {
			return fs.SkipDir
		}
		if claimed[filepath.Clean(path)] {
			return nil
		}
		if gaps := recognizedGapManifests(path); len(gaps) > 0 {
			out = append(out, discovered{Path: path, Adapter: gapAdapter{gaps}})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// gapAdapter is a synthetic ecosystem.Adapter for a directory whose recognized
// dependency manifest depsnort cannot resolve. Its Resolve emits a single root
// that DISCLOSES the unread manifest through the ordinary coverage channel
// (AttrUnresolved), so the scan degrades coverage — and gates under
// -fail-on-incomplete — instead of exiting clean in silence. It is never
// registered with the adapter registry; it is injected directly by the scan flow
// when normal detection finds nothing.
type gapAdapter struct {
	manifests []unreadManifest
}

func (gapAdapter) Name() string       { return "unscanned" }
func (gapAdapter) Detect(string) bool { return false }

func (a gapAdapter) Resolve(path string) (*graph.Graph, error) {
	g := graph.New()
	tokens := make([]string, 0, len(a.manifests))
	ecos := map[string]bool{}
	for _, m := range a.manifests {
		// Comma-free by construction (filenames and ecosystem labels carry none):
		// AttrUnresolved is comma-joined and re-split with no escaping.
		tokens = append(tokens, "<unread-manifest: "+m.File+" ("+m.Ecosystem+")>")
		ecos[m.Ecosystem] = true
	}
	ecoList := make([]string, 0, len(ecos))
	for e := range ecos {
		ecoList = append(ecoList, e)
	}
	sort.Strings(ecoList)

	name := gapProjectName(path)
	root := g.AddNode(&graph.Node{
		ID: "unscanned:" + name, Ecosystem: "unknown", Name: name, Version: "0.0.0", Depth: 0,
		Attr: map[string]string{
			graph.AttrUnresolved:      strings.Join(tokens, ","),
			graph.AttrUnresolvedCount: strconv.Itoa(len(tokens)),
			"depsnort.unscanned":      strings.Join(ecoList, ","),
		},
	})
	// A scan target is a local checkout; mark it path-origin so provenance
	// coverage does not additionally charge this synthetic root as unverifiable.
	root.SetSource(graph.SourcePath, "")
	g.MarkRoot(root.ID)
	return g, nil
}

func gapProjectName(path string) string {
	clean := filepath.Clean(path)
	if info, err := os.Stat(clean); err == nil && !info.IsDir() {
		clean = filepath.Dir(clean)
	}
	name := filepath.Base(clean)
	if name == "." || name == "" || name == string(filepath.Separator) {
		return "project"
	}
	return name
}
