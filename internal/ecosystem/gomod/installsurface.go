package gomod

import (
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/securefs"
)

// maxGoFiles bounds how many .go files the install-surface walk reads from one
// module. Go has no depth cap (OPU-22), but a file-count ceiling keeps a
// pathologically large or generated tree from dominating a scan. A real module is
// far under this; hitting it is disclosed as a gap, not a silent truncation.
const maxGoFiles = 5000

// ExtractInstallSurface implements ecosystem.InstallSurfaceExtractor (Decision
// D-26) for Go modules (OPU-28).
//
// Go runs no package code at `go get` or `go build` by design, so it has no
// install/postinstall analog. Its closest build-surface execution point is the
// `//go:generate` directive — an arbitrary command a developer triggers with
// `go generate` — which installsurface.AnalyzeGo classifies. Increment 1 scans
// the ROOT module's own .go files (the clone-and-assess-a-module workflow) and
// attributes any capability-bearing directive to the root gomod node.
// Per-dependency (vendor / module-cache) attribution, cgo `#cgo` flag injection,
// and build-tag-gated init evasion are later increments.
//
// Everything is read STATICALLY through securefs (containment + size caps) —
// nothing is executed (Decision D-04).
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)
	reader, err := securefs.NewReader(dir)
	if err != nil {
		return err
	}
	var gaps instsurf.Gaps

	sources := collectGoSources(reader, &gaps)
	if len(sources) == 0 {
		return gaps.Err()
	}

	surface := installsurface.AnalyzeGo(sources)
	if len(surface.Hooks) == 0 {
		return gaps.Err()
	}

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "gomod" || !roots[n.ID] {
			continue
		}
		instsurf.AddToGraph(g, n, surface)
	}
	return gaps.Err()
}

// collectGoSources walks the module directory and returns every readable, non-test
// .go file's contents keyed by its module-relative path. It descends real
// subdirectories only (an os.DirEntry symlink reports IsDir()==false, so symlinked
// directories are not followed — no traversal cycle), skipping the dirs Go itself
// ignores for a build (vendor/, testdata/, and names beginning with '.' or '_').
// Unreadable files and directories are recorded as gaps rather than aborting.
func collectGoSources(reader *securefs.Reader, gaps *instsurf.Gaps) map[string]string {
	sources := map[string]string{}
	count := 0

	var walk func(rel string)
	walk = func(rel string) {
		if count >= maxGoFiles {
			return
		}
		entries, err := reader.ReadDir(rel)
		if err != nil {
			gaps.Add("", rel, err)
			return
		}
		for _, e := range entries {
			if count >= maxGoFiles {
				return
			}
			name := e.Name()
			child := filepath.Join(rel, name)
			if e.IsDir() {
				if skipGoDir(name) {
					continue
				}
				walk(child)
				continue
			}
			if !strings.HasSuffix(name, ".go") {
				continue
			}
			count++
			b, err := reader.ReadFile(child)
			if err != nil {
				gaps.Add("", child, err)
				continue
			}
			sources[child] = string(b)
		}
	}
	walk(".")
	return sources
}

// skipGoDir reports whether a directory is one Go excludes from a build and the
// install-surface walk therefore skips: vendored dependency copies (a later
// increment attributes those to their own dependency nodes), test fixtures, and
// the '.'/'_'-prefixed directories the go tool ignores.
func skipGoDir(name string) bool {
	switch name {
	case "vendor", "testdata":
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}
