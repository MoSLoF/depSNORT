package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem"
)

// skipDirs are directories never descended into during workspace discovery.
//
// node_modules is the important one: it contains thousands of nested
// package.json files and its own lockfiles, so walking it would both take
// forever and resolve vendored copies as if they were first-class projects. The
// rest are the usual build/vendor/VCS noise.
var skipDirs = map[string]bool{
	"node_modules":     true,
	".git":             true,
	".hg":              true,
	".svn":             true,
	"vendor":           true,
	"venv":             true,
	".venv":            true,
	"site-packages":    true,
	"__pycache__":      true,
	"dist":             true,
	"build":            true,
	"target":           true,
	".tox":             true,
	".mypy_cache":      true,
	".next":            true,
	".cache":           true,
	"bower_components": true,
}

// maxWalkDepth bounds how deep discovery descends below the root. Workspaces
// nest a few levels; anything deeper is almost certainly vendored or generated.
const maxWalkDepth = 8

// discovered is one project found in a workspace.
type discovered struct {
	Path    string // directory containing the manifest
	Adapter ecosystem.Adapter
}

// discoverProjects walks root and returns every directory an adapter claims.
//
// A directory is offered to the adapters ONCE, so a repo carrying both a
// package-lock.json and a requirements.txt is claimed by whichever adapter
// matches first rather than being scanned twice. Unreadable subtrees are skipped
// rather than aborting the walk — a workspace usually contains at least one
// directory the current user cannot read, and that should not fail the scan.
//
// extraSkip adds operator-supplied directory names to the built-in skip set
// (the -exclude flag). This is how a caller gets a PRODUCTION-only scan of a tree
// that also carries test fixtures — for example `-exclude testdata` on depSNORT's
// own repo, whose adversarial corpus is meant to be found in a full-tree scan but
// not in a dependency audit of the shipped code (report §3.7 / §6).
func discoverProjects(root string, reg *ecosystem.Registry, extraSkip map[string]bool) ([]discovered, error) {
	rootClean := filepath.Clean(root)
	rootDepth := strings.Count(rootClean, string(os.PathSeparator))

	var out []discovered
	err := filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission denied or a vanished entry: skip it, keep walking.
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
			if skipDirs[name] || extraSkip[name] || strings.HasPrefix(name, ".") && name != "." {
				return fs.SkipDir
			}
		}
		if strings.Count(path, string(os.PathSeparator))-rootDepth > maxWalkDepth {
			return fs.SkipDir
		}
		if a, err := reg.Detect(path); err == nil {
			out = append(out, discovered{Path: path, Adapter: a})
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
