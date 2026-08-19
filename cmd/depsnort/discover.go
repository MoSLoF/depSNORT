package main

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem"
)

// neverDescend are directories the workspace walk never enters. They hold
// installed/vendored COPIES of already-resolved dependencies (node_modules,
// vendor, venv, site-packages, bower_components), or VCS and tooling caches.
// Descending would re-resolve an already-captured tree as nested first-class
// projects — exploding counts — or scan generated junk. These stay pruned even
// under full-send (OPU-19).
var neverDescend = map[string]bool{
	"node_modules":     true,
	"vendor":           true,
	"venv":             true,
	".venv":            true,
	"site-packages":    true,
	"__pycache__":      true,
	"bower_components": true,
	".git":             true,
	".hg":              true,
	".svn":             true,
	".tox":             true,
	".mypy_cache":      true,
	".next":            true,
	".cache":           true,
}

// buildDirs are build-output directories the walk DESCENDS and resolves by
// default (OPU-19). dist/ is where the real-source pattern actually lives — a
// Docker build context copies a project's requirements.txt/go.mod there (tpotce),
// so pruning it dropped 100% of that coverage. Only dist/ is reliably real
// source: the DEPSNORT_FULLSEND probe showed target/ and build/ duplicate the
// packaged pom / cargo-package lock on any built tree, so those are opt-in below.
var buildDirs = map[string]bool{"dist": true}

// optInBuildDirs are added to the descend set only when includeBuildDirs is set
// (the -include-build-dirs flag), for the rare repo that intentionally keeps
// source manifests under target/ or build/. Off by default because on a built
// Maven or `cargo package`d tree they hold a generated copy of the root manifest,
// which would double-count or double-disclose.
var optInBuildDirs = map[string]bool{"target": true, "build": true}

// discovered is one project found in a workspace.
type discovered struct {
	Path    string // directory containing the manifest
	Adapter ecosystem.Adapter
}

// discoverProjects walks root and returns every (directory, ecosystem) an adapter
// claims — one entry PER ECOSYSTEM per directory (OPU-21): a directory carrying a
// yarn.lock and a Gemfile.lock yields both an npm and a gem project, not one.
// Each adapter still selects its own single manifest internally, so there is no
// intra-ecosystem double-count.
//
// The walk descends build-output dirs that hold real source (buildDirs, plus
// optInBuildDirs when includeBuildDirs is set) and prunes vendored/VCS/tooling
// copies (neverDescend). There is no depth bound (OPU-22): a deep monorepo is
// reached in full, protected from pathological directory cycles (bind mounts,
// loopback) by a visited real-directory-identity set rather than an arbitrary
// depth cap. filepath.WalkDir does not follow symlinks, so a symlink cycle is
// already impossible; the identity set covers the mount-based case.
//
// Unreadable subtrees are skipped rather than aborting the walk — a workspace
// usually contains at least one directory the current user cannot read, and that
// should not fail the scan.
func discoverProjects(root string, reg *ecosystem.Registry, includeBuildDirs bool) ([]discovered, error) {
	rootClean := filepath.Clean(root)
	visited := map[dirIdentity]bool{}

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
		if skipWalkDir(path, rootClean, d, includeBuildDirs, visited) {
			return fs.SkipDir
		}
		// Co-scan: one project root per ecosystem claiming this directory.
		for _, a := range reg.DetectAll(path) {
			out = append(out, discovered{Path: path, Adapter: a})
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Adapter.Name() < out[j].Adapter.Name()
	})
	return out, nil
}

// skipWalkDir decides whether the walk should prune a directory. Shared by the
// project walk and the gap walk (gap.go) so the two cannot disagree about what a
// scan reaches. It also records directory identity for cycle protection, so it
// mutates visited and must be called exactly once per directory.
func skipWalkDir(path, rootClean string, d fs.DirEntry, includeBuildDirs bool, visited map[dirIdentity]bool) bool {
	name := d.Name()
	if path != rootClean {
		switch {
		case neverDescend[name]:
			// Vendored/VCS/tooling copies: never entered.
			return true
		case optInBuildDirs[name] && !includeBuildDirs:
			// target/ and build/ hold a generated copy of the root manifest on
			// built trees, so they are pruned unless -include-build-dirs asks for them.
			return true
		default:
			// Hidden dirs are pruned unless they are a build dir we will descend
			// (dist/ always; target/build/ under the opt-in).
			descendBuild := buildDirs[name] || (includeBuildDirs && optInBuildDirs[name])
			if strings.HasPrefix(name, ".") && name != "." && !descendBuild {
				return true
			}
		}
	}
	// Cycle guard (OPU-22): if this directory's real identity was already seen,
	// a mount loop has folded the tree back on itself — stop rather than recurse
	// forever. Best-effort: platforms without a stable identity fall back to no
	// guard (WalkDir still never follows symlinks, so this only matters for the
	// exotic bind-mount case on Unix).
	if id, ok := dirIdentityOf(d); ok {
		if visited[id] {
			return true
		}
		visited[id] = true
	}
	return false
}
