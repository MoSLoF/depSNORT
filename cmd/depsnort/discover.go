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

// buildDirs are build-output directory names the walk DESCENDS and resolves by
// default. dist/ is a Docker build context that copies a project's real
// requirements.txt/go.mod (tpotce). build/ and target/ hold real dependency-
// bearing source too — Titanis keeps four .NET projects under src/build/… — so
// they descend by default as well (OPU-25), with the generated-artifact copies
// beneath them pruned path-contextually (buildArtifactDirs). The earlier concern
// that target/ and build/ only ever hold generated duplicates was too broad; the
// duplication lives in specific tool-output SUBdirs, not the whole tree.
var buildDirs = map[string]bool{"dist": true, "build": true, "target": true}

// optionalBuildDirs are the build dirs -no-build-dirs suppresses (build/ and
// target/, for the rare user scanning a fully-built tree where the artifact
// subdirs are not worth even a duplicate disclosure). dist/ is never suppressed —
// it never carried the artifact-copy problem.
var optionalBuildDirs = map[string]bool{"build": true, "target": true}

// artifactContextDirs are the build roots whose SUBtrees hold generated artifact
// copies. dist/ is deliberately excluded (its contents are real source, not
// compiler output), so buildArtifactDirs pruning applies only under build/target.
var artifactContextDirs = map[string]bool{"build": true, "target": true}

// buildArtifactDirs are compiler/packaging output directory names that appear
// UNDER a build/ or target/ root. Manifests inside them are generated copies
// (Maven's packaged pom under target/classes/META-INF/maven, cargo's
// target/package lock, Gradle's build/generated poms), never a distinct project's
// source. They are pruned ONLY within a build/target subtree (insideBuildTree),
// so a real source directory that happens to share one of these names elsewhere —
// a Python package/, a resources/ source root — is untouched. The list is curated,
// not exhaustive: an unlisted output subdir leaks a DUPLICATE disclosure (a
// harmless note), which is the safe direction — over-exposing a generated copy is
// cosmetic, under-exposing real source hides actual dependencies (OPU-25).
var buildArtifactDirs = map[string]bool{
	// Maven / JVM
	"classes": true, "test-classes": true, "generated-sources": true,
	"generated-test-sources": true, "maven-status": true, "maven-archiver": true,
	// Rust / Cargo
	"package": true, "debug": true, "release": true, "deps": true,
	"incremental": true, ".fingerprint": true, "doc": true,
	// Gradle / generic
	"generated": true, "intermediates": true, "libs": true, "tmp": true,
	"resources": true, "reports": true, "publications": true, "classes-java": true,
}

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
// The walk descends build-output dirs that hold real source (buildDirs: dist/,
// build/, target/ — unless -no-build-dirs suppresses build/target), pruning the
// generated-artifact SUBdirs beneath them (buildArtifactDirs, path-contextual)
// and vendored/VCS/tooling copies (neverDescend). There is no depth bound (OPU-22): a deep monorepo is
// reached in full, protected from pathological directory cycles (bind mounts,
// loopback) by a visited real-directory-identity set rather than an arbitrary
// depth cap. filepath.WalkDir does not follow symlinks, so a symlink cycle is
// already impossible; the identity set covers the mount-based case.
//
// Unreadable subtrees are skipped rather than aborting the walk — a workspace
// usually contains at least one directory the current user cannot read, and that
// should not fail the scan.
func discoverProjects(root string, reg *ecosystem.Registry, noBuildDirs bool) ([]discovered, error) {
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
		if skipWalkDir(path, rootClean, d, noBuildDirs, visited) {
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
func skipWalkDir(path, rootClean string, d fs.DirEntry, noBuildDirs bool, visited map[dirIdentity]bool) bool {
	name := d.Name()
	if path != rootClean {
		switch {
		case neverDescend[name]:
			// Vendored/VCS/tooling copies: never entered.
			return true
		case noBuildDirs && optionalBuildDirs[name]:
			// -no-build-dirs: skip build/ and target/ entirely (dist/ still descends).
			return true
		case buildArtifactDirs[name] && insideBuildTree(path, rootClean):
			// A compiler/packaging output subdir inside a build/target tree holds
			// generated copies of manifests already resolved elsewhere, not a
			// distinct project. Pruned path-contextually (OPU-25), so a real source
			// dir of the same name OUTSIDE a build tree is untouched.
			return true
		default:
			// Hidden dirs are pruned unless they are a build dir we will descend.
			if strings.HasPrefix(name, ".") && name != "." && !buildDirs[name] {
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

// insideBuildTree reports whether path sits under a build/ or target/ directory
// within the scanned tree — i.e. whether an ANCESTOR (not path itself) is a build
// artifact context. Used to make buildArtifactDirs pruning path-contextual: a
// generated-output name is a real project's source unless it lives inside a build
// tree.
func insideBuildTree(path, rootClean string) bool {
	rel, err := filepath.Rel(rootClean, path)
	if err != nil {
		return false
	}
	segs := strings.Split(rel, string(filepath.Separator))
	// Ancestors only: exclude the current directory (the last segment).
	for _, s := range segs[:len(segs)-1] {
		if artifactContextDirs[s] {
			return true
		}
	}
	return false
}
