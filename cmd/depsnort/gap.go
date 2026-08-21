package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem"
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
	"pom.xml":          "maven",
	"build.gradle":     "gradle",
	"build.gradle.kts": "gradle",
	"pnpm-lock.yaml":   "pnpm",
	"poetry.lock":      "pypi",
	"uv.lock":          "pypi",
	"Pipfile":          "pypi",
	// Paket's manifest. Its resolved paket.lock IS parsed (the nuget adapter
	// claims it), so only the lock-less dependencies manifest reaches here (OPU-17).
	"paket.dependencies": "nuget",

	// OPU-18. Dependency-bearing files whose EXTENSION is too general to add to
	// the ext tables without manufacturing false disclosures (the dedication rule
	// below), plus lockfiles whose suffix the .lock catch-all cannot reach. Matched
	// by exact name so only the real manifest fires — a bare Custom.props or an
	// arbitrary foo.exs stays silent.
	"gradle.lockfile":          "gradle",
	"bun.lockb":                "npm",       // binary lockfile, not text
	".terraform.lock.hcl":      "terraform", // .hcl is mostly config, so name-only
	"mix.exs":                  "elixir",    // .exs is any Elixir script
	"Directory.Packages.props": "nuget",     // Central Package Management; .props is any MSBuild fragment
	"pubspec.yaml":             "dart",
	"Podfile":                  "cocoapods",
	"Package.swift":            "swift",
	// go.work is deliberately omitted: it is a workspace aggregator whose local
	// `use` modules are each scanned on their own, so disclosing the workspace
	// file as an unread gap would be a spurious note on an already-covered repo —
	// the same dedication reasoning that keeps general extensions out of the tables.

	// OPU-18 Tier 3: these already disclosed via the .lock catch-all as "unknown";
	// naming them upgrades attribution to the specific tool. They are gaps, not
	// parsed, so they are deliberately NOT in adapterHandledLocks.
	"mix.lock":     "elixir",
	"Podfile.lock": "cocoapods",
	"pubspec.lock": "dart",
	"flake.lock":   "nix",
	"conan.lock":   "conan",
	"deno.lock":    "deno",
}

// gapManifestByExt matches DEDICATED per-project file extensions — a suffix that
// exists SOLELY to declare dependencies, so its every occurrence is a real
// dependency-bearing manifest whose name varies per project (Foo.csproj,
// mygem.gemspec). This is the guardrail (OPU-18): a general extension used for
// many non-dependency purposes (.exs, .props, .targets, .hcl, .yaml, .toml,
// .json) must NEVER be blanket-added here — it would manufacture false
// disclosures on unrelated files. Such ecosystems' real manifests go in the
// exact-name table above instead.
var gapManifestByExt = map[string]string{
	".csproj":  "nuget",
	".fsproj":  "nuget",
	".vbproj":  "nuget",
	".vcxproj": "nuget",     // C++ PackageReference (parallels .csproj)
	".gemspec": "rubygems",  // spec.add_dependency (gem libraries; pairs with OPU-16)
	".podspec": "cocoapods", // s.dependency
	".cabal":   "hackage",   // build-depends (Haskell)
	".nimble":  "nim",       // requires (Nim)
	".sbt":     "sbt",       // libraryDependencies (Scala)
}

// gapCatchAllExts is the last-ditch "hail-mary" tier: a file suffix that almost
// always names a dependency lockfile, for ecosystems depsnort has no specific
// recognizer for at all (Elixir mix.lock, CocoaPods Podfile.lock, Dart
// pubspec.lock, Nix flake.lock, …). It fires only AFTER the name and ext tables
// miss, so a lock a real adapter parses (Cargo.lock, composer.lock, yarn.lock,
// Gemfile.lock, paket.lock) never reaches it — those dirs are claimed. The
// ecosystem is reported as "unknown" because that is the honest truth: we know a
// lockfile is here, not which tool wrote it. Over-disclosure is deliberately
// safe here — a catch-all match only degrades coverage (a note, gated under the
// opt-in -fail-on-incomplete), never a false block — while the failure it closes
// is the dangerous one: a real dependency surface skipped in total silence.
var gapCatchAllExts = map[string]string{
	".lock": "unknown",
}

// adapterHandledLocks are lockfiles a real adapter's Detect claims (so the
// directory is scanned, never a gap). They end in ".lock", so without this the
// catch-all above would mislabel a handled Cargo.lock / yarn.lock as an unknown
// gap. In the live flow a claimed directory never reaches classifyGapManifest,
// but keeping the pure classifier honest guards the contract "true == depsnort
// does not read this" against any future caller.
var adapterHandledLocks = map[string]bool{
	"Cargo.lock":    true, // cargo
	"composer.lock": true, // composer
	"yarn.lock":     true, // npm
	"Gemfile.lock":  true, // gem
	"Pipfile.lock":  true, // pypi
	"paket.lock":    true, // nuget (OPU-17)
	"bun.lock":      true, // npm (text lockfile; parsed by parseBunLock)
}

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
	ext := strings.ToLower(filepath.Ext(name))
	if eco, ok := gapManifestByExt[ext]; ok {
		return eco, true
	}
	// Hail-mary: an unrecognized lockfile suffix, disclosed as an unknown-ecosystem
	// gap rather than skipped in silence (OPU-17 cross-cutting). Locks a real
	// adapter reads are excluded so a handled Cargo.lock is never mislabeled.
	if eco, ok := gapCatchAllExts[ext]; ok && !adapterHandledLocks[name] {
		return eco, true
	}
	return "", false
}

// discoverManifestGaps walks root (mirroring discoverProjects' descent rules)
// and returns a gap pseudo-project for every directory carrying a
// recognized-but-unresolved manifest that was NOT already claimed by a real
// adapter. There is no cap (OPU-20): a repo with 127 unresolved .csproj discloses
// all 127, never a silent "50 of 127". It shares skipWalkDir with the project
// walk so the two agree on what a scan reaches (build dirs descended, vendored
// copies pruned, no depth bound, cycle-guarded).
func discoverManifestGaps(root string, claimed map[string]bool, noBuildDirs bool) []discovered {
	rootClean := filepath.Clean(root)
	visited := map[dirIdentity]bool{}

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
		if skipWalkDir(path, rootClean, d, noBuildDirs, visited) {
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

// discoveryCoverageGaps returns disclosure tokens for dependency surfaces a
// NON-recursive (--no-recursive) scan leaves unscanned: projects in
// subdirectories a default full-send scan would reach. It is the false-clean
// class at the discovery layer — a real dependency surface, in scope, silently
// skipped by the shallow escape hatch.
//
// The old same-directory "dropped ecosystem" disclosure is gone (OPU-24): every
// ecosystem in a directory is now co-scanned (OPU-21), so there is nothing to
// drop and nothing to disclose. A "gap" now means exactly one thing — depSNORT
// recognizes a manifest but has no resolver for it — never "chose a different
// ecosystem" or "you forgot -recursive" on the default path. This is called only
// on the --no-recursive branch; a full-send (default) scan produces no discovery
// notes here at all.
func discoveryCoverageGaps(root string, scanned []discovered, reg *ecosystem.Registry, noBuildDirs bool) []string {
	scannedDirs := map[string]bool{}
	for _, p := range scanned {
		scannedDirs[filepath.Clean(p.Path)] = true
	}

	var tokens []string
	found, _ := discoverProjects(root, reg, noBuildDirs)
	for _, f := range found {
		if scannedDirs[filepath.Clean(f.Path)] {
			continue
		}
		tokens = append(tokens, "<additional-project: "+f.Adapter.Name()+" in "+dirLabel(root, f.Path)+" — re-run without --no-recursive>")
	}
	sort.Strings(tokens)
	return tokens
}

// dirLabel renders a project directory relative to the scan root for a readable,
// comma-free disclosure token (AttrUnresolved is comma-joined, re-split with no
// escaping).
func dirLabel(root, path string) string {
	if rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path)); err == nil && rel != "" && !strings.HasPrefix(rel, "..") {
		rel = strings.ReplaceAll(rel, ",", " ")
		if rel == "." {
			return "the scanned directory"
		}
		return "./" + rel
	}
	return strings.ReplaceAll(filepath.Base(path), ",", " ")
}

// noteAdapter discloses discovery-layer coverage notes (present-but-unscanned
// projects and dropped same-dir ecosystems, OPU-12) through the same synthetic-
// root channel gapAdapter uses, so they degrade coverage and gate under
// -fail-on-incomplete instead of passing in silence.
type noteAdapter struct {
	tokens []string
}

func (noteAdapter) Name() string       { return "unscanned" }
func (noteAdapter) Detect(string) bool { return false }

func (a noteAdapter) Resolve(path string) (*graph.Graph, error) {
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "coverage-note:" + gapProjectName(path), Ecosystem: "unknown",
		Name: gapProjectName(path), Version: "0.0.0", Depth: 0,
		Attr: map[string]string{
			graph.AttrUnresolved:      strings.Join(a.tokens, ","),
			graph.AttrUnresolvedCount: strconv.Itoa(len(a.tokens)),
		},
	})
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
