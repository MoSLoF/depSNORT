// Command depsnort is the depSNORT CLI — the primitive that the CI gate and
// pre-commit hook are thin wrappers over (Decision D-09).
//
// Exit codes:
//
//	0   clean, or only advisory findings
//	1   a block-class finding (FLAG) was present
//	2   a gate-eligible finding was present AND --fail-on-eligible was set
//	3   resolution coverage was degraded AND --fail-on-incomplete was set,
//	    or zero projects were discovered AND --require-project was set
//	64  usage error
//	70  internal/operational error
//
// depSNORT is STATIC and never installs or executes a dependency
// (Decision D-04). `scan` reads lockfiles; it does not run npm.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"ihbv.io/depsnort/internal/baseline"
	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/check/builtin"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/depsdev"
	"ihbv.io/depsnort/internal/datasource/epss"
	"ihbv.io/depsnort/internal/datasource/goproxy"
	"ihbv.io/depsnort/internal/datasource/ioc"
	"ihbv.io/depsnort/internal/datasource/npmreg"
	"ihbv.io/depsnort/internal/datasource/osv"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/ecosystem"
	"ihbv.io/depsnort/internal/ecosystem/cargo"
	"ihbv.io/depsnort/internal/ecosystem/composer"
	"ihbv.io/depsnort/internal/ecosystem/gomod"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/ecosystem/npm"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
	"ihbv.io/depsnort/internal/emit"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/verdict"
)

// version is the tool version. The SINGLE SOURCE of the release version is
// pyproject.toml (finding F-06); `make build`, setup.py, and the release
// workflow all read it from there and inject it via -ldflags "-X main.version".
// This default is deliberately "dev" so an un-injected `go build` never claims a
// release number it may have drifted from — an unmarked source build reads as
// dev, which is the honest answer.
var version = "dev"

const (
	exitClean    = 0
	exitUsage    = 64
	exitInternal = 70
)

func main() {
	emit.Version = version
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, banner(os.Stdout))
		usage()
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "checks":
		return cmdChecks()
	case "baseline":
		return cmdBaseline(args[1:])
	case "banner":
		fmt.Fprint(os.Stdout, banner(os.Stdout))
		return 0
	case "sbom":
		// -release omits host-specific build settings so one document can
		// honestly describe every platform artifact of a release (R-03).
		releaseScope := false
		for _, a := range args[1:] {
			switch a {
			case "-release", "--release":
				releaseScope = true
			default:
				fmt.Fprintf(os.Stderr, "depsnort: sbom: unknown flag %q\n", a)
				return exitUsage
			}
		}
		if err := emitSBOM(os.Stdout, releaseScope); err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: sbom: %v\n", err)
			return exitInternal
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprint(os.Stdout, banner(os.Stdout))
		fmt.Println("depSNORT", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "depsnort: unknown command %q\n\n", args[0])
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `depSNORT — an IDS for the dependency supply chain (static, zero-execution)

usage:
  depsnort scan [flags] [path]     resolve and analyze a directory as a workspace:
                                   every project beneath it, every ecosystem, merged
                                   into one graph (default path "."; -no-recursive
                                   scans only the given directory)
  depsnort baseline create [path]  record a known-good profile per package, for
                                   later comparison with scan -baseline
  depsnort checks                  list the registered vector checks
  depsnort sbom [-release]         emit this binary's own CycloneDX SBOM
                                   (-release: platform-neutral, for release artifacts)
  depsnort version                 print version

scan flags:
  -format string           output format: json | dot | cypher | sarif | pdf (default "json")
  -fail-on-eligible        let gate-eligible warnings fail the run (exit 2)
  -real-roots string       comma-separated substrings naming the roots you
                           actually build/ship; findings no designated root can
                           reach are labeled CONTAINED with the reachability
                           proof attached — never hidden, never re-gated
  -fail-on-incomplete      let degraded resolution coverage fail the run (exit 3);
                           coverage is always REPORTED, this only makes it gate
  -require-project         let zero discovered projects fail the run (exit 3)
                           instead of the clean nothing-to-scan pass — for a CI
                           job pointed at a repo that must contain one
  -offline                 use only the local OSV cache; never touch the network
  -no-osv                  skip the OSV data-source layer entirely
  -osv-cache string        OSV advisory cache directory
  -no-registry             skip registry metadata (disables VC-004 / VC-005)
  -registry-cache string   registry metadata cache directory
  -expand                  discover transitive layers a manifest does not name,
                           past what the lockfile recorded (default true); the
                           versions it presumes are labelled and never gate
  -expand-depth int        stop expansion after N layers (0 = the default bound); set 1
                           to step through the tree one layer at a time
  -no-depsdev              expand transitive layers on PRESUMED (guessed) versions
                           only; by default the asserted tier consults deps.dev for
                           REAL resolved versions (also disabled by -offline).
                           Asserted versions still never gate; a presumed-only
                           closure is disclosed as such in the report
  -no-expand               alias for -expand=false: only what the files state
  -no-install-surface      skip static install-hook extraction (VC-002b..e)
  -epss                    enrich VC-008 findings with FIRST.org EPSS
                           exploit-prediction scores and rank them by peak score
                           (opt-in; needs network + OSV)
  -epss-gate float         escalate VC-008 findings with peak EPSS >= this
                           threshold (0..1) from advisory to gate-eligible;
                           combine with -fail-on-eligible to fail only on
                           vulnerabilities being exploited (implies -epss)
  -no-recursive            scan only the given directory, not its subdirectories
                           (default is full-send: every project beneath the path,
                           every ecosystem, every depth, build dirs included)
  -no-build-dirs           do not descend build/ or target/ (dist/ still is); by
                           default they ARE scanned, with their generated-artifact
                           subdirs (target/classes, target/package, …) pruned
  -internal-scopes string  comma-separated internal scopes (VC-007), e.g. @ihbv,@acme
  -internal-names string   comma-separated internal package names (VC-007)
  -ioc string              path to an IOC ledger feed (JSON); enables VC-003 —
                           a resolved package on the ledger blocks (exit 1)
  -baseline string         path to a known-good baseline file; enables the drift
                           axis (VC-010 capability drift, VC-011 publisher
                           lineage). Without it those checks do not fire.
  -o, -out string          output root: writes
                           <root>/YYYYMMDD/Report-<DTG>.<ext>
                           a path WITH an extension is used verbatim
                           (default: stdout)
  -local                   stamp report paths in local time instead of UTC

exit codes:
  0  clean / advisory-only   1  block (FLAG)   2  gate-eligible (if opted in)
  3  incomplete coverage (if opted in)
  64 usage error             70 internal error
`)
}

// maxGapDetails bounds how many individual extraction gaps are carried into the
// report. The COUNT is never capped — only the per-item detail list, so a tree
// with thousands of planted symlinks stays readable without understating what
// happened (R-01). Exceeding the cap is disclosed by summarizeReasons.
const maxGapDetails = 25

// hydrationCandidates picks the coordinates worth asking OSV's /v1/query about.
//
// D-146 restricted this to packages holding a non-CVE advisory id, because the
// only thing being fetched then was a CVE identity and a CVE-primary id already
// carries its own. D-147 also fetches SEVERITY, which querybatch never returns
// for ANY advisory, so that restriction no longer holds: a package whose
// advisories are all CVEs still has no severity until we ask.
//
// What still bounds the cost is that only a package with a real, non-malicious
// advisory is ever queried — malicious ones are VC-001's and never reach VC-008,
// and a clean package costs nothing. On a scan with no vulnerabilities this
// makes no requests at all.
func hydrationCandidates(g *graph.Graph, ctx *check.Context) []datasource.Coord {
	var out []datasource.Coord
	for _, n := range g.SortedNodes() {
		if n.Version == "" {
			continue
		}
		for _, a := range ctx.Advisories[n.ID] {
			if a.Malicious {
				continue
			}
			out = append(out, datasource.Coord{Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version})
			break
		}
	}
	return out
}

// advisoryCVEIDs returns an advisory's CVE identities: its own id when that is a
// CVE, plus any hydrated CVE aliases.
func advisoryCVEIDs(a datasource.Advisory) []string {
	var out []string
	if strings.HasPrefix(strings.ToUpper(a.ID), "CVE-") {
		out = append(out, strings.ToUpper(a.ID))
	}
	for _, al := range a.Aliases {
		if strings.HasPrefix(strings.ToUpper(al), "CVE-") {
			out = append(out, strings.ToUpper(al))
		}
	}
	return out
}

// summarizeReasons renders gap reason counts deterministically, e.g.
// ["containment-refusal x3", "file-too-large x1"].
func summarizeReasons(counts map[string]int) []string {
	if len(counts) == 0 {
		return nil
	}
	out := make([]string, 0, len(counts))
	for reason, n := range counts {
		out = append(out, fmt.Sprintf("%s x%d", reason, n))
	}
	sort.Strings(out) // determinism (D-13)
	return out
}

// checkRegistry returns the check registry. Separated from adapter construction
// so callers that only need checks (e.g. `depsnort checks`) can avoid scan config.
func checkRegistry() *check.Registry {
	// Single registration point, shared with the adversarial corpus so the two
	// can never drift apart (Decision D-37).
	return builtin.Default()
}

// adapterRegistry builds the ecosystem adapter registry with the given scan
// configuration. This is the single wiring point for adapters. An optional
// scanRoot bounds where a requirements.txt `-r`/`-c` include may be followed
// (D-54): the PyPI adapter reads an include only if it stays inside this root.
func adapterRegistry(offline bool, scanRoot ...string) *ecosystem.Registry {
	pypiCache := datasource.NewCache(defaultCacheDir("pypi-sdist"), 7*24*time.Hour)
	pypiAdapter := pypi.NewWithSdist(pypiCache, offline)
	if len(scanRoot) > 0 {
		pypiAdapter.ScanRoot = scanRoot[0]
	}
	return ecosystem.NewRegistry(
		npm.New(),
		pypiAdapter,
		rubygems.New(),
		cargo.New(),
		composer.New(),
		nuget.New(),
		gomod.New(),
	)
}

// registrySources returns a registry-metadata source for each ecosystem.
// Each gets its own cache subdirectory under cacheRoot.
func registrySources(cacheRoot string, offline bool) []datasource.RegistrySource {
	ttl := 24 * time.Hour
	return []datasource.RegistrySource{
		npmreg.New(datasource.NewCache(filepath.Join(cacheRoot, "npm"), ttl), offline),
		registry.NewPyPI(datasource.NewCache(filepath.Join(cacheRoot, "pypi"), ttl), offline),
		registry.NewGem(datasource.NewCache(filepath.Join(cacheRoot, "gem"), ttl), offline),
		registry.NewCargo(datasource.NewCache(filepath.Join(cacheRoot, "cargo"), ttl), offline),
		registry.NewComposer(datasource.NewCache(filepath.Join(cacheRoot, "composer"), ttl), offline),
		registry.NewNuGet(datasource.NewCache(filepath.Join(cacheRoot, "nuget"), ttl), offline),
		goproxy.New(datasource.NewCache(filepath.Join(cacheRoot, "goproxy-temporal"), ttl), offline),
	}
}

// formatExt maps an output format to its conventional file extension.
func formatExt(format string) string {
	switch format {
	case "dot":
		return ".dot"
	case "cypher":
		return ".cypher"
	case "sarif":
		return ".sarif"
	case "pdf":
		return ".pdf"
	default:
		return ".json"
	}
}

// sanitizeStamp strips anything that is not filename-safe from a DTG. Zones
// without a named abbreviation format as a numeric offset ("+0545"), which is
// legal on both Windows and POSIX but is normalized here so the stamp is always
// plain alphanumerics plus sign characters.
func sanitizeStamp(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9',
			r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r == '+', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// reportDTG formats the date-time group: YYYYMMDDHHMM followed by the timezone
// abbreviation, e.g. 202608071826UTC.
//
// UTC is the default deliberately. A local stamp alternates abbreviation across
// daylight saving (CDT/CST), which breaks lexical sorting of a report tree, and
// worse: on the fall-back night the same wall-clock hour occurs TWICE, so two
// genuinely different scans can produce an identical filename and one silently
// overwrites the other. UTC has neither problem. -local opts back in when a
// human-readable wall clock matters more than ordering.
func reportDTG(t time.Time) string {
	return sanitizeStamp(t.Format("200601021504MST"))
}

// reportRelPath is the iHBV report layout under an output root:
//
//	<YYYYMMDD>/Report-<DTG>.<ext>
//
// The date folder groups a day's scans; the DTG in the filename keeps each run
// distinct and self-describing if the file is moved out of its folder.
//
// The timestamp lives in the PATH, never in the file. Report content stays
// byte-reproducible (Decision D-13) while the layout still records when each
// scan ran, so a reports tree sorts chronologically and two scans of an
// unchanged tree still diff clean.
func reportRelPath(format string, t time.Time) string {
	return filepath.Join(t.Format("20060102"), "Report-"+reportDTG(t)+formatExt(format))
}

// resolveOutPath decides where output goes. An empty spec means stdout.
//
// A spec is treated as an output ROOT (the dated report tree is created beneath
// it) when it already is a directory, ends in a path separator, or — the case
// that matters in practice — carries no file extension. `-o ./reports` on a
// machine where ./reports does not exist yet obviously means "put reports in
// here"; an earlier exists-or-trailing-slash rule silently produced a file
// literally named `reports` instead. Anything with an extension is used verbatim
// as a filename, with no dated tree.
func resolveOutPath(spec, format string, local bool, now time.Time) (string, error) {
	if spec == "" {
		return "", nil
	}
	isDir := strings.HasSuffix(spec, "/") ||
		strings.HasSuffix(spec, string(os.PathSeparator)) ||
		filepath.Ext(spec) == ""
	if info, err := os.Stat(spec); err == nil {
		isDir = info.IsDir()
	}
	if !isDir {
		return spec, nil
	}
	if !local {
		now = now.UTC()
	}
	full := filepath.Join(spec, reportRelPath(format, now))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", fmt.Errorf("creating output directory: %w", err)
	}
	return full, nil
}

// splitCSV parses a comma-separated flag value into a trimmed, non-empty slice.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// defaultCacheDir returns the cache location under the user cache dir. sub
// separates data sources ("osv", "npmreg") so their keys can never collide.
func defaultCacheDir(sub string) string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return filepath.Join(os.TempDir(), "depsnort", sub)
	}
	return filepath.Join(base, "depsnort", sub)
}

// prefetchReleases fetches publish-time history for every distinct package name
// in the graph matching the source's ecosystem, and keys it by node ID for the
// temporal checks.
func prefetchReleases(g *graph.Graph, src datasource.RegistrySource) (map[string]*datasource.ReleaseHistory, error) {
	eco := src.Ecosystem()
	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	seen := map[string]bool{}
	var names []string
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || roots[n.ID] || n.Ecosystem != eco || n.Name == "" {
			continue
		}
		if !seen[n.Name] {
			seen[n.Name] = true
			names = append(names, n.Name)
		}
	}
	byNode := map[string]*datasource.ReleaseHistory{}
	if len(names) == 0 {
		return byNode, nil
	}
	byName, err := src.Histories(context.Background(), names)
	for _, n := range g.SortedNodes() {
		if h, ok := byName[n.Name]; ok && n.Kind == graph.KindPackage && !roots[n.ID] {
			byNode[n.ID] = h
		}
	}
	return byNode, err
}

// prefetchAdvisories collects coordinates for every non-root package node and
// queries the data-source layer once, returning advisories keyed by node ID.
// This is the pipeline's data-source stage — checks judge these facts, they do
// not fetch (Decision D-03).
// prefetchAdvisories also returns the queried coordinates paired with their
// results as exportable SnapshotEntry records — -osv-export writes these out
// so a later air-gapped scan can bootstrap from exactly what this run saw,
// without anyone hand-authoring snapshot JSON. Callers must only use entries
// when err is nil: on a batch failure results (and therefore entries) may be
// partial, and a partial snapshot silently masquerading as complete is worse
// than no snapshot at all.
func prefetchAdvisories(g *graph.Graph, src *osv.Client) (map[string][]datasource.Advisory, []datasource.SnapshotEntry, error) {
	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	var (
		coords []datasource.Coord
		ids    []string
	)
	for _, n := range g.SortedNodes() {
		if roots[n.ID] || n.Version == "" {
			continue
		}
		coords = append(coords, datasource.Coord{Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version})
		ids = append(ids, n.ID)
	}
	byNode := make(map[string][]datasource.Advisory, len(ids))
	if len(coords) == 0 {
		return byNode, nil, nil
	}
	results, err := src.QueryBatch(context.Background(), coords)
	entries := make([]datasource.SnapshotEntry, 0, len(coords))
	for i := range results {
		if i < len(ids) {
			byNode[ids[i]] = results[i]
		}
		if i < len(coords) {
			adv := results[i]
			if adv == nil {
				adv = []datasource.Advisory{}
			}
			entries = append(entries, datasource.SnapshotEntry{
				Ecosystem: coords[i].Ecosystem, Name: coords[i].Name, Version: coords[i].Version,
				Advisories: adv,
			})
		}
	}
	return byNode, entries, err
}

// enrichYankLure fetches the live-newest version's dependencies for cargo crates
// showing the yank-lure shape (pinned to a yanked version beneath a live newest
// atop a yanked run) and records, on the node, the BUILD dependencies that newest
// version introduces versus the pinned version — the arrayref tell (0.3.10 added
// proc-macro1 as a build dep). When a crate-source client is supplied (Increment 3),
// it also fetches each introduced build-dep's build.rs and records which are
// HOSTILE (network + exec/obfuscation — the compile-time payload). VC-012 reads
// the attributes to corroborate and escalate the shape (OPU-26). Only the flagged
// (rare) crates are fetched; the live-newest is not in the resolved graph, so this
// is a targeted enrichment, not a walk.
func enrichYankLure(g *graph.Graph, deps *registry.CargoDepsClient, src *registry.CrateSourceClient, sdist *pypi.SdistFetcher, releases map[string]*datasource.ReleaseHistory) emit.DataSourceCoverage {
	cov := emit.DataSourceCoverage{Name: "yanklure"}
	if len(releases) == 0 {
		return cov
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || (n.Ecosystem != "cargo" && n.Ecosystem != "pypi") {
			continue
		}
		h := releases[n.ID]
		if h == nil {
			continue
		}
		if yanked, known := h.IsYanked(n.Version); !known || !yanked {
			continue
		}
		newest, _, ok := h.YankLureShape()
		if !ok {
			continue
		}
		switch n.Ecosystem {
		case "cargo":
			enrichCargoYankLure(n, newest, deps, src, &cov)
		case "pypi":
			enrichPyPIYankLure(n, newest, sdist, &cov)
		}
	}
	if deps != nil {
		cov.Stats.Queried += deps.Stats.Queried
		cov.Stats.Gaps += deps.Stats.Gaps
	}
	if src != nil {
		cov.Stats.Queried += src.Stats.Queried
		cov.Stats.Gaps += src.Stats.Gaps
	}
	return cov
}

// enrichCargoYankLure records, on a flagged cargo crate, the BUILD dependencies its
// live-newest introduces vs the pinned version (Increment 2) and which of them ship
// a hostile build.rs (Increment 3).
func enrichCargoYankLure(n *graph.Node, newest string, deps *registry.CargoDepsClient, src *registry.CrateSourceClient, cov *emit.DataSourceCoverage) {
	if deps == nil {
		return
	}
	base := datasource.Coord{Ecosystem: "cargo", Name: n.Name, Version: n.Version}
	newC := datasource.Coord{Ecosystem: "cargo", Name: n.Name, Version: newest}
	reqs, err := deps.Requirements(context.Background(), []datasource.Coord{base, newC})
	if err != nil && cov.Error == "" {
		cov.Error = err.Error()
	}
	newestReqs := reqs[newC.Key()]
	introduced := registry.IntroducedBuildDeps(reqs[base.Key()], newestReqs)
	if len(introduced) == 0 {
		return
	}
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	n.Attr["yanklure.newest"] = newest
	n.Attr["yanklure.introduced_build_deps"] = strings.Join(introduced, ",")

	if src == nil {
		return
	}
	reqOf := map[string]string{}
	for _, r := range newestReqs {
		reqOf[r.Name] = r.Req
	}
	var hostile []string
	for _, dep := range introduced {
		buildRS, _, found, ferr := src.ResolveBuildRS(context.Background(), dep, reqOf[dep])
		if ferr != nil {
			if cov.Error == "" {
				cov.Error = ferr.Error()
			}
			continue
		}
		if found && hostileBuildRS(string(buildRS)) {
			hostile = append(hostile, dep)
		}
	}
	if len(hostile) > 0 {
		n.Attr["yanklure.hostile_build_deps"] = strings.Join(hostile, ",")
	}
}

// enrichCargoBuildRS fetches build.rs for cargo crates whose source was NOT on
// disk, and runs it through the same install-surface analysis a vendored crate
// gets — so the OPU-39 markers, and every other VC-002 check, see the same
// content either way.
//
// This exists because Cargo install-surface analysis is otherwise local-only
// (vendor/ or $CARGO_HOME/registry/src). On a cold CI clone that means no
// analysis at all, which is exactly the posture a gating scanner runs in and
// exactly when a live-but-not-yet-yanked compromise needs catching (D-139).
//
// Default-on since D-149 (opt out with -no-cargo-fetch-source). D-140 made this
// opt-in on the grounds that fetching would be "a substantial change to the
// tool's network posture" — a premise D-141 corrected: every ordinary online
// PyPI scan already fetches per-dependency source from a registry by default,
// and the owner's ruling is that coverage defaults on unless the action itself
// carries a risk worth weighing. This fetch is checksum-verified against the
// lockfile, executes nothing (D-04), and talks to a registry the scan's other
// default stages already talk to, so it adds no risk class. -offline still
// wins, via the client's own gate: a warm cache still serves, and a cold miss
// stays a source-unavailable gap.
//
// Only nodes the extraction actually reported as source-unavailable are
// fetched. Crates already read from vendor/ or CARGO_HOME are left alone: their
// on-disk content is what the build will use, and re-fetching could disagree
// with it.
// The returned set names the nodes whose install surface this pass DID resolve,
// so the caller can clear their stale source-unavailable gaps: reporting "not
// examined" for a crate that was examined is the same dishonesty as hiding a
// truncation, pointed the other way (D-138).
func enrichCargoBuildRS(g *graph.Graph, src *registry.CrateSourceClient, unavailable map[string]bool) (emit.DataSourceCoverage, map[string]bool) {
	cov := emit.DataSourceCoverage{Name: "cargo-source"}
	examined := map[string]bool{}
	if src == nil || len(unavailable) == 0 {
		return cov, examined
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "cargo" || !unavailable[n.ID] {
			continue
		}
		if n.Name == "" || n.Version == "" {
			continue
		}
		cov.Stats.Queried++
		// The EXACT locked version, not a requirement resolution: a lockfile may
		// pin a version yanked after the fact, and that pinned version is what
		// the build installs and runs.
		buildRS, found, err := src.BuildRSAt(context.Background(), n.Name, n.Version)
		if err != nil {
			cov.Stats.Gaps++
			if cov.Error == "" {
				cov.Error = err.Error()
			}
			continue
		}
		if !found {
			// The crate genuinely ships no build.rs. Nothing to analyze, and not
			// a gap — this is the answer, not a failure to get one, so the node
			// counts as examined.
			examined[n.ID] = true
			continue
		}
		examined[n.ID] = true
		surface := installsurface.AnalyzeRust(string(buildRS))
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
		if n.Attr == nil {
			n.Attr = map[string]string{}
		}
		n.Attr["cargo.build_rs_source"] = "fetched"
	}
	return cov, examined
}

// enrichPyPIYankLure records, on a flagged PyPI package, whether the live-newest's
// own setup.py is hostile at install time — the direct PyPI payload analogue of the
// cargo build.rs case (Increment 5). Unlike cargo, the payload is usually the
// package's OWN setup.py in the malicious release, not a new dependency, so this
// analyzes the newest version's setup.py directly.
func enrichPyPIYankLure(n *graph.Node, newest string, sdist *pypi.SdistFetcher, cov *emit.DataSourceCoverage) {
	if sdist == nil {
		return
	}
	cov.Stats.Queried++
	setupPy, found, err := sdist.SetupPySource(context.Background(), n.Name, newest)
	if err != nil {
		cov.Stats.Gaps++
		if cov.Error == "" {
			cov.Error = err.Error()
		}
		return
	}
	if !found || !hostileSetupPy(setupPy) {
		return
	}
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	n.Attr["yanklure.newest"] = newest
	n.Attr["yanklure.hostile_newest"] = newest
}

// hostileBuildRS reports whether a build.rs statically exhibits the compile-time
// payload shape: a download-and-run cradle, or network egress paired with decode-
// obfuscation or named-credential access. It reuses the capability analysis VC-002
// runs on install hooks (installsurface.AnalyzeRust), applied to the introduced
// build-dep's own source (OPU-26 Increment 3). Reading the script's TEXT is static
// analysis, not execution (D-04).
//
// CapExec is deliberately NOT a trigger: AnalyzeRust marks every build.rs CapExec
// because a build script executes by definition, so "network + exec" would flag a
// perfectly ordinary build that fetches a prebuilt binary and invokes a compiler.
// The signal is network paired with the things a legitimate build has no reason to
// do — decode a blob, read credentials — or a fetch-and-run cradle outright.
func hostileBuildRS(src string) bool {
	return hostileInstallCaps(installsurface.AnalyzeRust(src))
}

// hostileSetupPy is the PyPI analogue (Increment 5): the live-newest's own setup.py
// runs the install-time payload shape. Uses the same gate as hostileBuildRS.
func hostileSetupPy(src string) bool {
	return hostileInstallCaps(installsurface.AnalyzePython(src, "", nil))
}

// hostileInstallCaps applies the payload gate to an analyzed install surface (a
// build.rs or a setup.py): a download-and-run cradle, or network egress paired with
// decode-obfuscation or named-credential access. CapExec is excluded for the reason
// above — both AnalyzeRust and AnalyzePython mark an install hook CapExec ambiently.
func hostileInstallCaps(surface installsurface.Surface) bool {
	caps := map[installsurface.Capability]bool{}
	for _, h := range surface.Hooks {
		for _, c := range h.Caps {
			caps[c] = true
		}
	}
	if caps[installsurface.CapCradle] {
		return true
	}
	return caps[installsurface.CapNetwork] && (caps[installsurface.CapObfuscation] || caps[installsurface.CapCredentials])
}

// reconstructPyPIDepth targets only PyPI roots whose lockfile format left
// them fully flat (graph.AttrFlatResolution == "pypi"): it fetches
// requires_dist for the union of their pinned coordinates and calls
// pypi.ReconstructDepth to redraw real edges from it. Non-PyPI roots, and
// PyPI roots that already resolved real structure (e.g. a pip-compile
// requirements.txt with `# via` provenance), are left untouched — this
// never runs on data it would only duplicate or corrupt.
func reconstructPyPIDepth(g *graph.Graph, client *registry.PyPIDepsClient, roots []*graph.Node) emit.DataSourceCoverage {
	var flatRoots []*graph.Node
	for _, r := range roots {
		if r.Ecosystem == "pypi" && r.Attr[graph.AttrFlatResolution] == "pypi" {
			flatRoots = append(flatRoots, r)
		}
	}
	cov := emit.DataSourceCoverage{Name: client.Name()}
	if len(flatRoots) == 0 {
		return cov
	}

	seen := map[string]bool{}
	var coords []datasource.Coord
	for _, root := range flatRoots {
		for _, e := range g.SortedEdges() {
			if e.From != root.ID || e.Type != graph.EdgeDependsOn {
				continue
			}
			n := g.Get(e.To)
			if n == nil || n.Version == "" {
				continue
			}
			c := datasource.Coord{Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version}
			if key := c.Key(); !seen[key] {
				seen[key] = true
				coords = append(coords, c)
			}
		}
	}

	requiresDist, err := client.RequiresDist(context.Background(), coords)
	cov.Stats = client.Stats
	if err != nil {
		cov.Error = err.Error()
	}
	pypi.ReconstructDepth(g, flatRoots, requiresDist)
	return cov
}

// expandTransitive walks each root past what its lockfile recorded, discovering
// the layers a manifest does not name and presuming a published version at each
// (Decisions D-24 for coverage honesty, and the version-truth axis for the
// presumption grade). It is per-root by construction: a declaration in one
// project is never satisfied by another project's pinned version.
//
// depth is the -expand-depth cap. Zero is NOT "full depth" — it selects the
// engine's default bound (expand.defaultMaxDepth) — and this comment claimed
// otherwise, alongside a -expand-depth help string that told operators the same
// thing (D-143). The returned coverage folds every root's unread count into one
// data-source entry, so a walk bounded by the NETWORK degrades coverage exactly
// as the reconstruction stage does.
//
// A walk bounded by the CAP is disclosed too, and degrades only when the cap was
// not the operator's choice. D-24 exempted this bound from degrading on the
// stated grounds that it is "a limit the operator chose" — sound reasoning that
// simply does not hold for a default nobody selected, which is the case for
// every scan that does not pass the flag. Stepping a tree with an explicit
// -expand-depth=1 is still a deliberately partial walk and still returns clean.
func expandTransitive(g *graph.Graph, roots []*graph.Node, sources []expand.Declarer, resolver expand.Resolver, depth int) emit.DataSourceCoverage {
	cov := emit.DataSourceCoverage{Name: "expand"}
	walker := expand.NewWalker(sources...)
	// The resolver is handed to the walk itself: it asserts each root's
	// registry-queryable DIRECT dependencies once they have a coordinate, not the
	// un-queryable local project root (OPU-06). A resolved dependency's subtree is
	// merged as asserted and closed, so a presumed guess never overwrites it.
	opts := expand.Options{MaxDepth: depth, Resolver: resolver}

	var discovered, presumed, contested, unread, asserted, depthTruncated int
	for _, root := range roots {
		res, err := walker.ExpandRoot(context.Background(), g, root, opts)
		if err != nil && cov.Error == "" {
			cov.Error = err.Error()
		}
		discovered += res.Discovered
		presumed += res.Presumed
		contested += res.Contested
		unread += res.Unread
		asserted += res.Asserted
		depthTruncated += res.DepthTruncated
	}
	// Queried counts what we set out to learn; Gaps is the honest shortfall —
	// a coordinate whose metadata never came back is a layer we could not read,
	// which degrades coverage rather than passing as a complete walk (D-24).
	cov.Stats.Gaps = unread
	// The depth bound stopped the walk with packages still queued, so everything
	// beneath them is unread — the same shortfall an unfetched coordinate is,
	// arrived at by our own choice rather than the network's. Said out loud
	// either way; counted as a gap only when the choice was not the operator's.
	if depthTruncated > 0 {
		fmt.Fprintf(os.Stderr, "depsnort: WARNING - expansion stopped at the depth bound with %d package(s) still queued; everything below them is unexamined\n", depthTruncated)
		if depth <= 0 {
			cov.Stats.Gaps += depthTruncated
			cov.Note = joinNotes(cov.Note, depthBoundNote)
		}
	}
	if discovered > 0 || asserted > 0 {
		fmt.Fprintf(os.Stderr, "depsnort: expansion discovered %d transitive package(s) past the manifest (%d asserted, %d presumed, %d contested, %d unread)\n",
			discovered+asserted, asserted, presumed, contested, unread)
	}
	// Presumed-only disclosure (OPU-12 D-2): when the asserted tier resolved
	// NOTHING (asserted == 0) yet a transitive closure WAS discovered, state in the
	// report that the closure rests on presumed versions — this tool's guesses,
	// not resolved facts — so a clean result over it is not read as an
	// authoritative all-clear. Keying on asserted==0 rather than "resolver was
	// nil" is deliberate: it fires equally when the tier was not consulted
	// (-offline / -no-depsdev) AND when deps.dev was consulted but unreachable, so
	// a silently-failed asserted fetch cannot pass an entirely-presumed closure off
	// as fact. The per-node version-truth axis marks each node; this is the
	// run-level summary a reader needs.
	if asserted == 0 && discovered > 0 {
		// Appended, not assigned: a deep tree walked offline trips BOTH this and
		// the depth-bound note above, and assigning here would drop that one on
		// the floor in exactly the case where coverage is weakest.
		cov.Note = joinNotes(cov.Note, presumedClosureNote)
		fmt.Fprintln(os.Stderr, "depsnort: NOTE - "+presumedClosureNote)
	}
	cov.Stats.Queried = discovered + asserted
	return cov
}

// joinNotes concatenates coverage notes so a second one never erases the first.
func joinNotes(existing, add string) string {
	switch {
	case add == "":
		return existing
	case existing == "":
		return add
	default:
		return existing + "; " + add
	}
}

// depthBoundNote is the in-report statement attached to the expand data source
// when the walk hit the DEFAULT depth bound — one the operator never chose —
// leaving packages queued and their subtrees unread (D-143).
const depthBoundNote = "transitive expansion stopped at the default depth bound; " +
	"packages below it were never examined - raise -expand-depth to see further"

// presumedClosureNote is the in-report statement attached to the expand data
// source when the transitive closure was built entirely on presumed versions —
// whether because the asserted tier was not consulted (-offline / -no-depsdev) or
// because deps.dev was unreachable.
const presumedClosureNote = "transitive closure expanded on PRESUMED versions only — no version was resolved as fact (deps.dev asserted tier not consulted via -offline/-no-depsdev, or unreachable); these versions are this tool's guesses, so a clean result over this closure is not an authoritative all-clear"

// useAssertedTier reports whether a scan should consult the asserted tier:
// default on (OPU-12 D-2), suppressed by -no-depsdev, and impossible under
// -offline (no network), where the walk falls back to presumed versions.
func useAssertedTier(depsDev, noDepsDev, offline bool) bool {
	return depsDev && !noDepsDev && !offline
}

// assertedResolver routes asserted resolution by ecosystem (OPU-13 D-2). Go is
// resolved by a native goproxy MVS resolver because deps.dev's :dependencies
// endpoint 404s for every Go coordinate; every other supported ecosystem is
// resolved by deps.dev. Routing gomod away from deps.dev guarantees zero
// deps.dev traffic for Go coordinates.
type assertedResolver struct {
	depsDev expand.Resolver
	gomod   expand.Resolver
}

func (assertedResolver) Name() string { return "asserted" }

// NameFor attributes an asserted node to the backend that actually answered, so
// a Go node reads as go-proxy and a PyPI node as deps.dev (expand.EcosystemNamer).
func (a assertedResolver) NameFor(ecosystem string) string {
	if r := a.pick(ecosystem); r != nil {
		return r.Name()
	}
	return "asserted"
}

func (a assertedResolver) Resolve(ctx context.Context, ecosystem, name, version string) (expand.ResolvedGraph, bool, error) {
	if r := a.pick(ecosystem); r != nil {
		return r.Resolve(ctx, ecosystem, name, version)
	}
	return expand.ResolvedGraph{}, false, nil
}

// ResolveLocalRoot dispatches whole-build-list resolution of a LOCAL main module
// to the ecosystem's resolver when it supports it (gomod), so a `depsnort scan`
// of a local go.mod resolves Go's exact build list instead of the per-dependency
// union (expand.LocalRootResolver, OPU-15). Ecosystems whose resolver does not
// implement it return ok=false and the walker falls back to the per-dependency
// AssertRoot path.
func (a assertedResolver) ResolveLocalRoot(ctx context.Context, root expand.LocalRoot) (expand.ResolvedGraph, bool, error) {
	if r, ok := a.pick(root.Ecosystem).(expand.LocalRootResolver); ok {
		return r.ResolveLocalRoot(ctx, root)
	}
	return expand.ResolvedGraph{}, false, nil
}

func (a assertedResolver) pick(ecosystem string) expand.Resolver {
	if ecosystem == "gomod" {
		return a.gomod
	}
	return a.depsDev
}

// resolveResult is what one pass over a project list produced: the merged
// graph plus every way that pass fell short of seeing the whole tree.
type resolveResult struct {
	Graph         *graph.Graph
	Failures      int
	ExtractorGaps int
	GapReasons    map[string]int
	GapDetails    []string
	// SourceUnavailable holds the node IDs whose install surface could not be
	// examined because the package's source was not on disk. The cargo build.rs
	// fetch (default-on, D-149) uses it to know exactly which crates to fetch,
	// rather than re-fetching ones already scanned from vendor/ or CARGO_HOME.
	SourceUnavailable map[string]bool
}

// resolveProjects resolves each project and merges the results into a single
// multi-root graph. A package at the same version in two repos becomes ONE
// node, so shared dependencies collapse and a flagged package shows its blast
// radius across the workspace.
//
// Shared by `scan` and `baseline create` so the two cannot drift: a baseline
// must be built by exactly the pipeline that later scans compare against, or
// the first drift report would be an artifact of the tool disagreeing with
// itself about how to read a tree.
func resolveProjects(projects []discovered, extractSurface bool) resolveResult {
	out := resolveResult{Graph: graph.New(), GapReasons: map[string]int{}, SourceUnavailable: map[string]bool{}}
	for _, p := range projects {
		sub, err := p.Adapter.Resolve(p.Path)
		if err != nil {
			out.Failures++
			fmt.Fprintf(os.Stderr, "depsnort: warning: resolve %s (%s): %v\n", p.Path, p.Adapter.Name(), err)
			continue
		}

		// Install-surface extraction: statically read lifecycle hooks and the
		// files they reference, adding the install-time subgraph. Never executes
		// anything (Decision D-04). Adapters that do not implement it are skipped.
		if extractSurface {
			if ex, ok := p.Adapter.(ecosystem.InstallSurfaceExtractor); ok {
				if err := ex.ExtractInstallSurface(p.Path, sub); err != nil {
					// Typed gaps (R-01) carry one entry per unexamined file, so
					// count them individually and keep their reasons; anything
					// else is one opaque partial extraction.
					if gs := instsurf.GapsOf(err); len(gs) > 0 {
						out.ExtractorGaps += len(gs)
						for _, gp := range gs {
							out.GapReasons[string(gp.Reason)]++
							if gp.Reason == instsurf.GapUnavailable && gp.Package != "" {
								out.SourceUnavailable[gp.Package] = true
							}
							if len(out.GapDetails) < maxGapDetails {
								out.GapDetails = append(out.GapDetails, p.Path+": "+gp.String())
							}
						}
					} else {
						out.ExtractorGaps++
						out.GapReasons["extraction-error"]++
						if len(out.GapDetails) < maxGapDetails {
							out.GapDetails = append(out.GapDetails, p.Path+": "+err.Error())
						}
					}
					fmt.Fprintf(os.Stderr, "depsnort: warning: install surface not fully examined for %s: %v\n", p.Path, err)
				}
			}
		}
		out.Graph.Merge(sub)
	}
	return out
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "json", "output format: "+strings.Join(emit.Formats(), " | "))
	failEligible := fs.Bool("fail-on-eligible", false, "gate-eligible warnings fail the run (exit 2)")
	realRoots := fs.String("real-roots", "", "comma-separated substrings naming the roots you actually build/ship; findings no designated root can reach are labeled contained (with proof) — never hidden, never re-gated")
	failIncomplete := fs.Bool("fail-on-incomplete", false, "degraded resolution coverage fails the run (exit 3)")
	requireProject := fs.Bool("require-project", false, "zero discovered projects fails the run (exit 3) instead of the clean nothing-to-scan pass")
	offline := fs.Bool("offline", false, "use only the local OSV cache; never touch the network")
	noOSV := fs.Bool("no-osv", false, "skip the OSV data-source layer entirely")
	noCargoFetchSrc := fs.Bool("no-cargo-fetch-source", false, "skip fetching build.rs from crates.io for cargo dependencies whose source is not on disk (vendor/ or CARGO_HOME); the unexamined crates stay disclosed as source-unavailable (-offline also stops the fetch)")
	cacheDir := fs.String("osv-cache", defaultCacheDir("osv"), "OSV advisory cache directory")
	snapshotPath := fs.String("osv-snapshot", "", "path to a JSON advisory snapshot to import into the OSV cache before scanning (bootstraps -offline with zero network calls)")
	exportPath := fs.String("osv-export", "", "write this scan's OSV results to path as a JSON snapshot for later -osv-snapshot import; requires live network access (incompatible with -offline/-no-osv)")
	noBundled := fs.Bool("no-osv-bundled", false, "never use the compiled-in fallback advisory dataset, even when the network is unreachable")
	epssOn := fs.Bool("epss", false, "enrich VC-008 findings with FIRST.org EPSS exploit-prediction scores and order them by peak score (opt-in; needs network + OSV)")
	epssGate := fs.Float64("epss-gate", 0, "escalate VC-008 findings with peak EPSS >= this threshold (0..1) from advisory to gate-eligible; combine with -fail-on-eligible to fail on exploited vulnerabilities only (implies -epss)")
	regCacheDir := fs.String("registry-cache", defaultCacheDir("registry"), "registry metadata cache directory")
	noRegistry := fs.Bool("no-registry", false, "skip registry-metadata source (disables VC-004/VC-005)")
	expandTree := fs.Bool("expand", true, "discover transitive layers past what the lockfile recorded; presumed versions are labelled and never gate")
	noExpand := fs.Bool("no-expand", false, "alias for -expand=false")
	expandDepth := fs.Int("expand-depth", 0, "stop expansion after N layers (0 = the default bound, not unlimited); 1 steps one layer at a time")
	depsDev := fs.Bool("depsdev", true, "consult deps.dev for REAL resolved versions before presuming (the asserted tier; default on) — a supply-chain verdict should rest on resolved facts, not guesses; -offline or -no-depsdev falls back to presumed")
	noDepsDev := fs.Bool("no-depsdev", false, "do not consult deps.dev; expand transitive layers on presumed (guessed) versions only")
	noInstallSurface := fs.Bool("no-install-surface", false, "skip static install-hook extraction")
	recursive := fs.Bool("recursive", true, "walk the path as a workspace root: discover and merge every project beneath it (default; full-send)")
	shallow := fs.Bool("no-recursive", false, "scan only the given directory, not its subdirectories (still co-scans every ecosystem in it)")
	fs.BoolVar(shallow, "shallow", false, "alias for -no-recursive")
	noBuildDirs := fs.Bool("no-build-dirs", false, "do not descend build/ or target/ (dist/ is still descended); by default they are scanned, with their generated-artifact subdirs pruned")
	internalScopes := fs.String("internal-scopes", "", "comma-separated internal scopes for dependency-confusion (e.g. @ihbv,@acme)")
	internalNames := fs.String("internal-names", "", "comma-separated internal package names for dependency-confusion")
	iocPath := fs.String("ioc", "", "path to an IOC ledger feed (JSON); enables VC-003")
	baselinePath := fs.String("baseline", "", "path to a known-good baseline file (see `depsnort baseline create`); enables the drift axis (VC-010/VC-011)")
	var outSpec string
	fs.StringVar(&outSpec, "o", "", "output root: writes <root>/YYYYMMDD/Report-<DTG>.<ext>; a path with an extension is used verbatim (default: stdout)")
	fs.StringVar(&outSpec, "out", "", "alias for -o")
	localStamp := fs.Bool("local", false, "stamp report paths in local time instead of UTC")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *exportPath != "" && (*offline || *noOSV) {
		fmt.Fprintln(os.Stderr, "depsnort: -osv-export requires live network access; incompatible with -offline and -no-osv")
		return exitUsage
	}
	if *epssGate < 0 || *epssGate > 1 {
		fmt.Fprintln(os.Stderr, "depsnort: -epss-gate must be between 0 and 1")
		return exitUsage
	}
	// -epss-gate is meaningless without scores to compare, so it implies -epss.
	if *epssGate > 0 && !*epssOn {
		*epssOn = true
		fmt.Fprintln(os.Stderr, "depsnort: -epss-gate implies -epss; enabling EPSS enrichment")
	}
	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	emitter := emit.ByName(*format)
	if emitter == nil {
		fmt.Fprintf(os.Stderr, "depsnort: unknown format %q (have: %s)\n", *format, strings.Join(emit.Formats(), ", "))
		return exitUsage
	}

	adapters := adapterRegistry(*offline, path)
	checks := checkRegistry()

	// Build the list of projects to scan. A single path is one project; with
	// A path that does not exist is a USAGE error (a bad argument), distinct from
	// a path that exists but carries no supported manifest (nothing to scan,
	// exit clean). Separating them keeps a CI sweep's empty-but-valid repos from
	// looking like the operator's typo.
	pathInfo, statErr := os.Stat(path)
	if statErr != nil {
		fmt.Fprintf(os.Stderr, "depsnort: %v\n", statErr)
		return exitUsage
	}

	// Full-send by default (OPU-23): a DIRECTORY is a workspace root and every
	// project beneath it — every ecosystem, every depth, dist/ build dirs
	// included — is discovered and merged into one graph. --no-recursive/--shallow
	// restricts to the given directory, and a single manifest FILE pointed at
	// directly is always a single target (there is nothing beneath a file to walk).
	recurse := *recursive && !*shallow && pathInfo.IsDir()
	var projects []discovered
	if recurse {
		found, err := discoverProjects(path, adapters, *noBuildDirs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: discovery under %s: %v\n", path, err)
			return exitInternal
		}
		// Directories carrying a recognized manifest no adapter could resolve (a
		// bare .csproj, a pom.xml, a Pipfile) are disclosed as incomplete coverage
		// rather than skipped in silence (D-59).
		claimed := make(map[string]bool, len(found))
		for _, p := range found {
			claimed[filepath.Clean(p.Path)] = true
		}
		gaps := discoverManifestGaps(path, claimed, *noBuildDirs)
		if len(found) == 0 && len(gaps) == 0 {
			// Nothing to scan is not an internal error and not a risk finding —
			// a full-send sweep legitimately crosses repos with no supported
			// ecosystem (Go, C, a docs tree). Exit clean with a loud stderr
			// note, so a CI gate over many repos is not failed by an empty one.
			// -require-project inverts that default for a CI job pointed at a
			// repo that MUST contain one: there, a deleted or renamed manifest
			// would otherwise be indistinguishable from a clean pass (D-161).
			if *requireProject {
				fmt.Fprintf(os.Stderr, "depsnort: no supported projects found under %q and -require-project is set — zero coverage is not a clean pass\n", path)
				return verdict.ExitIncomplete
			}
			fmt.Fprintf(os.Stderr, "depsnort: no supported projects found under %q (nothing to scan)\n", path)
			return exitClean
		}
		projects = append(found, gaps...)
		fmt.Fprintf(os.Stderr, "depsnort: discovered %d project(s) under %s", len(found), path)
		if len(gaps) > 0 {
			fmt.Fprintf(os.Stderr, " (+%d with a recognized but unresolved manifest, disclosed as incomplete coverage)", len(gaps))
		}
		fmt.Fprintln(os.Stderr)
		// OPU-24: with every ecosystem co-scanned (OPU-21) and full depth reached,
		// a full-send scan has nothing to disclose at the discovery layer — no
		// dropped ecosystem, no unreached subtree. The only remaining gaps are the
		// structural ones already folded in above (recognizedGapManifests).
	} else {
		// --no-recursive: co-scan every ecosystem in this one directory (OPU-21),
		// but do not descend. A recognized-but-unresolvable manifest still discloses
		// as incomplete coverage rather than the silent "nothing to scan" pass (D-59).
		for _, a := range adapters.DetectAll(path) {
			projects = append(projects, discovered{Path: path, Adapter: a})
		}
		if len(projects) == 0 {
			if gaps := recognizedGapManifests(path); len(gaps) > 0 {
				fmt.Fprintf(os.Stderr, "depsnort: a recognized manifest at %s could not be resolved by any adapter; reporting as incomplete coverage, not a clean pass\n", path)
				projects = []discovered{{Path: path, Adapter: gapAdapter{gaps}}}
			}
		}

		// Disclose the projects in subdirectories this shallow scan did not reach,
		// so --no-recursive cannot pass green while a subtree project is omitted.
		notes := discoveryCoverageGaps(path, projects, adapters, *noBuildDirs)
		if len(projects) == 0 && len(notes) == 0 {
			// No supported manifest here and nothing below — genuinely nothing to
			// scan, not an internal error. Exit clean, unless the operator said
			// this path must contain a project (D-161, as above).
			if *requireProject {
				fmt.Fprintf(os.Stderr, "depsnort: no supported project at %q and -require-project is set — zero coverage is not a clean pass\n", path)
				return verdict.ExitIncomplete
			}
			fmt.Fprintf(os.Stderr, "depsnort: no supported project at %q (nothing to scan)\n", path)
			return exitClean
		}
		if len(notes) > 0 {
			projects = append(projects, discovered{Path: path, Adapter: noteAdapter{notes}})
			fmt.Fprintf(os.Stderr, "depsnort: %d subdirectory project(s) present but not scanned under --no-recursive; disclosed as incomplete coverage — drop --no-recursive to scan them\n", len(notes))
		}
	}

	pass := resolveProjects(projects, !*noInstallSurface)
	g := pass.Graph
	resolveFailures, extractorGaps := pass.Failures, pass.ExtractorGaps
	gapReasonCounts, gapDetails := pass.GapReasons, pass.GapDetails
	if g.Len() == 0 {
		fmt.Fprintf(os.Stderr, "depsnort: no projects resolved (%d failure(s))\n", resolveFailures)
		return exitInternal
	}
	if resolveFailures > 0 {
		fmt.Fprintf(os.Stderr, "depsnort: %d of %d project(s) failed to resolve; results are a lower bound\n",
			resolveFailures, len(projects))
	}
	// Projects are identified by the PURL derived from their manifest name and
	// version, so two checkouts declaring the same name@version merge into one
	// root. That is correct for the graph but would otherwise be an unexplained
	// gap between "discovered 48" and "4 roots", so say it out loud.
	if resolved := len(projects) - resolveFailures; resolved > len(g.Roots) {
		fmt.Fprintf(os.Stderr,
			"depsnort: %d resolved project(s) share %d distinct identit(ies); "+
				"checkouts declaring the same name@version merge into one root\n",
			resolved, len(g.Roots))
	}

	// Data-source stage: fetch advisories once (unless disabled). A network
	// failure degrades coverage but does not abort the scan — the coverage is
	// reported so a degraded run is never mistaken for a clean one.
	if *noExpand {
		*expandTree = false
	}
	ctx := &check.Context{Graph: g, Now: time.Now(), EPSSGate: *epssGate, Config: check.Config{
		InternalScopes: splitCSV(*internalScopes),
		InternalNames:  splitCSV(*internalNames),
	}}
	var info emit.RunInfo
	var dataSourceGaps []string // sources that errored or returned no data (F-02)
	for _, m := range checks.Metas() {
		info.Rules = append(info.Rules, emit.RuleInfo{
			ID: m.ID, Axis: string(m.Axis), Severity: string(m.DefaultSeverity),
			GateClass: string(m.DefaultGate), Description: m.Description,
		})
	}
	if *snapshotPath != "" {
		n, err := datasource.ImportSnapshot(datasource.NewCache(*cacheDir, 24*time.Hour), *snapshotPath, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: osv-snapshot import: %v\n", err)
			return exitInternal
		}
		fmt.Fprintf(os.Stderr, "depsnort: imported %d advisory record(s) from snapshot\n", n)
	}
	// osvClient is hoisted so the post-expansion advisory pass (below) can reuse
	// the same cached client; nil when -no-osv.
	var osvClient *osv.Client
	if !*noOSV {
		client := osv.New(datasource.NewCache(*cacheDir, 24*time.Hour), *offline)
		osvClient = client
		if *noBundled {
			client.Bundled = nil
		}
		advisories, exportEntries, qErr := prefetchAdvisories(g, client)
		ctx.Advisories = advisories
		cov := emit.DataSourceCoverage{Name: client.Name(), Stats: client.Stats}
		if qErr != nil {
			cov.Error = qErr.Error()
			fmt.Fprintf(os.Stderr, "depsnort: warning: OSV coverage degraded: %v\n", qErr)
		}
		// A bundled entry with no malicious-package advisory is disclosed
		// separately from a real bundled hit: it is present in the dataset but
		// answered nothing about malware, and it counts as a gap (DS-REV-01).
		if cov.Stats.BundledNonMalicious > 0 {
			fmt.Fprintf(os.Stderr,
				"depsnort: warning: %d coordinate(s) matched the embedded fallback dataset but carry no "+
					"malicious-package advisory — CVE context only, NOT malicious-package coverage\n",
				cov.Stats.BundledNonMalicious)
		}
		if cov.Stats.FromBundled > 0 {
			age := ""
			if cov.Stats.BundledDatasetAt != nil {
				days := int(time.Since(*cov.Stats.BundledDatasetAt).Hours() / 24)
				age = fmt.Sprintf(" (generated %s, %dd old)", cov.Stats.BundledDatasetAt.Format("2006-01-02"), days)
			}
			fmt.Fprintf(os.Stderr, "depsnort: warning: served %d coordinate(s) from the embedded fallback dataset%s — not a live check\n", cov.Stats.FromBundled, age)
		}
		if *exportPath != "" {
			if qErr != nil {
				fmt.Fprintf(os.Stderr, "depsnort: osv-export skipped: OSV query did not complete cleanly (%v)\n", qErr)
			} else if err := datasource.ExportSnapshot(*exportPath, exportEntries); err != nil {
				fmt.Fprintf(os.Stderr, "depsnort: osv-export: %v\n", err)
				return exitInternal
			} else {
				fmt.Fprintf(os.Stderr, "depsnort: exported %d advisory record(s) to %s\n", len(exportEntries), *exportPath)
			}
		}
		// A source that errored, or returned no data for coordinates it was
		// asked about (an offline miss / empty cache), is a coverage gap (F-02).
		// NotFound (a 404 for a private/unpublished package) is NOT a gap.
		if cov.Error != "" || cov.Stats.Gaps > 0 {
			dataSourceGaps = append(dataSourceGaps, client.Name())
		}
		info.DataSources = append(info.DataSources, cov)

	}

	// Registry-metadata stage: publish-time history for the temporal axis.
	// Each ecosystem has its own registry source; results merge into one map
	// keyed by node ID (PURLs are disjoint across ecosystems).
	if !*noRegistry {
		sources := registrySources(*regCacheDir, *offline)
		allReleases := map[string]*datasource.ReleaseHistory{}
		for _, src := range sources {
			releases, rErr := prefetchReleases(g, src)
			for k, v := range releases {
				allReleases[k] = v
			}
			cov := emit.DataSourceCoverage{Name: src.Name(), Stats: src.GetStats()}
			if rErr != nil {
				cov.Error = rErr.Error()
				fmt.Fprintf(os.Stderr, "depsnort: warning: %s coverage degraded: %v\n", src.Name(), rErr)
			}
			if cov.Error != "" || cov.Stats.Gaps > 0 {
				dataSourceGaps = append(dataSourceGaps, src.Name())
			}
			info.DataSources = append(info.DataSources, cov)
		}
		ctx.Releases = allReleases

		// Yank-lure enrichment (OPU-26 Inc.2): for cargo crates pinned to a yanked
		// version beneath a live-newest lure, fetch the live-newest's dependencies and
		// record the build-deps it introduces, so VC-012 can corroborate the shape
		// with the arrayref tell. Reuses the cargo-deps cache and the -offline gate;
		// only the flagged crates are fetched, so a non-cargo scan does nothing.
		cargoLureDeps := registry.NewCargoDeps(datasource.NewCache(filepath.Join(*regCacheDir, "cargo-deps"), 24*time.Hour), *offline)
		cargoLureSrc := registry.NewCrateSource(datasource.NewCache(filepath.Join(*regCacheDir, "cargo-source"), 24*time.Hour), *offline)
		pypiLureSdist := pypi.NewSdistFetcher(datasource.NewCache(filepath.Join(*regCacheDir, "pypi-sdist"), 24*time.Hour), *offline)
		if lureCov := enrichYankLure(g, cargoLureDeps, cargoLureSrc, pypiLureSdist, ctx.Releases); lureCov.Stats.Queried > 0 || lureCov.Error != "" {
			if lureCov.Error != "" {
				fmt.Fprintf(os.Stderr, "depsnort: warning: %s coverage degraded: %v\n", lureCov.Name, lureCov.Error)
			}
			if lureCov.Error != "" || lureCov.Stats.Gaps > 0 {
				dataSourceGaps = append(dataSourceGaps, lureCov.Name)
			}
			info.DataSources = append(info.DataSources, lureCov)
		}

		// Cargo build.rs fetch for unvendored crates (D-140), default-on since
		// D-149 for parity with the PyPI sdist path. Reuses the same
		// cargo-source client and cache as the yank-lure path above, so a crate
		// needed by both is fetched once. Under -offline the client serves only
		// its warm cache and a cold miss keeps its source-unavailable gap — the
		// same posture as OSV and the PyPI fetcher.
		if !*noCargoFetchSrc {
			srcCov, examined := enrichCargoBuildRS(g, cargoLureSrc, pass.SourceUnavailable)
			if srcCov.Stats.Queried > 0 || srcCov.Error != "" {
				if srcCov.Error != "" {
					fmt.Fprintf(os.Stderr, "depsnort: warning: %s coverage degraded: %v\n", srcCov.Name, srcCov.Error)
					dataSourceGaps = append(dataSourceGaps, srcCov.Name)
				}
				info.DataSources = append(info.DataSources, srcCov)
			}
			// Clear the source-unavailable gaps the fetch actually resolved. Leaving
			// them would report a crate as unexamined that this pass examined.
			for id := range examined {
				if gapReasonCounts[string(instsurf.GapUnavailable)] > 0 {
					gapReasonCounts[string(instsurf.GapUnavailable)]--
					if gapReasonCounts[string(instsurf.GapUnavailable)] == 0 {
						delete(gapReasonCounts, string(instsurf.GapUnavailable))
					}
					extractorGaps--
				}
				marker := string(instsurf.GapUnavailable) + ": " + id + " ("
				kept := gapDetails[:0]
				for _, d := range gapDetails {
					if !strings.Contains(d, marker) {
						kept = append(kept, d)
					}
				}
				gapDetails = kept
			}
		}

		// PyPI real transitive-depth reconstruction: a post-merge stage, same
		// tier as the release-history prefetch above, gated by the same
		// -offline/-no-registry flags rather than a new CLI flag. It only ever
		// touches PyPI roots the graph itself already marked flat.
		var rootNodes []*graph.Node
		for _, r := range g.Roots {
			if n := g.Get(r); n != nil {
				rootNodes = append(rootNodes, n)
			}
		}
		depsClient := registry.NewPyPIDeps(datasource.NewCache(filepath.Join(*regCacheDir, "pypi-requires-dist"), 24*time.Hour), *offline)
		depsCov := reconstructPyPIDepth(g, depsClient, rootNodes)
		if depsCov.Error != "" {
			fmt.Fprintf(os.Stderr, "depsnort: warning: %s coverage degraded: %v\n", depsCov.Name, depsCov.Error)
		}
		// UnparsedEntries counts too: a requires_dist entry this tool could not
		// read is a dependency edge missing from the graph, which must degrade
		// coverage rather than pass as a clean reconstruction (D-24).
		if depsCov.Error != "" || depsCov.Stats.Gaps > 0 || depsCov.Stats.UnparsedEntries > 0 {
			dataSourceGaps = append(dataSourceGaps, depsCov.Name)
		}
		info.DataSources = append(info.DataSources, depsCov)

		// Transitive expansion (default on): walk past what the lockfile
		// recorded, presuming a published version at each layer. Presumed nodes
		// are labelled (graph.AttrVersionTruth) and can never gate — the
		// guarantee is enforced in verdict, not here. Reuses the requires_dist
		// client above for declarations and a dedicated PyPI release client for
		// the version list; no new network surface beyond what -no-registry and
		// -offline already govern.
		if *expandTree {
			pypiIdx := registry.NewPyPI(datasource.NewCache(filepath.Join(*regCacheDir, "pypi"), 24*time.Hour), *offline)
			npmReg := npmreg.New(datasource.NewCache(filepath.Join(*regCacheDir, "npm"), 24*time.Hour), *offline)
			cargoDeps := registry.NewCargoDeps(datasource.NewCache(filepath.Join(*regCacheDir, "cargo-deps"), 24*time.Hour), *offline)
			cargoIdx := registry.NewCargo(datasource.NewCache(filepath.Join(*regCacheDir, "cargo"), 24*time.Hour), *offline)
			nugetDeps := registry.NewNuGetDeps(datasource.NewCache(filepath.Join(*regCacheDir, "nuget-deps"), 24*time.Hour), *offline)
			nugetIdx := registry.NewNuGet(datasource.NewCache(filepath.Join(*regCacheDir, "nuget"), 24*time.Hour), *offline)
			gemDeps := registry.NewGemDeps(datasource.NewCache(filepath.Join(*regCacheDir, "gem-deps"), 24*time.Hour), *offline)
			gemIdx := registry.NewGem(datasource.NewCache(filepath.Join(*regCacheDir, "gem"), 24*time.Hour), *offline)
			composerDeps := registry.NewComposerDeps(datasource.NewCache(filepath.Join(*regCacheDir, "composer-deps"), 24*time.Hour), *offline)
			composerIdx := registry.NewComposer(datasource.NewCache(filepath.Join(*regCacheDir, "composer"), 24*time.Hour), *offline)
			goProxy := goproxy.New(datasource.NewCache(filepath.Join(*regCacheDir, "goproxy"), 24*time.Hour), *offline)
			sources := []expand.Declarer{
				&pypi.WalkSource{Deps: depsClient, Index: pypiIdx},
				&npm.WalkSource{Reg: npmReg},
				&cargo.WalkSource{Deps: cargoDeps, Index: cargoIdx},
				&nuget.WalkSource{Deps: nugetDeps, Index: nugetIdx},
				&rubygems.WalkSource{Deps: gemDeps, Index: gemIdx},
				&composer.WalkSource{Deps: composerDeps, Index: composerIdx},
				&gomod.WalkSource{Proxy: goProxy},
			}
			// The asserted tier is default-on (OPU-12 D-2): a verdict presented as
			// authoritative should rest on resolved facts, not this tool's presumed
			// guesses. -offline (no network) and -no-depsdev both fall back to the
			// presumed walk, which is then disclosed as such. The tier is
			// multi-source (OPU-13): deps.dev resolves pypi/npm/cargo/nuget/gem, but
			// its v3 :dependencies endpoint 404s for every Go coordinate, so gomod is
			// routed to a native goproxy MVS resolver instead — never to deps.dev.
			var resolver expand.Resolver
			if useAssertedTier(*depsDev, *noDepsDev, *offline) {
				resolver = assertedResolver{
					depsDev: depsdev.New(datasource.NewCache(filepath.Join(*regCacheDir, "depsdev"), 24*time.Hour), false),
					gomod:   gomod.NewResolver(goProxy),
				}
			}
			expCov := expandTransitive(g, rootNodes, sources, resolver, *expandDepth)
			if expCov.Stats.Gaps > 0 {
				dataSourceGaps = append(dataSourceGaps, expCov.Name)
			}
			info.DataSources = append(info.DataSources, expCov)

			// The OPU-15 interim over-approximation disclosure (D-74) is retired here:
			// the asserted Go resolver now applies Go 1.17+ module-graph pruning
			// statically (D-75), so a go 1.17+ main's resolved closure matches
			// `go list -m all` exactly rather than over-approximating. When the
			// asserted tier is off (offline / -no-depsdev), the Go closure is presumed
			// and already disclosed as presumed-only (D-70) — no Go-specific caveat is
			// added on top.
		}
	} else {
		// -no-registry means requires_dist was never even fetched: a flat PyPI
		// root must say so explicitly rather than silently carrying no
		// reconstruction fact at all (Decision D-24 / "disclose, don't guess").
		for _, r := range g.Roots {
			n := g.Get(r)
			if n == nil || n.Ecosystem != "pypi" || n.Attr[graph.AttrFlatResolution] != "pypi" {
				continue
			}
			n.Attr[pypi.AttrReconstruction] = "not-attempted"
		}
	}

	// Post-expansion advisory pass. The first prefetch runs BEFORE transitive
	// expansion, so it can only ask about coordinates the manifests already
	// pinned. Two very common shapes were therefore never advisory-checked at
	// all: packages discovered BY expansion, and a manifest that pins nothing
	// (a Poetry-style pyproject.toml of version RANGES with no lockfile, whose
	// direct dependencies are unresolved placeholders at prefetch time and only
	// gain versions during expansion). Both produced a clean-looking
	// "0 advisory" verdict backed by zero OSV queries. This second pass asks
	// about every package that has a version and was not queried the first time;
	// the client is cached and batched, so already-known coordinates cost
	// nothing (D-59: disclose, never false-clean).
	if osvClient != nil {
		var (
			newCoords []datasource.Coord
			newIDs    []string
		)
		rootIDs := map[string]bool{}
		for _, r := range g.Roots {
			rootIDs[r] = true
		}
		for _, n := range g.SortedNodes() {
			if rootIDs[n.ID] || n.Kind != graph.KindPackage || n.Version == "" {
				continue
			}
			if _, queried := ctx.Advisories[n.ID]; queried {
				continue
			}
			newCoords = append(newCoords, datasource.Coord{Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version})
			newIDs = append(newIDs, n.ID)
		}
		if len(newCoords) > 0 {
			results, qErr := osvClient.QueryBatch(context.Background(), newCoords)
			if ctx.Advisories == nil {
				ctx.Advisories = map[string][]datasource.Advisory{}
			}
			for i := range results {
				if i < len(newIDs) {
					ctx.Advisories[newIDs[i]] = results[i]
				}
			}
			// Fold the second pass into the existing osv coverage line so the
			// report states one honest total rather than two partial ones.
			for i := range info.DataSources {
				if info.DataSources[i].Name != "osv" {
					continue
				}
				st := &info.DataSources[i].Stats
				st.Queried += osvClient.Stats.Queried
				st.Advisories += osvClient.Stats.Advisories
				st.Malicious += osvClient.Stats.Malicious
				st.FromCache += osvClient.Stats.FromCache
				st.FromNet += osvClient.Stats.FromNet
				st.Gaps += osvClient.Stats.Gaps
				st.NotFound += osvClient.Stats.NotFound
				if qErr != nil && info.DataSources[i].Error == "" {
					info.DataSources[i].Error = qErr.Error()
				}
				break
			}
			if qErr != nil {
				fmt.Fprintf(os.Stderr, "depsnort: warning: OSV coverage degraded (post-expansion): %v\n", qErr)
			}
			fmt.Fprintf(os.Stderr, "depsnort: advisory check covered %d additional package(s) resolved after expansion\n", len(newCoords))
		}

		// Never let a clean verdict be mistaken for a verified one: if resolved
		// packages exist and NONE of them was advisory-checked, say so loudly.
		var resolved int
		for _, n := range g.SortedNodes() {
			if !rootIDs[n.ID] && n.Kind == graph.KindPackage && n.Version != "" {
				resolved++
			}
		}
		var checked int
		for id := range ctx.Advisories {
			if !rootIDs[id] {
				checked++
			}
		}
		if resolved > 0 && checked == 0 {
			fmt.Fprintf(os.Stderr,
				"depsnort: WARNING - advisory coverage: 0 of %d resolved package(s) were checked against OSV; "+
					"a clean vulnerability verdict here is NOT a verified one\n", resolved)
		}
	}

	// EPSS enrichment (opt-in, -epss): resolve each vulnerable coordinate's
	// advisories to their CVE aliases (querybatch returns none), score those CVEs
	// with FIRST.org EPSS, and hand VC-008 the scores to annotate and rank by
	// exploit probability. Skipped offline (EPSS has no bundled fallback).
	// EPSS runs AFTER the post-expansion advisory pass so it scores the complete
	// advisory set, including packages discovered during expansion. Requires the
	// OSV client for CVE-alias resolution, so it is skipped under -no-osv.
	// CVE-alias hydration (D-146). Runs on its own now, not only under -epss.
	// OSV's querybatch returns advisory IDs without aliases, so a GHSA-primary
	// advisory arrives carrying no CVE identity at all: the report could not name
	// the CVE, an operator searching for one found nothing, and the recency
	// fallback (D-145) had no year to read. /v1/query returns the aliases, one
	// cached call per coordinate.
	aliasByID := map[string]osv.Hydration{}
	aliasDegraded := false
	if !*offline && osvClient != nil {
		coords := hydrationCandidates(g, ctx)
		if len(coords) > 0 {
			hydrated, aErr := osvClient.HydrateAdvisories(context.Background(), coords)
			if aErr != nil {
				aliasDegraded = true
				fmt.Fprintf(os.Stderr, "depsnort: warning: advisory hydration degraded: %v\n", aErr)
			}
			aliasByID = hydrated
			scored := 0
			for id, advs := range ctx.Advisories {
				for i := range advs {
					h, ok := aliasByID[advs[i].ID]
					if !ok {
						continue
					}
					advs[i].Aliases = append(advs[i].Aliases, h.CVEs...)
					advs[i].SeverityLabel = h.Label
					if h.Scored {
						advs[i].Severity, advs[i].ScoredSeverity = h.Severity, true
						scored++
					}
				}
				ctx.Advisories[id] = advs
			}
			fmt.Fprintf(os.Stderr, "depsnort: hydrated %d of %d coordinate(s) from OSV /v1/query (%d advisory severity score(s))\n",
				len(aliasByID), len(coords), scored)
		}
	}

	if *epssOn && !*offline && osvClient != nil {
		var coords []datasource.Coord
		for _, n := range g.SortedNodes() {
			hasVuln := false
			for _, a := range ctx.Advisories[n.ID] {
				if !a.Malicious {
					hasVuln = true
					break
				}
			}
			if hasVuln && n.Version != "" {
				coords = append(coords, datasource.Coord{Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version})
			}
		}
		if len(coords) > 0 {
			// Aliases were hydrated above and are already merged onto the
			// advisories; this pass only collects the CVEs to score.
			var cves []string
			for _, advs := range ctx.Advisories {
				for i := range advs {
					cves = append(cves, advisoryCVEIDs(advs[i])...)
				}
			}
			epssClient := epss.New(datasource.NewCache(*cacheDir, 24*time.Hour), *offline)
			scores, eErr := epssClient.Scores(context.Background(), cves)
			ctx.EPSS = scores
			epssCov := emit.DataSourceCoverage{
				Name:  epssClient.Name(),
				Stats: epssClient.Stats,
				// Whether alias resolution degraded is still reported: hydration
				// moved out of this block (D-146) but the fact travels with it,
				// because a partial alias map means partially-scored CVEs.
				Note: epss.EnrichmentSummary(len(coords), len(aliasByID), epssClient.Stats, aliasDegraded),
			}
			if eErr != nil {
				epssCov.Error = eErr.Error()
				fmt.Fprintf(os.Stderr, "depsnort: warning: EPSS coverage degraded: %v\n", eErr)
			}
			info.DataSources = append(info.DataSources, epssCov)
			fmt.Fprintf(os.Stderr, "depsnort: EPSS %s\n", epssCov.Note)
		}
	}

	// IOC ledger stage: match resolved packages against the operator's own
	// confirmed indicators (VC-003). The ledger is authoritative, so a match is
	// pre-computed here and fanned across the whole transitive tree by the check.
	if *iocPath != "" {
		feed, err := ioc.Load(*iocPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: %v\n", err)
			return exitUsage
		}
		matched := map[string]ioc.Indicator{}
		for _, n := range g.SortedNodes() {
			if n.Kind != graph.KindPackage {
				continue
			}
			if ind := feed.Match(n.ID, n.Ecosystem, n.Name, n.Version); ind != nil {
				matched[n.ID] = *ind
			}
		}
		ctx.IOC = matched
		fmt.Fprintf(os.Stderr, "depsnort: IOC ledger: %d indicator(s), %d match(es)\n",
			feed.Len(), len(matched))
	}

	// Baseline stage: the operator-promoted known-good record the drift axis
	// compares against (D-40). Loaded AFTER the registry stage so the candidate
	// profiles carry publisher identity, and before the checks run because
	// VC-010/VC-011 read it from the context.
	if *baselinePath != "" {
		base, err := baseline.Load(*baselinePath)
		if err != nil {
			// A baseline that cannot be read is a usage error, never a silent
			// downgrade to "no drift found": the operator asked for drift to be
			// evaluated and must not get a clean exit for a scan that skipped it.
			fmt.Fprintf(os.Stderr, "depsnort: %v\n", err)
			return exitUsage
		}
		ctx.Baseline = baseline.Index(base)
		ctx.Profiles = profileGraph(g, ctx.Releases)
		fmt.Fprintf(os.Stderr, "depsnort: baseline: %d known-good profile(s) from %s\n",
			len(base), *baselinePath)
		// A baseline holding several versions of one package cannot say which
		// one a candidate should be compared against, so VC-010 will decline
		// for those packages. Announce it here as well as in the finding: an
		// operator who expected drift coverage should not have to read the
		// report to learn part of it was skipped (DS-REV-03).
		if amb := baseline.AmbiguousKeys(ctx.Baseline); len(amb) > 0 {
			fmt.Fprintf(os.Stderr,
				"depsnort: WARNING - %d package(s) appear in the baseline at more than one version "+
					"(%s); drift is UNEVALUATED for them\n",
				len(amb), strings.Join(amb, ", "))
			// Not just a finding: an axis that could not be evaluated is
			// missing coverage, so it belongs where -fail-on-incomplete can
			// see it. Same treatment VC-009 gets for unverifiable provenance
			// (D-41) — name it in the report AND let it reach an exit code.
			dataSourceGaps = append(dataSourceGaps,
				fmt.Sprintf("baseline (ambiguous for %d package(s))", len(amb)))
		}
	} else {
		// Not a coverage gap — nothing failed — but never silent either: a scan
		// that could not have reported drift should not read as one that looked
		// for it and found none.
		fmt.Fprintln(os.Stderr, "depsnort: drift axis inactive (no -baseline)")
	}

	findings := checks.RunAll(ctx)

	// Assemble scan-level coverage: the graph's own resolution facts PLUS the
	// gaps the graph cannot see — failed data sources, partial install-surface
	// extraction, and workspace projects that never resolved (finding F-02).
	// Without this, -fail-on-incomplete could still return a clean 0 over an
	// empty OSV cache, a dead registry, or an unreadable subtree.
	cov := g.Coverage()
	cov.DataSourceGaps = dataSourceGaps
	cov.ExtractorGaps = extractorGaps
	cov.ExtractorGapReasons = summarizeReasons(gapReasonCounts)
	cov.ExtractorGapDetails = gapDetails
	cov.FailedProjects = resolveFailures
	cov.Complete = !cov.Incomplete() && len(cov.FlatEcosystems) == 0

	// Attach each finding's root→node dependency path BEFORE the verdict, so every
	// downstream copy (res.Findings and per-node graph.Node.Findings) carries it.
	// A deep transitive finding's first question is "why is this package here?" —
	// the chain answers it (OPU-12 D-3).
	for i := range findings {
		if p := g.PathToNode(findings[i].NodeID); len(p) > 1 {
			findings[i].DepPath = p
		}
	}

	res := verdict.EvaluateWithCoverage(g, findings, cov, verdict.Policy{
		FailOnEligible:   *failEligible,
		FailOnIncomplete: *failIncomplete,
		RealRoots:        splitCSV(*realRoots),
	})
	// Incomplete coverage is announced on stderr even when it does not gate: a
	// pipeline that only reads the exit code must still be told the tool could
	// not see the whole tree (Decision D-24 / F-02).
	if c := res.Coverage; c.Incomplete() {
		fmt.Fprintf(os.Stderr, "depsnort: WARNING - %s\n", c.IncompleteSummary())
	}

	// Render to a buffer first: a failed emit must not leave a truncated report
	// on disk that a later reader mistakes for a complete scan.
	var buf bytes.Buffer
	if err := emitter.Emit(&buf, g, res, info); err != nil {
		fmt.Fprintf(os.Stderr, "depsnort: emit: %v\n", err)
		return exitInternal
	}

	outPath, err := resolveOutPath(outSpec, *format, *localStamp, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "depsnort: %v\n", err)
		return exitInternal
	}
	if outPath == "" {
		if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: writing output: %v\n", err)
			return exitInternal
		}
		return res.ExitCode
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "depsnort: writing %s: %v\n", outPath, err)
		return exitInternal
	}
	// Path goes to stderr so stdout stays clean for piping when it is used.
	fmt.Fprintf(os.Stderr, "depsnort: wrote %s (%d bytes)\n", outPath, buf.Len())
	return res.ExitCode
}

func cmdChecks() int {
	checks := checkRegistry()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAXIS\tSEVERITY\tGATE-CLASS\tDESCRIPTION")
	for _, m := range checks.Metas() {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Axis, m.DefaultSeverity, m.DefaultGate, m.Description)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "depsnort: %v\n", err)
		return exitInternal
	}
	return 0
}
