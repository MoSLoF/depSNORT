// Command depsnort is the depSNORT CLI — the primitive that the CI gate and
// pre-commit hook are thin wrappers over (Decision D-09).
//
// Exit codes:
//
//	0   clean, or only advisory findings
//	1   a block-class finding (FLAG) was present
//	2   a gate-eligible finding was present AND --fail-on-eligible was set
//	3   resolution coverage was degraded AND --fail-on-incomplete was set
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

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/check/builtin"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/ioc"
	"ihbv.io/depsnort/internal/datasource/npmreg"
	"ihbv.io/depsnort/internal/datasource/osv"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/ecosystem"
	"ihbv.io/depsnort/internal/ecosystem/cargo"
	"ihbv.io/depsnort/internal/ecosystem/composer"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/ecosystem/npm"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
	"ihbv.io/depsnort/internal/emit"
	"ihbv.io/depsnort/internal/graph"
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
  depsnort scan [flags] [path]     resolve and analyze a project (default path ".")
                                   with -recursive, a workspace of projects
  depsnort checks                  list the registered vector checks
  depsnort sbom [-release]         emit this binary's own CycloneDX SBOM
                                   (-release: platform-neutral, for release artifacts)
  depsnort version                 print version

scan flags:
  -format string           output format: json | dot | cypher | sarif | pdf (default "json")
  -fail-on-eligible        let gate-eligible warnings fail the run (exit 2)
  -fail-on-incomplete      let degraded resolution coverage fail the run (exit 3);
                           coverage is always REPORTED, this only makes it gate
  -offline                 use only the local OSV cache; never touch the network
  -no-osv                  skip the OSV data-source layer entirely
  -osv-cache string        OSV advisory cache directory
  -no-registry             skip registry metadata (disables VC-004 / VC-005)
  -registry-cache string   registry metadata cache directory
  -no-install-surface      skip static install-hook extraction (VC-002b..e)
  -recursive               treat the path as a workspace root: discover every
                           project beneath it and merge into one graph
  -internal-scopes string  comma-separated internal scopes (VC-007), e.g. @ihbv,@acme
  -internal-names string   comma-separated internal package names (VC-007)
  -ioc string              path to an IOC ledger feed (JSON); enables VC-003 —
                           a resolved package on the ledger blocks (exit 1)
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
// configuration. This is the single wiring point for adapters.
func adapterRegistry(offline bool) *ecosystem.Registry {
	pypiCache := datasource.NewCache(defaultCacheDir("pypi-sdist"), 7*24*time.Hour)
	return ecosystem.NewRegistry(
		npm.New(),
		pypi.NewWithSdist(pypiCache, offline),
		rubygems.New(),
		cargo.New(),
		composer.New(),
		nuget.New(),
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
func prefetchAdvisories(g *graph.Graph, src *osv.Client) (map[string][]datasource.Advisory, error) {
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
		return byNode, nil
	}
	results, err := src.QueryBatch(context.Background(), coords)
	for i := range results {
		if i < len(ids) {
			byNode[ids[i]] = results[i]
		}
	}
	return byNode, err
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "json", "output format: "+strings.Join(emit.Formats(), " | "))
	failEligible := fs.Bool("fail-on-eligible", false, "gate-eligible warnings fail the run (exit 2)")
	failIncomplete := fs.Bool("fail-on-incomplete", false, "degraded resolution coverage fails the run (exit 3)")
	offline := fs.Bool("offline", false, "use only the local OSV cache; never touch the network")
	noOSV := fs.Bool("no-osv", false, "skip the OSV data-source layer entirely")
	cacheDir := fs.String("osv-cache", defaultCacheDir("osv"), "OSV advisory cache directory")
	regCacheDir := fs.String("registry-cache", defaultCacheDir("registry"), "registry metadata cache directory")
	noRegistry := fs.Bool("no-registry", false, "skip registry-metadata source (disables VC-004/VC-005)")
	noInstallSurface := fs.Bool("no-install-surface", false, "skip static install-hook extraction")
	recursive := fs.Bool("recursive", false, "treat the path as a workspace root: discover and merge every project beneath it")
	internalScopes := fs.String("internal-scopes", "", "comma-separated internal scopes for dependency-confusion (e.g. @ihbv,@acme)")
	internalNames := fs.String("internal-names", "", "comma-separated internal package names for dependency-confusion")
	iocPath := fs.String("ioc", "", "path to an IOC ledger feed (JSON); enables VC-003")
	var outSpec string
	fs.StringVar(&outSpec, "o", "", "output root: writes <root>/YYYYMMDD/Report-<DTG>.<ext>; a path with an extension is used verbatim (default: stdout)")
	fs.StringVar(&outSpec, "out", "", "alias for -o")
	localStamp := fs.Bool("local", false, "stamp report paths in local time instead of UTC")
	if err := fs.Parse(args); err != nil {
		return exitUsage
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

	adapters := adapterRegistry(*offline)
	checks := checkRegistry()

	// Build the list of projects to scan. A single path is one project; with
	// -recursive the path is a workspace root and every project beneath it is
	// discovered and merged into one graph.
	var projects []discovered
	if *recursive {
		found, err := discoverProjects(path, adapters)
		if err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: discovery under %s: %v\n", path, err)
			return exitInternal
		}
		if len(found) == 0 {
			fmt.Fprintf(os.Stderr, "depsnort: no supported projects found under %q\n", path)
			return exitInternal
		}
		projects = found
		fmt.Fprintf(os.Stderr, "depsnort: discovered %d project(s) under %s\n", len(projects), path)
	} else {
		adapter, err := adapters.Detect(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: %v\n", err)
			return exitInternal
		}
		projects = []discovered{{Path: path, Adapter: adapter}}
	}

	// Resolve each project and merge into a single multi-root graph. A package
	// at the same version in two repos becomes ONE node, so shared dependencies
	// collapse and a flagged package shows its blast radius across the workspace.
	g := graph.New()
	var resolveFailures, extractorGaps int
	gapReasonCounts := map[string]int{}
	var gapDetails []string
	for _, p := range projects {
		sub, err := p.Adapter.Resolve(p.Path)
		if err != nil {
			resolveFailures++
			fmt.Fprintf(os.Stderr, "depsnort: warning: resolve %s (%s): %v\n", p.Path, p.Adapter.Name(), err)
			continue
		}

		// Install-surface extraction: statically read lifecycle hooks and the
		// files they reference, adding the install-time subgraph. Never executes
		// anything (Decision D-04). Adapters that do not implement it are skipped.
		if !*noInstallSurface {
			if ex, ok := p.Adapter.(ecosystem.InstallSurfaceExtractor); ok {
				if err := ex.ExtractInstallSurface(p.Path, sub); err != nil {
					// Typed gaps (R-01) carry one entry per unexamined file, so
					// count them individually and keep their reasons; anything
					// else is one opaque partial extraction.
					if gs := instsurf.GapsOf(err); len(gs) > 0 {
						extractorGaps += len(gs)
						for _, gp := range gs {
							gapReasonCounts[string(gp.Reason)]++
							if len(gapDetails) < maxGapDetails {
								gapDetails = append(gapDetails, p.Path+": "+gp.String())
							}
						}
					} else {
						extractorGaps++
						gapReasonCounts["extraction-error"]++
						if len(gapDetails) < maxGapDetails {
							gapDetails = append(gapDetails, p.Path+": "+err.Error())
						}
					}
					fmt.Fprintf(os.Stderr, "depsnort: warning: install surface not fully examined for %s: %v\n", p.Path, err)
				}
			}
		}
		g.Merge(sub)
	}
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
	ctx := &check.Context{Graph: g, Now: time.Now(), Config: check.Config{
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
	if !*noOSV {
		client := osv.New(datasource.NewCache(*cacheDir, 24*time.Hour), *offline)
		advisories, qErr := prefetchAdvisories(g, client)
		ctx.Advisories = advisories
		cov := emit.DataSourceCoverage{Name: client.Name(), Stats: client.Stats}
		if qErr != nil {
			cov.Error = qErr.Error()
			fmt.Fprintf(os.Stderr, "depsnort: warning: OSV coverage degraded: %v\n", qErr)
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

	res := verdict.EvaluateWithCoverage(g, findings, cov, verdict.Policy{
		FailOnEligible:   *failEligible,
		FailOnIncomplete: *failIncomplete,
	})
	// Incomplete coverage is announced on stderr even when it does not gate: a
	// pipeline that only reads the exit code must still be told the tool could
	// not see the whole tree (Decision D-24 / F-02).
	if c := res.Coverage; c.Incomplete() {
		fmt.Fprintf(os.Stderr,
			"depsnort: WARNING - coverage is incomplete: %d unresolved dependenc(ies) across %d root(s), "+
				"%d orphaned package(s), %d failed project(s), %d partial install-surface extraction(s)",
			c.Unresolved, c.IncompleteRoots, c.Orphans, c.FailedProjects, c.ExtractorGaps)
		if len(c.ExtractorGapReasons) > 0 {
			fmt.Fprintf(os.Stderr, " [%s]", strings.Join(c.ExtractorGapReasons, ", "))
		}
		if len(c.DataSourceGaps) > 0 {
			fmt.Fprintf(os.Stderr, ", degraded data source(s): %s", strings.Join(c.DataSourceGaps, ", "))
		}
		fmt.Fprint(os.Stderr, ". This report is NOT an all-clear.\n")
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
