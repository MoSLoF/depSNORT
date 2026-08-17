package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"ihbv.io/depsnort/internal/baseline"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/profile"
)

// profileGraph builds one profile per resolved package in g, keyed by PURL.
//
// Shared by `baseline create` (which writes them) and `scan -baseline` (which
// compares against them), so the two sides of a diff are produced by identical
// code. Anything else would make the first drift report an artifact of the tool
// disagreeing with itself.
func profileGraph(g *graph.Graph, releases map[string]*datasource.ReleaseHistory) map[string]profile.Profile {
	out := make(map[string]profile.Profile)
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		p := profile.FromGraph(g, n)
		if p.IsZero() {
			continue
		}
		// releases is keyed by node ID, and is empty under -no-registry or a
		// cold offline cache — in which case WithPublisher records the absence
		// rather than leaving the profile silently publisher-free.
		out[p.PURL] = p.WithPublisher(releases[n.ID])
	}
	return out
}

// cmdBaseline implements `depsnort baseline <subcommand>`.
func cmdBaseline(args []string) int {
	if len(args) == 0 {
		baselineUsage()
		return exitUsage
	}
	switch args[0] {
	case "create":
		return cmdBaselineCreate(args[1:])
	case "help", "-h", "--help":
		baselineUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "depsnort: baseline: unknown subcommand %q\n\n", args[0])
		baselineUsage()
		return exitUsage
	}
}

func baselineUsage() {
	fmt.Fprint(os.Stderr, `depsnort baseline — record what a dependency tree looked like when you approved it

usage:
  depsnort baseline create [flags] [path]   write a known-good profile per package

create flags:
  -o, -out string          baseline file to write (default "depsnort-baseline.json")
  -recursive               treat the path as a workspace root
  -offline                 use only local caches; never touch the network
  -no-registry             skip registry metadata (records no publisher identity)
  -registry-cache string   registry metadata cache directory
  -no-install-surface      skip static install-hook extraction

A baseline is a file you commit and review, not an inferred "last good version".
Nothing promotes itself: re-run create when you have decided a tree is good.
`)
}

func cmdBaselineCreate(args []string) int {
	fs := flag.NewFlagSet("baseline create", flag.ContinueOnError)
	var outPath string
	fs.StringVar(&outPath, "o", "depsnort-baseline.json", "baseline file to write")
	fs.StringVar(&outPath, "out", "depsnort-baseline.json", "alias for -o")
	recursive := fs.Bool("recursive", false, "treat the path as a workspace root")
	offline := fs.Bool("offline", false, "use only local caches; never touch the network")
	noRegistry := fs.Bool("no-registry", false, "skip registry metadata (records no publisher identity)")
	regCacheDir := fs.String("registry-cache", defaultCacheDir("registry"), "registry metadata cache directory")
	noInstallSurface := fs.Bool("no-install-surface", false, "skip static install-hook extraction")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	adapters := adapterRegistry(*offline)

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
	} else {
		adapter, err := adapters.Detect(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "depsnort: %v\n", err)
			return exitInternal
		}
		projects = []discovered{{Path: path, Adapter: adapter}}
	}

	pass := resolveProjects(projects, !*noInstallSurface)
	g := pass.Graph
	if g.Len() == 0 {
		fmt.Fprintf(os.Stderr, "depsnort: no projects resolved (%d failure(s))\n", pass.Failures)
		return exitInternal
	}

	// A baseline built over a tree this run could not fully read would record
	// "no capabilities" for packages whose source was simply unavailable, and
	// every later scan would compare against that fiction. The profiles
	// themselves carry the per-package marker (profile.UnobservedInstallSurface),
	// but say it once at the top too: the operator is about to commit this file.
	if pass.Failures > 0 || pass.ExtractorGaps > 0 {
		fmt.Fprintf(os.Stderr,
			"depsnort: WARNING - this baseline is being recorded over incomplete coverage: "+
				"%d project(s) failed to resolve, %d install-surface gap(s). Affected profiles are "+
				"marked unobserved, but a capability that was never read cannot be baselined as absent.\n",
			pass.Failures, pass.ExtractorGaps)
	}

	// Publisher identity comes from the registry stage. Without it a baseline
	// still records capabilities and topology; it simply cannot anchor the
	// actor axis, and every profile says so.
	releases := map[string]*datasource.ReleaseHistory{}
	if !*noRegistry {
		for _, src := range registrySources(*regCacheDir, *offline) {
			got, err := prefetchReleases(g, src)
			if err != nil {
				fmt.Fprintf(os.Stderr, "depsnort: warning: %s coverage degraded: %v\n", src.Name(), err)
			}
			for k, v := range got {
				releases[k] = v
			}
		}
	}

	profiles := profileGraph(g, releases)
	list := make([]profile.Profile, 0, len(profiles))
	withPublisher := 0
	for _, p := range profiles {
		if !p.Publisher.IsZero() {
			withPublisher++
		}
		list = append(list, p)
	}

	if err := baseline.Write(outPath, "depsnort "+version, time.Now(), list); err != nil {
		fmt.Fprintf(os.Stderr, "depsnort: %v\n", err)
		return exitInternal
	}
	fmt.Fprintf(os.Stderr, "depsnort: wrote %d profile(s) to %s (%d with a publisher identity)\n",
		len(list), outPath, withPublisher)
	return 0
}
