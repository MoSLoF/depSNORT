package clojure

import (
	"context"
	"strings"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/purl"
)

// WalkSource is the maven-coordinate side of the Nth-layer walk — an
// IDENTITY-ONLY seam (D-164). Its load-bearing half is Identify: before it
// existed, a deps.dev-asserted maven child took the engine's raw fallback ID
// (`pkg:maven/group:artifact@v`, colon kept in the name) while the adapter's
// observed nodes carry the namespace form (`pkg:maven/group/artifact@v`) —
// two IDs for one package, so "observed beats asserted" failed to match and
// the same dependency could enter the graph twice with its advisories split
// across the twins. That is the D-15 identity leak, one tier up, and exactly
// what the Declarer contract says Identify exists to prevent.
//
// Declared is deliberately honest-empty: reading a Maven package's own
// declared dependencies means fetching and interpreting poms (parents,
// properties, dependencyManagement) — the pom.xml problem, its own decision.
// The walk's contract counts a coordinate ABSENT from the map as "not read",
// which is the true state, so presume-tier coverage over maven discloses as
// unread rather than being guessed. Real transitive resolution stays with the
// asserted tier (deps.dev), whose merged children this seam now names
// correctly.
type WalkSource struct{}

// Ecosystem implements expand.Declarer. Matches graph.Node.Ecosystem — the
// coordinate space, "maven", not the manifest family (see the package doc).
func (*WalkSource) Ecosystem() string { return "maven" }

// Identify normalizes a Maven coordinate to the adapter's own identity:
// `group:artifact` splits into the pkg:maven namespace form, and a bare name
// maps group == artifact (the Leiningen convention the adapter established).
// Coordinates are case-sensitive; nothing is folded.
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ""
	}
	group, artifact := name, name
	if i := strings.IndexByte(name, ':'); i > 0 && i < len(name)-1 {
		group, artifact = name[:i], name[i+1:]
	}
	return purl.NewMaven(group, artifact, version).String(), group + ":" + artifact
}

// Declared implements expand.Declarer: nothing is read (see the type comment).
// Every requested coordinate is absent from the returned map, which the walk
// counts as unread — disclosed, never presumed.
func (*WalkSource) Declared(context.Context, []datasource.Coord) (map[string][]expand.Declaration, error) {
	return map[string][]expand.Declaration{}, nil
}
