// Package profile is depSNORT's answer to "what did this package look like the
// last time we trusted it?".
//
// Every check that existed before this package evaluates a version as an
// isolated event: a hook is judged on what it can do, a burst on the package's
// own cadence, an advisory on a coordinate. None of them can answer the
// question an operator actually asks during a dependency update — did anything
// SECURITY-RELEVANT change? A Profile is the comparable form of one
// package@version: its install-time capabilities, the hooks that carry them,
// where they reach, who published it, and what it depends on. Two profiles
// diff (see diff.go), and that diff is the state-transition evidence the rest
// of the model was missing (Decision D-40).
//
// Two properties are load-bearing:
//
//   - DETERMINISM (D-13). Every slice is sorted and every value is derived from
//     graph facts, never from wall-clock or map iteration order. The same tree
//     must produce byte-identical profiles on every run, or a committed
//     baseline would show phantom drift on the next scan.
//
//   - UNOBSERVED IS NOT EMPTY. A profile built over an install surface that
//     could not be read records that fact. Without it, a baseline captured
//     under degraded coverage would launder itself into a known-good record
//     asserting "this package has no capabilities" — the same all-clear-over-
//     nothing failure the coverage model exists to prevent (D-24).
//
// Extraction vs judgment (D-03): nothing here decides what a capability change
// means. VC-010 does that.
package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// Schema is the profile format version. It travels in every serialized profile
// so a baseline written by an older build is rejected loudly rather than
// compared against silently (see internal/baseline).
const Schema = "depsnort.profile/1"

// Unobserved reasons. These are the ways a profile can be a LOWER BOUND on what
// the package actually does.
const (
	// UnobservedInstallSurface: the package's install-time source was not
	// available to read, so an absent capability may simply be an unread one.
	UnobservedInstallSurface = "install-surface-unread"
	// UnobservedPublisher: no per-version publisher identity was available for
	// this ecosystem or this package. Never confuse with "same publisher".
	UnobservedPublisher = "publisher-unavailable"
	// UnobservedSource: the package's origin is not a registry, so its contents
	// were taken on faith from the lockfile (D-41).
	UnobservedSource = "source-unverifiable"
)

// Profile is the comparable form of one package@version.
type Profile struct {
	Schema    string `json:"schema"`
	PURL      string `json:"purl"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`

	// SourceClass and SourceRef are the provenance facts from D-41, carried
	// here so a baseline records not just what a package could do but how
	// verifiable it was.
	SourceClass string `json:"source_class,omitempty"`
	SourceRef   string `json:"source_ref,omitempty"`

	// Hooks are the install-time lifecycle entry points the package declares.
	Hooks []string `json:"hooks,omitempty"`
	// Caps is the union of capabilities across every hook and every artifact
	// reachable from one, as installsurface.Capability strings.
	Caps []string `json:"caps,omitempty"`
	// RemoteHosts are the hosts of remote artifacts an install-time chain
	// reaches for. Hosts rather than full URLs: a cache-busting query string
	// changing between releases is not a security event, a new destination is.
	RemoteHosts []string `json:"remote_hosts,omitempty"`
	// Sinks are the named credential destinations the chain references.
	Sinks []string `json:"sinks,omitempty"`

	// Publisher is the identity that published THIS version, when the registry
	// exposes it.
	Publisher datasource.Publisher `json:"publisher,omitzero"`

	// TopologyDigest is a stable digest over the package's direct dependency
	// coordinates. It answers "did this release rewire what it pulls in?"
	// without storing the whole subtree in every baseline.
	TopologyDigest string `json:"topology_digest,omitempty"`

	// Unobserved names the ways this profile is a lower bound, sorted.
	Unobserved []string `json:"unobserved,omitempty"`
}

// IsZero reports whether p holds no package identity — the shape returned for
// a node that is not a package.
func (p Profile) IsZero() bool { return p.PURL == "" }

// FromGraph builds the profile of package node n from the graph around it.
//
// The install-time subgraph it reads is the one internal/ecosystem/instsurf
// already materialized: hook nodes hang off the package by declares-hook, and
// artifacts and sinks hang off those. Capabilities live on those nodes as
// "cap.<name>" attributes. This walks that structure rather than re-analyzing
// source, so a profile costs nothing beyond the scan that was already run.
func FromGraph(g *graph.Graph, n *graph.Node) Profile {
	if g == nil || n == nil || n.Kind != graph.KindPackage {
		return Profile{}
	}

	p := Profile{
		Schema:    Schema,
		PURL:      n.ID,
		Ecosystem: n.Ecosystem,
		Name:      n.Name,
		Version:   n.Version,
	}
	if class, ref := n.SourceOf(); class != graph.SourceUnknown {
		p.SourceClass, p.SourceRef = class, ref
		if !graph.Verifiable(class) {
			p.Unobserved = append(p.Unobserved, UnobservedSource)
		}
	}

	// Index edges once by source node: a large workspace graph has tens of
	// thousands of edges, and profiling every package with a linear scan each
	// time is the difference between a scan and a coffee break.
	out := map[string][]graph.Edge{}
	for _, e := range g.Edges {
		out[e.From] = append(out[e.From], e)
	}

	hooks := map[string]bool{}
	caps := map[string]bool{}
	hosts := map[string]bool{}
	sinks := map[string]bool{}
	surfaceUnread := false

	collectCaps := func(node *graph.Node) {
		for k, v := range node.Attr {
			if v == "true" && strings.HasPrefix(k, "cap.") {
				caps[strings.TrimPrefix(k, "cap.")] = true
			}
		}
	}

	for _, he := range out[n.ID] {
		if he.Type != graph.EdgeDeclaresHook {
			continue
		}
		hook := g.Get(he.To)
		if hook == nil {
			continue
		}
		hooks[hook.Name] = true
		collectCaps(hook)

		for _, ae := range out[hook.ID] {
			target := g.Get(ae.To)
			if target == nil {
				continue
			}
			switch target.Kind {
			case graph.KindReferencedArtifact:
				collectCaps(target)
				if target.Attr["artifact.remote"] == "true" {
					if h := hostOf(target.Name); h != "" {
						hosts[h] = true
					}
				}
				// An artifact the extractor could not read is the specific
				// shape of "absent capability might mean unread source".
				if target.Attr["artifact.read"] == "false" {
					surfaceUnread = true
				}
			case graph.KindSink:
				sinks[target.Name] = true
			}
		}
	}

	p.Hooks = sortedKeys(hooks)
	p.Caps = sortedKeys(caps)
	p.RemoteHosts = sortedKeys(hosts)
	p.Sinks = sortedKeys(sinks)
	if surfaceUnread {
		p.Unobserved = append(p.Unobserved, UnobservedInstallSurface)
	}
	p.TopologyDigest = topologyDigest(out[n.ID], g)
	sort.Strings(p.Unobserved)
	return p
}

// WithPublisher returns p carrying the version-level publisher from h, or
// carrying UnobservedPublisher when no such identity is available.
//
// Split from FromGraph because publisher lineage arrives from the data-source
// layer, which the graph knows nothing about; keeping FromGraph pure over the
// graph is what makes profiles reproducible offline.
func (p Profile) WithPublisher(h *datasource.ReleaseHistory) Profile {
	if h != nil {
		if pub, ok := h.PublisherAt(p.Version); ok {
			p.Publisher = pub
			p.Unobserved = removeString(p.Unobserved, UnobservedPublisher)
			return p
		}
	}
	p.Publisher = datasource.Publisher{}
	if !containsString(p.Unobserved, UnobservedPublisher) {
		p.Unobserved = append(p.Unobserved, UnobservedPublisher)
		sort.Strings(p.Unobserved)
	}
	return p
}

// topologyDigest hashes the sorted set of direct dependency coordinates. A
// digest rather than the list itself: a baseline is meant to be committed and
// reviewed, and inlining every subtree would make it unreadable without
// answering any question the digest does not.
func topologyDigest(edges []graph.Edge, g *graph.Graph) string {
	var deps []string
	for _, e := range edges {
		if e.Type != graph.EdgeDependsOn {
			continue
		}
		if dep := g.Get(e.To); dep != nil && dep.Kind == graph.KindPackage {
			deps = append(deps, dep.ID)
		}
	}
	if len(deps) == 0 {
		return ""
	}
	sort.Strings(deps)
	sum := sha256.Sum256([]byte(strings.Join(deps, "\n")))
	return hex.EncodeToString(sum[:])
}

// hostOf extracts the host from a remote artifact reference. A reference that
// does not parse contributes nothing rather than a garbage host: an
// unparseable URL is already reported as evidence by the install-surface
// analyzer, and inventing a host here would put noise in a file meant to be
// diffed.
func hostOf(ref string) string {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// removeString returns a NEW slice without s. It never filters in place: a
// Profile is copied by value but its slices share backing arrays, and
// rewriting one in place would silently edit the profile a caller still holds.
func removeString(list []string, s string) []string {
	if !containsString(list, s) {
		return list
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
