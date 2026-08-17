package graph

import "strings"

// Dependency-source provenance (Decision D-41).
//
// A lockfile records not just WHICH version was selected but WHERE it came
// from, and the two facts carry very different amounts of verifiability. A
// crate pinned to crates.io has a global coordinate: an advisory feed can be
// asked about it, and the answer means something. A crate vendored in-tree as a
// path dependency, or pulled from a git URL, has no such coordinate — an OSV
// lookup for it can only ever return nothing, and that nothing is not evidence
// of health.
//
// Before these keys existed the distinction was parsed and discarded. Every
// adapter read the source field and either dropped it or filed it under an
// ecosystem-private attribute nothing consumed, so a vendored fork and a
// registry package were indistinguishable to every downstream stage. A real
// field review of a Rust project had to reconstruct the classification by hand
// to know which two of its 246 lockfile nodes actually needed review.
//
// These keys are ECOSYSTEM-NEUTRAL for the same reason the coverage keys are
// (D-24): provenance is a property of the scan's verifiability, and the verdict
// layer must read it without knowing which adapter produced the graph. An
// adapter records where a package came from; it never decides what that means.
// (Extraction vs judgment, D-03.)
const (
	// AttrSourceClass is how verifiable the package's origin is: one of the
	// SourceClass constants below.
	AttrSourceClass = "depsnort.source_class"
	// AttrSourceRef is the origin itself — a git URL, a local path, or the
	// registry URL — recorded so a report can name what it could not verify
	// rather than merely counting it.
	AttrSourceRef = "depsnort.source_ref"
)

// SourceClass values. Only SourceRegistry carries a coordinate that advisory
// data sources can be meaningfully queried about; everything else is a package
// whose contents this tool takes on faith from the lockfile.
const (
	// SourceRegistry: resolved from an ecosystem package registry.
	SourceRegistry = "registry"
	// SourceGit: resolved from a git URL. Pinned to a revision at best, and
	// mutable underneath the pin at worst (a force-push replaces the code a
	// tag names).
	SourceGit = "git"
	// SourcePath: a local path or workspace member — vendored source. Often a
	// STRONGER posture than a git dependency (in-repo, auditable, immune to an
	// upstream force-push), but its contents were never published anywhere an
	// advisory feed indexes.
	SourcePath = "path"
	// SourceURL: fetched from a direct artifact URL that is not a known
	// registry endpoint.
	SourceURL = "url"
	// SourceUnknown: the lockfile records no origin at all.
	SourceUnknown = "unknown"
)

// Verifiable reports whether a source class has a registry coordinate that an
// advisory lookup can speak to. This is the single predicate the coverage layer
// and VC-009 share, so "which sources count as scannable" is defined once.
//
// Note that adapters record a class only on POSITIVE evidence from the
// lockfile: a node carrying no class at all is not "unknown", it is a node
// whose adapter had nothing to say. Coverage skips those rather than passing
// them through here, so a format that simply does not record origins cannot
// manufacture a scan-wide gap (the D-24 flat-resolution precedent: a limitation
// of the format is disclosed, not charged to the scan).
func Verifiable(class string) bool { return class == SourceRegistry }

// SetSource records a package's origin on a node. An empty class is ignored so
// callers can pass a classification result through unconditionally.
func (n *Node) SetSource(class, ref string) {
	if class == "" {
		return
	}
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	n.Attr[AttrSourceClass] = class
	if ref != "" {
		n.Attr[AttrSourceRef] = ref
	}
}

// SourceOf returns a node's recorded source class and reference. A node with no
// recorded class reports SourceUnknown, never an empty string, so a caller can
// switch on the result without a nil-ish special case.
func (n *Node) SourceOf() (class, ref string) {
	if n == nil || n.Attr == nil {
		return SourceUnknown, ""
	}
	class = n.Attr[AttrSourceClass]
	if class == "" {
		class = SourceUnknown
	}
	return class, n.Attr[AttrSourceRef]
}

// ClassifyRef classifies an origin string that is a URL or a path. It covers the
// shapes that recur across lockfile formats — git URLs in several spellings,
// file/path references, and plain artifact URLs — and leaves registry
// recognition to the caller, which is the only party that knows its own
// ecosystem's registry hosts.
//
// Returns SourceUnknown for an empty ref so an absent field never silently
// becomes a claim.
func ClassifyRef(ref string) string {
	r := strings.TrimSpace(ref)
	if r == "" {
		return SourceUnknown
	}
	lower := strings.ToLower(r)

	switch {
	case strings.HasPrefix(lower, "git+"),
		strings.HasPrefix(lower, "git:"),
		strings.HasPrefix(lower, "git@"),
		strings.HasPrefix(lower, "github:"),
		strings.HasPrefix(lower, "gitlab:"),
		strings.HasPrefix(lower, "bitbucket:"),
		strings.HasSuffix(lower, ".git"):
		return SourceGit
	case strings.HasPrefix(lower, "file:"),
		strings.HasPrefix(lower, "link:"),
		strings.HasPrefix(lower, "path+"),
		strings.HasPrefix(lower, "./"),
		strings.HasPrefix(lower, "../"),
		strings.HasPrefix(lower, "/"):
		return SourcePath
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return SourceURL
	}
	return SourceUnknown
}
