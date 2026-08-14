package instsurf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/securefs"
)

// Typed extraction gaps (finding R-01).
//
// The containment primitive (F-03) correctly refuses to read a file that
// escapes the scan root, is not a regular file, or is oversized. But the
// adapters all consumed those refusals with the same `if err == nil` that they
// use for an optional file that simply is not on disk — so a REFUSAL and an
// ABSENCE were indistinguishable, and neither reached the verdict.
//
// That is attacker-triggerable invisibility: plant a symlink pointing out of the
// repo where a package directory belongs, and the install hook inside it is
// never read, never judged, and the scan still reports complete coverage with
// exit 0. The unsafe read is blocked and the evidence disappears with it.
//
// The distinction this file draws:
//
//	os.ErrNotExist                -> ABSENCE. Normal and expected: a pre-install
//	                                 tree has no node_modules, most packages ship
//	                                 no build.rs. Not a gap.
//	ErrOutsideRoot / ErrNotRegular /
//	ErrTooLarge / anything else   -> GAP. We were supposed to be able to read
//	                                 this and could not. Say so.
type GapReason string

const (
	// GapContainment is the security-relevant one: the path escaped the scan
	// root by traversal or symlink. Something was planted.
	GapContainment GapReason = "containment-refusal"
	// GapNotRegular means the target was a directory, device, socket, or fifo.
	GapNotRegular GapReason = "not-a-regular-file"
	// GapTooLarge means the file exceeded the per-file read cap.
	GapTooLarge GapReason = "file-too-large"
	// GapParse means the file was read but could not be understood.
	GapParse GapReason = "parse-error"
	// GapUnavailable means the dependency's source was expected but could not be
	// located (not vendored, not cached). Unlike ErrNotExist on a single file,
	// this is the entire package being absent — the scan cannot judge what is not
	// there.
	GapUnavailable GapReason = "source-unavailable"
	// GapIdentityMismatch means a candidate source directory exists but its
	// manifest declares a different package name or version than requested.
	GapIdentityMismatch GapReason = "identity-mismatch"
	// GapAmbiguousSource means multiple candidate source directories passed
	// identity validation for the same dependency. All candidates are scanned,
	// but the ambiguity itself is a coverage signal — a repository-controlled
	// duplicate could hide or suppress dependency-owned build code.
	GapAmbiguousSource GapReason = "ambiguous-source"
	// GapUnreadable is any other I/O failure (permissions, I/O error).
	GapUnreadable GapReason = "unreadable"
)

// Gap is one piece of install-surface material that was deliberately not read.
type Gap struct {
	Package string    // node ID, when known
	Path    string    // what we tried to read
	Reason  GapReason //
	Detail  string    // the underlying error text
}

func (g Gap) String() string {
	where := g.Path
	if g.Package != "" {
		where = g.Package + " (" + g.Path + ")"
	}
	return string(g.Reason) + ": " + where
}

// Classify maps an error to a gap reason, reporting ok=false when the error is
// an ordinary absence that should NOT be treated as a gap.
func Classify(err error) (GapReason, bool) {
	switch {
	case err == nil:
		return "", false
	case errors.Is(err, os.ErrNotExist), errors.Is(err, fs.ErrNotExist):
		return "", false
	case errors.Is(err, securefs.ErrOutsideRoot):
		return GapContainment, true
	case errors.Is(err, securefs.ErrNotRegular):
		return GapNotRegular, true
	case errors.Is(err, securefs.ErrTooLarge):
		return GapTooLarge, true
	default:
		return GapUnreadable, true
	}
}

// Gaps accumulates extraction gaps across the packages of one project.
type Gaps struct {
	list []Gap
}

// Add records err against pkg/path unless it is an ordinary absence. It returns
// true when a gap was recorded, so callers can branch on "was this a refusal?".
func (gs *Gaps) Add(pkg, path string, err error) bool {
	reason, ok := Classify(err)
	if !ok {
		return false
	}
	gs.list = append(gs.list, Gap{Package: pkg, Path: path, Reason: reason, Detail: err.Error()})
	return true
}

// AddReason records a gap whose reason is already known (for example a parse
// failure, which is not a securefs error).
func (gs *Gaps) AddReason(pkg, path string, reason GapReason, err error) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	gs.list = append(gs.list, Gap{Package: pkg, Path: path, Reason: reason, Detail: detail})
}

// Len reports how many gaps were recorded.
func (gs *Gaps) Len() int { return len(gs.list) }

// List returns the accumulated gaps.
func (gs *Gaps) List() []Gap { return gs.list }

// Err returns nil when nothing was refused, and otherwise a *GapError carrying
// every gap. Adapters return this from ExtractInstallSurface so the CLI can
// count and describe them rather than seeing one opaque error.
func (gs *Gaps) Err() error {
	if len(gs.list) == 0 {
		return nil
	}
	return &GapError{Gaps: gs.list}
}

// GapError is the error type carrying extraction gaps. Multiple package-level
// refusals aggregate into one of these without losing per-package detail.
type GapError struct {
	Gaps []Gap
}

func (e *GapError) Error() string {
	if len(e.Gaps) == 1 {
		return "install-surface gap: " + e.Gaps[0].String()
	}
	// Summarize by reason so a tree with 400 planted symlinks does not print 400
	// lines, while still naming what happened.
	counts := map[GapReason]int{}
	for _, g := range e.Gaps {
		counts[g.Reason]++
	}
	keys := make([]string, 0, len(counts))
	for r, n := range counts {
		keys = append(keys, fmt.Sprintf("%s x%d", r, n))
	}
	sort.Strings(keys)
	return fmt.Sprintf("%d install-surface gaps (%s)", len(e.Gaps), strings.Join(keys, ", "))
}

// GapsOf extracts the gaps carried by err, if any.
func GapsOf(err error) []Gap {
	var ge *GapError
	if errors.As(err, &ge) {
		return ge.Gaps
	}
	return nil
}
