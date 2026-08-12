// Package securefs is the one contained-read primitive for every place depsnort
// reads a file whose path derives from untrusted repository content — a lockfile
// package name, a PSR-4 directory, an install-hook reference. It is the single
// answer to finding F-03: reject absolute and traversal inputs, resolve
// symlinks, confirm the canonical target stays inside the scan root, refuse
// anything that is not a regular file, and cap the bytes read.
//
// The threat is not a live attacker racing the scanner (there is no TOCTOU game
// to win against a one-shot static read); it is a hostile *checkout* — a crafted
// lockfile, a symlink committed into a repo — steering an ordinary os.ReadFile
// into /etc/shadow or a 10 GiB device. Canonicalize, contain, then read.
package securefs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMaxFileBytes bounds a single contained read. Install manifests and hook
// scripts are kilobytes; 16 MiB is generous headroom while still refusing an
// artifact planted to exhaust memory.
const DefaultMaxFileBytes = 16 << 20

var (
	// ErrOutsideRoot means a resolved path escaped the scan root (via traversal,
	// an absolute path, or a symlink pointing out of the tree).
	ErrOutsideRoot = errors.New("path escapes scan root")
	// ErrNotRegular means the target is a directory, device, socket, or fifo —
	// not something a static analyzer should slurp.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge means the file exceeds the reader's per-file cap.
	ErrTooLarge = errors.New("file exceeds size limit")
)

// Reader is a scan-root-bound file reader. Every read is contained to the root
// it was constructed with.
type Reader struct {
	absRoot   string // filepath.Abs(root) — the lexical root, for a cheap pre-check
	canonRoot string // EvalSymlinks(absRoot) — the real root, for the post-check
	maxBytes  int64
}

// NewReader binds a reader to root. The root must exist; its own symlinks are
// resolved once so later containment checks can compare canonical paths. Both
// the lexical and canonical roots are kept: a caller may build paths from the
// lexical root string, while symlink escapes are judged against the canonical
// one.
func NewReader(root string) (*Reader, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("securefs: resolve root %q: %w", root, err)
	}
	return &Reader{absRoot: filepath.Clean(abs), canonRoot: canon, maxBytes: DefaultMaxFileBytes}, nil
}

// Root returns the lexical (pre-symlink) scan root the reader was built with.
func (r *Reader) Root() string { return r.absRoot }

func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// ReadFile reads p — absolute, or relative to the reader's root — and returns
// its bytes only if the file is a regular file whose canonical path is inside
// root and whose size is within the cap. A file that does not exist returns an
// error satisfying errors.Is(err, os.ErrNotExist), so optional reads stay
// ergonomic (`if b, err := r.ReadFile(x); err == nil { ... }`).
func (r *Reader) ReadFile(p string) ([]byte, error) {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(r.absRoot, p)
	}
	abs = filepath.Clean(abs)

	// Lexical pre-check: reject a ".."-escape or an absolute-outside path before
	// touching the filesystem at all.
	if !within(abs, r.absRoot) {
		return nil, fmt.Errorf("securefs: %q: %w", p, ErrOutsideRoot)
	}

	// Resolve symlinks and re-check containment on the CANONICAL path. A symlink
	// that lives inside root but points out of it is exactly the escape the
	// lexical check cannot see.
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err // wraps os.ErrNotExist for a missing optional file
	}
	if !within(canon, r.canonRoot) {
		return nil, fmt.Errorf("securefs: %q -> %q: %w", p, canon, ErrOutsideRoot)
	}

	// canon has no symlinks left, so Lstat and Stat agree here.
	info, err := os.Lstat(canon)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("securefs: %q: %w", p, ErrNotRegular)
	}
	if info.Size() > r.maxBytes {
		return nil, fmt.Errorf("securefs: %q (%d bytes): %w", p, info.Size(), ErrTooLarge)
	}

	f, err := os.Open(canon)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// LimitReader is belt-and-suspenders against a file that grew between Stat
	// and Open; the Stat cap above is the primary guard.
	return io.ReadAll(io.LimitReader(f, r.maxBytes))
}

// Contains reports whether p resolves to a path inside the scan root. Unlike
// ReadFile it does not require a regular file, so callers can vet a DIRECTORY
// before enumerating it — listing a symlinked-out directory leaks its entry
// names even when every subsequent read is refused. A path that does not exist
// is not contained (there is nothing to enumerate).
func (r *Reader) Contains(p string) bool {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(r.absRoot, p)
	}
	abs = filepath.Clean(abs)
	if !within(abs, r.absRoot) {
		return false
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return false
	}
	return within(canon, r.canonRoot)
}

// Exists reports whether p resolves to a regular file contained within root.
// It never reads the file and never follows an escaping symlink.
func (r *Reader) Exists(p string) bool {
	b, err := r.stat(p)
	return err == nil && b
}

func (r *Reader) stat(p string) (bool, error) {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(r.absRoot, p)
	}
	abs = filepath.Clean(abs)
	if !within(abs, r.absRoot) {
		return false, ErrOutsideRoot
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return false, err
	}
	if !within(canon, r.canonRoot) {
		return false, ErrOutsideRoot
	}
	info, err := os.Lstat(canon)
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}
