//go:build unix

package main

import (
	"io/fs"
	"syscall"
)

// dirIdentity is a directory's filesystem identity: (device, inode). Two paths
// with the same identity are the same directory, which is how a bind-mount or
// loopback cycle is detected during the unbounded walk (OPU-22).
type dirIdentity struct{ dev, ino uint64 }

// dirIdentityOf returns the (device, inode) identity of a directory entry. It is
// best-effort: if the stat is unavailable it returns ok=false and the walk
// proceeds without cycle protection for that entry (WalkDir never follows
// symlinks, so the only uncovered case is an exotic mount loop).
func dirIdentityOf(d fs.DirEntry) (dirIdentity, bool) {
	info, err := d.Info()
	if err != nil {
		return dirIdentity{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return dirIdentity{}, false
	}
	return dirIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}
