//go:build !unix

package main

import "io/fs"

// dirIdentity is a no-op on platforms without a stable (device, inode) stat.
type dirIdentity struct{ n int }

// dirIdentityOf reports ok=false everywhere off Unix: WalkDir does not follow
// symlinks, so the only uncovered case is a mount loop, which these platforms do
// not create the same way. The unbounded walk proceeds without a cycle guard.
func dirIdentityOf(fs.DirEntry) (dirIdentity, bool) { return dirIdentity{}, false }
