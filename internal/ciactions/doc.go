// Package ciactions exists only to host a test (finding R-03 P2): it asserts
// that every GitHub Action referenced by the repository's workflows is pinned to
// an immutable commit SHA with a human-readable version comment.
//
// This is the Go-test twin of scripts/pin-actions.sh --check. The shell check
// runs in CI; this one runs in `go test ./...`, so the pin invariant cannot
// silently drift out of the test suite the way a documentation note or a
// separate script can. Both must agree, and each fails the other's blind spot.
package ciactions
