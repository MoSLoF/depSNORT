// Package versiondrift exists only to host a test: it asserts that every
// release-version literal in README.md matches the version declared in
// pyproject.toml.
//
// pyproject.toml is the single source of the release version (F-06 / D-33).
// The Go binary, the wheel tag, the SBOM, and release.yml's tag gate all derive
// from it, so they cannot drift. README.md is the exception — it carries two
// hardcoded literals that derive from nothing: the "baked-in version" note and
// the `gh attestation verify depsnort-vX.Y.Z-…` example.
//
// Before this test, nothing compared them to anything. release.yml gates only
// the TAG against pyproject.toml, so a bump that edited pyproject.toml and
// forgot the README shipped a README advertising the previous release with
// every check green. docs/RELEASING.md names both sites and supplies a grep,
// but a checklist item is the weakest possible guard: an earlier revision of
// that same document asserted "nothing else carries a version literal," which
// was false, and is precisely how a stale README nearly shipped.
//
// This is the same discipline as internal/ciactions — an invariant that used to
// live in prose now fails the Go suite instead of decaying quietly.
package versiondrift
