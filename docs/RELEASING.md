# Releasing depSNORT

A short, ordered checklist. The point of writing it down is that the parts most
likely to be forgotten are the ones with no immediate symptom — a stale cache
semantics version or an unpinned action does not break the build, it silently
weakens a guarantee.

## Before tagging

1. **Bump the version in one place.** Edit `version` in `pyproject.toml`. Nothing
   else carries a version literal — the Go binary, the wheel tag, the SBOM, and
   `py/depsnort/__init__.py` all derive from it (D-33 / F-06). Confirm:

   ```
   make build && ./depsnort version      # must print the new version
   ```

2. **Bump the sdist cache semantics if extraction meaning changed.** If this
   release changes *what a cached sdist-extraction record is allowed to mean* —
   a new hostile-input bound, a changed digest rule, a new fail-closed path — bump
   `sdistSemantics` in `internal/ecosystem/pypi/sdist.go`. This invalidates
   records written under the old rules so a weaker analysis cannot survive an
   upgrade as a cached clean result (D-35). Changing the record *shape* alone
   (a new JSON field) does not require a bump; changing its *meaning* does. When
   in doubt, bump — a needless cache miss is cheap, a stale fail-open record is
   not.

3. **Pin every workflow action to an immutable SHA.** New or updated actions must
   be commit-SHA pinned with a version comment:

   ```
   make pin          # resolves any tags via authenticated gh
   make pin-check    # must exit 0
   ```

   The Go suite enforces the same invariant (`internal/ciactions`), so a drift
   here also fails `go test`.

4. **Run the full pre-tag suite on the exact candidate:**

   ```
   test -z "$(gofmt -l .)"          # formatting clean
   go vet ./...
   go test -race ./...              # includes fuzz seeds, e2e gap tests, pin drift
   sh scripts/wrapper_test.sh       # exit-code contract
   make self-audit                  # module graph is one line (D-10)
   ./depsnort sbom -release | head  # release-scoped SBOM emits
   ```

   Optionally a longer fuzz pass and the cross-build matrix (both are CI jobs).

## Tagging

```
git tag vX.Y.Z            # must equal pyproject.toml — release.yml enforces this
git push origin main --tags
```

Pushing the tag fires `.github/workflows/release.yml`, which rebuilds the five
platform binaries, generates a platform-neutral SBOM, writes `SHA256SUMS`, signs
keyless SLSA build-provenance attestations via GitHub OIDC, and publishes the
GitHub Release with the `gh` CLI.

## After tagging

- Confirm the release workflow went green — the **attestation step only runs
  under real GitHub OIDC**, so its first execution on a tag is its first true
  test.
- Spot-check a consumer verification path:

  ```
  gh attestation verify depsnort-vX.Y.Z-linux-amd64 --repo MoSLoF/depSNORT
  sha256sum -c SHA256SUMS --ignore-missing
  ```
