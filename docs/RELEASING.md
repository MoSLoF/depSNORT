# Releasing depSNORT

A short, ordered checklist. The point of writing it down is that the parts most
likely to be forgotten are the ones with no immediate symptom — a stale cache
semantics version or an unpinned action does not break the build, it silently
weakens a guarantee.

## Before tagging

0. **The candidate must be a commit, not a directory.** This is first because it
   is the step whose omission produced the v0.7.3 mess: four "release candidate"
   archives, none of them committed, two of which did not compile, and a `v0.7.3`
   tag pointing at the v0.6.1 commit. Nothing below is meaningful if the thing you
   validated is not the thing you tag.

   ```
   git status --porcelain      # must be empty
   git log -1 --oneline        # this commit is the candidate
   ```

   If a review produced an archive, apply it to this tree and commit it *before*
   validating. Never validate an archive and tag a repo.

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

4. **Refresh the compiled-in OSV fallback dataset, from an environment with
   real network access:**

   ```
   make refresh-bundled-snapshot
   ```

   This regenerates `internal/datasource/osv/bundled_snapshot.json` — the
   last tier of the cache -> live query -> bundled -> gap resolution chain —
   from a live query against this repo's own real-world reference fixtures
   (`internal/ecosystem/{npm,pypi}/testdata/realworld`). It fails loudly and
   leaves the committed file untouched if it can't reach `api.osv.dev` — do
   not run this from a network-restricted sandbox or CI runner and do not
   force a stale result through. Skipping this step on a given release is
   fine (the dataset just carries an older `generated_at`, which stays
   honestly disclosed on every scan that uses it); committing a corrupted or
   silently-stale one is not. `git diff` the result before committing.

   If you're working from an environment with no outbound network access
   (a network-restricted sandbox, for instance — GitHub-hosted Actions
   runners are not behind that kind of restriction), run the
   `refresh-bundled-snapshot` workflow instead: Actions tab -> select it ->
   "Run workflow". It's `workflow_dispatch`-only (no `schedule:`) and never
   pushes to `main` directly — it opens a PR with the regenerated file for
   review, same as any other change. This is deliberate: a scheduled job
   with standing write access to refresh a security-advisory dataset
   unattended is real attack surface this project doesn't need for
   something that's fine to refresh by hand a few times a release.

5. **Run the full pre-tag suite on the exact candidate:**

   ```
   test -z "$(gofmt -l .)"          # formatting clean
   go vet ./...
   go test -race ./...              # includes fuzz seeds, e2e gap tests, pin drift
   sh scripts/wrapper_test.sh       # exit-code contract
   make self-audit                  # module graph is one line (D-10)
   ./depsnort sbom -release | head  # release-scoped SBOM emits
   ```

   Optionally a longer fuzz pass and the cross-build matrix (both are CI jobs).

## Publishing the sterile tree

The public repo is generated, never hand-edited (D-38):

```
sh scripts/make-public.sh ../depSNORT-public
```

Requires the Go toolchain: gofmt normalizes indentation shifted by the sentinel
unwrap, so generation without it is not byte-reproducible. The script refuses to
start if gofmt is missing (exit 1), and exits 2 on any leaked marker. It prints
the toolchain version it used — record that with the release evidence.

Copy the output over the public working tree, review `git diff` there, and commit.
A non-zero exit means a private marker survived — fix the source or add a
`PRIVATE` / `PUBLIC:` sentinel and re-run. Do not publish past a failure.

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
