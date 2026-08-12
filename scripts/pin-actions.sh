#!/usr/bin/env sh
# Pin every GitHub Action reference to an immutable commit SHA (finding R-03).
#
# A tag like @v4.2.2 is mutable: whoever controls the action's repository can
# repoint it at different code, and every workflow run picks that up silently.
# For a supply-chain security tool, running unpinned third-party code in the
# workflow that BUILDS AND SIGNS the release is the one dependency we cannot
# argue away. A commit SHA cannot be repointed.
#
# This rewrites `uses: owner/repo@vX.Y.Z` into
# `uses: owner/repo@<40-char-sha> # vX.Y.Z`, which is the form Dependabot
# understands and keeps updated — you get immutability AND automated updates.
#
# Usage:
#   sh scripts/pin-actions.sh            # resolve and rewrite in place
#   sh scripts/pin-actions.sh --check    # verify everything is pinned (CI)
#
# Requires the `gh` CLI, authenticated. Resolution goes through the GitHub API
# rather than a hardcoded table so the mapping is never stale or invented.
set -eu

WORKFLOW_DIR=".github/workflows"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

# A pinned reference is exactly 40 lowercase hex characters.
is_sha() {
  printf '%s' "$1" | grep -qE '^[0-9a-f]{40}$'
}

fail=0
found=0

for wf in "$WORKFLOW_DIR"/*.yml "$WORKFLOW_DIR"/*.yaml; do
  [ -e "$wf" ] || continue
  # Collect `uses:` references to third-party actions (skip local ./ and docker://).
  refs=$(grep -oE 'uses:[[:space:]]*[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@[A-Za-z0-9._-]+' "$wf" \
          | sed 's/uses:[[:space:]]*//' | sort -u || true)
  [ -n "$refs" ] || continue

  for ref in $refs; do
    found=$((found + 1))
    repo=${ref%@*}
    rev=${ref#*@}

    if is_sha "$rev"; then
      continue  # already immutable
    fi

    if [ "$CHECK_ONLY" -eq 1 ]; then
      echo "NOT PINNED: $wf: $repo@$rev"
      fail=1
      continue
    fi

    if ! command -v gh >/dev/null 2>&1; then
      echo "error: gh CLI is required to resolve $repo@$rev" >&2
      exit 1
    fi

    # Resolve the tag to a commit SHA. Annotated tags point at a tag object, so
    # dereference (^{}) to reach the commit.
    sha=$(gh api "repos/$repo/git/ref/tags/$rev" --jq '.object.sha' 2>/dev/null || true)
    type=$(gh api "repos/$repo/git/ref/tags/$rev" --jq '.object.type' 2>/dev/null || true)
    if [ "$type" = "tag" ] && [ -n "$sha" ]; then
      sha=$(gh api "repos/$repo/git/tags/$sha" --jq '.object.sha' 2>/dev/null || true)
    fi

    if ! is_sha "${sha:-}"; then
      echo "error: could not resolve $repo@$rev to a commit SHA" >&2
      fail=1
      continue
    fi

    echo "pinning $repo@$rev -> $sha"
    # Replace the reference and append the human-readable version as a comment.
    # Any pre-existing trailing comment on that line is replaced, not duplicated.
    tmp="$wf.tmp.$$"
    sed "s|uses:\([[:space:]]*\)$repo@$rev[[:space:]]*\(#.*\)\{0,1\}$|uses:\1$repo@$sha # $rev|" "$wf" > "$tmp"
    mv "$tmp" "$wf"
  done
done

if [ "$found" -eq 0 ]; then
  echo "no action references found under $WORKFLOW_DIR"
fi
if [ "$CHECK_ONLY" -eq 1 ] && [ "$fail" -eq 0 ]; then
  echo "all $found action reference(s) are pinned to immutable commit SHAs"
fi
exit "$fail"
