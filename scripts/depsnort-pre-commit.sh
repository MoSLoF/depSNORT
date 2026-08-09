#!/usr/bin/env sh
# depsnort pre-commit hook — block a commit that introduces a block-class
# supply-chain finding (Decision D-09 / D-30). Static and zero-execution: it
# reads the lockfiles in your tree, never installs anything.
#
# Install:
#   ln -s ../../scripts/depsnort-pre-commit.sh .git/hooks/pre-commit
# or add to .pre-commit-config.yaml as a local 'system' hook that runs this.
#
# Honors the same env as the CI gate (IOC=, DEPSNORT=, TARGET=). By design it
# only hard-fails on BLOCK so day-to-day commits are not held hostage by
# advisory CVE noise; set FAIL_ON_ELIGIBLE=1 to tighten.
set -eu

DEPSNORT="${DEPSNORT:-depsnort}"
TARGET="${TARGET:-.}"

if ! command -v "$DEPSNORT" >/dev/null 2>&1; then
  echo "depsnort: not found on PATH; skipping supply-chain gate" >&2
  exit 0
fi

set -- -recursive
[ "${FAIL_ON_ELIGIBLE:-0}" = "1" ] && set -- "$@" -fail-on-eligible
[ -n "${IOC:-}" ] && set -- "$@" -ioc "$IOC"

if "$DEPSNORT" scan "$@" -format json "$TARGET" >/dev/null; then
  exit 0
fi
rc=$?
if [ "$rc" -eq 1 ] || [ "$rc" -eq 2 ] || [ "$rc" -eq 3 ]; then
  echo "" >&2
  echo "depsnort: commit blocked — supply-chain finding (exit $rc)." >&2
  echo "  review:  $DEPSNORT scan -recursive -format pdf -o ./reports $TARGET" >&2
  echo "  bypass:  git commit --no-verify   (only if you understand the finding)" >&2
  exit "$rc"
fi
# Tool/usage error (64/70): do not block the commit on our own failure.
echo "depsnort: scan errored (exit $rc); not blocking commit" >&2
exit 0
