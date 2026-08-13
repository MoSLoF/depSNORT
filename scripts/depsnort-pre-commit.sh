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
# advisory CVE noise; set FAIL_ON_ELIGIBLE=1 and/or FAIL_ON_INCOMPLETE=1 to
# tighten.
set -eu

DEPSNORT="${DEPSNORT:-depsnort}"
TARGET="${TARGET:-.}"

if ! command -v "$DEPSNORT" >/dev/null 2>&1; then
  echo "depsnort: not found on PATH; skipping supply-chain gate" >&2
  exit 0
fi

set -- -recursive
[ "${FAIL_ON_ELIGIBLE:-0}" = "1" ] && set -- "$@" -fail-on-eligible
[ "${FAIL_ON_INCOMPLETE:-0}" = "1" ] && set -- "$@" -fail-on-incomplete
[ -n "${IOC:-}" ] && set -- "$@" -ioc "$IOC"

# Capture the scanner's exit status DIRECTLY (F-01). Running the scanner as an
# `if` condition and reading $? *after* `fi` is a trap: a completed if-statement
# with a false condition and no else clause returns 0, so $? would be 0 no
# matter what the scanner exited with (1/2/3). The `|| rc=$?` form both captures
# the true status and keeps `set -e` from aborting on a non-zero scan.
rc=0
"$DEPSNORT" scan "$@" -format json "$TARGET" >/dev/null || rc=$?

if [ "$rc" -eq 0 ]; then
  exit 0
fi
if [ "$rc" -eq 1 ] || [ "$rc" -eq 2 ] || [ "$rc" -eq 3 ]; then
  echo "" >&2
  echo "depsnort: commit blocked — supply-chain finding (exit $rc)." >&2
  echo "  review:  $DEPSNORT scan -recursive -format pdf -o ./reports $TARGET" >&2
  echo "  bypass:  git commit --no-verify   (only if you understand the finding)" >&2
  exit "$rc"
fi
# Tool/usage error (64/70, or anything unexpected): do not block the commit on
# our own failure — a broken scanner must not become a broken workflow.
echo "depsnort: scan errored (exit $rc); not blocking commit" >&2
exit 0
