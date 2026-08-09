#!/usr/bin/env sh
# depsnort CI gate — a thin wrapper over the CLI (Decision D-09 / D-30).
#
# Runs a static, zero-execution supply-chain scan and fails the build on
# block-class findings. Opt in to stricter gates via env:
#
#   FAIL_ON_ELIGIBLE=1   also fail on gate-eligible warnings   (exit 2)
#   FAIL_ON_INCOMPLETE=1 also fail on degraded resolution       (exit 3)
#   IOC=/path/to/ledger.json   cross-check against your IOC ledger (VC-003)
#   TARGET=.             directory to scan (default: current dir)
#   DEPSNORT=depsnort    path to the binary
#   REPORT_DIR=          if set, also write a dated PDF report tree there
#
# Exit codes are the depsnort contract, so CI reads them directly:
#   0 clean/advisory  1 block  2 gate-eligible  3 incomplete  64/70 tool error
set -eu

DEPSNORT="${DEPSNORT:-depsnort}"
TARGET="${TARGET:-.}"

# A CI gate scans the whole repo tree, so -recursive is always right.
set -- -recursive
[ "${FAIL_ON_ELIGIBLE:-0}" = "1" ] && set -- "$@" -fail-on-eligible
[ "${FAIL_ON_INCOMPLETE:-0}" = "1" ] && set -- "$@" -fail-on-incomplete
[ -n "${IOC:-}" ] && set -- "$@" -ioc "$IOC"
true  # keep the last conditional's status from tripping set -e

# Human-readable SARIF for the CI security tab, if the platform ingests it.
if [ -n "${REPORT_DIR:-}" ]; then
  "$DEPSNORT" scan "$@" -format pdf -o "$REPORT_DIR" "$TARGET" || true
fi

echo "depsnort: gating $TARGET"
"$DEPSNORT" scan "$@" -format sarif "$TARGET" > "${SARIF_OUT:-depsnort.sarif}" || rc=$?
rc="${rc:-0}"
echo "depsnort: exit $rc (0 clean/advisory, 1 block, 2 gate-eligible, 3 incomplete)"
exit "$rc"
