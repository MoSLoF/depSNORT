#!/bin/bash
# Adversarial validation harness for depSNORT.
#
# Runs the SHIPPED BINARY against each attack fixture directory and fails if a
# scenario goes undetected. This is the end-to-end counterpart to
# adversarial_test.go: that suite builds graphs and surfaces in memory to
# exercise the analyzer and checks, while this one drives the whole pipeline —
# adapter detection, lockfile parsing, install-surface extraction, checks,
# verdict — the way an operator does.
#
# Both matter, and neither substitutes for the other. Repairing this harness is
# what surfaced two fixtures that had never actually scanned (one had no
# lockfile, so no adapter matched) and a path-handling defect in the Composer
# extractor that made a relative scan path miss a block-class cradle an
# absolute path caught.

set -euo pipefail
cd "$(dirname "$0")/../.."

PASS=0
FAIL=0
TOTAL=0
EXPECTED_SCENARIOS=8

BIN=${DEPSNORT_BIN:-}
if [ -z "$BIN" ]; then
    BIN=$(mktemp -u)
    go build -o "$BIN" ./cmd/depsnort
    trap 'rm -f "$BIN"' EXIT
fi

# subsumes: does a detected check ID satisfy an expectation?
#
# Exact match, or a STRONGER classification in the same family. VC-002b (network
# egress) is the weak form of both VC-002d (credentials + egress) and VC-002f
# (download cradle), and VC-002b deliberately stands down when the cradle
# capability is set, so expecting the weak form and receiving the strong one is
# the rule working, not a regression.
#
# Without this, tightening a rule breaks the harness and the pressure is to
# loosen the rule. The stale expectations this replaced were exactly that: they
# named VC-002b for two scenarios that now correctly classify as VC-002d and
# VC-002f.
subsumes() {
    local detected="$1" expected="$2"
    [ "$detected" = "$expected" ] && return 0
    case "$expected" in
        VC-002b) [ "$detected" = "VC-002d" ] || [ "$detected" = "VC-002f" ] ;;
        VC-002a) [ "${detected#VC-002}" != "$detected" ] ;;
        *) return 1 ;;
    esac
}

check() {
    local name="$1" dir="$2" expected_checks="$3"
    TOTAL=$((TOTAL + 1))

    local output found_checks
    output=$("$BIN" scan -no-registry -no-osv -format json "$dir" 2>/dev/null) || true
    found_checks=$(printf '%s' "$output" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print('')
    sys.exit(0)
print(','.join(sorted({f['check_id'] for f in d.get('verdict', {}).get('findings', [])})))
" 2>/dev/null || true)

    local missing=""
    local IFS=','
    for want in $expected_checks; do
        local ok=1
        for got in $found_checks; do
            if subsumes "$got" "$want"; then ok=0; break; fi
        done
        [ $ok -eq 0 ] || missing="$missing $want"
    done
    unset IFS

    if [ -z "$missing" ] && [ -n "$found_checks" ]; then
        echo "PASS  $name"
        echo "      detected: $found_checks"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $name"
        echo "      expected:${missing:-  (none missing, but nothing was detected)}"
        echo "      detected: ${found_checks:-(nothing)}"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

echo "============================================="
echo "  depSNORT Adversarial Validation"
echo "============================================="
echo ""

check "npm-postinstall-exfil (ua-parser-js style)" \
    "testdata/adversarial/npm-postinstall-exfil" \
    "VC-002a,VC-002b"

check "pypi-ctx-exfil (ctx PyPI attack)" \
    "testdata/adversarial/pypi-ctx-exfil" \
    "VC-002d"

check "npm-obfuscated-payload (event-stream style)" \
    "testdata/adversarial/npm-obfuscated-payload" \
    "VC-002e"

check "nuget-clickfix (caret+wildcard evasion)" \
    "testdata/adversarial/nuget-clickfix" \
    "VC-002b,VC-002e"

check "gem-extconf-payload (malicious extconf.rb)" \
    "testdata/adversarial/gem-extconf-payload" \
    "VC-002b"

check "cargo-buildrs-exfil (build.rs credential theft)" \
    "testdata/adversarial/cargo-buildrs-exfil" \
    "VC-002d"

check "composer-plugin-cradle (certutil download)" \
    "testdata/adversarial/composer-plugin-cradle" \
    "VC-002f"

# The propagation phase (D-152). The corpus covered the credential phase and the
# persistence phase of this family; the step that turns one victim into many had
# no scenario, because until VC-002k there was no check to fail. D-37's rule is
# that a check cannot be live in production while the corpus stays blind to it.
#
# VC-002d is expected alongside VC-002k: the fixture harvests a token and sends
# it, which is the exfil shape, and the two findings together are the point —
# the worm loop is credential theft PLUS republication.
check "npm-shai-hulud-propagation (worm republishes itself)" \
    "testdata/adversarial/npm-shai-hulud-propagation" \
    "VC-002d,VC-002k"

echo "============================================="
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
echo "============================================="

# The harness used to end here, exiting 0 whatever the tally said — so every
# scenario could fail and the run still reported success. Two of them had been
# failing exactly that way. A validation harness that cannot fail validates
# nothing.
if [ "$TOTAL" -ne "$EXPECTED_SCENARIOS" ]; then
    echo "ERROR: ran $TOTAL scenario(s), expected $EXPECTED_SCENARIOS — the run was cut short." >&2
    exit 1
fi
if [ "$FAIL" -ne 0 ]; then
    echo "ERROR: $FAIL attack scenario(s) went undetected." >&2
    exit 1
fi
