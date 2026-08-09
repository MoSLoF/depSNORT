#!/bin/bash
# Adversarial validation harness for depSNORT
# Runs each synthetic attack fixture and reports detection results.

set -euo pipefail
cd "$(dirname "$0")/../.."

PASS=0
FAIL=0
TOTAL=0

check() {
    local name="$1"
    local dir="$2"
    local expected_checks="$3"  # comma-separated check IDs we expect to fire

    TOTAL=$((TOTAL + 1))

    # Run scan
    local output
    output=$(go run ./cmd/depsnort scan -no-registry -no-osv "$dir" 2>/dev/null) || true

    local findings
    findings=$(echo "$output" | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = data.get('verdict', {}).get('findings', [])
checks = set()
evidence = []
for f in findings:
    checks.add(f['check_id'])
    evidence.append(f['check_id'] + ': ' + f.get('title', ''))
print('CHECKS=' + ','.join(sorted(checks)))
for e in evidence:
    print('  ' + e)
" 2>/dev/null)

    local found_checks
    found_checks=$(echo "$findings" | head -1 | sed 's/CHECKS=//')

    # Check if all expected checks fired
    local all_found=true
    IFS=',' read -ra EXPECTED <<< "$expected_checks"
    for chk in "${EXPECTED[@]}"; do
        if ! echo "$found_checks" | grep -q "$chk"; then
            all_found=false
        fi
    done

    if $all_found && [ -n "$found_checks" ]; then
        echo "PASS  $name"
        echo "      detected: $found_checks"
        echo "$findings" | tail -n +2 | head -5
        PASS=$((PASS + 1))
    else
        echo "FAIL  $name"
        echo "      expected: $expected_checks"
        echo "      detected: $found_checks"
        echo "$findings" | tail -n +2 | head -5
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
    "VC-002a"

check "pypi-ctx-exfil (ctx PyPI attack)" \
    "testdata/adversarial/pypi-ctx-exfil" \
    "VC-002b"

check "npm-obfuscated-payload (event-stream style)" \
    "testdata/adversarial/npm-obfuscated-payload" \
    "VC-002a"

check "nuget-clickfix (caret+wildcard evasion)" \
    "testdata/adversarial/nuget-clickfix" \
    "VC-002b"

check "gem-extconf-payload (malicious extconf.rb)" \
    "testdata/adversarial/gem-extconf-payload" \
    "VC-002b"

check "cargo-buildrs-exfil (build.rs credential theft)" \
    "testdata/adversarial/cargo-buildrs-exfil" \
    "VC-002b"

check "composer-plugin-cradle (certutil download)" \
    "testdata/adversarial/composer-plugin-cradle" \
    "VC-002b"

echo "============================================="
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
echo "============================================="
