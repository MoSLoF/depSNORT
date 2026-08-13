#!/usr/bin/env sh
# Wrapper exit-code regression test for depsnort-pre-commit.sh (F-01).
#
# Stubs the scanner to return each supported exit code and asserts the hook's
# block-vs-pass mapping. Portable across POSIX shells (bash, dash, macOS sh) —
# run it under each: `sh scripts/wrapper_test.sh`, `bash …`, `dash …`.
#
# Contract under test:
#   scanner 0  -> hook 0   (clean/advisory: allow the commit)
#   scanner 1  -> hook 1   (block-class finding: stop the commit)
#   scanner 2  -> hook 2   (gate-eligible, opted in: stop)
#   scanner 3  -> hook 3   (incomplete coverage, opted in: stop)
#   scanner 64 -> hook 0   (usage error: our fault, don't block the commit)
#   scanner 70 -> hook 0   (internal error: our fault, don't block the commit)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
HOOK="$HERE/depsnort-pre-commit.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Stub scanner: exits with the code in STUB_RC, ignoring all arguments and
# writing nothing to stdout (the hook redirects stdout to /dev/null anyway).
stub="$tmp/depsnort"
cat > "$stub" <<'STUB'
#!/usr/bin/env sh
exit "${STUB_RC:-0}"
STUB
chmod +x "$stub"

fail=0
check() {
  scan_rc="$1"; want="$2"
  STUB_RC="$scan_rc" DEPSNORT="$stub" TARGET="$tmp" "$HOOK" >/dev/null 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: scanner exit $scan_rc -> hook exit $got (want $want)"
    fail=1
  else
    echo "ok:   scanner exit $scan_rc -> hook exit $got"
  fi
}

check 0  0
check 1  1
check 2  2
check 3  3
check 64 0
check 70 0

if [ "$fail" -eq 0 ]; then
  echo "PASS: pre-commit wrapper preserves every exit code"
else
  echo "FAILED: pre-commit wrapper mishandles at least one exit code"
fi
exit "$fail"
