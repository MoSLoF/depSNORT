#!/bin/sh
# Regenerates internal/datasource/osv/bundled_snapshot.json — the OSV
# fallback dataset compiled into the depsnort binary — from a LIVE query
# against this repo's own real-world reference fixtures.
#
# Requires actual network access to api.osv.dev. Run this from CI or any
# environment that isn't network-restricted (see docs/RELEASING.md); it fails
# loudly rather than writing an empty or partial dataset if nothing exports
# cleanly, so a blocked run can never silently commit stale/missing coverage.
#
# Usage: sh scripts/refresh-bundled-snapshot.sh

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BIN="$TMP/depsnort"
go build -o "$BIN" ./cmd/depsnort

# The "popular packages" reference list: this repo's own real-world fixtures
# — real, well-known packages pinned to real published versions, already
# maintained for exercising live OSV/registry lookups end to end (see the
# comment at the top of each fixture's lockfile). Grow this list by adding
# more reference project directories here as ecosystem coverage expands;
# nothing else in the pipeline needs to change.
REFS="internal/ecosystem/npm/testdata/realworld internal/ecosystem/pypi/testdata/realworld"

i=0
FILES=""
for ref in $REFS; do
  i=$((i + 1))
  out="$TMP/export-$i.json"
  echo "exporting: $ref"
  # The scan's own exit code reflects its VERDICT (findings against the
  # reference fixtures' deliberately-vulnerable pins), not export success —
  # ignore it here and check for the export file itself below.
  "$BIN" scan -osv-export "$out" -no-registry -no-install-surface "$ref" >"$TMP/log-$i.txt" 2>&1 || true
  if [ -f "$out" ]; then
    FILES="$FILES $out"
  else
    echo "warning: export skipped for $ref (no live OSV query succeeded); see $TMP/log-$i.txt" >&2
    cat "$TMP/log-$i.txt" >&2
  fi
done

if [ -z "$FILES" ]; then
  echo "error: no reference project produced an export — nothing to merge." >&2
  echo "This usually means api.osv.dev is unreachable from this environment." >&2
  echo "bundled_snapshot.json was NOT modified." >&2
  exit 1
fi

python3 - "$FILES" <<'PY'
import datetime
import json
import sys

files = sys.argv[1].split()
merged = {}
for f in files:
    with open(f) as fh:
        entries = json.load(fh)
    for e in entries:
        key = (e["ecosystem"], e["name"], e["version"])
        merged[key] = e  # a later export of the same coordinate wins

out = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "entries": [merged[k] for k in sorted(merged)],
}
dest = "internal/datasource/osv/bundled_snapshot.json"
with open(dest, "w") as fh:
    json.dump(out, fh, indent=2)
    fh.write("\n")
print(f"wrote {len(out['entries'])} entries to {dest} (generated_at={out['generated_at']})")
PY
