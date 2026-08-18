#!/bin/sh
# Regenerates internal/datasource/osv/bundled_snapshot.json — the OSV fallback
# dataset compiled into the depsnort binary — from LIVE known-malicious-package
# advisories published by OSV.
#
# WHY MALICIOUS RECORDS AND NOTHING ELSE (finding DS-REV-01):
#
# This tier exists to answer one question when neither the cache nor a live
# query can: "is this package@version known-malicious?" — the offline stand-in
# for VC-001. An earlier revision of this script seeded the dataset by scanning
# this repo's `realworld` fixtures, which are real popular packages pinned to
# deliberately VULNERABLE versions. That yields GHSA/CVE records and, by
# construction, never a single MAL-* record. The shipped dataset therefore held
# 156 advisories, none of them malicious, while the binary reported those
# coordinates as covered by the fallback tier. An offline scan of a bundled
# coordinate returned "clean, exit 0" from a dataset that had never looked for
# malware.
#
# The fix is in two halves and both are required. The scanner half
# (internal/datasource/osv) refuses to count a non-malicious entry as coverage.
# This half makes sure there is real malicious intelligence to count.
#
# Requires actual network access to OSV's public exports. It fails loudly rather
# than writing a partial or non-malicious dataset, so a blocked or degraded run
# can never silently commit a fallback tier that answers nothing.
#
# Usage: sh scripts/refresh-bundled-snapshot.sh

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# OSV publishes one zip of every record per ecosystem. There is no smaller
# index of malicious records alone, so the zip is fetched and only its MAL-*
# members are decompressed — a zip member is individually addressable, so the
# 200 MB npm archive costs bandwidth but not much CPU or memory.
#
# Ecosystem names are OSV's, not depSNORT's; the mapping to depSNORT ecosystem
# strings lives in the Python block below.
ECOSYSTEMS="npm PyPI crates.io RubyGems Packagist NuGet"

# Per-ecosystem cap on COORDINATES, newest advisory first. Malicious packages
# are pulled from registries quickly, so recency is the right selection axis:
# the coordinates most likely to still be sitting in someone's lockfile are the
# recent ones.
#
# The cap counts coordinates rather than advisories because that is what
# determines both lookup coverage and the size compiled into every binary. One
# advisory can enumerate hundreds of bad versions — capping advisories let NuGet
# contribute 4411 coordinates while crates.io contributed 11, which is not
# ecosystem diversity, it is whichever ecosystem happened to enumerate versions
# most aggressively.
PER_ECOSYSTEM=${PER_ECOSYSTEM:-400}

for eco in $ECOSYSTEMS; do
  echo "fetching: $eco"
  if ! curl -fsSL --retry 3 --retry-delay 2 \
      -o "$TMP/$eco.zip" \
      "https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip"; then
    echo "warning: could not fetch $eco export" >&2
    rm -f "$TMP/$eco.zip"
  fi
done

python3 - "$TMP" "$PER_ECOSYSTEM" <<'PY'
import datetime
import json
import os
import sys
import zipfile

tmp, per_eco = sys.argv[1], int(sys.argv[2])

# OSV ecosystem name -> depSNORT ecosystem string (must match purl types used
# by the adapters, which is what Coord.Key() is built from).
ECO_MAP = {
    "npm": "npm",
    "PyPI": "pypi",
    "crates.io": "cargo",
    "RubyGems": "gem",
    "Packagist": "composer",
    "NuGet": "nuget",
}


def normalize(eco, name):
    """Apply the SAME name normalization the matching adapter applies.

    A bundled entry is found by an exact Coord.Key() match, so a name recorded
    in a different form than the adapter produces is a coordinate that can
    never be hit. That failure is invisible — the dataset looks populated and
    simply never matches — which is a quieter version of the DS-REV-01 defect
    this script exists to fix.
    """
    if eco == "pypi":
        # PEP 503: lowercase, runs of -, _ and . collapse to a single -.
        # Mirrors purl.NormalizePyPI.
        out, prev_sep = [], False
        for ch in name.lower():
            if ch in "-_.":
                if not prev_sep:
                    out.append("-")
                prev_sep = True
            else:
                out.append(ch)
                prev_sep = False
        return "".join(out)
    if eco == "nuget":
        # The NuGet adapter lowercases package names.
        return name.lower()
    # npm (case-sensitive, scoped names keep their @scope/ form), cargo, gem,
    # and composer are recorded verbatim by their adapters.
    return name

def published(rec):
    return rec.get("published") or rec.get("modified") or ""

entries = {}
per_eco_counts = {}

for osv_eco, our_eco in ECO_MAP.items():
    path = os.path.join(tmp, f"{osv_eco}.zip")
    if not os.path.exists(path):
        continue
    records = []
    with zipfile.ZipFile(path) as z:
        # Only MAL-* members are decompressed. Everything else in the archive
        # is an ordinary vulnerability and is not what this tier is for.
        for name in z.namelist():
            base = os.path.basename(name)
            if not base.startswith("MAL-") or not base.endswith(".json"):
                continue
            try:
                rec = json.loads(z.read(name))
            except Exception:
                continue
            records.append(rec)

    records.sort(key=published, reverse=True)
    coords_kept = 0
    for rec in records:
        if coords_kept >= per_eco:
            break
        vid = rec.get("id", "")
        summary = rec.get("summary") or rec.get("details") or ""
        summary = " ".join(summary.split())[:300]
        coords = []
        for aff in rec.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem", "").split(":")[0] != osv_eco:
                continue
            name = pkg.get("name")
            if not name:
                continue
            versions = aff.get("versions") or []
            # A malicious advisory normally enumerates the exact bad versions.
            # One that does not cannot be pinned to a coordinate, so it is
            # skipped rather than recorded against a version it may not affect.
            for v in versions:
                coords.append((name, v))
        if not coords:
            continue
        for name, version in coords:
            if coords_kept >= per_eco:
                break
            key = (our_eco, normalize(our_eco, name), version)
            adv = {
                "id": vid,
                "summary": summary,
                "severity": "critical",
                "malicious": True,
            }
            e = entries.setdefault(key, {
                "ecosystem": key[0], "name": key[1], "version": key[2],
                "advisories": [],
            })
            if not any(a["id"] == vid for a in e["advisories"]):
                e["advisories"].append(adv)
                coords_kept += 1
    per_eco_counts[our_eco] = coords_kept
    print(f"  {osv_eco}: {coords_kept} malicious coordinate(s) -> {our_eco}")

# ---- fail closed ------------------------------------------------------------
# A dataset with no malicious records is precisely the failure DS-REV-01
# describes. Writing one would restore a tier that reports coverage and
# provides none, so nothing is written at all.
malicious = sum(
    1 for e in entries.values() for a in e["advisories"] if a.get("malicious")
)
ecosystems = {e["ecosystem"] for e in entries.values()}

if malicious == 0:
    sys.exit(
        "error: produced zero malicious-package records.\n"
        "  This tier is the offline substitute for a live VC-001 check; a dataset\n"
        "  without malicious intelligence cannot serve it. bundled_snapshot.json\n"
        "  was NOT modified."
    )
if len(ecosystems) < 2:
    sys.exit(
        f"error: produced records for only {len(ecosystems)} ecosystem(s): {sorted(ecosystems)}.\n"
        "  A single-ecosystem fallback leaves every other ecosystem silently\n"
        "  uncovered. bundled_snapshot.json was NOT modified."
    )
for e in entries.values():
    if not e["advisories"]:
        sys.exit(f"error: empty advisory list for {e['ecosystem']}/{e['name']}@{e['version']}")

out = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "entries": [entries[k] for k in sorted(entries)],
}
dest = "internal/datasource/osv/bundled_snapshot.json"
with open(dest, "w") as fh:
    json.dump(out, fh, indent=2)
    fh.write("\n")

size = os.path.getsize(dest)
print(
    f"wrote {len(out['entries'])} coordinate(s), {malicious} malicious advisor(ies) "
    f"across {len(ecosystems)} ecosystem(s) to {dest} "
    f"({size // 1024} KiB, generated_at={out['generated_at']})"
)
PY
