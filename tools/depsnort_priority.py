#!/usr/bin/env python3
"""
depsnort_priority.py  --  CI/CD-aware REMEDIATION-priority overlay for depSNORT.

Consumes real depSNORT JSON reports (schema: internal/emit/json.go). Findings
live at verdict.findings; each identifies its package by node_id (a PURL) which is
JOINED against nodes[] for the human name. This overlay does NOT re-score severity
-- the tool already computes gate_class, confidence, recency_decay and a composed
score. It RANKS remediation by trusting that judgment and adding exactly one new
signal: a live CI/CD pipeline in the owning repo (the secrets blast radius).

$global:Intent = 'Purple'  -- same CI/CD signal DepRaptor uses to pick juicier
attack targets, inverted into "fix this lockfile first."

Priority model (lower tier index = fix sooner):
    gate_class 'block'         -> P0   (poisoned / malicious; never softened)
    gate_class 'gate-eligible' -> P1
    gate_class 'advisory'      -> P3
    ...then a live CI/CD pipeline in the owning repo escalates ONE tier.
Within a tier, order by the tool's own composed score, then confidence.

Coverage is reported per-repo as a BLIND-SPOT banner from verdict.coverage --
"we could not look" is surfaced, never silently rendered as clean (D-24).
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

CI_MARKERS = {
    ".github/workflows": "GitHub Actions",
    ".gitlab-ci.yml": "GitLab CI",
    "Jenkinsfile": "Jenkins",
    ".circleci/config.yml": "CircleCI",
    "azure-pipelines.yml": "Azure Pipelines",
    ".travis.yml": "Travis CI",
    "bitbucket-pipelines.yml": "Bitbucket",
    ".drone.yml": "Drone",
}
TIERS = ["P0", "P1", "P2", "P3"]
GATE_BASE = {"block": 0, "gate-eligible": 1, "advisory": 3}


def detect_cicd(root: Path) -> list[str]:
    if not root or not root.exists():
        return []
    hits = []
    for marker, label in CI_MARKERS.items():
        p = root / marker
        if (p.is_dir() and any(p.iterdir())) or p.is_file():
            hits.append(label)
    return hits


def coverage_line(cov: dict) -> str | None:
    """verdict.coverage -> a one-line blind-spot banner, if degraded."""
    if not isinstance(cov, dict):
        return None
    def g(*keys):
        for k in keys:
            if k in cov:
                return cov[k]
        return None
    degraded = g("degraded", "Degraded")
    unresolved = g("unresolved", "Unresolved") or 0
    inc_roots = g("incomplete_roots", "IncompleteRoots") or 0
    orphans = g("orphans", "Orphans") or 0
    if degraded or unresolved or orphans:
        return (f"BLIND SPOT: {unresolved} unresolved dep(s) across "
                f"{inc_roots} root(s), {orphans} orphan(s) -- NOT an all-clear")
    return None


def rank(report: dict, repo_dir: Path | None) -> tuple[list[dict], str | None]:
    verdict = report.get("verdict", {}) or {}
    findings = verdict.get("findings", []) or []
    nodes = {n.get("id"): n for n in report.get("nodes", []) or []}
    prov = report.get("_provenance", {}) or {}

    # Prefer CI/CD markers stamped by depsnort_org.py (survives clone deletion).
    # Fall back to filesystem probing for single-report / local use.
    cicd = prov.get("cicd") or []
    if not cicd:
        root = repo_dir
        if root is None:
            abs_root = prov.get("_abs_root", "")
            root = Path(abs_root) if abs_root else None
        cicd = detect_cicd(root) if root else []

    rows = []
    for f in findings:
        gate = str(f.get("gate_class", "advisory"))
        base = GATE_BASE.get(gate, 3)
        if cicd:
            base = max(0, base - 1)          # the one new signal: escalate a tier
        tier = TIERS[min(base, 3)]

        node = nodes.get(f.get("node_id"), {})
        reasons = [f"gate={gate}"]
        if cicd:
            reasons.append(f"live CI/CD blast radius ({', '.join(cicd)})")
        if f.get("axis"):
            reasons.append(f"axis={f['axis']}")
        rd = f.get("recency_decay")
        if rd not in (None, 0):
            reasons.append(f"recency_decay={rd:.2f}")

        rows.append({
            "priority": tier,
            "score": round(float(f.get("score", 0.0)), 3),
            "confidence": round(float(f.get("confidence", 0.0)), 2),
            "check_id": f.get("check_id", "?"),
            "severity": f.get("severity", "?"),
            "gate_class": gate,
            "repo": prov.get("repo", ""),
            "proj": prov.get("root", ""),
            "ecosystem": node.get("ecosystem", "?"),
            "package": node.get("name") or f.get("node_id", "?"),
            "version": node.get("version", ""),
            "cicd": ", ".join(cicd),
            "title": f.get("title", ""),
            "remediation": f.get("remediation", ""),
            "reasons": "; ".join(reasons),
        })

    rows.sort(key=lambda r: (TIERS.index(r["priority"]), -r["score"], -r["confidence"]))
    return rows, coverage_line(verdict.get("coverage", {}))


def main() -> int:
    ap = argparse.ArgumentParser(description="CI/CD-aware remediation-priority overlay for depSNORT.")
    ap.add_argument("scans", nargs="+", help="depSNORT JSON report(s) or globs")
    ap.add_argument("-o", "--out", default="priority.json", help="write ranked JSON here")
    ap.add_argument("--repo-dir", default=None,
                    help="project dir for CI/CD detection (single-report use; "
                         "org-driver stamps _abs_root so this isn't needed for fleet scans)")
    ap.add_argument("--p0-only", action="store_true")
    args = ap.parse_args()

    files: list[str] = []
    for pat in args.scans:
        files.extend(glob.glob(pat) if any(c in pat for c in "*?[") else [pat])
    if not files:
        print("[priority] no scan files matched.", file=sys.stderr)
        return 2

    all_rows: list[dict] = []
    banners: list[str] = []
    for fp in files:
        try:
            report = json.loads(Path(fp).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[priority] skip {fp}: {e}", file=sys.stderr)
            continue
        rows, banner = rank(report, Path(args.repo_dir) if args.repo_dir else None)
        all_rows.extend(rows)
        if banner:
            label = report.get("_provenance", {}).get("repo") or Path(fp).name
            banners.append(f"  [{label}] {banner}")

    all_rows.sort(key=lambda r: (TIERS.index(r["priority"]), -r["score"], -r["confidence"]))
    Path(args.out).write_text(json.dumps(all_rows, indent=2), encoding="utf-8")

    shown = [r for r in all_rows if r["priority"] == "P0"] if args.p0_only else all_rows
    counts = {t: sum(1 for r in all_rows if r["priority"] == t) for t in TIERS}
    print(f"\n  P0:{counts['P0']}  P1:{counts['P1']}  P2:{counts['P2']}  P3:{counts['P3']}"
          f"   ({len(all_rows)} findings)\n")
    if banners:
        print("  coverage blind spots:")
        print("\n".join(banners))
        print()
    if shown:
        wp = min(max((len(r["package"]) for r in shown), default=7), 30)
        print(f"  {'PRI':<4}{'SCORE':<7}{'CHECK':<8}{'SEV':<9}{'ECO':<7}{'PACKAGE':<{wp+2}}{'CI/CD':<16}TITLE")
        print("  " + "-" * (4+7+8+9+7+wp+2+16+20))
        for r in shown:
            pkg = (r["package"][:wp-1] + "\u2026") if len(r["package"]) > wp else r["package"]
            print(f"  {r['priority']:<4}{r['score']:<7}{r['check_id']:<8}{r['severity']:<9}"
                  f"{r['ecosystem']:<7}{pkg:<{wp+2}}{(r['cicd'] or '-')[:15]:<16}{r['title']}")
    print(f"\n[priority] ranked JSON -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
