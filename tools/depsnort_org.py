#!/usr/bin/env python3
"""
depsnort_org.py  --  Per-org / per-project discovery + isolated-scan driver for depSNORT.

WHY THIS EXISTS
---------------
depSNORT's own smoke tests proved that merged-graph reachability over-attributes
findings across repos that share transitive nodes (@babel/core, brace-expansion, ...).
The fix established there: *correct attribution requires exactly one root per scan.*

This driver enforces that structurally. It does NOT call depSNORT with -recursive.
Instead it enumerates targets, finds every manifest-bearing project root, and invokes
depSNORT once per root in isolation. One root in, one JSON out, provenance tagged.
Those JSONs feed depsnort_sheet.py unchanged.

It does not touch depSNORT internals -- it rides the documented CLI:
    depsnort scan -format json <dir>   (override with --scan-args if yours differs)

TARGET MODES
------------
    org:NAME            All repos for a GitHub org (falls back to the user endpoint)
    list:repos.txt      Newline-delimited repo URLs / owner/name slugs
    paths:targets.txt   Newline-delimited local project paths
    ./local/dir         A single local directory (walked for project roots)

OUTPUT
------
    <out>/scans/<repo>__<projpath>.json   one isolated depSNORT JSON per project root
    <out>/index.json                       provenance map: scan file -> {repo, root, url}

Requires: git on PATH (for remote clones). GITHUB_TOKEN honored for the API + clones.
Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Files depSNORT's adapters actually RESOLVE (npm/pypi/rubygems/cargo/
# composer/nuget). It is a static lockfile IDS -- a bare package.json with no
# lockfile is unresolvable, so we scan lockfile-bearing dirs only.
LOCKFILES = (
    "package-lock.json",   # npm
    "requirements.txt",    # pypi
    "Pipfile.lock",        # pypi
    "Gemfile.lock",        # rubygems
    "Cargo.lock",          # cargo
    "composer.lock",       # composer
    "packages.lock.json",  # nuget
)
# Source manifests that imply a project exists. A dir with one of these but no
# lockfile is UNMEASURED, not clean -- surfaced in the index (hollow-clean).
MANIFESTS = (
    "package.json", "pyproject.toml", "setup.py", "Pipfile",
    "Gemfile", "Cargo.toml", "composer.json", "go.mod",
)
# Dirs we never descend into looking for project roots.
PRUNE = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build",
         "__pycache__", ".tox", "target", ".mypy_cache", "site-packages"}

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


def detect_cicd(root: Path) -> list[str]:
    """Detect CI/CD pipelines by filesystem markers. Run BEFORE clone deletion."""
    hits = []
    for marker, label in CI_MARKERS.items():
        p = root / marker
        if (p.is_dir() and any(p.iterdir())) or p.is_file():
            hits.append(label)
    return hits


def log(msg: str) -> None:
    print(f"[depsnort-org] {msg}", file=sys.stderr)


# ---------------------------------------------------------------- GitHub API ---
def _gh_get(url: str) -> list | dict:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "depsnort-org",
    })
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def enumerate_org(name: str, include_forks: bool, include_archived: bool) -> list[dict]:
    """Return [{slug, url}] for an org, falling back to the user endpoint."""
    repos: list[dict] = []
    for kind in ("orgs", "users"):
        page = 1
        got_any = False
        while True:
            url = f"https://api.github.com/{kind}/{name}/repos?per_page=100&page={page}&type=sources"
            try:
                batch = _gh_get(url)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    break  # try the next kind (org -> user)
                if e.code in (403, 429):
                    log(f"rate-limited/forbidden ({e.code}); set GITHUB_TOKEN. stopping enum.")
                    return repos
                raise
            if not batch:
                break
            got_any = True
            for repo in batch:
                if repo.get("fork") and not include_forks:
                    continue
                if repo.get("archived") and not include_archived:
                    continue
                repos.append({"slug": repo["full_name"], "url": repo["clone_url"]})
            page += 1
        if got_any:
            break
    return repos


# ------------------------------------------------------------------ Targets ---
def slug_to_clone_url(slug: str) -> str:
    slug = slug.strip().rstrip("/")
    if slug.startswith("http://") or slug.startswith("https://") or slug.startswith("git@"):
        return slug
    return f"https://github.com/{slug}.git"


def resolve_targets(target: str, args) -> list[dict]:
    """Normalize any target mode into a list of {slug, kind, url|path}."""
    if target.startswith("org:"):
        name = target[4:]
        log(f"enumerating GitHub repos for '{name}' ...")
        repos = enumerate_org(name, args.include_forks, args.include_archived)
        log(f"  found {len(repos)} repo(s)")
        return [{"slug": r["slug"], "kind": "remote", "url": r["url"]} for r in repos]

    if target.startswith("list:"):
        lines = Path(target[5:]).read_text(encoding="utf-8").splitlines()
        out = []
        for ln in lines:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            slug = re.sub(r"^https?://github\.com/", "", ln).removesuffix(".git")
            out.append({"slug": slug, "kind": "remote", "url": slug_to_clone_url(ln)})
        return out

    if target.startswith("paths:"):
        lines = Path(target[6:]).read_text(encoding="utf-8").splitlines()
        out = []
        for ln in lines:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            out.append({"slug": Path(ln).name, "kind": "local", "path": ln})
        return out

    # bare local dir
    return [{"slug": Path(target).resolve().name, "kind": "local", "path": target}]


# ------------------------------------------------------------ Project roots ---
def find_project_roots(base: Path) -> tuple[list[Path], list[Path]]:
    """Return (scan_roots, unmeasured).

    scan_roots  : dirs with a lockfile depSNORT can resolve -- one root = one scan.
    unmeasured  : dirs with a source manifest but NO lockfile -- reported, not scanned.
    """
    scan_roots: list[Path] = []
    unmeasured: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in PRUNE and not d.startswith(".git")]
        fs = set(filenames)
        if any(lf in fs for lf in LOCKFILES):
            scan_roots.append(Path(dirpath))
        elif any(m in fs for m in MANIFESTS):
            unmeasured.append(Path(dirpath))
    return sorted(set(scan_roots)), sorted(set(unmeasured))


# ------------------------------------------------------------------- Scanning --
def clone(url: str, dest: Path, depth: int) -> bool:
    env = dict(os.environ)
    tok = env.get("GITHUB_TOKEN")
    if tok and url.startswith("https://github.com/"):
        url = url.replace("https://", f"https://x-access-token:{tok}@", 1)
    cmd = ["git", "clone", "--quiet", "--depth", str(depth), url, str(dest)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        log(f"  clone failed: {r.stderr.strip().splitlines()[-1:] or ['?']}")
        return False
    return True


def scan_root(depsnort: str, scan_args: list[str], root: Path) -> dict | None:
    cmd = [depsnort, *scan_args, str(root)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    # depSNORT exit codes: 0 clean, 1 block, 2 gate-eligible, 3 incomplete
    # coverage -- ALL emit a full report. 64 usage, 70 internal are real failures.
    if r.returncode >= 64:
        log(f"  scan error ({r.returncode}) on {root}: {r.stderr.strip()[:200]}")
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        log(f"  non-JSON output on {root}; is --scan-args correct?")
        return None


def safe_name(*parts: str) -> str:
    raw = "__".join(p.strip("/").replace("/", "_").replace(" ", "_") for p in parts if p)
    return re.sub(r"[^A-Za-z0-9._-]", "_", raw)[:180] or "scan"


# ---------------------------------------------------------------------- main ---
def main() -> int:
    ap = argparse.ArgumentParser(description="Per-org / per-project isolated-scan driver for depSNORT.")
    ap.add_argument("target", help="org:NAME | list:file | paths:file | ./local/dir")
    ap.add_argument("-o", "--out", default="./depsnort-org-out", help="output dir")
    ap.add_argument("--depsnort", default="./depsnort", help="path to depSNORT binary")
    ap.add_argument("--scan-args", default="scan -format json",
                    help='args passed before the target (default: "scan -format json")')
    ap.add_argument("--repo-dir", default=None, help="dir for clones (default: <out>/repos)")
    ap.add_argument("--depth", type=int, default=1, help="git clone depth")
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--include-archived", action="store_true")
    ap.add_argument("--keep-clones", action="store_true", help="do not delete clones after scan")
    ap.add_argument("--limit", type=int, default=0, help="cap number of repos (0 = all)")
    ap.add_argument("--internal-scopes", default="",
                    help="comma-separated internal npm scopes for VC-007 (e.g. @ihbv,@acme). "
                         "REQUIRED for dependency-confusion detection -- VC-007 is a no-op without it.")
    ap.add_argument("--internal-names", default="",
                    help="comma-separated internal package names for VC-007")
    args = ap.parse_args()

    out = Path(args.out)
    scans = out / "scans"
    scans.mkdir(parents=True, exist_ok=True)
    repo_dir = Path(args.repo_dir) if args.repo_dir else out / "repos"
    repo_dir.mkdir(parents=True, exist_ok=True)
    scan_args = args.scan_args.split()
    if args.internal_scopes:
        scan_args += ["-internal-scopes", args.internal_scopes]
    if args.internal_names:
        scan_args += ["-internal-names", args.internal_names]
    if not args.internal_scopes and not args.internal_names:
        log("note: no --internal-scopes/--internal-names set; VC-007 (dependency "
            "confusion) will not fire. Pass them to detect confusion in a fleet scan.")

    targets = resolve_targets(args.target, args)
    if args.limit:
        targets = targets[:args.limit]
    if not targets:
        log("no targets resolved.")
        return 2

    index: list[dict] = []
    n_proj = 0
    for t in targets:
        slug = t["slug"]
        if t["kind"] == "remote":
            dest = repo_dir / safe_name(slug)
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            log(f"clone {slug}")
            if not clone(t["url"], dest, args.depth):
                index.append({"repo": slug, "status": "clone_failed"})
                continue
            base, src_url = dest, t.get("url", "")
        else:
            base, src_url = Path(t["path"]).resolve(), ""
            if not base.exists():
                log(f"missing local path: {base}")
                index.append({"repo": slug, "status": "missing"})
                continue

        scan_roots, unmeasured = find_project_roots(base)
        if not scan_roots and not unmeasured:
            log(f"  no projects in {slug}")
            index.append({"repo": slug, "status": "no_projects"})
        # A manifest with no lockfile is a BLIND SPOT, not clean. Record it.
        for u in unmeasured:
            rel = str(u.relative_to(base)) or "."
            log(f"  UNMEASURED (manifest, no lockfile): {slug}/{rel}")
            index.append({"repo": slug, "root": rel, "status": "unmeasured_no_lockfile"})
        for root in scan_roots:
            rel = str(root.relative_to(base)) or "."
            outfile = scans / (safe_name(slug, rel) + ".json")
            data = scan_root(args.depsnort, scan_args, root)
            if data is None:
                index.append({"repo": slug, "root": rel, "status": "scan_failed"})
                continue
            # Stamp provenance INTO the JSON so downstream never guesses the owner.
            # CI/CD detection runs HERE while the clone still exists -- the
            # priority overlay reads _provenance.cicd instead of probing the
            # filesystem, so --keep-clones is NOT required for fleet scans.
            cicd = detect_cicd(base)
            data.setdefault("_provenance", {})
            data["_provenance"].update({"repo": slug, "root": rel, "url": src_url,
                                        "_abs_root": str(root), "cicd": cicd})
            outfile.write_text(json.dumps(data, indent=2), encoding="utf-8")
            index.append({"repo": slug, "root": rel, "url": src_url,
                          "scan_file": str(outfile.relative_to(out))})
            n_proj += 1

        if t["kind"] == "remote" and not args.keep_clones:
            shutil.rmtree(base, ignore_errors=True)

    (out / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    log(f"done: {n_proj} project root(s) scanned in isolation across "
        f"{len({i.get('repo') for i in index})} repo(s)")
    log(f"per-project JSONs -> {scans}   (feed straight to depsnort_sheet.py / depsnort_priority.py)")
    print(str(scans))  # stdout = the dir of JSONs, for pipelining
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
