#!/usr/bin/env python3
"""
iHBV RepoGuard — repo-open execution surface triage.

WHY THIS EXISTS
---------------
Dependency scanners (depSNORT included) answer: "what happens when I INSTALL
these dependencies?" The Miasma/Hades campaign (Azure/durabletask, 2026-06-05)
skips that step entirely — its payload runs the moment a developer OPENS the
repository in an editor or AI coding agent, via checked-in configuration:
an obfuscated setup.js, a VS Code workspace tasks file, and agent hook settings.
No package is installed, so no dependency scanner sees it.

RepoGuard triages a repository BEFORE you open it, looking for the checked-in
files that can cause execution on open/attach, and grades them by whether they
also reach the network or obfuscate their payload.

DISCIPLINE
----------
Read-only. Parses text; never executes, installs, or imports anything from the
target. Reports what it CANNOT read rather than implying clean.

USAGE
-----
    python3 ihbv-repoguard.py /path/to/freshly-cloned-repo
    python3 ihbv-repoguard.py /path/to/repo --json

Exit codes:  0 = nothing found   1 = findings   2 = usage/error
"""

import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------- indicators

# Files whose mere presence creates an on-open / on-attach execution path.
# key: (glob-ish relative path match, severity, why)
AUTO_EXEC_FILES = [
    (".vscode/tasks.json", "high", "VS Code workspace tasks; can auto-run on folder open"),
    (".vscode/settings.json", "medium", "VS Code workspace settings; can redefine terminal/tooling paths"),
    (".vscode/launch.json", "medium", "debug configuration; can launch arbitrary programs"),
    (".devcontainer/devcontainer.json", "high", "devcontainer lifecycle commands (initializeCommand runs on the HOST)"),
    (".devcontainer.json", "high", "devcontainer lifecycle commands"),
    (".envrc", "high", "direnv: executes on cd into the directory"),
    (".claude/settings.json", "high", "Claude Code hooks can run commands on session/tool events"),
    (".claude/settings.local.json", "high", "Claude Code hooks (local override)"),
    (".mcp.json", "high", "MCP server definitions spawn local processes"),
    (".cursor/mcp.json", "high", "Cursor MCP server definitions spawn local processes"),
    (".cursor/rules", "low", "agent instruction surface"),
    (".gemini/settings.json", "high", "Gemini agent configuration/hooks"),
    (".idea/workspace.xml", "medium", "JetBrains run configurations"),
    (".husky", "medium", "git hooks installed into the working tree"),
    (".githooks", "medium", "checked-in git hooks directory"),
]

# Strings that turn a config file from "present" into "auto-executes".
AUTO_RUN_TRIGGERS = [
    (r'"runOn"\s*:\s*"folderOpen"', "critical", "VS Code task set to RUN ON FOLDER OPEN"),
    (r'"initializeCommand"', "critical", "devcontainer initializeCommand runs on the HOST before the container"),
    (r'"onCreateCommand"|"updateContentCommand"', "high", "devcontainer create-time command"),
    (r'"postCreateCommand"|"postStartCommand"|"postAttachCommand"', "high", "devcontainer lifecycle command"),
    (r'"hooks"\s*:', "high", "agent hook block (runs on session/tool events)"),
    (r'"SessionStart"|"PreToolUse"|"PostToolUse"|"UserPromptSubmit"', "critical", "agent hook bound to an automatic event"),
    (r'"command"\s*:\s*"[^"]*(node|python3?|bash|sh|powershell|pwsh|npx|uvx)\b', "high", "config spawns an interpreter"),
    (r'"terminal\.integrated\.(profiles|automationProfile|env)', "high", "workspace redefines the integrated terminal/automation profile"),
    (r'"git\.path"|"python\.defaultInterpreterPath"|"npm\.packageManager"', "medium", "workspace redirects a tool binary path"),
    (r'"task\.allowAutomaticTasks"\s*:\s*"on"', "critical", "workspace explicitly enables automatic tasks"),
    (r'"security\.workspace\.trust\.enabled"\s*:\s*false', "critical", "workspace attempts to disable Workspace Trust"),
]

# Payload characteristics — evaluated inside any file already flagged above,
# plus any loose script the config points at.
PAYLOAD_MARKERS = [
    (r'\beval\s*\(|new\s+Function\s*\(', "high", "dynamic code evaluation"),
    (r'child_process|spawnSync|execSync|\bexecFile\b|subprocess|os\.system', "high", "process execution"),
    (r'Buffer\.from\s*\([^)]*base64|atob\s*\(|b64decode', "high", "base64 decode (payload unpacking)"),
    (r'https?://[^\s"\']+', "info", "network endpoint"),
    (r'fetch\s*\(|https?\.request|urlopen|requests\.(get|post)|curl\s|wget\s', "high", "network fetch"),
    (r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){8,}', "high", "hex-escaped string blob (obfuscation)"),
    (r'[A-Za-z0-9+/]{200,}={0,2}', "high", "long base64 blob (obfuscation)"),
]

# Campaign-specific markers (Miasma / Hades / Shai-Hulud lineage).
CAMPAIGN_IOCS = [
    (r'thebeautifulmarchoftime|thebeautifulsnadsoftime|firedalazer', "critical", "Miasma GitHub commit-search keyword"),
    (r'IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully', "critical", "Miasma destructive-token canary name"),
    (r'Hades\s*[:*]\s*The End for the Damned', "critical", "Hades exfil-repo marker"),
    (r'Shai[- ]?Hulud|niagA oG eW ereH', "critical", "Shai-Hulud lineage marker"),
    (r'check\.git-service\.com|t\.m-kosche\.com|160\.119\.64\.3', "critical", "Miasma C2 infrastructure"),
    (r'managed\.pyz|rope\.pyz|pgsql-monitor\.service|pgmonitor\.py|\.sys-update-check', "critical", "Miasma host artifact"),
    (r'harden-runner|step-security', "high", "reference to Harden-Runner (Miasma actively hunts it to evade)"),
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv"}
MAX_READ = 512 * 1024


def read_text(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_READ)
        return raw.decode("utf-8", errors="replace"), None
    except Exception as exc:  # unreadable is DISCLOSED, not assumed clean
        return None, str(exc)


def scan_content(text, rules):
    hits = []
    for pattern, sev, why in rules:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            sample = m.group(0)[:60]
            hits.append((sev, why, sample))
    return hits


def walk_repo(root):
    """Yield (relpath, abspath) for candidate config/script files."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ap = os.path.join(dirpath, fn)
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            yield rel, ap


def triage(root):
    findings = []
    unreadable = []
    watched_prefixes = [p for p, _, _ in AUTO_EXEC_FILES]

    for rel, ap in walk_repo(root):
        is_watched = any(rel == p or rel.startswith(p + "/") for p in watched_prefixes)
        ext = os.path.splitext(rel)[1].lower()
        # Config files we care about, plus any JS/PY/SH they could point at.
        if not is_watched and ext not in (".js", ".mjs", ".cjs", ".py", ".sh", ".ps1", ".json"):
            continue

        text, err = read_text(ap)
        if text is None:
            unreadable.append((rel, err))
            continue

        entry = {"file": rel, "reasons": [], "severity": "info", "watched": is_watched}

        if is_watched:
            for p, sev, why in AUTO_EXEC_FILES:
                if rel == p or rel.startswith(p + "/"):
                    entry["reasons"].append((sev, "on-open surface", why, ""))
                    break
            for sev, why, sample in scan_content(text, AUTO_RUN_TRIGGERS):
                entry["reasons"].append((sev, "auto-run trigger", why, sample))
            for sev, why, sample in scan_content(text, PAYLOAD_MARKERS):
                entry["reasons"].append((sev, "payload marker", why, sample))

        # Campaign IOCs are checked in EVERY candidate file, watched or not.
        for sev, why, sample in scan_content(text, CAMPAIGN_IOCS):
            entry["reasons"].append((sev, "campaign IOC", why, sample))

        # An unwatched script only reports if it carries obfuscation + exec + net.
        if not is_watched and not any(r[1] == "campaign IOC" for r in entry["reasons"]):
            marks = scan_content(text, PAYLOAD_MARKERS)
            kinds = {why for _, why, _ in marks}
            if {"dynamic code evaluation", "process execution"} & kinds and (
                {"network fetch"} & kinds
                or {"long base64 blob (obfuscation)", "hex-escaped string blob (obfuscation)"} & kinds
            ):
                for sev, why, sample in marks:
                    entry["reasons"].append((sev, "payload marker", why, sample))

        if entry["reasons"]:
            entry["severity"] = min((r[0] for r in entry["reasons"]), key=lambda s: SEV_ORDER[s])
            findings.append(entry)

    findings.sort(key=lambda e: (SEV_ORDER[e["severity"]], e["file"]))
    return findings, unreadable


def main():
    ap = argparse.ArgumentParser(description="iHBV RepoGuard — repo-open execution surface triage")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if not os.path.isdir(args.path):
        print(f"repoguard: not a directory: {args.path}", file=sys.stderr)
        return 2

    findings, unreadable = triage(args.path)

    if args.json:
        print(json.dumps({
            "target": args.path,
            "findings": [
                {"file": f["file"], "severity": f["severity"],
                 "reasons": [{"severity": s, "kind": k, "why": w, "sample": x} for s, k, w, x in f["reasons"]]}
                for f in findings
            ],
            "unreadable": [{"file": f, "error": e} for f, e in unreadable],
        }, indent=2))
        return 1 if findings else 0

    print(f"iHBV RepoGuard — {args.path}")
    print("=" * 72)
    if not findings:
        print("No repo-open execution surface found.")
    for f in findings:
        print(f"\n[{f['severity'].upper():8s}] {f['file']}")
        for sev, kind, why, sample in f["reasons"]:
            line = f"    - ({sev}) {kind}: {why}"
            if sample:
                line += f"  ->  {sample!r}"
            print(line)
    if unreadable:
        print(f"\nUNREAD ({len(unreadable)}) — disclosed, not assumed clean:")
        for rel, err in unreadable[:10]:
            print(f"    {rel}: {err}")
    print("\n" + "=" * 72)
    print(f"{len(findings)} file(s) with on-open execution surface. "
          "This is a TRIAGE aid, not proof of safety — review before opening in an editor or agent.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
