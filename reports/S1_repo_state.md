# S1 — impacket Repo-State Determination

**Project:** TM-022 depSNORT supply-chain assessment · Session 1 of 2
**Date:** 2026-08-14
**Target repo (read-only this session):** `MoSLoF/impacket` (`https://github.com/MoSLoF/impacket`)
**Nature of this record:** factual patch-status observation drawn entirely from
public git history. It is *not* an exploit go/no-go gate; it makes no claim
about exploitability and constructs nothing offensive.

---

## Determination block

```
REPO STATE DETERMINATION
impacket HEAD commit:        4c09897a8645818e873787f2c79ec1bce90c5777
                             ("Fix some SMB relay server syntax error (#2245)")
impacket_0_13_1 tag present: no
master ahead of 0.13.1:      indeterminate (tag absent — no baseline to diff)
ccache.py changed since 0.13.1: indeterminate vs tag; latest change on master is
                             243d64a6 "Fix IndexError in CCache.getCredential
                             when handling 3-part SPNs in multi domain forests
                             (#2242)"
EC-01 fix status:            indeterminate — see note below
```

## Supporting facts

- **Tags:** the fork carries **0 tags**, confirmed after an explicit
  `git fetch --tags origin`. `impacket_0_13_1` is therefore not resolvable in
  this fork, so any `impacket_0_13_1..HEAD` comparison (commits ahead, per-file
  change since 0.13.1) cannot be computed here.
- **HEAD:** `4c09897a` on `master`; `git rev-list --count HEAD` = 4269 commits.
- **`impacket/krb5/ccache.py`** exists (32,733 bytes). Its 10 most-recent commits:

  ```
  243d64a6 Fix IndexError in CCache.getCredential when handling 3-part SPNs ... (#2242)
  bbbc9125 Check cached TGT matches requested user in getST.py (#2218)
  c779bb31 Fix AttributeError when parsing a credential with auth data (#2219)
  3439d335 Modify ticketer and ccache logic (#2159)
  a1454de6 Fix parsing STs from S4U2Self (#2087)
  835e1755 Fixed warnings with Python 3.12 (#1695)
  27e7e747 Updating copyright banner...
  9b4a1394 Updated Copyright to 2023
  828b549d Fix CVE-2020-17049
  8799a1a2 Update file banners to reflect Fortra ownership
  ```

## Note on "EC-01 fix status"

The template asks for an EC-01 fix determination. Two limits make that
indeterminate from a static supply-chain vantage:

1. **No baseline.** With `impacket_0_13_1` absent, there is no tag to diff
   `ccache.py` against, so "changed since 0.13.1" cannot be answered as
   specified.
2. **Out of this session's lane.** Mapping a specific commit to "EC-01" and
   judging whether it constitutes a fix requires the EC-01 definition and a
   security analysis of the ccache subsystem — which the Session-1 scope
   explicitly assigns to Session 2 and bars here ("The Kerberos ccache
   subsystem is Session 2's territory"; "no exploit construction"). This record
   therefore reports only the observable git facts above and does not
   characterize EC-01 or gate any downstream work.

## Handoff

Per operator instruction, Session 1 sets up **no** Session-2 handoff branch and
performs no offensive scaffolding; the operator manages the gate manually. This
file is the factual state record only.

## Other observations (informational)

- Pre-existing remote branches from prior sessions were present and left
  untouched: `claude/impacket-adversarial-wave-1-39koer`,
  `claude/impacket-ccache-adversarial-ggyjdd`,
  `claude/impacket-depsnort-assessment-8lgod7`.
- impacket declares its version dynamically via `importlib.metadata`; there is
  no static version string in-tree to cross-check against a tag.
