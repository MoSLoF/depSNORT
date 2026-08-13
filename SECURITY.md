# Security Policy

depSNORT is a **static, zero-execution** analyzer: it parses manifests and
lockfiles and never runs a package manager or a lifecycle hook.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for a security bug.

- **Preferred:** use GitHub's private vulnerability reporting. On this
  repository, go to the **Security** tab → **Report a vulnerability** (this opens
  a private advisory visible only to you and the maintainers).
  Maintainers: enable it once under *Settings → Advanced Security →
  Private vulnerability reporting* so the button is available.
- **Alternative:** email the maintainer at **moslof.jr@gmail.com** with
  `depSNORT security` in the subject.

Please include the affected version (`depsnort version`), a minimal reproducer,
and the impact you observed (for example: a crafted lockfile that steers a read
outside the scan root, or an input that makes the scanner report a clean result
over an incomplete one).

## Response expectations

This is a personal open-source project maintained on a best-effort basis. You
can expect an acknowledgement within **7 days** and, for confirmed issues, a
fix or documented mitigation coordinated privately before public disclosure.
There is no bug-bounty program.

## Scope note

`testdata/adversarial/` intentionally contains **simulated-malicious** fixtures.
They are inert test inputs — placeholder or publicly-documented indicators used
to validate detection — not live threats. Automated malware scanners may flag
them; that is expected.
