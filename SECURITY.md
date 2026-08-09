# Security Policy

dependaSNORT is a **static, zero-execution** analyzer: it parses manifests and
lockfiles and never runs a package manager or a lifecycle hook.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers rather than
opening a public issue. Include the affected version (`depsnort version`), a
minimal reproducer, and the impact you observed.

## Scope note

`testdata/adversarial/` intentionally contains simulated-malicious fixtures.
They are inert test inputs, not live threats.
