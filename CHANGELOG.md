# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

First release of the Go **auditlogs-verify**: check an AuditLogs audit yourself, without trusting
the service. A translation of the Python package auditlogs-verify 0.1.0, with the same rules,
messages, test values and reports.

- `auditlogs-verify` command (`cmd/auditlogs-verify`). Exit status 0 means INTACT, 1 means
  TAMPERED, and 2 means the input could not be checked.
- Library package `verify`: `LoadBundle`, `ParseBundle`, `ReadKeyFile`, `LoadTrustedKeys`,
  `VerifyBundle`, `VerifyChain` and the streaming `ChainVerifier`.
- The `auditlogs-bundle-v1` input format, and the hash and signature rules with shared test values,
  in `docs/SPEC.md`.
- Checks independent RFC 3161 checkpoint timestamps (`NewAnchorPolicy`, `LoadTSARoots`, the
  `BAD_ANCHOR` failure kind, and the `--tsa-roots`, `--max-anchor-delay` and `--skip-timestamps`
  flags). The report says when timestamps were not checked.
