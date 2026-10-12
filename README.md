# auditlogs-verify (Go)

An independent checker for AuditLogs audits. It recomputes the hash chain from the stored payloads
and checks the Ed25519 checkpoint signatures against public keys **you** pinned, so an auditor does
not have to take the service's word that nothing changed.

This is the Go version of the Python package
[auditlogs-verify](https://github.com/jamesadewara/auditlogs-python-package). Both implement
[docs/SPEC.md](docs/SPEC.md), reproduce the same test values, and give identical reports.

Everything else in AuditLogs is plain HTTPS. Sending, reading and provisioning need no library;
the dashboard shows ready-to-run examples.

## Install

```bash
go install github.com/jamesadewara/auditlogs-go-package/cmd/auditlogs-verify@latest   # command
go get github.com/jamesadewara/auditlogs-go-package/verify                            # library
```

Requires Go 1.27 or newer. Depends on `github.com/google/uuid` and `github.com/digitorus/timestamp`.

## Command line

```bash
auditlogs-verify audit-bundle.json --keys trusted-keys.json \
    --tsa-roots freetsa-root.pem --max-anchor-delay 86400
auditlogs-verify audit-bundle.json --keys trusted-keys.json --skip-timestamps --json
```

Get the bundle with `GET /v1/audits/{slug}/export/bundle` (read key). When it contains checkpoint
timestamps you must either pass `--tsa-roots` and `--max-anchor-delay`, or say `--skip-timestamps`;
the report then states that timestamps were not checked.

| Exit status | Meaning |
|---|---|
| 0 | INTACT |
| 1 | TAMPERED: prints the kind and exact sequence number of the first break |
| 2 | Not checked: the bundle or key file is missing or malformed, or a flag is wrong. This is never a verdict. |

- **`trusted-keys.json`** is either `{"key_id": "base64 public key"}` or a saved copy of
  `GET /v1/checkpoint-keys`.
- **`audit-bundle.json`** holds the audit's events and checkpoints, as described in
  [docs/SPEC.md](docs/SPEC.md).

## Library

```go
import "github.com/jamesadewara/auditlogs-go-package/verify"

keys, err := verify.ReadKeyFile("trusted-keys.json")
ring, err := verify.LoadTrustedKeys(keys)
bundle, err := verify.LoadBundle("audit-bundle.json")
roots, err := verify.LoadTSARoots("freetsa-root.pem")
policy, err := verify.NewAnchorPolicy(roots, 24*time.Hour)
report, err := verify.VerifyBundle(bundle, ring, policy) // nil policy skips timestamps on purpose
if !report.Intact() {
	fmt.Println(report.Failure.Kind, report.Failure.Seq, report.Failure.Message)
}
```

Check every `err`: an error means the input could not be checked (`*verify.ConfigurationError` or
`*verify.BundleError`), while a TAMPERED chain is a `Report`, never an error.

Also available:
- `VerifyChain`, for events and checkpoints you already hold in memory;
- `NewChainVerifier`, which checks events one at a time (`Feed`, then `Finish`) for very large audits;
- `GenesisHash`, `EventHash`, `CheckpointMessage`, `CheckpointProblem` and `AnchorProblem`.

## What it guarantees, and what it does not

It detects:
- edited, deleted, reordered or moved records;
- a chain recomputed without the signing key;
- newest records deleted after a checkpoint;
- forged or unknown checkpoints, and invalid or mismatched checkpoint timestamps.

It does not protect against an operator who holds the signing key and rewrites history before you
pinned any checkpoint. See "Known limits" in the spec.

## Differences from the Python package

The reports are the same. The input parsing is slightly stricter, by design:
- numbers in the bundle must be JSON integers (`"seq": "1"` or `1.0` is rejected);
- a checkpoint timestamp's `gen_time` must carry a time zone.

## Development

```bash
go vet ./... && go test ./...
```

See [RELEASING.md](RELEASING.md) to publish a version.
