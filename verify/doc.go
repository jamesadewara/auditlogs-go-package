// Package verify checks an AuditLogs audit yourself, without trusting the
// service.
//
// It recomputes the hash chain from the stored payloads and checks the Ed25519
// checkpoint signatures against public keys you pinned, plus each checkpoint's
// independent RFC 3161 timestamp. Everything else in AuditLogs is plain HTTP
// and needs no library. The format is specified in docs/SPEC.md.
//
//	keys, err := verify.ReadKeyFile("trusted-keys.json")
//	ring, err := verify.LoadTrustedKeys(keys)
//	bundle, err := verify.LoadBundle("audit-bundle.json")
//	roots, err := verify.LoadTSARoots("freetsa-root.pem")
//	policy, err := verify.NewAnchorPolicy(roots, 24*time.Hour)
//	report, err := verify.VerifyBundle(bundle, ring, policy)
//	if !report.Intact() {
//		fmt.Println(report.Failure.Kind, report.Failure.Seq, report.Failure.Message)
//	}
//
// An error means the input could not be checked; a TAMPERED chain is a
// Report, never an error.
//
// This is the Go counterpart of the Python package auditlogs-verify. Both
// implement docs/SPEC.md and reproduce the same test values.
package verify
