package verify

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/digitorus/timestamp"
)

// Independent checkpoint timestamps (RFC 3161).
//
// Each checkpoint may carry a timestamp from an independent timestamp
// authority (TSA) over SHA-256 of its signed message. It proves the checkpoint
// existed at the TSA's time, so an operator who holds the signing key still
// cannot re-sign a rewritten history later without the timestamps giving it
// away.
//
// A timestamp is valid when it is signed by a TSA chaining to a root you
// trust, covers exactly this checkpoint's message, its time equals the stored
// gen_time, and that time lies within the allowed delay of the checkpoint's
// signed_at (in either direction).

// AnchorPolicy is the trusted TSA roots and the largest allowed gap between a
// checkpoint's signed_at and its TSA time. Build it with NewAnchorPolicy.
type AnchorPolicy struct {
	roots    *x509.CertPool
	MaxDelay time.Duration
}

// NewAnchorPolicy needs at least one root and a positive delay.
func NewAnchorPolicy(roots []*x509.Certificate, maxDelay time.Duration) (*AnchorPolicy, error) {
	if len(roots) == 0 {
		return nil, &ConfigurationError{"at least one trusted TSA root certificate is required"}
	}
	if maxDelay <= 0 {
		return nil, &ConfigurationError{"the maximum timestamp delay must be positive"}
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	return &AnchorPolicy{roots: pool, MaxDelay: maxDelay}, nil
}

// LoadTSARoots reads one or more PEM certificates (for example FreeTSA's cacert.pem).
func LoadTSARoots(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigurationError{fmt.Sprintf("cannot read the TSA roots file %s: %v", path, err)}
	}
	var roots []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &ConfigurationError{fmt.Sprintf("the TSA roots file %s holds no valid PEM certificate: %v", path, err)}
		}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return nil, &ConfigurationError{fmt.Sprintf("the TSA roots file %s holds no certificate", path)}
	}
	return roots, nil
}

// AnchorProblem says why cp's timestamp is not valid, or "" when it verifies
// (or cp has none). message is cp's signed message (CheckpointMessage).
func AnchorProblem(cp Checkpoint, message []byte, policy AnchorPolicy) string {
	if cp.Timestamp == nil {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(cp.Timestamp.TSAResponse)
	if err != nil {
		return "the stored TSA response is not valid base64"
	}
	ts, err := timestamp.ParseResponse(der)
	if err != nil {
		return fmt.Sprintf("the TSA response cannot be parsed: %v", err)
	}
	digest := sha256.Sum256(message)
	if problem := tokenProblem(ts, digest[:], policy.roots); problem != "" {
		return "the timestamp does not verify: " + problem
	}
	genTime := ts.Time.UTC()
	stored := cp.Timestamp.GenTime.UTC()
	if !genTime.Equal(stored) {
		return fmt.Sprintf("the stored time %s differs from the signed TSA time %s",
			stored.Format(time.RFC3339Nano), genTime.Format(time.RFC3339Nano))
	}
	signedAt := cp.SignedAt.UTC()
	gap := genTime.Sub(signedAt)
	if gap < 0 {
		gap = -gap
	}
	if gap > policy.MaxDelay {
		return fmt.Sprintf("the TSA time %s is %s away from signed_at %s (allowed %s)",
			genTime.Format(time.RFC3339Nano), gap, signedAt.Format(time.RFC3339Nano), policy.MaxDelay)
	}
	return ""
}

// tokenProblem checks a parsed token: the library verifies the CMS signature
// only when certificates are present, so they are required; the imprint must
// be SHA-256 of this checkpoint's message; the signing certificate must have
// the time-stamping key usage and chain to a trusted root at the token's time.
func tokenProblem(ts *timestamp.Timestamp, digest []byte, roots *x509.CertPool) string {
	if len(ts.Certificates) == 0 {
		return "the response carries no certificates, so its signature cannot be checked"
	}
	if ts.HashAlgorithm != 0 && ts.HashAlgorithm != crypto.SHA256 {
		return fmt.Sprintf("the imprint uses %v, want SHA-256", ts.HashAlgorithm)
	}
	if !bytes.Equal(ts.HashedMessage, digest) {
		return fmt.Sprintf("it timestamps %s, not this checkpoint (%s)",
			hex.EncodeToString(ts.HashedMessage), hex.EncodeToString(digest))
	}
	var signer *x509.Certificate
	intermediates := x509.NewCertPool()
	for _, c := range ts.Certificates {
		isTSA := false
		for _, u := range c.ExtKeyUsage {
			if u == x509.ExtKeyUsageTimeStamping {
				isTSA = true
			}
		}
		if isTSA && signer == nil {
			signer = c
		} else {
			intermediates.AddCert(c)
		}
	}
	if signer == nil {
		return "no certificate in the response is a time-stamping certificate"
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: ts.Time,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return fmt.Sprintf("the TSA certificate does not chain to a trusted root: %v", err)
	}
	return ""
}
