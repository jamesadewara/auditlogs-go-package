package verify

// Checkpoint timestamps, checked against a real FreeTSA reply.
//
// testdata/anchor-checkpoint.tsr is FreeTSA's answer for SHA-256 of the
// message of the checkpoint in testdata/anchor-checkpoint.json (signed one
// second before the TSA time); testdata/freetsa-root.pem is FreeTSA's
// published root. The same fixture is checked by the service and the Python
// package.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var tsaTime = time.Date(2026, 10, 12, 11, 35, 2, 0, time.UTC)

// fixtureCheckpoint loads the fixture as a bundle would carry it, after
// applying edit to its JSON fields.
func fixtureCheckpoint(t *testing.T, edit func(m map[string]any)) Checkpoint {
	t.Helper()
	raw, err := os.ReadFile("testdata/anchor-checkpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Checkpoint map[string]any `json:"checkpoint"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	tsr, err := os.ReadFile("testdata/anchor-checkpoint.tsr")
	if err != nil {
		t.Fatal(err)
	}
	cp := doc.Checkpoint
	cp["timestamp"] = map[string]any{
		"tsa_url": "https://freetsa.org/tsr", "gen_time": tsaTime.Format(time.RFC3339),
		"tsa_response": base64.StdEncoding.EncodeToString(tsr),
	}
	if edit != nil {
		edit(cp)
	}
	data, _ := json.Marshal(map[string]any{
		"format": BundleFormat, "audit_id": cp["audit_id"], "slug": "fixture",
		"events": []any{}, "checkpoints": []any{cp},
	})
	b, err := ParseBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	return b.Checkpoints[0]
}

func freeTSAPolicy(t *testing.T, maxDelay time.Duration) AnchorPolicy {
	t.Helper()
	roots, err := LoadTSARoots("testdata/freetsa-root.pem")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewAnchorPolicy(roots, maxDelay)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func anchorCheck(t *testing.T, cp Checkpoint, p AnchorPolicy) string {
	t.Helper()
	msg, err := CheckpointMessage(cp)
	if err != nil {
		t.Fatal(err)
	}
	return AnchorProblem(cp, msg, p)
}

func TestFixtureMessageDigestMatchesTheRecordedOne(t *testing.T) {
	msg, err := CheckpointMessage(fixtureCheckpoint(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(msg)
	if hex.EncodeToString(sum[:]) != "c8b029199222dac310d89264f4b40f71eb968d31d9aed099f3c51ae6e580392d" {
		t.Fatalf("message digest %x", sum)
	}
}

func TestARealFreeTSATimestampVerifies(t *testing.T) {
	if p := anchorCheck(t, fixtureCheckpoint(t, nil), freeTSAPolicy(t, time.Hour)); p != "" {
		t.Fatalf("want a valid timestamp, got %q", p)
	}
}

func TestATimestampOfAnotherCheckpointIsRejected(t *testing.T) {
	cp := fixtureCheckpoint(t, func(m map[string]any) { m["last_seq"] = 6 })
	if p := anchorCheck(t, cp, freeTSAPolicy(t, time.Hour)); !strings.HasPrefix(p, "the timestamp does not verify") {
		t.Fatalf("got %q", p)
	}
}

func TestATimestampLongAfterSigningIsRejected(t *testing.T) {
	p := anchorCheck(t, fixtureCheckpoint(t, nil), freeTSAPolicy(t, 500*time.Millisecond))
	if !strings.Contains(p, "away from signed_at") {
		t.Fatalf("got %q", p)
	}
}

func TestAnEditedStoredTimeIsRejected(t *testing.T) {
	cp := fixtureCheckpoint(t, nil)
	cp.Timestamp.GenTime = tsaTime.Add(-time.Minute)
	if p := anchorCheck(t, cp, freeTSAPolicy(t, time.Hour)); !strings.Contains(p, "differs from the signed TSA time") {
		t.Fatalf("got %q", p)
	}
}

func TestACorruptTSAResponseIsRejected(t *testing.T) {
	cp := fixtureCheckpoint(t, nil)
	cp.Timestamp.TSAResponse = "not base64!!"
	if p := anchorCheck(t, cp, freeTSAPolicy(t, time.Hour)); p != "the stored TSA response is not valid base64" {
		t.Fatalf("got %q", p)
	}
	cp.Timestamp.TSAResponse = base64.StdEncoding.EncodeToString([]byte("garbage"))
	if p := anchorCheck(t, cp, freeTSAPolicy(t, time.Hour)); !strings.HasPrefix(p, "the TSA response cannot be parsed") {
		t.Fatalf("got %q", p)
	}
}

func TestAnUntrustedTSAIsRejected(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Some Other Root"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	other, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewAnchorPolicy([]*x509.Certificate{other}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if problem := anchorCheck(t, fixtureCheckpoint(t, nil), *p); !strings.HasPrefix(problem, "the timestamp does not verify") {
		t.Fatalf("got %q", problem)
	}
}

func TestPolicyNeedsRootsAndAPositiveDelay(t *testing.T) {
	_, err := NewAnchorPolicy(nil, time.Hour)
	expectConfigError(t, err, "at least one trusted TSA root")
	roots, err := LoadTSARoots("testdata/freetsa-root.pem")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewAnchorPolicy(roots, 0)
	expectConfigError(t, err, "must be positive")
}

func TestTSARootsFileMustHoldACertificate(t *testing.T) {
	_, err := LoadTSARoots("testdata/missing.pem")
	expectConfigError(t, err, "cannot read the TSA roots file")
	_, err = LoadTSARoots("testdata/anchor-checkpoint.json")
	expectConfigError(t, err, "holds no certificate")
}

// Through the whole verifier: a checkpoint carrying someone else's timestamp is
// BAD_ANCHOR at its seq, and one without a timestamp is counted, not failed.
func TestTimestampsInTheReport(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 3)
	p := freeTSAPolicy(t, 24*time.Hour)

	plain := s.checkpoint(t, audit, "periodic", 2, events[1].Hash)
	r, err := VerifyChain(audit, "orders", events, []Checkpoint{plain}, s.ring(t), &p)
	if err != nil || !r.Intact() || !r.TimestampsChecked || r.AnchorsChecked != 0 || r.CheckpointsUnanchored != 1 {
		t.Fatalf("unanchored checkpoint: %+v %v", r, err)
	}

	stamped := s.checkpoint(t, audit, "periodic", 3, events[2].Hash)
	stamped.Timestamp = fixtureCheckpoint(t, nil).Timestamp // FreeTSA's reply for another checkpoint
	r, err = VerifyChain(audit, "orders", events, []Checkpoint{plain, stamped}, s.ring(t), &p)
	if err != nil {
		t.Fatal(err)
	}
	f := expectFailure(t, r, FailureBadAnchor, 3)
	if !strings.HasPrefix(f.Message, "timestamp of the periodic checkpoint at seq 3: the timestamp does not verify") {
		t.Fatalf("message %q", f.Message)
	}

	r, err = VerifyChain(audit, "orders", events, []Checkpoint{plain, stamped}, s.ring(t), nil)
	if err != nil || !r.Intact() || r.TimestampsChecked {
		t.Fatalf("skipped timestamps must say so: %+v %v", r, err)
	}
}
