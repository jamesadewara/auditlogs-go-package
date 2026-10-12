package verify

// Shared test helpers: a real hash chain built with the documented formula and
// real Ed25519 checkpoint signatures from a key generated per test run. No test
// reads a developer's keys or .env.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

var t0 = time.Date(2026, 10, 12, 9, 0, 0, 123456000, time.UTC)

type testSigner struct {
	keyID   string
	private ed25519.PrivateKey
}

func newSigner(t *testing.T, keyID string) testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{keyID: keyID, private: priv}
}

func (s testSigner) publicB64() string {
	return base64.StdEncoding.EncodeToString(s.private.Public().(ed25519.PublicKey))
}

func (s testSigner) trusted() map[string]string { return map[string]string{s.keyID: s.publicB64()} }

func (s testSigner) ring(t *testing.T) KeyRing {
	t.Helper()
	r, err := LoadTrustedKeys(s.trusted())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (s testSigner) checkpoint(t *testing.T, auditID uuid.UUID, kind string, lastSeq int64, lastHash string) Checkpoint {
	t.Helper()
	cp := Checkpoint{
		ID: uuid.New(), AuditID: auditID, Kind: kind, LastSeq: lastSeq, LastHash: lastHash,
		KeyID: s.keyID, SignedAt: t0.Add(time.Duration(lastSeq) * time.Second),
	}
	if kind == "retention" {
		next := lastSeq + 1
		cp.FirstRetainedSeq = &next
	}
	msg, err := CheckpointMessage(cp)
	if err != nil {
		t.Fatal(err)
	}
	cp.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, msg))
	return cp
}

// payload is a canonical-looking payload; verification hashes whatever text is stored.
func payload(auditID uuid.UUID, seq int64, prev, extra string) string {
	return fmt.Sprintf(`{"audit_id":%q,"seq":%d,"prev_hash":%q,"hash":"","action":"order.created"%s}`, auditID.String(), seq, prev, extra)
}

func makeEvent(t *testing.T, seq int64, prev, text string) StoredEvent {
	t.Helper()
	h, err := EventHash(prev, text)
	if err != nil {
		t.Fatal(err)
	}
	e := StoredEvent{Seq: seq, Hash: h, CanonicalPayload: text}
	if seq > 1 {
		p := prev
		e.PrevHash = &p
	}
	return e
}

func buildChain(t *testing.T, auditID uuid.UUID, n int64) []StoredEvent {
	t.Helper()
	prev := GenesisHash(auditID)
	events := make([]StoredEvent, 0, n)
	for seq := int64(1); seq <= n; seq++ {
		e := makeEvent(t, seq, prev, payload(auditID, seq, prev, ""))
		events = append(events, e)
		prev = e.Hash
	}
	return events
}

func run(t *testing.T, auditID uuid.UUID, events []StoredEvent, cps []Checkpoint, s testSigner) Report {
	t.Helper()
	// These tests are about the chain; timestamps have their own tests.
	r, err := VerifyChain(auditID, "orders", events, cps, s.ring(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func expectFailure(t *testing.T, r Report, kind FailureKind, seq int64) Failure {
	t.Helper()
	if r.Status != StatusTampered || r.Failure == nil || r.Failure.Kind != kind || r.Failure.Seq != seq {
		t.Fatalf("want TAMPERED %s at seq %d, got %s %+v", kind, seq, r.Status, r.Failure)
	}
	return *r.Failure
}
