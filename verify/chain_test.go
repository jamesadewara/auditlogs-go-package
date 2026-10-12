package verify

// Local verification must agree with the service's verifier and the Python
// package: same hashes, same signed message bytes, and the same failure kind
// at the same seq.

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Golden values pinned by the service's tests (internal/core/hashchain) and
// the Python package's tests (test_chain.py). See docs/SPEC.md.
var goldenAudit = uuid.MustParse("11111111-1111-1111-1111-111111111111")

const (
	goldenGenesis = "8ca77dd1315d327e91d6b15196511eedde02397f45160ffa71a066552382f072"
	goldenHash    = "5b77a6063c22ba83c213f05cc90c654a7a4e4263d2655dcb0f09da5da6f7facb"
	goldenPayload = `{"audit_id":"11111111-1111-1111-1111-111111111111","schema_version":1,"seq":2,` +
		`"prev_hash":"8ca77dd1315d327e91d6b15196511eedde02397f45160ffa71a066552382f072","hash":"",` +
		`"recorded_at":"2026-10-12T09:00:00.123456Z","occurred_at":"2026-10-12T08:59:59Z",` +
		`"actor":{"id":"u-1","ip":"10.0.0.1","type":"user"},"action":"order.created","outcome":"success",` +
		`"summary":"Order \u003c42\u003e \u0026 co","resource":{"id":"42","type":"order"},` +
		`"changes":{"after":{"a":["x",null,true],"z":1.5}},"metadata":{"big":12345678901234567000,"k":"v"},` +
		`"idempotency_key":"idem-1"}`
)

// ── Parity with the other implementations ────────────────────────────────────

func TestGenesisMatchesGo(t *testing.T) {
	if got := GenesisHash(goldenAudit); got != goldenGenesis {
		t.Fatalf("genesis %s", got)
	}
}

func TestEventHashMatchesGo(t *testing.T) {
	got, err := EventHash(goldenGenesis, goldenPayload)
	if err != nil || got != goldenHash {
		t.Fatalf("hash %s, %v", got, err)
	}
}

func TestEventHashRejectsMalformedPreviousHash(t *testing.T) {
	_, err := EventHash(strings.ToUpper(goldenGenesis), goldenPayload)
	if err == nil || !strings.Contains(err.Error(), "64-character lowercase hex") {
		t.Fatalf("want a hex error, got %v", err)
	}
}

func TestCheckpointMessageMatchesGo(t *testing.T) {
	ten := int64(10)
	msg, err := CheckpointMessage(Checkpoint{
		ID: uuid.New(), AuditID: goldenAudit, Kind: "retention", LastSeq: 9, LastHash: goldenHash,
		FirstRetainedSeq: &ten, Signature: "AA==", KeyID: "ckpt-2026",
		SignedAt: time.Date(2026, 10, 12, 9, 0, 0, 123456000, time.UTC),
	})
	want := "auditlogs-checkpoint-v1\nkind=retention\naudit_id=11111111-1111-1111-1111-111111111111\n" +
		"last_seq=9\nlast_hash=" + goldenHash + "\nfirst_retained_seq=10\n" +
		"signed_at=2026-10-12T09:00:00.123456Z\nkey_id=ckpt-2026\n"
	if err != nil || string(msg) != want {
		t.Fatalf("message:\n%s\nerr %v", msg, err)
	}
}

// ── Intact chains ────────────────────────────────────────────────────────────

func TestIntactChainWithCheckpoint(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 5)
	r := run(t, audit, events, []Checkpoint{s.checkpoint(t, audit, "periodic", 3, events[2].Hash)}, s)
	if !r.Intact() || r.EventsChecked != 5 || r.FirstSequence != 1 || r.LastSequence != 5 ||
		r.LastHash != events[4].Hash || r.CheckpointsChecked != 1 || r.Failure != nil {
		t.Fatalf("report %+v", r)
	}
}

func TestEmptyAuditIsIntactAtGenesis(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	r := run(t, audit, nil, nil, s)
	if !r.Intact() || r.LastSequence != 0 || r.LastHash != GenesisHash(audit) {
		t.Fatalf("report %+v", r)
	}
}

func TestRetentionAnchorExplainsRemovedPrefix(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 6)
	r := run(t, audit, events[3:], []Checkpoint{s.checkpoint(t, audit, "retention", 3, events[2].Hash)}, s)
	if !r.Intact() || r.FirstSequence != 4 || r.Anchor == nil || r.Anchor.FirstRetainedSeq != 4 {
		t.Fatalf("report %+v", r)
	}
}

// ── Tamper detection (exact kind and seq) ────────────────────────────────────

func TestEditedFieldIsModifiedAtItsSeq(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 5)
	events[2].CanonicalPayload = strings.Replace(events[2].CanonicalPayload, "order.created", "order.deleted", 1)
	f := expectFailure(t, run(t, audit, events, nil, s), FailureModified, 3)
	if f.Message != "payload at seq 3 does not hash to the stored hash" {
		t.Fatalf("message %q", f.Message)
	}
}

func TestDeletedMiddleEventIsAGap(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 5)
	events = append(events[:2], events[3:]...)
	f := expectFailure(t, run(t, audit, events, nil, s), FailureGap, 3)
	if f.Message != "expected seq 3 but the next stored event is seq 4" {
		t.Fatalf("message %q", f.Message)
	}
}

func TestDeletedTailIsTruncatedAgainstCheckpoint(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 5)
	cps := []Checkpoint{s.checkpoint(t, audit, "periodic", 5, events[4].Hash)}
	f := expectFailure(t, run(t, audit, events[:3], cps, s), FailureTruncated, 4)
	if f.Message != "signed checkpoint covers seq 5 but stored events end at seq 3" {
		t.Fatalf("message %q", f.Message)
	}
}

func TestReorderedPairIsDetectedAtFirstSwap(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 5)
	events[1], events[2] = events[2], events[1]
	expectFailure(t, run(t, audit, events, nil, s), FailureGap, 2)
}

func TestRecomputedChainWithoutKeyMismatchesCheckpoint(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	original := buildChain(t, audit, 5)
	cps := []Checkpoint{s.checkpoint(t, audit, "periodic", 4, original[3].Hash)}
	// An attacker rewrites seq 2 and recomputes every later hash, but cannot re-sign.
	forged := []StoredEvent{original[0]}
	prev := original[0].Hash
	for seq := int64(2); seq <= 5; seq++ {
		extra := ""
		if seq == 2 {
			extra = `,"note":"forged"`
		}
		e := makeEvent(t, seq, prev, payload(audit, seq, prev, extra))
		forged = append(forged, e)
		prev = e.Hash
	}
	f := expectFailure(t, run(t, audit, forged, cps, s), FailureCheckpointMismatch, 4)
	if *f.ExpectedHash != original[3].Hash || *f.FoundHash != forged[3].Hash {
		t.Fatalf("hashes %+v", f)
	}
}

func TestBrokenLinkReportsExpectedAndFound(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 3)
	zeros := strings.Repeat("0", 64)
	events[2].PrevHash = &zeros
	f := expectFailure(t, run(t, audit, events, nil, s), FailureBrokenLink, 3)
	if *f.ExpectedHash != events[1].Hash || *f.FoundHash != zeros {
		t.Fatalf("hashes %+v", f)
	}
}

func TestPrefixDeletedWithoutAnchorIsGapAt1(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	f := expectFailure(t, run(t, audit, buildChain(t, audit, 5)[2:], nil, s), FailureGap, 1)
	if !strings.Contains(f.Message, "records from seq 1 to 2 are missing") {
		t.Fatalf("message %q", f.Message)
	}
}

func TestPayloadMovedFromAnotherAuditIsModified(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	prev := GenesisHash(audit)
	foreign := makeEvent(t, 1, prev, payload(uuid.New(), 1, prev, ""))
	f := expectFailure(t, run(t, audit, []StoredEvent{foreign}, nil, s), FailureModified, 1)
	if f.Message != "payload at seq 1 names a different audit" {
		t.Fatalf("message %q", f.Message)
	}
}

func TestPayloadWithAFloatSeqIsModified(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	prev := GenesisHash(audit)
	text := strings.Replace(payload(audit, 1, prev, ""), `"seq":1,`, `"seq":1.0,`, 1)
	f := expectFailure(t, run(t, audit, []StoredEvent{makeEvent(t, 1, prev, text)}, nil, s), FailureModified, 1)
	if f.Message != "payload at seq 1 records a different seq" {
		t.Fatalf("message %q", f.Message)
	}
}

func TestForgedSignatureIsBadCheckpoint(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 3)
	attacker := newSigner(t, s.keyID) // same key id, different key
	r := run(t, audit, events, []Checkpoint{attacker.checkpoint(t, audit, "periodic", 2, events[1].Hash)}, s)
	f := expectFailure(t, r, FailureBadCheckpoint, 2)
	if !strings.HasSuffix(f.Message, "signature does not verify") || r.CheckpointsChecked != 0 {
		t.Fatalf("message %q, checked %d", f.Message, r.CheckpointsChecked)
	}
}

func TestUnknownKeyIDIsBadCheckpoint(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 2)
	other := newSigner(t, "ckpt-other")
	f := expectFailure(t, run(t, audit, events, []Checkpoint{other.checkpoint(t, audit, "periodic", 2, events[1].Hash)}, s),
		FailureBadCheckpoint, 2)
	if !strings.Contains(f.Message, `unknown key id "ckpt-other"`) {
		t.Fatalf("message %q", f.Message)
	}
}

func TestCheckpointForAnotherAuditIsBadCheckpoint(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 2)
	f := expectFailure(t, run(t, audit, events, []Checkpoint{s.checkpoint(t, uuid.New(), "periodic", 2, events[1].Hash)}, s),
		FailureBadCheckpoint, 2)
	if !strings.Contains(f.Message, "belongs to audit") {
		t.Fatalf("message %q", f.Message)
	}
}

func TestVerifierCannotBeReusedAfterFinish(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	v, err := NewChainVerifier(audit, "orders", nil, s.ring(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Finish(); err != nil {
		t.Fatal(err)
	}
	var finished ErrFinished
	if _, err := v.Feed(buildChain(t, audit, 1)[0]); !errors.As(err, &finished) {
		t.Fatalf("Feed after Finish: want ErrFinished, got %v", err)
	}
	if _, err := v.Finish(); !errors.As(err, &finished) {
		t.Fatalf("second Finish: want ErrFinished, got %v", err)
	}
}

// ── Trusted keys ─────────────────────────────────────────────────────────────

func expectConfigError(t *testing.T, err error, want string) {
	t.Helper()
	var ce *ConfigurationError
	if !errors.As(err, &ce) || !strings.Contains(ce.Message, want) {
		t.Fatalf("want ConfigurationError containing %q, got %v", want, err)
	}
}

func TestTrustedKeysMustNotBeEmpty(t *testing.T) {
	_, err := LoadTrustedKeys(map[string]string{})
	expectConfigError(t, err, "at least one trusted")
}

func TestTrustedKeyMustBe32Bytes(t *testing.T) {
	_, err := LoadTrustedKeys(map[string]string{"k1": base64.StdEncoding.EncodeToString([]byte("abc"))})
	expectConfigError(t, err, "must decode to 32 bytes, got 3")
}

func TestTrustedKeyMustBeBase64(t *testing.T) {
	_, err := LoadTrustedKeys(map[string]string{"k1": "not base64!!"})
	expectConfigError(t, err, "not valid base64")
}

func TestVerifierNeedsKeys(t *testing.T) {
	_, err := NewChainVerifier(uuid.New(), "orders", nil, KeyRing{}, nil)
	expectConfigError(t, err, "at least one trusted")
}
