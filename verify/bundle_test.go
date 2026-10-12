package verify

// Bundle loading and key files.

import (
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func eventJSON(e StoredEvent) map[string]any {
	m := map[string]any{"seq": e.Seq, "prev_hash": nil, "hash": e.Hash, "canonical_payload": e.CanonicalPayload}
	if e.PrevHash != nil {
		m["prev_hash"] = *e.PrevHash
	}
	return m
}

func checkpointJSON(c Checkpoint) map[string]any {
	m := map[string]any{
		"id": c.ID.String(), "audit_id": c.AuditID.String(), "kind": c.Kind, "last_seq": c.LastSeq,
		"last_hash": c.LastHash, "signature": c.Signature, "key_id": c.KeyID,
		"signed_at": c.SignedAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
	}
	if c.FirstRetainedSeq != nil {
		m["first_retained_seq"] = *c.FirstRetainedSeq
	}
	return m
}

func bundleDict(auditID uuid.UUID, events []StoredEvent, cps []Checkpoint) map[string]any {
	ev := make([]any, 0, len(events))
	for _, e := range events {
		ev = append(ev, eventJSON(e))
	}
	cs := make([]any, 0, len(cps))
	for _, c := range cps {
		cs = append(cs, checkpointJSON(c))
	}
	return map[string]any{"format": BundleFormat, "audit_id": auditID.String(), "slug": "orders", "events": ev, "checkpoints": cs}
}

func writeJSON(t *testing.T, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func expectBundleError(t *testing.T, err error, want string) {
	t.Helper()
	var be *BundleError
	if !errors.As(err, &be) || !strings.Contains(be.Message, want) {
		t.Fatalf("want BundleError containing %q, got %v", want, err)
	}
}

func TestEventsAreSortedAndRepeatsCollapsed(t *testing.T) {
	audit := uuid.New()
	events := buildChain(t, audit, 5)
	shuffled := append(append([]StoredEvent{}, events...), events[2]) // a page boundary repeated one record
	rand.New(rand.NewSource(7)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	b, err := LoadBundle(writeJSON(t, "b.json", bundleDict(audit, shuffled, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var seqs []int64
	for _, e := range b.Events {
		seqs = append(seqs, e.Seq)
	}
	if len(seqs) != 5 || seqs[0] != 1 || seqs[4] != 5 {
		t.Fatalf("seqs %v", seqs)
	}
}

func TestConflictingDuplicateIsRejected(t *testing.T) {
	audit := uuid.New()
	events := buildChain(t, audit, 3)
	other := events[1]
	other.CanonicalPayload += " "
	_, err := LoadBundle(writeJSON(t, "b.json", bundleDict(audit, append(events, other), nil)))
	expectBundleError(t, err, "seq 2 appears twice with different content")
}

func TestWrongFormatIsRejected(t *testing.T) {
	audit := uuid.New()
	data := bundleDict(audit, buildChain(t, audit, 1), nil)
	data["format"] = "something-else"
	_, err := LoadBundle(writeJSON(t, "b.json", data))
	expectBundleError(t, err, "does not match the auditlogs-bundle-v1 format")
}

func TestMissingRequiredFieldsAreNamed(t *testing.T) {
	audit := uuid.New()
	cases := map[string]func(m map[string]any){
		"slug is required":        func(m map[string]any) { delete(m, "slug") },
		"events is required":      func(m map[string]any) { delete(m, "events") },
		"events[0]: hash must be": func(m map[string]any) { m["events"].([]any)[0].(map[string]any)["hash"] = "ABC" },
		"events[0]: seq must be at least 1": func(m map[string]any) {
			m["events"].([]any)[0].(map[string]any)["seq"] = 0
		},
	}
	for want, edit := range cases {
		data := bundleDict(audit, buildChain(t, audit, 1), nil)
		edit(data)
		_, err := LoadBundle(writeJSON(t, "b.json", data))
		expectBundleError(t, err, want)
	}
}

func TestCheckpointKindRulesAreEnforced(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 2)
	cp := checkpointJSON(s.checkpoint(t, audit, "periodic", 2, events[1].Hash))
	cp["first_retained_seq"] = 3
	data := bundleDict(audit, events, nil)
	data["checkpoints"] = []any{cp}
	_, err := LoadBundle(writeJSON(t, "b.json", data))
	expectBundleError(t, err, "a periodic checkpoint has no first_retained_seq")
}

func TestASignedAtWithoutZoneIsABadCheckpoint(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 2)
	cp := checkpointJSON(s.checkpoint(t, audit, "periodic", 2, events[1].Hash))
	cp["signed_at"] = strings.TrimSuffix(cp["signed_at"].(string), "Z")
	data := bundleDict(audit, events, nil)
	data["checkpoints"] = []any{cp}
	b, err := LoadBundle(writeJSON(t, "b.json", data))
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyBundle(b, s.ring(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := expectFailure(t, r, FailureBadCheckpoint, 2)
	if !strings.Contains(f.Message, "signed_at has no timezone") {
		t.Fatalf("message %q", f.Message)
	}
}

func TestMissingAndInvalidFilesAreReported(t *testing.T) {
	_, err := LoadBundle(filepath.Join(t.TempDir(), "nope.json"))
	expectBundleError(t, err, "cannot read the bundle file")
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadBundle(bad)
	expectBundleError(t, err, "is not valid JSON")
}

func TestAPIEventObjectsLoadAsReturned(t *testing.T) {
	// Extra fields from GET /events (actor, action, ...) are ignored, not rejected.
	audit := uuid.New()
	e := eventJSON(buildChain(t, audit, 1)[0])
	e["actor"] = map[string]any{"type": "user", "id": "u"}
	e["action"], e["metadata"] = "a", map[string]any{}
	data := bundleDict(audit, nil, nil)
	data["events"] = []any{e}
	b, err := LoadBundle(writeJSON(t, "b.json", data))
	if err != nil || b.Events[0].Seq != 1 {
		t.Fatalf("%+v %v", b, err)
	}
}

func TestBundleVerifiesAfterARoundTrip(t *testing.T) {
	audit, s := uuid.New(), newSigner(t, "ckpt-test")
	events := buildChain(t, audit, 4)
	cps := []Checkpoint{s.checkpoint(t, audit, "periodic", 4, events[3].Hash)}
	b, err := LoadBundle(writeJSON(t, "b.json", bundleDict(audit, events, cps)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyBundle(b, s.ring(t), nil)
	if err != nil || !r.Intact() || r.CheckpointsChecked != 1 || r.Slug != "orders" {
		t.Fatalf("%+v %v", r, err)
	}
	if b.Checkpoints[0].SignedAt.Sub(cps[0].SignedAt) != time.Duration(0) {
		t.Fatalf("signed_at changed in the round trip")
	}
}

// ── Key files ────────────────────────────────────────────────────────────────

func TestKeyFileAcceptsBothShapes(t *testing.T) {
	s := newSigner(t, "ckpt-test")
	plain, err := ReadKeyFile(writeJSON(t, "k1.json", s.trusted()))
	if err != nil {
		t.Fatal(err)
	}
	api, err := ReadKeyFile(writeJSON(t, "k2.json", map[string]any{
		"keys": []any{map[string]any{"key_id": s.keyID, "algorithm": "Ed25519", "public_key": s.publicB64()}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if plain[s.keyID] != s.publicB64() || api[s.keyID] != s.publicB64() || len(plain) != 1 || len(api) != 1 {
		t.Fatalf("plain %v api %v", plain, api)
	}
}

func TestKeyFileRejectsOtherAlgorithms(t *testing.T) {
	_, err := ReadKeyFile(writeJSON(t, "k.json", map[string]any{
		"keys": []any{map[string]any{"key_id": "k", "algorithm": "RSA", "public_key": "AA=="}},
	}))
	expectConfigError(t, err, "is not an Ed25519 key")
}

func TestKeyFileRejectsOtherShapes(t *testing.T) {
	_, err := ReadKeyFile(writeJSON(t, "k.json", []any{"a"}))
	expectConfigError(t, err, "the keys file must be")
	_, err = ReadKeyFile(writeJSON(t, "k.json", map[string]any{"k": 1}))
	expectConfigError(t, err, "the keys file must be")
}
