package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/google/uuid"
)

// Independent verification of an audit's hash chain and signed checkpoints,
// mirroring the service's verifier so a customer can check their audit
// without trusting the service's own /verify answer:
//
//	genesis      = sha256("GENESIS" + audit_id)              (hex)
//	hash(seq n)  = sha256(hash(seq n-1) + canonical_payload)  (hex)
//
// canonical_payload is the exact text the service hashed and returns with
// each event, so nothing is re-serialized here. Checkpoints are Ed25519
// signatures over the "auditlogs-checkpoint-v1" message, checked against
// public keys you trust. Pass keys you obtained out of band (pinned in your
// configuration); keys fetched from the service you are checking only prove
// consistency with that service.
//
// Limitation: when decoding a payload to confirm its audit_id, seq and
// prev_hash, field names are matched exactly (as the Python package does).
// The service matches them case-insensitively, so for a hand-crafted payload
// with oddly cased keys this check is stricter than the service's.

// MessageVersion is the first line of every signed checkpoint message.
const MessageVersion = "auditlogs-checkpoint-v1"

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ── Primitives ───────────────────────────────────────────────────────────────

// GenesisHash is the hash that seq 1 links to.
func GenesisHash(auditID uuid.UUID) string {
	sum := sha256.Sum256([]byte("GENESIS" + auditID.String()))
	return hex.EncodeToString(sum[:])
}

// EventHash is sha256(prevHash + canonicalPayload). prevHash must be a
// 64-character lowercase hex digest.
func EventHash(prevHash, canonicalPayload string) (string, error) {
	if !hashPattern.MatchString(prevHash) {
		return "", fmt.Errorf("previous hash %q is not a 64-character lowercase hex digest", prevHash)
	}
	sum := sha256.Sum256([]byte(prevHash + canonicalPayload))
	return hex.EncodeToString(sum[:]), nil
}

// CheckpointMessage is the exact bytes the service signed for cp. An error
// means cp's fields cannot form a valid signed message.
func CheckpointMessage(cp Checkpoint) ([]byte, error) {
	if !hashPattern.MatchString(cp.LastHash) {
		return nil, fmt.Errorf("last_hash is not a 64-character lowercase hex digest")
	}
	if cp.LastSeq < 1 {
		return nil, fmt.Errorf("last_seq must be at least 1, got %d", cp.LastSeq)
	}
	if !keyIDPattern.MatchString(cp.KeyID) {
		return nil, fmt.Errorf("key_id %q has an invalid format", cp.KeyID)
	}
	if cp.signedAtNaive {
		return nil, fmt.Errorf("signed_at has no timezone")
	}
	var firstRetained string
	switch cp.Kind {
	case "periodic":
		if cp.FirstRetainedSeq != nil {
			return nil, fmt.Errorf("a periodic checkpoint has no first_retained_seq")
		}
		firstRetained = "none"
	case "retention":
		if cp.FirstRetainedSeq == nil || *cp.FirstRetainedSeq != cp.LastSeq+1 {
			return nil, fmt.Errorf("a retention checkpoint needs first_retained_seq = last_seq + 1")
		}
		firstRetained = strconv.FormatInt(*cp.FirstRetainedSeq, 10)
	default:
		return nil, fmt.Errorf("kind must be periodic or retention, got %q", cp.Kind)
	}
	signedAt := cp.SignedAt.UTC().Format("2006-01-02T15:04:05.000000Z")
	return fmt.Appendf(nil, "%s\nkind=%s\naudit_id=%s\nlast_seq=%d\nlast_hash=%s\nfirst_retained_seq=%s\nsigned_at=%s\nkey_id=%s\n",
		MessageVersion, cp.Kind, cp.AuditID, cp.LastSeq, cp.LastHash, firstRetained, signedAt, cp.KeyID), nil
}

// ── Trusted keys ─────────────────────────────────────────────────────────────

// KeyRing maps a key id to a trusted Ed25519 public key.
type KeyRing map[string]ed25519.PublicKey

// LoadTrustedKeys builds the key ring from {key_id: base64 public key}. An
// empty or malformed key set is an error, never an empty ring.
func LoadTrustedKeys(keys map[string]string) (KeyRing, error) {
	if len(keys) == 0 {
		return nil, &ConfigurationError{"at least one trusted checkpoint public key is required"}
	}
	ring := make(KeyRing, len(keys))
	for keyID, encoded := range keys {
		if !keyIDPattern.MatchString(keyID) {
			return nil, &ConfigurationError{fmt.Sprintf("checkpoint key id %q has an invalid format", keyID)}
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, &ConfigurationError{fmt.Sprintf("checkpoint key %q is not valid base64: %v", keyID, err)}
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, &ConfigurationError{fmt.Sprintf("checkpoint key %q must decode to %d bytes, got %d",
				keyID, ed25519.PublicKeySize, len(raw))}
		}
		ring[keyID] = ed25519.PublicKey(raw)
	}
	return ring, nil
}

// CheckpointProblem says why cp cannot be trusted, or "" when its signature
// verifies against ring and it belongs to auditID.
func CheckpointProblem(cp Checkpoint, auditID uuid.UUID, ring KeyRing) string {
	if cp.AuditID != auditID {
		return fmt.Sprintf("checkpoint at seq %d belongs to audit %s", cp.LastSeq, cp.AuditID)
	}
	message, err := CheckpointMessage(cp)
	if err != nil {
		return fmt.Sprintf("checkpoint at seq %d is not trustworthy: invalid checkpoint: %v", cp.LastSeq, err)
	}
	key, ok := ring[cp.KeyID]
	if !ok {
		return fmt.Sprintf("checkpoint at seq %d is not trustworthy: signed with an unknown key id %q", cp.LastSeq, cp.KeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature) {
		return fmt.Sprintf("checkpoint at seq %d is not trustworthy: signature does not verify", cp.LastSeq)
	}
	return ""
}

// ── Verifier ─────────────────────────────────────────────────────────────────

type start struct {
	prevHash string
	anchor   *Checkpoint
}

// ChainVerifier is a streaming verifier: call Feed with events in ascending
// seq order, then Finish. It never needs the whole chain in memory. Single use.
type ChainVerifier struct {
	auditID     uuid.UUID
	slug        string
	genesis     string
	failure     *Failure
	checkpoints []Checkpoint
	cpChecked   int
	bySeq       map[int64][]Checkpoint
	starts      map[int64]start
	baseSeq     int64
	baseHash    string
	started     bool
	expected    int64
	prev        string
	eventsCount int64
	firstSeq    int64
	lastSeq     int64
	lastHash    string
	anchor      *Checkpoint
	finished    bool
	policy      *AnchorPolicy // nil: the caller chose not to check timestamps
	anchorsOK   int
	unanchored  int
}

// NewChainVerifier checks every checkpoint's signature first; a bad one is
// the result (Feed then returns false at once). policy checks the checkpoints'
// independent timestamps; pass nil only to skip that on purpose (the report
// then says so). The error is only for an unusable argument.
func NewChainVerifier(auditID uuid.UUID, slug string, checkpoints []Checkpoint, ring KeyRing, policy *AnchorPolicy) (*ChainVerifier, error) {
	if len(ring) == 0 {
		return nil, &ConfigurationError{"at least one trusted checkpoint public key is required"}
	}
	v := &ChainVerifier{
		auditID: auditID, slug: slug, genesis: GenesisHash(auditID), policy: policy,
		bySeq: map[int64][]Checkpoint{}, starts: map[int64]start{},
	}
	v.starts[1] = start{prevHash: v.genesis}
	v.baseHash = v.genesis
	v.checkpoints = append([]Checkpoint(nil), checkpoints...)
	sort.SliceStable(v.checkpoints, func(i, j int) bool { return v.checkpoints[i].LastSeq < v.checkpoints[j].LastSeq })
	for _, cp := range v.checkpoints {
		if problem := CheckpointProblem(cp, auditID, ring); problem != "" {
			v.fail(FailureBadCheckpoint, cp.LastSeq, problem, "", "")
			return v, nil
		}
	}
	v.cpChecked = len(v.checkpoints)
	for i := range v.checkpoints {
		cp := &v.checkpoints[i]
		if cp.Kind == "retention" {
			v.starts[cp.LastSeq+1] = start{prevHash: cp.LastHash, anchor: cp}
			if cp.LastSeq > v.baseSeq {
				v.baseSeq, v.baseHash = cp.LastSeq, cp.LastHash
			}
		}
		v.bySeq[cp.LastSeq] = append(v.bySeq[cp.LastSeq], *cp)
	}
	return v, nil
}

// Failed reports whether a break has been found; stop feeding events then.
func (v *ChainVerifier) Failed() bool { return v.failure != nil }

func (v *ChainVerifier) fail(kind FailureKind, seq int64, message, expected, found string) {
	f := &Failure{Kind: kind, Seq: seq, Message: message}
	if expected != "" {
		f.ExpectedHash = &expected
	}
	if found != "" {
		f.FoundHash = &found
	}
	v.failure = f
}

// Feed checks one event and returns false once the chain is broken. The error
// is only for use after Finish.
func (v *ChainVerifier) Feed(e StoredEvent) (bool, error) {
	if v.finished {
		return false, ErrFinished{}
	}
	if v.Failed() {
		return false, nil
	}
	if !v.started {
		v.started = true
		if !v.begin(e.Seq) {
			return false, nil
		}
	}
	if e.Seq != v.expected {
		v.fail(FailureGap, v.expected, fmt.Sprintf("expected seq %d but the next stored event is seq %d", v.expected, e.Seq), "", "")
		return false, nil
	}

	storedPrev := ""
	if e.PrevHash != nil {
		storedPrev = *e.PrevHash
	} else if e.Seq == 1 && v.prev == v.genesis {
		storedPrev = v.genesis // the writer stores NULL for the first event
	}
	if storedPrev != v.prev {
		v.fail(FailureBrokenLink, e.Seq, fmt.Sprintf("prev_hash at seq %d does not match the hash of the previous record", e.Seq), v.prev, storedPrev)
		return false, nil
	}

	computed, err := EventHash(v.prev, e.CanonicalPayload)
	if err != nil {
		v.fail(FailureBrokenLink, e.Seq, fmt.Sprintf("cannot hash seq %d: %v", e.Seq, err), v.prev, "")
		return false, nil
	}
	if computed != e.Hash {
		v.fail(FailureModified, e.Seq, fmt.Sprintf("payload at seq %d does not hash to the stored hash", e.Seq), computed, e.Hash)
		return false, nil
	}
	if msg := v.payloadMismatch(e); msg != "" {
		v.fail(FailureModified, e.Seq, msg, "", "")
		return false, nil
	}
	for _, cp := range v.bySeq[e.Seq] {
		if cp.LastHash != e.Hash {
			v.fail(FailureCheckpointMismatch, e.Seq,
				fmt.Sprintf("signed %s checkpoint at seq %d records a different hash", cp.Kind, e.Seq), cp.LastHash, e.Hash)
			return false, nil
		}
	}

	if v.eventsCount == 0 {
		v.firstSeq = e.Seq
	}
	v.eventsCount++
	v.lastSeq, v.lastHash = e.Seq, e.Hash
	v.prev = e.Hash
	v.expected = e.Seq + 1
	return true, nil
}

// begin chooses the starting point for the first stored event.
func (v *ChainVerifier) begin(firstSeq int64) bool {
	if s, ok := v.starts[firstSeq]; ok {
		v.expected, v.prev, v.anchor = firstSeq, s.prevHash, s.anchor
		return true
	}
	// No legitimate start explains this first event: earlier records were
	// deleted without a retention anchor. Report the first missing seq.
	missing := int64(-1)
	for s := range v.starts {
		if s <= firstSeq && s > missing {
			missing = s
		}
	}
	if missing == -1 {
		for s := range v.starts {
			if missing == -1 || s < missing {
				missing = s
			}
		}
	}
	v.fail(FailureGap, missing, fmt.Sprintf("records from seq %d to %d are missing and no retention checkpoint covers them",
		missing, firstSeq-1), "", "")
	return false
}

// payloadMismatch checks that the hashed payload agrees with the record about
// its audit, position and predecessor, so a valid record cannot be moved.
func (v *ChainVerifier) payloadMismatch(e StoredEvent) string {
	dec := json.NewDecoder(bytes.NewReader([]byte(e.CanonicalPayload)))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return fmt.Sprintf("payload at seq %d is not valid JSON: %v", e.Seq, err)
	}
	body, ok := raw.(map[string]any)
	if !ok {
		return fmt.Sprintf("payload at seq %d is not valid JSON: not an object", e.Seq)
	}
	if id, ok := body["audit_id"].(string); !ok || id != v.auditID.String() {
		return fmt.Sprintf("payload at seq %d names a different audit", e.Seq)
	}
	// An integer literal only: 3.0 or 3e0 is a different seq field.
	if n, ok := body["seq"].(json.Number); !ok || n.String() != strconv.FormatInt(e.Seq, 10) {
		return fmt.Sprintf("payload at seq %d records a different seq", e.Seq)
	}
	if p, ok := body["prev_hash"].(string); !ok || p != v.prev {
		return fmt.Sprintf("payload at seq %d records a different prev_hash", e.Seq)
	}
	return ""
}

// Finish completes the run. A signed checkpoint beyond the last stored event
// means the newest records were removed (TRUNCATED). Timestamps are checked
// last, only on an otherwise intact chain.
func (v *ChainVerifier) Finish() (Report, error) {
	if v.finished {
		return Report{}, ErrFinished{}
	}
	v.finished = true
	if !v.Failed() {
		if v.eventsCount == 0 {
			v.lastSeq, v.lastHash = v.baseSeq, v.baseHash
		}
		for _, cp := range v.checkpoints {
			if cp.LastSeq > v.lastSeq {
				v.fail(FailureTruncated, v.lastSeq+1, fmt.Sprintf("signed checkpoint covers seq %d but stored events end at seq %d",
					cp.LastSeq, v.lastSeq), cp.LastHash, "")
				break
			}
		}
	}
	if !v.Failed() {
		v.checkTimestamps()
	}
	r := Report{
		Status: StatusIntact, Slug: v.slug, AuditID: v.auditID,
		EventsChecked: v.eventsCount, FirstSequence: v.firstSeq, LastSequence: v.lastSeq, LastHash: v.lastHash,
		CheckpointsChecked: v.cpChecked, AnchorsChecked: v.anchorsOK, CheckpointsUnanchored: v.unanchored,
		TimestampsChecked: v.policy != nil, Failure: v.failure,
	}
	if v.Failed() {
		r.Status = StatusTampered
	}
	if v.anchor != nil {
		r.Anchor = &Anchor{LastSeq: v.anchor.LastSeq, LastHash: v.anchor.LastHash, FirstRetainedSeq: v.anchor.LastSeq + 1}
	}
	return r, nil
}

// checkTimestamps checks every checkpoint's independent timestamp (the same
// rules as the service). A checkpoint without one is counted, not failed.
func (v *ChainVerifier) checkTimestamps() {
	for _, cp := range v.checkpoints {
		if cp.Timestamp == nil {
			v.unanchored++
			continue
		}
		if v.policy == nil {
			continue
		}
		message, err := CheckpointMessage(cp)
		if err != nil { // already verified above; kept explicit rather than ignored
			v.fail(FailureBadCheckpoint, cp.LastSeq, fmt.Sprintf("checkpoint at seq %d: %v", cp.LastSeq, err), "", "")
			return
		}
		if problem := AnchorProblem(cp, message, *v.policy); problem != "" {
			v.fail(FailureBadAnchor, cp.LastSeq, fmt.Sprintf("timestamp of the %s checkpoint at seq %d: %s", cp.Kind, cp.LastSeq, problem), "", "")
			return
		}
		v.anchorsOK++
	}
}

// VerifyChain verifies events (ascending seq order) and checkpoints you already hold.
func VerifyChain(auditID uuid.UUID, slug string, events []StoredEvent, checkpoints []Checkpoint, ring KeyRing, policy *AnchorPolicy) (Report, error) {
	v, err := NewChainVerifier(auditID, slug, checkpoints, ring, policy)
	if err != nil {
		return Report{}, err
	}
	for _, e := range events {
		ok, err := v.Feed(e)
		if err != nil {
			return Report{}, err
		}
		if !ok {
			break
		}
	}
	return v.Finish()
}

// VerifyBundle verifies a loaded audit bundle (see LoadBundle).
func VerifyBundle(b Bundle, ring KeyRing, policy *AnchorPolicy) (Report, error) {
	return VerifyChain(b.AuditID, b.Slug, b.Events, b.Checkpoints, ring, policy)
}
