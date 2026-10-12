package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Loading audit bundles and trusted key files, with strict validation. Input
// objects are accepted exactly as the AuditLogs API returns them (events from
// GET /v1/audits/{slug}/events, checkpoints from /checkpoints) and fields the
// verifier does not need are ignored. A missing or mistyped field the verifier
// does need is an error, never defaulted.

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func readJSON(path, what string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &BundleError{fmt.Sprintf("cannot read the %s file %s: %v", what, path, err)}
	}
	if !json.Valid(data) {
		var probe any
		err := json.Unmarshal(data, &probe)
		return nil, &BundleError{fmt.Sprintf("the %s file %s is not valid JSON: %v", what, path, err)}
	}
	return data, nil
}

// LoadBundle reads and validates a bundle file. Events come back once each, in seq order.
func LoadBundle(path string) (Bundle, error) {
	data, err := readJSON(path, "bundle")
	if err != nil {
		return Bundle{}, err
	}
	return ParseBundle(data)
}

// Wire shapes: pointers tell a missing field from a zero value.
type wireEvent struct {
	Seq              *int64  `json:"seq"`
	PrevHash         *string `json:"prev_hash"`
	Hash             *string `json:"hash"`
	CanonicalPayload *string `json:"canonical_payload"`
}

type wireTimestamp struct {
	TSAURL      *string `json:"tsa_url"`
	GenTime     *string `json:"gen_time"`
	TSAResponse *string `json:"tsa_response"`
}

type wireCheckpoint struct {
	ID               *string        `json:"id"`
	AuditID          *string        `json:"audit_id"`
	Kind             *string        `json:"kind"`
	LastSeq          *int64         `json:"last_seq"`
	LastHash         *string        `json:"last_hash"`
	FirstRetainedSeq *int64         `json:"first_retained_seq"`
	Signature        *string        `json:"signature"`
	KeyID            *string        `json:"key_id"`
	SignedAt         *string        `json:"signed_at"`
	Timestamp        *wireTimestamp `json:"timestamp"`
}

type wireBundle struct {
	Format      *string           `json:"format"`
	AuditID     *string           `json:"audit_id"`
	Slug        *string           `json:"slug"`
	Events      *[]wireEvent      `json:"events"`
	Checkpoints *[]wireCheckpoint `json:"checkpoints"`
}

func formatError(detail string) error {
	return &BundleError{"the bundle does not match the " + BundleFormat + " format: " + detail}
}

// ParseBundle validates a bundle that is already in memory as JSON bytes.
// Events may be in any order; a seq that appears twice must be identical both
// times (paging can repeat a record).
func ParseBundle(data []byte) (Bundle, error) {
	var w wireBundle
	if err := json.Unmarshal(data, &w); err != nil {
		return Bundle{}, formatError(err.Error())
	}
	switch {
	case w.Format == nil:
		return Bundle{}, formatError("format is required")
	case *w.Format != BundleFormat:
		return Bundle{}, formatError(fmt.Sprintf("format must be %q, got %q", BundleFormat, *w.Format))
	case w.AuditID == nil:
		return Bundle{}, formatError("audit_id is required")
	case w.Slug == nil || *w.Slug == "":
		return Bundle{}, formatError("slug is required")
	case w.Events == nil:
		return Bundle{}, formatError("events is required")
	case w.Checkpoints == nil:
		return Bundle{}, formatError("checkpoints is required")
	}
	auditID, err := uuid.Parse(*w.AuditID)
	if err != nil {
		return Bundle{}, formatError(fmt.Sprintf("audit_id: %v", err))
	}
	b := Bundle{Format: *w.Format, AuditID: auditID, Slug: *w.Slug}

	seen := map[int64]StoredEvent{}
	for i, we := range *w.Events {
		e, err := we.validate()
		if err != nil {
			return Bundle{}, formatError(fmt.Sprintf("events[%d]: %v", i, err))
		}
		if earlier, ok := seen[e.Seq]; ok && !earlier.same(e) {
			return Bundle{}, &BundleError{fmt.Sprintf("seq %d appears twice with different content", e.Seq)}
		}
		seen[e.Seq] = e
	}
	seqs := make([]int64, 0, len(seen))
	for s := range seen {
		seqs = append(seqs, s)
	}
	slices.Sort(seqs)
	b.Events = make([]StoredEvent, 0, len(seqs))
	for _, s := range seqs {
		b.Events = append(b.Events, seen[s])
	}

	b.Checkpoints = make([]Checkpoint, 0, len(*w.Checkpoints))
	for i, wc := range *w.Checkpoints {
		c, err := wc.validate()
		if err != nil {
			return Bundle{}, formatError(fmt.Sprintf("checkpoints[%d]: %v", i, err))
		}
		b.Checkpoints = append(b.Checkpoints, c)
	}
	return b, nil
}

func (w wireEvent) validate() (StoredEvent, error) {
	switch {
	case w.Seq == nil:
		return StoredEvent{}, fmt.Errorf("seq is required")
	case *w.Seq < 1:
		return StoredEvent{}, fmt.Errorf("seq must be at least 1, got %d", *w.Seq)
	case w.PrevHash != nil && !hashPattern.MatchString(*w.PrevHash):
		return StoredEvent{}, fmt.Errorf("prev_hash must be null or 64 lowercase hex characters")
	case w.Hash == nil || !hashPattern.MatchString(*w.Hash):
		return StoredEvent{}, fmt.Errorf("hash must be 64 lowercase hex characters")
	case w.CanonicalPayload == nil || utf8.RuneCountInString(*w.CanonicalPayload) < 2:
		return StoredEvent{}, fmt.Errorf("canonical_payload must be a string of at least 2 characters")
	}
	return StoredEvent{Seq: *w.Seq, PrevHash: w.PrevHash, Hash: *w.Hash, CanonicalPayload: *w.CanonicalPayload}, nil
}

func (w wireCheckpoint) validate() (Checkpoint, error) {
	var c Checkpoint
	need := func(v *string, name string) error {
		if v == nil || *v == "" {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	for _, f := range []struct {
		v    *string
		name string
	}{{w.ID, "id"}, {w.AuditID, "audit_id"}, {w.Kind, "kind"}, {w.LastHash, "last_hash"},
		{w.Signature, "signature"}, {w.KeyID, "key_id"}, {w.SignedAt, "signed_at"}} {
		if err := need(f.v, f.name); err != nil {
			return c, err
		}
	}
	var err error
	if c.ID, err = uuid.Parse(*w.ID); err != nil {
		return c, fmt.Errorf("id: %v", err)
	}
	if c.AuditID, err = uuid.Parse(*w.AuditID); err != nil {
		return c, fmt.Errorf("audit_id: %v", err)
	}
	if *w.Kind != "periodic" && *w.Kind != "retention" {
		return c, fmt.Errorf("kind must be periodic or retention, got %q", *w.Kind)
	}
	if w.LastSeq == nil || *w.LastSeq < 1 {
		return c, fmt.Errorf("last_seq is required and must be at least 1")
	}
	if !hashPattern.MatchString(*w.LastHash) {
		return c, fmt.Errorf("last_hash must be 64 lowercase hex characters")
	}
	if *w.Kind == "retention" && (w.FirstRetainedSeq == nil || *w.FirstRetainedSeq != *w.LastSeq+1) {
		return c, fmt.Errorf("a retention checkpoint needs first_retained_seq = last_seq + 1")
	}
	if *w.Kind == "periodic" && w.FirstRetainedSeq != nil {
		return c, fmt.Errorf("a periodic checkpoint has no first_retained_seq")
	}
	signedAt, hasZone, err := parseTime(*w.SignedAt)
	if err != nil {
		return c, fmt.Errorf("signed_at: %v", err)
	}
	c.Kind, c.LastSeq, c.LastHash, c.FirstRetainedSeq = *w.Kind, *w.LastSeq, *w.LastHash, w.FirstRetainedSeq
	c.Signature, c.KeyID, c.SignedAt, c.signedAtNaive = *w.Signature, *w.KeyID, signedAt, !hasZone
	if w.Timestamp != nil {
		t := w.Timestamp
		for _, f := range []struct {
			v    *string
			name string
		}{{t.TSAURL, "timestamp.tsa_url"}, {t.GenTime, "timestamp.gen_time"}, {t.TSAResponse, "timestamp.tsa_response"}} {
			if err := need(f.v, f.name); err != nil {
				return c, err
			}
		}
		gen, hasZone, err := parseTime(*t.GenTime)
		if err != nil {
			return c, fmt.Errorf("timestamp.gen_time: %v", err)
		}
		if !hasZone {
			return c, fmt.Errorf("timestamp.gen_time must include a time zone")
		}
		c.Timestamp = &CheckpointTimestamp{TSAURL: *t.TSAURL, GenTime: gen, TSAResponse: *t.TSAResponse}
	}
	return c, nil
}

// parseTime reads an RFC 3339 / ISO 8601 date-time ("T" or a space between
// date and time), with or without a zone. hasZone says whether one was given.
func parseTime(s string) (t time.Time, hasZone bool, err error) {
	v := strings.Replace(s, " ", "T", 1)
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, true, nil
	}
	if t, err := time.Parse("2006-01-02T15:04:05.999999999", v); err == nil {
		return t, false, nil
	}
	return time.Time{}, false, fmt.Errorf("%q is not an ISO 8601 date-time", s)
}

// ReadKeyFile reads trusted checkpoint keys. It accepts either
// {"key_id": "base64 public key"} or the service's GET /v1/checkpoint-keys
// response {"keys": [{"key_id", "algorithm", "public_key", ...}]}.
func ReadKeyFile(path string) (map[string]string, error) {
	data, err := readJSON(path, "keys")
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, &BundleError{fmt.Sprintf("the keys file %s is not valid JSON: %v", path, err)}
	}
	obj, isObj := doc.(map[string]any)
	if isObj {
		if list, ok := obj["keys"].([]any); ok {
			pairs := map[string]string{}
			for _, raw := range list {
				item, ok := raw.(map[string]any)
				keyID, idOK := item["key_id"].(string)
				pub, pubOK := item["public_key"].(string)
				if !ok || !idOK || !pubOK {
					return nil, &ConfigurationError{"each entry in 'keys' needs string key_id and public_key"}
				}
				if alg, _ := item["algorithm"].(string); alg != "Ed25519" {
					return nil, &ConfigurationError{fmt.Sprintf("key %q is not an Ed25519 key", keyID)}
				}
				pairs[keyID] = pub
			}
			return pairs, nil
		}
		pairs := make(map[string]string, len(obj))
		for k, v := range obj {
			s, ok := v.(string)
			if !ok {
				pairs = nil
				break
			}
			pairs[k] = s
		}
		if pairs != nil {
			return pairs, nil
		}
	}
	return nil, &ConfigurationError{`the keys file must be {"key_id": "base64 key"} or a /v1/checkpoint-keys response`}
}
