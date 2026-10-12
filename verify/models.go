package verify

import (
	"time"

	"github.com/google/uuid"
)

// BundleFormat is the only bundle format this version reads.
const BundleFormat = "auditlogs-bundle-v1"

// StoredEvent is one stored chain record. CanonicalPayload is the exact text
// that was hashed: Hash == sha256(PrevHash + CanonicalPayload), with the
// genesis hash in place of PrevHash for seq 1 (stored as null).
type StoredEvent struct {
	Seq              int64
	PrevHash         *string
	Hash             string
	CanonicalPayload string
}

// same reports whether two records are identical (paging can repeat one).
func (e StoredEvent) same(o StoredEvent) bool {
	if (e.PrevHash == nil) != (o.PrevHash == nil) {
		return false
	}
	if e.PrevHash != nil && *e.PrevHash != *o.PrevHash {
		return false
	}
	return e.Seq == o.Seq && e.Hash == o.Hash && e.CanonicalPayload == o.CanonicalPayload
}

// CheckpointTimestamp is an RFC 3161 timestamp of a checkpoint from an
// independent timestamp authority.
type CheckpointTimestamp struct {
	TSAURL      string
	GenTime     time.Time
	TSAResponse string // standard base64 of the DER TimeStampResp
}

// Checkpoint is a signed statement of the chain's hash at LastSeq.
type Checkpoint struct {
	ID               uuid.UUID
	AuditID          uuid.UUID
	Kind             string // "periodic" or "retention"
	LastSeq          int64
	LastHash         string
	FirstRetainedSeq *int64 // LastSeq + 1 for retention, nil for periodic
	Signature        string // standard base64 Ed25519 signature
	KeyID            string
	SignedAt         time.Time
	Timestamp        *CheckpointTimestamp

	// signedAtNaive is set by the bundle parser when signed_at carried no time
	// zone; such a checkpoint cannot form a signed message (BAD_CHECKPOINT).
	signedAtNaive bool
}

// Bundle is everything needed to verify one audit offline. See docs/SPEC.md.
// After ParseBundle, Events hold each seq once, in ascending order.
type Bundle struct {
	Format      string
	AuditID     uuid.UUID
	Slug        string
	Events      []StoredEvent
	Checkpoints []Checkpoint
}

// FailureKind names the first break found.
type FailureKind string

// The failure kinds, in the order they are looked for: checkpoints first,
// then events, then truncation, then timestamps.
const (
	FailureBadCheckpoint      FailureKind = "BAD_CHECKPOINT"
	FailureGap                FailureKind = "GAP"
	FailureBrokenLink         FailureKind = "BROKEN_LINK"
	FailureModified           FailureKind = "MODIFIED"
	FailureCheckpointMismatch FailureKind = "CHECKPOINT_MISMATCH"
	FailureTruncated          FailureKind = "TRUNCATED"
	FailureBadAnchor          FailureKind = "BAD_ANCHOR"
)

// Status is the overall verdict.
type Status string

const (
	StatusIntact   Status = "INTACT"
	StatusTampered Status = "TAMPERED"
)

// Failure is the first break found. Seq is where the chain stops being trustworthy.
type Failure struct {
	Kind         FailureKind `json:"kind"`
	Seq          int64       `json:"seq"`
	ExpectedHash *string     `json:"expected_hash"`
	FoundHash    *string     `json:"found_hash"`
	Message      string      `json:"message"`
}

// Anchor is the signed retention checkpoint the walk started from.
type Anchor struct {
	LastSeq          int64  `json:"last_seq"`
	LastHash         string `json:"last_hash"`
	FirstRetainedSeq int64  `json:"first_retained_seq"`
}

// Report has the same shape as the service's GET /v1/audits/{slug}/verify
// response and the Python package's report.
type Report struct {
	Status             Status    `json:"status"`
	Slug               string    `json:"slug"`
	AuditID            uuid.UUID `json:"audit_id"`
	EventsChecked      int64     `json:"events_checked"`
	FirstSequence      int64     `json:"first_sequence"`
	LastSequence       int64     `json:"last_sequence"`
	LastHash           string    `json:"last_hash"`
	CheckpointsChecked int       `json:"checkpoints_checked"`
	// Independent timestamps: how many verified, and how many checkpoints have
	// none. TimestampsChecked is false when the caller chose not to check them.
	AnchorsChecked        int      `json:"anchors_checked"`
	CheckpointsUnanchored int      `json:"checkpoints_unanchored"`
	TimestampsChecked     bool     `json:"timestamps_checked"`
	Anchor                *Anchor  `json:"anchor"`
	Failure               *Failure `json:"failure"`
}

// Intact reports whether no break was found.
func (r Report) Intact() bool { return r.Status == StatusIntact }
