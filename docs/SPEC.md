# AuditLogs verification spec (v1)

What an independent checker must compute to verify an AuditLogs audit. The service
(`internal/core/hashchain`), this Go module and the Python package `auditlogs-verify` all
implement it, and all must reproduce the [test values](#test-values) exactly.

## Hash chain

All hashes are SHA-256, written as 64 lowercase hex characters.

```
genesis       = sha256( "GENESIS" + audit_id )              audit_id as lowercase hyphenated UUID text
hash(seq 1)   = sha256( genesis + canonical_payload(1) )
hash(seq n)   = sha256( hash(seq n-1) + canonical_payload(n) )
```

`+` is plain concatenation of the UTF-8 bytes; the previous hash goes in as its hex text.
`canonical_payload` is the exact text the service stored and hashed. A checker hashes it as
given and never rebuilds it.

The stored `prev_hash` of seq 1 is null and means the genesis hash. Each payload is a JSON object
whose `audit_id`, `seq` and `prev_hash` must equal the record's own values, so a valid record
cannot be moved to another audit or position.

### How the service writes payloads (informational)

A checker never rebuilds a payload, so this only matters to anyone writing events by hand:

- `schema_version: 2` (since 2026-10-12): the whole event object in RFC 8785 JSON Canonicalization
  Scheme form. Keys are sorted by UTF-16 code units, there is no whitespace, strings use only the
  escapes JSON requires, and numbers are written as ECMAScript does. Integers beyond plus or
  minus 2^53-1 are refused at ingestion (send them as strings), never rounded.
- `schema_version: 1` (older rows): struct-ordered keys and an embedded empty `"hash"`.

Both kinds verify the same way, because the stored text is what is hashed.

## Checkpoints

A checkpoint is an Ed25519 signature over this exact text (each line ends with `\n`):

```
auditlogs-checkpoint-v1
kind=<periodic|retention>
audit_id=<uuid>
last_seq=<integer>
last_hash=<64 hex>
first_retained_seq=<last_seq + 1 for retention, "none" for periodic>
signed_at=<UTC, YYYY-MM-DDTHH:MM:SS.ffffffZ, always six fraction digits>
key_id=<[A-Za-z0-9._-]{1,64}>
```

The signature is standard base64, and so are the public keys (raw 32 bytes). Keys are looked up by
`key_id` among keys **the checker trusts**: pin them from a source you control. Keys served by the
same service only prove the service agrees with itself.

A **retention** checkpoint anchors the chain after expired events are removed. Verification may
start at `last_seq + 1`, with `last_hash` as the previous hash.

## Result

Checking walks the stored events in seq order and reports `INTACT`, or `TAMPERED` with the
first break:

| Kind | Meaning | Reported seq |
|---|---|---|
| `BAD_CHECKPOINT` | A signature fails, its key is unknown, its fields are invalid, or it belongs to another audit | The checkpoint's `last_seq` |
| `GAP` | An expected seq is missing, or a prefix was deleted without a retention anchor | The first missing seq |
| `BROKEN_LINK` | A stored `prev_hash` is not the previous record's hash | That record |
| `MODIFIED` | A payload does not hash to its stored hash, or names another audit, seq or predecessor | That record |
| `CHECKPOINT_MISMATCH` | A validly signed checkpoint records a different hash at its seq (history recomputed) | That seq |
| `TRUNCATED` | A signed checkpoint covers seqs that are no longer stored (newest events deleted) | Last stored seq + 1 |
| `BAD_ANCHOR` | A checkpoint's independent timestamp is invalid, covers another message, or lies further from `signed_at` than allowed | The checkpoint's `last_seq` |

Checkpoints are checked first, then events, then truncation, then timestamps.

## Independent timestamps (RFC 3161)

The service asks an independent timestamp authority (TSA) to timestamp each signed checkpoint:
it sends SHA-256 of the checkpoint message above and stores the full `TimeStampResp`. Because a
third party signs the time, an operator who holds the signing key still cannot re-sign a rewritten
history later without the timestamps giving it away.

A timestamp is valid when:

1. it is signed by a TSA whose certificate chains to a root the checker trusts (pin it; the service
   uses FreeTSA, root at `https://freetsa.org/files/cacert.pem`);
2. its message imprint is SHA-256 of this checkpoint's message;
3. its `genTime` equals the stored `gen_time`; and
4. `genTime` is within the allowed delay of the checkpoint's `signed_at`, in either direction.

A checkpoint without a timestamp is counted (`checkpoints_unanchored`), not failed: checkpoints
signed before anchoring existed, or during a TSA outage, have none yet.

Any timestamp can also be checked with OpenSSL alone:

```bash
base64 -d <<< "$TSA_RESPONSE" > checkpoint.tsr
openssl ts -verify -digest "$MESSAGE_SHA256" -in checkpoint.tsr -CAfile freetsa-root.pem
```

## Bundle file (`auditlogs-bundle-v1`)

The input for offline checking:

```json
{
  "format": "auditlogs-bundle-v1",
  "audit_id": "uuid",
  "slug": "orders",
  "events":      [ { "seq": 1, "prev_hash": null, "hash": "...", "canonical_payload": "..." } ],
  "checkpoints": [ { "id": "uuid", "audit_id": "uuid", "kind": "periodic", "last_seq": 1,
                     "last_hash": "...", "first_retained_seq": null, "signature": "base64",
                     "key_id": "ckpt-1", "signed_at": "2026-10-12T09:00:00.123456Z",
                     "timestamp": { "tsa_url": "https://freetsa.org/tsr",
                                    "gen_time": "2026-10-12T09:00:02Z", "tsa_response": "base64" } } ]
}
```

`timestamp` is present once the service has timestamped that checkpoint.

`GET /v1/audits/{slug}/export/bundle` (read key) returns this file directly, read from one database
snapshot.

Events and checkpoints are the objects the API returns from `GET /v1/audits/{slug}/events` and
`GET /v1/audits/{slug}/checkpoints`. Other fields are ignored.

- Events may come in any order.
- A seq may repeat (paging can return one record twice), but only with identical content.

## Test values

Shared by every implementation's test suite. Any implementation must reproduce them.

- `audit_id = 11111111-1111-1111-1111-111111111111`
- `genesis = 8ca77dd1315d327e91d6b15196511eedde02397f45160ffa71a066552382f072`
- Event hash `5b77a6063c22ba83c213f05cc90c654a7a4e4263d2655dcb0f09da5da6f7facb` for the payload in
  `verify/chain_test.go` (`goldenPayload`) with the genesis hash as the previous hash.
- The checkpoint message for a retention checkpoint at seq 9, signed at
  `2026-10-12T09:00:00.123456Z` by `ckpt-2026`. The full text is in `TestCheckpointMessageMatchesGo`.
- `verify/testdata/anchor-checkpoint.*`: a real FreeTSA timestamp of a fixed checkpoint, accepted
  by this module, the Python package and the service.

## Known limits

- Timestamps bound when a checkpoint existed, but a TSA cannot know which history is the original.
  Detecting a re-signed history relies on the allowed delay, and on auditors keeping earlier
  bundles or reports to compare with.
- Checkpoints signed before anchoring was introduced carry no timestamp.
- Payload field names are matched exactly when checking `audit_id`, `seq` and `prev_hash`. The
  service matches them case-insensitively.
