package main

// The command line, including every exit status. Mirrors the Python
// package's test_bundle_and_cli.py.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jamesadewara/auditlogs-go-package/verify"
)

const keyID = "ckpt-test"

type fixture struct {
	audit   uuid.UUID
	private ed25519.PrivateKey
	events  []map[string]any
	hashes  []string
}

func newFixture(t *testing.T, n int) fixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{audit: uuid.New(), private: priv}
	prev := verify.GenesisHash(f.audit)
	for seq := 1; seq <= n; seq++ {
		text := fmt.Sprintf(`{"audit_id":%q,"seq":%d,"prev_hash":%q,"hash":"","action":"order.created"}`, f.audit, seq, prev)
		h, err := verify.EventHash(prev, text)
		if err != nil {
			t.Fatal(err)
		}
		e := map[string]any{"seq": seq, "prev_hash": nil, "hash": h, "canonical_payload": text}
		if seq > 1 {
			e["prev_hash"] = prev
		}
		f.events = append(f.events, e)
		f.hashes = append(f.hashes, h)
		prev = h
	}
	return f
}

func (f fixture) checkpoint(t *testing.T, lastSeq int64) map[string]any {
	t.Helper()
	signedAt := time.Date(2026, 10, 12, 9, 0, int(lastSeq), 123456000, time.UTC)
	cp := verify.Checkpoint{AuditID: f.audit, Kind: "periodic", LastSeq: lastSeq, LastHash: f.hashes[lastSeq-1], KeyID: keyID, SignedAt: signedAt}
	msg, err := verify.CheckpointMessage(cp)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id": uuid.NewString(), "audit_id": f.audit.String(), "kind": "periodic", "last_seq": lastSeq,
		"last_hash": cp.LastHash, "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(f.private, msg)),
		"key_id": keyID, "signed_at": signedAt.Format("2006-01-02T15:04:05.000000Z"),
	}
}

func (f fixture) keys() map[string]string {
	return map[string]string{keyID: base64.StdEncoding.EncodeToString(f.private.Public().(ed25519.PublicKey))}
}

func (f fixture) bundle(events []map[string]any, cps []map[string]any) map[string]any {
	return map[string]any{"format": verify.BundleFormat, "audit_id": f.audit.String(), "slug": "orders", "events": events, "checkpoints": cps}
}

func write(t *testing.T, name string, v any) string {
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

func cli(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestCLIIntact(t *testing.T) {
	f := newFixture(t, 4)
	bundle := write(t, "b.json", f.bundle(f.events, []map[string]any{f.checkpoint(t, 4)}))
	keys := write(t, "k.json", f.keys())
	code, out, _ := cli(bundle, "--keys", keys)
	if code != exitIntact || !strings.Contains(out, "status     INTACT") || !strings.Contains(out, "4 checked, seq 1 to 4") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestCLIFlagsMayComeFirst(t *testing.T) {
	f := newFixture(t, 2)
	bundle := write(t, "b.json", f.bundle(f.events, []map[string]any{}))
	keys := write(t, "k.json", f.keys())
	if code, out, errOut := cli("--keys", keys, "--json", bundle); code != exitIntact || !strings.Contains(out, `"status": "INTACT"`) {
		t.Fatalf("code %d\n%s%s", code, out, errOut)
	}
}

func TestCLITamperedNamesKindAndSeq(t *testing.T) {
	f := newFixture(t, 4)
	events := append([]map[string]any{f.events[0]}, f.events[2:]...)
	bundle := write(t, "b.json", f.bundle(events, []map[string]any{}))
	keys := write(t, "k.json", f.keys())
	code, out, _ := cli(bundle, "--keys", keys, "--json")
	if code != exitTampered {
		t.Fatalf("code %d", code)
	}
	var report struct {
		Status  string `json:"status"`
		Failure struct {
			Kind         string  `json:"kind"`
			Seq          int     `json:"seq"`
			ExpectedHash *string `json:"expected_hash"`
		} `json:"failure"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if report.Status != "TAMPERED" || report.Failure.Kind != "GAP" || report.Failure.Seq != 2 || report.Failure.ExpectedHash != nil {
		t.Fatalf("report %+v", report)
	}
}

func TestCLIUnusableInputIsNotAVerdict(t *testing.T) {
	f := newFixture(t, 1)
	bundle := write(t, "b.json", f.bundle(f.events, []map[string]any{}))
	emptyKeys := write(t, "k.json", map[string]string{})
	code, _, errOut := cli(bundle, "--keys", emptyKeys)
	if code != exitUnchecked || !strings.Contains(errOut, "not checked: at least one trusted checkpoint public key is required") {
		t.Fatalf("code %d: %s", code, errOut)
	}
	code, _, errOut = cli(bundle)
	if code != exitUnchecked || !strings.Contains(errOut, "--keys is required") {
		t.Fatalf("missing --keys: code %d: %s", code, errOut)
	}
	code, _, errOut = cli(filepath.Join(t.TempDir(), "none.json"), "--keys", write(t, "k2.json", f.keys()))
	if code != exitUnchecked || !strings.Contains(errOut, "cannot read the bundle file") {
		t.Fatalf("missing bundle: code %d: %s", code, errOut)
	}
}

func TestCLIDemandsAChoiceAboutTimestamps(t *testing.T) {
	f := newFixture(t, 2)
	cp := f.checkpoint(t, 2)
	cp["timestamp"] = map[string]any{"tsa_url": "https://freetsa.org/tsr", "gen_time": "2026-10-12T11:35:02Z", "tsa_response": "AAAA"}
	bundle := write(t, "b.json", f.bundle(f.events, []map[string]any{cp}))
	keys := write(t, "k.json", f.keys())

	code, _, errOut := cli(bundle, "--keys", keys)
	if code != exitUnchecked || !strings.Contains(errOut, "pass --tsa-roots and --max-anchor-delay, or --skip-timestamps") {
		t.Fatalf("no choice: code %d: %s", code, errOut)
	}
	code, _, errOut = cli(bundle, "--keys", keys, "--skip-timestamps", "--max-anchor-delay", "60")
	if code != exitUnchecked || !strings.Contains(errOut, "cannot be combined") {
		t.Fatalf("contradictory flags: code %d: %s", code, errOut)
	}
	code, out, _ := cli(bundle, "--keys", keys, "--skip-timestamps")
	if code != exitIntact || !strings.Contains(out, "timestamps NOT CHECKED") {
		t.Fatalf("skipped: code %d: %s", code, out)
	}
	roots := filepath.Join("..", "..", "verify", "testdata", "freetsa-root.pem")
	code, out, errOut = cli(bundle, "--keys", keys, "--tsa-roots", roots, "--max-anchor-delay", "86400", "--json")
	if code != exitTampered {
		t.Fatalf("bad anchor: code %d: %s%s", code, out, errOut)
	}
	var report struct {
		Failure struct {
			Kind string `json:"kind"`
			Seq  int    `json:"seq"`
		} `json:"failure"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.Failure.Kind != "BAD_ANCHOR" || report.Failure.Seq != 2 {
		t.Fatalf("report %+v %v", report, err)
	}
	code, _, errOut = cli(bundle, "--keys", keys, "--tsa-roots", roots, "--max-anchor-delay", "0")
	if code != exitUnchecked || !strings.Contains(errOut, "must be positive") {
		t.Fatalf("zero delay: code %d: %s", code, errOut)
	}
}

func TestCLIVersion(t *testing.T) {
	code, out, _ := cli("--version")
	if code != exitIntact || strings.TrimSpace(out) != "auditlogs-verify "+verify.Version {
		t.Fatalf("code %d: %q", code, out)
	}
}

func TestCLIReportJSONHasTheServiceShape(t *testing.T) {
	f := newFixture(t, 1)
	bundle := write(t, "b.json", f.bundle(f.events, []map[string]any{}))
	keys := write(t, "k.json", f.keys())
	_, out, _ := cli(bundle, "--keys", keys, "--json")
	var fields map[string]any
	if err := json.Unmarshal([]byte(out), &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"status", "slug", "audit_id", "events_checked", "first_sequence", "last_sequence", "last_hash",
		"checkpoints_checked", "anchors_checked", "checkpoints_unanchored", "timestamps_checked", "anchor", "failure"} {
		if _, ok := fields[k]; !ok {
			t.Fatalf("report lacks %q: %s", k, out)
		}
	}
	if len(fields) != 13 {
		t.Fatalf("report has %d fields, want 13: %s", len(fields), out)
	}
}
