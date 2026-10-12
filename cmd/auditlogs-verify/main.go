// Command auditlogs-verify verifies an AuditLogs audit bundle offline against
// keys you trust.
//
//	auditlogs-verify BUNDLE.json --keys KEYS.json [--tsa-roots ROOTS.pem --max-anchor-delay SECONDS | --skip-timestamps] [--json]
//
// Exit status: 0 INTACT, 1 TAMPERED, 2 the input could not be checked
// (missing or malformed file, unusable keys, bad flags). Exit 2 is never a verdict.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jamesadewara/auditlogs-go-package/verify"
)

const (
	exitIntact    = 0
	exitTampered  = 1
	exitUnchecked = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	bundle, keys, tsaRoots string
	maxAnchorDelay         int
	maxAnchorDelaySet      bool
	skipTimestamps, asJSON bool
}

// parseArgs accepts flags before or after the bundle path, as the Python CLI does.
func parseArgs(args []string, stderr io.Writer) (options, bool, error) {
	var o options
	var version bool
	fs := flag.NewFlagSet("auditlogs-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.keys, "keys", "", `trusted keys JSON: {"key_id": "base64"} or a /v1/checkpoint-keys response (required)`)
	fs.StringVar(&o.tsaRoots, "tsa-roots", "", "PEM file of trusted timestamp authority roots (for example FreeTSA's cacert.pem)")
	fs.IntVar(&o.maxAnchorDelay, "max-anchor-delay", 0, "largest allowed gap in SECONDS between a checkpoint's signed_at and its timestamp")
	fs.BoolVar(&o.skipTimestamps, "skip-timestamps", false, "do not check checkpoint timestamps (the report says they were not checked)")
	fs.BoolVar(&o.asJSON, "json", false, "print the report as JSON")
	fs.BoolVar(&version, "version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: auditlogs-verify BUNDLE.json --keys KEYS.json [flags]")
		fmt.Fprintln(stderr, "Verify an AuditLogs audit bundle offline: hash chain, Ed25519 checkpoint signatures and timestamps.")
		fs.PrintDefaults()
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return o, false, err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if version {
		return o, true, nil
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "max-anchor-delay" {
			o.maxAnchorDelaySet = true
		}
	})
	switch {
	case len(positional) != 1:
		fs.Usage()
		return o, false, fmt.Errorf("exactly one bundle file is required, got %d", len(positional))
	case o.keys == "":
		fs.Usage()
		return o, false, errors.New("--keys is required")
	}
	o.bundle = positional[0]
	return o, false, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	o, version, err := parseArgs(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitIntact
	}
	if err != nil {
		fmt.Fprintf(stderr, "auditlogs-verify: not checked: %v\n", err)
		return exitUnchecked
	}
	if version {
		fmt.Fprintf(stdout, "auditlogs-verify %s\n", verify.Version)
		return exitIntact
	}
	report, err := check(o)
	if err != nil {
		fmt.Fprintf(stderr, "auditlogs-verify: not checked: %v\n", err)
		return exitUnchecked
	}
	if o.asJSON {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "auditlogs-verify: not checked: cannot encode the report: %v\n", err)
			return exitUnchecked
		}
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprintln(stdout, describe(report))
	}
	if report.Intact() {
		return exitIntact
	}
	return exitTampered
}

func check(o options) (verify.Report, error) {
	keys, err := verify.ReadKeyFile(o.keys)
	if err != nil {
		return verify.Report{}, err
	}
	ring, err := verify.LoadTrustedKeys(keys)
	if err != nil {
		return verify.Report{}, err
	}
	bundle, err := verify.LoadBundle(o.bundle)
	if err != nil {
		return verify.Report{}, err
	}
	var policy *verify.AnchorPolicy
	stamped := false
	for _, cp := range bundle.Checkpoints {
		if cp.Timestamp != nil {
			stamped = true
		}
	}
	switch {
	case o.skipTimestamps:
		if o.tsaRoots != "" || o.maxAnchorDelaySet {
			return verify.Report{}, &verify.ConfigurationError{
				Message: "--skip-timestamps cannot be combined with --tsa-roots or --max-anchor-delay"}
		}
	case stamped:
		if o.tsaRoots == "" || !o.maxAnchorDelaySet {
			return verify.Report{}, &verify.ConfigurationError{
				Message: "the bundle has checkpoint timestamps: pass --tsa-roots and --max-anchor-delay, or --skip-timestamps to leave them unchecked"}
		}
		roots, err := verify.LoadTSARoots(o.tsaRoots)
		if err != nil {
			return verify.Report{}, err
		}
		if policy, err = verify.NewAnchorPolicy(roots, time.Duration(o.maxAnchorDelay)*time.Second); err != nil {
			return verify.Report{}, err
		}
	}
	return verify.VerifyBundle(bundle, ring, policy)
}

func describe(r verify.Report) string {
	lines := []string{
		fmt.Sprintf("audit      %s (%s)", r.Slug, r.AuditID),
		fmt.Sprintf("status     %s", r.Status),
		fmt.Sprintf("events     %d checked, seq %d to %d", r.EventsChecked, r.FirstSequence, r.LastSequence),
		fmt.Sprintf("checkpoints %d signature(s) verified", r.CheckpointsChecked),
	}
	if r.TimestampsChecked {
		lines = append(lines, fmt.Sprintf("timestamps %d verified, %d checkpoint(s) without one", r.AnchorsChecked, r.CheckpointsUnanchored))
	} else {
		lines = append(lines, "timestamps NOT CHECKED (--skip-timestamps or none present)")
	}
	lines = append(lines, fmt.Sprintf("head hash  %s", r.LastHash))
	if r.Anchor != nil {
		lines = append(lines, fmt.Sprintf("anchor     retention checkpoint at seq %d", r.Anchor.LastSeq))
	}
	if f := r.Failure; f != nil {
		lines = append(lines, fmt.Sprintf("failure    %s at seq %d: %s", f.Kind, f.Seq, f.Message))
		if f.ExpectedHash != nil {
			lines = append(lines, fmt.Sprintf("expected   %s", *f.ExpectedHash))
		}
		if f.FoundHash != nil {
			lines = append(lines, fmt.Sprintf("found      %s", *f.FoundHash))
		}
	}
	return strings.Join(lines, "\n")
}
