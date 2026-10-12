package verify

// Errors returned by this package. A TAMPERED chain is a result, not an error.
// Test for the kind with errors.As.

// ConfigurationError means the trusted keys, TSA roots or arguments are
// unusable (empty key set, bad base64, wrong key length, non-positive delay).
type ConfigurationError struct{ Message string }

func (e *ConfigurationError) Error() string { return e.Message }

// BundleError means the audit bundle file is missing, unreadable or does not
// match the documented format.
type BundleError struct{ Message string }

func (e *BundleError) Error() string { return e.Message }

// ErrFinished is returned when a ChainVerifier is used after Finish.
type ErrFinished struct{}

func (ErrFinished) Error() string { return "this verifier has already finished" }
