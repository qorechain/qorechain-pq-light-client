// SPDX-License-Identifier: Apache-2.0

package pqlightclient

import "fmt"

// Code is a stable error code, identical in the Go, Rust and TypeScript verifiers.
type Code string

const (
	CodeMalformed             Code = "MALFORMED"
	CodeChainIDMismatch       Code = "CHAIN_ID_MISMATCH"
	CodeTrustExpired          Code = "TRUST_EXPIRED"
	CodeFutureCheckpoint      Code = "FUTURE_CHECKPOINT"
	CodeNotNewer              Code = "NOT_NEWER"
	CodeSetMismatch           Code = "SET_MISMATCH"
	CodeUnknownValidator      Code = "UNKNOWN_VALIDATOR"
	CodeBadSignature          Code = "BAD_SIGNATURE"
	CodeInsufficientPower     Code = "INSUFFICIENT_POWER"
	CodeConflictingCheckpoint Code = "CONFLICTING_CHECKPOINT"
	CodeRequiresChainSupport  Code = "REQUIRES_CHAIN_SUPPORT"
)

// RequiresChainSupportMessage is carried by every function that needs the
// chain to produce checkpoints.
const RequiresChainSupportMessage = "requires chain support (not scheduled)"

// Error is returned by every function in this package. Compare with errors.Is
// against the Err* values, which match on Code.
type Error struct {
	Code   Code
	Detail string
	// Misbehaviour is set when Code is CodeConflictingCheckpoint.
	Misbehaviour *Misbehaviour
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Is reports whether target is an *Error with the same Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

var (
	ErrMalformed             = &Error{Code: CodeMalformed}
	ErrChainIDMismatch       = &Error{Code: CodeChainIDMismatch}
	ErrTrustExpired          = &Error{Code: CodeTrustExpired}
	ErrFutureCheckpoint      = &Error{Code: CodeFutureCheckpoint}
	ErrNotNewer              = &Error{Code: CodeNotNewer}
	ErrSetMismatch           = &Error{Code: CodeSetMismatch}
	ErrUnknownValidator      = &Error{Code: CodeUnknownValidator}
	ErrBadSignature          = &Error{Code: CodeBadSignature}
	ErrInsufficientPower     = &Error{Code: CodeInsufficientPower}
	ErrConflictingCheckpoint = &Error{Code: CodeConflictingCheckpoint}
	ErrRequiresChainSupport  = &Error{Code: CodeRequiresChainSupport}
)

func fail(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}
