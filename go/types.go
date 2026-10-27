// SPDX-License-Identifier: Apache-2.0

// Package pqlightclient is the Go reference verifier for QoreChain
// post-quantum light client checkpoints, specification v1 (draft).
//
// Validators would sign epoch checkpoints with a separate ML-DSA-87 (FIPS 204)
// checkpoint key; a light client follows the checkpoint chain and accepts a
// checkpoint once more than two thirds of the named set's power has signed it.
// Producing checkpoints requires chain support (not scheduled): this package
// verifies the format and the rules only.
package pqlightclient

// Version of this module.
const Version = "0.1.0"

// Checkpoint is what the validators sign at the end of an epoch (spec section 3).
type Checkpoint struct {
	ChainID              string
	Epoch                uint64
	Height               uint64
	Time                 uint64 // block time at Height, Unix seconds
	HeaderHash           [HashSize]byte
	AppHash              [HashSize]byte // state root carried in the header at Height
	ValidatorSetHash     [HashSize]byte // the set that signs this checkpoint
	NextValidatorSetHash [HashSize]byte // the set that signs the next checkpoint
}

// Validator is one member of a checkpoint validator set.
type Validator struct {
	Address   [AddressSize]byte // consensus address
	Power     uint64
	PublicKey []byte // ML-DSA-87 checkpoint public key, 2,592 bytes
}

// ValidatorSet is sorted by address, strictly ascending.
type ValidatorSet struct {
	Validators []Validator
}

// CheckpointSignature is one validator's ML-DSA-87 signature over the sign-bytes.
type CheckpointSignature struct {
	ValidatorAddress [AddressSize]byte
	Signature        []byte // 4,627 bytes
}

// SignedCheckpoint is a checkpoint with its signatures. Signatures are sorted
// by address, strictly ascending. NextValidatorSet is present exactly when
// Checkpoint.NextValidatorSetHash differs from Checkpoint.ValidatorSetHash.
type SignedCheckpoint struct {
	Checkpoint       Checkpoint
	Signatures       []CheckpointSignature
	NextValidatorSet *ValidatorSet
}

// TrustedState is what a light client keeps between updates (spec section 7).
type TrustedState struct {
	Checkpoint       Checkpoint
	Signatures       []CheckpointSignature // empty for an unsigned trust root
	ValidatorSet     ValidatorSet          // signed Checkpoint
	NextValidatorSet ValidatorSet          // must sign the next checkpoint
	TrustingPeriod   uint64                // seconds
	MaxClockDrift    uint64                // seconds
}

// Misbehaviour is two checkpoints for the same chain and epoch, each signed by
// more than two thirds of one set. First is the one whose sign-bytes sort first.
type Misbehaviour struct {
	ChainID           string
	Epoch             uint64
	First             SignedCheckpoint
	Second            SignedCheckpoint
	DoubleSigners     [][AddressSize]byte // valid signature on both, sorted
	DoubleSignedPower uint64
}
