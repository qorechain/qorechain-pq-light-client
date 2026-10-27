// SPDX-License-Identifier: Apache-2.0

package pqlightclient

import (
	"bytes"
	"fmt"

	pqc "github.com/qorechain/qorechain-pqc/go"
)

func members(s *ValidatorSet) map[[AddressSize]byte]*Validator {
	m := make(map[[AddressSize]byte]*Validator, len(s.Validators))
	for i := range s.Validators {
		m[s.Validators[i].Address] = &s.Validators[i]
	}
	return m
}

func totalPower(s *ValidatorSet) uint64 {
	var t uint64
	for i := range s.Validators {
		t += s.Validators[i].Power
	}
	return t
}

// checkQuorum is spec section 8.2: signatures are checked in order; the first
// unknown signer or invalid signature rejects the checkpoint, then the signed
// power must exceed two thirds of the set's total power.
func checkQuorum(c *Checkpoint, sigs []CheckpointSignature, set *ValidatorSet) error {
	h, err := HashValidatorSet(set)
	if err != nil {
		return err
	}
	if h != c.ValidatorSetHash {
		return fail(CodeSetMismatch, "the checkpoint names a different validator set")
	}
	msg, err := EncodeCheckpointSignBytes(c)
	if err != nil {
		return err
	}
	m := members(set)
	var signed uint64
	for i := range sigs {
		v, ok := m[sigs[i].ValidatorAddress]
		if !ok {
			return fail(CodeUnknownValidator, "signer %x is not in the set", sigs[i].ValidatorAddress)
		}
		if !pqc.MLDSA87.Verify(v.PublicKey, msg, sigs[i].Signature) {
			return fail(CodeBadSignature, "invalid signature from %x", sigs[i].ValidatorAddress)
		}
		signed += v.Power
	}
	// Total power is at most 2^60 - 1, so neither product overflows.
	if signed*3 <= totalPower(set)*2 {
		return fail(CodeInsufficientPower, "signed power does not exceed two thirds of the set")
	}
	return nil
}

func buildMisbehaviour(set *ValidatorSet, a, b *SignedCheckpoint) (*Misbehaviour, error) {
	aBytes, err := EncodeCheckpointSignBytes(&a.Checkpoint)
	if err != nil {
		return nil, err
	}
	bBytes, err := EncodeCheckpointSignBytes(&b.Checkpoint)
	if err != nil {
		return nil, err
	}
	first, firstBytes, second, secondBytes := a, aBytes, b, bBytes
	if bytes.Compare(aBytes, bBytes) > 0 {
		first, firstBytes, second, secondBytes = b, bBytes, a, aBytes
	}
	m := members(set)
	other := make(map[[AddressSize]byte][]byte, len(second.Signatures))
	for i := range second.Signatures {
		other[second.Signatures[i].ValidatorAddress] = second.Signatures[i].Signature
	}
	ev := &Misbehaviour{
		ChainID:       first.Checkpoint.ChainID,
		Epoch:         first.Checkpoint.Epoch,
		First:         *first,
		Second:        *second,
		DoubleSigners: [][AddressSize]byte{},
	}
	for i := range first.Signatures {
		s := &first.Signatures[i]
		v, ok := m[s.ValidatorAddress]
		o, ok2 := other[s.ValidatorAddress]
		if !ok || !ok2 {
			continue
		}
		if pqc.MLDSA87.Verify(v.PublicKey, firstBytes, s.Signature) && pqc.MLDSA87.Verify(v.PublicKey, secondBytes, o) {
			ev.DoubleSigners = append(ev.DoubleSigners, v.Address)
			ev.DoubleSignedPower += v.Power
		}
	}
	return ev, nil
}

// NewTrustedState builds a trust root (spec section 7.1). The caller obtains
// the checkpoint and both sets out of band; signatures, if given, are kept for
// evidence but not verified here.
func NewTrustedState(c Checkpoint, sigs []CheckpointSignature, set, next ValidatorSet, trustingPeriod, maxClockDrift uint64) (*TrustedState, error) {
	if err := validateCheckpoint(&c); err != nil {
		return nil, err
	}
	if err := validateSignatures(sigs); err != nil {
		return nil, err
	}
	if trustingPeriod < 1 {
		return nil, fail(CodeMalformed, "trusting period must be at least one second")
	}
	h, err := HashValidatorSet(&set)
	if err != nil {
		return nil, err
	}
	if h != c.ValidatorSetHash {
		return nil, fail(CodeSetMismatch, "validator set does not match the checkpoint")
	}
	hn, err := HashValidatorSet(&next)
	if err != nil {
		return nil, err
	}
	if hn != c.NextValidatorSetHash {
		return nil, fail(CodeSetMismatch, "next validator set does not match the checkpoint")
	}
	if sigs == nil {
		sigs = []CheckpointSignature{}
	}
	return &TrustedState{
		Checkpoint:       c,
		Signatures:       sigs,
		ValidatorSet:     set,
		NextValidatorSet: next,
		TrustingPeriod:   trustingPeriod,
		MaxClockDrift:    maxClockDrift,
	}, nil
}

// VerifyCheckpoint verifies signed against trusted at time now (Unix seconds)
// and returns the new trusted state. Errors are *Error with a stable Code; the
// checks run in the order of spec section 8.1.
func VerifyCheckpoint(trusted *TrustedState, signed *SignedCheckpoint, now uint64) (*TrustedState, error) {
	if trusted == nil {
		return nil, fail(CodeMalformed, "missing trusted state")
	}
	if err := validateSignedCheckpoint(signed); err != nil {
		return nil, err
	}
	c := &signed.Checkpoint
	t := &trusted.Checkpoint

	if c.ChainID != t.ChainID {
		return nil, fail(CodeChainIDMismatch, "expected %s, got %s", t.ChainID, c.ChainID)
	}
	if now >= t.Time && now-t.Time >= trusted.TrustingPeriod {
		return nil, fail(CodeTrustExpired, "the trusted checkpoint is older than the trusting period")
	}
	if c.Time > now && c.Time-now > trusted.MaxClockDrift {
		return nil, fail(CodeFutureCheckpoint, "checkpoint time is ahead of the local clock by more than the allowed drift")
	}

	if c.Epoch == t.Epoch {
		cb, err := EncodeCheckpointSignBytes(c)
		if err != nil {
			return nil, err
		}
		tb, err := EncodeCheckpointSignBytes(t)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(cb, tb) {
			return nil, fail(CodeNotNewer, "this checkpoint is already trusted")
		}
		if err := checkQuorum(c, signed.Signatures, &trusted.ValidatorSet); err != nil {
			return nil, err
		}
		ts := &SignedCheckpoint{Checkpoint: *t, Signatures: trusted.Signatures}
		if t.ValidatorSetHash != t.NextValidatorSetHash {
			next := trusted.NextValidatorSet
			ts.NextValidatorSet = &next
		}
		ev, err := buildMisbehaviour(&trusted.ValidatorSet, ts, signed)
		if err != nil {
			return nil, err
		}
		return nil, &Error{
			Code:         CodeConflictingCheckpoint,
			Detail:       fmt.Sprintf("two checkpoints for epoch %d carry more than two thirds of the power", c.Epoch),
			Misbehaviour: ev,
		}
	}

	if c.Epoch < t.Epoch || c.Height <= t.Height || c.Time <= t.Time {
		return nil, fail(CodeNotNewer, "epoch, height and time must all increase")
	}
	if c.ValidatorSetHash != t.NextValidatorSetHash {
		return nil, fail(CodeSetMismatch, "the checkpoint is not signed by the set the trusted state names")
	}
	next := trusted.NextValidatorSet
	if signed.NextValidatorSet != nil {
		h, err := HashValidatorSet(signed.NextValidatorSet)
		if err != nil {
			return nil, err
		}
		if h != c.NextValidatorSetHash {
			return nil, fail(CodeSetMismatch, "the next validator set does not match its hash")
		}
		next = *signed.NextValidatorSet
	}
	if err := checkQuorum(c, signed.Signatures, &trusted.NextValidatorSet); err != nil {
		return nil, err
	}
	return &TrustedState{
		Checkpoint:       *c,
		Signatures:       signed.Signatures,
		ValidatorSet:     trusted.NextValidatorSet,
		NextValidatorSet: next,
		TrustingPeriod:   trusted.TrustingPeriod,
		MaxClockDrift:    trusted.MaxClockDrift,
	}, nil
}

// DetectMisbehaviour returns evidence when a and b are two different
// checkpoints for the same chain and epoch, each carrying more than two
// thirds of set (spec section 9). It returns nil otherwise, including for
// malformed input.
func DetectMisbehaviour(set *ValidatorSet, a, b *SignedCheckpoint) *Misbehaviour {
	if validateValidatorSet(set) != nil || validateSignedCheckpoint(a) != nil || validateSignedCheckpoint(b) != nil {
		return nil
	}
	if a.Checkpoint.ChainID != b.Checkpoint.ChainID || a.Checkpoint.Epoch != b.Checkpoint.Epoch {
		return nil
	}
	ab, _ := EncodeCheckpointSignBytes(&a.Checkpoint)
	bb, _ := EncodeCheckpointSignBytes(&b.Checkpoint)
	if bytes.Equal(ab, bb) {
		return nil
	}
	if checkQuorum(&a.Checkpoint, a.Signatures, set) != nil || checkQuorum(&b.Checkpoint, b.Signatures, set) != nil {
		return nil
	}
	ev, err := buildMisbehaviour(set, a, b)
	if err != nil {
		return nil
	}
	return ev
}

// SignCheckpoint signs a checkpoint with an ML-DSA-87 checkpoint secret key
// (deterministic FIPS 204 signing). For simulators and tests; validators would
// sign inside the node once the chain supports checkpoints.
func SignCheckpoint(secretKey []byte, c *Checkpoint) ([]byte, error) {
	msg, err := EncodeCheckpointSignBytes(c)
	if err != nil {
		return nil, err
	}
	return pqc.MLDSA87.Sign(secretKey, msg)
}
