// SPDX-License-Identifier: Apache-2.0

package pqlightclient

import (
	"bytes"
	"encoding/binary"

	pqc "github.com/qorechain/qorechain-pqc/go"
)

const (
	// CheckpointSignDomain prefixes every checkpoint sign-bytes (spec section 4).
	// Proposed for reservation.
	CheckpointSignDomain = "qorechain-pqlc-checkpoint-v1|"
	// ValidatorSetHashDomain is hashed in front of an encoded validator set.
	ValidatorSetHashDomain = "qorechain-pqlc-valset-v1|"
	// EncodingVersion is the version byte of every encoding in this specification.
	EncodingVersion = 1

	PublicKeySize    = 2592 // ML-DSA-87
	SignatureSize    = 4627 // ML-DSA-87
	AddressSize      = 20
	HashSize         = 32
	MaxChainIDLength = 64
	MaxValidators    = 256
	// MaxTotalPower is the consensus engine's bound, (2^63 - 1) / 8.
	MaxTotalPower uint64 = 1<<60 - 1
)

// ---------------------------------------------------------------------------
// structural validation (spec section 6)

func validateChainID(id string) error {
	if len(id) < 1 || len(id) > MaxChainIDLength {
		return fail(CodeMalformed, "chain id must be 1 to 64 characters")
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return fail(CodeMalformed, "chain id must be printable ASCII without spaces")
		}
	}
	return nil
}

func validateCheckpoint(c *Checkpoint) error {
	if c == nil {
		return fail(CodeMalformed, "missing checkpoint")
	}
	return validateChainID(c.ChainID)
}

func validateValidatorSet(s *ValidatorSet) error {
	if s == nil || len(s.Validators) < 1 || len(s.Validators) > MaxValidators {
		return fail(CodeMalformed, "a validator set has 1 to %d validators", MaxValidators)
	}
	var total uint64
	for i := range s.Validators {
		v := &s.Validators[i]
		if len(v.PublicKey) != PublicKeySize {
			return fail(CodeMalformed, "validator public key must be %d bytes", PublicKeySize)
		}
		if v.Power < 1 {
			return fail(CodeMalformed, "validator power must be at least 1")
		}
		if i > 0 && bytes.Compare(s.Validators[i-1].Address[:], v.Address[:]) >= 0 {
			return fail(CodeMalformed, "validators must be sorted by address, without duplicates")
		}
		if v.Power > MaxTotalPower-total {
			return fail(CodeMalformed, "total power exceeds the maximum")
		}
		total += v.Power
	}
	return nil
}

func validateSignatures(sigs []CheckpointSignature) error {
	if len(sigs) > MaxValidators {
		return fail(CodeMalformed, "at most %d signatures", MaxValidators)
	}
	for i := range sigs {
		if len(sigs[i].Signature) != SignatureSize {
			return fail(CodeMalformed, "signature must be %d bytes", SignatureSize)
		}
		if i > 0 && bytes.Compare(sigs[i-1].ValidatorAddress[:], sigs[i].ValidatorAddress[:]) >= 0 {
			return fail(CodeMalformed, "signatures must be sorted by address, without duplicates")
		}
	}
	return nil
}

func validateSignedCheckpoint(sc *SignedCheckpoint) error {
	if sc == nil {
		return fail(CodeMalformed, "missing signed checkpoint")
	}
	if err := validateCheckpoint(&sc.Checkpoint); err != nil {
		return err
	}
	if err := validateSignatures(sc.Signatures); err != nil {
		return err
	}
	changes := sc.Checkpoint.ValidatorSetHash != sc.Checkpoint.NextValidatorSetHash
	if changes && sc.NextValidatorSet == nil {
		return fail(CodeMalformed, "the next validator set is required when it changes")
	}
	if !changes && sc.NextValidatorSet != nil {
		return fail(CodeMalformed, "the next validator set must be omitted when it does not change")
	}
	if sc.NextValidatorSet != nil {
		return validateValidatorSet(sc.NextValidatorSet)
	}
	return nil
}

// ---------------------------------------------------------------------------
// encoders

func appendCheckpoint(out []byte, c *Checkpoint) []byte {
	out = append(out, EncodingVersion, byte(len(c.ChainID)))
	out = append(out, c.ChainID...)
	out = binary.BigEndian.AppendUint64(out, c.Epoch)
	out = binary.BigEndian.AppendUint64(out, c.Height)
	out = binary.BigEndian.AppendUint64(out, c.Time)
	out = append(out, c.HeaderHash[:]...)
	out = append(out, c.AppHash[:]...)
	out = append(out, c.ValidatorSetHash[:]...)
	return append(out, c.NextValidatorSetHash[:]...)
}

func appendValidatorSet(out []byte, s *ValidatorSet) []byte {
	out = append(out, EncodingVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(s.Validators)))
	for i := range s.Validators {
		v := &s.Validators[i]
		out = append(out, v.Address[:]...)
		out = binary.BigEndian.AppendUint64(out, v.Power)
		out = append(out, v.PublicKey...)
	}
	return out
}

// EncodeCheckpoint returns the canonical checkpoint encoding (spec section 3).
func EncodeCheckpoint(c *Checkpoint) ([]byte, error) {
	if err := validateCheckpoint(c); err != nil {
		return nil, err
	}
	return appendCheckpoint(make([]byte, 0, 154+len(c.ChainID)), c), nil
}

// EncodeCheckpointSignBytes returns the bytes each validator signs:
// CheckpointSignDomain followed by the checkpoint encoding.
func EncodeCheckpointSignBytes(c *Checkpoint) ([]byte, error) {
	if err := validateCheckpoint(c); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(CheckpointSignDomain)+154+len(c.ChainID))
	out = append(out, CheckpointSignDomain...)
	return appendCheckpoint(out, c), nil
}

// EncodeValidatorSet returns the canonical validator set encoding (spec section 5).
func EncodeValidatorSet(s *ValidatorSet) ([]byte, error) {
	if err := validateValidatorSet(s); err != nil {
		return nil, err
	}
	return appendValidatorSet(make([]byte, 0, 3+len(s.Validators)*(AddressSize+8+PublicKeySize)), s), nil
}

// HashValidatorSet returns SHAKE-256 over ValidatorSetHashDomain and the set
// encoding, 32 bytes.
func HashValidatorSet(s *ValidatorSet) ([HashSize]byte, error) {
	var h [HashSize]byte
	enc, err := EncodeValidatorSet(s)
	if err != nil {
		return h, err
	}
	copy(h[:], pqc.Shake256(append([]byte(ValidatorSetHashDomain), enc...), HashSize))
	return h, nil
}

// EncodeSignedCheckpoint returns the canonical signed checkpoint encoding.
func EncodeSignedCheckpoint(sc *SignedCheckpoint) ([]byte, error) {
	if err := validateSignedCheckpoint(sc); err != nil {
		return nil, err
	}
	out := []byte{EncodingVersion}
	out = appendCheckpoint(out, &sc.Checkpoint)
	out = binary.BigEndian.AppendUint16(out, uint16(len(sc.Signatures)))
	for i := range sc.Signatures {
		out = append(out, sc.Signatures[i].ValidatorAddress[:]...)
		out = append(out, sc.Signatures[i].Signature...)
	}
	if sc.NextValidatorSet == nil {
		return append(out, 0), nil
	}
	out = append(out, 1)
	return appendValidatorSet(out, sc.NextValidatorSet), nil
}

// ---------------------------------------------------------------------------
// decoders (strict: any deviation from the canonical encoding is MALFORMED)

type reader struct {
	buf []byte
	off int
}

func (r *reader) take(n int, what string) ([]byte, error) {
	if n < 0 || len(r.buf)-r.off < n {
		return nil, fail(CodeMalformed, "truncated %s", what)
	}
	b := r.buf[r.off : r.off+n]
	r.off += n
	return b, nil
}

func (r *reader) u8(what string) (byte, error) {
	b, err := r.take(1, what)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) u16(what string) (int, error) {
	b, err := r.take(2, what)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

func (r *reader) u64(what string) (uint64, error) {
	b, err := r.take(8, what)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func (r *reader) fixed(dst []byte, what string) error {
	b, err := r.take(len(dst), what)
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}

func (r *reader) end() error {
	if r.off != len(r.buf) {
		return fail(CodeMalformed, "trailing bytes")
	}
	return nil
}

func (r *reader) version(what string) error {
	v, err := r.u8(what + " version")
	if err != nil {
		return err
	}
	if v != EncodingVersion {
		return fail(CodeMalformed, "unknown %s version", what)
	}
	return nil
}

func (r *reader) checkpoint() (Checkpoint, error) {
	var c Checkpoint
	if err := r.version("checkpoint"); err != nil {
		return c, err
	}
	n, err := r.u8("chain id length")
	if err != nil {
		return c, err
	}
	if n < 1 || n > MaxChainIDLength {
		return c, fail(CodeMalformed, "chain id must be 1 to 64 characters")
	}
	id, err := r.take(int(n), "chain id")
	if err != nil {
		return c, err
	}
	c.ChainID = string(id)
	if err := validateChainID(c.ChainID); err != nil {
		return c, err
	}
	if c.Epoch, err = r.u64("epoch"); err != nil {
		return c, err
	}
	if c.Height, err = r.u64("height"); err != nil {
		return c, err
	}
	if c.Time, err = r.u64("time"); err != nil {
		return c, err
	}
	for _, f := range []struct {
		dst  []byte
		what string
	}{
		{c.HeaderHash[:], "header hash"},
		{c.AppHash[:], "app hash"},
		{c.ValidatorSetHash[:], "validator set hash"},
		{c.NextValidatorSetHash[:], "next validator set hash"},
	} {
		if err := r.fixed(f.dst, f.what); err != nil {
			return c, err
		}
	}
	return c, nil
}

func (r *reader) validatorSet() (*ValidatorSet, error) {
	if err := r.version("validator set"); err != nil {
		return nil, err
	}
	count, err := r.u16("validator count")
	if err != nil {
		return nil, err
	}
	if count < 1 || count > MaxValidators {
		return nil, fail(CodeMalformed, "a validator set has 1 to %d validators", MaxValidators)
	}
	s := &ValidatorSet{Validators: make([]Validator, count)}
	for i := 0; i < count; i++ {
		v := &s.Validators[i]
		if err := r.fixed(v.Address[:], "validator address"); err != nil {
			return nil, err
		}
		if v.Power, err = r.u64("validator power"); err != nil {
			return nil, err
		}
		pk, err := r.take(PublicKeySize, "validator public key")
		if err != nil {
			return nil, err
		}
		v.PublicKey = append([]byte(nil), pk...)
	}
	if err := validateValidatorSet(s); err != nil {
		return nil, err
	}
	return s, nil
}

// DecodeCheckpoint parses a canonical checkpoint encoding.
func DecodeCheckpoint(b []byte) (*Checkpoint, error) {
	r := &reader{buf: b}
	c, err := r.checkpoint()
	if err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return &c, nil
}

// DecodeValidatorSet parses a canonical validator set encoding.
func DecodeValidatorSet(b []byte) (*ValidatorSet, error) {
	r := &reader{buf: b}
	s, err := r.validatorSet()
	if err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return s, nil
}

// DecodeSignedCheckpoint parses a canonical signed checkpoint encoding.
func DecodeSignedCheckpoint(b []byte) (*SignedCheckpoint, error) {
	r := &reader{buf: b}
	if err := r.version("signed checkpoint"); err != nil {
		return nil, err
	}
	c, err := r.checkpoint()
	if err != nil {
		return nil, err
	}
	count, err := r.u16("signature count")
	if err != nil {
		return nil, err
	}
	if count > MaxValidators {
		return nil, fail(CodeMalformed, "at most %d signatures", MaxValidators)
	}
	sc := &SignedCheckpoint{Checkpoint: c, Signatures: make([]CheckpointSignature, count)}
	for i := 0; i < count; i++ {
		s := &sc.Signatures[i]
		if err := r.fixed(s.ValidatorAddress[:], "signer address"); err != nil {
			return nil, err
		}
		sig, err := r.take(SignatureSize, "signature")
		if err != nil {
			return nil, err
		}
		s.Signature = append([]byte(nil), sig...)
	}
	flag, err := r.u8("next validator set flag")
	if err != nil {
		return nil, err
	}
	switch flag {
	case 0:
	case 1:
		if sc.NextValidatorSet, err = r.validatorSet(); err != nil {
			return nil, err
		}
	default:
		return nil, fail(CodeMalformed, "next validator set flag must be 0 or 1")
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	if err := validateSignedCheckpoint(sc); err != nil {
		return nil, err
	}
	return sc, nil
}
