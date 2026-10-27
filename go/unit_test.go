// SPDX-License-Identifier: Apache-2.0

package pqlightclient

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"

	pqc "github.com/qorechain/qorechain-pqc/go"
)

type unitKey struct {
	pub, sec []byte
	addr     [AddressSize]byte
}

func unitFixture(t *testing.T) ([]unitKey, ValidatorSet) {
	t.Helper()
	var keys []unitKey
	for i := 0; i < 3; i++ {
		pub, sec, err := pqc.MLDSA87.KeygenFromSeed(pqc.Shake256([]byte{'u', byte(i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		k := unitKey{pub: pub, sec: sec}
		copy(k.addr[:], pqc.Shake256([]byte{'a', byte(i)}, AddressSize))
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i].addr[:], keys[j].addr[:]) < 0 })
	var set ValidatorSet
	for _, k := range keys {
		set.Validators = append(set.Validators, Validator{Address: k.addr, Power: 10, PublicKey: k.pub})
	}
	return keys, set
}

func unitCheckpoint(t *testing.T, set *ValidatorSet, epoch uint64) Checkpoint {
	t.Helper()
	h, err := HashValidatorSet(set)
	if err != nil {
		t.Fatal(err)
	}
	c := Checkpoint{ChainID: "unit-chain", Epoch: epoch, Height: 100 * (epoch + 1), Time: 1000 + 60*epoch, ValidatorSetHash: h, NextValidatorSetHash: h}
	c.AppHash[0] = byte(epoch)
	return c
}

func unitSign(t *testing.T, keys []unitKey, c Checkpoint) *SignedCheckpoint {
	t.Helper()
	sc := &SignedCheckpoint{Checkpoint: c}
	for _, k := range keys {
		sig, err := SignCheckpoint(k.sec, &c)
		if err != nil {
			t.Fatal(err)
		}
		sc.Signatures = append(sc.Signatures, CheckpointSignature{ValidatorAddress: k.addr, Signature: sig})
	}
	return sc
}

func TestSignBytesLayout(t *testing.T) {
	_, set := unitFixture(t)
	c := unitCheckpoint(t, &set, 1)
	sb, _ := EncodeCheckpointSignBytes(&c)
	enc, _ := EncodeCheckpoint(&c)
	if !bytes.HasPrefix(sb, []byte(CheckpointSignDomain)) || !bytes.Equal(sb[len(CheckpointSignDomain):], enc) {
		t.Fatal("sign-bytes must be the domain followed by the checkpoint encoding")
	}
	if len(enc) != 154+len(c.ChainID) {
		t.Fatalf("checkpoint encoding is %d bytes", len(enc))
	}
}

func TestVerifyAndQuorum(t *testing.T) {
	keys, set := unitFixture(t)
	root, err := NewTrustedState(unitCheckpoint(t, &set, 0), nil, set, set, 3600, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCheckpoint(root, unitSign(t, keys[:2], unitCheckpoint(t, &set, 1)), 1061); !errors.Is(err, ErrInsufficientPower) {
		t.Fatalf("two of three equal validators: got %v", err)
	}
	s, err := VerifyCheckpoint(root, unitSign(t, keys, unitCheckpoint(t, &set, 1)), 1061)
	if err != nil || s.Checkpoint.Epoch != 1 {
		t.Fatalf("got %v", err)
	}
	sc := unitSign(t, keys, unitCheckpoint(t, &set, 1))
	sc.Signatures[0].Signature = append(sc.Signatures[0].Signature, 0)
	if _, err := EncodeSignedCheckpoint(sc); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a 4,628-byte signature must be rejected: %v", err)
	}
}

// TestRequiresChainSupport is the controlled failure for every live-chain
// function: QoreChain does not produce checkpoints, so they fail with
// REQUIRES_CHAIN_SUPPORT and make no request.
func TestRequiresChainSupport(t *testing.T) {
	var src CheckpointSource = ChainCheckpointSource{Endpoint: "https://rpc.example.invalid"}
	for _, err := range []error{
		func() error {
			_, err := FetchCheckpoint(context.Background(), "https://rpc.example.invalid", "unit-chain", 1)
			return err
		}(),
		func() error { _, err := src.FetchCheckpoint(context.Background(), "unit-chain", 1); return err }(),
	} {
		if !errors.Is(err, ErrRequiresChainSupport) || err.Error() != "REQUIRES_CHAIN_SUPPORT: requires chain support (not scheduled)" {
			t.Fatalf("got %v", err)
		}
	}
}
