// SPDX-License-Identifier: Apache-2.0

package pqlightclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func addVectorSeeds(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "pq-light-client-v1.json"))
	if err != nil {
		f.Fatal(err)
	}
	var v struct {
		SignedCheckpoints map[string]struct {
			Encoded string `json:"encoded"`
		} `json:"signedCheckpoints"`
		Cases []struct {
			Encoded string `json:"encoded"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	for _, c := range v.SignedCheckpoints {
		b, _ := hex.DecodeString(c.Encoded)
		f.Add(b)
	}
	for _, c := range v.Cases {
		if c.Encoded != "" {
			b, _ := hex.DecodeString(c.Encoded)
			f.Add(b)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{1})
}

// FuzzDecodeSignedCheckpoint: the decoder never panics, only returns
// MALFORMED, and whatever it accepts re-encodes to the same bytes.
func FuzzDecodeSignedCheckpoint(f *testing.F) {
	addVectorSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		sc, err := DecodeSignedCheckpoint(b)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("decoder returned %v", err)
			}
			return
		}
		enc, err := EncodeSignedCheckpoint(sc)
		if err != nil || !bytes.Equal(enc, b) {
			t.Fatalf("accepted input is not canonical: %v", err)
		}
	})
}

// FuzzDecodeValidatorSet: same properties for validator sets.
func FuzzDecodeValidatorSet(f *testing.F) {
	addVectorSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeValidatorSet(b)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("decoder returned %v", err)
			}
			return
		}
		enc, err := EncodeValidatorSet(s)
		if err != nil || !bytes.Equal(enc, b) {
			t.Fatalf("accepted input is not canonical: %v", err)
		}
	})
}

// FuzzDecodeCheckpoint: same properties for checkpoints.
func FuzzDecodeCheckpoint(f *testing.F) {
	addVectorSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeCheckpoint(b)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("decoder returned %v", err)
			}
			return
		}
		enc, err := EncodeCheckpoint(c)
		if err != nil || !bytes.Equal(enc, b) {
			t.Fatalf("accepted input is not canonical: %v", err)
		}
	})
}
