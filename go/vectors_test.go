// SPDX-License-Identifier: Apache-2.0

package pqlightclient

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type vectorFile struct {
	Constants struct {
		CheckpointSignDomain   string `json:"checkpointSignDomain"`
		ValidatorSetHashDomain string `json:"validatorSetHashDomain"`
	} `json:"constants"`
	ValidatorSets map[string]struct {
		Encoded string `json:"encoded"`
		Hash    string `json:"hash"`
	} `json:"validatorSets"`
	SignedCheckpoints map[string]struct {
		Encoded   string `json:"encoded"`
		SignBytes string `json:"signBytes"`
	} `json:"signedCheckpoints"`
	TrustRoots map[string]struct {
		Checkpoint       string `json:"checkpoint"`
		ValidatorSet     string `json:"validatorSet"`
		NextValidatorSet string `json:"nextValidatorSet"`
		TrustingPeriod   string `json:"trustingPeriod"`
		MaxClockDrift    string `json:"maxClockDrift"`
	} `json:"trustRoots"`
	Cases []vectorCase `json:"cases"`
}

type evidence struct {
	Found             bool     `json:"found"`
	ChainID           string   `json:"chainId"`
	Epoch             string   `json:"epoch"`
	FirstSignBytes    string   `json:"firstSignBytes"`
	SecondSignBytes   string   `json:"secondSignBytes"`
	DoubleSigners     []string `json:"doubleSigners"`
	DoubleSignedPower string   `json:"doubleSignedPower"`
}

type vectorCase struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	TrustRoot string `json:"trustRoot"`
	Steps     []struct {
		Checkpoint string `json:"checkpoint"`
		Now        string `json:"now"`
		Expect     struct {
			OK                   bool      `json:"ok"`
			Error                string    `json:"error"`
			Epoch                string    `json:"epoch"`
			Height               string    `json:"height"`
			ValidatorSetHash     string    `json:"validatorSetHash"`
			NextValidatorSetHash string    `json:"nextValidatorSetHash"`
			Misbehaviour         *evidence `json:"misbehaviour"`
		} `json:"expect"`
	} `json:"steps"`
	ValidatorSet string `json:"validatorSet"`
	A            string `json:"a"`
	B            string `json:"b"`
	Object       string `json:"object"`
	Encoded      string `json:"encoded"`
	Expect       struct {
		evidence
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	} `json:"expect"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "pq-light-client-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func u64(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func signBytesHex(t *testing.T, c *Checkpoint) string {
	t.Helper()
	b, err := EncodeCheckpointSignBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func setHashHex(t *testing.T, s *ValidatorSet) string {
	t.Helper()
	h, err := HashValidatorSet(s)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h[:])
}

func checkEvidence(t *testing.T, m *Misbehaviour, want *evidence) {
	t.Helper()
	if m == nil {
		t.Fatal("expected misbehaviour evidence")
	}
	if want.ChainID != "" && (m.ChainID != want.ChainID || strconv.FormatUint(m.Epoch, 10) != want.Epoch) {
		t.Fatalf("evidence for %s/%d, want %s/%s", m.ChainID, m.Epoch, want.ChainID, want.Epoch)
	}
	if signBytesHex(t, &m.First.Checkpoint) != want.FirstSignBytes || signBytesHex(t, &m.Second.Checkpoint) != want.SecondSignBytes {
		t.Fatal("evidence order differs")
	}
	if len(m.DoubleSigners) != len(want.DoubleSigners) {
		t.Fatalf("double signers: got %d, want %d", len(m.DoubleSigners), len(want.DoubleSigners))
	}
	for i := range m.DoubleSigners {
		if hex.EncodeToString(m.DoubleSigners[i][:]) != want.DoubleSigners[i] {
			t.Fatalf("double signer %d differs", i)
		}
	}
	if strconv.FormatUint(m.DoubleSignedPower, 10) != want.DoubleSignedPower {
		t.Fatalf("double signed power %d, want %s", m.DoubleSignedPower, want.DoubleSignedPower)
	}
}

func TestVectors(t *testing.T) {
	v := loadVectors(t)
	if v.Constants.CheckpointSignDomain != CheckpointSignDomain || v.Constants.ValidatorSetHashDomain != ValidatorSetHashDomain {
		t.Fatal("domains differ from the vectors")
	}

	sets := map[string]*ValidatorSet{}
	for id, s := range v.ValidatorSets {
		set, err := DecodeValidatorSet(unhex(t, s.Encoded))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		enc, _ := EncodeValidatorSet(set)
		if hex.EncodeToString(enc) != s.Encoded || setHashHex(t, set) != s.Hash {
			t.Fatalf("%s: round trip or hash differs", id)
		}
		sets[id] = set
	}

	signed := func(id string) *SignedCheckpoint {
		sc, err := DecodeSignedCheckpoint(unhex(t, v.SignedCheckpoints[id].Encoded))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		return sc
	}
	for id, c := range v.SignedCheckpoints {
		sc := signed(id)
		enc, err := EncodeSignedCheckpoint(sc)
		if err != nil || hex.EncodeToString(enc) != c.Encoded {
			t.Fatalf("%s: round trip differs", id)
		}
		if signBytesHex(t, &sc.Checkpoint) != c.SignBytes {
			t.Fatalf("%s: sign-bytes differ", id)
		}
	}

	for _, tc := range v.Cases {
		t.Run(tc.Type+"/"+tc.Name, func(t *testing.T) {
			switch tc.Type {
			case "chain":
				r := v.TrustRoots[tc.TrustRoot]
				root := signed(r.Checkpoint)
				state, err := NewTrustedState(root.Checkpoint, root.Signatures, *sets[r.ValidatorSet], *sets[r.NextValidatorSet], u64(t, r.TrustingPeriod), u64(t, r.MaxClockDrift))
				if err != nil {
					t.Fatal(err)
				}
				for _, step := range tc.Steps {
					next, err := VerifyCheckpoint(state, signed(step.Checkpoint), u64(t, step.Now))
					if step.Expect.OK {
						if err != nil {
							t.Fatalf("%s: %v", step.Checkpoint, err)
						}
						if strconv.FormatUint(next.Checkpoint.Epoch, 10) != step.Expect.Epoch ||
							strconv.FormatUint(next.Checkpoint.Height, 10) != step.Expect.Height ||
							setHashHex(t, &next.ValidatorSet) != step.Expect.ValidatorSetHash ||
							setHashHex(t, &next.NextValidatorSet) != step.Expect.NextValidatorSetHash {
							t.Fatalf("%s: new state differs", step.Checkpoint)
						}
						state = next
						continue
					}
					var e *Error
					if !errors.As(err, &e) || string(e.Code) != step.Expect.Error {
						t.Fatalf("%s: got %v, want %s", step.Checkpoint, err, step.Expect.Error)
					}
					if !errors.Is(err, &Error{Code: Code(step.Expect.Error)}) {
						t.Fatal("errors.Is does not match the code")
					}
					if step.Expect.Misbehaviour != nil {
						checkEvidence(t, e.Misbehaviour, step.Expect.Misbehaviour)
					}
				}
			case "misbehaviour":
				m := DetectMisbehaviour(sets[tc.ValidatorSet], signed(tc.A), signed(tc.B))
				if !tc.Expect.Found {
					if m != nil {
						t.Fatal("unexpected evidence")
					}
					return
				}
				checkEvidence(t, m, &tc.Expect.evidence)
			case "decode":
				b := unhex(t, tc.Encoded)
				var enc []byte
				var err error
				switch tc.Object {
				case "checkpoint":
					var c *Checkpoint
					if c, err = DecodeCheckpoint(b); err == nil {
						enc, err = EncodeCheckpoint(c)
					}
				case "validatorSet":
					var s *ValidatorSet
					if s, err = DecodeValidatorSet(b); err == nil {
						enc, err = EncodeValidatorSet(s)
					}
				case "signedCheckpoint":
					var sc *SignedCheckpoint
					if sc, err = DecodeSignedCheckpoint(b); err == nil {
						enc, err = EncodeSignedCheckpoint(sc)
					}
				default:
					t.Fatalf("unknown object %s", tc.Object)
				}
				if tc.Expect.OK {
					if err != nil || hex.EncodeToString(enc) != tc.Encoded {
						t.Fatalf("round trip failed: %v", err)
					}
				} else if !errors.Is(err, ErrMalformed) {
					t.Fatalf("got %v, want MALFORMED", err)
				}
			default:
				t.Fatalf("unknown case type %s", tc.Type)
			}
		})
	}
}
