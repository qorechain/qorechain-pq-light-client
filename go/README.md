# qorechain-pq-light-client (Go)

`github.com/qorechain/qorechain-pq-light-client/go`, package `pqlightclient`: reference verifier for QoreChain post-quantum light client checkpoints (ML-DSA-87, FIPS 204), over `github.com/qorechain/qorechain-pqc/go` v0.2.3. Specification: [spec/pq-light-client-v1.md](../spec/pq-light-client-v1.md) (draft).

> **Requires chain support (not scheduled).** QoreChain does not produce these checkpoints; this module verifies the format and the rules against simulated chains. `FetchCheckpoint` always returns an error with code `REQUIRES_CHAIN_SUPPORT` and makes no request.

```go
signed, err := pqlightclient.DecodeSignedCheckpoint(b)
if err != nil {
	return err
}
next, err := pqlightclient.VerifyCheckpoint(trusted, signed, uint64(time.Now().Unix()))
if errors.Is(err, pqlightclient.ErrConflictingCheckpoint) {
	// err.(*pqlightclient.Error).Misbehaviour holds the evidence
}
```

API: `Checkpoint`, `ValidatorSet`, `SignedCheckpoint`, `TrustedState`, `Misbehaviour`; `EncodeCheckpointSignBytes`, `VerifyCheckpoint`, `DetectMisbehaviour`, `NewTrustedState`, `SignCheckpoint` (simulators and tests), the encoders and decoders, `HashValidatorSet`; `CheckpointSource` and `FetchCheckpoint`. Errors are `*Error` with a stable `Code`; compare with `errors.Is(err, ErrInsufficientPower)` and so on.

```bash
go test ./...                                                         # unit tests and the shared vectors
go test -run '^$' -fuzz FuzzDecodeSignedCheckpoint -fuzztime 60s      # fuzz the decoder
```

Apache-2.0.
