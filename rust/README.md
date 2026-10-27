# qorechain-pq-light-client (Rust)

Reference verifier for QoreChain post-quantum light client checkpoints: ML-DSA-87 (FIPS 204) epoch checkpoints signed by a separate validator checkpoint key. Specification: [spec/pq-light-client-v1.md](https://github.com/qorechain/qorechain-pq-light-client/blob/main/spec/pq-light-client-v1.md) (draft).

> **Requires chain support (not scheduled).** QoreChain does not produce these checkpoints; this crate verifies the format and the rules against simulated chains. `fetch_checkpoint` always returns `Error::RequiresChainSupport`.

```rust
use qorechain_pq_light_client::{decode_signed_checkpoint, verify_checkpoint};

let signed = decode_signed_checkpoint(&bytes)?;
let next_state = verify_checkpoint(&trusted_state, &signed, now_unix_seconds)?;
```

API: `Checkpoint`, `ValidatorSet`, `SignedCheckpoint`, `TrustedState`, `Misbehaviour`; `encode_checkpoint_sign_bytes`, `verify_checkpoint`, `detect_misbehaviour`, `new_trusted_state`, `sign_checkpoint` (simulators and tests), the encoders and decoders, `hash_validator_set`; `CheckpointSource` and `fetch_checkpoint`. Errors are `Error` with `code()` returning the stable codes shared with Go and TypeScript.

Depends only on `qorechain-pqc` 0.2.3. No `unsafe`, no I/O.

```bash
cargo test                      # unit tests and the shared vectors
cargo run --example relayer     # a relayer loop over the vectors
```

See also the [guide for relayer developers](https://github.com/qorechain/qorechain-pq-light-client/blob/main/docs/guides/relayer-rust.md). Apache-2.0.
