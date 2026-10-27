<!-- SPDX-License-Identifier: Apache-2.0 -->
# Guide for relayer developers (Rust)

How a relayer would carry QoreChain post-quantum checkpoints, with the `qorechain-pq-light-client` crate.

> **Requires chain support (not scheduled).** QoreChain does not produce checkpoints yet, and `fetch_checkpoint` always fails with `REQUIRES_CHAIN_SUPPORT`. Everything below can be built and tested today against the shared vectors and your own simulated chains; it cannot follow a live network.

## Add the crate

The crate is not on crates.io yet; use the repository:

```toml
[dependencies]
qorechain-pq-light-client = { git = "https://github.com/qorechain/qorechain-pq-light-client" }
```

It depends only on `qorechain-pqc` 0.2.3 (ML-DSA-87 and SHAKE-256), uses no `unsafe` code and does no I/O.

## The loop

A relayer keeps one `TrustedState` per QoreChain network it follows, and for each new checkpoint:

1. fetches the signed checkpoint bytes from a source it chooses (`CheckpointSource`);
2. decodes them with `decode_signed_checkpoint` (strict: anything non-canonical is `MALFORMED`);
3. verifies them with `verify_checkpoint(&trusted, &signed, now)`;
4. on success, stores the returned state and forwards the **same bytes** to the destination;
5. on `ConflictingCheckpoint`, stops relaying for that network and reports the evidence.

```rust
use qorechain_pq_light_client::{verify_checkpoint, CheckpointSource, Error, TrustedState};

/// Follows the checkpoint chain from `trusted` up to `latest_epoch`.
fn advance(
    source: &dyn CheckpointSource,
    trusted: &TrustedState,
    latest_epoch: u64,
    now: u64,
) -> Result<TrustedState, Error> {
    let mut state = trusted.clone();
    for epoch in trusted.checkpoint.epoch + 1..=latest_epoch {
        let signed = source.fetch_checkpoint(&state.checkpoint.chain_id, epoch)?;
        state = verify_checkpoint(&state, &signed, now)?;
    }
    Ok(state)
}
```

A complete version that runs over the shared vectors is `rust/examples/relayer.rs` (`cargo run --example relayer`). A real source implements `CheckpointSource` over the node API that the chain would add; until then `ChainCheckpointSource` returns `RequiresChainSupport`, and tests use a source backed by the vectors:

```rust
use qorechain_pq_light_client::{decode_signed_checkpoint, CheckpointSource, Error, SignedCheckpoint};
use std::collections::BTreeMap;

struct Fixture(BTreeMap<u64, Vec<u8>>);

impl CheckpointSource for Fixture {
    fn fetch_checkpoint(&self, _chain_id: &str, epoch: u64) -> Result<SignedCheckpoint, Error> {
        let bytes = self
            .0
            .get(&epoch)
            .ok_or_else(|| Error::Malformed("no checkpoint for this epoch".into()))?;
        decode_signed_checkpoint(bytes)
    }
}
```

## Errors and what to do

| Error | Relayer action |
|---|---|
| `Malformed` | drop the bytes; the source is faulty |
| `ChainIdMismatch` | configuration error |
| `TrustExpired` | stop; re-initialise from a new trust root (spec section 7) |
| `FutureCheckpoint` | check the local clock; retry later |
| `NotNewer` | nothing new; wait |
| `SetMismatch` | an intermediate checkpoint with a set rotation is missing; fetch the epochs in between |
| `UnknownValidator`, `BadSignature` | drop; a signer outside the set or a corrupted signature invalidates the checkpoint |
| `InsufficientPower` | wait for more signatures |
| `ConflictingCheckpoint` | stop relaying; `err.misbehaviour()` holds both checkpoints and the double signers |
| `RequiresChainSupport` | expected today; the chain does not produce checkpoints |

`err.code()` returns the same stable strings as the Go and TypeScript verifiers.

## Skipping epochs

`verify_checkpoint` accepts a later epoch directly while the signing set has not changed. If the set rotated in between, it returns `SetMismatch`, and the relayer must submit every checkpoint from the rotation on: each handover is signed by the outgoing set, and nothing else proves it.

## Forwarding to a destination

Forward the canonical bytes unchanged, never a re-encoding from another library: every implementation must agree on them. Strip signatures from non-members before forwarding only if you produce the bytes yourself; a checkpoint containing one is rejected by every verifier.

For IBC, the destination would run a light client of the type sketched in the specification, section 14. Proofs are then available at checkpoint heights only: query the proof at `height - 1` and submit the checkpoint for `height`.

## Time

Pass the verifier your own clock in Unix seconds. Keep the clock synchronised: a fast clock expires trust early, a slow one rejects new checkpoints as `FutureCheckpoint` once they are more than `max_clock_drift` ahead.

## Testing

`vectors/pq-light-client-v1.json` contains complete checkpoint chains for a 4-validator and a 21-validator set, with rotations, every rejection the verifier can produce, and conflicting checkpoints. Running your relayer logic over them is the closest you can get to a live chain today.
