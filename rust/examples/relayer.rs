// SPDX-License-Identifier: Apache-2.0
//! A relayer loop over the shared vectors: follows the 21-validator checkpoint
//! chain (with a set rotation) from its trust root, then shows the controlled
//! failure of the live source.
//!
//!     cargo run --example relayer

use qorechain_pq_light_client::{
    decode_signed_checkpoint, decode_validator_set, new_trusted_state, verify_checkpoint,
    ChainCheckpointSource, CheckpointSource, Error, SignedCheckpoint, TrustedState,
};
use std::collections::BTreeMap;

/// A checkpoint source backed by bytes in memory.
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/pq-light-client-v1.json"
    ))?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let hex_of = |path: &[&str]| -> Vec<u8> {
        let mut x = &v;
        for p in path {
            x = &x[*p];
        }
        unhex(x.as_str().unwrap())
    };

    let root = decode_signed_checkpoint(&hex_of(&["signedCheckpoints", "c21-e0-root", "encoded"]))?;
    let set = decode_validator_set(&hex_of(&["validatorSets", "C21", "encoded"]))?;
    let trusted = new_trusted_state(
        root.checkpoint,
        root.signatures,
        set.clone(),
        set,
        1_209_600,
        10,
    )?;

    let mut epochs = BTreeMap::new();
    for (epoch, id) in [(1, "c21-e1"), (2, "c21-e2-rotate"), (3, "c21-e3")] {
        epochs.insert(epoch, hex_of(&["signedCheckpoints", id, "encoded"]));
    }
    let latest = decode_signed_checkpoint(&epochs[&3])?.checkpoint.time;
    let state = advance(&Fixture(epochs), &trusted, 3, latest + 5)?;
    println!(
        "trusted epoch {} at height {}, next set of {} validators",
        state.checkpoint.epoch,
        state.checkpoint.height,
        state.next_validator_set.validators.len()
    );

    let live = ChainCheckpointSource {
        endpoint: "https://rpc.example.invalid".into(),
    };
    match live.fetch_checkpoint(&state.checkpoint.chain_id, 4) {
        Err(e) => println!("live source: {e}"),
        Ok(_) => unreachable!(),
    }
    Ok(())
}
