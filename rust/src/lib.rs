// SPDX-License-Identifier: Apache-2.0
//! Reference verifier for QoreChain post-quantum light client checkpoints,
//! specification v1 (draft).
//!
//! Validators would sign epoch checkpoints with a separate ML-DSA-87 (FIPS 204)
//! checkpoint key; a light client follows the checkpoint chain and accepts a
//! checkpoint once more than two thirds of the named set's power has signed it.
//! Producing checkpoints requires chain support (not scheduled): this crate
//! verifies the format and the rules only.
//!
//! ```no_run
//! use qorechain_pq_light_client::{decode_signed_checkpoint, verify_checkpoint, TrustedState};
//!
//! fn update(state: &TrustedState, bytes: &[u8], now: u64) -> Result<TrustedState, qorechain_pq_light_client::Error> {
//!     let signed = decode_signed_checkpoint(bytes)?;
//!     verify_checkpoint(state, &signed, now)
//! }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod chain;
mod encoding;
mod error;
mod types;
mod verify;

pub use chain::{fetch_checkpoint, ChainCheckpointSource, CheckpointSource};
pub use encoding::{
    decode_checkpoint, decode_signed_checkpoint, decode_validator_set, encode_checkpoint,
    encode_checkpoint_sign_bytes, encode_signed_checkpoint, encode_validator_set,
    hash_validator_set, ADDRESS_SIZE, CHECKPOINT_SIGN_DOMAIN, ENCODING_VERSION, HASH_SIZE,
    MAX_CHAIN_ID_LENGTH, MAX_TOTAL_POWER, MAX_VALIDATORS, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
    VALIDATOR_SET_HASH_DOMAIN,
};
pub use error::{Error, REQUIRES_CHAIN_SUPPORT_MESSAGE};
pub use types::{
    Address, Checkpoint, CheckpointSignature, Hash, Misbehaviour, SignedCheckpoint, TrustedState,
    Validator, ValidatorSet,
};
pub use verify::{detect_misbehaviour, new_trusted_state, sign_checkpoint, verify_checkpoint};

/// Version of this crate.
pub const VERSION: &str = "0.1.0";
