// SPDX-License-Identifier: Apache-2.0

/// A 20-byte validator consensus address.
pub type Address = [u8; 20];
/// A 32-byte hash.
pub type Hash = [u8; 32];

/// What the validators sign at the end of an epoch (spec section 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Chain id, 1 to 64 printable ASCII characters (0x21 to 0x7e).
    pub chain_id: String,
    /// Epoch number; strictly increasing along the checkpoint chain.
    pub epoch: u64,
    /// Height of the block the checkpoint commits to.
    pub height: u64,
    /// Block time at `height`, Unix seconds.
    pub time: u64,
    /// Hash of the block header at `height`.
    pub header_hash: Hash,
    /// Application state root carried in the header at `height`.
    pub app_hash: Hash,
    /// Hash of the checkpoint validator set that signs this checkpoint.
    pub validator_set_hash: Hash,
    /// Hash of the checkpoint validator set that signs the next checkpoint.
    pub next_validator_set_hash: Hash,
}

/// One member of a checkpoint validator set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    /// Consensus address.
    pub address: Address,
    /// Voting power, at least 1.
    pub power: u64,
    /// ML-DSA-87 checkpoint public key, 2,592 bytes.
    pub public_key: Vec<u8>,
}

/// A checkpoint validator set, sorted by address, strictly ascending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    /// The members.
    pub validators: Vec<Validator>,
}

/// One validator's ML-DSA-87 signature over the checkpoint sign-bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSignature {
    /// Address of the signing validator.
    pub validator_address: Address,
    /// ML-DSA-87 signature, 4,627 bytes.
    pub signature: Vec<u8>,
}

/// A checkpoint with its signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// The checkpoint.
    pub checkpoint: Checkpoint,
    /// Sorted by validator address, strictly ascending. May be empty for a trust root.
    pub signatures: Vec<CheckpointSignature>,
    /// Present exactly when `checkpoint.next_validator_set_hash` differs from
    /// `checkpoint.validator_set_hash`.
    pub next_validator_set: Option<ValidatorSet>,
}

/// What a light client keeps between updates (spec section 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedState {
    /// The latest trusted checkpoint.
    pub checkpoint: Checkpoint,
    /// Its signatures (empty for an unsigned trust root).
    pub signatures: Vec<CheckpointSignature>,
    /// The set that signed `checkpoint`.
    pub validator_set: ValidatorSet,
    /// The set that must sign the next checkpoint.
    pub next_validator_set: ValidatorSet,
    /// Seconds after `checkpoint.time` during which the state may be used.
    pub trusting_period: u64,
    /// Seconds a checkpoint's time may be ahead of the verifier's clock.
    pub max_clock_drift: u64,
}

/// Two checkpoints for the same chain and epoch, each signed by more than
/// two thirds of one set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Misbehaviour {
    /// Chain id of both checkpoints.
    pub chain_id: String,
    /// Epoch of both checkpoints.
    pub epoch: u64,
    /// The checkpoint whose sign-bytes sort first.
    pub first: SignedCheckpoint,
    /// The checkpoint whose sign-bytes sort second.
    pub second: SignedCheckpoint,
    /// Validators with a valid signature on both, sorted by address.
    pub double_signers: Vec<Address>,
    /// Sum of their power.
    pub double_signed_power: u64,
}
