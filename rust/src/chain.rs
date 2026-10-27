// SPDX-License-Identifier: Apache-2.0
use crate::error::Error;
use crate::types::SignedCheckpoint;

/// Where a light client gets checkpoints from. Relayers implement it over
/// their own transport; the verifier does not depend on it.
pub trait CheckpointSource {
    /// Returns the signed checkpoint for `epoch` on `chain_id`.
    fn fetch_checkpoint(&self, chain_id: &str, epoch: u64) -> Result<SignedCheckpoint, Error>;
}

/// Fetches a signed checkpoint from a QoreChain node.
///
/// Requires chain support (not scheduled): QoreChain does not produce
/// post-quantum checkpoints, so this always returns
/// [`Error::RequiresChainSupport`] and makes no network request.
pub fn fetch_checkpoint(
    endpoint: &str,
    chain_id: &str,
    epoch: u64,
) -> Result<SignedCheckpoint, Error> {
    let _ = (endpoint, chain_id, epoch);
    Err(Error::RequiresChainSupport)
}

/// A [`CheckpointSource`] over [`fetch_checkpoint`]; fails until the chain
/// supports checkpoints.
#[derive(Clone, Debug)]
pub struct ChainCheckpointSource {
    /// Node endpoint.
    pub endpoint: String,
}

impl CheckpointSource for ChainCheckpointSource {
    fn fetch_checkpoint(&self, chain_id: &str, epoch: u64) -> Result<SignedCheckpoint, Error> {
        fetch_checkpoint(&self.endpoint, chain_id, epoch)
    }
}
