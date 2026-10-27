// SPDX-License-Identifier: Apache-2.0
import { PqLightClientError, REQUIRES_CHAIN_SUPPORT_MESSAGE } from "./errors.js";
import type { SignedCheckpoint } from "./types.js";

/**
 * Where a light client gets checkpoints from. Relayers and applications can
 * implement it over any transport; the verifier does not depend on it.
 */
export interface CheckpointSource {
  fetchCheckpoint(chainId: string, epoch: bigint): Promise<SignedCheckpoint>;
}

/**
 * Fetches a signed checkpoint from a QoreChain node.
 *
 * Requires chain support (not scheduled): QoreChain does not produce
 * post-quantum checkpoints, so this always rejects with REQUIRES_CHAIN_SUPPORT
 * and makes no network request.
 */
export async function fetchCheckpoint(
  endpoint: string,
  chainId: string,
  epoch: bigint,
): Promise<SignedCheckpoint> {
  void endpoint;
  void chainId;
  void epoch;
  throw new PqLightClientError("REQUIRES_CHAIN_SUPPORT", REQUIRES_CHAIN_SUPPORT_MESSAGE);
}

/** A CheckpointSource over fetchCheckpoint; rejects until the chain supports checkpoints. */
export function chainCheckpointSource(endpoint: string): CheckpointSource {
  return { fetchCheckpoint: (chainId, epoch) => fetchCheckpoint(endpoint, chainId, epoch) };
}
