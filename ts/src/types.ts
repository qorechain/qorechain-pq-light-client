// SPDX-License-Identifier: Apache-2.0

/**
 * What the validators sign at the end of an epoch (spec section 3).
 * All 64-bit fields are unsigned and carried as bigint.
 */
export interface Checkpoint {
  /** Chain id, 1 to 64 printable ASCII characters (0x21 to 0x7e). */
  chainId: string;
  /** Epoch number; strictly increasing along the checkpoint chain. */
  epoch: bigint;
  /** Height of the block the checkpoint commits to. */
  height: bigint;
  /** Block time of that height, Unix seconds. */
  time: bigint;
  /** Hash of the block header at `height` (32 bytes). */
  headerHash: Uint8Array;
  /** Application state root carried in the header at `height` (32 bytes). */
  appHash: Uint8Array;
  /** Hash of the checkpoint validator set that signs this checkpoint. */
  validatorSetHash: Uint8Array;
  /** Hash of the checkpoint validator set that signs the next checkpoint. */
  nextValidatorSetHash: Uint8Array;
}

/** One member of a checkpoint validator set. */
export interface Validator {
  /** Validator consensus address (20 bytes). */
  address: Uint8Array;
  /** Voting power, at least 1. */
  power: bigint;
  /** ML-DSA-87 checkpoint public key (2,592 bytes). */
  publicKey: Uint8Array;
}

/** A checkpoint validator set, sorted by address, strictly ascending. */
export interface ValidatorSet {
  validators: Validator[];
}

/** One validator's ML-DSA-87 signature over the checkpoint sign-bytes. */
export interface CheckpointSignature {
  /** Address of the signing validator (20 bytes). */
  validatorAddress: Uint8Array;
  /** ML-DSA-87 signature (4,627 bytes). */
  signature: Uint8Array;
}

/** A checkpoint with its signatures, as a relayer or a light client receives it. */
export interface SignedCheckpoint {
  checkpoint: Checkpoint;
  /** Sorted by validator address, strictly ascending. May be empty for a trust root. */
  signatures: CheckpointSignature[];
  /**
   * The next validator set. Present exactly when
   * `checkpoint.nextValidatorSetHash` differs from `checkpoint.validatorSetHash`.
   */
  nextValidatorSet?: ValidatorSet;
}

/** What a light client keeps between updates (spec section 7). */
export interface TrustedState {
  /** The latest trusted checkpoint. */
  checkpoint: Checkpoint;
  /** Its signatures (empty for a trust root that was not received signed). */
  signatures: CheckpointSignature[];
  /** The set that signed `checkpoint`; hashes to `checkpoint.validatorSetHash`. */
  validatorSet: ValidatorSet;
  /** The set that must sign the next checkpoint; hashes to `checkpoint.nextValidatorSetHash`. */
  nextValidatorSet: ValidatorSet;
  /** Seconds after `checkpoint.time` during which the state may be used. */
  trustingPeriod: bigint;
  /** Seconds a checkpoint's time may be ahead of the verifier's clock. */
  maxClockDrift: bigint;
}

/** Two checkpoints for the same chain and epoch, both signed by more than 2/3 of one set. */
export interface Misbehaviour {
  chainId: string;
  epoch: bigint;
  /** The checkpoint whose sign-bytes sort first. */
  first: SignedCheckpoint;
  /** The checkpoint whose sign-bytes sort second. */
  second: SignedCheckpoint;
  /** Validators with a valid signature on both, sorted by address. */
  doubleSigners: Uint8Array[];
  /** Sum of their power. */
  doubleSignedPower: bigint;
}
