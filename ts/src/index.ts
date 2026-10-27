// SPDX-License-Identifier: Apache-2.0
/**
 * Reference verifier for QoreChain post-quantum light client checkpoints,
 * specification v1 (draft). Producing checkpoints requires chain support
 * (not scheduled); this package verifies the format and the rules only.
 */
export type {
  Checkpoint,
  CheckpointSignature,
  Misbehaviour,
  SignedCheckpoint,
  TrustedState,
  Validator,
  ValidatorSet,
} from "./types.js";
export { PqLightClientError, REQUIRES_CHAIN_SUPPORT_MESSAGE } from "./errors.js";
export type { ErrorCode } from "./errors.js";
export {
  ADDRESS_SIZE,
  CHECKPOINT_SIGN_DOMAIN,
  ENCODING_VERSION,
  HASH_SIZE,
  MAX_CHAIN_ID_LENGTH,
  MAX_TOTAL_POWER,
  MAX_VALIDATORS,
  ML_DSA_87_PUBLIC_KEY_SIZE,
  ML_DSA_87_SIGNATURE_SIZE,
  VALIDATOR_SET_HASH_DOMAIN,
  decodeCheckpoint,
  decodeSignedCheckpoint,
  decodeValidatorSet,
  encodeCheckpoint,
  encodeCheckpointSignBytes,
  encodeSignedCheckpoint,
  encodeValidatorSet,
  hashValidatorSet,
} from "./encoding.js";
export { detectMisbehaviour, newTrustedState, signCheckpoint, verifyCheckpoint } from "./verify.js";
export type { TrustedStateInit } from "./verify.js";
export { chainCheckpointSource, fetchCheckpoint } from "./chain.js";
export type { CheckpointSource } from "./chain.js";

export const VERSION = "0.1.0";
