// SPDX-License-Identifier: Apache-2.0
import { mldsa87 } from "@qorechain/pqc";
import {
  bytesEqual,
  compareBytes,
  encodeCheckpointSignBytes,
  hashValidatorSet,
  validateCheckpoint,
  validateSignatures,
  validateSignedCheckpoint,
  validateValidatorSet,
} from "./encoding.js";
import { PqLightClientError, fail } from "./errors.js";
import type {
  Checkpoint,
  CheckpointSignature,
  Misbehaviour,
  SignedCheckpoint,
  TrustedState,
  Validator,
  ValidatorSet,
} from "./types.js";

const U64_MAX = (1n << 64n) - 1n;

function hexKey(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function index(set: ValidatorSet): Map<string, Validator> {
  const m = new Map<string, Validator>();
  for (const v of set.validators) m.set(hexKey(v.address), v);
  return m;
}

function totalPower(set: ValidatorSet): bigint {
  let t = 0n;
  for (const v of set.validators) t += v.power;
  return t;
}

/**
 * Spec section 8.2: the signatures are checked in order; the first unknown
 * signer or invalid signature rejects the checkpoint, then the signed power
 * must exceed two thirds of the set's total power.
 */
function checkQuorum(c: Checkpoint, signatures: CheckpointSignature[], set: ValidatorSet): void {
  if (!bytesEqual(hashValidatorSet(set), c.validatorSetHash)) {
    fail("SET_MISMATCH", "the checkpoint names a different validator set");
  }
  const msg = encodeCheckpointSignBytes(c);
  const members = index(set);
  let signed = 0n;
  for (const s of signatures) {
    const v = members.get(hexKey(s.validatorAddress));
    if (!v) fail("UNKNOWN_VALIDATOR", `signer ${hexKey(s.validatorAddress)} is not in the set`);
    if (!mldsa87.verify(v.publicKey, msg, s.signature)) {
      fail("BAD_SIGNATURE", `invalid signature from ${hexKey(s.validatorAddress)}`);
    }
    signed += v.power;
  }
  if (signed * 3n <= totalPower(set) * 2n) {
    fail("INSUFFICIENT_POWER", "signed power does not exceed two thirds of the set");
  }
}

function buildMisbehaviour(set: ValidatorSet, a: SignedCheckpoint, b: SignedCheckpoint): Misbehaviour {
  const aBytes = encodeCheckpointSignBytes(a.checkpoint);
  const bBytes = encodeCheckpointSignBytes(b.checkpoint);
  const [first, firstBytes, second, secondBytes] =
    compareBytes(aBytes, bBytes) <= 0 ? [a, aBytes, b, bBytes] : [b, bBytes, a, aBytes];
  const members = index(set);
  const secondSigs = new Map<string, Uint8Array>();
  for (const s of second.signatures) secondSigs.set(hexKey(s.validatorAddress), s.signature);
  const doubleSigners: Uint8Array[] = [];
  let doubleSignedPower = 0n;
  for (const s of first.signatures) {
    const key = hexKey(s.validatorAddress);
    const v = members.get(key);
    const other = secondSigs.get(key);
    if (!v || !other) continue;
    if (mldsa87.verify(v.publicKey, firstBytes, s.signature) && mldsa87.verify(v.publicKey, secondBytes, other)) {
      doubleSigners.push(v.address);
      doubleSignedPower += v.power;
    }
  }
  return {
    chainId: first.checkpoint.chainId,
    epoch: first.checkpoint.epoch,
    first,
    second,
    doubleSigners,
    doubleSignedPower,
  };
}

export interface TrustedStateInit {
  checkpoint: Checkpoint;
  signatures?: CheckpointSignature[];
  validatorSet: ValidatorSet;
  nextValidatorSet: ValidatorSet;
  trustingPeriod: bigint;
  maxClockDrift: bigint;
}

/**
 * Builds a trust root (spec section 7.1). The caller obtains the checkpoint
 * and both sets out of band; signatures, if given, are kept for evidence but
 * not verified here.
 */
export function newTrustedState(init: TrustedStateInit): TrustedState {
  validateCheckpoint(init.checkpoint);
  const signatures = init.signatures ?? [];
  validateSignatures(signatures);
  validateValidatorSet(init.validatorSet);
  validateValidatorSet(init.nextValidatorSet);
  if (typeof init.trustingPeriod !== "bigint" || init.trustingPeriod < 1n || init.trustingPeriod > U64_MAX) {
    fail("MALFORMED", "trusting period must be at least one second");
  }
  if (typeof init.maxClockDrift !== "bigint" || init.maxClockDrift < 0n || init.maxClockDrift > U64_MAX) {
    fail("MALFORMED", "max clock drift must be a 64-bit unsigned integer");
  }
  if (!bytesEqual(hashValidatorSet(init.validatorSet), init.checkpoint.validatorSetHash)) {
    fail("SET_MISMATCH", "validator set does not match the checkpoint");
  }
  if (!bytesEqual(hashValidatorSet(init.nextValidatorSet), init.checkpoint.nextValidatorSetHash)) {
    fail("SET_MISMATCH", "next validator set does not match the checkpoint");
  }
  return {
    checkpoint: init.checkpoint,
    signatures,
    validatorSet: init.validatorSet,
    nextValidatorSet: init.nextValidatorSet,
    trustingPeriod: init.trustingPeriod,
    maxClockDrift: init.maxClockDrift,
  };
}

/**
 * Verifies `signed` against `trusted` at time `now` (Unix seconds) and
 * returns the new trusted state. Throws PqLightClientError with a stable code;
 * the checks run in the order of spec section 8.1.
 */
export function verifyCheckpoint(trusted: TrustedState, signed: SignedCheckpoint, now: bigint): TrustedState {
  validateSignedCheckpoint(signed);
  if (typeof now !== "bigint" || now < 0n || now > U64_MAX) fail("MALFORMED", "now must be Unix seconds");
  const c = signed.checkpoint;
  const t = trusted.checkpoint;

  if (c.chainId !== t.chainId) fail("CHAIN_ID_MISMATCH", `expected ${t.chainId}, got ${c.chainId}`);
  if (now >= t.time && now - t.time >= trusted.trustingPeriod) {
    fail("TRUST_EXPIRED", "the trusted checkpoint is older than the trusting period");
  }
  if (c.time > now && c.time - now > trusted.maxClockDrift) {
    fail("FUTURE_CHECKPOINT", "checkpoint time is ahead of the local clock by more than the allowed drift");
  }

  if (c.epoch === t.epoch) {
    if (bytesEqual(encodeCheckpointSignBytes(c), encodeCheckpointSignBytes(t))) {
      fail("NOT_NEWER", "this checkpoint is already trusted");
    }
    checkQuorum(c, signed.signatures, trusted.validatorSet);
    const trustedSigned: SignedCheckpoint = { checkpoint: t, signatures: trusted.signatures };
    if (!bytesEqual(t.validatorSetHash, t.nextValidatorSetHash)) {
      trustedSigned.nextValidatorSet = trusted.nextValidatorSet;
    }
    const evidence = buildMisbehaviour(trusted.validatorSet, trustedSigned, signed);
    throw new PqLightClientError(
      "CONFLICTING_CHECKPOINT",
      `two checkpoints for epoch ${c.epoch} carry more than two thirds of the power`,
      evidence,
    );
  }

  if (c.epoch < t.epoch || c.height <= t.height || c.time <= t.time) {
    fail("NOT_NEWER", "epoch, height and time must all increase");
  }
  if (!bytesEqual(c.validatorSetHash, t.nextValidatorSetHash)) {
    fail("SET_MISMATCH", "the checkpoint is not signed by the set the trusted state names");
  }
  const next = signed.nextValidatorSet ?? trusted.nextValidatorSet;
  if (signed.nextValidatorSet && !bytesEqual(hashValidatorSet(next), c.nextValidatorSetHash)) {
    fail("SET_MISMATCH", "the next validator set does not match its hash");
  }
  checkQuorum(c, signed.signatures, trusted.nextValidatorSet);

  return {
    checkpoint: c,
    signatures: signed.signatures,
    validatorSet: trusted.nextValidatorSet,
    nextValidatorSet: next,
    trustingPeriod: trusted.trustingPeriod,
    maxClockDrift: trusted.maxClockDrift,
  };
}

/**
 * Returns evidence when `a` and `b` are two different checkpoints for the
 * same chain and epoch, each carrying more than two thirds of `validatorSet`
 * (spec section 9). Returns null otherwise, including for malformed input.
 */
export function detectMisbehaviour(
  validatorSet: ValidatorSet,
  a: SignedCheckpoint,
  b: SignedCheckpoint,
): Misbehaviour | null {
  try {
    validateValidatorSet(validatorSet);
    validateSignedCheckpoint(a);
    validateSignedCheckpoint(b);
    if (a.checkpoint.chainId !== b.checkpoint.chainId) return null;
    if (a.checkpoint.epoch !== b.checkpoint.epoch) return null;
    if (bytesEqual(encodeCheckpointSignBytes(a.checkpoint), encodeCheckpointSignBytes(b.checkpoint))) {
      return null;
    }
    checkQuorum(a.checkpoint, a.signatures, validatorSet);
    checkQuorum(b.checkpoint, b.signatures, validatorSet);
  } catch (e) {
    if (e instanceof PqLightClientError) return null;
    throw e;
  }
  return buildMisbehaviour(validatorSet, a, b);
}

/**
 * Signs a checkpoint with an ML-DSA-87 checkpoint secret key (deterministic
 * FIPS 204 signing). For simulators and tests; validators would sign inside
 * the node once the chain supports checkpoints.
 */
export function signCheckpoint(secretKey: Uint8Array, checkpoint: Checkpoint): Uint8Array {
  return mldsa87.sign(secretKey, encodeCheckpointSignBytes(checkpoint));
}
