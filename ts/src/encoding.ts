// SPDX-License-Identifier: Apache-2.0
import { shake256 } from "@qorechain/pqc";
import { fail } from "./errors.js";
import type {
  Checkpoint,
  CheckpointSignature,
  SignedCheckpoint,
  Validator,
  ValidatorSet,
} from "./types.js";

/** Prefix of every checkpoint sign-bytes (spec section 4). Proposed for reservation. */
export const CHECKPOINT_SIGN_DOMAIN = "qorechain-pqlc-checkpoint-v1|";
/** Prefix hashed in front of an encoded validator set (spec section 5). */
export const VALIDATOR_SET_HASH_DOMAIN = "qorechain-pqlc-valset-v1|";
/** Version byte of every encoding in this specification. */
export const ENCODING_VERSION = 1;
export const ML_DSA_87_PUBLIC_KEY_SIZE = 2592;
export const ML_DSA_87_SIGNATURE_SIZE = 4627;
export const ADDRESS_SIZE = 20;
export const HASH_SIZE = 32;
export const MAX_CHAIN_ID_LENGTH = 64;
export const MAX_VALIDATORS = 256;
/** Same bound as the consensus engine: (2^63 - 1) / 8. */
export const MAX_TOTAL_POWER = (1n << 60n) - 1n;

const U64_MAX = (1n << 64n) - 1n;
const textEncoder = new TextEncoder();

// ---------------------------------------------------------------------------
// byte helpers

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Lexicographic order of two byte strings: negative, zero or positive. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

function concat(parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u8(v: number): Uint8Array {
  return Uint8Array.of(v);
}

function u16(v: number): Uint8Array {
  return Uint8Array.of((v >>> 8) & 0xff, v & 0xff);
}

function u64(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, false);
  return out;
}

class Reader {
  private off = 0;
  constructor(private readonly buf: Uint8Array) {}

  take(n: number, what: string): Uint8Array {
    if (this.off + n > this.buf.length) fail("MALFORMED", `truncated ${what}`);
    const out = this.buf.slice(this.off, this.off + n);
    this.off += n;
    return out;
  }

  u8(what: string): number {
    return this.take(1, what)[0]!;
  }

  u16(what: string): number {
    const b = this.take(2, what);
    return (b[0]! << 8) | b[1]!;
  }

  u64(what: string): bigint {
    const b = this.take(8, what);
    return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, false);
  }

  end(): void {
    if (this.off !== this.buf.length) fail("MALFORMED", "trailing bytes");
  }
}

// ---------------------------------------------------------------------------
// structural validation (spec section 6)

function isU64(v: unknown): v is bigint {
  return typeof v === "bigint" && v >= 0n && v <= U64_MAX;
}

function checkBytes(v: unknown, len: number, what: string): void {
  if (!(v instanceof Uint8Array) || v.length !== len) {
    fail("MALFORMED", `${what} must be ${len} bytes`);
  }
}

export function validateCheckpoint(c: Checkpoint): void {
  if (typeof c?.chainId !== "string") fail("MALFORMED", "chain id must be a string");
  const n = c.chainId.length;
  if (n < 1 || n > MAX_CHAIN_ID_LENGTH) fail("MALFORMED", "chain id must be 1 to 64 characters");
  for (let i = 0; i < n; i++) {
    const ch = c.chainId.charCodeAt(i);
    if (ch < 0x21 || ch > 0x7e) fail("MALFORMED", "chain id must be printable ASCII without spaces");
  }
  if (!isU64(c.epoch)) fail("MALFORMED", "epoch must be a 64-bit unsigned integer");
  if (!isU64(c.height)) fail("MALFORMED", "height must be a 64-bit unsigned integer");
  if (!isU64(c.time)) fail("MALFORMED", "time must be a 64-bit unsigned integer");
  checkBytes(c.headerHash, HASH_SIZE, "header hash");
  checkBytes(c.appHash, HASH_SIZE, "app hash");
  checkBytes(c.validatorSetHash, HASH_SIZE, "validator set hash");
  checkBytes(c.nextValidatorSetHash, HASH_SIZE, "next validator set hash");
}

export function validateValidatorSet(s: ValidatorSet): void {
  const vs = s?.validators;
  if (!Array.isArray(vs) || vs.length < 1 || vs.length > MAX_VALIDATORS) {
    fail("MALFORMED", `a validator set has 1 to ${MAX_VALIDATORS} validators`);
  }
  let total = 0n;
  let prev: Uint8Array | undefined;
  for (const v of vs) {
    checkBytes(v.address, ADDRESS_SIZE, "validator address");
    checkBytes(v.publicKey, ML_DSA_87_PUBLIC_KEY_SIZE, "validator public key");
    if (!isU64(v.power) || v.power < 1n) fail("MALFORMED", "validator power must be at least 1");
    if (prev && compareBytes(prev, v.address) >= 0) {
      fail("MALFORMED", "validators must be sorted by address, without duplicates");
    }
    prev = v.address;
    total += v.power;
    if (total > MAX_TOTAL_POWER) fail("MALFORMED", "total power exceeds the maximum");
  }
}

export function validateSignatures(sigs: CheckpointSignature[]): void {
  if (!Array.isArray(sigs) || sigs.length > MAX_VALIDATORS) {
    fail("MALFORMED", `at most ${MAX_VALIDATORS} signatures`);
  }
  let prev: Uint8Array | undefined;
  for (const s of sigs) {
    checkBytes(s.validatorAddress, ADDRESS_SIZE, "signer address");
    checkBytes(s.signature, ML_DSA_87_SIGNATURE_SIZE, "signature");
    if (prev && compareBytes(prev, s.validatorAddress) >= 0) {
      fail("MALFORMED", "signatures must be sorted by address, without duplicates");
    }
    prev = s.validatorAddress;
  }
}

export function validateSignedCheckpoint(sc: SignedCheckpoint): void {
  validateCheckpoint(sc?.checkpoint);
  validateSignatures(sc.signatures);
  const changes = !bytesEqual(sc.checkpoint.validatorSetHash, sc.checkpoint.nextValidatorSetHash);
  if (changes && !sc.nextValidatorSet) {
    fail("MALFORMED", "the next validator set is required when it changes");
  }
  if (!changes && sc.nextValidatorSet) {
    fail("MALFORMED", "the next validator set must be omitted when it does not change");
  }
  if (sc.nextValidatorSet) validateValidatorSet(sc.nextValidatorSet);
}

// ---------------------------------------------------------------------------
// encoders

/** Canonical checkpoint encoding (spec section 3). */
export function encodeCheckpoint(c: Checkpoint): Uint8Array {
  validateCheckpoint(c);
  return concat([
    u8(ENCODING_VERSION),
    u8(c.chainId.length),
    textEncoder.encode(c.chainId),
    u64(c.epoch),
    u64(c.height),
    u64(c.time),
    c.headerHash,
    c.appHash,
    c.validatorSetHash,
    c.nextValidatorSetHash,
  ]);
}

/** The bytes each validator signs: CHECKPOINT_SIGN_DOMAIN followed by the checkpoint encoding. */
export function encodeCheckpointSignBytes(c: Checkpoint): Uint8Array {
  return concat([textEncoder.encode(CHECKPOINT_SIGN_DOMAIN), encodeCheckpoint(c)]);
}

export function encodeValidatorSet(s: ValidatorSet): Uint8Array {
  validateValidatorSet(s);
  const parts: Uint8Array[] = [u8(ENCODING_VERSION), u16(s.validators.length)];
  for (const v of s.validators) parts.push(v.address, u64(v.power), v.publicKey);
  return concat(parts);
}

/** SHAKE-256 over VALIDATOR_SET_HASH_DOMAIN and the set encoding, 32 bytes. */
export function hashValidatorSet(s: ValidatorSet): Uint8Array {
  return shake256(
    concat([textEncoder.encode(VALIDATOR_SET_HASH_DOMAIN), encodeValidatorSet(s)]),
    HASH_SIZE,
  );
}

export function encodeSignedCheckpoint(sc: SignedCheckpoint): Uint8Array {
  validateSignedCheckpoint(sc);
  const parts: Uint8Array[] = [
    u8(ENCODING_VERSION),
    encodeCheckpoint(sc.checkpoint),
    u16(sc.signatures.length),
  ];
  for (const s of sc.signatures) parts.push(s.validatorAddress, s.signature);
  if (sc.nextValidatorSet) {
    parts.push(u8(1), encodeValidatorSet(sc.nextValidatorSet));
  } else {
    parts.push(u8(0));
  }
  return concat(parts);
}

// ---------------------------------------------------------------------------
// decoders (strict: any deviation from the canonical encoding is MALFORMED)

function readVersion(r: Reader, what: string): void {
  if (r.u8(`${what} version`) !== ENCODING_VERSION) fail("MALFORMED", `unknown ${what} version`);
}

function readCheckpoint(r: Reader): Checkpoint {
  readVersion(r, "checkpoint");
  const n = r.u8("chain id length");
  if (n < 1 || n > MAX_CHAIN_ID_LENGTH) fail("MALFORMED", "chain id must be 1 to 64 characters");
  const idBytes = r.take(n, "chain id");
  let chainId = "";
  for (const b of idBytes) {
    if (b < 0x21 || b > 0x7e) fail("MALFORMED", "chain id must be printable ASCII without spaces");
    chainId += String.fromCharCode(b);
  }
  const c: Checkpoint = {
    chainId,
    epoch: r.u64("epoch"),
    height: r.u64("height"),
    time: r.u64("time"),
    headerHash: r.take(HASH_SIZE, "header hash"),
    appHash: r.take(HASH_SIZE, "app hash"),
    validatorSetHash: r.take(HASH_SIZE, "validator set hash"),
    nextValidatorSetHash: r.take(HASH_SIZE, "next validator set hash"),
  };
  return c;
}

function readValidatorSet(r: Reader): ValidatorSet {
  readVersion(r, "validator set");
  const count = r.u16("validator count");
  if (count < 1 || count > MAX_VALIDATORS) {
    fail("MALFORMED", `a validator set has 1 to ${MAX_VALIDATORS} validators`);
  }
  const validators: Validator[] = [];
  for (let i = 0; i < count; i++) {
    validators.push({
      address: r.take(ADDRESS_SIZE, "validator address"),
      power: r.u64("validator power"),
      publicKey: r.take(ML_DSA_87_PUBLIC_KEY_SIZE, "validator public key"),
    });
  }
  const s = { validators };
  validateValidatorSet(s);
  return s;
}

export function decodeCheckpoint(bytes: Uint8Array): Checkpoint {
  const r = new Reader(bytes);
  const c = readCheckpoint(r);
  r.end();
  return c;
}

export function decodeValidatorSet(bytes: Uint8Array): ValidatorSet {
  const r = new Reader(bytes);
  const s = readValidatorSet(r);
  r.end();
  return s;
}

export function decodeSignedCheckpoint(bytes: Uint8Array): SignedCheckpoint {
  const r = new Reader(bytes);
  readVersion(r, "signed checkpoint");
  const checkpoint = readCheckpoint(r);
  const count = r.u16("signature count");
  if (count > MAX_VALIDATORS) fail("MALFORMED", `at most ${MAX_VALIDATORS} signatures`);
  const signatures: CheckpointSignature[] = [];
  for (let i = 0; i < count; i++) {
    signatures.push({
      validatorAddress: r.take(ADDRESS_SIZE, "signer address"),
      signature: r.take(ML_DSA_87_SIGNATURE_SIZE, "signature"),
    });
  }
  const flag = r.u8("next validator set flag");
  if (flag > 1) fail("MALFORMED", "next validator set flag must be 0 or 1");
  const sc: SignedCheckpoint = { checkpoint, signatures };
  if (flag === 1) sc.nextValidatorSet = readValidatorSet(r);
  r.end();
  validateSignedCheckpoint(sc);
  return sc;
}
