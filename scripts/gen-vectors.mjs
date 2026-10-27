#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic checkpoint-chain simulator. Writes vectors/pq-light-client-v1.json.
//
//   (cd ts && pnpm install --frozen-lockfile && pnpm build) && node scripts/gen-vectors.mjs
//
// Every key comes from a fixed test seed and ML-DSA-87 signing is
// deterministic (FIPS 204), so the output is identical on every run.
// The keys are public test keys: never use them for anything else.

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const lc = await import(new URL("../ts/dist/index.js", import.meta.url).href);
const pqc = await import(new URL("../ts/node_modules/@qorechain/pqc/src/index.js", import.meta.url).href);
const { mldsa87, shake256 } = pqc;

const enc = new TextEncoder();
const hex = (b) => Buffer.from(b).toString("hex");
const h32 = (label) => shake256(enc.encode(`qorechain-pqlc-sim|${label}`), 32);

const T0 = 1_800_000_000n; // fixed simulated start time, Unix seconds
const EPOCH_SECONDS = 3_600n;
const TRUSTING_PERIOD = 1_209_600n; // 14 days
const MAX_CLOCK_DRIFT = 10n;

// ---------------------------------------------------------------------------
// keys and sets

const keyCache = new Map();
function key(label, i) {
  const id = `${label}|${i}`;
  if (!keyCache.has(id)) {
    const seed = shake256(enc.encode(`qorechain-pqlc-test-seed-v1|${id}`), 32);
    const { publicKey, secretKey } = mldsa87.keygen(seed);
    const address = shake256(enc.encode(`qorechain-pqlc-test-address-v1|${id}`), 20);
    keyCache.set(id, { id, seed, publicKey, secretKey, address });
  }
  return keyCache.get(id);
}

function makeSet(members) {
  // members: [[key, power], ...]
  const validators = members
    .map(([k, power]) => ({ address: k.address, power: BigInt(power), publicKey: k.publicKey }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.address), Buffer.from(b.address)));
  return { validators };
}

const sets = {};
const setHash = {};
function defineSet(id, members) {
  const s = makeSet(members);
  sets[id] = s;
  setHash[id] = lc.hashValidatorSet(s);
  return s;
}

// ---------------------------------------------------------------------------
// checkpoints

const checkpoints = {};
function cp({ chainId, epoch, height, set, next, salt = "" }) {
  const e = BigInt(epoch);
  return {
    chainId,
    epoch: e,
    height: BigInt(height),
    time: T0 + e * EPOCH_SECONDS,
    headerHash: h32(`header|${chainId}|${height}${salt}`),
    appHash: h32(`app|${chainId}|${height}${salt}`),
    validatorSetHash: setHash[set],
    nextValidatorSetHash: setHash[next],
  };
}

function sign(checkpoint, signers, nextSetId) {
  const signatures = signers
    .map((k) => ({ validatorAddress: k.address, signature: lc.signCheckpoint(k.secretKey, checkpoint) }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.validatorAddress), Buffer.from(b.validatorAddress)));
  const sc = { checkpoint, signatures };
  if (nextSetId) sc.nextValidatorSet = sets[nextSetId];
  return sc;
}

function define(id, sc, encodedOverride) {
  const encoded = encodedOverride ?? lc.encodeSignedCheckpoint(sc);
  checkpoints[id] = {
    encoded: hex(encoded),
    signBytes: hex(lc.encodeCheckpointSignBytes(sc.checkpoint)),
    epoch: sc.checkpoint.epoch.toString(),
    height: sc.checkpoint.height.toString(),
    signers: sc.signatures.length,
  };
  return sc;
}

// ---------------------------------------------------------------------------
// 4-validator scenario: powers 100, 100, 50, 50 (total 300)

const CHAIN = "qorechain-sim";
const K = [0, 1, 2, 3, 4].map((i) => key("v4", i));
defineSet("A4", [[K[0], 100], [K[1], 100], [K[2], 50], [K[3], 50]]);
// Rotation: K3 leaves, K4 joins with power 60 (total 310).
defineSet("B4", [[K[0], 100], [K[1], 100], [K[2], 50], [K[4], 60]]);

const c4 = {
  e0: cp({ chainId: CHAIN, epoch: 0, height: 1000, set: "A4", next: "A4" }),
  e1: cp({ chainId: CHAIN, epoch: 1, height: 2000, set: "A4", next: "A4" }),
  e2: cp({ chainId: CHAIN, epoch: 2, height: 3000, set: "A4", next: "B4" }),
  e3: cp({ chainId: CHAIN, epoch: 3, height: 4000, set: "B4", next: "B4" }),
};
define("c4-e0-root", sign(c4.e0, []));
const s4e1 = define("c4-e1", sign(c4.e1, [K[0], K[1], K[2], K[3]]));
define("c4-e2-rotate", sign(c4.e2, [K[0], K[1], K[2]], "B4"));
define("c4-e3", sign(c4.e3, [K[0], K[1], K[4]]));

// Invalid or adversarial variants.
define("c4-e1-two-thirds", sign(c4.e1, [K[0], K[1]])); // 200 of 300, exactly 2/3
{
  const tampered = { ...s4e1, checkpoint: { ...c4.e1, height: 2001n } };
  define("c4-e1-tampered-height", tampered);
}
{
  const sigs = s4e1.signatures.map((s) => ({ ...s, signature: Uint8Array.from(s.signature) }));
  sigs[1].signature[100] ^= 0x01;
  define("c4-e1-flipped-signature", { ...s4e1, signatures: sigs });
}
define(
  "c4-e1-wrong-chain",
  sign({ ...c4.e1, chainId: "qorechain-sim-other" }, [K[0], K[1], K[2], K[3]]),
);
define("c4-e3-removed-signer", sign(c4.e3, [K[0], K[1], K[4], K[3]]));
define(
  "c4-e3-old-set",
  sign(cp({ chainId: CHAIN, epoch: 3, height: 4000, set: "A4", next: "A4" }), [K[0], K[1], K[2], K[3]]),
);
{
  // Names B4 as the next set but carries A4.
  const sc = sign(c4.e2, [K[0], K[1], K[2]]);
  sc.nextValidatorSet = sets.A4;
  define("c4-e2-wrong-next-set", sc);
}
define(
  "c4-e1-other-set",
  sign(cp({ chainId: CHAIN, epoch: 1, height: 2000, set: "B4", next: "B4" }), [K[0], K[1], K[2], K[4]]),
);
const c4e1Conflict = cp({ chainId: CHAIN, epoch: 1, height: 2000, set: "A4", next: "A4", salt: "|fork" });
define("c4-e1-conflict", sign(c4e1Conflict, [K[0], K[1], K[3]]));
define("c4-e1-conflict-weak", sign(c4e1Conflict, [K[0], K[1]]));
define(
  "c4-e2-height-not-increasing",
  sign(cp({ chainId: CHAIN, epoch: 2, height: 1000, set: "A4", next: "A4" }), [K[0], K[1], K[2], K[3]]),
);

// ---------------------------------------------------------------------------
// 21-validator scenario: powers 50, 55, ..., 150 (total 2100)

const CHAIN21 = "qorechain-sim-21";
const L = Array.from({ length: 24 }, (_, i) => key("v21", i));
const pow21 = (i) => 50 + 5 * i;
defineSet("C21", L.slice(0, 21).map((k, i) => [k, pow21(i)]));
// Rotation: L18, L19, L20 leave; L21, L22, L23 join with power 100 each (total 1965).
defineSet("D21", [
  ...L.slice(0, 18).map((k, i) => [k, pow21(i)]),
  [L[21], 100],
  [L[22], 100],
  [L[23], 100],
]);

const c21 = {
  e0: cp({ chainId: CHAIN21, epoch: 0, height: 10000, set: "C21", next: "C21" }),
  e1: cp({ chainId: CHAIN21, epoch: 1, height: 11000, set: "C21", next: "C21" }),
  e2: cp({ chainId: CHAIN21, epoch: 2, height: 12000, set: "C21", next: "D21" }),
  e3: cp({ chainId: CHAIN21, epoch: 3, height: 13000, set: "D21", next: "D21" }),
};
const top15 = L.slice(6, 21); // powers 80..150, sum 1725
const dSigners = [...L.slice(5, 18), L[21], L[22], L[23]]; // D21 without L0..L4, sum 1665
define("c21-e0-root", sign(c21.e0, []));
const s21e1 = define("c21-e1", sign(c21.e1, top15));
define("c21-e2-rotate", sign(c21.e2, top15, "D21"));
define("c21-e3", sign(c21.e3, dSigners));
define("c21-e1-two-thirds", sign(c21.e1, L.slice(0, 16))); // 1400 of 2100, exactly 2/3
define("c21-e1-tampered-height", { ...s21e1, checkpoint: { ...c21.e1, height: 11001n } });
define("c21-e3-removed-signer", sign(c21.e3, [...dSigners, L[18]]));
define(
  "c21-e1-conflict",
  sign(
    cp({ chainId: CHAIN21, epoch: 1, height: 11000, set: "C21", next: "C21", salt: "|fork" }),
    [...L.slice(0, 6), ...L.slice(11, 21)], // 375 + 1275 = 1650
  ),
);

// ---------------------------------------------------------------------------
// verification cases: start from a trust root, apply steps in order; a
// failed step leaves the state unchanged.

const trustRoots = {
  "root4": { checkpoint: "c4-e0-root", validatorSet: "A4", nextValidatorSet: "A4" },
  "root21": { checkpoint: "c21-e0-root", validatorSet: "C21", nextValidatorSet: "C21" },
};
for (const r of Object.values(trustRoots)) {
  r.trustingPeriod = TRUSTING_PERIOD.toString();
  r.maxClockDrift = MAX_CLOCK_DRIFT.toString();
}

const decodedCache = new Map();
function decoded(id) {
  if (!decodedCache.has(id)) {
    decodedCache.set(id, lc.decodeSignedCheckpoint(Buffer.from(checkpoints[id].encoded, "hex")));
  }
  return decodedCache.get(id);
}

function timeOf(id) {
  return decoded(id).checkpoint.time;
}

function rootState(rootId) {
  const r = trustRoots[rootId];
  const sc = decoded(r.checkpoint);
  return lc.newTrustedState({
    checkpoint: sc.checkpoint,
    signatures: sc.signatures,
    validatorSet: sets[r.validatorSet],
    nextValidatorSet: sets[r.nextValidatorSet],
    trustingPeriod: BigInt(r.trustingPeriod),
    maxClockDrift: BigInt(r.maxClockDrift),
  });
}

function signBytesHex(c) {
  return hex(lc.encodeCheckpointSignBytes(c));
}

const cases = [];
// steps: [checkpointId, nowOffsetFromCheckpointTime?] ; expected results are
// computed by the reference implementation and must match intent below.
function chainCase(name, rootId, steps) {
  let state = rootState(rootId);
  const out = [];
  for (const step of steps) {
    const [id, intent, nowOverride] = step;
    const now = nowOverride ?? timeOf(id) + 5n;
    const rec = { checkpoint: id, now: now.toString() };
    try {
      state = lc.verifyCheckpoint(state, decoded(id), now);
      rec.expect = {
        ok: true,
        epoch: state.checkpoint.epoch.toString(),
        height: state.checkpoint.height.toString(),
        validatorSetHash: hex(lc.hashValidatorSet(state.validatorSet)),
        nextValidatorSetHash: hex(lc.hashValidatorSet(state.nextValidatorSet)),
      };
      if (intent !== "ok") throw new Error(`${name}: ${id} expected ${intent}, got ok`);
    } catch (e) {
      if (!(e instanceof lc.PqLightClientError)) throw e;
      if (intent !== e.code) throw new Error(`${name}: ${id} expected ${intent}, got ${e.code} (${e.detail})`);
      rec.expect = { ok: false, error: e.code };
      if (e.misbehaviour) {
        rec.expect.misbehaviour = {
          firstSignBytes: signBytesHex(e.misbehaviour.first.checkpoint),
          secondSignBytes: signBytesHex(e.misbehaviour.second.checkpoint),
          doubleSigners: e.misbehaviour.doubleSigners.map(hex),
          doubleSignedPower: e.misbehaviour.doubleSignedPower.toString(),
        };
      }
    }
    out.push(rec);
  }
  cases.push({ name, type: "chain", trustRoot: rootId, steps: out });
}

const e1Time = timeOf("c4-e1");
chainCase("4 validators: valid chain with a set rotation", "root4", [
  ["c4-e1", "ok"],
  ["c4-e2-rotate", "ok"],
  ["c4-e3", "ok"],
]);
chainCase("4 validators: skips epochs while the set is unchanged", "root4", [
  ["c4-e2-rotate", "ok"],
  ["c4-e3", "ok"],
]);
chainCase("4 validators: cannot skip over a set rotation", "root4", [["c4-e3", "SET_MISMATCH"]]);
chainCase("4 validators: exactly two thirds of the power is not enough", "root4", [
  ["c4-e1-two-thirds", "INSUFFICIENT_POWER"],
  ["c4-e1", "ok"],
]);
chainCase("4 validators: tampered height", "root4", [["c4-e1-tampered-height", "BAD_SIGNATURE"]]);
chainCase("4 validators: one flipped signature byte", "root4", [["c4-e1-flipped-signature", "BAD_SIGNATURE"]]);
chainCase("4 validators: wrong chain id", "root4", [["c4-e1-wrong-chain", "CHAIN_ID_MISMATCH"]]);
chainCase("4 validators: signature by a removed validator", "root4", [
  ["c4-e1", "ok"],
  ["c4-e2-rotate", "ok"],
  ["c4-e3-removed-signer", "UNKNOWN_VALIDATOR"],
  ["c4-e3", "ok"],
]);
chainCase("4 validators: the outgoing set cannot sign after the rotation", "root4", [
  ["c4-e2-rotate", "ok"],
  ["c4-e3-old-set", "SET_MISMATCH"],
]);
chainCase("4 validators: next set does not match its hash", "root4", [["c4-e2-wrong-next-set", "SET_MISMATCH"]]);
chainCase("4 validators: signed by a set the trusted state does not name", "root4", [
  ["c4-e1-other-set", "SET_MISMATCH"],
]);
chainCase("4 validators: conflicting checkpoints for one epoch", "root4", [
  ["c4-e1", "ok"],
  ["c4-e1-conflict", "CONFLICTING_CHECKPOINT"],
]);
chainCase("4 validators: a conflicting checkpoint without quorum is only rejected", "root4", [
  ["c4-e1", "ok"],
  ["c4-e1-conflict-weak", "INSUFFICIENT_POWER"],
]);
chainCase("4 validators: replay of the trusted checkpoint", "root4", [
  ["c4-e1", "ok"],
  ["c4-e1", "NOT_NEWER"],
]);
chainCase("4 validators: height must increase", "root4", [["c4-e2-height-not-increasing", "NOT_NEWER"]]);
chainCase("4 validators: trust expires after the trusting period", "root4", [
  ["c4-e1", "TRUST_EXPIRED", T0 + TRUSTING_PERIOD],
  ["c4-e1", "ok", T0 + TRUSTING_PERIOD - 1n],
]);
chainCase("4 validators: checkpoint from the future", "root4", [
  ["c4-e1", "FUTURE_CHECKPOINT", e1Time - MAX_CLOCK_DRIFT - 1n],
  ["c4-e1", "ok", e1Time - MAX_CLOCK_DRIFT],
]);
chainCase("21 validators: valid chain with a set rotation (three validators replaced)", "root21", [
  ["c21-e1", "ok"],
  ["c21-e2-rotate", "ok"],
  ["c21-e3", "ok"],
]);
chainCase("21 validators: exactly two thirds of the power is not enough", "root21", [
  ["c21-e1-two-thirds", "INSUFFICIENT_POWER"],
  ["c21-e1", "ok"],
]);
chainCase("21 validators: tampered height", "root21", [["c21-e1-tampered-height", "BAD_SIGNATURE"]]);
chainCase("21 validators: signature by a removed validator", "root21", [
  ["c21-e1", "ok"],
  ["c21-e2-rotate", "ok"],
  ["c21-e3-removed-signer", "UNKNOWN_VALIDATOR"],
]);
chainCase("21 validators: conflicting checkpoints for one epoch", "root21", [
  ["c21-e1", "ok"],
  ["c21-e1-conflict", "CONFLICTING_CHECKPOINT"],
]);

// ---------------------------------------------------------------------------
// detectMisbehaviour cases

function misbehaviourCase(name, setId, a, b, expectFound) {
  const m = lc.detectMisbehaviour(sets[setId], decoded(a), decoded(b));
  if (Boolean(m) !== expectFound) throw new Error(`${name}: expected found=${expectFound}`);
  cases.push({
    name,
    type: "misbehaviour",
    validatorSet: setId,
    a,
    b,
    expect: m
      ? {
          found: true,
          chainId: m.chainId,
          epoch: m.epoch.toString(),
          firstSignBytes: signBytesHex(m.first.checkpoint),
          secondSignBytes: signBytesHex(m.second.checkpoint),
          doubleSigners: m.doubleSigners.map(hex),
          doubleSignedPower: m.doubleSignedPower.toString(),
        }
      : { found: false },
  });
}

misbehaviourCase("4 validators: two checkpoints for epoch 1, both with quorum", "A4", "c4-e1", "c4-e1-conflict", true);
misbehaviourCase("4 validators: argument order does not matter", "A4", "c4-e1-conflict", "c4-e1", true);
misbehaviourCase("4 validators: the same checkpoint twice", "A4", "c4-e1", "c4-e1", false);
misbehaviourCase("4 validators: same content, different signer subsets", "A4", "c4-e1", "c4-e1-two-thirds", false);
misbehaviourCase("4 validators: different epochs", "A4", "c4-e1", "c4-e2-rotate", false);
misbehaviourCase("4 validators: one side without quorum", "A4", "c4-e1", "c4-e1-conflict-weak", false);
misbehaviourCase("4 validators: checked against the wrong set", "B4", "c4-e1", "c4-e1-conflict", false);
misbehaviourCase("21 validators: two checkpoints for epoch 1, both with quorum", "C21", "c21-e1", "c21-e1-conflict", true);

// ---------------------------------------------------------------------------
// decoder cases

function setU16(buf, off, v) {
  buf[off] = (v >> 8) & 0xff;
  buf[off + 1] = v & 0xff;
}

function decodeCase(name, object, bytes, expectOk) {
  const fn = {
    checkpoint: lc.decodeCheckpoint,
    validatorSet: lc.decodeValidatorSet,
    signedCheckpoint: lc.decodeSignedCheckpoint,
  }[object];
  let ok = true;
  try {
    fn(bytes);
  } catch (e) {
    if (!(e instanceof lc.PqLightClientError) || e.code !== "MALFORMED") throw e;
    ok = false;
  }
  if (ok !== expectOk) throw new Error(`${name}: expected ok=${expectOk}`);
  cases.push({ name, type: "decode", object, encoded: hex(bytes), expect: expectOk ? { ok: true } : { ok: false, error: "MALFORMED" } });
}

const e1Bytes = Buffer.from(checkpoints["c4-e1"].encoded, "hex");
const e2Bytes = Buffer.from(checkpoints["c4-e2-rotate"].encoded, "hex");
const cpBytes = lc.encodeCheckpoint(c4.e1);
const setBytes = lc.encodeValidatorSet(sets.A4);
const cpLen = cpBytes.length;
const sigOff = 1 + cpLen + 2; // first signature entry
const SIG_ENTRY = 20 + 4627;
const VAL_ENTRY = 20 + 8 + 2592;

decodeCase("checkpoint: canonical encoding", "checkpoint", cpBytes, true);
decodeCase("checkpoint: truncated", "checkpoint", cpBytes.slice(0, cpLen - 1), false);
decodeCase("checkpoint: trailing byte", "checkpoint", Buffer.concat([cpBytes, Buffer.of(0)]), false);
{
  const b = Buffer.from(cpBytes);
  b[0] = 2;
  decodeCase("checkpoint: unknown version", "checkpoint", b, false);
}
{
  const b = Buffer.concat([Buffer.of(1, 0), Buffer.from(cpBytes.slice(2 + CHAIN.length))]);
  decodeCase("checkpoint: empty chain id", "checkpoint", b, false);
}
{
  const b = Buffer.from(cpBytes);
  b[2 + 4] = 0x20; // a space inside the chain id
  decodeCase("checkpoint: chain id with a space", "checkpoint", b, false);
}
decodeCase("validator set: canonical encoding", "validatorSet", setBytes, true);
decodeCase("validator set: no validators", "validatorSet", Buffer.of(1, 0, 0), false);
decodeCase("validator set: 257 validators announced", "validatorSet", Buffer.of(1, 1, 1), false);
{
  const b = Buffer.from(setBytes);
  const first = Buffer.from(b.subarray(3, 3 + VAL_ENTRY));
  b.copy(b, 3, 3 + VAL_ENTRY, 3 + 2 * VAL_ENTRY);
  first.copy(b, 3 + VAL_ENTRY);
  decodeCase("validator set: not sorted by address", "validatorSet", b, false);
}
{
  const b = Buffer.from(setBytes);
  b.fill(0, 3 + 20, 3 + 28);
  decodeCase("validator set: zero power", "validatorSet", b, false);
}
{
  const one = makeSet([[K[0], (1n << 60n) - 1n], [K[1], 1n]]);
  const parts = [Buffer.of(1, 0, 2)];
  for (const v of one.validators) {
    const p = Buffer.alloc(8);
    p.writeBigUInt64BE(v.power);
    parts.push(Buffer.from(v.address), p, Buffer.from(v.publicKey));
  }
  decodeCase("validator set: total power above 2^60 - 1", "validatorSet", Buffer.concat(parts), false);
}
decodeCase("signed checkpoint: canonical encoding with a next set", "signedCheckpoint", e2Bytes, true);
decodeCase("signed checkpoint: truncated", "signedCheckpoint", e1Bytes.subarray(0, e1Bytes.length - 1), false);
decodeCase("signed checkpoint: trailing byte", "signedCheckpoint", Buffer.concat([e1Bytes, Buffer.of(0)]), false);
{
  const b = Buffer.from(e1Bytes);
  b[0] = 2;
  decodeCase("signed checkpoint: unknown version", "signedCheckpoint", b, false);
}
{
  const b = Buffer.from(e1Bytes);
  const first = Buffer.from(b.subarray(sigOff, sigOff + SIG_ENTRY));
  b.copy(b, sigOff, sigOff + SIG_ENTRY, sigOff + 2 * SIG_ENTRY);
  first.copy(b, sigOff + SIG_ENTRY);
  decodeCase("signed checkpoint: signatures not sorted", "signedCheckpoint", b, false);
}
{
  const b = Buffer.from(e1Bytes);
  b.copy(b, sigOff + SIG_ENTRY, sigOff, sigOff + SIG_ENTRY);
  decodeCase("signed checkpoint: duplicate signer", "signedCheckpoint", b, false);
}
{
  const b = Buffer.from(e1Bytes);
  setU16(b, 1 + cpLen, 257);
  decodeCase("signed checkpoint: 257 signatures announced", "signedCheckpoint", b, false);
}
{
  const b = Buffer.concat([e1Bytes.subarray(0, e1Bytes.length - 1), Buffer.of(1), setBytes]);
  decodeCase("signed checkpoint: next set present although unchanged", "signedCheckpoint", b, false);
}
{
  const nextLen = 3 + 4 * VAL_ENTRY;
  const b = Buffer.concat([e2Bytes.subarray(0, e2Bytes.length - nextLen - 1), Buffer.of(0)]);
  decodeCase("signed checkpoint: next set missing although it changes", "signedCheckpoint", b, false);
}
{
  const b = Buffer.from(e1Bytes);
  b[b.length - 1] = 2;
  decodeCase("signed checkpoint: next set flag 2", "signedCheckpoint", b, false);
}

// ---------------------------------------------------------------------------
// output

const out = {
  name: "qorechain-pq-light-client-v1",
  description:
    "Shared test vectors for the QoreChain post-quantum light client v1 (draft). Generated by scripts/gen-vectors.mjs from fixed test seeds; the keys are public test keys. All 64-bit integers are decimal strings; all bytes are lowercase hex.",
  constants: {
    checkpointSignDomain: lc.CHECKPOINT_SIGN_DOMAIN,
    validatorSetHashDomain: lc.VALIDATOR_SET_HASH_DOMAIN,
    encodingVersion: lc.ENCODING_VERSION,
    publicKeySize: lc.ML_DSA_87_PUBLIC_KEY_SIZE,
    signatureSize: lc.ML_DSA_87_SIGNATURE_SIZE,
    maxValidators: lc.MAX_VALIDATORS,
    maxTotalPower: lc.MAX_TOTAL_POWER.toString(),
  },
  validatorSets: Object.fromEntries(
    Object.entries(sets).map(([id, s]) => [
      id,
      {
        encoded: hex(lc.encodeValidatorSet(s)),
        hash: hex(setHash[id]),
        validators: s.validators.length,
        totalPower: s.validators.reduce((t, v) => t + v.power, 0n).toString(),
      },
    ]),
  ),
  signedCheckpoints: checkpoints,
  trustRoots,
  cases,
};

const file = join(root, "vectors", "pq-light-client-v1.json");
writeFileSync(file, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${file}: ${cases.length} cases, ${Object.keys(checkpoints).length} signed checkpoints`);
