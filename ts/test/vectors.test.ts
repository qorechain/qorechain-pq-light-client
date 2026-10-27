// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CHECKPOINT_SIGN_DOMAIN,
  PqLightClientError,
  VALIDATOR_SET_HASH_DOMAIN,
  decodeCheckpoint,
  decodeSignedCheckpoint,
  decodeValidatorSet,
  detectMisbehaviour,
  encodeCheckpoint,
  encodeCheckpointSignBytes,
  encodeSignedCheckpoint,
  encodeValidatorSet,
  hashValidatorSet,
  newTrustedState,
  verifyCheckpoint,
  type TrustedState,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const v: any = JSON.parse(readFileSync(join(here, "..", "..", "vectors", "pq-light-client-v1.json"), "utf8"));

const fromHex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const sets = Object.fromEntries(
  Object.entries(v.validatorSets).map(([id, s]) => [id, decodeValidatorSet(fromHex((s as { encoded: string }).encoded))]),
);
const signed = (id: string) => decodeSignedCheckpoint(fromHex(v.signedCheckpoints[id].encoded));

function root(id: string): TrustedState {
  const r = v.trustRoots[id];
  const sc = signed(r.checkpoint);
  return newTrustedState({
    checkpoint: sc.checkpoint,
    signatures: sc.signatures,
    validatorSet: sets[r.validatorSet]!,
    nextValidatorSet: sets[r.nextValidatorSet]!,
    trustingPeriod: BigInt(r.trustingPeriod),
    maxClockDrift: BigInt(r.maxClockDrift),
  });
}

describe("vectors: constants", () => {
  it("match the implementation", () => {
    expect(v.constants.checkpointSignDomain).toBe(CHECKPOINT_SIGN_DOMAIN);
    expect(v.constants.validatorSetHashDomain).toBe(VALIDATOR_SET_HASH_DOMAIN);
  });
});

describe("vectors: validator sets", () => {
  for (const [id, s] of Object.entries(v.validatorSets) as [string, { encoded: string; hash: string }][]) {
    it(`${id} round-trips and hashes`, () => {
      const set = decodeValidatorSet(fromHex(s.encoded));
      expect(toHex(encodeValidatorSet(set))).toBe(s.encoded);
      expect(toHex(hashValidatorSet(set))).toBe(s.hash);
    });
  }
});

describe("vectors: signed checkpoints", () => {
  for (const [id, c] of Object.entries(v.signedCheckpoints) as [string, { encoded: string; signBytes: string }][]) {
    it(`${id} round-trips and has the expected sign-bytes`, () => {
      const sc = decodeSignedCheckpoint(fromHex(c.encoded));
      expect(toHex(encodeSignedCheckpoint(sc))).toBe(c.encoded);
      expect(toHex(encodeCheckpointSignBytes(sc.checkpoint))).toBe(c.signBytes);
    });
  }
});

describe("vectors: cases", () => {
  for (const tc of v.cases) {
    it(`${tc.type}: ${tc.name}`, () => {
      if (tc.type === "chain") {
        let state = root(tc.trustRoot);
        for (const step of tc.steps) {
          const sc = signed(step.checkpoint);
          if (step.expect.ok) {
            state = verifyCheckpoint(state, sc, BigInt(step.now));
            expect(state.checkpoint.epoch.toString()).toBe(step.expect.epoch);
            expect(state.checkpoint.height.toString()).toBe(step.expect.height);
            expect(toHex(hashValidatorSet(state.validatorSet))).toBe(step.expect.validatorSetHash);
            expect(toHex(hashValidatorSet(state.nextValidatorSet))).toBe(step.expect.nextValidatorSetHash);
          } else {
            let err: unknown;
            try {
              verifyCheckpoint(state, sc, BigInt(step.now));
            } catch (e) {
              err = e;
            }
            expect(err).toBeInstanceOf(PqLightClientError);
            const pe = err as PqLightClientError;
            expect(pe.code).toBe(step.expect.error);
            if (step.expect.misbehaviour) {
              const m = pe.misbehaviour!;
              expect(toHex(encodeCheckpointSignBytes(m.first.checkpoint))).toBe(step.expect.misbehaviour.firstSignBytes);
              expect(toHex(encodeCheckpointSignBytes(m.second.checkpoint))).toBe(step.expect.misbehaviour.secondSignBytes);
              expect(m.doubleSigners.map(toHex)).toEqual(step.expect.misbehaviour.doubleSigners);
              expect(m.doubleSignedPower.toString()).toBe(step.expect.misbehaviour.doubleSignedPower);
            }
          }
        }
      } else if (tc.type === "misbehaviour") {
        const m = detectMisbehaviour(sets[tc.validatorSet]!, signed(tc.a), signed(tc.b));
        if (!tc.expect.found) {
          expect(m).toBeNull();
          return;
        }
        expect(m).not.toBeNull();
        expect(m!.chainId).toBe(tc.expect.chainId);
        expect(m!.epoch.toString()).toBe(tc.expect.epoch);
        expect(toHex(encodeCheckpointSignBytes(m!.first.checkpoint))).toBe(tc.expect.firstSignBytes);
        expect(toHex(encodeCheckpointSignBytes(m!.second.checkpoint))).toBe(tc.expect.secondSignBytes);
        expect(m!.doubleSigners.map(toHex)).toEqual(tc.expect.doubleSigners);
        expect(m!.doubleSignedPower.toString()).toBe(tc.expect.doubleSignedPower);
      } else if (tc.type === "decode") {
        const bytes = fromHex(tc.encoded);
        const [dec, enc] = {
          checkpoint: [decodeCheckpoint, encodeCheckpoint],
          validatorSet: [decodeValidatorSet, encodeValidatorSet],
          signedCheckpoint: [decodeSignedCheckpoint, encodeSignedCheckpoint],
        }[tc.object as "checkpoint"] as [(b: Uint8Array) => unknown, (x: unknown) => Uint8Array];
        if (tc.expect.ok) {
          expect(toHex(enc(dec(bytes)))).toBe(tc.encoded);
        } else {
          expect(() => dec(bytes)).toThrowError(PqLightClientError);
          try {
            dec(bytes);
          } catch (e) {
            expect((e as PqLightClientError).code).toBe("MALFORMED");
          }
        }
      } else {
        throw new Error(`unknown case type ${tc.type}`);
      }
    });
  }
});
