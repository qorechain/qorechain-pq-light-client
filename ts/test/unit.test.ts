// SPDX-License-Identifier: Apache-2.0
import { mldsa87, shake256 } from "@qorechain/pqc";
import { describe, expect, it } from "vitest";
import {
  CHECKPOINT_SIGN_DOMAIN,
  PqLightClientError,
  REQUIRES_CHAIN_SUPPORT_MESSAGE,
  chainCheckpointSource,
  decodeSignedCheckpoint,
  encodeCheckpoint,
  encodeCheckpointSignBytes,
  encodeSignedCheckpoint,
  fetchCheckpoint,
  hashValidatorSet,
  newTrustedState,
  signCheckpoint,
  verifyCheckpoint,
  type Checkpoint,
  type ValidatorSet,
} from "../src/index.js";

const enc = new TextEncoder();
const keys = [0, 1, 2].map((i) => {
  const kp = mldsa87.keygen(shake256(enc.encode(`unit-seed-${i}`), 32));
  return { ...kp, address: shake256(enc.encode(`unit-addr-${i}`), 20) };
});
const set: ValidatorSet = {
  validators: keys
    .map((k) => ({ address: k.address, power: 10n, publicKey: k.publicKey }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.address), Buffer.from(b.address))),
};
const setHash = hashValidatorSet(set);

function checkpoint(epoch: bigint, overrides: Partial<Checkpoint> = {}): Checkpoint {
  return {
    chainId: "unit-chain",
    epoch,
    height: 100n * (epoch + 1n),
    time: 1_000n + 60n * epoch,
    headerHash: new Uint8Array(32).fill(1),
    appHash: new Uint8Array(32).fill(Number(epoch) + 2),
    validatorSetHash: setHash,
    nextValidatorSetHash: setHash,
    ...overrides,
  };
}

function signAll(c: Checkpoint, signers = keys) {
  return {
    checkpoint: c,
    signatures: signers
      .map((k) => ({ validatorAddress: k.address, signature: signCheckpoint(k.secretKey, c) }))
      .sort((a, b) => Buffer.compare(Buffer.from(a.validatorAddress), Buffer.from(b.validatorAddress))),
  };
}

const rootState = () =>
  newTrustedState({
    checkpoint: checkpoint(0n),
    validatorSet: set,
    nextValidatorSet: set,
    trustingPeriod: 3_600n,
    maxClockDrift: 5n,
  });

describe("encoding", () => {
  it("sign-bytes are the domain followed by the checkpoint encoding", () => {
    const c = checkpoint(1n);
    const sb = encodeCheckpointSignBytes(c);
    expect(Buffer.from(sb.subarray(0, CHECKPOINT_SIGN_DOMAIN.length)).toString()).toBe(CHECKPOINT_SIGN_DOMAIN);
    expect(Buffer.from(sb.subarray(CHECKPOINT_SIGN_DOMAIN.length))).toEqual(Buffer.from(encodeCheckpoint(c)));
    expect(encodeCheckpoint(c).length).toBe(154 + c.chainId.length);
  });

  it("a signed checkpoint round-trips", () => {
    const sc = signAll(checkpoint(1n));
    const bytes = encodeSignedCheckpoint(sc);
    expect(bytes.length).toBe(1 + 154 + 10 + 2 + 3 * (20 + 4627) + 1);
    expect(encodeSignedCheckpoint(decodeSignedCheckpoint(bytes))).toEqual(bytes);
  });

  it("rejects a 4,628-byte signature", () => {
    const sc = signAll(checkpoint(1n));
    sc.signatures[0]!.signature = new Uint8Array(4628);
    expect(() => encodeSignedCheckpoint(sc)).toThrowError(/MALFORMED/);
  });

  it("rejects a chain id longer than 64 characters", () => {
    expect(() => encodeCheckpoint(checkpoint(1n, { chainId: "x".repeat(65) }))).toThrowError(/MALFORMED/);
  });
});

describe("verifyCheckpoint", () => {
  it("accepts a checkpoint signed by all validators and advances the state", () => {
    const s = verifyCheckpoint(rootState(), signAll(checkpoint(1n)), 1_061n);
    expect(s.checkpoint.epoch).toBe(1n);
  });

  it("rejects two of three equal validators (exactly 2/3)", () => {
    expect(() => verifyCheckpoint(rootState(), signAll(checkpoint(1n), keys.slice(0, 2)), 1_061n)).toThrowError(
      /INSUFFICIENT_POWER/,
    );
  });

  it("returns a typed error with a stable code", () => {
    try {
      verifyCheckpoint(rootState(), signAll(checkpoint(1n, { chainId: "other" })), 1_061n);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(PqLightClientError);
      expect((e as PqLightClientError).code).toBe("CHAIN_ID_MISMATCH");
    }
  });

  it("newTrustedState rejects a set that does not match the checkpoint", () => {
    expect(() =>
      newTrustedState({
        checkpoint: checkpoint(0n, { nextValidatorSetHash: new Uint8Array(32) }),
        validatorSet: set,
        nextValidatorSet: set,
        trustingPeriod: 1n,
        maxClockDrift: 0n,
      }),
    ).toThrowError(/SET_MISMATCH/);
  });
});

describe("requires chain support (not scheduled)", () => {
  it("fetchCheckpoint fails in a controlled way and makes no request", async () => {
    await expect(fetchCheckpoint("https://rpc.example.invalid", "unit-chain", 1n)).rejects.toMatchObject({
      code: "REQUIRES_CHAIN_SUPPORT",
      detail: REQUIRES_CHAIN_SUPPORT_MESSAGE,
    });
    await expect(chainCheckpointSource("https://rpc.example.invalid").fetchCheckpoint("unit-chain", 1n)).rejects.toThrow(
      "requires chain support (not scheduled)",
    );
  });
});
