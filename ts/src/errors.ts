// SPDX-License-Identifier: Apache-2.0
import type { Misbehaviour } from "./types.js";

/** Stable error codes, identical in the Go, Rust and TypeScript verifiers. */
export type ErrorCode =
  | "MALFORMED"
  | "CHAIN_ID_MISMATCH"
  | "TRUST_EXPIRED"
  | "FUTURE_CHECKPOINT"
  | "NOT_NEWER"
  | "SET_MISMATCH"
  | "UNKNOWN_VALIDATOR"
  | "BAD_SIGNATURE"
  | "INSUFFICIENT_POWER"
  | "CONFLICTING_CHECKPOINT"
  | "REQUIRES_CHAIN_SUPPORT";

/** The message carried by every function that needs the chain to produce checkpoints. */
export const REQUIRES_CHAIN_SUPPORT_MESSAGE = "requires chain support (not scheduled)";

export class PqLightClientError extends Error {
  readonly code: ErrorCode;
  readonly detail: string;
  /** Set when `code` is CONFLICTING_CHECKPOINT. */
  readonly misbehaviour?: Misbehaviour;

  constructor(code: ErrorCode, detail: string, misbehaviour?: Misbehaviour) {
    super(`${code}: ${detail}`);
    this.name = "PqLightClientError";
    this.code = code;
    this.detail = detail;
    if (misbehaviour) this.misbehaviour = misbehaviour;
  }
}

export function fail(code: ErrorCode, detail: string): never {
  throw new PqLightClientError(code, detail);
}
