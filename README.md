# qorechain-pq-light-client

A specification and reference verifiers for a post-quantum light client of QoreChain: validators sign epoch checkpoints with a separate ML-DSA-87 (FIPS 204) key, and a light client follows the checkpoint chain by verifying those signatures only.

> **Requires chain support (not scheduled).** QoreChain does not produce these checkpoints today. Validator consensus keys are ed25519 and IBC uses the standard 07 client. This repository lets the design be reviewed and the verifiers be tested before any chain work is planned.

## Status

| Part | Status |
|---|---|
| Specification ([spec/pq-light-client-v1.md](spec/pq-light-client-v1.md)) | Draft, open for review |
| Go, Rust and TypeScript verifiers | Reference only, tested against simulated checkpoint chains |
| Shared test vectors ([vectors](vectors/README.md)) | Generated, deterministic, passing in all three languages |
| Checkpoint keys, checkpoint signing and storage on QoreChain | Requires chain support (not scheduled) |
| IBC light client type, EVM and Solana verifiers | Design notes only (spec sections 14 and 15) |
| Fetching checkpoints from a node (`fetchCheckpoint`) | Interface only; fails with `REQUIRES_CHAIN_SUPPORT` |

## How it works

1. Each validator registers an ML-DSA-87 **checkpoint key**, separate from its consensus key.
2. At the end of each epoch the validators sign a short checkpoint: chain id, epoch, height, time, header hash, app hash, the hash of the set that signs it and the hash of the set that signs the next one.
3. A light client accepts a checkpoint signed by more than two thirds of the power of the set its last trusted checkpoint named. Set changes are therefore always signed by the outgoing set.
4. Two different checkpoints for one epoch, each with a quorum, are misbehaviour; the verifier returns the evidence.

Per-block consensus is unchanged. Heights inside an epoch stay classical until the next checkpoint; the specification explains why this is preferred over per-block post-quantum signatures (section 12).

Proposed signing domain, to be reserved: `qorechain-pqlc-checkpoint-v1|` (and `qorechain-pqlc-key-pop-v1|` for key registration).

## Packages

| Language | Package | Path |
|---|---|---|
| Go | `github.com/qorechain/qorechain-pq-light-client/go` | [go](go/README.md) |
| Rust | `qorechain-pq-light-client` | [rust](rust/README.md) |
| TypeScript | `@qorechain/pq-light-client` | [ts](ts/README.md) |

All three are built over the `qorechain-pqc` bindings 0.2.3 and expose the same API: `Checkpoint`, `ValidatorSet`, `SignedCheckpoint`, `TrustedState`, `encodeCheckpointSignBytes`, `verifyCheckpoint`, `detectMisbehaviour`, the encoders and decoders, and typed errors with stable codes (`INSUFFICIENT_POWER`, `BAD_SIGNATURE`, `UNKNOWN_VALIDATOR`, `SET_MISMATCH`, `TRUST_EXPIRED`, `CONFLICTING_CHECKPOINT`, ...). Install: `npm install @qorechain/pq-light-client`, `cargo add qorechain-pq-light-client`, `go get github.com/qorechain/qorechain-pq-light-client/go`.

```ts
import { decodeSignedCheckpoint, verifyCheckpoint } from "@qorechain/pq-light-client";

// `trusted` comes from newTrustedState(...) or a previous update.
const next = verifyCheckpoint(trusted, decodeSignedCheckpoint(bytes), BigInt(Math.floor(Date.now() / 1000)));
```

## Quick start

Offline: follow the simulated 21-validator checkpoint chain from the shared vectors (with a validator set rotation at epoch 2). The vector keys are public test keys; nothing touches a QoreChain network.

```bash
mkdir pqlc && cd pqlc && npm init -y && npm pkg set type=module
npm install @qorechain/pq-light-client
curl -sLO https://raw.githubusercontent.com/qorechain/qorechain-pq-light-client/v0.1.0/vectors/pq-light-client-v1.json
```

```js
// follow.mjs: a TypeScript port of the repository's Rust relayer example.
import { readFileSync } from "node:fs";
import {
  PqLightClientError,
  decodeSignedCheckpoint,
  decodeValidatorSet,
  fetchCheckpoint,
  newTrustedState,
  verifyCheckpoint,
} from "@qorechain/pq-light-client";

const v = JSON.parse(readFileSync("pq-light-client-v1.json", "utf8"));
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));

const root = decodeSignedCheckpoint(hex(v.signedCheckpoints["c21-e0-root"].encoded));
const set = decodeValidatorSet(hex(v.validatorSets.C21.encoded));
let state = newTrustedState({
  checkpoint: root.checkpoint,
  signatures: root.signatures,
  validatorSet: set,
  nextValidatorSet: set,
  trustingPeriod: 1_209_600n, // 14 days
  maxClockDrift: 10n,
});

for (const id of ["c21-e1", "c21-e2-rotate", "c21-e3"]) {
  const signed = decodeSignedCheckpoint(hex(v.signedCheckpoints[id].encoded));
  state = verifyCheckpoint(state, signed, signed.checkpoint.time + 5n);
  console.log(`trusted epoch ${state.checkpoint.epoch} at height ${state.checkpoint.height}`);
}

try {
  await fetchCheckpoint("https://rpc.example.invalid", state.checkpoint.chainId, 4n);
} catch (e) {
  if (e instanceof PqLightClientError) console.log("live source:", e.code);
}
```

`node follow.mjs` prints:

```
trusted epoch 1 at height 11000
trusted epoch 2 at height 12000
trusted epoch 3 at height 13000
live source: REQUIRES_CHAIN_SUPPORT
```

The same flow in Rust: `cargo run --example relayer` in [rust](rust/README.md).

## Documents

- [Specification v1 (draft)](spec/pq-light-client-v1.md)
- [When can a route be called post-quantum](docs/position-post-quantum-routes.md)
- [Guide for relayer developers (Rust)](docs/guides/relayer-rust.md)
- [Test vectors](vectors/README.md)

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
