# @qorechain/pq-light-client

Reference verifier for QoreChain post-quantum light client checkpoints (ML-DSA-87, FIPS 204), over `@qorechain/pqc` 0.2.3. Works in Node.js 20.19+ and browsers. Specification: [spec/pq-light-client-v1.md](https://github.com/qorechain/qorechain-pq-light-client/blob/main/spec/pq-light-client-v1.md) (draft).

> **Requires chain support (not scheduled).** QoreChain does not produce these checkpoints; this package verifies the format and the rules against simulated chains. `fetchCheckpoint` always rejects with `REQUIRES_CHAIN_SUPPORT` and makes no request.

```ts
import { PqLightClientError, decodeSignedCheckpoint, verifyCheckpoint } from "@qorechain/pq-light-client";

try {
  trusted = verifyCheckpoint(trusted, decodeSignedCheckpoint(bytes), BigInt(Math.floor(Date.now() / 1000)));
} catch (e) {
  if (e instanceof PqLightClientError && e.code === "CONFLICTING_CHECKPOINT") {
    report(e.misbehaviour);
  }
}
```

API: `Checkpoint`, `ValidatorSet`, `SignedCheckpoint`, `TrustedState`, `Misbehaviour`; `encodeCheckpointSignBytes`, `verifyCheckpoint`, `detectMisbehaviour`, `newTrustedState`, `signCheckpoint` (simulators and tests), the encoders and decoders, `hashValidatorSet`; `CheckpointSource`, `fetchCheckpoint`, `chainCheckpointSource`. 64-bit fields are `bigint`. Errors are `PqLightClientError` with a stable `code` shared with Go and Rust.

```bash
pnpm install && pnpm build && pnpm test
```

Apache-2.0.
