<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org); before 1.0, a minor version may contain breaking changes, which are always called out.

## [0.1.0] - Unreleased

### Added

- Specification `spec/pq-light-client-v1.md` (draft): ML-DSA-87 epoch checkpoints signed by a separate validator checkpoint key, canonical encodings, sign-bytes with the proposed domain `qorechain-pqlc-checkpoint-v1|`, validator set hashing, threshold and set transition rules, trusting period, misbehaviour, sizes and verification cost, why checkpoints instead of per-block signatures, an IBC light client mapping and a comparison of EVM and Solana verifier designs. Chain support is not scheduled.
- Reference verifiers with the same API in Go (`github.com/qorechain/qorechain-pq-light-client/go`), Rust (`qorechain-pq-light-client`) and TypeScript (`@qorechain/pq-light-client`), over `qorechain-pqc` 0.2.3: `verifyCheckpoint`, `detectMisbehaviour`, `newTrustedState`, `encodeCheckpointSignBytes`, encoders and strict decoders, typed errors with stable codes.
- `fetchCheckpoint` and `CheckpointSource` as interfaces only; they fail with `REQUIRES_CHAIN_SUPPORT`.
- Shared vectors `vectors/pq-light-client-v1.json` from a deterministic simulator (4 and 21 validators, rotations, invalid and conflicting checkpoints, decoder cases), passing in all three languages.
- Go fuzz tests for the decoders; a Rust relayer example.
- Position page on when a route can be called post-quantum, and a guide for relayer developers.
