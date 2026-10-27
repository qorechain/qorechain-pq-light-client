<!-- SPDX-License-Identifier: Apache-2.0 -->
# QoreChain post-quantum light client, v1

| | |
|---|---|
| Status | **Draft.** Open for review. |
| Chain support | **Requires chain support (not scheduled).** QoreChain does not produce the checkpoints described here. |
| Reference verifiers | Go, Rust and TypeScript in this repository, checked against `vectors/pq-light-client-v1.json` |
| Signature scheme | ML-DSA-87 (FIPS 204), pure mode, empty context |
| Hash | SHAKE-256 (FIPS 202), 32-byte output |

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Summary

A light client that follows QoreChain today verifies ed25519 signatures of the validators' consensus keys. That is the standard model of the consensus engine and of the IBC light client type QoreChain uses (07). Its security rests on ed25519, which a large enough quantum computer can break.

This specification adds a second, independent chain of **epoch checkpoints**. At the end of each epoch every validator signs a short checkpoint with a separate **ML-DSA-87 checkpoint key**. A checkpoint is final for a light client once validators holding more than two thirds of the checkpoint set's power have signed it. Each checkpoint names the set that signs the next one, so a light client can walk from a trusted checkpoint to the latest one by verifying ML-DSA-87 signatures only.

Per-block consensus keeps ed25519. The post-quantum guarantee applies to checkpoint heights; heights inside an epoch stay classical until the next checkpoint (section 12).

## 2. Current state and scope

What the network does today, on mainnet and testnet:

- The consensus engine accepts ed25519 validator keys only (`pub_key_types` is `["ed25519"]`), and every validator key is ed25519.
- Vote extensions are off.
- IBC allows the standard 07 client type only.
- No post-quantum consensus or checkpoint design is scheduled.

Everything in sections 10 and 11, and any function in the reference verifiers that would talk to a node, **requires chain support (not scheduled)**. The verifiers in this repository check the format and the rules against simulated checkpoint chains; they cannot follow a live network until the chain produces checkpoints.

This document does not claim that any route, bridge or network is post-quantum. See `docs/position-post-quantum-routes.md` for when such a claim would be justified.

## 3. Checkpoint

A checkpoint commits to one block height and to the validator sets around it.

| Field | Type | Meaning |
|---|---|---|
| `chain_id` | 1 to 64 bytes | Chain id. Printable ASCII, 0x21 to 0x7e (no spaces). |
| `epoch` | u64 | Checkpoint sequence number. Strictly increasing; not tied to a block count (section 10.3). |
| `height` | u64 | The block height the checkpoint commits to. |
| `time` | u64 | Block time of that header, Unix seconds (truncated). |
| `header_hash` | 32 bytes | Hash of the block header at `height`, as computed by the consensus engine. |
| `app_hash` | 32 bytes | The application state root carried in the header at `height` (the state after block `height - 1`, the same convention as the 07 client). |
| `validator_set_hash` | 32 bytes | Hash (section 5) of the checkpoint validator set that signs this checkpoint. |
| `next_validator_set_hash` | 32 bytes | Hash of the checkpoint validator set that signs the next checkpoint. |

`header_hash` lets a client connect a checkpoint to the classical header chain; `app_hash` lets it verify state proofs at that height without the header. A checkpoint is valid only if both are the values the signer's own node committed (section 10.2).

### 3.1 Encoding

All integers are unsigned big-endian. The encoding is canonical: there is exactly one encoding per checkpoint.

| Bytes | Field |
|---|---|
| 1 | version, `0x01` |
| 1 | `len(chain_id)`, 1 to 64 |
| `len(chain_id)` | `chain_id` |
| 8 | `epoch` |
| 8 | `height` |
| 8 | `time` |
| 32 | `header_hash` |
| 32 | `app_hash` |
| 32 | `validator_set_hash` |
| 32 | `next_validator_set_hash` |

Length: `154 + len(chain_id)` bytes; 169 bytes for `qorechain-vladi`.

## 4. Sign-bytes and signing domain

Each validator signs:

```
sign_bytes = "qorechain-pqlc-checkpoint-v1|" || encode(checkpoint)
```

with its ML-DSA-87 checkpoint key, in FIPS 204 pure mode with an empty context string. Deterministic and hedged signing are both valid; the reference vectors use deterministic signing so they are reproducible.

The prefix is 29 ASCII bytes. Every ML-DSA-87 signature made on QoreChain starts with a domain of its own, so that a signature for one purpose cannot be replayed as another. This specification proposes the following prefixes **for the maintainers to reserve** in the list of ML-DSA-87 signing domains:

| Prefix | Use | Kind |
|---|---|---|
| `qorechain-pqlc-checkpoint-v1\|` | checkpoint sign-bytes (this section) | signing domain |
| `qorechain-pqlc-key-pop-v1\|` | proof of possession when a checkpoint key is registered (section 10.1) | signing domain |
| `qorechain-pqlc-valset-v1\|` | validator set hash input (section 5) | hash domain, never signed |

A checkpoint key MUST NOT sign anything that does not start with one of the two signing prefixes above, and no other ML-DSA-87 key on QoreChain may sign a message starting with them.

## 5. Checkpoint validator set

| Field | Type | Meaning |
|---|---|---|
| `address` | 20 bytes | Validator consensus address. |
| `power` | u64 | Voting power, at least 1. |
| `public_key` | 2,592 bytes | ML-DSA-87 checkpoint public key. |

A set has 1 to 256 validators, sorted by `address` in strictly ascending byte order (no duplicates). The total power is at most `2^60 - 1`, the consensus engine's own bound; with it, `3 x signed` and `2 x total` fit in 64 bits.

Encoding:

| Bytes | Field |
|---|---|
| 1 | version, `0x01` |
| 2 | number of validators, 1 to 256 |
| 2,620 each | `address` (20), `power` (8), `public_key` (2,592) |

Hash:

```
validator_set_hash = SHAKE-256("qorechain-pqlc-valset-v1|" || encode(set), 32 bytes)
```

## 6. Signed checkpoint

A signed checkpoint is what a relayer carries and a light client verifies.

| Bytes | Field |
|---|---|
| 1 | version, `0x01` |
| 154 + n | checkpoint (section 3.1) |
| 2 | number of signatures, 0 to 256 |
| 4,647 each | signer `address` (20), ML-DSA-87 `signature` (4,627) |
| 1 | next set flag, `0x00` or `0x01` |
| if flag is 1 | the next validator set (section 5) |

Structural rules; a decoder MUST reject with `MALFORMED` anything that breaks one:

1. Every version byte is `0x01`.
2. `chain_id` is 1 to 64 bytes of printable ASCII (0x21 to 0x7e).
3. Signatures are sorted by signer address, strictly ascending (no duplicate signers). Each signature is exactly 4,627 bytes; each public key exactly 2,592 bytes.
4. The next set is present **exactly when** `next_validator_set_hash` differs from `validator_set_hash`.
5. Validator sets follow section 5 (count, order, power, total).
6. No bytes follow the last field.

A signed checkpoint may carry zero signatures; it then decodes, but fails verification with `INSUFFICIENT_POWER`. Trust roots (section 7.1) are often distributed that way.

## 7. Trusted state

A light client keeps:

| Field | Meaning |
|---|---|
| `checkpoint` | the latest trusted checkpoint |
| `signatures` | its signatures (may be empty for a trust root); kept as evidence for section 9 |
| `validator_set` | the set that signed `checkpoint`; hashes to `checkpoint.validator_set_hash` |
| `next_validator_set` | the set that must sign the next checkpoint; hashes to `checkpoint.next_validator_set_hash` |
| `trusting_period` | seconds after `checkpoint.time` during which the state may be used, at least 1 |
| `max_clock_drift` | seconds a new checkpoint's time may be ahead of the local clock |

### 7.1 Trust root

A light client starts from a checkpoint it trusts for reasons outside this protocol (social consensus, a checkpoint published by the operator it already trusts, a genesis file). `newTrustedState` checks only that both sets hash to the values in the checkpoint; it does not verify signatures. Choosing a trust root is the same subjective step as with any proof-of-stake light client.

### 7.2 Trusting period

The trusting period MUST be shorter than the period during which a validator that signed a checkpoint can still be penalised for misbehaviour (the unbonding period, or the corresponding period of the checkpoint module). Otherwise validators who have left could sign a conflicting history at no cost. A client whose trusted checkpoint is older than the trusting period MUST stop and be re-initialised from a new trust root.

## 8. Verification

`verifyCheckpoint(trusted, signed, now)` returns a new trusted state or an error with one of the codes below. `now` is the verifier's clock in Unix seconds. Implementations MUST run the checks in this order, so that every implementation returns the same code for the same input.

### 8.1 Order of checks

1. **Structure.** `signed` follows section 6, else `MALFORMED`.
2. **Chain.** `signed.chain_id == trusted.chain_id`, else `CHAIN_ID_MISMATCH`.
3. **Expiry.** If `now >= trusted.time` and `now - trusted.time >= trusting_period`: `TRUST_EXPIRED`.
4. **Clock.** If `signed.time > now` and `signed.time - now > max_clock_drift`: `FUTURE_CHECKPOINT`.
5. **Same epoch.** If `signed.epoch == trusted.epoch`:
   - identical sign-bytes: `NOT_NEWER`;
   - otherwise run the quorum check (8.2) against `trusted.validator_set`. If it fails, return that error. If it passes, two checkpoints for one epoch both have a quorum: return `CONFLICTING_CHECKPOINT` with the evidence of section 9. The client SHOULD stop and report it.
6. **Progress.** `signed.epoch > trusted.epoch`, `signed.height > trusted.height` and `signed.time > trusted.time`, else `NOT_NEWER`.
7. **Signing set.** `signed.validator_set_hash == trusted.next_validator_set_hash`, else `SET_MISMATCH`.
8. **Next set.** If the next set is present, it hashes to `signed.next_validator_set_hash`, else `SET_MISMATCH`.
9. **Quorum.** Section 8.2 against `trusted.next_validator_set`.
10. **Result.** The new state: `checkpoint` and `signatures` from `signed`; `validator_set` = `trusted.next_validator_set`; `next_validator_set` = the set carried by `signed`, or the same set again when it does not change; the same trusting period and drift.

Step 6 allows skipping epochs **only while the signing set is unchanged**: if the set rotated in between, step 7 fails and the client must fetch the intermediate checkpoints. Every set handover is therefore signed by the outgoing set.

A failed verification leaves the trusted state unchanged.

### 8.2 Quorum check

1. The set hashes to `checkpoint.validator_set_hash`, else `SET_MISMATCH`.
2. For each signature, in order: the signer is a member of the set, else `UNKNOWN_VALIDATOR`; the ML-DSA-87 signature verifies over the sign-bytes under the member's key, else `BAD_SIGNATURE`. The first failure rejects the whole checkpoint.
3. With `signed` the sum of the signers' power and `total` the set's total power: `3 x signed > 2 x total`, else `INSUFFICIENT_POWER`. Exactly two thirds is not enough.

Signatures from non-members are not ignored: they make the checkpoint invalid. Relayers SHOULD strip them before forwarding.

### 8.3 Error codes

| Code | Meaning |
|---|---|
| `MALFORMED` | not a canonical encoding, or a structural rule is broken |
| `CHAIN_ID_MISMATCH` | checkpoint for another chain |
| `TRUST_EXPIRED` | trusted checkpoint older than the trusting period |
| `FUTURE_CHECKPOINT` | checkpoint time too far ahead of the local clock |
| `NOT_NEWER` | already trusted, or epoch, height or time does not increase |
| `SET_MISMATCH` | a validator set does not match the hash it must match |
| `UNKNOWN_VALIDATOR` | a signer is not in the set |
| `BAD_SIGNATURE` | a signature does not verify |
| `INSUFFICIENT_POWER` | signed power is two thirds of the total or less |
| `CONFLICTING_CHECKPOINT` | two checkpoints for one epoch both have a quorum; evidence attached |
| `REQUIRES_CHAIN_SUPPORT` | the function needs the chain to produce checkpoints (not scheduled) |

## 9. Misbehaviour

Two signed checkpoints are **conflicting** when they have the same `chain_id` and `epoch`, different sign-bytes, and each passes the quorum check against the same validator set.

`detectMisbehaviour(set, a, b)` returns evidence for such a pair and nothing otherwise (including for malformed input). The evidence holds:

- `first` and `second`: the two signed checkpoints, ordered by their sign-bytes (lexicographic, shorter first on a common prefix), so that the evidence is the same whichever order it was found in;
- `double_signers`: the members with a valid signature on both, sorted by address;
- `double_signed_power`: their total power.

Because each side has more than two thirds of the power, the double signers always hold more than one third of it, unless one side came from a trust root distributed without signatures. Double signers are the validators the chain would penalise (section 10.4).

## 10. What the chain would need

Everything in this section **requires chain support (not scheduled)**. It is a design for review, not a commitment.

### 10.1 Checkpoint keys

- Each validator registers a separate ML-DSA-87 **checkpoint key**, distinct from its consensus key and from any account key.
- Registration is an ordinary transaction from the validator operator account, carrying the public key and a proof of possession: an ML-DSA-87 signature by the new key over `"qorechain-pqlc-key-pop-v1|" || chain_id || operator address || consensus address || public key`. This binds the key to the operator and to the consensus address.
- The chain rejects a key that is already registered for another validator or as an account key.
- A rotated key takes effect in the next checkpoint set, never inside an epoch.
- Validators without a registered key are not in the checkpoint set, and their power is not counted.

### 10.2 Signing

- At each checkpoint height every validator in the current checkpoint set signs the checkpoint for that height with its checkpoint key and submits it as an ordinary transaction (for example `MsgSignCheckpoint`). A validator signs only `header_hash` and `app_hash` values that its own node committed.
- A module collects signatures and stores the checkpoint, its signatures and the next set once more than two thirds of the power has signed. Nodes serve them to light clients and relayers.
- Because signatures travel in ordinary transactions, block production never waits for them: a validator that does not sign delays the checkpoint, not the chain.

### 10.3 Epochs and set transitions

- A checkpoint is due every N blocks (a chain parameter) and additionally when the checkpoint set would change by more than a threshold of power. `epoch` counts checkpoints, so an extra checkpoint for a set change simply takes the next epoch number.
- `next_validator_set_hash` is fixed when a checkpoint is signed; that set, and only that set, signs the next checkpoint.
- Open question for the chain design: whether small power changes update the checkpoint set at every checkpoint (exact, but every checkpoint then carries the full next set) or only past a threshold (smaller, but the light client then counts power that lags behind the stake by up to that threshold).
- Recommended rule: the chain does not emit a checkpoint while validators with registered checkpoint keys hold two thirds or less of the bonded power, so that the checkpoint set always represents a supermajority of the stake.

### 10.4 Penalties

- Signing two different checkpoints for the same epoch is provable from the evidence of section 9 and SHOULD be penalised like double signing.
- Whether a validator that does not sign checkpoints is penalised is open.

## 11. Sizes and verification cost

ML-DSA-87 sizes from FIPS 204: public key 2,592 bytes, signature 4,627 bytes. Verification takes about 0.29 ms per signature measured through the chain's native verifier; the TypeScript verifier is slower.

For chain id `qorechain-vladi`: the checkpoint is 169 bytes and the sign-bytes 198 bytes. A signed checkpoint is `173 + 4,647 x signers` bytes, plus `3 + 2,620 x validators` when it carries the next set. "Quorum" below is the smallest number of equal-power signers above two thirds.

| Validators | Signed checkpoint, quorum signers | Signed checkpoint, all signers | Next set | Verification, all signers |
|---|---|---|---|---|
| 4 | 3 signers: 14,114 B | 18,761 B | 10,483 B | about 1.2 ms |
| 8 | 6 signers: 28,055 B | 37,349 B | 20,963 B | about 2.3 ms |
| 21 | 15 signers: 69,878 B | 97,760 B | 55,023 B | about 6.1 ms |
| 100 | 67 signers: 311,522 B | 464,873 B | 262,003 B | about 29 ms |

On chain, each signature also travels in its own transaction, which carries that account's own signatures; chain-side storage is therefore roughly twice the figures above. The light client downloads only the signed checkpoint.

## 12. Why checkpoints and not per-block signatures

The alternative is an ML-DSA-87 signature from every validator on every block. The consensus engine accepts only ed25519, secp256k1 or bls12-381 votes, so per-block ML-DSA-87 signatures would have to ride in vote extensions. That has two costs:

- **Liveness.** With vote extensions, a block cannot be finalised until the extensions are produced and checked, so a fault in the post-quantum path can stop the chain.
- **Size.** Signatures alone are about 37 KB per block at 8 validators (about 1 GB per day at the current block rate) and about 463 KB per block at 100 validators (about 12.7 GB per day).

Checkpoints keep consensus unchanged, cost one signature per validator per epoch (with one checkpoint per hour at 21 validators, about 2.3 MB per day; at 100 validators, about 11 MB per day), and let a light client skip whole epochs while the set does not change.

The trade-off: heights inside an epoch are authenticated only by the classical ed25519 headers until the next checkpoint. A client that needs the post-quantum guarantee uses checkpoint heights only, and accepts up to one epoch of latency.

## 13. Security notes

- **Assumption.** More than two thirds of each checkpoint set's power is held by validators that sign only checkpoints their own node committed. A quantum adversary that forges ed25519 consensus signatures cannot produce ML-DSA-87 checkpoint signatures for a history the honest validators did not commit.
- **Hashes.** Header and state hashes in the consensus engine and the state store are SHA-256; the set hash is SHAKE-256. Both keep a large security margin against known quantum attacks at 256-bit output.
- **Strict encoding.** The decoders accept exactly one encoding per object, and the verifiers reject signatures of any length other than 4,627 bytes, so a client never accepts bytes the chain would treat differently.
- **Unknown signers** invalidate a checkpoint instead of being skipped, which keeps all implementations on the same result.
- **Trust roots** are subjective (section 7.1); this protocol cannot protect a client that starts from a wrong one.

## 14. How this maps to IBC

Design only; **requires chain support (not scheduled)**.

A new IBC light client type (for example `qorechain-pqlc`) implements this specification inside ibc-go's light client module interface:

| ibc-go concept | This specification |
|---|---|
| Client state | `chain_id`, latest checkpoint epoch and height, `next_validator_set_hash`, `trusting_period`, `max_clock_drift`, frozen flag |
| Consensus state (per height) | `time`, `app_hash` (commitment root), `next_validator_set_hash` |
| Client message: header | a signed checkpoint, plus the signing set when the client stores only its hash |
| Client message: misbehaviour | two conflicting signed checkpoints (section 9) |
| `VerifyClientMessage` | section 8.1, steps 1 to 9, with `now` from the host chain's block time |
| `CheckForMisbehaviour` / `UpdateStateOnMisbehaviour` | section 9; on evidence the client is frozen |
| `UpdateState` | section 8.1, step 10 |
| `VerifyMembership` / `VerifyNonMembership` | ICS-23 proofs against the stored `app_hash`, as with the 07 client |
| `Status` | expired after the trusting period, frozen on misbehaviour |
| IBC height | revision number from the chain id, revision height = checkpoint `height` |

Consequences:

- Proofs are possible only at checkpoint heights, so packets wait up to one epoch. Relayers query proofs at `height - 1` and submit the checkpoint for `height`, the same convention as the 07 client.
- The client can be deployed natively in a counterparty chain or as a wasm light client where the counterparty supports one; allowing a new client type is a governance decision on each chain.
- QoreChain itself must produce checkpoints (section 10) before such a client can follow it. The reverse direction is separate: QoreChain's client of the counterparty is only as strong as the counterparty's own consensus.

## 15. EVM and Solana verifiers

Design comparison, no code. Figures marked "estimate" are not measured.

### 15.1 On-chain ML-DSA-87 verification

The destination contract stores the hash of the current checkpoint set and verifies each checkpoint's signatures directly.

- **EVM.** There is no ML-DSA verification precompile on Ethereum. Public keys are best passed in calldata and checked against the stored set hash (storing 21 keys of 2,592 bytes costs about 1,700 storage slots). Calldata for a 21-validator quorum (15 signatures and 15 keys, about 108 KB) is about 1.7 million gas at 16 gas per non-zero byte, more under calldata floor pricing. Each verification needs SHAKE-256 expansion and polynomial arithmetic in the EVM; estimate: millions of gas per signature, so tens of millions per checkpoint. QoreChain's own EVM has an ML-DSA verification precompile on testnet only; it does not help on other chains.
- **Solana.** A transaction is limited to 1,232 bytes, so a single 4,627-byte signature does not fit; signatures and keys must be uploaded into accounts over several transactions, and the verification split across transactions to stay within the compute budget. Estimate: dozens of transactions per checkpoint.

Keeps the post-quantum property end to end. Cost is the problem.

### 15.2 STARK proof of verification

A prover runs this verifier off-chain inside a STARK (or a zero-knowledge virtual machine with a STARK backend) and the destination verifies one proof per checkpoint.

- Destination cost does not grow with the number of validators. Estimate for direct STARK verification on the EVM: low millions of gas, with proofs of tens to hundreds of KB; proving 15 or more ML-DSA-87 verifications is heavy off-chain work.
- STARKs rely on hash functions only, so the post-quantum property is kept. **Wrapping the STARK in a pairing-based SNARK** to reduce gas, a common practice, gives that property up: pairing-based proofs are not secure against a quantum adversary.
- On Solana the same transaction-size limits apply to the proof.

### 15.3 Attestor set

A committee runs this verifier off-chain and signs attestations that the destination checks.

- Cheapest: a few secp256k1 or ed25519 signatures per update.
- Adds trust in the committee, and with classical signatures the destination is not post-quantum. With ML-DSA-87 attestations the cost falls back to 15.1, for fewer signers.

### 15.4 Comparison

| | On-chain ML-DSA-87 | STARK | Attestor set |
|---|---|---|---|
| Trust added | none | none (hash-based proof) | the committee |
| Post-quantum at the destination | yes | yes, unless wrapped in a pairing-based SNARK | only with post-quantum attestor signatures |
| Destination cost | very high (estimate) | high, constant in validators (estimate) | low |
| Off-chain cost | low | high (proving) | low |
| Maturity | needs precompiles or heavy contracts | needs a production prover | available, interim only |

None of these exists for QoreChain today, and none is useful until the chain produces checkpoints.

## 16. Test vectors

`vectors/pq-light-client-v1.json`, generated by `scripts/gen-vectors.mjs` from fixed test seeds (the keys are public test keys):

- a 4-validator set (powers 100, 100, 50, 50) and a 21-validator set (powers 50 to 150), each with a valid checkpoint chain and a set rotation;
- invalid steps: exactly two thirds of the power, tampered height, flipped signature byte, wrong chain id, signature by a removed validator, the outgoing set signing after a rotation, a next set that does not match its hash, a set the trusted state does not name, replay, non-increasing height, expired trust, a checkpoint from the future;
- conflicting checkpoints, through `verifyCheckpoint` and `detectMisbehaviour`;
- decoder cases for every structural rule of section 6.

Each case lists the expected result or error code; the Go, Rust and TypeScript verifiers all produce exactly those results.

## 17. Changes

- v1 draft (this document).
