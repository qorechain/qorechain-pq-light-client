<!-- SPDX-License-Identifier: Apache-2.0 -->
# When can a route be called post-quantum

A position of the QoreChain Association. It applies to anything that moves value or messages between QoreChain and another chain: IBC channels, bridges, relayers and wrapped assets, which this page calls routes.

## The rule

A route may be called **post-quantum** only when **both ends verify post-quantum-signed state of the other end**:

1. The destination accepts a message only after verifying, with a post-quantum signature scheme, that the source chain's validators committed it; and
2. the same holds in the opposite direction for any message the route accepts back (acknowledgements, timeouts, returns of locked assets).

Everything the verification relies on must keep that property: the signatures, the hashes, and any proof system in between.

## What does not qualify

- **Post-quantum user signatures alone.** QoreChain accounts sign transactions with ML-DSA-87 alongside secp256k1. That protects the account; it says nothing about how another chain learns that QoreChain committed a transaction.
- **A classical light client at either end.** A light client that verifies ed25519, secp256k1 or BLS validator signatures can be deceived by an adversary able to forge them, whatever the rest of the route does. The standard IBC client QoreChain uses today (07) is classical.
- **A proof wrapped in a pairing-based SNARK.** A STARK keeps the property; the common step of wrapping it in a pairing-based SNARK to make on-chain verification cheaper removes it.
- **An attestor or multisig committee with classical signatures.** It adds a trust assumption and the destination still verifies classical signatures.
- **One direction only.** If assets can return over a classical path, the route as a whole is classical.

## Where QoreChain stands

- QoreChain validators sign consensus with ed25519 keys.
- The checkpoint design in this repository would give QoreChain's side of a route post-quantum-signed state. It **requires chain support (not scheduled)**.
- Even then, a route qualifies only if the other chain also offers post-quantum-signed state and verifies QoreChain's checkpoints in a way that keeps the property (see the specification, sections 14 and 15).

Until both ends meet the rule, routes should be described by what they actually verify, for example "secured by the counterparty's classical light client", and not as post-quantum.

## Wording

| Situation | Acceptable wording |
|---|---|
| Accounts sign with ML-DSA-87 | "post-quantum account signatures" |
| One end verifies post-quantum checkpoints, the other does not | "post-quantum verification of QoreChain state on chain X; the return path is classical" |
| Both ends verify post-quantum-signed state, with no classical step | "post-quantum route" |
