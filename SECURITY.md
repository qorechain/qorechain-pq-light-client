# Security Policy

This repository specifies and implements a verifier: a bug in it can make a client accept state that the validators never signed. We treat reports for it with priority.

## Reporting a vulnerability

Please **do not** report vulnerabilities through public issues, discussions or pull requests. Email:

**security@qore.network**

Include, as far as you can: a description and the impact, steps to reproduce or a proof of concept (for example the bytes of a checkpoint that a verifier wrongly accepts), the affected implementation (Go, Rust or TypeScript) and commit, and a suggested fix.

Qualifying reports are eligible for the QoreChain bug bounty; scope and rules are published at <https://www.qorechain.io/security>.

## What to expect

- We acknowledge your report and keep you informed while we investigate.
- We coordinate disclosure with you once a fix is released.

## Status

The specification is a draft and the verifiers are reference implementations. QoreChain does not produce post-quantum checkpoints today, so nothing in production depends on this code yet. Reports are still welcome: they shape the design before any chain support exists.

## Cryptography

This repository implements no cryptographic primitive itself. ML-DSA-87 (FIPS 204) and SHAKE-256 (FIPS 202) come from the `qorechain-pqc` bindings (over Cloudflare CIRCL in Go, `fips204` and `sha3` in Rust, `@noble/post-quantum` and `@noble/hashes` in TypeScript). Issues in those libraries should also be reported upstream.
