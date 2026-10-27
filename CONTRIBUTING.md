# Contributing to qorechain-pq-light-client

Thanks for your interest. Issues, pull requests and discussion are welcome, in particular on the specification while it is a draft.

## Layout

| Path | Contents |
|---|---|
| `spec` | the specification (`pq-light-client-v1.md`) |
| `vectors` | test vectors shared by every implementation |
| `scripts` | the deterministic simulator that generates the vectors |
| `go` | Go module `github.com/qorechain/qorechain-pq-light-client/go` |
| `rust` | Rust crate `qorechain-pq-light-client` |
| `ts` | TypeScript package `@qorechain/pq-light-client` |
| `docs` | position paper and guides |

## Build and test

```bash
(cd ts && pnpm install --frozen-lockfile && pnpm build && pnpm typecheck && pnpm test)   # TypeScript
(cd rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)   # Rust
(cd go && gofmt -l . && go vet ./... && go test ./...)                                   # Go
(cd go && go test -run '^$' -fuzz FuzzDecodeSignedCheckpoint -fuzztime 30s)               # Go fuzzing
```

Regenerate the vectors after building the TypeScript package:

```bash
node scripts/gen-vectors.mjs
```

The output is deterministic: running it twice gives the same file, and CI fails if the committed file differs.

## Changing the format or the rules

The specification is normative; the three implementations follow it. A change to bytes on the wire or to a verification rule needs, in the same pull request: the specification updated, a **new** versioned vectors file, and Go, Rust and TypeScript passing it.

## Content rules

This is a public repository. Do not claim that any route, bridge or network is post-quantum unless the specification's conditions are met and live, and label anything that depends on the chain "requires chain support (not scheduled)".

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
