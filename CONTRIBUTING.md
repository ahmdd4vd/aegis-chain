# Contributing to Aegis Chain

## Setup

```bash
rustup toolchain install stable
cargo build --workspace
cargo test --workspace
```

Windows note: the repository pins `stable-x86_64-pc-windows-msvc` in
`rust-toolchain.toml`. On Linux/macOS the file resolves via your default
toolchain; CI uses `dtolnay/rust-toolchain@stable`.

## Quality gates

Every change must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Layout

- `crates/aegis-core` — domain model, diff engine, decision pipeline
- `crates/aegis-cargo` — cargo metadata adapter + snapshots
- `crates/aegis-graph` — generic graph + reverse-BFS impact analysis
- `crates/aegis-policy` — policy schema/evaluator/risk score
- `crates/aegis-evidence` — CycloneDX SBOM provider
- `crates/aegis-report` — terminal/markdown/json/sarif renderers
- `crates/aegis-github` — PR comment client (idempotent marker upsert)
- `crates/aegis-cli` — the `aegis` binary wiring everything together

Dependency rule: domain crates must not depend on `aegis-cli` or
`aegis-github`.

## Fixtures

Integration tests run against real workspaces under `fixtures/`. When adding a
fixture, commit its generated `Cargo.lock` so resolution stays deterministic,
and keep package names stable across related fixtures so diffs are meaningful.

## Commits

Use concise imperative subjects (`diff: pair cross-family source swaps`). Keep
refactors separate from behavior changes.
