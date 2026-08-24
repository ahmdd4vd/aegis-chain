# ADR 0001: Cargo metadata is the source of truth

Status: accepted

## Context

Aegis needs a resolved dependency graph for a Rust workspace. Options were
parsing `Cargo.lock` directly, scraping manifests, or using
`cargo metadata --format-version 1`.

## Decision

All snapshot construction runs `cargo metadata --format-version 1 --locked`
(plus `--offline` in analysis contexts). The lockfile parser fallback is
explicitly deferred; manifests are never parsed for graph facts.

## Consequences

- Feature resolution, dependency kinds, and workspace membership come from
  Cargo itself, eliminating an entire class of drift bugs.
- Snapshots inherit Cargo's resolution semantics (including pre-release and
  platform quirks) without re-implementing them.
- Running Aegis requires a working `cargo` binary; pure static analysis of a
  checkout without cargo is out of scope until the fallback exists.
