# ADR 0002: Local-first by default

Status: accepted

## Context

A supply-chain review tool asks for trust: it reads manifests, runs cargo, and
posts to GitHub. Shipping code or metadata to a server would create a new
attack surface and a privacy problem for private repos.

## Decision

Every MVP analysis path runs locally (developer machine or GitHub runner).
`--offline --locked` is the default for snapshot construction. Network access
is limited to explicit opt-ins: posting the PR comment (`--comment`) and,
later, advisory plugins.

## Consequences

- No Aegis server exists; there is nothing to breach.
- Determinism is testable end-to-end because inputs are files on disk.
- Features that genuinely need shared state (dashboards, org-wide baselines)
  are deferred rather than smuggled in.
