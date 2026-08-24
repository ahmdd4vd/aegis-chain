# Threat Model (minimum)

## Assets

1. CI verdicts: the pass/warn/block status Aegis emits gates merges.
2. GitHub token provided to the action (comment posting).
3. Developer trust in report contents.

## Trust boundaries

| Boundary | Trust assumption |
| --- | --- |
| Repository policy file (`aegis.yml`) | Trusted configuration owned by the repo; parsed strictly, unknown fields rejected |
| Snapshot / SBOM files on disk | Untrusted data: parsed defensively, never executed, errors become findings not panics |
| `cargo metadata` output | Semi-trusted (produced by cargo from repo state); malformed output surfaces as runtime error |
| GitHub API responses | Only comment IDs/bodies are consumed; bodies are echoed into markdown-escaped contexts only |

## Abuse cases and mitigations

- **Malicious or malformed policy YAML** → strict schema, `deny_unknown_fields`,
  duplicate-id and threshold-order validation, table-driven parser tests.
- **Path tricks via `--manifest-path` / `--sbom`** → inputs are read as files
  only; no directory traversal beyond the given path; missing files produce
  config errors with recovery hints.
- **Huge workspaces exhausting CI memory/CPU** → bounded traversal
  (max 5 paths per change), deterministic BFS over sorted adjacency;
  subprocess timeouts are a backlog item.
- **Comment spam / marker forgery** → upsert matches the exact hidden marker
  `<!-- aegis-chain:report:v1 -->`; human comments are never modified.
- **Silent policy bypass via tool failure** → runtime failures exit non-zero
  distinct from policy verdicts; `--fail-on` cannot be satisfied by a crash.
- **False sense of safety** → reports state which evidence sources were used;
  "pass" means "no rule fired", never "secure".

## Known gaps (accepted for v0.x)

- SBOM matching is name-based; cryptographic verification is future work.
- Comment listing uses default pagination (first page only).
- No sandboxing of cargo execution beyond `--locked --offline` flags.
