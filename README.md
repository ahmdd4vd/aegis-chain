# Aegis Chain

[![CI](https://github.com/ahmdd4vd/aegis-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmdd4vd/aegis-chain/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Dependency impact reports and policy gates for Rust workspaces.

Aegis Chain reads dependency changes across a Cargo workspace, builds an
impact graph, and produces human-readable reports about what changed, which
local packages are affected, which supply-chain evidence is missing, and what
policy decision is recommended.

It is not a vulnerability scanner. It is an **explanation and decision layer**
on top of dependency changes.

---

## Why

When a pull request touches `Cargo.toml` or `Cargo.lock`, reviewers have to
answer four questions:

1. What changed?
2. Which services are affected?
3. Is the required supply-chain evidence present?
4. Does the change violate our policy?

Existing tools answer fragments of that list. Aegis Chain answers all four in
a single report:

| Without Aegis Chain | With Aegis Chain |
| --- | --- |
| "`reqwest` changed from 0.12.1 to 0.12.2." | "`reqwest` changed and impacts `api-gateway` and `payment-worker`." |
| "One new dependency." | "A new dependency reaches a `critical` path; policy requires an SBOM." |
| "High severity finding." | "Risk 67/100 on a critical path — release blocked by policy." |

---

## How it works

```text
snapshot(base) ──┐
                 ├──> diff ──> impact graph ──> risk score ──> policy ──> report
snapshot(head) ──┘                     │                            │
                              reverse BFS + paths          pass / warn / block
                                                                  │
                                               terminal · markdown · json · sarif · html
```

| Stage | What it does |
| --- | --- |
| Snapshot | Runs `cargo metadata --format-version 1 --locked --offline` and freezes the resolved graph as versioned JSON. |
| Diff | Classifies added, removed, major/minor/patch upgrades, downgrades, and source mutations using logical coordinates `(name, source family)`. |
| Impact | Reverse-BFS finds every workspace root that can reach a changed package, with up to five deterministic shortest paths. |
| Score | Transparent weighted formula — magnitude, breadth, proximity, criticality, evidence gap, findings — no hidden magic numbers. |
| Policy | Strict YAML rules (`all`/`any`/`not` plus predicates) evaluated into an auditable trace; decisions are `pass`, `warn`, or `block`. |
| Evidence | CycloneDX SBOM (and optional `hashes`/`license`), OSV.dev advisory findings, and Sigstore/cosign provenance close evidence gaps before rules fire. |

Every `warn` or `block` ships with its rule id, predicate trace, and graph
path — reviewers see *why*, not just a number.

---

## Install

From source (Rust stable):

```bash
cargo install --path crates/aegis-cli
aegis --help
```

## Usage

Freeze both sides of a change, then diff them:

```bash
aegis snapshot --manifest-path path/to/Cargo.toml --output head.json

aegis diff \
  --base-snapshot base.json \
  --head-snapshot head.json \
  --policy aegis.yml \
  --sbom sbom/bom.json \
  --advisory \
  --provenance ./sigstore-bundles \
  --format markdown \
  --sarif report.sarif
```

Optional, opt-in enrichments (both respect the local-first principle — nothing
leaves the runner unless you pass the flag):

- `--advisory` queries the [OSV.dev](https://osv.dev) database for the
  `crates.io` ecosystem and feeds any findings into the risk score.
- `--provenance <DIR>` verifies a Sigstore/cosign bundle
  (`{name}@{version}.json`) per package from `DIR` and marks provenance as
  satisfied evidence, lowering the risk score.

Bootstrap and validate a policy:

```bash
aegis policy init              # writes a starter aegis.yml
aegis policy check --policy aegis.yml
```

Explain why a rule fired — or didn't:

```bash
aegis explain critical-new-package-needs-sbom --report aegis-report.json
```

### Example output (terminal)

```text
Aegis diff report (schema v2)
Changes: 1 (1 added)
Overall status: BLOCK (formula risk-formula/v1)

[ADDED] unicode-width 0.2.2
  Status: BLOCK | Risk: 67/100 (high)
  Matched rules: critical-new-package-needs-sbom
  Impacted roots: basic-app
  Paths:
    basic-app -> unicode-width
```

The same decision renders as an idempotent PR comment (marker
`<!-- aegis-chain:report:v1 -->`), versioned JSON for CI, and SARIF 2.1.0 for
code scanning.

Exit codes: `0` = success (advisory warnings included); non-zero = gate failed
via `--fail-on`, or an input/runtime error.

---

## Policy

Policies live with the repository (`aegis.yml`) and are parsed strictly —
unknown fields are rejected, thresholds must be ordered, rule ids unique.

```yaml
schema_version: 1

critical_packages:
  - api-gateway
  - payment-worker

evidence:
  require_for_added_packages:
    - sbom
  require_for_critical_path:
    - sbom
    - provenance

thresholds:
  warn_at: 30
  high_at: 60
  block_at: 80

rules:
  - id: critical-new-package-needs-sbom
    when:
      all:
        - is_added: true
        - touches_critical: true
        - missing_evidence: sbom
    action: block
    message: "New package reaches a critical path but no SBOM was found."

  - id: source-mutation-review
    when:
      any:
        - source_changed: true
        - is_major_upgrade: true
    action: warn
```

See `config/aegis.example.yml` for a complete reference and
`docs/policy-reference.md` once published.

---

## Use as a GitHub Action

```yaml
- uses: ahmdd4vd/aegis-chain/.github/actions/aegis-chain@v0.2.0
  with:
    base-ref: ${{ github.event.pull_request.base.sha }}
    policy: aegis.yml
    comment: "true"
    pr-number: ${{ github.event.pull_request.number }}
    fail-on: block
  env:
    GITHUB_TOKEN: ${{ github.token }}
```

The action builds base/head snapshots via `git worktree`, evaluates your
policy, posts **one** report comment per PR (reruns update it instead of
spamming), and fails only when the overall status reaches `fail-on`.

This repository dogfoods itself with the same flow — see
`.github/workflows/dogfood.yml`.

---

## Use as a GitLab CI job

Include the reusable job template and extend it in your `.gitlab-ci.yml`:

```yaml
include:
  - local: '.gitlab/aegis-chain.yml'

aegis_chain:
  extends: .aegis_chain
  variables:
    AEGIS_FAIL_ON: block      # never | warn | block
    AEGIS_POLICY: aegis.yml   # optional
```

The template snapshots the base (target branch) and head, evaluates the
policy, and posts the Markdown report as an **idempotent merge-request note**
(marker `<!-- aegis-chain:report:v1 -->`).

---

## Repository layout

| Crate | Responsibility |
| --- | --- |
| `aegis-cli` | The `aegis` binary wiring everything together |
| `aegis-core` | Domain model, diff engine, decision pipeline |
| `aegis-cargo` | cargo metadata adapter and snapshot export |
| `aegis-graph` | Generic directed graph and reverse-BFS impact analysis |
| `aegis-policy` | Policy schema, evaluator, transparent risk scoring |
| `aegis-evidence` | CycloneDX SBOM evidence provider |
| `aegis-advisory` | OSV.dev advisory provider (feeds risk findings) |
| `aegis-sigstore` | Sigstore/cosign provenance verification provider |
| `aegis-report` | Terminal, Markdown, JSON, SARIF, and HTML renderers |
| `aegis-github` | Idempotent PR comment client |

Dependency rule: domain crates never depend on `aegis-cli` or `aegis-github`.

---

## Design principles

- **Local-first** — analysis runs on your machine or runner; nothing is sent
  to an Aegis server (there isn't one).
- **Cargo is the source of truth** — no hand-parsed lockfiles.
- **Deterministic** — identical inputs produce byte-identical snapshots,
  reports, and exit codes.
- **Explainable by default** — every verdict carries its rule, trace, and path.
- **Fail closed only when asked** — advisory by default; blocking requires an
  explicit policy or `--fail-on`.
- **No overclaiming** — "pass" means "no rule fired on the enabled sources",
  never "secure".

---

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The suite covers unit tests, fixture-driven integration tests against real
workspaces under `fixtures/`, property tests for reverse-reachability and
score bounds, mock-HTTP tests for comment idempotency, and an end-to-end run
from fixtures to Markdown/SARIF.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup details and conventions.

---

## Security

Please report vulnerabilities privately via GitHub Security Advisories — see
[SECURITY.md](SECURITY.md). The working threat model lives in
[docs/threat-model.md](docs/threat-model.md), including accepted limitations
(name-based SBOM matching; presence checks are signals, not attestations).

## License

Apache-2.0
