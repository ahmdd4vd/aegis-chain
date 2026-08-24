# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not open a
public issue for anything you believe is exploitable.

You can expect an initial response within 7 days.

## Scope

Aegis Chain analyzes local Rust workspaces. Of particular interest:

- Policy parsing (`aegis.yml`) and any path where untrusted YAML is evaluated.
- Snapshot/report files treated as input (`aegis snapshot` output, `--sbom` files).
- The GitHub Action wrapper: token handling, comment posting, shell steps.
- Path traversal when reading manifests or SBOM paths.

## Non-goals

- Aegis does not claim packages are "safe"; absence of findings means nothing
  was found by the enabled evidence sources.
- Cryptographic verification of SBOM/provenance artifacts is not implemented
  yet; presence checks are advisory signals, not attestations.
