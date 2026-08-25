use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use aegis_cargo::{build_snapshot, MetadataOptions};
use aegis_core::run_decision;
use aegis_policy::{parse_policy, EvidenceAvailability};

fn repo_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn ensure_lockfile(dir: &Path) {
    let status = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(dir)
        .status()
        .expect("failed to spawn cargo generate-lockfile");
    assert!(status.success(), "cargo generate-lockfile failed");
}

fn snapshot_of(name: &str) -> aegis_core::model::DependencySnapshot {
    let dir = repo_dir().join("fixtures").join(name);
    assert!(dir.is_dir(), "fixture {name} exists");
    ensure_lockfile(&dir);
    build_snapshot(&MetadataOptions::new(dir.join("Cargo.toml"))).expect("snapshot builds")
}

const POLICY_YAML: &str = "
schema_version: 1
critical_packages:
  - basic-app
evidence:
  require_for_added_packages:
    - sbom
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
    message: \"New package reaches a critical path but no SBOM was found.\"
";

#[test]
fn fixture_diff_renders_markdown_and_sarif_end_to_end() {
    let base = snapshot_of("basic-workspace");
    let head = snapshot_of("added-package-workspace");

    let policy = parse_policy(POLICY_YAML).expect("policy parses");
    let evidence = EvidenceAvailability::default();

    let report = run_decision(&base, &head, Some(&policy), &evidence, None, None);

    assert!(report.policy.as_ref().is_some());
    assert_eq!(
        report.policy.as_ref().unwrap().overall_status,
        aegis_policy::Action::Block,
        "added package on critical path without SBOM must block"
    );

    let markdown = aegis_report::markdown::render(&report);

    assert!(markdown.contains(aegis_github::REPORT_MARKER));
    assert!(markdown.contains("## Aegis Chain Report"));
    assert!(markdown.contains(":no_entry_sign:"));
    assert!(markdown.contains("| unicode-width |"));
    assert!(markdown.contains("BLOCK"));
    assert!(markdown.contains("`critical-new-package-needs-sbom`"));
    assert!(markdown.contains("basic-app -> unicode-width"));

    let sarif = aegis_report::sarif::render(&report);
    aegis_report::sarif::validate_shape(&sarif)
        .unwrap_or_else(|error| panic!("sarif invalid: {error}"));

    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("aegis-chain"));
    assert!(sarif.contains("critical-new-package-needs-sbom"));
    assert!(sarif.contains("\"level\": \"error\""));

    let terminal = aegis_report::terminal::render(&report);
    assert!(terminal.contains("Overall status: BLOCK"));
    assert!(terminal.contains("unicode-width"));
}
