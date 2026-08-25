use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use aegis_cargo::{build_snapshot, MetadataOptions};
use aegis_core::diff::ChangeKind;
use aegis_core::model::{DependencySnapshot, PackageKey, PackageNode};
use aegis_core::pipeline;
use aegis_policy::parse_policy;
use semver::Version;

fn fixture_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    assert!(dir.is_dir(), "fixture {name} exists");
    dir
}

fn ensure_lockfile(dir: &Path) {
    let status = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(dir)
        .status()
        .expect("failed to spawn cargo generate-lockfile");
    assert!(status.success(), "cargo generate-lockfile failed");
}

fn snapshot_of(name: &str) -> DependencySnapshot {
    let dir = fixture_dir(name);
    ensure_lockfile(&dir);
    build_snapshot(&MetadataOptions::new(dir.join("Cargo.toml"))).expect("snapshot builds")
}

fn semver_key(snapshot: &DependencySnapshot) -> PackageKey {
    snapshot
        .packages
        .iter()
        .find(|node| node.key.name == "semver")
        .expect("semver present")
        .key
        .clone()
}

fn substituted(
    original: &DependencySnapshot,
    old: &PackageKey,
    new: &PackageKey,
) -> DependencySnapshot {
    let mut snapshot = original.clone();
    snapshot.packages = original
        .packages
        .iter()
        .map(|node| {
            if &node.key == old {
                PackageNode {
                    key: new.clone(),
                    ..node.clone()
                }
            } else {
                node.clone()
            }
        })
        .collect();
    snapshot.edges = original
        .edges
        .iter()
        .map(|edge| {
            let mut edge = edge.clone();
            if edge.from == *old {
                edge.from = new.clone();
            }
            if edge.to == *old {
                edge.to = new.clone();
            }
            edge
        })
        .collect();
    snapshot.workspace_members = original.workspace_members.clone();
    snapshot
}

#[test]
fn real_fixtures_detect_added_and_removed_with_impact() {
    let basic = snapshot_of("basic-workspace");
    let added = snapshot_of("added-package-workspace");

    let forward = pipeline::run_diff(&basic, &added);
    let added_change = forward
        .changes
        .iter()
        .find(|change| change.kind == ChangeKind::Added && change.name == "unicode-width")
        .expect("unicode-width detected as added");
    assert_eq!(added_change.impacted_roots.len(), 1);
    assert_eq!(added_change.impacted_roots[0].name, "basic-app");
    assert!(added_change
        .paths
        .contains(&"basic-app -> unicode-width".to_string()));

    let reverse = pipeline::run_diff(&added, &basic);
    let removed_change = reverse
        .changes
        .iter()
        .find(|change| change.kind == ChangeKind::Removed && change.name == "unicode-width")
        .expect("unicode-width detected as removed");
    assert_eq!(removed_change.impacted_roots.len(), 1);
    assert_eq!(removed_change.impacted_roots[0].name, "basic-app");
}

#[test]
fn mutated_snapshots_produce_minor_upgrade_and_source_mutation() {
    let basic = snapshot_of("basic-workspace");

    let identical = pipeline::run_diff(&basic, &basic);
    assert!(identical.changes.is_empty());

    let current = semver_key(&basic);
    let bumped = PackageKey {
        version: Version::new(1, 1, 0),
        ..current.clone()
    };
    let upgraded_report = pipeline::run_diff(&basic, &substituted(&basic, &current, &bumped));
    let upgrade = upgraded_report
        .changes
        .iter()
        .find(|change| change.name == "semver")
        .expect("semver change found");
    assert_eq!(upgrade.kind, ChangeKind::MinorUpgrade);
    assert_eq!(
        upgrade.after.as_ref().unwrap().version,
        Version::new(1, 1, 0)
    );
    assert_eq!(upgrade.impacted_roots[0].name, "basic-app");
    assert!(upgrade.paths.contains(&"basic-app -> semver".to_string()));

    let forked = PackageKey {
        source: Some("git+https://example.com/semver-fork".to_string()),
        ..current.clone()
    };
    let mutation_report = pipeline::run_diff(&basic, &substituted(&basic, &current, &forked));
    let mutation = mutation_report
        .changes
        .iter()
        .find(|change| change.name == "semver")
        .expect("semver change found");
    assert_eq!(mutation.kind, ChangeKind::SourceMutation);
    assert_eq!(
        mutation.before.as_ref().unwrap().source_family(),
        "registry"
    );
    assert_eq!(mutation.after.as_ref().unwrap().source_family(), "git");
}

#[test]
fn critical_path_rule_fires_when_change_reaches_critical_member() {
    let snapshot = snapshot_of("critical-path-workspace");

    let current = semver_key(&snapshot);
    let bumped = PackageKey {
        version: Version::new(1, 1, 0),
        ..current.clone()
    };
    let head = substituted(&snapshot, &current, &bumped);

    let policy = aegis_policy::parse_policy(
        "schema_version: 1\n\
         critical_packages:\n  - critical-app\nthresholds:\n  warn_at: 30\n  high_at: 60\n  block_at: 80\nrules:\n  - id: critical-path-touched\n    when:\n      touches_critical: true\n    action: warn\n    message: \"change reaches a critical path\"\n",
    )
    .expect("policy parses");

    let report = aegis_core::run_decision(
        &snapshot,
        &head,
        Some(&policy),
        &Default::default(),
        None,
        None,
    );

    let decision = report
        .decisions
        .iter()
        .find(|decision| decision.change.name == "semver")
        .expect("semver decision present");
    assert!(
        decision
            .matched_rules
            .contains(&"critical-path-touched".to_string()),
        "rule touching critical path should fire"
    );
    assert_eq!(decision.status.label(), "warn");
}

#[test]
fn renamed_source_mutation_via_cross_family_pairing() {
    let snapshot = snapshot_of("renamed-dependency-workspace");

    let current = semver_key(&snapshot);
    let git = PackageKey {
        source: Some("git+https://example.com/semver.git".to_string()),
        ..current.clone()
    };
    let head = substituted(&snapshot, &current, &git);

    let report = pipeline::run_diff(&snapshot, &head);
    let change = report
        .changes
        .iter()
        .find(|change| change.name == "semver")
        .expect("semver change present");
    assert_eq!(change.kind, ChangeKind::SourceMutation);
    assert_eq!(change.before.as_ref().unwrap().source_family(), "registry");
    assert_eq!(change.after.as_ref().unwrap().source_family(), "git");
}

#[test]
fn scan_command_runs_on_fixture_without_policy() {
    let dir = fixture_dir("basic-workspace");
    ensure_lockfile(&dir);

    let output = Command::new(env!("CARGO_BIN_EXE_aegis"))
        .arg("scan")
        .arg("--manifest-path")
        .arg(dir.join("Cargo.toml"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("spawn aegis scan");

    assert!(
        output.status.success(),
        "scan should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("schema_version"),
        "scan should emit a JSON report"
    );
}

struct FixedAdvisory(f64);

impl aegis_core::AdvisorySource for FixedAdvisory {
    fn severity_for(&self, _name: &str, _version: &semver::Version) -> Option<f64> {
        Some(self.0)
    }
}

#[test]
fn advisory_finding_raises_risk_score() {
    let basic = snapshot_of("basic-workspace");
    let current = semver_key(&basic);
    let bumped = PackageKey {
        version: Version::new(1, 1, 0),
        ..current.clone()
    };
    let head = substituted(&basic, &current, &bumped);

    let policy = parse_policy(
        "schema_version: 1\nthresholds:\n  warn_at: 30\n  high_at: 60\n  block_at: 80\nrules: []\n",
    )
    .expect("policy parses");

    let without = aegis_core::run_decision(
        &basic,
        &head,
        Some(&policy),
        &Default::default(),
        None,
        None,
    );
    let with = aegis_core::run_decision(
        &basic,
        &head,
        Some(&policy),
        &Default::default(),
        Some(&FixedAdvisory(1.0)),
        None,
    );

    let score_without = without
        .decisions
        .iter()
        .find(|decision| decision.change.name == "semver")
        .expect("semver decision")
        .score;
    let score_with = with
        .decisions
        .iter()
        .find(|decision| decision.change.name == "semver")
        .expect("semver decision")
        .score;

    assert!(
        score_with > score_without,
        "advisory should raise the risk score: {score_with} <= {score_without}"
    );
}

struct FixedProvenance(bool);

impl aegis_core::ProvenanceSource for FixedProvenance {
    fn has_provenance(&self, _name: &str, _version: &semver::Version) -> bool {
        self.0
    }
}

#[test]
fn provenance_verification_lowers_evidence_gap() {
    let snapshot = snapshot_of("critical-path-workspace");
    let current = semver_key(&snapshot);
    let bumped = PackageKey {
        version: Version::new(1, 1, 0),
        ..current.clone()
    };
    let head = substituted(&snapshot, &current, &bumped);

    let policy = parse_policy(
        "schema_version: 1\n\
         critical_packages:\n  - critical-app\n\
         thresholds:\n  warn_at: 30\n  high_at: 60\n  block_at: 80\n\
         evidence:\n  require_for_critical_path:\n    - provenance\n\
         rules: []\n",
    )
    .expect("policy parses");

    let without = aegis_core::run_decision(
        &snapshot,
        &head,
        Some(&policy),
        &Default::default(),
        None,
        None,
    );
    let with = aegis_core::run_decision(
        &snapshot,
        &head,
        Some(&policy),
        &Default::default(),
        None,
        Some(&FixedProvenance(true)),
    );

    let score_without = without
        .decisions
        .iter()
        .find(|decision| decision.change.name == "semver")
        .expect("semver decision")
        .score;
    let score_with = with
        .decisions
        .iter()
        .find(|decision| decision.change.name == "semver")
        .expect("semver decision")
        .score;

    assert!(
        score_with < score_without,
        "verified provenance should lower the risk score: {score_with} >= {score_without}"
    );
}
