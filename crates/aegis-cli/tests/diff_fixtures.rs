use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use aegis_cargo::{build_snapshot, MetadataOptions};
use aegis_core::diff::ChangeKind;
use aegis_core::model::{DependencySnapshot, PackageKey, PackageNode};
use aegis_core::pipeline;
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
