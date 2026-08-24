use std::collections::BTreeSet;

use aegis_core::diff::{classify_changes, ChangeKind};
use aegis_core::model::{DependencySnapshot, PackageKey};
use semver::Version;

fn registry(name: &str, major: u64, minor: u64, patch: u64) -> PackageKey {
    PackageKey {
        name: name.to_string(),
        version: Version::new(major, minor, patch),
        source: Some("registry+https://github.com/rust-lang/crates.io-index".to_string()),
    }
}

fn local(name: &str, major: u64, minor: u64, patch: u64) -> PackageKey {
    PackageKey {
        name: name.to_string(),
        version: Version::new(major, minor, patch),
        source: None,
    }
}

fn snapshot_with(keys: &[PackageKey]) -> DependencySnapshot {
    let mut packages = BTreeSet::new();
    let mut members = BTreeSet::new();
    for key in keys {
        let is_member = key.source.is_none();
        packages.insert(aegis_core::model::PackageNode {
            key: key.clone(),
            manifest_path: None,
            is_workspace_member: is_member,
            dependency_kinds: BTreeSet::new(),
            enabled_features: BTreeSet::new(),
        });
        if is_member {
            members.insert(key.clone());
        }
    }
    DependencySnapshot {
        schema_version: 1,
        tool_version: "test".to_string(),
        git_revision: None,
        workspace_root: "/ws".to_string(),
        packages,
        edges: BTreeSet::new(),
        workspace_members: members,
        cargo_metadata_format_version: 1,
    }
}

#[test]
fn detects_minor_upgrade() {
    let base = snapshot_with(&[registry("lib", 1, 2, 9)]);
    let head = snapshot_with(&[registry("lib", 1, 3, 0)]);

    let changes = classify_changes(&base, &head);

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, ChangeKind::MinorUpgrade);
    assert_eq!(
        changes[0].before.as_ref().unwrap().version,
        Version::new(1, 2, 9)
    );
    assert_eq!(
        changes[0].after.as_ref().unwrap().version,
        Version::new(1, 3, 0)
    );
}

#[test]
fn detects_major_patch_and_downgrade() {
    let cases = [
        ((1u64, 0u64, 0u64), (2, 0, 0), ChangeKind::MajorUpgrade),
        ((1, 0, 0), (1, 0, 1), ChangeKind::PatchUpgrade),
        ((1, 2, 0), (1, 1, 0), ChangeKind::Downgrade),
    ];

    for ((bmaj, bmin, bpat), (hmaj, hmin, hpat), expected) in cases {
        let base = snapshot_with(&[registry("lib", bmaj, bmin, bpat)]);
        let head = snapshot_with(&[registry("lib", hmaj, hmin, hpat)]);

        let changes = classify_changes(&base, &head);

        assert_eq!(
            changes.len(),
            1,
            "{bmaj}.{bmin}.{bpat} -> {hmaj}.{hmin}.{hpat}"
        );
        assert_eq!(changes[0].kind, expected);
    }
}

#[test]
fn detects_added_and_removed() {
    let base = snapshot_with(&[local("app", 0, 1, 0), registry("old", 1, 0, 0)]);
    let head = snapshot_with(&[local("app", 0, 1, 0), registry("new", 1, 0, 0)]);

    let changes = classify_changes(&base, &head);

    let kinds: Vec<_> = changes.iter().map(|change| change.kind).collect();
    assert!(kinds.contains(&ChangeKind::Added));
    assert!(kinds.contains(&ChangeKind::Removed));
}

#[test]
fn added_and_removed_never_overlap_for_same_coordinate() {
    let base = snapshot_with(&[registry("a", 1, 0, 0), registry("b", 1, 0, 0)]);
    let head = snapshot_with(&[registry("b", 1, 0, 0), registry("c", 1, 0, 0)]);

    let changes = classify_changes(&base, &head);

    let added: Vec<&str> = changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Added)
        .map(|change| change.name.as_str())
        .collect();
    let removed: Vec<&str> = changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Removed)
        .map(|change| change.name.as_str())
        .collect();

    assert_eq!(added, vec!["c"]);
    assert_eq!(removed, vec!["a"]);
}

#[test]
fn source_mutation_detected_for_same_name_and_version() {
    let original = registry("lib", 1, 0, 0);
    let base = snapshot_with(std::slice::from_ref(&original));

    let forked = PackageKey {
        source: Some("git+https://example.com/fork".to_string()),
        ..original.clone()
    };
    let head = snapshot_with(&[forked]);

    let changes = classify_changes(&base, &head);

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, ChangeKind::SourceMutation);
    assert_eq!(changes[0].before.as_ref().unwrap(), &original);
}

#[test]
fn identical_snapshots_produce_no_changes() {
    let snapshot = snapshot_with(&[registry("lib", 1, 0, 0), local("app", 0, 1, 0)]);
    assert!(classify_changes(&snapshot, &snapshot).is_empty());
}

#[test]
fn changes_sorted_deterministically_by_name_then_version() {
    let base = snapshot_with(&[
        registry("zlib", 1, 0, 0),
        registry("alib", 1, 0, 0),
        registry("mlib", 1, 0, 5),
    ]);
    let head = snapshot_with(&[
        registry("zlib", 1, 1, 0),
        registry("alib", 2, 0, 0),
        registry("mlib", 1, 0, 9),
        registry("newlib", 1, 0, 0),
    ]);

    let changes = classify_changes(&base, &head);
    let names: Vec<&str> = changes.iter().map(|change| change.name.as_str()).collect();

    let mut expected = names.clone();
    expected.sort();
    assert_eq!(names, expected);
}
