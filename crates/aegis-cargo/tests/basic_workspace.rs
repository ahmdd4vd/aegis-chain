use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use aegis_cargo::{build_snapshot, MetadataOptions};
use aegis_core::model::{DependencyKind, DependencySnapshot, SNAPSHOT_SCHEMA_VERSION};

fn fixture_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/basic-workspace");
    assert!(dir.is_dir(), "fixture directory exists");
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

#[test]
fn snapshot_of_basic_workspace_fixture_is_correct_and_deterministic() {
    let dir = fixture_dir();
    ensure_lockfile(&dir);

    let options = MetadataOptions::new(dir.join("Cargo.toml"));
    let snapshot = build_snapshot(&options).expect("snapshot builds");

    assert_eq!(snapshot.schema_version, SNAPSHOT_SCHEMA_VERSION);

    let member_names: Vec<&str> = snapshot
        .workspace_members
        .iter()
        .map(|key| key.name.as_str())
        .collect();
    assert_eq!(member_names, vec!["basic-app", "basic-lib"]);

    for member in &snapshot.workspace_members {
        let node = snapshot
            .packages
            .iter()
            .find(|node| &node.key == member)
            .unwrap_or_else(|| panic!("node missing for workspace member {}", member.name));
        assert!(node.is_workspace_member);
    }

    let semver_node = snapshot
        .packages
        .iter()
        .find(|node| node.key.name == "semver")
        .expect("registry dependency semver present in snapshot");
    assert_eq!(semver_node.key.source_family(), "registry");

    let app_to_lib = snapshot
        .edges
        .iter()
        .find(|edge| edge.from.name == "basic-app" && edge.to.name == "basic-lib")
        .expect("edge basic-app -> basic-lib");
    assert!(app_to_lib.kinds.contains(&DependencyKind::Normal));

    let app_to_semver = snapshot
        .edges
        .iter()
        .find(|edge| edge.from.name == "basic-app" && edge.to.name == "semver")
        .expect("edge basic-app -> semver");
    assert!(app_to_semver.kinds.contains(&DependencyKind::Normal));

    let lib_outgoing: Vec<_> = snapshot
        .edges
        .iter()
        .filter(|edge| edge.from.name == "basic-lib")
        .collect();
    assert!(lib_outgoing.is_empty());

    let json_one = serde_json::to_string_pretty(&snapshot).expect("serialize snapshot");
    let snapshot_again = build_snapshot(&options).expect("second snapshot builds");
    let json_two = serde_json::to_string_pretty(&snapshot_again).expect("serialize again");
    assert_eq!(json_one, json_two, "snapshot output must be deterministic");

    let parsed: DependencySnapshot = serde_json::from_str(&json_one).expect("deserialize snapshot");
    assert_eq!(parsed, snapshot);
}
