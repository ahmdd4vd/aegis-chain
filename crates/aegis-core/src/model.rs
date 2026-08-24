use std::collections::BTreeSet;

use semver::Version;
use serde::{Deserialize, Serialize};

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageKey {
    pub name: String,
    pub version: Version,
    pub source: Option<String>,
}

impl PackageKey {
    pub fn source_family(&self) -> &'static str {
        match self.source.as_deref() {
            Some(source) if source.starts_with("registry+") => "registry",
            Some(source) if source.starts_with("git+") => "git",
            Some(_) => "unknown",
            None => "local",
        }
    }
}

impl std::fmt::Display for PackageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyKind {
    Normal,
    Dev,
    Build,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: PackageKey,
    pub to: PackageKey,
    pub kinds: BTreeSet<DependencyKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageNode {
    pub key: PackageKey,
    pub manifest_path: Option<String>,
    pub is_workspace_member: bool,
    pub dependency_kinds: BTreeSet<DependencyKind>,
    pub enabled_features: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySnapshot {
    pub schema_version: u32,
    pub tool_version: String,
    pub git_revision: Option<String>,
    pub workspace_root: String,
    pub packages: BTreeSet<PackageNode>,
    pub edges: BTreeSet<DependencyEdge>,
    pub workspace_members: BTreeSet<PackageKey>,
    pub cargo_metadata_format_version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, major: u64, minor: u64, patch: u64) -> PackageKey {
        PackageKey {
            name: name.to_string(),
            version: Version::new(major, minor, patch),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_string()),
        }
    }

    #[test]
    fn package_keys_sort_by_name_then_version() {
        let mut keys = [
            key("serde", 1, 0, 210),
            key("anyhow", 1, 0, 90),
            key("serde", 1, 0, 100),
        ];
        keys.sort();

        assert_eq!(keys[0].name, "anyhow");
        assert_eq!(keys[1].version, Version::new(1, 0, 100));
        assert_eq!(keys[2].version, Version::new(1, 0, 210));
    }

    #[test]
    fn same_name_and_version_with_different_source_are_distinct() {
        let registry = key("lib", 1, 0, 0);
        let git = PackageKey {
            source: Some("git+https://example.com/lib".to_string()),
            ..key("lib", 1, 0, 0)
        };

        assert_ne!(registry, git);
        assert_eq!(registry.source_family(), "registry");
        assert_eq!(git.source_family(), "git");
    }

    #[test]
    fn missing_source_means_local_package() {
        let local = PackageKey {
            source: None,
            ..key("app", 0, 1, 0)
        };
        assert_eq!(local.source_family(), "local");
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let app = PackageKey {
            source: None,
            ..key("app", 0, 1, 0)
        };
        let lib = key("serde", 1, 0, 210);

        let mut kinds = BTreeSet::new();
        kinds.insert(DependencyKind::Normal);

        let mut packages = BTreeSet::new();
        packages.insert(PackageNode {
            key: app.clone(),
            manifest_path: Some("app/Cargo.toml".to_string()),
            is_workspace_member: true,
            dependency_kinds: kinds.clone(),
            enabled_features: BTreeSet::new(),
        });
        packages.insert(PackageNode {
            key: lib.clone(),
            manifest_path: None,
            is_workspace_member: false,
            dependency_kinds: BTreeSet::new(),
            enabled_features: BTreeSet::new(),
        });

        let mut edges = BTreeSet::new();
        edges.insert(DependencyEdge {
            from: app.clone(),
            to: lib.clone(),
            kinds,
        });

        let mut members = BTreeSet::new();
        members.insert(app.clone());

        let snapshot = DependencySnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            tool_version: "0.1.0".to_string(),
            git_revision: None,
            workspace_root: "/tmp/workspace".to_string(),
            packages,
            edges,
            workspace_members: members,
            cargo_metadata_format_version: 1,
        };

        let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
        let parsed: DependencySnapshot = serde_json::from_str(&json).expect("deserialize snapshot");

        assert_eq!(parsed, snapshot);
    }
}
