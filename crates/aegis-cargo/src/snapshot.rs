use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use aegis_core::model::{
    DependencyEdge, DependencyKind, DependencySnapshot, PackageKey, PackageNode,
    SNAPSHOT_SCHEMA_VERSION,
};
use aegis_core::AegisError;
use cargo_metadata::{DependencyKind as MetadataDependencyKind, Metadata};

use crate::metadata::{load_metadata, MetadataOptions};

pub fn build_snapshot(options: &MetadataOptions) -> Result<DependencySnapshot, AegisError> {
    let metadata = load_metadata(options)?;
    convert_metadata(metadata)
}

fn convert_metadata(metadata: Metadata) -> Result<DependencySnapshot, AegisError> {
    let root_raw = metadata.workspace_root.as_str().to_string();

    let member_ids: HashSet<&str> = metadata
        .workspace_members
        .iter()
        .map(|id| id.repr.as_str())
        .collect();

    let mut key_by_id: HashMap<String, PackageKey> = HashMap::new();
    let mut ids: Vec<String> = Vec::new();
    let mut nodes: Vec<PackageNode> = Vec::new();

    for package in &metadata.packages {
        let key = PackageKey {
            name: package.name.to_string(),
            version: package.version.clone(),
            source: package.source.as_ref().map(|source| source.repr.clone()),
        };

        key_by_id.insert(package.id.repr.clone(), key.clone());
        ids.push(package.id.repr.clone());

        let manifest_path = relative_manifest_path(package.manifest_path.as_str(), &root_raw);

        nodes.push(PackageNode {
            key,
            manifest_path: Some(manifest_path),
            is_workspace_member: member_ids.contains(package.id.repr.as_str()),
            dependency_kinds: BTreeSet::new(),
            enabled_features: BTreeSet::new(),
        });
    }

    let resolve = metadata.resolve.as_ref().ok_or_else(|| {
        AegisError::Runtime(
            "`cargo metadata` returned no resolve graph; run without --no-deps".to_string(),
        )
    })?;

    let mut edge_map: BTreeMap<(PackageKey, PackageKey), BTreeSet<DependencyKind>> =
        BTreeMap::new();
    let mut features_by_id: HashMap<&str, BTreeSet<String>> = HashMap::new();

    for node in &resolve.nodes {
        features_by_id.insert(
            node.id.repr.as_str(),
            node.features
                .iter()
                .map(|feature| feature.to_string())
                .collect(),
        );

        let from = key_by_id.get(node.id.repr.as_str()).ok_or_else(|| {
            AegisError::Runtime(format!(
                "resolve node {} is missing from the package list",
                node.id.repr
            ))
        })?;

        for dep in &node.deps {
            let to = key_by_id.get(dep.pkg.repr.as_str()).ok_or_else(|| {
                AegisError::Runtime(format!(
                    "resolve dependency {} is missing from the package list",
                    dep.pkg.repr
                ))
            })?;

            for info in &dep.dep_kinds {
                if let Some(kind) = map_dependency_kind(info.kind) {
                    edge_map
                        .entry((from.clone(), to.clone()))
                        .or_default()
                        .insert(kind);
                }
            }
        }
    }

    let mut edges = BTreeSet::new();
    for ((from, to), kinds) in edge_map {
        edges.insert(DependencyEdge { from, to, kinds });
    }

    let mut kinds_by_key: HashMap<&PackageKey, BTreeSet<DependencyKind>> = HashMap::new();
    for edge in &edges {
        kinds_by_key
            .entry(&edge.from)
            .or_default()
            .extend(edge.kinds.iter().copied());
    }

    let mut packages: BTreeSet<PackageNode> = BTreeSet::new();
    for (id, node) in ids.into_iter().zip(nodes) {
        packages.insert(PackageNode {
            dependency_kinds: kinds_by_key.get(&node.key).cloned().unwrap_or_default(),
            enabled_features: features_by_id.get(id.as_str()).cloned().unwrap_or_default(),
            ..node
        });
    }

    let workspace_members: BTreeSet<PackageKey> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| key_by_id.get(&id.repr).cloned())
        .collect();

    Ok(DependencySnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        git_revision: None,
        workspace_root: normalize_separators(&root_raw),
        packages,
        edges,
        workspace_members,
        cargo_metadata_format_version: 1,
    })
}

fn map_dependency_kind(kind: MetadataDependencyKind) -> Option<DependencyKind> {
    match kind {
        MetadataDependencyKind::Normal => Some(DependencyKind::Normal),
        MetadataDependencyKind::Development => Some(DependencyKind::Dev),
        MetadataDependencyKind::Build => Some(DependencyKind::Build),
        _ => None,
    }
}

fn relative_manifest_path(manifest_path: &str, workspace_root: &str) -> String {
    let manifest = strip_verbatim_prefix(manifest_path);
    let root = strip_verbatim_prefix(workspace_root);

    Path::new(manifest)
        .strip_prefix(root)
        .map(|relative| normalize_separators(relative.to_string_lossy().as_ref()))
        .unwrap_or_else(|_| normalize_separators(manifest))
}

fn strip_verbatim_prefix(path: &str) -> &str {
    path.strip_prefix(r"\\?\").unwrap_or(path)
}

fn normalize_separators(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_path_inside_workspace_is_relativized() {
        let sep = std::path::MAIN_SEPARATOR_STR;
        let manifest = format!("C:{sep}ws{sep}app{sep}Cargo.toml");
        let root = format!("C:{sep}ws");
        let path = relative_manifest_path(&manifest, &root);
        assert_eq!(path, normalize_separators(&format!("app{sep}Cargo.toml")));
    }

    #[test]
    fn manifest_path_outside_workspace_stays_absolute() {
        let sep = std::path::MAIN_SEPARATOR_STR;
        let manifest = format!("D:{sep}other{sep}Cargo.toml");
        let root = format!("C:{sep}ws");
        let path = relative_manifest_path(&manifest, &root);
        assert_eq!(path, normalize_separators(&manifest));
    }

    #[test]
    fn unix_style_paths_pass_through_normalized() {
        let path = relative_manifest_path("/home/user/ws/lib/Cargo.toml", "/home/user/ws");
        assert_eq!(path, "lib/Cargo.toml");
    }

    #[test]
    fn dependency_kinds_are_mapped() {
        assert_eq!(
            map_dependency_kind(MetadataDependencyKind::Normal),
            Some(DependencyKind::Normal)
        );
        assert_eq!(
            map_dependency_kind(MetadataDependencyKind::Development),
            Some(DependencyKind::Dev)
        );
        assert_eq!(
            map_dependency_kind(MetadataDependencyKind::Build),
            Some(DependencyKind::Build)
        );
    }
}
