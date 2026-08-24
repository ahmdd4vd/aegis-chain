use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::model::{DependencySnapshot, PackageKey};

pub const DIFF_REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    MajorUpgrade,
    MinorUpgrade,
    PatchUpgrade,
    Downgrade,
    SourceMutation,
}

impl ChangeKind {
    pub fn label(&self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::MajorUpgrade => "major upgrade",
            ChangeKind::MinorUpgrade => "minor upgrade",
            ChangeKind::PatchUpgrade => "patch upgrade",
            ChangeKind::Downgrade => "downgrade",
            ChangeKind::SourceMutation => "source mutation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct PackageChange {
    pub kind: ChangeKind,
    pub name: String,
    pub before: Option<PackageKey>,
    pub after: Option<PackageKey>,
    pub impacted_roots: Vec<PackageKey>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffReport {
    pub schema_version: u32,
    pub changes: Vec<PackageChange>,
}

type CoordinateMap = BTreeMap<(String, &'static str), BTreeMap<Version, PackageKey>>;

fn coordinate_of(key: &PackageKey) -> (String, &'static str) {
    (key.name.clone(), key.source_family())
}

fn index_by_coordinate(snapshot: &DependencySnapshot) -> CoordinateMap {
    let mut index: CoordinateMap = BTreeMap::new();
    for node in &snapshot.packages {
        index
            .entry(coordinate_of(&node.key))
            .or_default()
            .insert(node.key.version.clone(), node.key.clone());
    }
    index
}

fn classify_version_change(base: &Version, head: &Version) -> Option<ChangeKind> {
    if head > base {
        if head.major > base.major {
            Some(ChangeKind::MajorUpgrade)
        } else if head.minor > base.minor {
            Some(ChangeKind::MinorUpgrade)
        } else {
            Some(ChangeKind::PatchUpgrade)
        }
    } else if head < base {
        Some(ChangeKind::Downgrade)
    } else {
        None
    }
}

pub fn classify_changes(
    base: &DependencySnapshot,
    head: &DependencySnapshot,
) -> Vec<PackageChange> {
    let base_index = index_by_coordinate(base);
    let head_index = index_by_coordinate(head);

    let mut coordinates: BTreeSet<(String, &'static str)> = BTreeSet::new();
    coordinates.extend(base_index.keys().cloned());
    coordinates.extend(head_index.keys().cloned());

    let mut changes = Vec::new();

    for coordinate in coordinates {
        let base_versions = base_index.get(&coordinate);
        let head_versions = head_index.get(&coordinate);

        match (base_versions, head_versions) {
            (Some(base_versions), Some(head_versions)) => {
                let mut consumed: BTreeSet<Version> = BTreeSet::new();

                for (version, head_key) in head_versions {
                    match base_versions.get(version) {
                        Some(base_key) => {
                            if base_key.source != head_key.source {
                                changes.push(PackageChange {
                                    kind: ChangeKind::SourceMutation,
                                    name: coordinate.0.clone(),
                                    before: Some(base_key.clone()),
                                    after: Some(head_key.clone()),
                                    impacted_roots: Vec::new(),
                                    paths: Vec::new(),
                                });
                            }
                        }
                        None => {
                            let representative =
                                base_versions.keys().next_back().expect("non-empty");
                            if let Some(kind) = classify_version_change(representative, version) {
                                let before = base_versions
                                    .get(representative)
                                    .cloned()
                                    .expect("representative exists");
                                consumed.insert(representative.clone());
                                changes.push(PackageChange {
                                    kind,
                                    name: coordinate.0.clone(),
                                    before: Some(before),
                                    after: Some(head_key.clone()),
                                    impacted_roots: Vec::new(),
                                    paths: Vec::new(),
                                });
                            }
                        }
                    }
                }

                for (version, base_key) in base_versions {
                    if !head_versions.contains_key(version) && !consumed.contains(version) {
                        changes.push(PackageChange {
                            kind: ChangeKind::Removed,
                            name: coordinate.0.clone(),
                            before: Some(base_key.clone()),
                            after: None,
                            impacted_roots: Vec::new(),
                            paths: Vec::new(),
                        });
                    }
                }
            }
            (None, Some(head_versions)) => {
                for head_key in head_versions.values() {
                    changes.push(PackageChange {
                        kind: ChangeKind::Added,
                        name: coordinate.0.clone(),
                        before: None,
                        after: Some(head_key.clone()),
                        impacted_roots: Vec::new(),
                        paths: Vec::new(),
                    });
                }
            }
            (Some(base_versions), None) => {
                for base_key in base_versions.values() {
                    changes.push(PackageChange {
                        kind: ChangeKind::Removed,
                        name: coordinate.0.clone(),
                        before: Some(base_key.clone()),
                        after: None,
                        impacted_roots: Vec::new(),
                        paths: Vec::new(),
                    });
                }
            }
            (None, None) => unreachable!("coordinate came from one of the snapshots"),
        }
    }

    let mut paired = pair_cross_family_source_swaps(changes);

    paired.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| change_version(a).cmp(&change_version(b)))
    });

    paired
}

fn pair_cross_family_source_swaps(changes: Vec<PackageChange>) -> Vec<PackageChange> {
    let mut added_by_name: BTreeMap<String, Vec<PackageChange>> = BTreeMap::new();
    let mut removed_by_name: BTreeMap<String, Vec<PackageChange>> = BTreeMap::new();
    let mut others: Vec<PackageChange> = Vec::new();

    for change in changes {
        match change.kind {
            ChangeKind::Added => added_by_name
                .entry(change.name.clone())
                .or_default()
                .push(change),
            ChangeKind::Removed => removed_by_name
                .entry(change.name.clone())
                .or_default()
                .push(change),
            _ => others.push(change),
        }
    }

    let mut result = others;

    for (_, mut added_list) in added_by_name {
        for mut added_change in added_list.drain(..) {
            if let Some(removed_list) = removed_by_name.get_mut(&added_change.name) {
                if let Some(mut removed_change) = removed_list.pop() {
                    result.push(PackageChange {
                        kind: ChangeKind::SourceMutation,
                        name: added_change.name.clone(),
                        before: removed_change.before.take(),
                        after: added_change.after.take(),
                        impacted_roots: Vec::new(),
                        paths: Vec::new(),
                    });
                    continue;
                }
            }
            result.push(added_change);
        }
    }

    for (_, removed_list) in removed_by_name {
        result.extend(removed_list);
    }

    result
}

fn change_version(change: &PackageChange) -> Version {
    change
        .after
        .as_ref()
        .or(change.before.as_ref())
        .map(|key| key.version.clone())
        .unwrap_or_else(|| Version::new(0, 0, 0))
}
