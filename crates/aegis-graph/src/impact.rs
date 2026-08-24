use std::collections::{BTreeMap, BTreeSet, VecDeque};

use std::fmt::Display;

use crate::dependency_graph::DependencyGraph;

pub const MAX_PATHS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactResult<K: Ord + Clone> {
    pub impacted_roots: Vec<K>,
    pub root_distances: Vec<usize>,
    pub paths: Vec<String>,
}

struct BfsEntry<K: Ord + Clone> {
    parent: Option<K>,
    depth: usize,
}

pub fn analyze_impact<K: Ord + Clone + Display>(
    graph: &DependencyGraph<K>,
    changed: &K,
    workspace_members: &BTreeSet<K>,
) -> ImpactResult<K> {
    let mut entries: BTreeMap<K, BfsEntry<K>> = BTreeMap::new();
    entries.insert(
        changed.clone(),
        BfsEntry {
            parent: None,
            depth: 0,
        },
    );

    let mut queue: VecDeque<K> = VecDeque::new();
    queue.push_back(changed.clone());

    while let Some(current) = queue.pop_front() {
        let current_depth = entries.get(&current).map(|entry| entry.depth).unwrap_or(0);
        if let Some(dependents) = graph.dependents(&current) {
            for dependent in dependents {
                if !entries.contains_key(dependent) {
                    entries.insert(
                        dependent.clone(),
                        BfsEntry {
                            parent: Some(current.clone()),
                            depth: current_depth + 1,
                        },
                    );
                    queue.push_back(dependent.clone());
                }
            }
        }
    }

    let mut impacted_roots: Vec<K> = entries
        .keys()
        .filter(|key| workspace_members.contains(key))
        .cloned()
        .collect();

    impacted_roots.sort();

    let root_distances: Vec<usize> = impacted_roots
        .iter()
        .map(|root| entries.get(root).map(|entry| entry.depth).unwrap_or(0))
        .collect();

    let mut paths: Vec<String> = impacted_roots
        .iter()
        .map(|root| reconstruct_path(&entries, root, changed))
        .collect();

    paths.sort();
    paths.truncate(MAX_PATHS);

    ImpactResult {
        impacted_roots,
        root_distances,
        paths,
    }
}

fn reconstruct_path<K: Ord + Clone + Display>(
    entries: &BTreeMap<K, BfsEntry<K>>,
    root: &K,
    changed: &K,
) -> String {
    let mut parts = vec![root.to_string()];
    let mut current = root;

    while current != changed {
        match entries.get(current).and_then(|entry| entry.parent.as_ref()) {
            Some(next) => {
                parts.push(next.to_string());
                current = next;
            }
            None => break,
        }
    }

    parts.join(" -> ")
}
