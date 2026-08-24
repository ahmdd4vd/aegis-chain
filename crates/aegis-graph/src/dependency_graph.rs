use std::collections::{BTreeMap, BTreeSet};

use crate::reverse_index::ReverseIndex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyGraph<K: Ord + Clone> {
    nodes: BTreeSet<K>,
    forward: BTreeMap<K, BTreeSet<K>>,
    reverse: ReverseIndex<K>,
}

impl<K: Ord + Clone> Default for DependencyGraph<K> {
    fn default() -> Self {
        Self {
            nodes: BTreeSet::new(),
            forward: BTreeMap::new(),
            reverse: ReverseIndex::default(),
        }
    }
}

impl<K: Ord + Clone> DependencyGraph<K> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, key: K) {
        self.nodes.insert(key.clone());
        self.forward.entry(key).or_default();
    }

    pub fn add_edge(&mut self, from: K, to: K) {
        self.reverse.insert(&from, &to);
        self.nodes.insert(from.clone());
        self.nodes.insert(to.clone());
        self.forward.entry(from).or_default().insert(to);
    }

    pub fn contains_node(&self, key: &K) -> bool {
        self.nodes.contains(key)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &K> {
        self.nodes.iter()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn dependencies(&self, key: &K) -> Option<&BTreeSet<K>> {
        self.forward.get(key)
    }

    pub fn dependents(&self, key: &K) -> Option<&BTreeSet<K>> {
        self.reverse.dependents(key)
    }

    pub fn edge_count(&self) -> usize {
        self.forward.values().map(|targets| targets.len()).sum()
    }
}
