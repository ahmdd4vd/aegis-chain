use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseIndex<K: Ord + Clone>(BTreeMap<K, BTreeSet<K>>);

impl<K: Ord + Clone> Default for ReverseIndex<K> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<K: Ord + Clone> ReverseIndex<K> {
    pub fn insert(&mut self, dependent: &K, dependency: &K) {
        self.0
            .entry(dependency.clone())
            .or_default()
            .insert(dependent.clone());
    }

    pub fn dependents(&self, dependency: &K) -> Option<&BTreeSet<K>> {
        self.0.get(dependency)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
