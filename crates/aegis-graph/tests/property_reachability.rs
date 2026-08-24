use std::collections::{BTreeMap, BTreeSet, VecDeque};

use proptest::prelude::*;

use aegis_graph::{analyze_impact, DependencyGraph};

const NODE_SPACE: u32 = 9;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct N(u32);

impl std::fmt::Display for N {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pkg{}", self.0)
    }
}

fn reaches_forward(adjacency: &BTreeMap<u32, Vec<u32>>, from: u32, target: u32) -> bool {
    let mut visited = BTreeSet::from([from]);
    let mut queue = VecDeque::from([from]);

    while let Some(current) = queue.pop_front() {
        if current == target {
            return true;
        }
        for next in adjacency.get(&current).cloned().unwrap_or_default() {
            if visited.insert(next) {
                queue.push_back(next);
            }
        }
    }

    false
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn reverse_reachability_matches_brute_force(
        edges in proptest::collection::vec((0u32..NODE_SPACE, 1u32..NODE_SPACE), 0..40),
        changed in 0u32..NODE_SPACE,
    ) {
        let deduped: BTreeSet<(u32, u32)> =
            edges.into_iter().filter(|(a, b)| a != b).collect();

        let mut adjacency: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for (from, to) in &deduped {
            adjacency.entry(*from).or_default().push(*to);
        }

        let mut graph: DependencyGraph<N> = DependencyGraph::new();
        let mut members: BTreeSet<N> = BTreeSet::new();
        for id in 0..NODE_SPACE {
            graph.add_node(N(id));
            if id % 3 == 0 {
                members.insert(N(id));
            }
        }
        for (from, to) in &deduped {
            graph.add_edge(N(*from), N(*to));
        }

        let result = analyze_impact(&graph, &N(changed), &members);

        for root in &result.impacted_roots {
            prop_assert!(reaches_forward(&adjacency, root.0, changed));
        }

        for id in (0..NODE_SPACE).step_by(3) {
            let expected = reaches_forward(&adjacency, id, changed);
            let found = result.impacted_roots.contains(&N(id));
            prop_assert_eq!(expected, found);
        }

        prop_assert!(result.paths.len() <= aegis_graph::MAX_PATHS);

        for path in &result.paths {
            let parts: Vec<&str> = path.split(" -> ").collect();
            let first = parts.first().copied().unwrap_or_default();
            let last = parts.last().copied().unwrap_or_default();
            prop_assert_eq!(last, format!("pkg{changed}"));
            let first_id: u32 = first.trim_start_matches("pkg").parse().unwrap();
            prop_assert!(first_id.is_multiple_of(3));
        }
    }
}
