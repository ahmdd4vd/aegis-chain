use std::collections::BTreeSet;

use aegis_graph::{analyze_impact, DependencyGraph};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Pkg(&'static str);

impl std::fmt::Display for Pkg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn graph_from(edges: &[(Pkg, Pkg)]) -> DependencyGraph<Pkg> {
    let mut graph = DependencyGraph::new();
    for (from, to) in edges {
        graph.add_edge(from.clone(), to.clone());
    }
    graph
}

#[test]
fn forward_and_reverse_adjacency_are_consistent() {
    let app = Pkg("app");
    let lib = Pkg("lib");
    let core = Pkg("core");

    let graph = graph_from(&[(app.clone(), lib.clone()), (lib.clone(), core.clone())]);

    assert_eq!(graph.node_count(), 3);
    assert_eq!(graph.edge_count(), 2);
    assert!(graph.contains_node(&core));

    let dependents_of_lib = graph.dependents(&lib).expect("reverse entry exists");
    assert!(dependents_of_lib.contains(&app));

    let dependencies_of_app = graph.dependencies(&app).expect("forward entry exists");
    assert!(dependencies_of_app.contains(&lib));
}

#[test]
fn impact_finds_roots_through_transitive_paths() {
    let app = Pkg("app");
    let worker = Pkg("worker");
    let lib = Pkg("lib");
    let leaf = Pkg("leaf");

    let members = BTreeSet::from([app.clone(), worker.clone()]);
    let graph = graph_from(&[
        (app.clone(), lib.clone()),
        (worker.clone(), lib.clone()),
        (lib.clone(), leaf.clone()),
    ]);

    let result = analyze_impact(&graph, &leaf, &members);

    assert_eq!(result.impacted_roots.len(), 2);
    assert_eq!(result.impacted_roots[0], app);
    assert_eq!(result.impacted_roots[1], worker);
    assert_eq!(
        result.paths,
        vec!["app -> lib -> leaf", "worker -> lib -> leaf"]
    );
}

#[test]
fn unreachable_package_has_no_impact() {
    let app = Pkg("app");
    let isolated = Pkg("isolated");

    let members = BTreeSet::from([app.clone()]);
    let graph = DependencyGraph::new();

    let result = analyze_impact(&graph, &isolated, &members);
    assert!(result.impacted_roots.is_empty());
    assert!(result.paths.is_empty());
}

#[test]
fn changed_workspace_member_impacts_itself() {
    let app = Pkg("app");
    let lib = Pkg("lib");

    let members = BTreeSet::from([app.clone()]);
    let graph = graph_from(&[(app.clone(), lib.clone())]);

    let result = analyze_impact(&graph, &app, &members);

    assert_eq!(result.impacted_roots, vec![app]);
    assert_eq!(result.paths, vec!["app"]);
}
