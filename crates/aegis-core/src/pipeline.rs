use aegis_graph::{analyze_impact, DependencyGraph};

use crate::diff::{classify_changes, DiffReport, PackageChange, DIFF_REPORT_SCHEMA_VERSION};
use crate::model::{DependencySnapshot, PackageKey};

pub fn run_diff(base: &DependencySnapshot, head: &DependencySnapshot) -> DiffReport {
    let classified = classify_changes(base, head);
    let base_graph = graph_of(base);
    let head_graph = graph_of(head);

    let changes = classified
        .into_iter()
        .map(|change| enrich_with_impact(change, base, head, &base_graph, &head_graph))
        .collect();

    DiffReport {
        schema_version: DIFF_REPORT_SCHEMA_VERSION,
        changes,
    }
}

pub(crate) fn graph_of(snapshot: &DependencySnapshot) -> DependencyGraph<PackageKey> {
    let mut graph = DependencyGraph::new();
    for node in &snapshot.packages {
        graph.add_node(node.key.clone());
    }
    for edge in &snapshot.edges {
        graph.add_edge(edge.from.clone(), edge.to.clone());
    }
    graph
}

fn enrich_with_impact(
    mut change: PackageChange,
    base: &DependencySnapshot,
    head: &DependencySnapshot,
    base_graph: &DependencyGraph<PackageKey>,
    head_graph: &DependencyGraph<PackageKey>,
) -> PackageChange {
    let uses_head = change.after.is_some();
    let reference_snapshot = if uses_head { head } else { base };
    let reference_graph = if uses_head { head_graph } else { base_graph };

    if let Some(changed_key) = change.after.as_ref().or(change.before.as_ref()) {
        let impact = analyze_impact(
            reference_graph,
            changed_key,
            &reference_snapshot.workspace_members,
        );
        change.impacted_roots = impact.impacted_roots;
        change.paths = impact.paths;
    }

    change
}
