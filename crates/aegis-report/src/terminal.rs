use std::collections::BTreeMap;

use aegis_core::decision::DecisionReport;

pub fn render(report: &DecisionReport) -> String {
    let mut out = String::new();

    if report.changes.is_empty() {
        out.push_str("No dependency changes detected.\n");
        return out;
    }

    let mut summary: BTreeMap<&'static str, usize> = BTreeMap::new();
    for change in &report.changes {
        *summary.entry(change.kind.label()).or_default() += 1;
    }
    let breakdown: Vec<String> = summary
        .into_iter()
        .map(|(label, count)| format!("{count} {label}"))
        .collect();

    out.push_str(&format!(
        "Aegis diff report (schema v{})\n",
        report.schema_version
    ));
    out.push_str(&format!(
        "Changes: {} ({})\n",
        report.changes.len(),
        breakdown.join(", ")
    ));

    if let Some(policy) = &report.policy {
        out.push_str(&format!(
            "Overall status: {} (formula {})\n",
            policy.overall_status.label().to_uppercase(),
            policy.formula_version
        ));
    }

    for decision in &report.decisions {
        let change = &decision.change;
        let kind_label = change.kind.label().to_uppercase();
        out.push('\n');
        match (&change.before, &change.after) {
            (Some(before), Some(after)) => out.push_str(&format!(
                "[{kind_label}] {} {} -> {}\n",
                change.name, before.version, after.version
            )),
            (None, Some(after)) => out.push_str(&format!(
                "[{kind_label}] {} {}\n",
                change.name, after.version
            )),
            (Some(before), None) => out.push_str(&format!(
                "[{kind_label}] {} {}\n",
                change.name, before.version
            )),
            (None, None) => continue,
        }

        out.push_str(&format!(
            "  Status: {} | Risk: {}/100 ({})\n",
            decision.status.label().to_uppercase(),
            decision.score,
            decision.level
        ));

        if !decision.matched_rules.is_empty() {
            out.push_str(&format!(
                "  Matched rules: {}\n",
                decision.matched_rules.join(", ")
            ));
        }

        if change.impacted_roots.is_empty() {
            out.push_str("  Impacted roots: (none)\n");
        } else {
            let roots: Vec<String> = change
                .impacted_roots
                .iter()
                .map(|root| root.name.clone())
                .collect();
            out.push_str(&format!("  Impacted roots: {}\n", roots.join(", ")));
        }

        if !change.paths.is_empty() {
            out.push_str("  Paths:\n");
            for path in &change.paths {
                out.push_str(&format!("    {path}\n"));
            }
        }
    }

    out
}
