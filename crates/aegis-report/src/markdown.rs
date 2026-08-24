use aegis_core::decision::{ChangeDecision, DecisionReport};
use aegis_core::diff::{ChangeKind, PackageChange};
use aegis_policy::Action;

fn status_icon(status: Action) -> &'static str {
    match status {
        Action::Pass => "white_check_mark",
        Action::Warn => "warning",
        Action::Block => "no_entry",
    }
}

fn overall_label(report: &DecisionReport) -> String {
    match &report.policy {
        Some(summary) => format!(
            "{} {}",
            summary.overall_status.label().to_uppercase(),
            match summary.overall_status {
                Action::Pass => ":white_check_mark:",
                Action::Warn => ":warning:",
                Action::Block => ":no_entry_sign:",
            }
        ),
        None => "ANALYSIS ONLY".to_string(),
    }
}

fn change_summary(report: &DecisionReport) -> String {
    if report.changes.is_empty() {
        return "0".to_string();
    }
    let mut counts: Vec<(&'static str, usize)> = Vec::new();
    for kind in [
        ChangeKind::Added,
        ChangeKind::Removed,
        ChangeKind::MajorUpgrade,
        ChangeKind::MinorUpgrade,
        ChangeKind::PatchUpgrade,
        ChangeKind::Downgrade,
        ChangeKind::SourceMutation,
    ] {
        let count = report
            .changes
            .iter()
            .filter(|change| change.kind == kind)
            .count();
        if count > 0 {
            counts.push((kind.label(), count));
        }
    }
    let breakdown: Vec<String> = counts
        .iter()
        .map(|(label, count)| format!("{count} {label}"))
        .collect();
    format!("{} ({})", report.changes.len(), breakdown.join(", "))
}

fn version_span(change: &PackageChange) -> String {
    match (&change.before, &change.after) {
        (Some(before), Some(after)) => format!("{} → {}", before.version, after.version),
        (None, Some(after)) => after.version.to_string(),
        (Some(before), None) => before.version.to_string(),
        (None, None) => "—".to_string(),
    }
}

pub fn render(report: &DecisionReport) -> String {
    let mut out = String::new();

    out.push_str("<!-- aegis-chain:report:v1 -->\n");
    out.push_str("## Aegis Chain Report\n\n");
    out.push_str(&format!("**Status:** {}\n", overall_label(report)));
    out.push_str(&format!("**Changes:** {}\n", change_summary(report)));
    if let Some(policy) = &report.policy {
        out.push_str(&format!("**Formula:** `{}`\n", policy.formula_version));
    }
    out.push('\n');

    if report.decisions.is_empty() {
        if report.changes.is_empty() {
            out.push_str("No dependency changes were detected.\n");
        } else {
            out.push_str("| Package | Change | Version | Impacted roots |\n");
            out.push_str("| --- | --- | --- | --- |\n");
            for change in &report.changes {
                let roots: Vec<String> = change
                    .impacted_roots
                    .iter()
                    .map(|root| root.name.clone())
                    .collect();
                out.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    change.name,
                    change.kind.label(),
                    version_span(change),
                    if roots.is_empty() {
                        "—".to_string()
                    } else {
                        roots.join(", ")
                    }
                ));
            }
            out.push_str("\n> Run with `--policy` to get risk scores and gate statuses.\n");
        }
        return out;
    }

    out.push_str("| Package | Change | Version | Risk | Impacted roots | Status |\n");
    out.push_str("| --- | --- | --- | ---: | --- | --- |\n");
    for decision in &report.decisions {
        let roots: Vec<String> = decision
            .change
            .impacted_roots
            .iter()
            .map(|root| root.name.clone())
            .collect();
        out.push_str(&format!(
            "| {} | {} | {} | {}/100 ({}) | {} | {} :{}: |\n",
            decision.change.name,
            decision.change.kind.label(),
            version_span(&decision.change),
            decision.score,
            decision.level,
            if roots.is_empty() {
                "—".to_string()
            } else {
                roots.join(", ")
            },
            decision.status.label().to_uppercase(),
            status_icon(decision.status),
        ));
    }

    out.push_str("\n### Why does this need review?\n\n");
    for decision in &report.decisions {
        if decision.status == Action::Pass && decision.matched_rules.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "- **{}** ({}): risk {}/100 ({})\n",
            decision.change.name,
            decision.change.kind.label(),
            decision.score,
            decision.level
        ));
        for rule_id in &decision.matched_rules {
            let message = decision
                .traces
                .iter()
                .find(|trace| trace.rule_id == *rule_id)
                .and_then(|trace| trace.message.clone());
            match message {
                Some(message) => out.push_str(&format!("  - rule `{rule_id}`: {message}\n")),
                None => out.push_str(&format!("  - rule `{rule_id}`\n")),
            }
        }
    }

    let with_paths: Vec<&ChangeDecision> = report
        .decisions
        .iter()
        .filter(|decision| !decision.change.paths.is_empty())
        .collect();
    if !with_paths.is_empty() {
        out.push_str("\n<details>\n<summary>Impact paths</summary>\n\n");
        for decision in with_paths {
            out.push_str(&format!("**{}**\n\n", decision.change.name));
            for path in &decision.change.paths {
                out.push_str(&format!("- `{path}`\n"));
            }
            out.push('\n');
        }
        out.push_str("</details>\n");
    }

    out
}
