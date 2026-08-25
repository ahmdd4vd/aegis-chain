use aegis_core::decision::{ChangeDecision, DecisionReport};
use aegis_core::diff::{ChangeKind, PackageChange};
use aegis_policy::Action;

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn status_class(status: Action) -> &'static str {
    match status {
        Action::Pass => "pass",
        Action::Warn => "warn",
        Action::Block => "block",
    }
}

fn overall_label(report: &DecisionReport) -> String {
    match &report.policy {
        Some(summary) => summary.overall_status.label().to_uppercase(),
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

fn roots_list(change: &PackageChange) -> String {
    if change.impacted_roots.is_empty() {
        return "—".to_string();
    }
    change
        .impacted_roots
        .iter()
        .map(|root| root.name.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render(report: &DecisionReport) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>Aegis Chain Report</title>\n");
    out.push_str("<style>\n");
    out.push_str(
        "body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:2rem;color:#1f2328;background:#fff}\n",
    );
    out.push_str("h1{margin:0 0 1rem;font-size:1.5rem}\n");
    out.push_str(".meta{color:#57606a;margin-bottom:1.5rem}\n");
    out.push_str("table{border-collapse:collapse;width:100%;margin-bottom:1.5rem}\n");
    out.push_str(
        "th,td{border:1px solid #d0d7de;padding:.5rem .75rem;text-align:left;font-size:.9rem}\n",
    );
    out.push_str("th{background:#f6f8fa}\n");
    out.push_str(".pass{color:#1a7f37;font-weight:600}\n");
    out.push_str(".warn{color:#9a6700;font-weight:600}\n");
    out.push_str(".block{color:#cf222e;font-weight:600}\n");
    out.push_str(".pill{display:inline-block;padding:.1rem .5rem;border-radius:1rem;font-size:.8rem;border:1px solid currentColor}\n");
    out.push_str(".section{margin-top:1.5rem}\n");
    out.push_str("code{background:#f6f8fa;padding:.1rem .3rem;border-radius:.25rem}\n");
    out.push_str("ul{margin:.25rem 0}\n");
    out.push_str("</style>\n</head>\n<body>\n");

    out.push_str("<h1>Aegis Chain Report</h1>\n");
    out.push_str(&format!(
        "<div class=\"meta\"><strong>Status:</strong> <span class=\"{}\">{}</span><br>\n",
        status_class(
            report
                .policy
                .as_ref()
                .map(|s| s.overall_status)
                .unwrap_or(Action::Pass)
        ),
        escape_html(&overall_label(report))
    ));
    out.push_str(&format!(
        "<strong>Changes:</strong> {}<br>\n",
        escape_html(&change_summary(report))
    ));
    if let Some(policy) = &report.policy {
        out.push_str(&format!(
            "<strong>Formula:</strong> <code>{}</code>\n",
            escape_html(&policy.formula_version)
        ));
    }
    out.push_str("</div>\n");

    if report.decisions.is_empty() {
        if report.changes.is_empty() {
            out.push_str("<p>No dependency changes were detected.</p>\n");
        } else {
            out.push_str("<table>\n<thead><tr><th>Package</th><th>Change</th><th>Version</th><th>Impacted roots</th></tr></thead>\n<tbody>\n");
            for change in &report.changes {
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    escape_html(&change.name),
                    escape_html(change.kind.label()),
                    escape_html(&version_span(change)),
                    escape_html(&roots_list(change)),
                ));
            }
            out.push_str("</tbody></table>\n");
            out.push_str(
                "<p>Run with <code>--policy</code> to get risk scores and gate statuses.</p>\n",
            );
        }
        out.push_str("</body>\n</html>\n");
        return out;
    }

    out.push_str("<table>\n<thead><tr><th>Package</th><th>Change</th><th>Version</th><th>Risk</th><th>Impacted roots</th><th>Status</th></tr></thead>\n<tbody>\n");
    for decision in &report.decisions {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}/100 ({})</td><td>{}</td><td><span class=\"pill {}\">{}</span></td></tr>\n",
            escape_html(&decision.change.name),
            escape_html(decision.change.kind.label()),
            escape_html(&version_span(&decision.change)),
            decision.score,
            escape_html(&decision.level),
            escape_html(&roots_list(&decision.change)),
            status_class(decision.status),
            escape_html(&decision.status.label().to_uppercase()),
        ));
    }
    out.push_str("</tbody></table>\n");

    out.push_str("<div class=\"section\"><h2>Why does this need review?</h2>\n<ul>\n");
    let mut any = false;
    for decision in &report.decisions {
        if decision.status == Action::Pass && decision.matched_rules.is_empty() {
            continue;
        }
        any = true;
        out.push_str(&format!(
            "<li><strong>{}</strong> ({}): risk {}/100 ({})</li>\n",
            escape_html(&decision.change.name),
            escape_html(decision.change.kind.label()),
            decision.score,
            escape_html(&decision.level),
        ));
        for rule_id in &decision.matched_rules {
            let message = decision
                .traces
                .iter()
                .find(|trace| trace.rule_id == *rule_id)
                .and_then(|trace| trace.message.clone());
            match message {
                Some(message) => out.push_str(&format!(
                    "<ul><li>rule <code>{}</code>: {}</li></ul>\n",
                    escape_html(rule_id),
                    escape_html(&message)
                )),
                None => out.push_str(&format!(
                    "<ul><li>rule <code>{}</code></li></ul>\n",
                    escape_html(rule_id)
                )),
            }
        }
    }
    if !any {
        out.push_str("<li>All changes passed policy evaluation.</li>\n");
    }
    out.push_str("</ul></div>\n");

    let with_paths: Vec<&ChangeDecision> = report
        .decisions
        .iter()
        .filter(|decision| !decision.change.paths.is_empty())
        .collect();
    if !with_paths.is_empty() {
        out.push_str("<div class=\"section\"><h2>Impact paths</h2>\n");
        for decision in with_paths {
            out.push_str(&format!(
                "<p><strong>{}</strong></p>\n<ul>\n",
                escape_html(&decision.change.name)
            ));
            for path in &decision.change.paths {
                out.push_str(&format!("<li><code>{}</code></li>\n", escape_html(path)));
            }
            out.push_str("</ul>\n");
        }
        out.push_str("</div>\n");
    }

    out.push_str("</body>\n</html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::decision::DECISION_REPORT_SCHEMA_VERSION;
    use aegis_core::decision::{ChangeDecision, DecisionReport, PolicySummary};
    use aegis_core::diff::ChangeKind;
    use aegis_core::model::PackageKey;
    use aegis_policy::Action;
    use semver::Version;

    fn sample_report() -> DecisionReport {
        let key = PackageKey {
            name: "serde".to_string(),
            version: Version::new(1, 0, 210),
            source: None,
        };
        DecisionReport {
            schema_version: DECISION_REPORT_SCHEMA_VERSION,
            changes: vec![],
            policy: Some(PolicySummary {
                overall_status: Action::Warn,
                formula_version: "1.0".to_string(),
            }),
            decisions: vec![ChangeDecision {
                change: aegis_core::diff::PackageChange {
                    kind: ChangeKind::MinorUpgrade,
                    name: "serde".to_string(),
                    before: Some(PackageKey {
                        name: "serde".to_string(),
                        version: Version::new(1, 0, 200),
                        source: None,
                    }),
                    after: Some(key),
                    impacted_roots: vec![],
                    paths: vec![],
                },
                score: 48,
                level: "medium".to_string(),
                status: Action::Warn,
                matched_rules: vec!["critical-path-touched".to_string()],
                traces: vec![],
            }],
        }
    }

    #[test]
    fn renders_html_document() {
        let html = render(&sample_report());
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(html.contains("serde"));
        assert!(html.contains("class=\"warn\""));
        assert!(html.contains("48/100"));
    }

    #[test]
    fn escapes_user_controlled_text() {
        let key = PackageKey {
            name: "<script>".to_string(),
            version: Version::new(1, 0, 0),
            source: None,
        };
        let report = DecisionReport {
            schema_version: DECISION_REPORT_SCHEMA_VERSION,
            changes: vec![],
            policy: None,
            decisions: vec![ChangeDecision {
                change: aegis_core::diff::PackageChange {
                    kind: ChangeKind::Added,
                    name: "<script>".to_string(),
                    before: None,
                    after: Some(key),
                    impacted_roots: vec![],
                    paths: vec![],
                },
                score: 10,
                level: "low".to_string(),
                status: Action::Pass,
                matched_rules: vec![],
                traces: vec![],
            }],
        };
        let html = render(&report);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
