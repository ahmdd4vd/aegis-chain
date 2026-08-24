use std::collections::BTreeSet;
use std::path::PathBuf;

use aegis_core::decision::DecisionReport;
use clap::Args;

#[derive(Debug, Args)]
pub struct ExplainArgs {
    pub rule_id: String,

    #[arg(long)]
    pub report: Option<PathBuf>,
}

fn load_report(path: &std::path::Path) -> miette::Result<DecisionReport> {
    let content = super::read_utf8(path)?;
    serde_json::from_str(&content)
        .map_err(|error| miette::Report::msg(format!("invalid report {}: {error}", path.display())))
}

fn known_rule_ids(report: &DecisionReport) -> BTreeSet<String> {
    report
        .decisions
        .iter()
        .flat_map(|decision| decision.traces.iter().map(|trace| trace.rule_id.clone()))
        .collect()
}

pub fn run(args: &ExplainArgs) -> miette::Result<()> {
    let report_path = args
        .report
        .clone()
        .unwrap_or_else(|| PathBuf::from("aegis-report.json"));
    let report = load_report(&report_path)?;

    if report.decisions.is_empty() {
        println!(
            "No policy decisions found in {}. Re-run 'aegis diff' with --policy to produce them.",
            report_path.display()
        );
        return Ok(());
    }

    let mut matched_any = false;

    for decision in &report.decisions {
        for trace in &decision.traces {
            if trace.rule_id != args.rule_id {
                continue;
            }
            matched_any = true;

            let change = &decision.change;
            let versions = match (&change.before, &change.after) {
                (Some(before), Some(after)) => format!("{} -> {}", before.version, after.version),
                (None, Some(after)) => after.version.to_string(),
                (Some(before), None) => before.version.to_string(),
                (None, None) => String::new(),
            };

            println!(
                "rule '{}' on {} {} ({})",
                trace.rule_id,
                change.kind.label(),
                change.name,
                versions
            );
            println!("  action: {}", trace.action.label());
            println!("  matched: {}", if trace.matched { "yes" } else { "no" });
            println!("  change status: {}", decision.status.label());

            if let Some(message) = &trace.message {
                println!("  message: {message}");
            }

            println!("  predicates:");
            for predicate in &trace.predicates {
                println!(
                    "    [{}] {}",
                    if predicate.matched { "x" } else { " " },
                    predicate.label
                );
            }
            println!();
        }
    }

    if !matched_any {
        println!("Rule '{}' did not match any change.", args.rule_id);
        let ids: Vec<String> = known_rule_ids(&report).into_iter().collect();
        if !ids.is_empty() {
            println!("Known rule ids in this report:");
            for id in ids {
                println!("  - {id}");
            }
        }
    }

    Ok(())
}
