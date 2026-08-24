use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    #[command(about = "Validate an aegis.yml policy file")]
    Check(PolicyCheckArgs),

    #[command(about = "Generate a starter aegis.yml policy file")]
    Init(PolicyInitArgs),
}

#[derive(Debug, Args)]
pub struct PolicyCheckArgs {
    #[arg(long, default_value = "aegis.yml")]
    pub policy: PathBuf,
}

#[derive(Debug, Args)]
pub struct PolicyInitArgs {
    #[arg(long, default_value = "aegis.yml")]
    pub output: PathBuf,
}

const STARTER_POLICY: &str = "\
schema_version: 1

analysis:
  mode: offline
  max_paths_per_change: 5

critical_packages: []

evidence:
  require_for_added_packages: []

thresholds:
  warn_at: 30
  high_at: 60
  block_at: 80

rules:
  - id: source-mutation-review
    when:
      any:
        - source_changed: true
        - is_major_upgrade: true
    action: warn
    message: \"Source changed or major upgrade requires maintainer review.\"

  - id: risk-threshold-block
    when:
      risk_at_least: 80
    action: block
    message: \"Risk score passed the block threshold.\"
";

pub fn run(command: PolicyCommand) -> miette::Result<()> {
    match command {
        PolicyCommand::Check(args) => check(&args.policy),
        PolicyCommand::Init(args) => init(&args.output),
    }
}

fn check(path: &std::path::Path) -> miette::Result<()> {
    let content = super::read_utf8(path)?;

    let policy = aegis_policy::parse_policy(&content)
        .map_err(|error| miette::Report::msg(format!("{}", error)))?;

    println!(
        "{}: valid ({} rules, {} critical packages, thresholds warn/high/block = {}/{}/{})",
        path.display(),
        policy.rules.len(),
        policy.critical_packages.len(),
        policy.thresholds.warn_at,
        policy.thresholds.high_at,
        policy.thresholds.block_at
    );
    Ok(())
}

fn init(output: &PathBuf) -> miette::Result<()> {
    if output.exists() {
        return Err(miette::Report::msg(format!(
            "refusing to overwrite existing {}",
            output.display()
        )));
    }

    std::fs::write(output, STARTER_POLICY).map_err(|error| {
        miette::Report::msg(format!("failed to write {}: {error}", output.display()))
    })?;

    println!("starter policy written to {}", output.display());
    Ok(())
}
