mod diff;
mod explain;
mod policy;
mod scan;
mod snapshot;

use std::path::Path;

use clap::{Parser, Subcommand};

pub(crate) fn read_utf8(path: &Path) -> miette::Result<String> {
    let bytes = std::fs::read(path).map_err(|error| {
        miette::Report::msg(format!("failed to read {}: {error}", path.display()))
    })?;
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    String::from_utf8(bytes.to_vec()).map_err(|error| {
        miette::Report::msg(format!("invalid UTF-8 in {}: {error}", path.display()))
    })
}

use self::diff::DiffArgs;
use self::explain::ExplainArgs;
use self::policy::PolicyCommand;
use self::scan::ScanArgs;
use self::snapshot::SnapshotArgs;

#[derive(Debug, Parser)]
#[command(
    name = "aegis",
    version,
    about = "Dependency impact reports for Rust workspaces",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Analyze the current working tree")]
    Scan(ScanArgs),

    #[command(about = "Compare dependency snapshots between two revisions")]
    Diff(DiffArgs),

    #[command(about = "Show the decision trace for a policy rule")]
    Explain(ExplainArgs),

    #[command(subcommand)]
    #[command(about = "Validate or generate the aegis.yml policy file")]
    Policy(PolicyCommand),

    #[command(about = "Export a Cargo metadata snapshot as JSON")]
    Snapshot(SnapshotArgs),
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Markdown,
    Sarif,
}

pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

pub fn dispatch(command: Command) -> miette::Result<()> {
    tracing::debug!(?command, "dispatching command");

    match command {
        Command::Scan(args) => scan::run(&args),
        Command::Diff(args) => diff::run(&args),
        Command::Explain(args) => explain::run(&args),
        Command::Policy(policy) => policy::run(policy),
        Command::Snapshot(args) => snapshot::run(&args),
    }
}
