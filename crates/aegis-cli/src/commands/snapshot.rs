use std::path::PathBuf;

use clap::Args;

use aegis_cargo::{build_snapshot, MetadataOptions};

#[derive(Debug, Args)]
pub struct SnapshotArgs {
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,

    #[arg(long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: &SnapshotArgs) -> miette::Result<()> {
    let manifest_path = args
        .manifest_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("./Cargo.toml"));

    let options = MetadataOptions::new(manifest_path);
    let snapshot =
        build_snapshot(&options).map_err(|error| miette::Report::msg(error.to_string()))?;

    let json = serde_json::to_string_pretty(&snapshot)
        .map_err(|error| miette::Report::msg(error.to_string()))?;

    match &args.output {
        Some(output) => {
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| miette::Report::msg(error.to_string()))?;
                }
            }
            std::fs::write(output, json).map_err(|error| miette::Report::msg(error.to_string()))?;
            println!(
                "snapshot written: {} ({} packages, {} edges, {} workspace members)",
                output.display(),
                snapshot.packages.len(),
                snapshot.edges.len(),
                snapshot.workspace_members.len()
            );
        }
        None => println!("{json}"),
    }

    Ok(())
}
