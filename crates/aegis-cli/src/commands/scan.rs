use std::path::PathBuf;

use aegis_advisory::OsvSource;
use aegis_core::advisory::AdvisorySource;
use aegis_core::provenance::ProvenanceSource;
use aegis_core::run_decision;
use aegis_policy::EvidenceAvailability;
use aegis_sigstore::CosignProvenanceProvider;
use clap::Args;

use super::{read_utf8, OutputFormat};

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,

    #[arg(long, help = "Path to an aegis.yml policy file; ignored if missing")]
    pub policy: Option<PathBuf>,

    #[arg(
        long,
        help = "Query the OSV.dev advisory database and feed findings into the risk score (network opt-in)"
    )]
    pub advisory: bool,

    #[arg(
        long,
        help = "Directory of Sigstore/cosign bundle files ({name}@{version}.json) used to verify build provenance (offline)"
    )]
    pub provenance: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    #[arg(
        long,
        help = "Write the rendered report to this file instead of stdout"
    )]
    pub output: Option<PathBuf>,
}

pub fn run(args: &ScanArgs) -> miette::Result<()> {
    let manifest_path = args
        .manifest_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("./Cargo.toml"));

    let options = aegis_cargo::MetadataOptions::new(manifest_path);
    let snapshot = aegis_cargo::build_snapshot(&options)
        .map_err(|error| miette::Report::msg(error.to_string()))?;

    let policy = match &args.policy {
        Some(path) if path.is_file() => {
            let content = read_utf8(path)?;
            Some(aegis_policy::parse_policy(&content).map_err(|error| {
                miette::Report::msg(format!("invalid policy {}: {error}", path.display()))
            })?)
        }
        _ => None,
    };

    let evidence = EvidenceAvailability::new();

    let osv = args.advisory.then(OsvSource::new);
    let advisory: Option<&dyn AdvisorySource> =
        osv.as_ref().map(|source| source as &dyn AdvisorySource);

    let provenance_source = args.provenance.clone().map(CosignProvenanceProvider::new);
    let provenance: Option<&dyn ProvenanceSource> = provenance_source
        .as_ref()
        .map(|source| source as &dyn ProvenanceSource);

    let report = run_decision(
        &snapshot,
        &snapshot,
        policy.as_ref(),
        &evidence,
        advisory,
        provenance,
    );

    let rendered = match args.format {
        OutputFormat::Terminal => aegis_report::terminal::render(&report),
        OutputFormat::Json => aegis_report::json::render(&report),
        OutputFormat::Markdown => aegis_report::markdown::render(&report),
        OutputFormat::Sarif => aegis_report::sarif::render(&report),
        OutputFormat::Html => aegis_report::html::render(&report),
    };

    match &args.output {
        Some(output) => {
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| miette::Report::msg(error.to_string()))?;
                }
            }
            std::fs::write(output, rendered)
                .map_err(|error| miette::Report::msg(error.to_string()))?;
            println!("report written: {}", output.display());
        }
        None => println!("{rendered}"),
    }

    Ok(())
}
