use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aegis_advisory::OsvSource;
use aegis_core::advisory::AdvisorySource;
use aegis_core::decision::DecisionReport;
use aegis_core::model::DependencySnapshot;
use aegis_core::provenance::ProvenanceSource;
use aegis_core::run_decision;
use aegis_policy::{Action, EvidenceAvailability, EvidenceKind};
use aegis_sigstore::CosignProvenanceProvider;
use clap::{Args, ValueEnum};

use super::{read_utf8, OutputFormat};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    Never,
    Warn,
    Block,
}

impl FailOn {
    fn severity(self) -> u8 {
        match self {
            FailOn::Never => 0,
            FailOn::Warn => 1,
            FailOn::Block => 2,
        }
    }

    fn threshold(self) -> Action {
        match self {
            FailOn::Never => Action::Block,
            FailOn::Warn => Action::Warn,
            FailOn::Block => Action::Block,
        }
    }
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    #[arg(long)]
    pub base_snapshot: PathBuf,

    #[arg(long)]
    pub head_snapshot: PathBuf,

    #[arg(long)]
    pub policy: Option<PathBuf>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Evidence per package as name=kind pairs, e.g. --available-evidence serde=sbom,provenance (repeatable)"
    )]
    pub available_evidence: Vec<String>,

    #[arg(
        long,
        help = "CycloneDX SBOM JSON files used as real evidence for matched packages"
    )]
    pub sbom: Vec<PathBuf>,

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

    #[arg(long, help = "Additionally write a SARIF report to this path")]
    pub sarif: Option<PathBuf>,

    #[arg(
        long,
        value_enum,
        default_value_t = FailOn::Never,
        help = "Exit non-zero when overall status reaches this severity"
    )]
    pub fail_on: FailOn,

    #[arg(
        long,
        requires = "pr_number",
        help = "Post or update the PR report comment"
    )]
    pub comment: bool,

    #[arg(long)]
    pub pr_number: Option<u64>,

    #[arg(
        long,
        help = "Target repository as owner/name; defaults to $GITHUB_REPOSITORY"
    )]
    pub repo: Option<String>,
}

fn load_snapshot(path: &std::path::Path) -> miette::Result<DependencySnapshot> {
    let content = read_utf8(path)?;
    serde_json::from_str(&content).map_err(|error| {
        miette::Report::msg(format!("invalid snapshot {}: {error}", path.display()))
    })
}

fn parse_evidence_specs(specs: &[String]) -> miette::Result<EvidenceAvailability> {
    let mut evidence: EvidenceAvailability = BTreeMap::new();
    for spec in specs {
        let Some((package, kinds)) = spec.split_once('=') else {
            return Err(miette::Report::msg(format!(
                "invalid evidence spec '{spec}': expected package=kind1,kind2"
            )));
        };
        let entry = evidence.entry(package.to_string()).or_default();
        for kind in kinds.split(',').filter(|kind| !kind.is_empty()) {
            let parsed = match kind.trim() {
                "sbom" => EvidenceKind::Sbom,
                "provenance" => EvidenceKind::Provenance,
                "approved_source" => EvidenceKind::ApprovedSource,
                "vulnerability_feed" => EvidenceKind::VulnerabilityFeed,
                "hashes" => EvidenceKind::Hashes,
                "license" => EvidenceKind::License,
                other => {
                    return Err(miette::Report::msg(format!(
                        "unknown evidence kind '{other}' in spec '{spec}'"
                    )))
                }
            };
            entry.insert(parsed);
        }
    }
    Ok(evidence)
}

fn write_or_print(path: Option<&Path>, content: &str) -> miette::Result<()> {
    match path {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| miette::Report::msg(error.to_string()))?;
                }
            }
            std::fs::write(path, content)
                .map_err(|error| miette::Report::msg(error.to_string()))?;
            println!("report written: {}", path.display());
            Ok(())
        }
        None => {
            println!("{content}");
            Ok(())
        }
    }
}

fn post_pr_comment(args: &DiffArgs, report: &DecisionReport) -> miette::Result<()> {
    let Some(pr_number) = args.pr_number else {
        return Err(miette::Report::msg("--comment requires --pr-number"));
    };

    let repo = args
        .repo
        .clone()
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .ok_or_else(|| {
            miette::Report::msg("--repo or $GITHUB_REPOSITORY is required for --comment")
        })?;

    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .map_err(|_| miette::Report::msg("GITHUB_TOKEN (or GH_TOKEN) is required for --comment"))?;

    let markdown = aegis_report::markdown::render(report);
    let client = aegis_github::GitHubClient::new(token, repo);

    match aegis_github::upsert_report_comment(&client, pr_number, &markdown) {
        Ok(outcome) => {
            match outcome {
                aegis_github::UpsertOutcome::Created { comment_id } => {
                    println!("PR comment created (id {comment_id})");
                }
                aegis_github::UpsertOutcome::Updated { comment_id } => {
                    println!("PR comment updated (id {comment_id})");
                }
            }
            Ok(())
        }
        Err(error) => Err(miette::Report::msg(error.to_string())),
    }
}

pub fn run(args: &DiffArgs) -> miette::Result<()> {
    let base = load_snapshot(&args.base_snapshot)?;
    let head = load_snapshot(&args.head_snapshot)?;

    let policy = match &args.policy {
        Some(path) => {
            let content = read_utf8(path)?;
            Some(aegis_policy::parse_policy(&content).map_err(|error| {
                miette::Report::msg(format!("invalid policy {}: {error}", path.display()))
            })?)
        }
        None => None,
    };

    let mut evidence = parse_evidence_specs(&args.available_evidence)?;
    if !args.sbom.is_empty() {
        let paths: Vec<&Path> = args.sbom.iter().map(|path| path.as_path()).collect();
        let from_sbom = aegis_evidence::availability_from_bom_files(&paths)
            .map_err(|error| miette::Report::msg(error.to_string()))?;
        for (package, kinds) in from_sbom {
            evidence.entry(package).or_default().extend(kinds);
        }
    }
    let osv = args.advisory.then(OsvSource::new);
    let advisory: Option<&dyn AdvisorySource> =
        osv.as_ref().map(|source| source as &dyn AdvisorySource);

    let provenance_source = args.provenance.clone().map(CosignProvenanceProvider::new);
    let provenance: Option<&dyn ProvenanceSource> = provenance_source
        .as_ref()
        .map(|source| source as &dyn ProvenanceSource);

    let report = run_decision(
        &base,
        &head,
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

    write_or_print(args.output.as_deref(), &rendered)?;

    if let Some(sarif_path) = &args.sarif {
        let sarif = aegis_report::sarif::render(&report);
        if let Some(parent) = sarif_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| miette::Report::msg(error.to_string()))?;
            }
        }
        std::fs::write(sarif_path, sarif)
            .map_err(|error| miette::Report::msg(error.to_string()))?;
        println!("sarif written: {}", sarif_path.display());
    }

    if args.comment {
        post_pr_comment(args, &report)?;
    }

    if let Some(summary) = &report.policy {
        let gate_threshold = args.fail_on.threshold();
        if summary.overall_status >= gate_threshold && args.fail_on.severity() > 0 {
            return Err(miette::Report::msg(format!(
                "policy status is {}; failing per --fail-on {}",
                summary.overall_status.label().to_uppercase(),
                match args.fail_on {
                    FailOn::Never => unreachable!(),
                    FailOn::Warn => "warn",
                    FailOn::Block => "block",
                }
            )));
        }
    }

    Ok(())
}
