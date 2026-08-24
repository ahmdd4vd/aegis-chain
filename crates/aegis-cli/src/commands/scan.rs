use std::path::PathBuf;

use clap::Args;

use super::OutputFormat;

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[arg(long, default_value = "aegis.yml")]
    pub policy: PathBuf,

    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,
}

pub fn run(args: &ScanArgs) -> miette::Result<()> {
    println!(
        "'aegis scan' is not implemented yet (policy: {}, format: {:?}).",
        args.policy.display(),
        args.format
    );
    Ok(())
}
