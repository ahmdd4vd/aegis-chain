use std::process::ExitCode;

use clap::Parser;

mod commands;

fn main() -> ExitCode {
    let cli = commands::Cli::parse();
    commands::init_tracing();

    match commands::dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aegis: {error:?}");
            ExitCode::FAILURE
        }
    }
}
