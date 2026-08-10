#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "poc-audit", about = "What actually backs each claim in a Proof-of-Control evidence record")]
struct Cli {
    /// The evidence record to audit.
    record: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let src = match std::fs::read_to_string(&cli.record) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", cli.record.display());
            return ExitCode::from(2);
        }
    };
    match poc_audit::record::Record::parse(&src) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
