#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "poc-audit", about = "What actually backs each claim in a Proof-of-Control evidence record")]
struct Cli {
    /// The evidence record to audit.
    record: PathBuf,

    /// A parallax deployment description, to establish who operates the
    /// reference values.
    #[arg(long)]
    deployment: Option<PathBuf>,
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
    let rec = match poc_audit::record::Record::parse(&src) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    // Strict: an unreadable optional input is an error, not a quiet
    // downgrade to UNCHECKED. UNCHECKED looks benign, so a typo would turn a
    // real audit into a clean-looking report with fewer rows.
    if let Some(p) = cli.deployment.as_ref() {
        if let Err(e) = parallax::deployment::Deployment::load(p) {
            eprintln!("error: cannot use --deployment {}: {e}", p.display());
            return ExitCode::from(2);
        }
    }
    let ctx = poc_audit::verdict::Context { deployment: cli.deployment.clone(), ..Default::default() };
    let findings = poc_audit::registry::run(&rec, &ctx);
    print!("{}", poc_audit::report::render_table(&findings));
    ExitCode::from(poc_audit::report::exit_code(&findings, false))
}
