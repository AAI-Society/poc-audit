#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "poc-audit",
    about = "What actually backs each claim in a Proof-of-Control evidence record"
)]
struct Cli {
    /// The evidence record to audit.
    record: PathBuf,

    /// A parallax deployment description, to establish who operates the
    /// reference values.
    #[arg(long)]
    deployment: Option<PathBuf>,

    /// The request bytes the record's canonical_snapshot_hash covers. No
    /// decoder configuration is needed: transit runs every model it can find.
    #[arg(long)]
    payload: Option<PathBuf>,

    /// An occultation fleet description, for the anonymity-set size.
    #[arg(long)]
    fleet: Option<PathBuf>,

    /// The identity profile in force. A persistent agent_id satisfies C5.1.1
    /// under `standard` and cannot hold under `unlinkable`. Not inferred from
    /// the record, because the record does not say.
    #[arg(long, value_enum, default_value_t = poc_audit::verdict::Profile::Standard)]
    profile: poc_audit::verdict::Profile,

    /// Print the residual trust set behind one field instead of the table.
    #[arg(long, value_name = "FIELD")]
    explain: Option<String>,
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
    if let Some(p) = cli.fleet.as_ref() {
        if let Err(e) = occultation::anonymity::Fleet::load(p) {
            eprintln!("error: cannot use --fleet {}: {e}", p.display());
            return ExitCode::from(2);
        }
    }
    let payload = match cli.payload.as_ref() {
        None => None,
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("error: cannot use --payload {}: {e}", p.display());
                return ExitCode::from(2);
            }
        },
    };
    let ctx = poc_audit::verdict::Context {
        deployment: cli.deployment.clone(),
        payload,
        fleet: cli.fleet.clone(),
        profile: cli.profile,
    };
    let findings = poc_audit::registry::run(&rec, &ctx);
    if let Some(field) = cli.explain.as_ref() {
        return match poc_audit::report::render_explain(&findings, field) {
            Ok(s) => {
                print!("{s}");
                ExitCode::from(poc_audit::report::exit_code(&findings, false))
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }
    print!("{}", poc_audit::report::render_table(&findings));
    ExitCode::from(poc_audit::report::exit_code(&findings, false))
}
