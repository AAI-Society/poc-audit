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
    /// The evidence record to audit. Omit this when using --chain to audit a
    /// sequence of records instead of one.
    #[arg(required_unless_present = "chain", conflicts_with = "chain")]
    record: Option<PathBuf>,

    /// Audit a SEQUENCE of records for chain continuity instead of one
    /// record's fields: step_index contiguity (0, 1, 2, … with no gaps,
    /// duplicates, or reordering), tree_size monotonicity, and a shared
    /// agent_id. Give at least two files, oldest first — the order given is
    /// the claimed sequence and is not sorted for you. chain_head is never
    /// recomputed (its hash construction is not pinned by the standard) but
    /// a repeated chain_head is still reported, since that is impossible
    /// under any construction.
    #[arg(long, num_args = 2.., value_name = "FILE", conflicts_with = "record")]
    chain: Option<Vec<PathBuf>>,

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

    /// A JSON file naming the measurements you accept, to compare against
    /// submods.attestation.measurement. Not the record's own
    /// reference_values_uri — that is a URI in the record and is never
    /// fetched; this is what YOU assert you accept. See the README for the
    /// file format.
    #[arg(long, value_name = "FILE")]
    reference_values: Option<PathBuf>,

    /// The identity profile in force. A persistent agent_id satisfies C5.1.1
    /// under `standard` and cannot hold under `unlinkable`. Not inferred from
    /// the record, because the record does not say.
    #[arg(long, value_enum, default_value_t = poc_audit::verdict::Profile::Standard)]
    profile: poc_audit::verdict::Profile,

    /// Print the residual trust set behind one field instead of the table.
    #[arg(long, value_name = "FIELD")]
    explain: Option<String>,

    /// Fail on any UNCHECKED row a deepening flag could resolve (a missing
    /// --deployment, --payload, or --fleet) — not on fields this tool does
    /// not audit at all. Changes only the exit code; the report is
    /// byte-identical.
    #[arg(long)]
    require_checked: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // The --chain mode audits a SEQUENCE of records for continuity
    // (step_index, tree_size, agent_id), a different question from the
    // single-record table below, and it does not use --deployment,
    // --payload, --fleet, --reference-values, or --profile — none of those
    // deepen a cross-record fact. clap's conflicts_with already rejects
    // --chain together with a positional `record`, so this branch never
    // needs to reconcile the two.
    if let Some(paths) = cli.chain.as_ref() {
        let records = match poc_audit::chain::load_chain(paths) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        };
        let findings = poc_audit::chain::audit(&records);
        if let Some(field) = cli.explain.as_ref() {
            return match poc_audit::report::render_explain(&findings, field) {
                Ok(s) => {
                    print!("{s}");
                    ExitCode::from(poc_audit::report::exit_code(&findings, cli.require_checked))
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            };
        }
        print!("{}", poc_audit::report::render_table(&findings));
        return ExitCode::from(poc_audit::report::exit_code(&findings, cli.require_checked));
    }

    // clap's `required_unless_present = "chain"` guarantees `record` is
    // `Some` here: the chain branch above returned already if `--chain` was
    // given, and clap itself rejects invocations with neither.
    let record_path = cli
        .record
        .as_ref()
        .expect("clap requires record when --chain is absent");
    let src = match std::fs::read_to_string(record_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", record_path.display());
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
    if let Some(p) = cli.reference_values.as_ref() {
        if let Err(e) = poc_audit::reference_values::ReferenceValues::load(p) {
            eprintln!("error: cannot use --reference-values {}: {e}", p.display());
            return ExitCode::from(2);
        }
    }
    let payload = match cli.payload.as_ref() {
        None => None,
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => {
                // A wrong or truncated payload file is the most likely
                // misconfiguration of this flag, and an empty or non-JSON
                // file used to sail through to `Verdict::Asserted` — a
                // cleaner-looking row than supplying nothing at all. That is
                // exactly the quiet downgrade FAILS LOUD forbids, so this is
                // validated here, the same way `--deployment` and `--fleet`
                // validate at load time, rather than left for `transit` to
                // find nothing to disagree about.
                if let Err(e) = serde_json::from_str::<serde_json::Value>(&s) {
                    eprintln!(
                        "error: cannot use --payload {}: not valid JSON: {e}",
                        p.display()
                    );
                    return ExitCode::from(2);
                }
                Some(s)
            }
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
        reference_values: cli.reference_values.clone(),
        profile: cli.profile,
    };
    let findings = poc_audit::registry::run(&rec, &ctx);
    if let Some(field) = cli.explain.as_ref() {
        return match poc_audit::report::render_explain(&findings, field) {
            Ok(s) => {
                print!("{s}");
                ExitCode::from(poc_audit::report::exit_code(&findings, cli.require_checked))
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }
    print!("{}", poc_audit::report::render_table(&findings));
    println!("{}", poc_audit::report::tier_line(&rec));
    ExitCode::from(poc_audit::report::exit_code(&findings, cli.require_checked))
}
