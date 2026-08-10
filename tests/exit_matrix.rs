use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_poc-audit"))
}
const GOOD: &str = "tests/fixtures/vectors/positive/hardware-attested.json";

/// A conformant record under the default profile has nothing that DIVERGES
/// and nothing that CANNOT HOLD, so it exits 0. If this ever exits 1, an
/// auditor is reporting a failure on a record that has none — the false
/// finding this tool exists to avoid.
#[test]
fn a_conformant_record_under_the_default_profile_exits_0() {
    let out = bin().arg(GOOD).output().expect("run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The same record, one flag, the opposite outcome. This pair is what makes
/// exit 0 meaningful: without it, a tool that always exits 1 would pass every
/// other test in this file.
#[test]
fn the_same_record_exits_1_once_an_unlinkable_profile_is_declared() {
    let out = bin()
        .arg(GOOD)
        .arg("--profile")
        .arg("unlinkable")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
}

/// UNCHECKED rows exist in the default run (chain, canonical), so the CI gate
/// must bite on a record that otherwise passes.
#[test]
fn require_checked_turns_a_clean_record_into_a_failure() {
    assert_eq!(
        bin().arg(GOOD).output().expect("run").status.code(),
        Some(0)
    );
    let strict = bin()
        .arg(GOOD)
        .arg("--require-checked")
        .output()
        .expect("run");
    assert_eq!(strict.status.code(), Some(1));
}

#[test]
fn require_checked_does_not_change_the_report_only_the_code() {
    let plain = bin().arg(GOOD).output().expect("run");
    let strict = bin()
        .arg(GOOD)
        .arg("--require-checked")
        .output()
        .expect("run");
    assert_eq!(
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&strict.stdout),
        "--require-checked must change only the exit code"
    );
}

#[test]
fn a_malformed_record_exits_2() {
    std::fs::write("/tmp/poc-audit-bad.json", "{}").expect("write");
    let out = bin().arg("/tmp/poc-audit-bad.json").output().expect("run");
    assert_eq!(out.status.code(), Some(2));
}

/// The subtle one. Without this, a panicking auditor yields UNCHECKED,
/// UNCHECKED does not fail, and a crash reads as a pass.
#[test]
fn an_auditor_failure_outranks_everything_and_exits_2() {
    use poc_audit::verdict::{Finding, Verdict, Why};
    let findings = vec![
        Finding {
            field: "a",
            verdict: Verdict::Diverges,
            reason: String::new(),
            residual: vec![],
        },
        Finding {
            field: "b",
            verdict: Verdict::Unchecked(Why::AuditorFailed("boom".into())),
            reason: String::new(),
            residual: vec![],
        },
    ];
    assert_eq!(
        poc_audit::report::exit_code(&findings, false),
        2,
        "a failed auditor must outrank a divergence: the report is incomplete"
    );
}

/// `main.rs` has TWO `exit_code` call sites — the table path and the
/// `--explain` path — and every other test in this file exercises only the
/// first. Reverting the `--explain` arm to a hardcoded `false` left all forty
/// tests green, so a refactor dropping the flag there would ship a gating
/// exit code of 0 on a record full of UNCHECKED rows, with no CI signal.
#[test]
fn require_checked_reaches_the_explain_path_too() {
    let field = "poc_claims.chain_head";
    let plain = bin()
        .arg(GOOD)
        .arg("--explain")
        .arg(field)
        .output()
        .expect("run");
    let strict = bin()
        .arg(GOOD)
        .arg("--explain")
        .arg(field)
        .arg("--require-checked")
        .output()
        .expect("run");

    assert_eq!(
        plain.status.code(),
        Some(0),
        "the explain path must start clean"
    );
    assert_eq!(
        strict.status.code(),
        Some(1),
        "--require-checked did not reach the --explain call site"
    );
    assert_eq!(
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&strict.stdout),
        "--require-checked must change only the exit code, on this path too"
    );
}

/// `--require-checked` must be reachable, or it is a constant function that
/// fails every record and gets deleted from CI. With every deepening input
/// supplied, no row can be `Unchecked(Why::MissingInput(_))` — only
/// `Why::NoAuditor` rows remain, and those are excluded from the gate on
/// purpose (see `verdict::Verdict::is_unchecked_missing_input`). So the gate
/// must be satisfiable.
#[test]
fn require_checked_can_exit_0_with_every_deepening_input_supplied() {
    let out = bin()
        .arg(GOOD)
        .arg("--deployment")
        .arg("tests/fixtures/parallax/sigma2-tdx.toml")
        .arg("--payload")
        .arg("tests/fixtures/payload/unambiguous.json")
        .arg("--fleet")
        .arg("tests/fixtures/occultation/fleet-uniform.toml")
        .arg("--require-checked")
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The other direction: with a deepening input missing (here, no
/// `--deployment`, so `submods.attestation.measurement` stays
/// `Unchecked(Why::MissingInput("--deployment"))`), the gate must still
/// fail. Without this, scoping the gate to `Why::MissingInput` could have
/// been implemented by excluding everything and the gate would never bite.
#[test]
fn require_checked_still_exits_1_when_a_deepening_input_is_missing() {
    let out = bin()
        .arg(GOOD)
        .arg("--require-checked")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_clean_set_of_findings_exits_0() {
    use poc_audit::verdict::{BackedBy, Finding, Verdict};
    let findings = vec![Finding {
        field: "a",
        verdict: Verdict::Established(BackedBy::new("x").expect("non-empty")),
        reason: String::new(),
        residual: vec![],
    }];
    assert_eq!(poc_audit::report::exit_code(&findings, false), 0);
    assert_eq!(poc_audit::report::exit_code(&findings, true), 0);
}
