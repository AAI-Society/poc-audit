use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_poc-audit"))
}
const GOOD: &str = "tests/fixtures/vectors/positive/hardware-attested.json";

/// A unique path per call, not a fixed name — a fixed `/tmp` path is
/// hazardous under parallel test execution (cargo runs tests in the same
/// binary concurrently by default) or a shared runner: two tests, or two
/// concurrent CI jobs, writing and reading the same path race each other.
/// Includes the caller-supplied name for a readable leftover file if a test
/// panics before cleanup, the process id to separate concurrent processes,
/// and a nanosecond timestamp to separate concurrent threads within one.
fn unique_temp_path(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "poc-audit-{name}-{}-{nanos}.json",
        std::process::id()
    ))
}

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

/// Gate-relevant UNCHECKED rows exist in the default run: `submods.
/// attestation.measurement` (no `--deployment`) and `poc_claims.
/// canonical_snapshot_hash` (no `--payload`) are both `Unchecked(Why::
/// MissingInput(_))`, so the CI gate must bite on a record that otherwise
/// exits 0. The chain rows (`chain_head`, `merkle_root`, `step_index`) are
/// UNCHECKED too, but via `Why::NoAuditor`, which `--require-checked`
/// deliberately excludes — see `verdict::Verdict::is_unchecked_missing_
/// input` — so they are not why this test's `strict` run fails; naming them
/// here would be stale the moment chain continuity gets an auditor.
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
    let path = unique_temp_path("malformed-record");
    std::fs::write(&path, "{}").expect("write");
    let out = bin().arg(&path).output().expect("run");
    let _ = std::fs::remove_file(&path);
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

/// The real path to exit 2 via a failed auditor, not only the synthetic
/// `Finding` list above. `--fleet`'s CLI pre-check only calls
/// `occultation::anonymity::Fleet::load`, which just parses TOML — a fleet
/// declaring no hosts loads fine and passes that check, then fails inside
/// `Identity`'s audit when `occultation::anonymity::partition` runs on it.
/// Before this test, that whole path — pre-check passes, auditor fails,
/// process exits 2, row says why — was exercised by nothing.
#[test]
fn a_fleet_that_loads_but_cannot_partition_drives_a_real_exit_2() {
    let out = bin()
        .arg(GOOD)
        .arg("--fleet")
        .arg("tests/fixtures/occultation/fleet-empty.toml")
        .output()
        .expect("run");

    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("poc_claims.agent_id") && stdout.contains("UNCHECKED"),
        "the row must still be printed, naming the field: {stdout}"
    );
    assert!(
        stdout.contains("could not partition the fleet"),
        "the row must say the auditor failed, not just UNCHECKED, got:\n{stdout}"
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

// `require_checked_still_exits_1_when_a_deepening_input_is_missing` used to
// live here. Its body was byte-identical to `require_checked_turns_a_clean_
// record_into_a_failure`'s `strict` half — both just ran GOOD with
// `--require-checked` and asserted exit 1 — so it added no coverage beyond
// what that test's updated docstring above now explains directly. Merged
// away rather than left as a second copy of the same assertion under a
// different name.

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
