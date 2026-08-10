use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_poc-audit"))
}
const GOOD: &str = "tests/fixtures/vectors/positive/hardware-attested.json";

/// The whole point of this feature, exercised through the real binary: a
/// matching reference-values file upgrades `submods.attestation.measurement`
/// from UNCHECKED to ESTABLISHED, and the record has nothing else that
/// DIVERGES or CANNOT HOLD, so the process exits 0.
#[test]
fn a_matching_reference_values_file_establishes_the_measurement() {
    let out = bin()
        .arg(GOOD)
        .arg("--reference-values")
        .arg("tests/fixtures/reference-values/matches-hardware-attested.json")
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout
        .lines()
        .find(|l| l.starts_with("submods.attestation.measurement"))
        .unwrap_or_else(|| panic!("no measurement row in:\n{stdout}"));
    assert!(row.contains("ESTABLISHED"), "got: {row}");
    assert!(
        row.contains("--reference-values"),
        "the row must name what backs it: {row}"
    );
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
}

/// The highest-value output this tool can produce: attested code that is not
/// the code you approved. A non-matching reference-values file must DIVERGE
/// and drive the process to exit 1, not merely print a differently worded
/// clean row.
#[test]
fn a_non_matching_reference_values_file_diverges_and_exits_1() {
    let out = bin()
        .arg(GOOD)
        .arg("--reference-values")
        .arg("tests/fixtures/reference-values/does-not-match.json")
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout
        .lines()
        .find(|l| l.starts_with("submods.attestation.measurement"))
        .unwrap_or_else(|| panic!("no measurement row in:\n{stdout}"));
    assert!(row.contains("DIVERGES"), "got: {row}");
    assert!(
        row.contains("a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81"),
        "the row must show the record's own measurement: {row}"
    );
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
}

/// Same strictness as `--deployment`, `--payload`, `--fleet`: a bad path is
/// an error, never a quiet downgrade to a benign-looking UNCHECKED row.
#[test]
fn an_unreadable_reference_values_file_is_an_error_not_an_unchecked_row() {
    let out = bin()
        .arg(GOOD)
        .arg("--reference-values")
        .arg("/nonexistent/reference-values.json")
        .output()
        .expect("run poc-audit");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a bad --reference-values must exit 2"
    );
    assert!(
        out.stdout.is_empty(),
        "a bad --reference-values must print nothing to stdout, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("/nonexistent/reference-values.json"),
        "the error must name the path"
    );
}

/// The other misconfiguration shape: a file that exists but is not valid
/// JSON.
#[test]
fn a_malformed_reference_values_file_is_an_error_not_an_unchecked_row() {
    let out = bin()
        .arg(GOOD)
        .arg("--reference-values")
        .arg("tests/fixtures/reference-values/malformed.json")
        .output()
        .expect("run poc-audit");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a malformed --reference-values file must exit 2"
    );
    assert!(
        out.stdout.is_empty(),
        "a malformed --reference-values file must print nothing to stdout, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tests/fixtures/reference-values/malformed.json"),
        "the error must name the path, got: {stderr}"
    );
}
