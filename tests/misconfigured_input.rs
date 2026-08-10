use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_poc-audit"))
}

/// A bad path must be an error, never a quiet downgrade. `UNCHECKED` looks
/// benign, so a typo would otherwise turn a real audit into a clean-looking
/// report with fewer rows. This is the failure mode most likely to occur.
#[test]
fn an_unreadable_deployment_is_an_error_not_an_unchecked_row() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .arg("--deployment")
        .arg("/nonexistent/deployment.toml")
        .output()
        .expect("run poc-audit");

    assert_eq!(out.status.code(), Some(2), "a bad --deployment must exit 2");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("UNCHECKED"),
        "a bad --deployment produced a report instead of an error:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("/nonexistent/deployment.toml"),
        "the error must name the path, got: {stderr}"
    );
}

/// The same strictness applies to `--payload`: a bad path is an error, not a
/// quiet downgrade to an UNCHECKED row.
#[test]
fn an_unreadable_payload_is_an_error_not_an_unchecked_row() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .arg("--payload")
        .arg("/nonexistent/payload.json")
        .output()
        .expect("run poc-audit");

    assert_eq!(out.status.code(), Some(2), "a bad --payload must exit 2");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("UNCHECKED"),
        "a bad --payload produced a report instead of an error:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("/nonexistent/payload.json"),
        "the error must name the path, got: {stderr}"
    );
}

/// The same strictness applies to `--fleet`: a bad path is an error, not a
/// quiet downgrade to an UNCHECKED row. `--deployment` and `--payload` each
/// got this test the moment they gained the strict pre-check; `--fleet` uses
/// the identical pattern and needs the identical guard, or a later refactor
/// of the exit matrix could regress it with nothing to catch it.
#[test]
fn an_unreadable_fleet_is_an_error_not_an_unchecked_row() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .arg("--fleet")
        .arg("/nonexistent/fleet.toml")
        .output()
        .expect("run poc-audit");

    assert_eq!(out.status.code(), Some(2), "a bad --fleet must exit 2");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("UNCHECKED"),
        "a bad --fleet produced a report instead of an error"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("/nonexistent/fleet.toml"),
        "the error must name the path"
    );
}

/// `--explain` naming a field that does not exist is an error, not a silent
/// success: it must exit 2 with the field named on stderr, and print nothing
/// on stdout that could be mistaken for a report.
#[test]
fn explaining_an_unknown_field_exits_2_and_names_the_field() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .arg("--explain")
        .arg("poc_claims.nope")
        .output()
        .expect("run poc-audit");

    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown --explain field must exit 2, got: {:?} stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "an unknown --explain field must print no report to stdout"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("poc_claims.nope"),
        "the error must name the field"
    );
}
