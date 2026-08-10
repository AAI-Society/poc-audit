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
