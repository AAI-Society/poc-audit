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

    // This early-return error path never reaches `render_table`, so stdout
    // is empty — not merely free of the substring "UNCHECKED", which an
    // empty string is trivially and unfalsifiably free of. Assert the real
    // property: nothing was printed on the path where a real report would
    // be everything that follows.
    assert!(
        out.stdout.is_empty(),
        "a bad --deployment must print nothing to stdout, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
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

    // See the matching comment on the --deployment test above: the real,
    // falsifiable property on this early-return path is an empty stdout, not
    // an unfalsifiable substring check on what could be an empty string.
    assert!(
        out.stdout.is_empty(),
        "a bad --payload must print nothing to stdout, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
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
    // See the matching comment on the --deployment test above.
    assert!(
        out.stdout.is_empty(),
        "a bad --fleet must print nothing to stdout, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("/nonexistent/fleet.toml"),
        "the error must name the path"
    );
}

/// The most likely misconfiguration of `--payload` is not a bad path but a
/// wrong or truncated FILE: empty, or not JSON at all. Before this fix, that
/// silently produced `ASSERTED — "every decoder that ran agreed on this
/// payload"` at exit 0 — a *cleaner-looking* row than supplying nothing,
/// because transit's differential over an empty/garbage string finds no
/// decoders disagreeing about a payload none of them could parse. That
/// violates FAILS LOUD: a misconfigured input must be an error, never a
/// quiet downgrade to a good-looking verdict. `--deployment` and `--fleet`
/// already validate at load time; `--payload` must too.
#[test]
fn an_empty_payload_is_an_error_not_an_asserted_row() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .arg("--payload")
        .arg("tests/fixtures/payload/empty.json")
        .output()
        .expect("run poc-audit");

    assert_eq!(out.status.code(), Some(2), "an empty --payload must exit 2");
    assert!(
        out.stdout.is_empty(),
        "an empty --payload must print no report to stdout, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tests/fixtures/payload/empty.json"),
        "the error must name the path, got: {stderr}"
    );
}

/// The other shape of the same misconfiguration: a file that has content but
/// is not JSON (e.g. the wrong file was passed).
#[test]
fn a_non_json_payload_is_an_error_not_an_asserted_row() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .arg("--payload")
        .arg("tests/fixtures/payload/not-json.txt")
        .output()
        .expect("run poc-audit");

    assert_eq!(
        out.status.code(),
        Some(2),
        "a non-JSON --payload must exit 2"
    );
    assert!(
        out.stdout.is_empty(),
        "a non-JSON --payload must print no report to stdout, got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tests/fixtures/payload/not-json.txt"),
        "the error must name the path, got: {stderr}"
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
