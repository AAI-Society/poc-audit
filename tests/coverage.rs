use std::collections::BTreeSet;

/// The schema's `required` arrays are the source of truth for the report's
/// rows. When the standard adds a required field, this fails rather than the
/// report silently narrowing.
#[test]
fn every_required_field_is_accounted_for() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/poc-evidence.schema.json"
    ))
    .expect("vendored schema is json");

    let mut required: BTreeSet<String> = BTreeSet::new();
    for r in schema["required"].as_array().expect("top-level required") {
        required.insert(r.as_str().expect("required entry is a string").to_string());
    }
    for r in schema["$defs"]["pocClaims"]["required"].as_array().expect("pocClaims required") {
        required.insert(format!("poc_claims.{}", r.as_str().expect("string")));
    }
    for r in schema["$defs"]["attestation"]["required"].as_array().expect("attestation required") {
        required.insert(format!("submods.attestation.{}", r.as_str().expect("string")));
    }
    assert!(required.len() > 10, "the schema parse found almost nothing: {required:?}");

    let accounted: BTreeSet<String> = poc_audit::registry::ACCOUNTED
        .iter()
        .map(|(f, _)| (*f).to_string())
        .collect();

    // Every Audited field must have an auditor claiming it. `run` panics on a
    // mismatch by design, and until this test existed that panic was invisible:
    // no test ran the binary, so a registry claiming auditors it did not have
    // shipped a tool that died on its first real record.
    let claimed: BTreeSet<&str> = poc_audit::registry::auditors()
        .iter()
        .map(|a| a.field())
        .collect();
    for (field, coverage) in poc_audit::registry::ACCOUNTED {
        if matches!(coverage, poc_audit::registry::Coverage::Audited) {
            assert!(
                claimed.contains(field),
                "{field} is marked Audited but no auditor claims it; \
                 registry::run would panic on every record"
            );
        }
    }

    let unaccounted: Vec<&String> = required.difference(&accounted).collect();
    assert!(
        unaccounted.is_empty(),
        "the schema requires fields that ACCOUNTED does not list: {unaccounted:?}\n\
         Add each to src/registry.rs, either with an auditor or as \
         Coverage::Unaudited with a reason."
    );

    let stale: Vec<&String> = accounted.difference(&required).collect();
    assert!(
        stale.is_empty(),
        "ACCOUNTED lists fields the schema does not require: {stale:?}"
    );
}

/// Task 2's deliverable is a complete tool that honestly reports nothing, so
/// running it end to end has to work. Without this, `registry::run`'s
/// deliberate panic on an unclaimed Audited field is invisible until someone
/// runs the CLI by hand.
#[test]
fn the_binary_audits_a_real_record_without_panicking() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_poc-audit"))
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .output()
        .expect("run poc-audit");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.code().is_some(),
        "the binary died on a signal; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "the binary panicked on a valid record:\n{stderr}"
    );
    assert_eq!(
        stdout.lines().filter(|l| l.contains("UNCHECKED")).count(),
        poc_audit::registry::ACCOUNTED.len(),
        "every accounted field must produce a row at this stage:\n{stdout}"
    );
}
