use std::collections::BTreeSet;

/// The schema's `required` arrays are the source of truth for the report's
/// rows. When the standard adds a required field, this fails rather than the
/// report silently narrowing.
#[test]
fn every_required_field_is_accounted_for() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/poc-evidence.schema.json"))
            .expect("vendored schema is json");

    let mut required: BTreeSet<String> = BTreeSet::new();
    for r in schema["required"].as_array().expect("top-level required") {
        required.insert(r.as_str().expect("required entry is a string").to_string());
    }
    for r in schema["$defs"]["pocClaims"]["required"]
        .as_array()
        .expect("pocClaims required")
    {
        required.insert(format!("poc_claims.{}", r.as_str().expect("string")));
    }
    for r in schema["$defs"]["attestation"]["required"]
        .as_array()
        .expect("attestation required")
    {
        required.insert(format!(
            "submods.attestation.{}",
            r.as_str().expect("string")
        ));
    }
    assert!(
        required.len() > 10,
        "the schema parse found almost nothing: {required:?}"
    );

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

    // And the other direction: a field an auditor claims but that ACCOUNTED
    // still marks Unaudited is not caught by the panic above (`run` just
    // never calls the auditor), so it needs its own check. This is the silent
    // half of the mismatch: a real, working auditor whose row quietly stays
    // UNCHECKED with a stale reason -- exactly the "clean-looking report with
    // fewer rows" this tool exists to prevent, only here it is the registry's
    // own bookkeeping doing it rather than a misconfigured input.
    for field in &claimed {
        let coverage = poc_audit::registry::ACCOUNTED
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, c)| c);
        assert!(
            matches!(coverage, Some(poc_audit::registry::Coverage::Audited)),
            "{field} has an auditor claiming it but ACCOUNTED does not mark it \
             Coverage::Audited; its row would silently stay UNCHECKED"
        );
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

/// The whole tool has to work end to end, not just its parts in isolation.
/// Without this, `registry::run`'s deliberate panic on an unclaimed Audited
/// field is invisible until someone runs the CLI by hand.
///
/// This no longer asserts every row is `UNCHECKED`: that was only true at
/// Task 2's baseline, before any real auditor existed. From Task 3 onward
/// some fields are genuinely audited, so the invariant this test can still
/// hold unconditionally is narrower — every accounted field produces exactly
/// one row, and the binary never panics producing them.
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

    let row_fields: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    for (field, _) in poc_audit::registry::ACCOUNTED {
        assert_eq!(
            row_fields.iter().filter(|f| *f == field).count(),
            1,
            "expected exactly one row for {field}:\n{stdout}"
        );
    }
}
