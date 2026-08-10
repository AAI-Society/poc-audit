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
