use poc_audit::field::{canonical::Canonical, FieldAuditor};
use poc_audit::record::Record;
use poc_audit::verdict::Context;

/// transit ships this payload as its headline demonstration.
///
/// Both halves matter and the test asserts both. Upstream must still find the
/// divergence, AND our auditor must still surface it — a test that only
/// checked upstream would pass while `field/canonical` dropped the result on
/// the floor. Run everything through our auditor, then compare against
/// transit's own answer.
#[test]
fn our_divergence_is_transit_s_own() {
    let payload = r#"{"to":"acct-legit","amount":100,"to":"acct-attacker"}"#;

    let case = transit::differential::run_payload(payload);
    let upstream = case.divergence.expect(
        "transit no longer diverges on its own duplicate-key example; \
         poc-audit's field/canonical is built on the assumption that it does",
    );
    assert!(
        upstream.classes.len() >= 2,
        "a divergence with fewer than two classes is not a disagreement: {:?}",
        upstream.classes
    );

    let rec = Record::parse(include_str!(
        "fixtures/vectors/positive/hardware-attested.json"
    ))
    .expect("fixture parses");
    let ctx = Context {
        payload: Some(payload.to_string()),
        ..Default::default()
    };
    let f = Canonical.audit(&rec, &ctx);

    assert_eq!(
        f.verdict.label(),
        "DIVERGES",
        "upstream found a divergence and our auditor did not; reason: {}",
        f.reason
    );
    assert_eq!(
        f.residual.len(),
        upstream.classes.len(),
        "our residual rows must be one per observation class transit reported"
    );
}
