use poc_audit::field::{attestation::AttestationField, FieldAuditor};
use poc_audit::record::Record;
use poc_audit::verdict::Context;

/// Our residual list must be exactly parallax's own.
///
/// This test must run through OUR auditor. An earlier version called
/// `solve()` twice and compared the results — a pure function fed the same
/// input twice, which cannot fail for any reason this crate could cause. It
/// would have passed while `measurement_finding` swapped `principal` and
/// `capability`, dropped entries, or mis-formatted `detect`. The seam being
/// tested is the mapping from `parallax::trust::Assumption` to
/// `verdict::Residual`, so the mapping has to be in the call path.
#[test]
fn our_residual_list_is_parallax_s_own() {
    let path = std::path::Path::new("tests/fixtures/parallax/sigma2-tdx.toml");
    let d = parallax::deployment::Deployment::load(path).expect("fixture loads");
    let upstream = parallax::solve::solve(&d).expect("fixture solves");

    let mut theirs: Vec<String> = upstream
        .0
        .iter()
        .map(|a| format!("{}|{}", a.principal, a.capability))
        .collect();
    theirs.sort();
    assert!(!theirs.is_empty(), "the fixture solved to nothing");

    // Reference values must be present, or the auditor short-circuits to
    // ASSERTED and never reaches the solver.
    let mut v: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/vectors/positive/hardware-attested.json"
    ))
    .expect("fixture is json");
    v["submods"]["attestation"]["reference_values_uri"] =
        serde_json::json!("https://rv.example/values.json");
    let rec = Record::parse(&v.to_string()).expect("fixture parses");

    let ctx = Context {
        deployment: Some(path.to_path_buf()),
        ..Default::default()
    };
    let f = AttestationField("submods.attestation.measurement").audit(&rec, &ctx);

    // ASSERTED, not ESTABLISHED: the solver tells us who must be honest for
    // the *reference values* to hold, but nothing here ever compares this
    // record's measurement against them. See CRITICAL 2.
    //
    // ASSERTED alone no longer discriminates whether the solver was reached:
    // the short-circuit branch (no reference_values_uri) is ASSERTED too. The
    // reference values are set above, so that branch cannot fire here — what
    // actually proves the solver ran is the residual comparison below: the
    // short-circuit branch always returns an empty residual, and `theirs` is
    // asserted non-empty, so a short-circuit would fail `ours == theirs`
    // rather than merely fail a label check.
    assert_eq!(f.verdict.label(), "ASSERTED", "reason was: {}", f.reason);

    let mut ours: Vec<String> = f
        .residual
        .iter()
        .map(|r| format!("{}|{}", r.principal, r.capability))
        .collect();
    ours.sort();
    assert_eq!(
        ours, theirs,
        "our residual list diverged from parallax's own answer \
         (or the auditor short-circuited: theirs is non-empty, so an empty \
         `ours` here means the solver was never reached)"
    );
}
