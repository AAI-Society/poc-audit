use std::fs;
use std::path::Path;

fn read(dir: &str) -> Vec<(String, String)> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/vectors")
        .join(dir);
    let mut out: Vec<(String, String)> = fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", base.display()))
        .map(|e| {
            let p = e.expect("dir entry").path();
            (
                p.file_name()
                    .expect("file name")
                    .to_string_lossy()
                    .into_owned(),
                fs::read_to_string(&p).expect("read vector"),
            )
        })
        .collect();
    out.sort();
    // A directory that silently became empty would make every assertion below
    // pass vacuously.
    assert!(!out.is_empty(), "no vectors found in {}", base.display());
    out
}

#[test]
fn every_positive_vector_parses() {
    for (name, body) in read("positive") {
        poc_audit::record::Record::parse(&body)
            .unwrap_or_else(|e| panic!("positive vector {name} failed to parse: {e}"));
    }
}

#[test]
fn a_record_missing_a_required_claim_is_an_error() {
    let mut v: serde_json::Value =
        serde_json::from_str(&read("positive")[0].1).expect("positive vector is json");
    v["poc_claims"]
        .as_object_mut()
        .expect("claims object")
        .remove("chain_head");
    let err = poc_audit::record::Record::parse(&v.to_string())
        .expect_err("a record missing chain_head must not parse");
    assert!(
        err.to_string().contains("chain_head"),
        "the error must name the missing field, got: {err}"
    );
}
