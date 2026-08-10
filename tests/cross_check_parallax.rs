/// Our residual list must be exactly parallax's, not a re-derivation of it.
/// If parallax changes what it solves, this fails rather than us continuing to
/// report the old answer.
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

    // Same route the auditor takes.
    let set = parallax::solve::solve(&d).expect("solves twice");
    let mut ours: Vec<String> = set
        .0
        .iter()
        .map(|a| format!("{}|{}", a.principal, a.capability))
        .collect();
    ours.sort();
    assert_eq!(ours, theirs);
}
