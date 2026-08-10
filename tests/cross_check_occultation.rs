use poc_audit::field::{identity::Identity, FieldAuditor};
use poc_audit::record::Record;
use poc_audit::verdict::Context;

/// Our anonymity figures must be occultation's own, and they must survive the
/// trip through our auditor. Checking only `partition()` would pass while
/// `field/identity` printed the wrong number or none at all.
#[test]
fn our_anonymity_figures_are_occultation_s_own() {
    let path = std::path::Path::new("tests/fixtures/occultation/fleet-drifted.toml");
    let fleet = occultation::anonymity::Fleet::load(path).expect("fixture loads");
    let upstream = occultation::anonymity::partition(&fleet).expect("fixture partitions");

    assert!(upstream.fleet_size > 0, "the fixture described no hosts");
    assert!(
        upstream.min_set <= upstream.max_set,
        "min {} exceeds max {}",
        upstream.min_set,
        upstream.max_set
    );
    // The drifted fleet is the one that demonstrates fragmentation; a run
    // reporting one uniform partition means the fixture or the tool changed.
    assert!(
        upstream.max_set < upstream.fleet_size,
        "the drifted fleet no longer fragments: every host is in one set"
    );

    let rec = Record::parse(include_str!(
        "fixtures/vectors/positive/hardware-attested.json"
    ))
    .expect("fixture parses");
    let ctx = Context {
        fleet: Some(path.to_path_buf()),
        ..Default::default()
    };
    let f = Identity("poc_claims.agent_id").audit(&rec, &ctx);

    // The figures reach the operator through `reason`, so assert on what the
    // operator actually reads rather than on an internal value.
    //
    // Each number is asserted TOGETHER WITH ITS LABEL. A bare
    // `contains(&min_set.to_string())` passes coincidentally: on this fixture
    // `min_set` and `singletons` are both 1, and the base reason already
    // contains a stray "1" from the agent id `…ref-1`, so swapping the two
    // fields left the test green. Only `fleet_size` was doing any work.
    for (label, value) in [
        ("hosts", upstream.fleet_size),
        ("smallest anonymity set", upstream.min_set),
        ("singletons", upstream.singletons),
    ] {
        let needle = match label {
            "hosts" => format!("{value} hosts"),
            "singletons" => format!("{value} singletons"),
            _ => format!("{label} {value}"),
        };
        assert!(
            f.reason.contains(&needle),
            "our reason does not carry occultation's own {label} as `{needle}`: {}",
            f.reason
        );
    }
}
