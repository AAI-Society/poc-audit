use super::FieldAuditor;
use crate::record::Record;
use crate::verdict::{BackedBy, Context, Finding, Profile, Residual, Verdict, Why};

/// Audits `poc_claims.agent_id` and `poc_claims.initiating_user`.
///
/// occultation's finding is not that these fields are wrong but that C5.1.1
/// requires both and an unlinkable profile cannot supply either. That is a
/// requirement a profile must suspend, not one better engineering satisfies.
pub struct Identity(pub &'static str);

impl Identity {
    /// Exact match on the two field paths this auditor is ever constructed
    /// with in `registry::auditors()`. A `.ends_with("agent_id")` /
    /// fall-through-else dispatch quietly reads `initiating_user`'s value for
    /// ANY other field path, including a typo — so an unrecognized path
    /// panics here rather than silently quoting the wrong field.
    fn value<'a>(&self, rec: &'a Record) -> &'a str {
        match self.0 {
            "poc_claims.agent_id" => &rec.poc_claims.agent_id,
            "poc_claims.initiating_user" => &rec.poc_claims.initiating_user,
            other => panic!("Identity auditor constructed with unknown field path: {other}"),
        }
    }
}

impl FieldAuditor for Identity {
    fn field(&self) -> &'static str {
        self.0
    }

    fn audit(&self, rec: &Record, ctx: &Context) -> Finding {
        let value = self.value(rec);
        if value.trim().is_empty() {
            return Finding {
                field: self.0,
                verdict: Verdict::Unchecked(Why::NoAuditor),
                reason: "the field is empty; there is no identifier to assess".into(),
                residual: Vec::new(),
            };
        }

        // The same identifier earns opposite verdicts under the two profiles,
        // and the record cannot say which is in force. Under Standard this
        // field is SATISFIED; reporting a failure would be a false finding on
        // every conformant record.
        let (verdict, mut reason) = match ctx.profile {
            Profile::Standard => (
                Verdict::Established(
                    BackedBy::new("the record carries a persistent identifier")
                        .expect("non-empty literal"),
                ),
                format!(
                    "'{value}' is a persistent identifier, so C5.1.1 is satisfied. \
                     The cost is that every action carrying it is linkable to one \
                     subject — which is precisely what an unlinkable profile \
                     cannot provide"
                ),
            ),
            Profile::Unlinkable => (
                Verdict::CannotHold,
                format!(
                    "an unlinkable profile is declared, and C5.1.1 requires a \
                     persistent identifier. '{value}' is one, so either the \
                     profile is not in force or the requirement must be \
                     suspended. It cannot be satisfied"
                ),
            ),
        };
        let mut residual = Vec::new();

        if let Some(path) = ctx.fleet.as_ref() {
            match occultation::anonymity::Fleet::load(path)
                .and_then(|f| occultation::anonymity::partition(&f))
            {
                Ok(r) => {
                    reason.push_str(&format!(
                        ". Against the supplied fleet: {} hosts, smallest anonymity set {}, \
                         effective set {:.1}, {} singletons",
                        r.fleet_size, r.min_set, r.effective_set, r.singletons
                    ));
                    residual.push(Residual {
                        principal: "the relying party".into(),
                        capability: format!(
                            "distinguishes this agent among {} in the smallest set",
                            r.min_set
                        ),
                        detect: "never".into(),
                        impact: "Privacy".into(),
                    });
                }
                Err(e) => {
                    return Finding {
                        field: self.0,
                        verdict: Verdict::Unchecked(Why::AuditorFailed(e.to_string())),
                        reason: format!("occultation could not partition the fleet: {e}"),
                        residual: Vec::new(),
                    }
                }
            }
        } else {
            reason.push_str(". Supply --fleet for the anonymity-set size");
        }

        Finding {
            field: self.0,
            verdict,
            reason,
            residual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;
    use crate::verdict::Context;

    fn record_with_agent(agent_id: &str) -> Record {
        let mut v: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("fixture is json");
        v["poc_claims"]["agent_id"] = serde_json::json!(agent_id);
        Record::parse(&v.to_string()).expect("fixture parses")
    }

    fn record_with_both(agent_id: &str, initiating_user: &str) -> Record {
        let mut v: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("fixture is json");
        v["poc_claims"]["agent_id"] = serde_json::json!(agent_id);
        v["poc_claims"]["initiating_user"] = serde_json::json!(initiating_user);
        Record::parse(&v.to_string()).expect("fixture parses")
    }

    /// Under the default profile a persistent identifier SATISFIES C5.1.1.
    /// Reporting a failure here would be a false finding on every conformant
    /// record — the overclaim this whole programme attacks.
    #[test]
    fn a_stable_agent_id_is_established_under_the_default_profile() {
        let f = Identity("poc_claims.agent_id").audit(
            &record_with_agent("did:web:example.org:agents:ref-1"),
            &Context::default(),
        );
        assert_eq!(f.verdict.label(), "ESTABLISHED");
        assert!(
            f.reason.contains("linkable"),
            "satisfying C5.1.1 has a cost and the reason must name it, got: {}",
            f.reason
        );
    }

    /// The same record, the other profile, the opposite verdict. This pair is
    /// the whole point: the record cannot tell you which profile is in force,
    /// so the operator must.
    #[test]
    fn the_same_id_cannot_hold_once_an_unlinkable_profile_is_declared() {
        let ctx = Context {
            profile: Profile::Unlinkable,
            ..Default::default()
        };
        let f = Identity("poc_claims.agent_id")
            .audit(&record_with_agent("did:web:example.org:agents:ref-1"), &ctx);
        assert_eq!(f.verdict.label(), "CANNOT HOLD");
        assert!(f.reason.contains("C5.1.1"), "got: {}", f.reason);
    }

    /// An empty identifier is not a persistent one, so neither verdict above
    /// applies — otherwise both are hardcoded on the profile alone.
    #[test]
    fn an_absent_identifier_is_neither_established_nor_cannot_hold() {
        for profile in [Profile::Standard, Profile::Unlinkable] {
            let ctx = Context {
                profile,
                ..Default::default()
            };
            let f = Identity("poc_claims.agent_id").audit(&record_with_agent(""), &ctx);
            assert_ne!(f.verdict.label(), "ESTABLISHED", "profile {profile:?}");
            assert_ne!(f.verdict.label(), "CANNOT HOLD", "profile {profile:?}");
        }
    }

    /// This auditor must work with no flags at all, or a first run shows an
    /// entirely UNCHECKED table and reads as a broken tool.
    #[test]
    fn it_returns_a_real_verdict_with_no_context() {
        let f = Identity("poc_claims.agent_id").audit(
            &record_with_agent("did:web:example.org:agents:ref-1"),
            &Context::default(),
        );
        assert!(!f.verdict.is_unchecked());
    }

    /// `Identity::value`'s dispatch used to be `ends_with("agent_id")` /
    /// else, which falls through to `initiating_user` for ANY other field
    /// path. Replacing the whole if/else with `&rec.poc_claims.agent_id`
    /// left every existing test green, because none of them constructed
    /// `Identity("poc_claims.initiating_user")` with a record where the two
    /// values differ. This one does, and reads the reason — the only place
    /// the value surfaces — to prove `initiating_user`'s own value came
    /// through, not `agent_id`'s. See IMPORTANT 4.
    #[test]
    fn initiating_user_reads_its_own_field_not_agent_id() {
        let rec = record_with_both(
            "did:web:example.org:agents:agent-value",
            "user:initiating-value",
        );
        let f = Identity("poc_claims.initiating_user").audit(&rec, &Context::default());
        assert!(
            f.reason.contains("user:initiating-value"),
            "expected initiating_user's own value in the reason, got: {}",
            f.reason
        );
        assert!(
            !f.reason.contains("agent-value"),
            "must not quote agent_id's value for the initiating_user row, got: {}",
            f.reason
        );
    }
}
