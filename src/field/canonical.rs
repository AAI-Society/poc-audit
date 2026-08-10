use super::FieldAuditor;
use crate::record::Record;
use crate::verdict::{Context, Finding, Residual, Verdict, Why};

/// Audits `poc_claims.canonical_snapshot_hash`.
///
/// The record carries one digest. transit's finding is that two parties can
/// compute different digests over the same wire bytes, so one field name hides
/// a divergence. This runs the payload through every decoder model available
/// and reports whether they agree about what it *means*.
pub struct Canonical;

const FIELD: &str = "poc_claims.canonical_snapshot_hash";

fn missing_note() -> String {
    let missing = transit::external::missing_runtimes();
    if missing.is_empty() {
        String::new()
    } else {
        let ids: Vec<&str> = missing.iter().map(|m| m.id).collect();
        format!(
            " (weaker result: {} decoder runtimes missing on this host: {})",
            ids.len(),
            ids.join(", ")
        )
    }
}

impl FieldAuditor for Canonical {
    fn field(&self) -> &'static str {
        FIELD
    }

    fn audit(&self, _rec: &Record, ctx: &Context) -> Finding {
        let Some(payload) = ctx.payload.as_ref() else {
            return Finding {
                field: FIELD,
                verdict: Verdict::Unchecked(Why::MissingInput("--payload")),
                reason: "the record carries one digest; supply --payload to find out \
                         whether both sides compute it the same way"
                    .into(),
                residual: Vec::new(),
            };
        };

        let case = transit::differential::run_payload(payload);
        match case.divergence {
            Some(d) => Finding {
                field: FIELD,
                verdict: Verdict::Diverges,
                reason: format!(
                    "{} decoders disagree about what this payload means{}",
                    d.classes.len(),
                    missing_note()
                ),
                residual: d
                    .classes
                    .iter()
                    .map(|(observation, ids)| Residual {
                        principal: ids.join(", "),
                        capability: format!("reads this payload as {observation}"),
                        detect: "never".into(),
                        impact: "Soundness".into(),
                    })
                    .collect(),
            },
            None => Finding {
                field: FIELD,
                verdict: Verdict::Asserted,
                reason: format!(
                    "every decoder that ran agreed on this payload; the digest is \
                     still asserted rather than recomputed here{}",
                    missing_note()
                ),
                residual: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;
    use crate::verdict::Context;

    fn record() -> Record {
        Record::parse(include_str!(
            "../../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("fixture parses")
    }

    fn ctx_with(payload: &str) -> Context {
        Context {
            payload: Some(payload.to_string()),
            ..Default::default()
        }
    }

    /// The duplicate-key payload is transit's headline finding: one byte
    /// sequence, two decoders, two different canonical forms.
    #[test]
    fn a_duplicate_key_payload_diverges() {
        let payload = r#"{"to":"acct-legit","amount":100,"to":"acct-attacker"}"#;
        let f = Canonical.audit(&record(), &ctx_with(payload));
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
    }

    /// The other direction, so DIVERGES is not hardcoded.
    #[test]
    fn an_unambiguous_payload_does_not_diverge() {
        let payload = r#"{"amount":100,"to":"acct-legit"}"#;
        let f = Canonical.audit(&record(), &ctx_with(payload));
        assert_ne!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
    }

    #[test]
    fn no_payload_is_unchecked_and_names_the_flag() {
        let f = Canonical.audit(&record(), &Context::default());
        assert_eq!(f.verdict.label(), "UNCHECKED");
        assert!(f.reason.contains("--payload"), "got: {}", f.reason);
    }

    /// A result computed by fewer decoders is weaker, and the report must say
    /// so rather than varying silently by host.
    #[test]
    fn the_reason_names_missing_runtimes_when_there_are_any() {
        let f = Canonical.audit(&record(), &ctx_with(r#"{"a":1}"#));
        let missing = transit::external::missing_runtimes();
        if !missing.is_empty() {
            assert!(
                f.reason.contains("missing"),
                "runtimes were missing but the reason did not say so: {}",
                f.reason
            );
        }
    }
}
