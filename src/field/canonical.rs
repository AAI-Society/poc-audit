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

/// Takes the list rather than fetching it, so a test can supply a synthetic
/// one. Fetching it internally makes this note — the entire host-dependence
/// honesty of this auditor — unverifiable on any machine that happens to have
/// every runtime installed, which is precisely the machine where it silently
/// does nothing.
fn missing_note(missing: &[transit::external::Missing]) -> String {
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

/// Occurrences of the note's name in real code, ignoring comment lines.
///
/// A raw `matches(..).count()` over the source is satisfied by a comment, so
/// the guard that uses it can be defeated by the same edit that breaks what it
/// guards. Borrowed from the sibling `occultation` crate, whose formatter ban
/// strips comment lines for exactly this reason.
#[cfg(test)]
fn count_real_calls(src: &str) -> usize {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(|l| l.matches("missing_note(").count())
        .sum()
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
                    missing_note(&transit::external::missing_runtimes())
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
                    missing_note(&transit::external::missing_runtimes())
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
    ///
    /// Synthetic input, deliberately. The host-derived version of this test
    /// does nothing at all on a machine with every runtime installed — the
    /// exact machine where a silent omission would never be noticed.
    #[test]
    fn the_note_names_every_missing_runtime_and_counts_them() {
        let missing = vec![
            transit::external::Missing {
                id: "go",
                runtime: "go",
                reason: None,
            },
            transit::external::Missing {
                id: "node",
                runtime: "node",
                reason: None,
            },
        ];
        let note = missing_note(&missing);
        assert!(note.contains("go"), "got: {note}");
        assert!(note.contains("node"), "got: {note}");
        assert!(
            note.contains('2'),
            "the count must reach the reader: {note}"
        );
    }

    #[test]
    fn the_note_is_empty_when_no_runtime_is_missing() {
        assert_eq!(missing_note(&[]), "");
    }

    /// Both branches must carry the note, and the dangerous direction is the
    /// AGREEING one: an absence of divergence computed by fewer decoders is
    /// the weakest result this tool can produce and the one most likely to be
    /// read as "fine". Deleting the call from that branch alone survived the
    /// suite on a host with every runtime installed, because the note is then
    /// empty either way. A lexical guard catches it on any host.
    #[test]
    fn both_branches_carry_the_note() {
        let src = include_str!("canonical.rs");
        let marker = "#[cfg(test)]\nmod tests {";
        assert_eq!(src.matches(marker).count(), 1, "ambiguous test module");
        let non_test = src.split(marker).next().expect("split yields a head");
        assert_eq!(
            count_real_calls(non_test),
            4,
            "expected the definition, one call in each of the two branches, and one \
             occurrence inside count_real_calls's own string literal; \
             the agreeing branch is the one that silently loses it"
        );
    }

    /// The guard above counts occurrences in source, and a raw substring count
    /// is satisfied by a COMMENT. A reviewer demonstrated it: deleting the real
    /// call from the agreeing branch and adding a commented-out mention
    /// restored the count, and the suite went green while the regression it
    /// exists to catch was live. Comment lines are therefore stripped before
    /// counting, and this test is what holds that.
    #[test]
    fn a_commented_mention_does_not_satisfy_the_guard() {
        let synthetic = concat!(
            "fn missing_note(m: &[X]) -> String { }\n",
            "    // a mention of missing_note( in a comment\n",
            "        let a = missing_note(&x);\n",
        );
        assert_eq!(
            count_real_calls(synthetic),
            2,
            "a commented occurrence was counted as a call"
        );
    }
}
