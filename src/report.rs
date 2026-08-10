use crate::record::Record;
use crate::verdict::{Finding, Residual, Verdict, Why};

/// The WHY column's text for one finding.
///
/// `Why::MissingInput` carries the flag that would deepen the row, but until
/// this function existed nothing ever read it — every UNCHECKED-by-missing-
/// input row named its flag only because each auditor's `reason` prose
/// happened to say so. That is a rule enforced by discipline, not structure:
/// a new auditor (or an edit to an existing one) could drop the mention and
/// nothing would catch it. This makes the guarantee structural: the flag is
/// always present in the rendered text, appended if the reason did not
/// already say it, for every `MissingInput` row without exception.
fn why_text(f: &Finding) -> String {
    if let Verdict::Unchecked(Why::MissingInput(flag)) = &f.verdict {
        if !f.reason.contains(flag) {
            return format!("{} (supply {flag})", f.reason);
        }
    }
    f.reason.clone()
}

pub fn render_table(findings: &[Finding]) -> String {
    let width = findings
        .iter()
        .map(|f| f.field.len())
        .max()
        .unwrap_or(0)
        .max(5);
    let mut out = format!(
        "{:<width$}  {:<12}  {}\n",
        "FIELD",
        "VERDICT",
        "WHY",
        width = width
    );
    for f in findings {
        out.push_str(&format!(
            "{:<width$}  {:<12}  {}\n",
            f.field,
            f.verdict.label(),
            why_text(f),
            width = width
        ));
    }
    out.push_str("\nNo aggregate verdict is printed. Each row stands alone; see the exit code.\n");
    out
}

/// The drill-down behind one finding: who must be honest, what they could do,
/// and how long before you would know. This is parallax's model used as the
/// detail view rather than the headline — "five principals, four undetectable"
/// does not tell a developer whether they passed.
pub fn render_explain(findings: &[Finding], field: &str) -> Result<String, String> {
    let f = findings.iter().find(|f| f.field == field).ok_or_else(|| {
        let known: Vec<&str> = findings.iter().map(|f| f.field).collect();
        format!(
            "no such field: {field}\nknown fields:\n  {}",
            known.join("\n  ")
        )
    })?;

    let mut out = format!("{}  {}\n{}\n\n", f.field, f.verdict.label(), why_text(f));
    if f.residual.is_empty() {
        out.push_str("There is no residual trust set behind this finding.\n");
        return Ok(out);
    }
    out.push_str("Who must be honest for this to mean what it says:\n\n");
    let w = f
        .residual
        .iter()
        .map(|r: &Residual| r.principal.len())
        .max()
        .unwrap_or(0);
    for r in &f.residual {
        out.push_str(&format!(
            "  {:<w$}  {}  detect: {}  impact: {}\n",
            r.principal,
            r.capability,
            r.detect,
            r.impact,
            w = w
        ));
    }
    Ok(out)
}

/// `0` clean · `1` a failure or, under `--require-checked`, a row waiting on
/// a missing input · `2` an auditor failed.
///
/// `--require-checked` is scoped to `Why::MissingInput` rows on purpose. A
/// row with `Why::NoAuditor` cannot be turned into anything else by any
/// invocation of this tool, so gating on it would make the flag permanently
/// red on every record — which is how CI gates get deleted.
pub fn exit_code(findings: &[Finding], require_checked: bool) -> u8 {
    if findings.iter().any(|f| f.verdict.auditor_failed()) {
        return 2;
    }
    if findings.iter().any(|f| f.verdict.is_failure()) {
        return 1;
    }
    if require_checked
        && findings
            .iter()
            .any(|f| f.verdict.is_unchecked_missing_input())
    {
        return 1;
    }
    0
}

/// The C8 tier, printed because a conformance process asks for it and
/// subordinated because P01 holds the ladder is wrong as written. Attribution
/// is not decoration: it is the difference between reporting the standard's
/// framing and endorsing it.
pub fn tier_line(rec: &Record) -> String {
    let tier = match rec.submods.attestation.platform.as_str() {
        "SOFTWARE" => 1,
        _ if rec.submods.attestation.reference_values_uri.is_some() => 3,
        _ => 2,
    };
    let why = match tier {
        1 => "platform is SOFTWARE: no hardware isolation",
        2 => "no reference values, so code identity is unestablished",
        _ => "hardware platform with named reference values",
    };
    format!("per C8 (see P01: the ladder is contested): Tier {tier} — {why}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Finding, Residual, Verdict, Why};

    fn finding_with_residual() -> Finding {
        Finding {
            field: "submods.attestation.measurement",
            verdict: Verdict::Asserted,
            reason: "compared to nothing".into(),
            residual: vec![Residual {
                principal: "did:web:intel.com".into(),
                capability: "silicon_and_microcode_integrity".into(),
                detect: "never".into(),
                impact: "Soundness".into(),
            }],
        }
    }

    /// `Why::MissingInput` carries the flag that would deepen a row, and
    /// nothing used to read it: the guarantee that every UNCHECKED-by-missing-
    /// input row names its flag rested entirely on each auditor's author
    /// remembering to mention it in prose. `render_table` now enforces it
    /// structurally: even a reason that forgets the flag gets it appended, so
    /// the rule cannot be silently dropped by a future auditor's reason text.
    #[test]
    fn render_table_names_the_missing_flag_even_if_the_reason_forgot_to() {
        let findings = vec![Finding {
            field: "poc_claims.canonical_snapshot_hash",
            verdict: Verdict::Unchecked(Why::MissingInput("--payload")),
            reason: "the digest is asserted but nothing here recomputes it".into(),
            residual: Vec::new(),
        }];
        let table = render_table(&findings);
        assert!(
            table.contains("--payload"),
            "the flag that would deepen this row must appear in the rendered \
             output, structurally, even though the reason text omitted it: {table}"
        );
    }

    /// The common case — a reason that already names its flag — must not end
    /// up with the flag printed twice.
    #[test]
    fn render_table_does_not_double_the_flag_when_the_reason_already_names_it() {
        let findings = vec![Finding {
            field: "poc_claims.canonical_snapshot_hash",
            verdict: Verdict::Unchecked(Why::MissingInput("--payload")),
            reason: "the record carries one digest; supply --payload to check it".into(),
            residual: Vec::new(),
        }];
        let table = render_table(&findings);
        assert_eq!(
            table.matches("--payload").count(),
            1,
            "the flag must appear once, not doubled by the structural guard: {table}"
        );
    }

    #[test]
    fn explain_prints_every_residual_row() {
        let out = render_explain(
            &[finding_with_residual()],
            "submods.attestation.measurement",
        )
        .expect("field exists");
        assert!(out.contains("did:web:intel.com"), "got: {out}");
        assert!(
            out.contains("silicon_and_microcode_integrity"),
            "got: {out}"
        );
        assert!(out.contains("never"), "got: {out}");
    }

    #[test]
    fn explaining_an_unknown_field_is_an_error_naming_the_field() {
        let err = render_explain(&[finding_with_residual()], "poc_claims.nope")
            .expect_err("unknown field must error");
        assert!(err.contains("poc_claims.nope"), "got: {err}");
    }

    /// A finding with no residual must say so rather than printing an empty
    /// block that reads as "nothing to worry about".
    #[test]
    fn a_finding_with_no_residual_says_so() {
        let f = Finding {
            field: "poc_claims.chain_head",
            verdict: Verdict::Unchecked(Why::NoAuditor),
            reason: "unimplemented".into(),
            residual: Vec::new(),
        };
        let out = render_explain(&[f], "poc_claims.chain_head").expect("field exists");
        assert!(
            out.contains("no residual trust set"),
            "an empty drill-down must be stated, got: {out}"
        );
    }

    #[test]
    fn the_tier_line_attributes_itself_to_the_standard_and_names_the_dispute() {
        let rec = crate::record::Record::parse(include_str!(
            "../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("fixture parses");
        let line = tier_line(&rec);
        assert!(
            line.contains("per C8"),
            "the tier must be attributed: {line}"
        );
        assert!(line.contains("P01"), "the dispute must be named: {line}");
    }

    #[test]
    fn a_software_platform_cannot_reach_tier_3() {
        let mut v: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("json");
        v["submods"]["attestation"]["platform"] = serde_json::json!("SOFTWARE");
        let rec = crate::record::Record::parse(&v.to_string()).expect("parses");
        assert!(
            tier_line(&rec).contains("Tier 1"),
            "got: {}",
            tier_line(&rec)
        );
    }

    /// All three tiers, pinned to distinct inputs.
    ///
    /// Without this, `tier_line` can be hardcoded to return Tier 1 and both
    /// other tests still pass: one checks only for the attribution substrings
    /// and never a tier number, the other only that SOFTWARE yields Tier 1.
    /// Tier 2 — hardware present, reference values absent — was produced by
    /// nothing in the repository, unit or fixture. That is the interesting
    /// tier: it is the one that says the silicon is attested and the code
    /// identity is not.
    #[test]
    fn each_tier_is_reachable_and_named_by_its_own_condition() {
        fn line(platform: &str, reference_values: Option<&str>) -> String {
            let mut v: serde_json::Value = serde_json::from_str(include_str!(
                "../tests/fixtures/vectors/positive/hardware-attested.json"
            ))
            .expect("fixture is json");
            v["submods"]["attestation"]["platform"] = serde_json::json!(platform);
            match reference_values {
                Some(u) => {
                    v["submods"]["attestation"]["reference_values_uri"] = serde_json::json!(u)
                }
                None => {
                    v["submods"]["attestation"]
                        .as_object_mut()
                        .expect("attestation object")
                        .remove("reference_values_uri");
                }
            }
            tier_line(&crate::record::Record::parse(&v.to_string()).expect("parses"))
        }

        let t3 = line("INTEL_TDX", Some("https://rv.example/values.json"));
        let t2 = line("INTEL_TDX", None);
        let t1 = line("SOFTWARE", Some("https://rv.example/values.json"));

        assert!(t3.contains("Tier 3"), "{t3}");
        assert!(t2.contains("Tier 2"), "{t2}");
        assert!(t1.contains("Tier 1"), "{t1}");

        // Distinct inputs must give distinct lines, or one branch is shadowing
        // another while every individual assertion still passes.
        assert_ne!(t3, t2);
        assert_ne!(t2, t1);

        // Tier 2's reason must name what is missing, not merely be a number.
        assert!(
            t2.contains("reference values"),
            "Tier 2 must say why it is not Tier 3: {t2}"
        );
    }

    /// The report must never print an aggregate pass, and the tier line is the
    /// nearest thing to one. Guard the words directly — in every user-facing
    /// rendering, not only `render_table`.
    ///
    /// This test used to call only `render_table`. Prepending
    /// `"COMPLIANT — this deployment passed."` to `tier_line`'s output left
    /// every test green while the binary printed it, because nothing here
    /// ever looked at `tier_line`'s or `render_explain`'s output. All three
    /// renderings are checked now.
    ///
    /// `render_explain` has two branches — the early return for an empty
    /// residual, and the header-plus-rows path for a non-empty one — and a
    /// finding with an EMPTY residual only ever exercises the first. A
    /// reviewer mutated the residual-printing header to
    /// `"COMPLIANT. Who must be honest…"` and every test, including an
    /// earlier version of this one, stayed green. Both branches are checked
    /// now, the second via `finding_with_residual()`.
    #[test]
    fn no_rendering_prints_an_aggregate_pass() {
        let findings = vec![Finding {
            field: "a",
            verdict: Verdict::Asserted,
            reason: "r".into(),
            residual: vec![],
        }];
        let banned = ["compliant", "passed", "conformant"];

        let table = render_table(&findings).to_lowercase();
        for word in banned {
            assert!(!table.contains(word), "render_table said {word:?}");
        }

        let rec = crate::record::Record::parse(include_str!(
            "../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("fixture parses");
        let tier = tier_line(&rec).to_lowercase();
        for word in banned {
            assert!(!tier.contains(word), "tier_line said {word:?}");
        }

        let explain_empty = render_explain(&findings, "a")
            .expect("field exists")
            .to_lowercase();
        for word in banned {
            assert!(
                !explain_empty.contains(word),
                "render_explain (empty residual) said {word:?}"
            );
        }

        let with_residual = vec![finding_with_residual()];
        let explain_residual = render_explain(&with_residual, "submods.attestation.measurement")
            .expect("field exists")
            .to_lowercase();
        for word in banned {
            assert!(
                !explain_residual.contains(word),
                "render_explain (non-empty residual) said {word:?}"
            );
        }
    }
}
