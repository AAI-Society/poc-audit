use crate::record::Record;
use crate::verdict::{Finding, Residual};

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
            f.reason,
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

    let mut out = format!("{}  {}\n{}\n\n", f.field, f.verdict.label(), f.reason);
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

/// `0` clean · `1` a failure or, under `--require-checked`, an unchecked row ·
/// `2` an auditor failed.
pub fn exit_code(findings: &[Finding], require_checked: bool) -> u8 {
    if findings.iter().any(|f| f.verdict.auditor_failed()) {
        return 2;
    }
    if findings.iter().any(|f| f.verdict.is_failure()) {
        return 1;
    }
    if require_checked && findings.iter().any(|f| f.verdict.is_unchecked()) {
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
    /// nearest thing to one. Guard the words directly.
    #[test]
    fn no_rendering_prints_an_aggregate_pass() {
        let findings = vec![Finding {
            field: "a",
            verdict: Verdict::Asserted,
            reason: "r".into(),
            residual: vec![],
        }];
        let table = render_table(&findings).to_lowercase();
        for banned in ["compliant", "passed", "conformant"] {
            assert!(!table.contains(banned), "the table said {banned:?}");
        }
    }
}
