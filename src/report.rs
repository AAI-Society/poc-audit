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
}
