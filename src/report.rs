use crate::verdict::Finding;

pub fn render_table(findings: &[Finding]) -> String {
    let width = findings.iter().map(|f| f.field.len()).max().unwrap_or(0).max(5);
    let mut out = format!("{:<width$}  {:<12}  {}\n", "FIELD", "VERDICT", "WHY", width = width);
    for f in findings {
        out.push_str(&format!(
            "{:<width$}  {:<12}  {}\n",
            f.field,
            f.verdict.label(),
            f.reason,
            width = width
        ));
    }
    out.push_str(
        "\nNo aggregate verdict is printed. Each row stands alone; see the exit code.\n",
    );
    out
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
