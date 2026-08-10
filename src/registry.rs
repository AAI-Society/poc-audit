use crate::field::{chain::Chain, FieldAuditor};
use crate::record::Record;
use crate::verdict::{Context, Finding, Verdict, Why};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// An auditor in `auditors()` claims this field.
    Audited,
    /// Deliberately not audited. The string is shown as the row's reason.
    Unaudited(&'static str),
}

/// Every field the schema requires, and how it is covered.
///
/// This list is the acknowledgement gate. A field added upstream fails
/// `every_required_field_is_accounted_for` until someone decides, explicitly,
/// whether it gets an auditor or a reason.
pub const ACCOUNTED: &[(&str, Coverage)] = &[
    ("iss",         Coverage::Unaudited("issuer identity is out of scope")),
    ("iat",         Coverage::Unaudited("issuance time is out of scope")),
    ("nonce",       Coverage::Unaudited("freshness against a challenge is out of scope")),
    ("eat_profile", Coverage::Unaudited("profile identity is checked by validate.py")),
    ("poc_claims",  Coverage::Unaudited("audited through its individual claims")),
    ("submods",     Coverage::Unaudited("audited through submods.attestation.*")),

    // Flipped to Coverage::Audited by the task that adds the auditor. A field
    // marked Audited with no auditor claiming it panics `run` by design, so
    // these two facts must move together, in one commit, every time.
    ("poc_claims.agent_id",                Coverage::Unaudited("identity auditor arrives in Task 5")),
    ("poc_claims.initiating_user",         Coverage::Unaudited("identity auditor arrives in Task 5")),
    ("poc_claims.canonical_snapshot_hash", Coverage::Unaudited("canonical auditor arrives in Task 4")),

    ("poc_claims.chain_head",              Coverage::Audited),
    ("poc_claims.merkle_root",             Coverage::Audited),
    ("poc_claims.step_index",              Coverage::Audited),

    ("poc_claims.agbom_digest",       Coverage::Unaudited("no AgBOM tooling exists; see P10")),
    ("poc_claims.interception_point", Coverage::Unaudited("enumerated value, checked by validate.py")),
    ("poc_claims.tree_size",          Coverage::Unaudited("consistency with step_index is validate.py's semantic layer")),
    ("poc_claims.policy_bundle_hash", Coverage::Unaudited("no policy-bundle tooling exists")),
    ("poc_claims.target_resource",    Coverage::Unaudited("free text; nothing to check it against")),
    ("poc_claims.path_summary_hash",  Coverage::Unaudited("bounded path summaries are P04, unbuilt")),
    ("poc_claims.verdict",            Coverage::Unaudited("enumerated value, checked by validate.py")),
    ("poc_claims.alg",                Coverage::Unaudited("signature checking is validate.py's semantic layer")),

    ("submods.attestation.platform",    Coverage::Unaudited("attestation auditor arrives in Task 3")),
    ("submods.attestation.measurement", Coverage::Unaudited("attestation auditor arrives in Task 3")),
];

/// Every auditor. Later tasks push onto this list.
pub fn auditors() -> Vec<Box<dyn FieldAuditor>> {
    vec![
        Box::new(Chain("poc_claims.chain_head")),
        Box::new(Chain("poc_claims.merkle_root")),
        Box::new(Chain("poc_claims.step_index")),
    ]
}

/// Run every accounted field and return one `Finding` each, in `ACCOUNTED`
/// order so output is stable.
///
/// An auditor that panics becomes `AuditorFailed` rather than taking the other
/// findings down with it — a third-party parser over supplied bytes is exactly
/// where a panic would originate. It must never be mistaken for a clean row,
/// which is why `AuditorFailed` sets exit 2.
pub fn run(rec: &Record, ctx: &Context) -> Vec<Finding> {
    let auditors = auditors();
    ACCOUNTED
        .iter()
        .map(|(field, coverage)| match coverage {
            Coverage::Unaudited(reason) => Finding {
                field,
                verdict: Verdict::Unchecked(Why::NoAuditor),
                reason: (*reason).to_string(),
                residual: Vec::new(),
            },
            Coverage::Audited => {
                let a = auditors
                    .iter()
                    .find(|a| a.field() == *field)
                    .unwrap_or_else(|| panic!(
                        "{field} is marked Audited but no auditor claims it"
                    ));
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.audit(rec, ctx)))
                    .unwrap_or_else(|_| Finding {
                        field,
                        verdict: Verdict::Unchecked(Why::AuditorFailed(
                            format!("the auditor for {field} panicked"),
                        )),
                        reason: format!("the auditor for {field} panicked"),
                        residual: Vec::new(),
                    })
            }
        })
        .collect()
}
