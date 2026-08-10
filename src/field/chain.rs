use super::FieldAuditor;
use crate::record::Record;
use crate::verdict::{Context, Finding, Verdict, Why};

/// Hash-chain continuity is not audited by anything yet.
///
/// This ships and returns `UNCHECKED` on purpose. Omitting the row would make
/// a report that looks complete; a gap you can see is worth more than a table
/// implying coverage it does not have.
pub struct Chain(pub &'static str);

impl FieldAuditor for Chain {
    fn field(&self) -> &'static str {
        self.0
    }
    fn audit(&self, _rec: &Record, _ctx: &Context) -> Finding {
        Finding {
            field: self.0,
            verdict: Verdict::Unchecked(Why::NoAuditor),
            reason: "no auditor: chain continuity across records is unimplemented".into(),
            residual: Vec::new(),
        }
    }
}
