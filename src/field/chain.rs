use super::FieldAuditor;
use crate::record::Record;
use crate::verdict::{Context, Finding, Verdict, Why};

/// Chain continuity now HAS an auditor (`crate::chain`) — it is simply
/// unreachable from a single record. `step_index`, `merkle_root`, and
/// `chain_head` all describe a SEQUENCE property (contiguity, tree
/// coverage, hash linkage), and one record alone cannot establish or
/// contradict any of them; you need its neighbours. So this field auditor,
/// which is what a single-record invocation always runs, stays UNCHECKED —
/// but the reason now points at the mode that CAN check it, rather than
/// claiming nothing exists.
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
            reason: "a single record cannot establish chain continuity on its own; run \
                     `poc-audit --chain <records...>` with its neighbours to audit the sequence"
                .into(),
            residual: Vec::new(),
        }
    }
}
