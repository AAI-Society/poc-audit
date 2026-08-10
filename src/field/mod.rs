pub mod attestation;
pub mod canonical;
pub mod chain;

use crate::record::Record;
use crate::verdict::{Context, Finding};

pub trait FieldAuditor {
    /// Dotted path into the record, matching a `registry::ACCOUNTED` entry.
    fn field(&self) -> &'static str;
    fn audit(&self, rec: &Record, ctx: &Context) -> Finding;
}
