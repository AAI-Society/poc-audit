//! Auditing a SEQUENCE of records for chain continuity — the thing a single
//! record can never establish on its own.
//!
//! `validate.py` checks `tree_size > step_index` WITHIN one record. Nothing
//! anywhere checks CONTINUITY across records: that `step_index` actually
//! walks 0, 1, 2, … with no gaps, duplicates, or reordering; that
//! `tree_size` does not shrink; that every record in the sequence belongs to
//! the same agent. Those are all soundly checkable from the records
//! themselves. `chain_head`'s own construction is NOT: the schema describes
//! it as `H(previous_head || canonical_snapshot_hash || verdict)` but pins
//! neither `H`, the encoding, nor the concatenation, so recomputing it would
//! be a guess dressed as a verdict — the worst defect this tool can have.
//! `chain_head` therefore stays UNCHECKED here, with one exception: a
//! REPEATED head is impossible under any construction, so that cheap
//! structural fact is checked and reported as CANNOT HOLD.

use crate::record::Record;
use crate::verdict::{BackedBy, Finding, Verdict, Why};
use std::path::{Path, PathBuf};

/// One record read for chain auditing, paired with the path it came from so
/// findings can name it.
#[derive(Debug)]
pub struct ChainRecord {
    pub path: PathBuf,
    pub record: Record,
}

/// Reads every path in order. The order given IS the claimed sequence —
/// nothing here sorts by `step_index`, because a caller passing them out of
/// order is exactly the "reordering" failure mode this auditor exists to
/// catch, not something to silently correct.
pub fn load_chain(paths: &[PathBuf]) -> Result<Vec<ChainRecord>, String> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let s =
            std::fs::read_to_string(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        let record = Record::parse(&s).map_err(|e| format!("{}: {e}", p.display()))?;
        out.push(ChainRecord {
            path: p.clone(),
            record,
        });
    }
    Ok(out)
}

/// Every chain-continuity finding for the sequence. Five rows, mirroring the
/// single-record table's shape so the same `report::render_table` and
/// `report::exit_code` apply unchanged.
pub fn audit(records: &[ChainRecord]) -> Vec<Finding> {
    vec![
        audit_agent_id(records),
        audit_step_index(records),
        audit_tree_size(records),
        audit_chain_head(records),
        audit_merkle_root(records),
    ]
}

fn established(field: &'static str, backed_by: &str, reason: String) -> Finding {
    Finding {
        field,
        verdict: Verdict::Established(BackedBy::new(backed_by).expect("non-empty literal")),
        reason,
        residual: Vec::new(),
    }
}

fn diverges(field: &'static str, reason: String) -> Finding {
    Finding {
        field,
        verdict: Verdict::Diverges,
        reason,
        residual: Vec::new(),
    }
}

/// "A chain of records from different agents is not a chain." All records
/// must share one `agent_id`.
fn audit_agent_id(records: &[ChainRecord]) -> Finding {
    let first = &records[0].record.poc_claims.agent_id;
    let mismatches: Vec<String> = records
        .iter()
        .skip(1)
        .filter(|r| &r.record.poc_claims.agent_id != first)
        .map(|r| {
            format!(
                "{} has agent_id '{}'",
                r.path.display(),
                r.record.poc_claims.agent_id
            )
        })
        .collect();
    if mismatches.is_empty() {
        established(
            "poc_claims.agent_id",
            "shared agent_id across the supplied records",
            format!(
                "all {} supplied records share agent_id '{first}'",
                records.len()
            ),
        )
    } else {
        diverges(
            "poc_claims.agent_id",
            format!(
                "the supplied records do not share one agent_id: {} has '{first}', but {}",
                records[0].path.display(),
                mismatches.join("; ")
            ),
        )
    }
}

/// The schema's own words: "Monotonic per agent, starting at 0, with no
/// gaps." A single pass checking `records[i].step_index == i` catches gaps,
/// duplicates, AND reordering in one shot — any of those makes some position
/// disagree with its expected index.
fn audit_step_index(records: &[ChainRecord]) -> Finding {
    let problems: Vec<String> = records
        .iter()
        .enumerate()
        .filter(|(i, r)| r.record.poc_claims.step_index != *i as u64)
        .map(|(i, r)| {
            format!(
                "{} has step_index {} at position {i} (expected {i})",
                r.path.display(),
                r.record.poc_claims.step_index
            )
        })
        .collect();
    if problems.is_empty() {
        established(
            "poc_claims.step_index",
            "step_index contiguity across the supplied records",
            format!(
                "step_index runs 0..{} across the {} supplied records, in order, with no gaps, \
                 duplicates, or reordering",
                records.len() - 1,
                records.len()
            ),
        )
    } else {
        diverges(
            "poc_claims.step_index",
            format!(
                "step_index is not the contiguous 0..N sequence the schema requires: {}",
                problems.join("; ")
            ),
        )
    }
}

/// Two properties, both cheap and both soundly checkable from the records
/// alone: `tree_size` never decreases across the sequence, and each record's
/// own `tree_size` covers its own `step_index` (the same `>` relation
/// `validate.py` checks within one record, restated here because chain mode
/// reads every record anyway and a violation here is exactly the kind of
/// fact this auditor exists to surface).
fn audit_tree_size(records: &[ChainRecord]) -> Finding {
    let mut problems = Vec::new();
    let mut prev: Option<(u64, &Path)> = None;
    for r in records {
        let ts = r.record.poc_claims.tree_size;
        let si = r.record.poc_claims.step_index;
        if ts <= si {
            problems.push(format!(
                "{} has tree_size {ts}, which does not cover its own step_index {si}",
                r.path.display()
            ));
        }
        if let Some((prev_ts, prev_path)) = prev {
            if ts < prev_ts {
                problems.push(format!(
                    "{} has tree_size {ts}, smaller than {}'s {prev_ts}",
                    r.path.display(),
                    prev_path.display()
                ));
            }
        }
        prev = Some((ts, &r.path));
    }
    if problems.is_empty() {
        established(
            "poc_claims.tree_size",
            "tree_size monotonicity across the supplied records",
            format!(
                "tree_size is non-decreasing across the {} supplied records, and each covers \
                 its own step_index",
                records.len()
            ),
        )
    } else {
        diverges(
            "poc_claims.tree_size",
            format!(
                "tree_size is not consistent across the sequence: {}",
                problems.join("; ")
            ),
        )
    }
}

/// The construction (`H(previous_head || canonical_snapshot_hash ||
/// verdict)`) is prose, not a pinned algorithm: neither the schema nor
/// `validate.py` names `H`, the byte encoding, or the concatenation
/// semantics. Recomputing it would be a guess dressed as a verdict, so this
/// never does. What IS checkable without guessing: a repeated `chain_head`
/// is impossible under ANY construction (a collision-resistant hash does not
/// legitimately repeat across distinct steps), so that is checked and, if
/// found, reported as CANNOT HOLD rather than folded into the default
/// UNCHECKED.
fn audit_chain_head(records: &[ChainRecord]) -> Finding {
    let mut seen: std::collections::HashMap<&str, &Path> = std::collections::HashMap::new();
    for r in records {
        let head = r.record.poc_claims.chain_head.as_str();
        if let Some(other) = seen.get(head) {
            return Finding {
                field: "poc_claims.chain_head",
                verdict: Verdict::CannotHold,
                reason: format!(
                    "{} and {} both carry chain_head '{head}'; a collision-resistant hash \
                     cannot legitimately repeat across distinct steps, so this sequence cannot \
                     hold together as a chain",
                    other.display(),
                    r.path.display(),
                ),
                residual: Vec::new(),
            };
        }
        seen.insert(head, &r.path);
    }
    Finding {
        field: "poc_claims.chain_head",
        verdict: Verdict::Unchecked(Why::NoAuditor),
        reason: "chain_head is described as H(previous_head || canonical_snapshot_hash || \
                 verdict), but neither the schema nor validate.py pins the hash function, byte \
                 encoding, or concatenation semantics, so it is not recomputed here — that \
                 would be a guess dressed as a verdict. Every chain_head across the supplied \
                 records is at least distinct, which is checked."
            .into(),
        residual: Vec::new(),
    }
}

/// `merkle_root` is an RFC 6962 tree head over ALL leaves through this step —
/// recomputing it needs every leaf ever appended, not merely the records
/// supplied to one `--chain` invocation, which may be a subsequence. No
/// cheap structural fact is claimed here (unlike `chain_head`, nothing in the
/// schema says a repeated `merkle_root` is impossible: two adjacent steps
/// could in principle share one if no leaf were added, and guessing that
/// away would risk exactly the false finding this tool exists to avoid).
fn audit_merkle_root(records: &[ChainRecord]) -> Finding {
    Finding {
        field: "poc_claims.merkle_root",
        verdict: Verdict::Unchecked(Why::NoAuditor),
        reason: format!(
            "merkle_root is an RFC 6962 tree head over all leaves through this step; \
             recomputing it needs every leaf, not only the {} record(s) supplied here, so it \
             is not checked",
            records.len()
        ),
        residual: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with(step_index: u64, tree_size: u64, agent_id: &str, chain_head: &str) -> Record {
        let mut v: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("fixture is json");
        v["poc_claims"]["step_index"] = serde_json::json!(step_index);
        v["poc_claims"]["tree_size"] = serde_json::json!(tree_size);
        v["poc_claims"]["agent_id"] = serde_json::json!(agent_id);
        v["poc_claims"]["chain_head"] = serde_json::json!(chain_head);
        Record::parse(&v.to_string()).expect("fixture parses")
    }

    fn at(path: &str, step_index: u64, tree_size: u64, agent_id: &str, head: &str) -> ChainRecord {
        ChainRecord {
            path: PathBuf::from(path),
            record: record_with(step_index, tree_size, agent_id, head),
        }
    }

    fn valid_chain() -> Vec<ChainRecord> {
        vec![
            at(
                "0.json",
                0,
                1,
                "did:web:example.org:agents:ref-1",
                "sha-256:head0",
            ),
            at(
                "1.json",
                1,
                2,
                "did:web:example.org:agents:ref-1",
                "sha-256:head1",
            ),
            at(
                "2.json",
                2,
                3,
                "did:web:example.org:agents:ref-1",
                "sha-256:head2",
            ),
        ]
    }

    fn find<'a>(findings: &'a [Finding], field: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.field == field)
            .unwrap_or_else(|| panic!("no finding for {field}"))
    }

    #[test]
    fn a_valid_chain_establishes_agent_id_step_index_and_tree_size() {
        let findings = audit(&valid_chain());
        assert_eq!(
            find(&findings, "poc_claims.agent_id").verdict.label(),
            "ESTABLISHED"
        );
        assert_eq!(
            find(&findings, "poc_claims.step_index").verdict.label(),
            "ESTABLISHED"
        );
        assert_eq!(
            find(&findings, "poc_claims.tree_size").verdict.label(),
            "ESTABLISHED"
        );
    }

    /// `chain_head` never becomes ESTABLISHED — recomputing it is exactly
    /// what this tool must not do. A valid chain still leaves it UNCHECKED.
    #[test]
    fn a_valid_chain_leaves_chain_head_unchecked_not_established() {
        let findings = audit(&valid_chain());
        let f = find(&findings, "poc_claims.chain_head");
        assert_eq!(f.verdict.label(), "UNCHECKED");
        assert!(
            f.reason.contains("not recomputed") || f.reason.contains("dressed as a verdict"),
            "must say why it refuses to guess, got: {}",
            f.reason
        );
    }

    #[test]
    fn a_valid_chain_leaves_merkle_root_unchecked() {
        let findings = audit(&valid_chain());
        assert_eq!(
            find(&findings, "poc_claims.merkle_root").verdict.label(),
            "UNCHECKED"
        );
    }

    /// A gap: step_index 0, 1, 3 — skips 2.
    #[test]
    fn a_gap_in_step_index_diverges() {
        let records = vec![
            at("0.json", 0, 1, "a", "sha-256:h0"),
            at("1.json", 1, 2, "a", "sha-256:h1"),
            at("2.json", 3, 4, "a", "sha-256:h2"),
        ];
        let findings = audit(&records);
        let f = find(&findings, "poc_claims.step_index");
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
        assert!(
            f.reason.contains('3'),
            "must name the offending value: {}",
            f.reason
        );
    }

    /// A duplicate: step_index 0, 1, 1.
    #[test]
    fn a_duplicate_step_index_diverges() {
        let records = vec![
            at("0.json", 0, 1, "a", "sha-256:h0"),
            at("1.json", 1, 2, "a", "sha-256:h1"),
            at("2.json", 1, 3, "a", "sha-256:h2"),
        ];
        let findings = audit(&records);
        let f = find(&findings, "poc_claims.step_index");
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
    }

    /// Reordering: the sequence 0, 2, 1 given in that order — a duplicate or
    /// gap check alone would not catch this; the positional check does.
    #[test]
    fn a_reordered_sequence_diverges() {
        let records = vec![
            at("0.json", 0, 1, "a", "sha-256:h0"),
            at("1.json", 2, 3, "a", "sha-256:h2"),
            at("2.json", 1, 4, "a", "sha-256:h1"),
        ];
        let findings = audit(&records);
        let f = find(&findings, "poc_claims.step_index");
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
    }

    /// Mixed agents: a "chain" of records from different agents is not a
    /// chain.
    #[test]
    fn mixed_agents_diverges() {
        let records = vec![
            at("0.json", 0, 1, "did:web:a", "sha-256:h0"),
            at("1.json", 1, 2, "did:web:a", "sha-256:h1"),
            at("2.json", 2, 3, "did:web:b", "sha-256:h2"),
        ];
        let findings = audit(&records);
        let f = find(&findings, "poc_claims.agent_id");
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
        assert!(f.reason.contains("did:web:b"), "got: {}", f.reason);
    }

    /// Mixed agents must not corrupt the OTHER rows: step_index and
    /// tree_size are still contiguous/monotonic here, so they must stay
    /// ESTABLISHED. Otherwise one bad row silently poisons unrelated ones.
    #[test]
    fn mixed_agents_does_not_corrupt_step_index_or_tree_size() {
        let records = vec![
            at("0.json", 0, 1, "did:web:a", "sha-256:h0"),
            at("1.json", 1, 2, "did:web:a", "sha-256:h1"),
            at("2.json", 2, 3, "did:web:b", "sha-256:h2"),
        ];
        let findings = audit(&records);
        assert_eq!(
            find(&findings, "poc_claims.step_index").verdict.label(),
            "ESTABLISHED"
        );
        assert_eq!(
            find(&findings, "poc_claims.tree_size").verdict.label(),
            "ESTABLISHED"
        );
    }

    /// Shrinking tree: tree_size 3, 2, 4 — 3 -> 2 is a decrease, even though
    /// every record still covers its own step_index (3>0, 2>1, 4>2).
    #[test]
    fn a_shrinking_tree_size_diverges() {
        let records = vec![
            at("0.json", 0, 3, "a", "sha-256:h0"),
            at("1.json", 1, 2, "a", "sha-256:h1"),
            at("2.json", 2, 4, "a", "sha-256:h2"),
        ];
        let findings = audit(&records);
        let f = find(&findings, "poc_claims.tree_size");
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
        assert!(
            f.reason.contains("smaller"),
            "must say it shrank, got: {}",
            f.reason
        );
    }

    /// tree_size that fails to cover its own step_index is caught too, not
    /// only the cross-record monotonicity property.
    #[test]
    fn a_tree_size_not_covering_its_own_step_index_diverges() {
        let records = vec![
            at("0.json", 0, 1, "a", "sha-256:h0"),
            at("1.json", 1, 1, "a", "sha-256:h1"),
        ];
        let findings = audit(&records);
        let f = find(&findings, "poc_claims.tree_size");
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
        assert!(f.reason.contains("does not cover"), "got: {}", f.reason);
    }

    /// The one structural fact this auditor checks about `chain_head`: a
    /// repeat is impossible under any construction, so it is CANNOT HOLD,
    /// not UNCHECKED.
    #[test]
    fn a_repeated_chain_head_cannot_hold() {
        let records = vec![
            at("0.json", 0, 1, "a", "sha-256:same"),
            at("1.json", 1, 2, "a", "sha-256:same"),
        ];
        let findings = audit(&records);
        let f = find(&findings, "poc_claims.chain_head");
        assert_eq!(f.verdict.label(), "CANNOT HOLD", "reason was: {}", f.reason);
        assert!(f.reason.contains("sha-256:same"), "got: {}", f.reason);
    }

    #[test]
    fn load_chain_reads_every_file_in_the_order_given() {
        let paths = vec![
            PathBuf::from("tests/fixtures/vectors/positive/hardware-attested.json"),
            PathBuf::from("tests/fixtures/vectors/positive/hardware-attested.json"),
        ];
        let records = load_chain(&paths).expect("both files exist and parse");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn load_chain_names_the_unreadable_path() {
        let paths = vec![PathBuf::from("/nonexistent/record.json")];
        let err = load_chain(&paths).expect_err("must fail");
        assert!(err.contains("/nonexistent/record.json"), "got: {err}");
    }
}
