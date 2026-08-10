use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_poc-audit"))
}

fn chain(dir: &str, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("tests/fixtures/chain/{dir}/step-{i}.json"))
        .collect()
}

/// A conformant sequence: contiguous step_index, non-decreasing tree_size,
/// one shared agent_id. Nothing DIVERGES or CANNOT HOLD, so exit 0 — the
/// same meaning exit 0 has for a single record.
#[test]
fn a_valid_chain_exits_0() {
    let out = bin()
        .arg("--chain")
        .args(chain("valid", 3))
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(
        stdout.contains("poc_claims.step_index") && stdout.contains("ESTABLISHED"),
        "got:\n{stdout}"
    );
    assert!(stdout.contains("poc_claims.tree_size"), "got:\n{stdout}");
    assert!(stdout.contains("poc_claims.agent_id"), "got:\n{stdout}");
    // chain_head is never recomputed, even on a fully valid chain.
    let head_row = stdout
        .lines()
        .find(|l| l.starts_with("poc_claims.chain_head"))
        .unwrap_or_else(|| panic!("no chain_head row in:\n{stdout}"));
    assert!(head_row.contains("UNCHECKED"), "got: {head_row}");
}

/// C1: a contiguous window of a longer chain that does not start at
/// step_index 0 — steps 5, 6, 7, one agent, distinct heads — must ESTABLISH
/// step_index, not DIVERGE. This is the exact scenario the README documents
/// under "what this does not do" ("a contiguous, agent-consistent
/// subsequence ... passes exactly like a complete one"): the old check
/// (`step_index == position`) conflated contiguity with "starts at
/// genesis" and produced a false DIVERGES on this conformant input.
#[test]
fn a_non_zero_start_chain_establishes_step_index_and_exits_0() {
    let out = bin()
        .arg("--chain")
        .args(chain("non-zero-start", 3))
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout
        .lines()
        .find(|l| l.starts_with("poc_claims.step_index"))
        .unwrap_or_else(|| panic!("no step_index row in:\n{stdout}"));
    assert!(row.contains("ESTABLISHED"), "got: {row}");
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
}

/// A gap (step_index 0, 1, 3) must DIVERGE on step_index and exit 1.
#[test]
fn a_gap_in_step_index_diverges_and_exits_1() {
    let out = bin()
        .arg("--chain")
        .args(chain("gap", 3))
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout
        .lines()
        .find(|l| l.starts_with("poc_claims.step_index"))
        .unwrap_or_else(|| panic!("no step_index row in:\n{stdout}"));
    assert!(row.contains("DIVERGES"), "got: {row}");
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
}

/// A duplicate step_index (0, 1, 1) must DIVERGE and exit 1.
#[test]
fn a_duplicate_step_index_diverges_and_exits_1() {
    let out = bin()
        .arg("--chain")
        .args(chain("duplicate", 3))
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout
        .lines()
        .find(|l| l.starts_with("poc_claims.step_index"))
        .unwrap_or_else(|| panic!("no step_index row in:\n{stdout}"));
    assert!(row.contains("DIVERGES"), "got: {row}");
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
}

/// Records from two different agents are not a chain: agent_id must DIVERGE.
#[test]
fn mixed_agents_diverges_and_exits_1() {
    let out = bin()
        .arg("--chain")
        .args(chain("mixed-agent", 3))
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout
        .lines()
        .find(|l| l.starts_with("poc_claims.agent_id"))
        .unwrap_or_else(|| panic!("no agent_id row in:\n{stdout}"));
    assert!(row.contains("DIVERGES"), "got: {row}");
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
}

/// tree_size going 3, 2, 4 shrinks between the first two records: DIVERGES.
#[test]
fn a_shrinking_tree_size_diverges_and_exits_1() {
    let out = bin()
        .arg("--chain")
        .args(chain("shrinking-tree", 3))
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout
        .lines()
        .find(|l| l.starts_with("poc_claims.tree_size"))
        .unwrap_or_else(|| panic!("no tree_size row in:\n{stdout}"));
    assert!(row.contains("DIVERGES"), "got: {row}");
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
}

/// I4: `--chain` does not read `--deployment`, `--payload`, `--fleet`, or
/// `--reference-values` — none of them deepen a cross-record fact — but the
/// chain branch in `main.rs` used to return before the single-record path's
/// strict pre-checks, so a nonexistent file for any of them was silently
/// swallowed instead of failing loud the way it does in single-record mode.
/// clap must reject the combination outright via `conflicts_with`, exit 2,
/// for each flag independently.
#[test]
fn chain_rejects_every_deepening_flag_even_with_a_nonexistent_file() {
    for (flag, path) in [
        ("--deployment", "/nope.toml"),
        ("--payload", "/nope.json"),
        ("--fleet", "/nope.toml"),
        ("--reference-values", "/nope.json"),
    ] {
        let out = bin()
            .arg("--chain")
            .args(chain("valid", 2))
            .arg(flag)
            .arg(path)
            .output()
            .expect("run poc-audit");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{flag} together with --chain must be a clap error, stdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            out.stdout.is_empty(),
            "{flag} together with --chain must print no table, got:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// `--chain` and the positional record are mutually exclusive; clap must
/// reject supplying both rather than silently picking one.
#[test]
fn chain_and_record_together_is_a_clap_error() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .arg("--chain")
        .args(chain("valid", 3))
        .output()
        .expect("run poc-audit");
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
}

/// Neither a record nor --chain: clap must reject this too, not panic on an
/// absent record path.
#[test]
fn neither_record_nor_chain_is_a_clap_error() {
    let out = bin().output().expect("run poc-audit");
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
}

/// A single file is not a sequence; clap's `num_args = 2..` must reject it
/// rather than silently auditing a "chain" of one.
#[test]
fn a_single_chain_file_is_a_clap_error() {
    let out = bin()
        .arg("--chain")
        .arg("tests/fixtures/chain/valid/step-0.json")
        .output()
        .expect("run poc-audit");
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
}

/// The common single-record path must not have gotten more awkward: no
/// `--chain`, just a bare record, exactly as before this feature existed.
#[test]
fn the_single_record_path_is_unchanged() {
    let out = bin()
        .arg("tests/fixtures/vectors/positive/hardware-attested.json")
        .output()
        .expect("run poc-audit");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// `--explain` must reach the chain path too, the same way
/// `tests/exit_matrix.rs`'s `require_checked_reaches_the_explain_path_too`
/// pins it for the single-record path.
#[test]
fn explain_works_in_chain_mode() {
    let out = bin()
        .arg("--chain")
        .args(chain("gap", 3))
        .arg("--explain")
        .arg("poc_claims.step_index")
        .output()
        .expect("run poc-audit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DIVERGES"), "got:\n{stdout}");
    assert_eq!(out.status.code(), Some(1));
}

/// An unreadable record path inside a --chain invocation is a hard error
/// naming the path, the same strictness as every other input.
#[test]
fn an_unreadable_chain_member_is_an_error_not_an_unchecked_row() {
    let out = bin()
        .arg("--chain")
        .arg("tests/fixtures/chain/valid/step-0.json")
        .arg("/nonexistent/step-1.json")
        .output()
        .expect("run poc-audit");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stdout.is_empty(),
        "got:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("/nonexistent/step-1.json"),
        "the error must name the path"
    );
}
