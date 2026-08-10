use std::path::PathBuf;

/// A non-empty attribution. `Verdict::Established` cannot be constructed
/// without one, which makes the presence of an attribution structural; the
/// non-emptiness is enforced here and pinned by test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackedBy(String);

impl BackedBy {
    pub fn new(s: impl Into<String>) -> Option<Self> {
        let s = s.into();
        if s.trim().is_empty() { None } else { Some(Self(s)) }
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

/// Why a field was not checked. The variants differ in consequence, not only
/// in wording: `AuditorFailed` sets exit 2, the others do not. Without that
/// split a panicking auditor yields `UNCHECKED`, `UNCHECKED` does not fail,
/// and a crash reads as a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Why {
    /// Carries the flag that would deepen this row.
    MissingInput(&'static str),
    NoAuditor,
    AuditorFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Established(BackedBy),
    Asserted,
    Diverges,
    CannotHold,
    Unchecked(Why),
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Established(_) => "ESTABLISHED",
            Verdict::Asserted => "ASSERTED",
            Verdict::Diverges => "DIVERGES",
            Verdict::CannotHold => "CANNOT HOLD",
            Verdict::Unchecked(_) => "UNCHECKED",
        }
    }
    pub fn is_failure(&self) -> bool {
        matches!(self, Verdict::Diverges | Verdict::CannotHold)
    }
    pub fn is_unchecked(&self) -> bool { matches!(self, Verdict::Unchecked(_)) }
    pub fn auditor_failed(&self) -> bool {
        matches!(self, Verdict::Unchecked(Why::AuditorFailed(_)))
    }
}

/// One principal that must be honest for a finding to mean what it says.
/// Mirrors `parallax::trust::Assumption` without depending on it, so that
/// findings from all three tools can carry the same drill-down shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Residual {
    pub principal: String,
    pub capability: String,
    pub detect: String,
    pub impact: String,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub field: &'static str,
    pub verdict: Verdict,
    /// One line, shown beside the verdict.
    pub reason: String,
    /// Shown by `--explain`. Empty is normal.
    pub residual: Vec<Residual>,
}

/// Which identity profile the deployment declares.
///
/// C5.1.1 requires a persistent agent identifier. That requirement is
/// SATISFIABLE under `Standard` and unsatisfiable under `Unlinkable`, so the
/// same record earns opposite verdicts depending on which is in force —
/// and nothing in a record says which. It is therefore an input, never an
/// inference: guessing it from the shape of an identifier would manufacture
/// the false finding this tool exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Profile {
    /// A persistent agent identifier is expected. C5.1.1 can be met.
    #[default]
    Standard,
    /// No persistent agent identifier exists. C5.1.1 must be suspended.
    Unlinkable,
}

/// The optional inputs. Each auditor names the flag it needs in
/// `Why::MissingInput` when its own input is absent.
#[derive(Debug, Default, Clone)]
pub struct Context {
    pub deployment: Option<PathBuf>,
    pub payload: Option<String>,
    pub fleet: Option<PathBuf>,
    /// Defaults to `Standard`. See `Profile`.
    pub profile: Profile,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_established_verdict_cannot_name_nothing() {
        assert!(BackedBy::new("parallax::solve").is_some());
        assert!(BackedBy::new("").is_none(), "an empty attribution is not an attribution");
        assert!(BackedBy::new("   ").is_none(), "whitespace is not an attribution");
    }

    /// The distinction the whole report rests on: "I checked and there is
    /// nothing behind this" is not "I did not check". Collapsing them is how a
    /// report implies coverage it does not have.
    #[test]
    fn asserted_and_unchecked_are_not_the_same_verdict() {
        let asserted = Verdict::Asserted;
        let unchecked = Verdict::Unchecked(Why::MissingInput("--payload"));
        assert_ne!(asserted.label(), unchecked.label());
        assert_eq!(asserted.label(), "ASSERTED");
        assert_eq!(unchecked.label(), "UNCHECKED");
    }

    #[test]
    fn only_diverges_and_cannot_hold_are_failures() {
        assert!(!Verdict::Asserted.is_failure());
        assert!(!Verdict::Unchecked(Why::NoAuditor).is_failure());
        assert!(Verdict::Diverges.is_failure());
        assert!(Verdict::CannotHold.is_failure());
        assert!(!Verdict::Established(BackedBy::new("x").expect("non-empty")).is_failure());
    }
}
