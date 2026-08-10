use serde::Deserialize;
use std::path::Path;

/// The operator's own list of measurements they accept.
///
/// `submods.attestation.reference_values_uri` is a URI *in the record*, and
/// this tool never fetches it — that would break the offline constraint, and
/// it would also be auditing the record's own claim about where to look
/// rather than anything independent. This file is the other half: the
/// operator, out of band, asserting "these are the measurements I approved."
/// Comparing the record's measurement against this file is a real check;
/// comparing it against nothing (the old behaviour) was the defect this
/// closes.
///
/// Format: a JSON object with one array of digest strings, in the same
/// `alg:hex` shape the record itself uses for `submods.attestation.
/// measurement`. Deliberately minimal — no metadata, no per-entry
/// provenance — because anything richer would invite this tool to start
/// interpreting *why* a value was approved, which is exactly the kind of
/// inference FAILS LOUD forbids. See the README for a worked example.
#[derive(Debug, Clone, Deserialize)]
pub struct ReferenceValues {
    pub measurements: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReferenceValuesError {
    #[error("{0}")]
    Io(std::io::Error),
    #[error("not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<std::io::Error> for ReferenceValuesError {
    fn from(e: std::io::Error) -> Self {
        ReferenceValuesError::Io(e)
    }
}

impl ReferenceValues {
    pub fn load(path: &Path) -> Result<Self, ReferenceValuesError> {
        let s = std::fs::read_to_string(path)?;
        let rv: ReferenceValues = serde_json::from_str(&s)?;
        Ok(rv)
    }

    pub fn contains(&self, measurement: &str) -> bool {
        self.measurements.iter().any(|m| m == measurement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_a_minimal_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "poc-audit-reference-values-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"measurements": ["sha-256:abc", "sha-256:def"]}"#)
            .expect("write");
        let rv = ReferenceValues::load(&path).expect("loads");
        let _ = std::fs::remove_file(&path);
        assert!(rv.contains("sha-256:abc"));
        assert!(!rv.contains("sha-256:zzz"));
    }

    #[test]
    fn malformed_json_is_an_error() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "poc-audit-reference-values-bad-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, "not json").expect("write");
        let err = ReferenceValues::load(&path).expect_err("must not parse");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("not valid JSON"));
    }
}
