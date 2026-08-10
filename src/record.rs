use serde::Deserialize;

/// The Proof-of-Control Evidence Token, as far as this tool reads it.
///
/// `deny_unknown_fields` is deliberately NOT set: the schema allows additional
/// properties on `poc_claims`, and refusing them here would reject records the
/// standard considers valid.
#[derive(Debug, Clone, Deserialize)]
pub struct Record {
    pub iss: String,
    pub iat: i64,
    pub nonce: String,
    pub eat_profile: String,
    pub poc_claims: PocClaims,
    pub submods: Submods,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PocClaims {
    pub agent_id: String,
    pub initiating_user: String,
    pub agbom_digest: String,
    pub interception_point: String,
    pub step_index: u64,
    pub chain_head: String,
    pub merkle_root: String,
    pub tree_size: u64,
    pub policy_bundle_hash: String,
    pub target_resource: String,
    pub canonical_snapshot_hash: String,
    pub path_summary_hash: String,
    pub verdict: String,
    pub alg: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Submods {
    pub attestation: Attestation,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Attestation {
    pub platform: String,
    pub measurement: String,
    /// Optional in the schema. That it is optional is `parallax`'s finding.
    #[serde(default)]
    pub reference_values_uri: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("{0}\n\nThis tool is the fourth layer and assumes the first three passed. Run ov-poc-standard/schema/validate.py on this record first.")]
    Malformed(String),
}

impl Record {
    pub fn parse(src: &str) -> Result<Self, RecordError> {
        serde_json::from_str(src).map_err(|e| RecordError::Malformed(e.to_string()))
    }
}
