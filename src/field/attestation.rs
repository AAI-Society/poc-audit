use super::FieldAuditor;
use crate::record::Record;
use crate::verdict::{BackedBy, Context, Finding, Residual, Verdict, Why};

/// Audits `submods.attestation`. One instance per field path, because the two
/// required sub-fields fail differently: `platform` can be structurally
/// unsupportable, `measurement` can be present but compared to nothing.
pub struct AttestationField(pub &'static str);

impl AttestationField {
    fn platform_finding(&self, rec: &Record) -> Finding {
        if rec.submods.attestation.platform == "SOFTWARE" {
            return Finding {
                field: self.0,
                verdict: Verdict::CannotHold,
                reason: "platform is SOFTWARE: no hardware isolation, so this \
                         evidence cannot support a Tier 3 or Tier 4 claim"
                    .into(),
                residual: Vec::new(),
            };
        }
        Finding {
            field: self.0,
            verdict: Verdict::Asserted,
            reason: format!(
                "platform is {}; the record asserts it and nothing here re-verifies the quote",
                rec.submods.attestation.platform
            ),
            residual: Vec::new(),
        }
    }

    fn measurement_finding(&self, rec: &Record, ctx: &Context) -> Finding {
        if rec.submods.attestation.reference_values_uri.is_none() {
            return Finding {
                field: self.0,
                verdict: Verdict::Asserted,
                reason: "reference_values_uri is absent, so the measurement was \
                         compared to nothing: this attests that some code ran in a \
                         genuine trust domain, not that it is your code"
                    .into(),
                residual: Vec::new(),
            };
        }
        let Some(path) = ctx.deployment.as_ref() else {
            return Finding {
                field: self.0,
                verdict: Verdict::Unchecked(Why::MissingInput("--deployment")),
                reason: "reference values are named, but who operates them is unknown".into(),
                residual: Vec::new(),
            };
        };
        // Loading errors are handled at Context construction, so a failure here
        // is a genuine solver failure rather than a bad path.
        match parallax::deployment::Deployment::load(path)
            .map_err(|e| e.to_string())
            .and_then(|d| parallax::solve::solve(&d).map_err(|e| e.to_string()))
        {
            Ok(set) => Finding {
                field: self.0,
                verdict: Verdict::Established(
                    BackedBy::new("parallax::solve").expect("non-empty literal"),
                ),
                reason: format!(
                    "reference values are named and the deployment solves; \
                     {} principals must be honest",
                    set.0.len()
                ),
                residual: set
                    .0
                    .iter()
                    .map(|a| Residual {
                        principal: a.principal.clone(),
                        capability: a.capability.clone(),
                        detect: format!("{:?}", a.latency),
                        impact: format!("{:?}", a.impact),
                    })
                    .collect(),
            },
            Err(e) => Finding {
                field: self.0,
                verdict: Verdict::Unchecked(Why::AuditorFailed(e.clone())),
                reason: format!("parallax could not solve the deployment: {e}"),
                residual: Vec::new(),
            },
        }
    }
}

impl FieldAuditor for AttestationField {
    fn field(&self) -> &'static str { self.0 }
    fn audit(&self, rec: &Record, ctx: &Context) -> Finding {
        if self.0.ends_with(".platform") {
            self.platform_finding(rec)
        } else {
            self.measurement_finding(rec, ctx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;
    use crate::verdict::Context;

    fn record_with(platform: &str, reference_values_uri: Option<&str>) -> Record {
        let mut v: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/vectors/positive/hardware-attested.json"
        ))
        .expect("fixture is json");
        v["submods"]["attestation"]["platform"] = serde_json::json!(platform);
        match reference_values_uri {
            Some(u) => v["submods"]["attestation"]["reference_values_uri"] = serde_json::json!(u),
            None => {
                v["submods"]["attestation"]
                    .as_object_mut()
                    .expect("attestation object")
                    .remove("reference_values_uri");
            }
        }
        Record::parse(&v.to_string()).expect("fixture parses")
    }

    #[test]
    fn a_quote_without_reference_values_is_asserted_not_established() {
        let f = AttestationField("submods.attestation.measurement")
            .audit(&record_with("INTEL_TDX", None), &Context::default());
        assert_eq!(f.verdict.label(), "ASSERTED");
        assert!(
            f.reason.contains("compared to nothing"),
            "the reason must say what is missing, got: {}",
            f.reason
        );
    }

    /// The other direction, so the verdict is not hardcoded.
    #[test]
    fn reference_values_present_is_not_asserted() {
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/values.json")),
            &Context::default(),
        );
        assert_ne!(f.verdict.label(), "ASSERTED");
    }

    /// SOFTWARE means no hardware isolation at all. The schema says a verifier
    /// MUST refuse to treat it as a Tier 3 claim, so it cannot be established.
    #[test]
    fn a_software_platform_cannot_hold() {
        let f = AttestationField("submods.attestation.platform")
            .audit(&record_with("SOFTWARE", Some("https://rv.example/v.json")), &Context::default());
        assert_eq!(f.verdict.label(), "CANNOT HOLD");
    }

    #[test]
    fn a_hardware_platform_does_not_report_cannot_hold() {
        let f = AttestationField("submods.attestation.platform")
            .audit(&record_with("INTEL_TDX", None), &Context::default());
        assert_ne!(f.verdict.label(), "CANNOT HOLD");
    }
}
