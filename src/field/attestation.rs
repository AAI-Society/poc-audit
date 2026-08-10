use super::FieldAuditor;
use crate::record::Record;
use crate::verdict::{Context, Finding, Residual, Verdict, Why};

/// Audits `submods.attestation`. One instance per field path, because the two
/// required sub-fields fail differently: `platform` can be structurally
/// unsupportable, `measurement` can be present but compared to nothing.
pub struct AttestationField(pub &'static str);

/// Human text for a `parallax::trust::Impact`, for `--explain`'s "how long
/// before you would know" drill-down.
///
/// Deliberately exhaustive with no catch-all arm: a new `Impact` variant
/// added upstream must fail to compile here rather than silently falling
/// through to a generic label that hides what it actually means.
fn impact_label(impact: &parallax::trust::Impact) -> &'static str {
    use parallax::trust::Impact;
    match impact {
        Impact::Soundness => "Soundness",
        Impact::Revocation => "Revocation",
        // The one variant whose Rust identifier reads badly verbatim: no
        // space, and `Debug` prints exactly the identifier.
        Impact::SplitView => "Split View",
        Impact::Availability => "Availability",
    }
}

impl AttestationField {
    fn platform_finding(&self, rec: &Record) -> Finding {
        if rec.submods.attestation.platform == "SOFTWARE" {
            // A SOFTWARE platform claims no tier at all, so it is perfectly
            // satisfiable — it is not CANNOT HOLD. What it cannot do is back
            // a Tier 3 or Tier 4 claim, and that limitation belongs in the
            // reason, not smuggled in as a structural-impossibility verdict.
            return Finding {
                field: self.0,
                verdict: Verdict::Asserted,
                reason: "platform is SOFTWARE: the record asserts it and nothing \
                         here re-verifies it. It cannot support a Tier 3 or \
                         Tier 4 claim."
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
                reason: "reference values are named, but who operates them is unknown; \
                         supply --deployment to find out"
                    .into(),
                residual: Vec::new(),
            };
        };
        // Loading errors are handled at Context construction, so a failure here
        // is a genuine solver failure rather than a bad path.
        match parallax::deployment::Deployment::load(path)
            .map_err(|e| e.to_string())
            .and_then(|d| parallax::solve::solve(&d).map_err(|e| e.to_string()))
        {
            // The deployment solving tells us who would have to be honest
            // FOR the reference values to hold, and that residual set is
            // genuinely valuable. It is not, on its own, a comparison of
            // `rec.submods.attestation.measurement` against those values —
            // nothing here reads that field at all — so this cannot be
            // ESTABLISHED. It is ASSERTED, with the residual kept.
            Ok(set) => Finding {
                field: self.0,
                verdict: Verdict::Asserted,
                reason: format!(
                    "reference values are named and the deployment solves \
                     ({} principals would need to be honest for them to hold), \
                     but nothing here compares this record's measurement to \
                     those reference values",
                    set.0.len()
                ),
                residual: set
                    .0
                    .iter()
                    .map(|a| Residual {
                        principal: a.principal.clone(),
                        capability: a.capability.clone(),
                        // `Latency::label()` is parallax's own one canonical
                        // rendering ("never", "43200s") — the same string its
                        // own CLI prints — rather than a reimplementation
                        // here that could drift from it.
                        detect: a.latency.label(),
                        impact: impact_label(&a.impact).to_string(),
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
    fn field(&self) -> &'static str {
        self.0
    }
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

    /// The other direction from the test above: reference values ARE named,
    /// but `--deployment` was not supplied, so who operates them is unknown.
    /// This is UNCHECKED (an input could deepen it), not ASSERTED (we looked
    /// and found nothing) — the two must stay distinguishable, or ASSERTED
    /// has silently collapsed into UNCHECKED. See IMPORTANT 3.
    #[test]
    fn reference_values_present_but_no_deployment_is_unchecked() {
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/values.json")),
            &Context::default(),
        );
        assert_eq!(f.verdict.label(), "UNCHECKED");
        // Every UNCHECKED row must name the flag that would deepen it —
        // `canonical.rs` names `--payload` and `identity.rs` names `--fleet`
        // in their reasons; this one must name `--deployment`, not just
        // gesture at "who operates them" without saying how to find out.
        assert!(
            f.reason.contains("--deployment"),
            "the UNCHECKED reason must name the deepening flag, got: {}",
            f.reason
        );
    }

    /// Top rung, downgraded: reference values are named, a deployment is
    /// supplied and solves — but `measurement_finding` never reads
    /// `rec.submods.attestation.measurement`, so this cannot be ESTABLISHED.
    /// It is ASSERTED, and the residual set it built along the way (who must
    /// be honest for the *reference values themselves* to hold) is kept
    /// rather than thrown away. See CRITICAL 2.
    #[test]
    fn measurement_with_a_solving_deployment_is_asserted_not_established() {
        let path = std::path::Path::new("tests/fixtures/parallax/sigma2-tdx.toml");
        let ctx = Context {
            deployment: Some(path.to_path_buf()),
            ..Context::default()
        };
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/v.json")),
            &ctx,
        );
        assert_eq!(f.verdict.label(), "ASSERTED", "reason was: {}", f.reason);
        assert!(
            f.reason.contains("compares"),
            "the reason must say plainly that nothing compares the measurement \
             to the reference values, got: {}",
            f.reason
        );
        assert!(
            !f.residual.is_empty(),
            "the residual set is the genuinely valuable part of this row and \
             must survive the downgrade"
        );
    }

    /// SOFTWARE means no hardware isolation, and it cannot back a Tier 3 or
    /// Tier 4 claim — but that is a limitation carried in the reason, not a
    /// structural impossibility. Nothing in the record claims Tier 3 or 4, so
    /// a SOFTWARE platform is perfectly satisfiable: ASSERTED, not CANNOT
    /// HOLD. See CRITICAL 1.
    #[test]
    fn a_software_platform_is_asserted_with_the_tier_limitation_named() {
        let f = AttestationField("submods.attestation.platform").audit(
            &record_with("SOFTWARE", Some("https://rv.example/v.json")),
            &Context::default(),
        );
        assert_eq!(f.verdict.label(), "ASSERTED");
        assert!(
            f.reason.contains("Tier 3") && f.reason.contains("Tier 4"),
            "the tier limitation must be named in the reason, got: {}",
            f.reason
        );
    }

    /// `--explain` prints `Residual::detect` and `Residual::impact` as
    /// user-facing text, but they used to be built with `{:?}` over
    /// `parallax`'s enums, so "how long before you would know" printed
    /// `Bounded(43200)` instead of readable text. `Latency::label()` (the one
    /// canonical rendering `parallax` itself defines, also used by its own
    /// CLI) fixes `detect`; `impact` gets an explicit, exhaustive match so a
    /// future `Impact` variant fails to compile here rather than silently
    /// mis-rendering.
    #[test]
    fn residual_detect_and_impact_render_as_human_text_not_debug() {
        let path = std::path::Path::new("tests/fixtures/parallax/sigma2-tdx.toml");
        let ctx = Context {
            deployment: Some(path.to_path_buf()),
            ..Context::default()
        };
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/v.json")),
            &ctx,
        );
        assert!(
            !f.residual.is_empty(),
            "fixture must solve to a non-empty set"
        );
        for r in &f.residual {
            assert!(
                !r.detect.contains('('),
                "detect leaked Debug formatting: {}",
                r.detect
            );
            assert_ne!(
                r.detect, "Never",
                "detect must use parallax's own lowercase spelling, got: {}",
                r.detect
            );
        }

        let pcs = f
            .residual
            .iter()
            .find(|r| r.principal == "did:web:pcs.intel.com")
            .expect("pcs principal present in this fixture's solved set");
        assert_eq!(pcs.detect, "43200s", "got: {}", pcs.detect);
        assert_eq!(pcs.impact, "Revocation", "got: {}", pcs.impact);

        let intel = f
            .residual
            .iter()
            .find(|r| r.principal == "did:web:intel.com")
            .expect("intel principal present in this fixture's solved set");
        assert_eq!(intel.detect, "never", "got: {}", intel.detect);
        assert_eq!(intel.impact, "Soundness", "got: {}", intel.impact);
    }

    /// `SplitView` is the one `Impact` variant whose Rust identifier reads
    /// badly verbatim (no space). Pinned on the enum directly rather than
    /// only through a fixture, since no shipped fixture's solved set
    /// currently produces it.
    #[test]
    fn impact_label_covers_every_variant_with_readable_text() {
        use parallax::trust::Impact;
        assert_eq!(impact_label(&Impact::Soundness), "Soundness");
        assert_eq!(impact_label(&Impact::Revocation), "Revocation");
        assert_eq!(impact_label(&Impact::SplitView), "Split View");
        assert_eq!(impact_label(&Impact::Availability), "Availability");
    }

    /// The other direction, pinned positively rather than merely `!=
    /// "CANNOT HOLD"`: if the non-SOFTWARE branch's `Asserted` verdict
    /// silently became `Unchecked(Why::NoAuditor)`, a `!=` check against
    /// "CANNOT HOLD" would still pass and the collapse would ship
    /// undetected. See IMPORTANT 3. The reason must also stay distinguishable
    /// from the SOFTWARE case, or the fix is untested.
    #[test]
    fn a_hardware_platform_does_not_report_cannot_hold() {
        let hw = AttestationField("submods.attestation.platform")
            .audit(&record_with("INTEL_TDX", None), &Context::default());
        assert_eq!(hw.verdict.label(), "ASSERTED");
        assert!(
            !hw.reason.contains("Tier 3"),
            "a hardware platform must not carry the SOFTWARE tier limitation, got: {}",
            hw.reason
        );

        let sw = AttestationField("submods.attestation.platform")
            .audit(&record_with("SOFTWARE", None), &Context::default());
        assert_ne!(
            hw.reason, sw.reason,
            "SOFTWARE and hardware must produce distinguishable output"
        );
    }
}
