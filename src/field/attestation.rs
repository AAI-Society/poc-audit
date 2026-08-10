use super::FieldAuditor;
use crate::record::Record;
use crate::verdict::{BackedBy, Context, Finding, Residual, Verdict, Why};

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

    /// `--reference-values` compared directly to `rec.submods.attestation.
    /// measurement`. This is the only path that can ever reach ESTABLISHED
    /// for this field: it is the one place something outside the record
    /// actually reads the measurement and checks it against a value the
    /// operator chose, rather than a value the record names.
    ///
    /// Independent of whether `reference_values_uri` is present — the record
    /// naming a source and the operator supplying one are different claims,
    /// and the reason text says which one is in play here.
    fn measurement_against_reference_values(
        &self,
        rec: &Record,
        ctx: &Context,
        path: &std::path::Path,
    ) -> Finding {
        let rv = match crate::reference_values::ReferenceValues::load(path) {
            Ok(rv) => rv,
            Err(e) => {
                return Finding {
                    field: self.0,
                    verdict: Verdict::Unchecked(Why::AuditorFailed(e.to_string())),
                    reason: format!("could not use --reference-values {}: {e}", path.display()),
                    residual: Vec::new(),
                }
            }
        };
        let source_note = if rec.submods.attestation.reference_values_uri.is_some() {
            "the record names a reference source (reference_values_uri), but that URI is not \
             fetched"
        } else {
            "the record does not name a reference source"
        };
        let measurement = &rec.submods.attestation.measurement;

        if !rv.contains(measurement) {
            return Finding {
                field: self.0,
                verdict: Verdict::Diverges,
                reason: format!(
                    "{source_note}; you supplied {} reference value(s) via --reference-values \
                     and this record's measurement '{measurement}' is NOT among them: [{}]",
                    rv.measurements.len(),
                    rv.measurements.join(", "),
                ),
                residual: Vec::new(),
            };
        }

        // The comparison itself holds. A deployment, if also supplied, adds
        // an orthogonal residual (who must be honest for the reference
        // values THEMSELVES to hold) that must survive alongside it.
        let (residual, deployment_note) = match ctx.deployment.as_ref() {
            None => (Vec::new(), String::new()),
            Some(dp) => match parallax::deployment::Deployment::load(dp)
                .map_err(|e| e.to_string())
                .and_then(|d| parallax::solve::solve(&d).map_err(|e| e.to_string()))
            {
                Ok(set) => {
                    let note = format!(
                        "; the deployment also solves ({} principals would need to be honest \
                         for the reference values themselves to hold)",
                        set.0.len()
                    );
                    let residual = set
                        .0
                        .iter()
                        .map(|a| Residual {
                            principal: a.principal.clone(),
                            capability: a.capability.clone(),
                            detect: a.latency.label(),
                            impact: impact_label(&a.impact).to_string(),
                        })
                        .collect();
                    (residual, note)
                }
                Err(e) => {
                    return Finding {
                        field: self.0,
                        verdict: Verdict::Unchecked(Why::AuditorFailed(e.clone())),
                        reason: format!("parallax could not solve the deployment: {e}"),
                        residual: Vec::new(),
                    }
                }
            },
        };

        Finding {
            field: self.0,
            verdict: Verdict::Established(
                BackedBy::new("--reference-values comparison").expect("non-empty literal"),
            ),
            reason: format!(
                "{source_note}; you supplied {} reference value(s) via --reference-values and \
                 this record's measurement '{measurement}' is among them{deployment_note}",
                rv.measurements.len(),
            ),
            residual,
        }
    }

    fn measurement_finding(&self, rec: &Record, ctx: &Context) -> Finding {
        if let Some(path) = ctx.reference_values.as_ref() {
            return self.measurement_against_reference_values(rec, ctx, path);
        }
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

    /// A unique temp file per call: a fixed name would race under parallel
    /// test execution, the same hazard `tests/exit_matrix.rs`'s
    /// `unique_temp_path` documents.
    fn write_reference_values(measurements: &[&str]) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("poc-audit-rv-{}-{nanos}.json", std::process::id()));
        let body = serde_json::json!({ "measurements": measurements });
        std::fs::write(&path, body.to_string()).expect("write reference values fixture");
        path
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

    /// The whole point of `--reference-values`: a file supplied, and the
    /// record's measurement is IN it. This is the first time this auditor can
    /// ever produce ESTABLISHED for `measurement` — everything else in this
    /// file downgrades to ASSERTED or UNCHECKED precisely because nothing
    /// used to compare the field to anything.
    #[test]
    fn measurement_in_the_supplied_reference_values_is_established() {
        let rv_path = write_reference_values(&[
            "sha-256:a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81",
        ]);
        let ctx = Context {
            reference_values: Some(rv_path.clone()),
            ..Context::default()
        };
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/v.json")),
            &ctx,
        );
        let _ = std::fs::remove_file(&rv_path);
        assert_eq!(f.verdict.label(), "ESTABLISHED", "reason was: {}", f.reason);
        assert!(
            f.reason.contains("--reference-values"),
            "the reason must name what backs the comparison, got: {}",
            f.reason
        );
    }

    /// The highest-value output this tool can produce: a file was supplied,
    /// and the record's measurement is NOT in it. Attested code that is not
    /// the code you approved.
    #[test]
    fn measurement_absent_from_the_supplied_reference_values_diverges() {
        let rv_path = write_reference_values(&[
            "sha-256:0000000000000000000000000000000000000000000000000000000000000",
        ]);
        let ctx = Context {
            reference_values: Some(rv_path.clone()),
            ..Context::default()
        };
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/v.json")),
            &ctx,
        );
        let _ = std::fs::remove_file(&rv_path);
        assert_eq!(f.verdict.label(), "DIVERGES", "reason was: {}", f.reason);
        assert!(
            f.reason
                .contains("a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81"),
            "the reason must show the record's own measurement, got: {}",
            f.reason
        );
        assert!(
            f.reason
                .contains("0000000000000000000000000000000000000000000000000000000000000"),
            "the reason must show what was expected, got: {}",
            f.reason
        );
    }

    /// ESTABLISHED via `--reference-values` must not silently drop the
    /// residual trust set when `--deployment` is also supplied — that
    /// residual (who must be honest for the *deployment's* reference values
    /// to hold) is orthogonal to, and still valuable alongside, the
    /// operator's own comparison.
    #[test]
    fn established_by_reference_values_keeps_the_deployment_residual() {
        let rv_path = write_reference_values(&[
            "sha-256:a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81",
        ]);
        let deployment = std::path::Path::new("tests/fixtures/parallax/sigma2-tdx.toml");
        let ctx = Context {
            reference_values: Some(rv_path.clone()),
            deployment: Some(deployment.to_path_buf()),
            ..Context::default()
        };
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/v.json")),
            &ctx,
        );
        let _ = std::fs::remove_file(&rv_path);
        assert_eq!(f.verdict.label(), "ESTABLISHED", "reason was: {}", f.reason);
        assert!(
            !f.residual.is_empty(),
            "the deployment's residual set must survive alongside the reference-values comparison"
        );
    }

    /// The reason text must keep the record's claim ("a reference source is
    /// named") distinct from the operator's own act of comparison ("you
    /// supplied values and I compared"). Conflating them is the exact defect
    /// this feature exists to remove.
    #[test]
    fn the_reason_distinguishes_the_records_claim_from_the_operators_comparison() {
        let rv_path = write_reference_values(&[
            "sha-256:a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81",
        ]);
        let ctx = Context {
            reference_values: Some(rv_path.clone()),
            ..Context::default()
        };
        let f = AttestationField("submods.attestation.measurement").audit(
            &record_with("INTEL_TDX", Some("https://rv.example/v.json")),
            &ctx,
        );
        let _ = std::fs::remove_file(&rv_path);
        assert!(
            f.reason.contains("names a reference source"),
            "must name the record's own claim separately, got: {}",
            f.reason
        );
        assert!(
            f.reason.contains("you supplied") || f.reason.contains("--reference-values"),
            "must name the operator's own act of comparison separately, got: {}",
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
