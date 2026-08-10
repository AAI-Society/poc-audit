# Vendored from ov-poc-standard

`poc-evidence.schema.json` and `../tests/fixtures/vectors/` are copies from
<https://github.com/AAI-Society/ov-poc-standard>.

Upstream commit: 26702a9eb8ebe25bbb65e06b3a53493aebd2f214

Refreshing is a manual step, on purpose. A build-time fetch would break the
offline constraint the whole suite holds. Nothing detects that this copy has
gone stale; `every_required_field_is_accounted_for` in `src/registry.rs`
catches a schema that has *gained* a required field only once this copy is
refreshed.
