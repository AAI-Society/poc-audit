# poc-audit

The Proof-of-Control standard ships a validator with three layers. This is the
fourth.

```
validate.py                     poc-audit
  1 STRUCTURE   the JSON Schema      ─┐
  2 CANONICAL   RFC 8785 + profile    ├─ assumed to have passed
  3 SEMANTIC    tier / signature      ─┘
                                          4 RESIDUAL
                                            what the fields do not tell you
```

Layers 1–3 ask whether a record is well-formed and internally consistent.
This one asks whether it means what you think.

```console
$ poc-audit tests/fixtures/vectors/positive/hardware-attested.json
FIELD                               VERDICT       WHY
iss                                 UNCHECKED     issuer identity is out of scope
iat                                 UNCHECKED     issuance time is out of scope
nonce                               UNCHECKED     freshness against a challenge is out of scope
eat_profile                         UNCHECKED     profile identity is checked by validate.py
poc_claims                          UNCHECKED     audited through its individual claims
submods                             UNCHECKED     audited through submods.attestation.*
poc_claims.agent_id                 ESTABLISHED   'did:web:example.org:agents:ref-1' is a persistent identifier, so C5.1.1 is satisfied. The cost is that every action carrying it is linkable to one subject — which is precisely what an unlinkable profile cannot provide. Supply --fleet for the anonymity-set size
poc_claims.initiating_user          ESTABLISHED   'user:alice' is a persistent identifier, so C5.1.1 is satisfied. The cost is that every action carrying it is linkable to one subject — which is precisely what an unlinkable profile cannot provide. Supply --fleet for the anonymity-set size
poc_claims.canonical_snapshot_hash  UNCHECKED     the record carries one digest; supply --payload to find out whether both sides compute it the same way
poc_claims.chain_head               UNCHECKED     a single record cannot establish chain continuity on its own; run `poc-audit --chain <records...>` with its neighbours to audit the sequence
poc_claims.merkle_root              UNCHECKED     a single record cannot establish chain continuity on its own; run `poc-audit --chain <records...>` with its neighbours to audit the sequence
poc_claims.step_index               UNCHECKED     a single record cannot establish chain continuity on its own; run `poc-audit --chain <records...>` with its neighbours to audit the sequence
poc_claims.agbom_digest             UNCHECKED     no AgBOM tooling exists; see P10
poc_claims.interception_point       UNCHECKED     enumerated value, checked by validate.py
poc_claims.tree_size                UNCHECKED     consistency with step_index is validate.py's semantic layer
poc_claims.policy_bundle_hash       UNCHECKED     no policy-bundle tooling exists
poc_claims.target_resource          UNCHECKED     free text; nothing to check it against
poc_claims.path_summary_hash        UNCHECKED     bounded path summaries are P04, unbuilt
poc_claims.verdict                  UNCHECKED     enumerated value, checked by validate.py
poc_claims.alg                      UNCHECKED     signature checking is validate.py's semantic layer
submods.attestation.platform        ASSERTED      platform is INTEL_TDX; the record asserts it and nothing here re-verifies the quote
submods.attestation.measurement     UNCHECKED     reference values are named, but who operates them is unknown; supply --deployment to find out

No aggregate verdict is printed. Each row stands alone; see the exit code.
per C8 (see P01: the ladder is contested): Tier 3 — hardware platform with named reference values
```

Each row is answered by a different research tool: `parallax` for the
attestation, `transit` for the canonical form, `occultation` for identity.
They are reused as libraries, not reimplemented.

## The five verdicts

| verdict | means |
| --- | --- |
| `ESTABLISHED` | something outside the record checked it, and it holds |
| `ASSERTED` | we looked, and found nothing behind it |
| `DIVERGES` | two parties who must agree produce different values |
| `CANNOT HOLD` | structurally unsatisfiable here, not merely unverified |
| `UNCHECKED` | we did not look — no auditor, or its input was missing |

**`ASSERTED` is not `UNCHECKED`.** "I checked and there is nothing behind this"
is a different statement from "I did not check." Collapsing them is how a
report ends up implying coverage it does not have.

## Deepening a report

The record alone always produces a report. Each optional input upgrades some
`UNCHECKED` rows to real verdicts. `--deployment`, `--payload`, and `--fleet`
each reuse one of the three research tools' own existing formats.
`--reference-values` is the one exception — poc-audit's own format, kept
deliberately minimal (see below) because it has no upstream tool to borrow
from.

| flag | deepens | format |
| --- | --- | --- |
| `--deployment` | `submods.attestation.measurement` | a `parallax` deployment |
| `--payload` | `poc_claims.canonical_snapshot_hash` | the raw request bytes |
| `--fleet` | `poc_claims.agent_id`, `poc_claims.initiating_user` | an `occultation` fleet |
| `--profile` | `poc_claims.agent_id` | `standard` (default) or `unlinkable` |
| `--reference-values` | `submods.attestation.measurement` | a local JSON file (see below) |

`--deployment` deepens only `submods.attestation.measurement`, not
`submods.attestation.platform` — the platform row asserts the record's own
claim and is byte-identical whether or not `--deployment` is supplied; only
`measurement` reads it. `--fleet` deepens both identity rows, not only
`agent_id`: `initiating_user` goes through the same `Identity` auditor and
picks up the same anonymity-set figures.

`--profile` is the one input that can *reverse* a verdict rather than deepen
it. A persistent `agent_id` satisfies C5.1.1 under `standard` and cannot hold
under `unlinkable`, and nothing in a record says which is in force — so the
tool asks rather than guessing. Guessing it from the shape of an identifier
would manufacture exactly the false finding this tool exists to avoid.

`--explain <field>` prints the residual trust set behind one finding: who must
be honest, what they could do, and how long before you would know.

### `--reference-values`: comparing the measurement to something

Without this flag, `submods.attestation.measurement` can never rise above
`ASSERTED`: `reference_values_uri`, when present, is a URI *in the record*,
naming where the issuer says reference values live — and this tool never
fetches it, because that would both break the offline constraint and only
re-check the record's own claim about where to look, not anything
independent. `--deployment` tells you *who operates* those reference values,
which is a real and separate fact, but it still never reads the measurement
field itself.

`--reference-values <FILE>` is the other half: a local JSON file naming the
measurements *you* accept, compared directly against
`submods.attestation.measurement`.

```json
{
  "measurements": [
    "sha-256:a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81"
  ]
}
```

One object, one array of digest strings in the same `alg:hex` shape the
record itself uses. Nothing richer — no per-entry metadata or provenance —
because that would invite this tool to start interpreting *why* a value was
approved, which is an inference FAILS LOUD forbids.

```console
$ poc-audit tests/fixtures/vectors/positive/hardware-attested.json \
    --reference-values tests/fixtures/reference-values/matches-hardware-attested.json | \
    grep measurement
submods.attestation.measurement     ESTABLISHED   the record names a reference source (reference_values_uri), but that URI is not fetched; you supplied 1 reference value(s) via --reference-values and this record's measurement 'sha-256:a1d0bdcf12b227dbe4347ce7a24a9a385a92369cd671fc1deaf9d2f7bb35cb81' is among them

$ poc-audit tests/fixtures/vectors/positive/hardware-attested.json \
    --reference-values tests/fixtures/reference-values/does-not-match.json | \
    grep measurement
submods.attestation.measurement     DIVERGES      the record names a reference source (reference_values_uri), but that URI is not fetched; you supplied 2 reference value(s) via --reference-values and this record's measurement 'sha-256:a1d0bdcf...' is NOT among them: [sha-256:0000..., sha-256:1111...]
```

The reason text always keeps two claims apart: whether *the record* names a
reference source (`reference_values_uri`), and whether *you* supplied values
and this tool compared against them. Conflating those is the exact defect
this feature exists to remove — the old behaviour used to say "reference
values are named" and stop there, which reads as more verification than
ever happened.

The DIVERGES row is the highest-value output this tool can produce:
attested code that is not the code you approved. If `--deployment` is also
supplied and the comparison holds, its residual trust set (who must be
honest for the reference values *themselves* to hold) is kept alongside the
ESTABLISHED verdict — the two facts are orthogonal, and neither should push
the other out.

An unreadable or malformed `--reference-values` file is a hard error (exit
2), the same strictness as `--deployment`, `--payload`, and `--fleet`.

## `--chain`: auditing a sequence, not one record

`validate.py`'s semantic layer checks `tree_size > step_index` *within* one
record. Nothing anywhere checks continuity *across* records: that
`step_index` actually walks 0, 1, 2, … with no gaps, duplicates, or
reordering; that `tree_size` never shrinks; that every record in a run
belongs to the same agent. Those are all soundly checkable once you have the
whole sequence, and a single-record invocation structurally cannot check
them — there is nothing to compare against.

```console
$ poc-audit --chain step-0.json step-1.json step-2.json
FIELD                    VERDICT       WHY
poc_claims.agent_id      ESTABLISHED   all 3 supplied records share agent_id '...'
poc_claims.step_index    ESTABLISHED   step_index runs 0..2 across the 3 supplied records, in order, with no gaps, duplicates, or reordering
poc_claims.tree_size     ESTABLISHED   tree_size is non-decreasing across the 3 supplied records, and each covers its own step_index
poc_claims.chain_head    UNCHECKED     chain_head is described as H(previous_head || canonical_snapshot_hash || verdict), but neither the schema nor validate.py pins the hash function, byte encoding, or concatenation semantics, so it is not recomputed here — that would be a guess dressed as a verdict. Every chain_head across the supplied records is at least distinct, which is checked.
poc_claims.merkle_root   UNCHECKED     merkle_root is an RFC 6962 tree head over all leaves through this step; recomputing it needs every leaf, not only the 3 record(s) supplied here, so it is not checked
```

Give at least two files, **oldest first**: the order on the command line
*is* the claimed sequence, and nothing sorts it for you — passing them out of
order is the "reordering" failure this mode exists to catch, not something
to silently correct. `--chain` and the positional `record` argument are
mutually exclusive; the common single-record invocation (`poc-audit
record.json`) is completely unchanged by this feature's existence.

Each row's failure mode, against a broken variant of the same three-record
sequence:

| what broke | row | verdict | example reason |
| --- | --- | --- | --- |
| a step is skipped (`0, 1, 3`) | `step_index` | `DIVERGES` | `step_index is not the contiguous 0..N sequence the schema requires: step-2.json has step_index 3 at position 2 (expected 2)` |
| a step repeats (`0, 1, 1`) | `step_index` | `DIVERGES` | `step_index is not the contiguous 0..N sequence the schema requires: step-2.json has step_index 1 at position 2 (expected 2)` |
| two agents in one run | `agent_id` | `DIVERGES` | `the supplied records do not share one agent_id: step-0.json has '...ref-1', but step-2.json has agent_id '...ref-2'` |
| `tree_size` shrinks (`3, 2, 4`) | `tree_size` | `DIVERGES` | `tree_size is not consistent across the sequence: step-1.json has tree_size 2, smaller than step-0.json's 3` |
| two records share one `chain_head` | `chain_head` | `CANNOT HOLD` | `... both carry chain_head '...'; a collision-resistant hash cannot legitimately repeat across distinct steps, so this sequence cannot hold together as a chain` |

That last row is the one exception to "`chain_head` is never recomputed."
The schema describes its construction as `H(previous_head ||
canonical_snapshot_hash || verdict)`, but pins neither `H`, the byte
encoding, nor the concatenation — recomputing it would be a guess dressed as
a verdict, the worst defect this tool can have, so it never is. A *repeated*
head, though, is impossible under any construction a collision-resistant
hash could satisfy, so that cheap structural fact is checked and reported.

`merkle_root` gets no such exception: nothing about a repeated
`merkle_root` is impossible (two adjacent steps could in principle share one
if no leaf were appended), so it stays plain `UNCHECKED` with no additional
claim.

`--chain` mode does not read `--deployment`, `--payload`, `--fleet`,
`--reference-values`, or `--profile` — none of those deepen a cross-record
fact — but `--explain` and `--require-checked` both work against it exactly
as they do for a single record.

## Exit codes

| code | condition |
| :--: | --- |
| `0` | nothing `DIVERGES` or `CANNOT HOLD` |
| `1` | at least one did, or a deepenable `UNCHECKED` row under `--require-checked` |
| `2` | bad input, an unreadable optional input, or an auditor that failed |

`--require-checked` is the CI gate for "no field is waiting on an input you
could supply." It fails only on `UNCHECKED` rows caused by a missing flag —
`--deployment`, `--payload`, or `--reference-values` not given for a field
that has an auditor — not on rows with no auditor reachable from *this*
invocation at all: AgBOM, the rest of `registry::ACCOUNTED`'s
`Coverage::Unaudited` entries, and the three chain fields in single-record
mode, which need a different invocation (`--chain`) rather than a flag added
to this one. Those cannot be turned into anything else by any invocation of
this tool run this way, so gating on them would leave the flag permanently
red on every record. It changes only the exit code; the report is
byte-identical. (`--chain` mode's own findings are never
`Unchecked(Why::MissingInput(_))` either — a repeated `chain_head` aside,
every row resolves outright from the records supplied — so
`--require-checked` is a no-op there, never a source of new failures.)

`--fleet` is not part of this list: its two rows (`agent_id`,
`initiating_user`) are never `UNCHECKED` for lack of it — they resolve to
`ESTABLISHED` or `CANNOT HOLD` from the record and `--profile` alone, and
`--fleet`'s absence only shortens the reason text ("Supply --fleet for the
anonymity-set size") rather than leaving the row waiting. `--require-checked`
therefore cannot be made to fire on a missing `--fleet`.

## What this does not do

- **No signing, no keys, no `--emit`.** It reads records and reports on them.
  Signing a "you passed" token is the overclaim this whole programme attacks.
- **No aggregate pass/fail, and never the word "compliant".** A single summary
  word is how a deployment claims a tier it has not earned. The C8 tier is
  printed, attributed to the standard rather than endorsed — see P01, which
  holds the ladder is wrong as written.
- **No runtime composition.** Chaining the three tools' proxies in one request
  path is a separate, unbuilt design: two of them refuse requests and the third
  guarantees it never will.
- **No fetching `reference_values_uri`.** It is a URI *in the record*.
  `--reference-values` compares against a local file *you* supply — your own
  asserted trust, not a live fetch of the record's own claim about where to
  look. Nothing here ever makes a network request.
- **No provenance on the `--reference-values` file itself.** The tool trusts
  that whoever handed you that file is who they say they are and approved
  what they say they approved. It checks membership, not the file's own
  chain of custody.
- **No `chain_head` recomputation, ever — not even for a fully valid
  `--chain` run.** The construction is prose (`H(previous_head ||
  canonical_snapshot_hash || verdict)`), not a pinned algorithm; guessing it
  would risk a false `DIVERGES` on conformant input, the worst defect this
  tool can have. Only a *repeated* head is reported, because that alone is
  impossible under any hash.
- **No `merkle_root` recomputation.** It is a tree head over every leaf ever
  appended, not only the records handed to one `--chain` invocation.
- **No proof that a `--chain` invocation was handed the WHOLE history.**
  Continuity is checked only across the files you supplied. A contiguous,
  agent-consistent *subsequence* of a longer chain — with earlier records
  simply omitted from the command line — passes exactly like a complete one.
  `--chain` audits what you show it, not what you might be withholding.

## Building

`parallax`, `transit` and `occultation` are pulled in as git dependencies from
private sibling repos in this org. `cargo build`/`cargo test` locally need SSH
or HTTPS credentials for those repos already configured in your git, same as
any other private dependency. In CI, the workflow's default `GITHUB_TOKEN` is
scoped to this repository only and cannot read them, so the pipeline rewrites
GitHub URLs to authenticate with a `DEPS_READ_TOKEN` repository secret (a
fine-grained PAT with read access to the org's repos) before the first `cargo`
invocation. Without that secret set, CI fails fast with an explicit error
rather than the opaque `could not read Username for 'https://github.com'`
failure that cost a full CI run to diagnose.

## Design

[`2026-08-09-poc-audit-design.md`](https://github.com/Task-force-for-AI-agents-in-Healthcare/poc-research-roadmap/blob/master/docs/superpowers/specs/2026-08-09-poc-audit-design.md)
