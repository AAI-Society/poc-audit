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
poc_claims.chain_head               UNCHECKED     no auditor: chain continuity across records is unimplemented
poc_claims.merkle_root              UNCHECKED     no auditor: chain continuity across records is unimplemented
poc_claims.step_index               UNCHECKED     no auditor: chain continuity across records is unimplemented
poc_claims.agbom_digest             UNCHECKED     no AgBOM tooling exists; see P10
poc_claims.interception_point       UNCHECKED     enumerated value, checked by validate.py
poc_claims.tree_size                UNCHECKED     consistency with step_index is validate.py's semantic layer
poc_claims.policy_bundle_hash       UNCHECKED     no policy-bundle tooling exists
poc_claims.target_resource          UNCHECKED     free text; nothing to check it against
poc_claims.path_summary_hash        UNCHECKED     bounded path summaries are P04, unbuilt
poc_claims.verdict                  UNCHECKED     enumerated value, checked by validate.py
poc_claims.alg                      UNCHECKED     signature checking is validate.py's semantic layer
submods.attestation.platform        ASSERTED      platform is INTEL_TDX; the record asserts it and nothing here re-verifies the quote
submods.attestation.measurement     UNCHECKED     reference values are named, but who operates them is unknown

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
`UNCHECKED` rows to real verdicts, and each is one of the three tools' own
existing formats — there is no fourth config language.

| flag | deepens | format |
| --- | --- | --- |
| `--deployment` | `submods.attestation.*` | a `parallax` deployment |
| `--payload` | `poc_claims.canonical_snapshot_hash` | the raw request bytes |
| `--fleet` | `poc_claims.agent_id` | an `occultation` fleet |
| `--profile` | `poc_claims.agent_id` | `standard` (default) or `unlinkable` |

`--profile` is the one input that can *reverse* a verdict rather than deepen
it. A persistent `agent_id` satisfies C5.1.1 under `standard` and cannot hold
under `unlinkable`, and nothing in a record says which is in force — so the
tool asks rather than guessing. Guessing it from the shape of an identifier
would manufacture exactly the false finding this tool exists to avoid.

`--explain <field>` prints the residual trust set behind one finding: who must
be honest, what they could do, and how long before you would know.

## Exit codes

| code | condition |
| :--: | --- |
| `0` | nothing `DIVERGES` or `CANNOT HOLD` |
| `1` | at least one did, or a deepenable `UNCHECKED` row under `--require-checked` |
| `2` | bad input, an unreadable optional input, or an auditor that failed |

`--require-checked` is the CI gate for "no field is waiting on an input you
could supply." It fails only on `UNCHECKED` rows caused by a missing flag —
`--deployment`, `--payload`, or `--fleet` not given for a field that has an
auditor — not on rows with no auditor at all (chain continuity, AgBOM, and
the rest of `registry::ACCOUNTED`'s `Coverage::Unaudited` entries). Those
cannot be turned into anything else by any invocation of this tool, so gating
on them would leave the flag permanently red on every record. It changes only
the exit code; the report is byte-identical.

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

## Design

[`2026-08-09-poc-audit-design.md`](https://github.com/Task-force-for-AI-agents-in-Healthcare/poc-research-roadmap/blob/master/docs/superpowers/specs/2026-08-09-poc-audit-design.md)
