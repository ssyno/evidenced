# Evidence model

Every observation evidenced makes is stored as an **evidence record**. This
page explains what a record contains and why the stored evidence can be
trusted not to have been altered after the fact.

## What a record contains

| Field | Meaning for an audit |
| --- | --- |
| `collectorId`, `collectorVersion` | Which component produced the evidence, and its exact version. |
| `target` | What was observed (for example a certificate, a role binding, a TLS endpoint). |
| `collectedAt` | When the observation was made. |
| `outcome` | `observed` for a successful observation, or `collection-failed` when evidence could not be gathered. Failed collections are kept as evidence in their own right — a gap in monitoring is itself a reportable fact. |
| `observation` | The structured facts observed (expiry dates, key sizes, issuer references — never secret values or key material). |
| `controlIds` | The regulatory control(s) this evidence supports (DORA article identifiers in the MVP). |
| `prevHash`, `hash` | Tamper-evidence links; see below. |

## Tamper evidence

Records form a **hash chain**. Each record carries a SHA-256 fingerprint
(`hash`) of its own content, and that content includes the fingerprint of
the record collected before it (`prevHash`). Changing, removing, reordering
or back-dating any record therefore breaks the chain at that point, and
verification reports exactly which record no longer matches.

Verification recomputes every fingerprint from the stored content, so it
needs no external service or stored secret — an auditor can re-run it
independently on an exported bundle.

Records are immutable once written. evidenced only ever appends new
records; corrections are expressed as new observations, never as edits to
history.
