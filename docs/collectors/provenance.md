# Deployment provenance (`provenance`)

## What it observes

Records where the software running in your cluster comes from and what
gates it on the way in:

1. **Workload images** — for every Deployment, StatefulSet and
   DaemonSet: each container's image reference, which registry it comes
   from, whether it is pinned to an immutable digest (`@sha256:...`)
   rather than a mutable tag, and its pull policy.
2. **Admission policy posture** — the validating admission webhooks
   active in the cluster, and whether any known image signature
   verification engine (Kyverno, Sigstore policy-controller, Connaisseur,
   Ratify, Notation) is among them.

An auditor reads this as: which sources software is procured from,
whether deployed artifacts are immutable and attributable, and whether
unauthorized software is technically prevented from running.

## What it never records

Workload specs beyond image and pull-policy fields — no environment
variables, no mounted secrets, no command lines.

## Controls served

| Control | Why this evidence supports it |
| --- | --- |
| DORA Article 9(3) — prevention of unauthorised software | Admission policy posture and image provenance show the controls gating what runs. |
| DORA Article 8(1) — identification of ICT assets | A recurring inventory of deployed images and their sources. |

## Configuration

```yaml
collectors:
  provenance:
    enabled: true
    settings:
      namespaces: []   # empty = all namespaces
```

## Access required

Kubernetes read-only (`get`, `list`, `watch`) on `deployments`,
`statefulsets`, `daemonsets` and `validatingwebhookconfigurations`.
