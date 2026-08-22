# RBAC posture (`rbacposture`)

## What it observes

Reads Kubernetes access-control configuration and records three kinds of
evidence:

1. **Privileged cluster roles** — roles with wildcard permissions (any
   verb, any resource, or any API group) or the ability to read Secrets.
   Ordinary, narrowly-scoped roles produce no records; the evidence
   focuses on what an auditor needs to review.
2. **Bindings to cluster-admin** — every subject (user, group or service
   account) currently granted the cluster's highest privilege.
3. **Service-account sprawl** — a cluster-wide summary of how many
   service accounts exist, per namespace.

Collected on an interval, this shows access-rights drift over time: new
admin bindings, newly created privileged roles, and accumulating
service accounts all appear in the evidence record with timestamps.

## What it never records

Role and binding *structure* only — subject names, rule shapes, counts.
Never tokens, secret values or credentials. A test seeds the fake
cluster with a secret value and asserts it cannot appear in output.

## Controls served

| Control | Why this evidence supports it |
| --- | --- |
| DORA Article 9(4)(d) — ICT access management | Recurring proof of who holds elevated access and how privilege is scoped. |
| DORA Article 8(1) — identification of ICT assets (service accounts) | An inventory of machine identities in the cluster. |

## Configuration

```yaml
collectors:
  rbacposture:
    enabled: true
```

## Access required

Kubernetes read-only (`get`, `list`, `watch`) on `clusterroles`,
`clusterrolebindings` and `serviceaccounts`.
