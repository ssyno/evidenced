# Certificate lifecycle (`certlifecycle`)

## What it observes

Reads cert-manager's Certificate, Issuer and ClusterIssuer resources in
your Kubernetes cluster and records, per certificate: the validity
window and days until expiry, the renewal time cert-manager has planned,
how many times the certificate has been reissued (revision), the key
algorithm, size and rotation policy, which issuer signs it, and whether
cert-manager reports it Ready. Per issuer it records the issuer type
(ACME/Let's Encrypt, internal CA, Vault, self-signed) and readiness.

Together these show an auditor that certificates are actively managed:
rotated before expiry, by a known issuer, with adequate key sizes.

## What it never records

The collector reads only cert-manager's own resources — it has no access
to the Kubernetes Secrets holding private keys, and its cluster role
does not permit reading Secrets at all. It records the *name* of the
secret a certificate is stored in, never its contents.

## Controls served

| Control | Why this evidence supports it |
| --- | --- |
| DORA Article 9(4)(c) — cryptographic key and certificate management | Continuous proof that certificates are rotated, expiry is tracked, and key parameters meet policy. |
| DORA Article 8(1) — identification of ICT assets | A recurring inventory of certificates in use. |

## Configuration

```yaml
collectors:
  certlifecycle:
    enabled: true
    settings:
      namespaces: []   # empty = all namespaces
```

## Access required

Kubernetes read-only (`get`, `list`, `watch`) on
`certificates.cert-manager.io`, `issuers.cert-manager.io`,
`clusterissuers.cert-manager.io`. If cert-manager is not installed the
collection attempt is recorded as a failure — evidence that this control
had no data source during the window.
