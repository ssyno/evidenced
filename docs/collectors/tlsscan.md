# TLS endpoint scanner (`tlsscan`)

## What it observes

Connects to the TLS endpoints you configure — from the outside, with no
credentials — and records how each one presents itself: negotiated TLS
protocol version and cipher, certificate subject, issuer, validity window
and days until expiry, key algorithm and strength, whether the
certificate chain is trusted by standard root authorities, and whether
the certificate matches the hostname.

Endpoints that cannot be reached are recorded as collection failures for
that endpoint — an outage or a blocked scan is itself part of the
evidence trail.

## What it never records

No connection payloads and no private key material. Only the public
certificate metadata any client on the internet could see. A test in the
codebase pins the exact set of fields that may appear in output.

## Controls served

| Control | Why this evidence supports it |
| --- | --- |
| DORA Article 9(2) — security of networks and data in transit | Recurring, timestamped proof of the encryption posture your services present externally. |
| DORA Article 10(1) / 6(1) — detection and monitoring (on failure) | Failed scans document monitoring gaps rather than hiding them. |

## Configuration

```yaml
collectors:
  tlsscan:
    enabled: true
    settings:
      endpoints: ["www.example.com:443", "api.example.com:443"]
      timeout: 10s
```

## Access required

Outbound TCP to the configured endpoints. Nothing else.
