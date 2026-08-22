# evidenced

Continuous technical compliance evidence collection. One static Go
binary that observes your infrastructure read-only, maps every
observation to regulatory controls (DORA first), and exports
auditor-ready, tamper-evident reports.

**The problem**: when the auditor asks "show me that certificates are
rotated / access is scoped / deployments are gated", teams burn weeks
producing screenshots that prove only what things looked like that day.

**What evidenced does**: collects that proof continuously, on a
schedule, as structured records that are hash-chained (tampering is
detectable), mapped to control articles, and exportable as a signed
bundle any auditor can verify independently.

## Principles

- **Read-only, always.** Collectors observe; nothing is ever mutated.
  The minimal RBAC footprint is a product feature.
- **No secrets in evidence.** Metadata and posture only — expiry dates,
  key sizes, issuer references. Never key material or secret values,
  enforced by tests.
- **Runs where you run.** Kubernetes operator, systemd daemon on a VM,
  or one-shot CLI in CI — same engine, same YAML schema, same output.
- **No phone-home.** The agent never sends data anywhere on its own.
  Evidence reaches the evidenced portal (or any other destination) only
  when you explicitly export or upload it.

## Collectors (MVP)

| Collector | Evidence | DORA controls |
| --- | --- | --- |
| [certlifecycle](docs/collectors/certlifecycle.md) | cert-manager certificate expiry, rotation, issuer config, key params | 9(4)(c), 8(1) |
| [rbacposture](docs/collectors/rbacposture.md) | privileged roles, cluster-admin bindings, service-account sprawl | 9(4)(d), 8(1) |
| [provenance](docs/collectors/provenance.md) | image sources, digest pinning, admission/signature policy posture | 9(3), 8(1) |
| [tlsscan](docs/collectors/tlsscan.md) | external TLS protocol + certificate posture, zero access needed | 9(2) |

Collection failures are themselves recorded as evidence (Articles 10(1),
6(1)): a monitoring gap is a fact an auditor needs, not an error to
swallow.

## Quick start

```sh
make build
cat > evidenced.yaml <<'EOF'
storePath: evidence.jsonl
signing:
  keyPath: signing.pem
collectors:
  tlsscan:
    enabled: true
    settings:
      endpoints: ["www.example.com:443"]
EOF
./bin/evidenced collect --config evidenced.yaml --report
./bin/evidenced verify-bundle reports/evidence-*Z
```

See [docs/deployment.md](docs/deployment.md) for the operator and
daemon shells, [docs/evidence-model.md](docs/evidence-model.md) for how
tamper evidence works.

## Development

Go 1.24+. `make lint test` must pass; `make build-all` cross-compiles
static binaries for linux/amd64 and linux/arm64.

Layout: `internal/core` (engine, zero platform assumptions),
`internal/collectors/*` (pluggable observers), `internal/shells/*`
(operator / daemon / cli frontends), ``mapping/dora` (control
catalog as data).
