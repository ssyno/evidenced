# Deploying evidenced

One static binary, three shells. All three run the same engine on the
same configuration schema — pick the shell that fits the environment.

## Kubernetes operator

```sh
helm install evidenced deploy/helm/evidenced -n evidenced --create-namespace
```

The chart installs the CRDs, a read-only ClusterRole, a single-replica
Deployment backed by a PersistentVolumeClaim (the evidence store must
survive restarts), and a default `EvidencePolicy`. Tune collection via
the policy:

```yaml
apiVersion: evidenced.io/v1alpha1
kind: EvidencePolicy
metadata:
  name: default
spec:
  interval: 1h
  signingKeyPath: /var/lib/evidenced/signing.pem
  collectors:
    - name: certlifecycle
    - name: rbacposture
    - name: provenance
    - name: tlsscan
      settings:
        endpoints: ["www.example.com:443"]
```

Every cycle appends to the tamper-evident store, exports a signed bundle
under `/var/lib/evidenced/reports`, and creates an `EvidenceReport`:

```sh
kubectl get evidencepolicies    # records count, last run, last error
kubectl get evidencereports     # one per exported bundle
```

## VM / systemd daemon

```sh
install -m 0755 evidenced-linux-amd64 /usr/local/bin/evidenced
install -Dm 0640 deploy/systemd/config.example.yaml /etc/evidenced/config.yaml
install -m 0644 deploy/systemd/evidenced.service /etc/systemd/system/
useradd --system --home /var/lib/evidenced evidenced
systemctl enable --now evidenced
```

The unit is hardened (read-only system, no privileges); evidenced writes
only to `/var/lib/evidenced`. Kubernetes collectors work from a VM when
a kubeconfig is readable by the `evidenced` user.

## CLI (CI pipelines, auditors)

```sh
evidenced collect --config evidenced.yaml --report   # one cycle + bundle
evidenced export  --config evidenced.yaml            # bundle from existing store
evidenced verify  --config evidenced.yaml            # hash-chain integrity
evidenced verify-bundle reports/evidence-20260822-110000Z
```

`verify-bundle` needs nothing but the bundle directory — hand it to an
auditor together with the bundle and they can check checksums and the
ed25519 signature independently.

## Connecting to a portal (opt-in push)

By default the agent makes **no outbound connections** — evidence stays
where it was collected. To upload each exported bundle to an evidenced
portal, add a push block; the API token is read from an environment
variable or a mounted file, never from the config itself:

```yaml
push:
  url: https://portal.example.com
  tokenEnv: EVIDENCED_PUSH_TOKEN   # or tokenFile: /var/run/secrets/evidenced/token
  agent: prod-cluster              # defaults to hostname
  # caFile: /etc/evidenced/portal-ca.pem   # private CA, if needed
```

All shells honor it: the daemon and operator upload after every cycle,
`collect --report` uploads in CI, and `evidenced push <bundle-dir>`
re-uploads an existing bundle. HTTPS is required (plain HTTP is allowed
only toward loopback for development). A failed upload never interrupts
collection: the bundle stays on disk and the failure is logged (and
surfaced in the EvidencePolicy status in the operator).

In the helm chart:

```yaml
policy:
  push:
    enabled: true
    url: https://portal.example.com
    existingSecret: evidenced-portal-token   # key "token"
```

## The evidence store

- Append-only JSONL, one record per line, SHA-256 hash-chained.
- Verified fully on every open; a tampered store refuses to load.
- Keep it on durable storage. Losing it does not break future
  collection (a new chain starts), but history is your audit trail.
