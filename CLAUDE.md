# CLAUDE.md — evidenced

Continuous technical compliance evidence collection. One static Go binary
(`evidenced`) that collects infrastructure evidence, maps it to regulatory
controls (DORA first), and exports auditor-ready, tamper-evident reports.
Deployable anywhere: Kubernetes operator, systemd unit on a VM, container,
or one-shot CLI.

## What this is (and is not)

- It is an **evidence engine** with pluggable collectors and pluggable
  deployment shells. Kubernetes is one deployment mode, not the product.
- It is **read-only, always**. No collector may mutate anything it observes.
  The tightly scoped read-only permission set is a product feature — never
  widen it for convenience.
- It is **not** an enforcement tool, not a policy engine, not an agent
  framework, not a SaaS control plane. Do not build toward those; they are
  explicitly out of scope (see Scope).

## Architecture — three layers, strictly separated

1. **Core** (`internal/core/`): scheduler, evidence store, control mapping
   engine, report exporter. ZERO platform assumptions. Must compile and run
   with no kubeconfig, no cloud credentials, no network. If a change to core
   imports k8s.io/* or controller-runtime, it is wrong — stop and restructure.
2. **Collector plugins** (`internal/collectors/<name>/`): each implements
   the Collector interface (roughly `Collect(ctx) ([]Evidence, error)` plus
   metadata/self-description). Collectors declare what credentials/access
   they need; the shell provides it.
3. **Deployment shells** (`cmd/` + `internal/shells/`): thin adapters that
   configure and run the core.
   - `operator` shell: controller-runtime, CRDs (`EvidencePolicy`,
     `EvidenceReport`) as a *frontend* to the same plain-YAML config the
     other shells use. controller-runtime types must never leak below this
     shell.
   - `daemon` shell: systemd/VM mode, YAML file config.
   - `cli` shell: `evidenced collect --report` one-shot mode for CI.

Config is plain YAML everywhere; CRDs translate to it. One schema, multiple
frontends.

## Evidence model

- Evidence records are structured, timestamped, immutable once written.
- Records are hash-chained (each record includes the hash of the previous)
  so tampering is detectable. Keep this cheap and simple — SHA-256 chain,
  no blockchain theater.
- Every record carries: collector id + version, target identity, collection
  timestamp, raw observation (structured), and the control ids it maps to.
- Export bundle = JSON (machine) + human-readable report (auditor-facing),
  both signed/checksummed.

## 90-day MVP scope — the fence

IN scope:
- Collectors: (1) certificate lifecycle (cert-manager resources, expiry,
  rotation history, issuer config), (2) RBAC posture (permissions, privilege
  drift, service-account sprawl), (3) deployment provenance (image sources,
  signature verification state, admission policy posture), (4) TLS endpoint
  scanner (external, zero-access, demo/sales path).
- Framework mapping: DORA ICT risk-management articles only.
- Output: signed evidence bundle + human-readable report export.
- Shells: operator + daemon + cli (daemon/cli may be thin, but must work —
  they prove the layering).

OUT of scope (stub interfaces only, do not implement, do not "just add"):
- NIS2 / AI Act / PCI-DSS mappings
- Host posture and cloud API collectors (interface + stub only)
- Any UI beyond the report export
- Multi-cluster, SaaS control plane, agent identity module, enforcement of
  any kind

If a task drifts toward OUT items, stop and flag it instead of building it.

## Go conventions

- Go 1.24+, single module. Standard library first; justify every dependency.
- Allowed heavyweight deps: controller-runtime (operator shell ONLY),
  client-go (k8s collectors ONLY). Core must stay dependency-light.
- Static binary: CGO_ENABLED=0. Cross-compile targets: linux/amd64,
  linux/arm64. `make build-all` must produce both.
- Errors: wrap with context (`fmt.Errorf("...: %w", err)`), no panics in
  library code. Collectors must degrade gracefully — a failing collector
  reports its failure AS evidence (an auditor wants to know collection
  failed), it never crashes the process.
- Table-driven tests. Core and mapping engine: high coverage, no mocks of
  our own code. Collectors: test against fake/envtest clients, never require
  a live cluster for unit tests.
- Lint: golangci-lint with defaults + gosec. `make lint test` must pass
  before any commit is considered done.
- Conventional commits (feat:, fix:, docs:, refactor:).

## Security posture

- The operator's ClusterRole is read-only and minimal — list/watch/get on
  exactly the resources collectors declare. Any PR widening RBAC must say
  why in the description.
- No secrets in evidence records: collectors observe metadata and posture
  (expiry dates, key sizes, issuer refs), never key material or secret
  values. Redaction is the collector's responsibility; add tests that prove
  secret values cannot appear in output.
- No telemetry, no phone-home. Everything runs in the customer's
  environment; evidence never leaves it unless the customer exports it.

## Repo layout (target)

```
cmd/evidenced/            # main; subcommands select shell
internal/core/            # scheduler, store, mapping engine, exporter
internal/evidence/        # record types, hash chain, signing
internal/collectors/
  certlifecycle/
  rbacposture/
  provenance/
  tlsscan/
  hostposture/            # stub only
  cloudconfig/            # stub only
internal/shells/
  operator/               # controller-runtime lives here and only here
  daemon/
  cli/
internal/mapping/dora/    # control catalog + mapping data (YAML) + engine glue
api/v1alpha1/             # CRD types (operator shell frontend)
deploy/helm/evidenced/
deploy/systemd/
docs/
Makefile
```

## Definition of done (per feature)

1. Compiles for both targets, `make lint test` clean.
2. Collector output maps to at least one DORA control id, with the mapping
   data in `internal/mapping/dora/`, not hardcoded in Go.
3. Works in at least the operator shell AND one non-k8s shell (cli counts)
   if the feature is core-level; k8s-only collectors need operator shell +
   unit tests only.
4. Docs: a short section in docs/ describing what evidence is produced and
   which controls it serves. Write for a compliance officer, not a
   platform engineer.

## Working style for Claude Code sessions

- Work in small, reviewable increments; one collector or one core component
  per session, not sweeping changes across layers.
- When ambiguity arises about scope, choose the narrower interpretation and
  leave a TODO with the question — do not expand scope to resolve ambiguity.
- Never commit directly to main; branch per feature.
- Ask before adding any new external dependency.