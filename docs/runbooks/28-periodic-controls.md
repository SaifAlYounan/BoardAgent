# 28 — Periodic controls

**Owners:** deployment administrator, secretariat, and security contact according to item.
**Purpose:** detect drift between releases instead of relying on launch-day evidence.

## Daily/continuous

- Liveness/readiness, clock, PostgreSQL/storage/connections, worker heartbeat and oldest job.
- Failed/retried/dead-letter notifications and exports; WAL staging/archive continuity.
- DNS/TLS state, unexpected egress, authentication/rate-limit anomalies, container restart.

## Weekly

- Backup/manifest/off-host-copy freshness and key-ID availability.
- Audit checkpoint age/continuity; export cleanup and temporary-retention backlog.
- Active clients, sessions, webhooks, blocked state, and privileged member changes.
- Capacity trend against the verified envelope.

## Monthly and after material change

- Isolated logical restore; scheduled physical/PITR exercise at the approved cadence.
- Purpose-key inventory/expiry/custody and historical public-key availability.
- Dependency/container/scanner advisories, SBOM/license drift, exact image/source binding.
- Registry/migration/ADR/runbook currency and a sample of role/recusal/observer denials.
- Onboarding/support terms, incident contacts, OIDC/provider/client metadata, DNS ownership.

## Quarterly or owner-defined cadence

- Full recovery exercise including declared RPO/RTO observation.
- Access/role/board/AI-observer/accountable-principal review by the secretariat.
- Webhook need and egress policy review; disable unused endpoints.
- Threat model, known limitations, residual client/agent risk, and independent-review plan.
- Regression-net drift audit, including protocol/eval corpus and third-party toolchain.

Each control has a named owner, due date, evidence link/hash, result, exception, and closure
date. Skipped is not passed. An overdue restore, checkpoint, backup, key, or critical
security control closes readiness/release as defined by policy and is escalated—not
backdated or silently waived.

Record the completed control set, omissions, evidence digests, escalations, and next due
dates in the deployment's private operations register.
