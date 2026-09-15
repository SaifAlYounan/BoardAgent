# ADR 0009: Worker, exports, recovery, and single-VPS deployment

- Status: accepted at Gate 2
- Date: 2026-08-28
- Authority: D2-046 through D2-054

## Context

BoardAgent needs crash-safe background work, bounded outbound behavior, portable evidence,
and recoverability while remaining a simple self-hosted deployment.

## Decision

- Webhooks are optional/off by default, HTTPS-public-only, SSRF/redirect/rebinding checked,
  per-member HMAC authenticated, and carry only a random wake-up class/time (D2-046).
- One immutable image runs separate least-privilege server/worker processes. PostgreSQL
  typed jobs use transactional outbox, leases, heartbeat, retry/dead letter; unsafe clock
  drift suppresses automatic close (D2-047).
- Audit/system exports are asynchronous confirmed jobs with frozen repeatable-read scope,
  encrypted complete manifest, chunk reads, cancellation/deletion, and 24-hour temporary
  artifact lifetime; they never bundle keys/tokens (D2-048).
- Governance/content/audit/consent/evidence retention is unlimited. Soft delete is
  visibility-only; only named operational secrets/ephemera expire (D2-049).
- Production objective is RPO 15 minutes/RTO 4 hours through continuous encrypted WAL,
  daily encrypted base backup off-host, 7 daily/4 weekly/12 monthly generations, and
  quarterly clean-room restore (D2-050).
- Supported deployment is one Linux VPS, one server, one worker, PostgreSQL 18.6 internal
  network, and Caddy/Compose; no serverless or multi-replica profile (D2-051).
- Local dev uses one master secret with domain-separated derivation. Production requires
  distinct database/OAuth/evidence/session/data/backup key sources and rejects placeholders
  or unknown settings (D2-052).
- Logs/metrics use allowlisted, content-free fields and no raw protected identifiers;
  telemetry is off. Break-glass diagnostics are local/time-bounded/audited (D2-053).
- The verified capacity envelope is 25 boards, 1,000 seats, 100 concurrent requests, 100k
  document versions, 1m audit/feed events, 10 MiB content, and the frozen latency/resync
  thresholds; it is not a hyperscale claim (D2-054).

## Consequences and rejected alternatives

The design accepts one-host availability limits, manual key/recovery custody, storage
growth, worker operations, and limited push content. It rejects content-bearing webhooks,
in-process timers, proprietary queues, synchronous large exports, physical governance
purge, local-only untested backups, one production master secret, body-rich logs, serverless,
and unverified scale claims.

Queue, egress, retention, recovery objective, secret custody, topology, observability, or
capacity changes require an ADR, operations proof, and relevant full-net rerun.
