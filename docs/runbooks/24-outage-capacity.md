# 24 — Outage and capacity

**Owners:** deployment administrator; security contact if hostile activity is plausible.
**Purpose:** restore availability without bypassing integrity/authority checks.

1. Declare the incident time and affected surfaces. Distinguish DNS/TLS, edge, server,
   worker, PostgreSQL, storage, clock, OIDC, webhook, and client failures.
2. Preserve logs/metrics and current container/image/volume state. Do not restart repeatedly
   before capturing the first failure.
3. Check `/health/live` and `/health/ready`, container exits/restarts, database connections/
   locks/storage, worker heartbeat/oldest job, clock, export/blob capacity, WAL staging and
   backup freshness. Redact all content/secrets from shared diagnostics.
4. Contain new traffic if integrity, authority, key, clock, migration, storage, or database
   state is uncertain. A live-but-unready instance remains closed.
5. Apply the narrowest reversible repair: restore dependency, free only approved temporary
   ephemera, replace the verified image, or use the recovery runbook. Never delete audit,
   content, evidence, or retained recovery generations to free space.
6. Require readiness, backlog recovery, audit/checkpoint continuity, and synthetic role/
   confirmation/worker tests before reopening.

Capacity alerts should fire before PostgreSQL, blob/export volume, WAL staging, recovery
store, memory, connections, or job age reaches the tested envelope. Scaling beyond the
single-VPS profile requires architecture review. Record timeline, signals, scope, repair,
verification, data-loss assessment, backlog disposition, and follow-up owner.

For an intact history whose signing deadline was missed, use
[the operator audit-signing recovery procedure](29-audit-signing-recovery.md). It records
the delay permanently and keeps ordinary permission checks in force. Do not improvise SQL.

## Read and HTTP request capacity

The server can reject an admitted read with `response_capacity_busy`.
Its fixed message does not disclose the record size or distinguish temporary
occupancy from a projection that cannot fit, a changed observation or an interrupted
request. Retry the same read after a short delay; investigate a persistent refusal
using its nonsecret request reference and server logs. Do not remove canonical
content or loosen authorization to make a response fit.

Native request/body exhaustion returns HTTP 503 `temporarily_unavailable` with
`Retry-After: 1`. Clients should respect that delay and avoid repeated parallel
retries. If a write's outcome is uncertain, inspect its saved result under the usual
retry procedure before resubmitting it.

The process-local allocation budget and the native request limit are separate
controls. Allocation units estimate retained response work; they are not a memory
limit or an RSS guarantee. Database work, runtime memory and the actual deployment
still need capacity qualification. Do not increase those limits or container memory
and record the incident as resolved without reproducing and validating the workload.
See the response memory policy in [known limitations](../KNOWN_LIMITATIONS.md) for the
limits of this control.
