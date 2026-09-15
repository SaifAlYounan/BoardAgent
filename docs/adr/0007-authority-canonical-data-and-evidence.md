# ADR 0007: Layered authority, canonical data, and evidence

- Status: accepted at Gate 2
- Date: 2026-08-28
- Authority: D2-019 through D2-022, D2-041 through D2-045, D2-058 through D2-060

## Context

A governance system cannot let any handler, scope string, client, database query, or retry
invent authority. Its records and evidence must also remain byte-stable and correctable
without rewriting history.

## Decision

- Scopes are ceilings. Every request rechecks active/current identity, onboarding, role,
  board membership, object state, ACL, and live exclusion; deny wins (D2-019).
- One generated registry and typed policy are backed by composite constraints, distinct
  database principals, transaction-local actor context, and `FORCE ROW LEVEL SECURITY`
  (D2-020).
- Use UUIDv7 internal IDs, random public IDs, RFC 8785/JCS versioned canonical JSON, UTC
  database microseconds, and integer/rational arithmetic (D2-021).
- PostgreSQL 18.6 is authoritative; typed schema plus immutable checksum migrations move
  forward under a fixed advisory lock. Production has no automatic down path (D2-022).
- Audit events form an immutable canonical SHA-256 previous-hash chain, with separate
  Ed25519 checkpoints at the frozen cadence. There is no blockchain/external timestamp
  claim (D2-041).
- Evidence describes what the server observed: resource-fetch preparation/completion and
  feed handoff, never proof of human rendering/reading (D2-042).
- Certificates bind full vote/rule/electorate/tally/consent lineage and use distinct
  authenticated, generic public, and stateless offline verification paths (D2-043).
- Every mutation is idempotent by actor/client/operation/key and request hash; replay never
  reveals a one-time secret (D2-044).
- Snapshot/delta/feed contains entitled metadata, signed cursors, and tombstones; canonical
  content is separately fetched/audited. Search is deterministic PostgreSQL FTS and any
  semantic memory stays client-side (D2-045 and ADR 0005).
- Registries are closed/generated; each mutation has one class, policy, idempotency,
  evidence, and proof. Observer exceptions are enumerated, not inferred (D2-058).
- Terminal/deleted history is corrected by linked superseding records; backup restore is
  disaster recovery, not business undo (D2-059).
- Bootstrap is the sole pre-identity CLI. Online governance stays on the same authority
  path; offline verifiers are read-only; migration/backup roles remain distinct (D2-060).

## Consequences and rejected alternatives

This costs database policy complexity, append serialization, permanent version readers,
and explicit correction cycles. It rejects scope-only checks, application-only visibility,
ad-hoc IDs/JSON/floats, editable migrations, handler-specific idempotency, public full
certificate archives, direct database admin scripts, and repair-in-place.

Any authorization, canonicalization, registry, audit/certificate schema, cursor, correction,
or operator-authority change requires versioned compatibility and the full relevant net.
