# Consecutive checkpoint segments — implementation revision 1

Authority: [the operational completion instruction](operational-completion-instruction-2026-09-08.md).
This is the first implementation unit of the audit-signing recovery work (F8). It does not adopt the old draft's
one-million-event allowance for a business transaction. Ordinary database admission still
refuses new events when 1,000 committed events await signing. The larger atomic-action
fix and explicit recovery after a missed deadline remain separate unfinished work.

The worker signs the next consecutive prefix of at most 1,000 events, using its existing
evidence key and the actual signing time. It repeats until all records that existed before
its final signature are covered, including earlier signatures' own audit events. The final
signature's own event remains uncovered, as before. All existing key, signature, interval,
organization and 15-minute checks remain. The signed format stays version 1.

The database insert guard always assigns two internal checkpoint fields: the actual
PostgreSQL transaction ID and the next audit sequence. At a full backlog, only that
checkpoint's exact matching audit event may use the exception. It must match the instance,
checkpoint, hashes, range, key, origin, transaction and sequence. A copied record, caller
flag, later transaction or ordinary action cannot inherit this allowance. Existing chain
sequence uniqueness makes the assigned sequence single-use. Historical checkpoint rows
have no such authority. These fields are internal enforcement metadata, not signed claims.

The worker holds the audit-head lock through snapshot/sign/commit and catch-up. Other
appenders and signers cannot extend its target while it runs. Each full segment clears
999 net events after its own audit entry. The loop is bounded at 1,002 segments, sufficient
for the supported one-million-event retained backlog including new signer events. This
does not prove a million-event recovery meets the performance gates; qualification still
must measure it. It is not permission for a caller to append a million events. A failure
or reported lease loss rolls back the whole catch-up transaction; no partial success is
reported. Existing worker lease heartbeat and job completion checks remain separate.

The old head-change rejection test now matches the precise error wording "exact next chain
segment". Its stale-evidence refusal remains required; no assertion or threshold is dropped.

Implementation: SQL 0118, the typed schema mirror and core worker signing handler.
Executing cases: `tests/integration/checkpoint-segments.postgres.test.ts`, alongside the
existing checkpoint/backpressure/outage/signing-time/worker/migration and export tests.
Exact executing tests belong in the verification register, not an assumed pass
in this decision. Recent larger backlog fixtures use an isolated owner-only setup; they
do not establish that normal larger business actions are already supported.
