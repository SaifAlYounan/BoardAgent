# Audit recovery authority and retained findings — 9 September 2026

This additive implementation follows the actual instruction in
`operational-completion-instruction-2026-09-08.md` and the separate recovery format in
`audit-recovery-format-v1.md`. It changes no frozen planning or historical migration bytes.
This checkpoint implements the database engine and evidence propagation. The usable
operator CLI, full-backlog upgrade and actual encrypted recovery operations remain required
before shipping the procedure. No new VPS activation or human acceptance is claimed.

## Authority and failure behavior

SQL0123 records an immutable operator request, exact original audit head/range, evidence
key, reason, operator reference and thirty-minute lifetime. Preparation gives no write
permission. A serializable migrator transaction must lock and recheck the actual head,
key and request. The authorization records the actual database transaction, server start
and database principal. Server, worker and backup principals cannot create it, including
by changing a transaction-scope setting. No agent tool grants this operator authority.

SQL0124 accepts the separately signed recovery format only in that same operator
transaction. Each segment contains at most 1,000 events and an exact positive historical
miss. Recent tail segments use the ordinary checkpoint format. Original events remain
unchanged. Matching CLI audit attestations and the completion record are mandatory;
a deferred constraint prevents partial completion or further unaccounted audit writes.
Signer failure, cancellation, failed final audit and stale proposals roll back the entire
transaction. An exact retry after a lost response returns the immutable committed receipt;
a changed request refuses. Concurrent attempts cannot produce two competing recoveries.

The original ordinary fifteen-minute checkpoint rule and atomic admission limits remain.
A recovery signature by itself does not authorize a database exception. Recovery engine
code is `lib/db/src/transactions/audit-recovery.ts`; full stored verification remains in
`checkpoints.ts` and `audit-evidence-stream.ts`.

## Evidence leaving the database

One original signed first recovery checkpoint per completed incident forms the nonempty,
ordered `auditRecoveryEvidence` set. It includes the exact original request, actual delayed
signing time and missed interval. Full persisted verification validates retained request
and completion bindings, signatures and the entire event chain before returning that set.
Its warning remains after subsequent ordinary signing has resumed.

Recovered histories use explicit export-snapshot.v2, audit-export-attestation.v2,
backup-receipt.v2 and restore-receipt.v2 formats. Ordinary v1 variants remain strict and
unchanged. Even a scoped system export without audit records contains the recovery set;
a signed audit export binds it together with the exact snapshot and component hashes.
Offline verification uses independently supplied trusted public keys and requires matching
findings in the snapshot context, signed attestation and checkpoint component. A subset of
events outside the original incident still reports the finding. An older reader cannot
silently interpret the new format as ordinary v1 evidence.

Restored full-chain verification requires the source manifest's set to equal the restored
history's set. SQL0125 binds stored backup findings to completed recoveries inside the
original captured audit head, and restored receipts to the immutable source backup receipt.
Later recoveries do not retrospectively change older backup findings. Worker receipt-health
inspection understands both versions. Recomputed outer hashes do not permit an omitted,
altered or downgraded finding at the same retained boundary.

These are server-attested records. They do not establish an independent timestamp, an
external operator signature, human understanding or immunity from a compromised trusted
signing key. Incident reasons and operator references must contain no secret material.

## Executing cases and remaining proof

SR-028/049/067–070/082 coverage includes:

- `audit-recovery-authority.postgres.test.ts`: actual runtime denials, unfinished commit,
  request bindings and a valid signed copy of completed authority in a later transaction.
- `audit-recovery-apply.postgres.test.ts`: stale head/key, wrong signing key, all-or-nothing
  segment failure, cancellation, final audit failure, competing attempts and exact retry.
- `audit-recovery-propagation.postgres.test.ts`: encrypted scoped audit/system exports,
  independent offline verification, downgrade/tamper refusal and stored backup findings.
- `audit-recovery-restore.postgres.test.ts`: isolated PostgreSQL clone, retained findings,
  manifest downgrade/tamper refusal, immutable backup/restore lineage and health inspection.

The clone case is not an actual pg_dump/pg_restore proof. The operator commands and actual
encrypted backup/restore must be tested before closure. F7 key lifecycle, complete local
and native qualification, independent review and synthetic commissioning remain. A case
name or this decision document is not itself a passing result.
