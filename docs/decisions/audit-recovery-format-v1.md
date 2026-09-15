# Audit recovery format — primitive implementation

Authority: operational-completion-instruction-2026-09-08.md. This implements the signed
format prerequisite for explicit recovery. It does not yet grant database authority,
implement an operator command, recover a stored chain or activate a new wire format.

`lib/audit/src/recovery-checkpoint.ts` defines a strict
`boardagent.audit-recovery-request.v1`: recovery identity, instance/organization, exact
uncovered first/last sequence and endpoint hashes, evidence-key identity, first uncovered
event time, preparation/expiry, required operator reference and reason. A request covers
at most one million retained events and expires exactly thirty minutes after preparation.
It must describe a range already beyond the ordinary fifteen-minute signing deadline.
The range bound is not an ordinary action allowance or a performance claim.

`boardagent.audit.recovery-checkpoint.v1` binds that complete request and its canonical
SHA-256 into each recovery signature. A segment stays within the authorized original
range and the existing 1,000-event checkpoint limit. Its first covered event time and
positive missed duration are explicit to microsecond precision. Its instance, key,
request digest, endpoint hashes when applicable and actual issue time must agree.
Issuance is at or after preparation and strictly before expiry. Invalid calendar dates,
omitted/extra fields, invalid bounds, contradictory findings and changed hashes fail.

The operator reference is request metadata; parsing or signing it does not prove that
an operator acted. The subsequent database/CLI unit must enforce actual authorization,
read timestamps/hashes from retained records and verify the full chain. An interior
segment's endpoint/timestamp values also require that stored-chain verification; the
format alone cannot establish them. A valid signature does not establish compliance
with the missed deadline or an external time of existence.

Signing requires an Ed25519 private key; verification requires a public key and canonical
64-byte base64url signature encoding. The existing v1 reader remains strict and rejects
this separate format. Production database, worker, export, backup and offline paths have
not been changed to accept recovery evidence. Do not enable acceptance before protected
operator authorization and permanent warning propagation are implemented together.

Tests: `tests/unit/audit-recovery-checkpoint.test.ts`, ordinary checkpoint/offline tests
and `tests/integration/checkpoint-outage-boundary.postgres.test.ts`. The first new-suite
attempt failed collection because this module did not exist: zero tests executed, not
proof of a product defect.
