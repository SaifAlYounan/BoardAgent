# Atomic audit admission — implementation revision 1

Authority: [the operational completion instruction](operational-completion-instruction-2026-09-08.md).
This is an additive engineering decision. It preserves the frozen files and does not
adopt the earlier proposal's one-million-event allowance for a single business action.

A transaction may begin its ordinary audit effect only while fewer than 1,000 committed
events await signing. Once admitted, the same transaction may complete at most 10,000
audit events, with at most 16 MiB of cumulative canonical payload bytes. Both limits
apply across all append calls. Either limit rolls back the transaction with a permanent
action-size error. A later transaction must wait for signing if the backlog is full.
The existing 10 MiB individual-event limit also remains; this new cumulative limit is
stricter for multiple large events. There is no agent-controlled allowance or runtime
configuration switch to remove the guard.

The choice provides room for the supported 1,000-seat actions and their associated
notice/disposition records, while bounding memory/storage growth before the signer can
run. A meeting, vote opening or minutes publication with 1,000 recipients needs 1,002
events including consent. Replacement and recusal have additional per-act effects;
linked management revisions and retained draft history are not bounded by seat count
alone. The 10,000-event limit is an explicit action-size boundary, not proof that every
possible history-dependent action fits. Do not claim unlimited linked votes, pending
stages or task histories. Do not split a confirmed governance action, omit notices or
silently change its recipients to fit. An installation needing larger indivisible work
requires a tested capacity revision, including count/byte limits and signing performance.

SQL0119 stores admission coordination on the protected audit head. The actual xid8
transaction ID and database server start time identify the allowance. Runtime roles
cannot update these fields. A copied caller setting, another transaction or stale
metadata from a prior server incarnation cannot carry the allowance forward. The
existing head lock serializes admission and signing. Statement/savepoint/transaction
rollback restores the allowance with the records. Genuine checkpoint attestation remains
the narrowly checked SQL0118 exception; it cannot admit ordinary work against full debt.
Checkpoint segments remain at most 1,000 events and the 15-minute limit remains unchanged.

The MCP surface distinguishes retryable signing backlog (`audit_checkpoint_capacity`)
from permanent action size (`audit_transaction_capacity`). Only the exact SQLSTATE and
constraint pair maps to each message; unrelated database errors stay generic. A lost
reply still requires checking the saved result before retry. A failed final commit may
leave previously saved preparation records; do not tell the user that nothing was saved.

Verification pointers: `audit-atomic-admission.postgres.test.ts` covers separate append
calls, exact count, byte limit, savepoint refund, runtime metadata denial, competing
transactions and restored coordination state. Surface meeting/vote/minutes cases verify
actual confirmation, all 1,000 notices and subsequent signed evidence. Existing vote,
recusal, management, consent, checkpoint, backup/export and migration cases remain in the
affected net. The verification register records the executing tests; this
decision itself is not qualification, missed-deadline recovery or deployment approval.

The larger vote case also exposed a separate pre-existing defect: SQL0011's generic RLS
policy skipped `wizard_steps`, which has no organization column. SQL0061 granted INSERT
but provided no applicable policy. SQL0120 permits only the live authorized secretary's
own final step on an unexpired, ready vote draft in their active board. It adds no read,
update or delete access. The affected vote surface tests now use `boardagent_server`;
earlier owner-role fixtures did not establish this production boundary. Dedicated tests
retain other-user, wrong-board, nonsecretary, wrong-draft/state and immutability refusals.

The export regression also found that SQL0032 serialized every checkpoint column. SQL0118's
new internal attestation fields therefore entered a strict v1 export and broke offline
verification. SQL0121 explicitly projects the eleven existing published fields. It preserves
scope checks, evidence bytes and the offline schema; unknown fields are not newly accepted.
The export transaction test now checks every exported row's exact field set as well as
actual encrypted export decryption and offline verification.
