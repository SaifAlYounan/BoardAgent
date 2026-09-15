# Atomic evidence-key retirement and compromise — 9 September 2026

Migration 0131 and `applyKeyLifecycleInTransaction` implement the first database lifecycle
lane: retiring an evidence-signing key or recording its earliest suspected compromise time.
These commands change the database record only. Replacement and the other four key purposes
are explicitly refused until their effects are implemented. No operator CLI, file installation
or restart is supplied by this checkpoint.

The operator prepares a strict request using the previously implemented read-only procedure.
Application hashes its canonical bytes and rechecks its database inventory under the ordered
locks in migration 0130. Active signing stages, closing votes, unfinished signed outcomes,
leased jobs/notifications and running exports cause refusal. Their resolution and emergency
handling remain part of completing the operator procedure.

The database creates an immutable operation bound to its actual transaction, server start,
operator principal and recording time. It changes only retirement/compromise timestamps,
derives the exact audit facts from that change, then requires a matching audit event and
immutable completion receipt. A deferred check refuses the entire commit if completion is
missing or the resulting key differs from the recorded change. This includes unrelated
changes to the file reference, identity or any other key-row field. A failed audit write
rolls back the key change and operation record.

The original key ID, public material, activation time and prior warnings remain. Compromise
time is the operator's earliest suspected time, distinct from the database recording time.
A later report may move the suspicion earlier; it cannot remove the warning or move it later.
Retirement disables further use as a current signer; this database receipt does not prove
that a private file was destroyed or that an already running process stopped.

The `key_lifecycle_changed` event now has its SQL catalog entry and an enforcing trigger.
A matching-looking event without the actual operation is refused. Server and worker roles
cannot invoke the lifecycle function or write its records, even with a claimed bootstrap
flag. Backup has read access for preservation. The operation's key foreign key has an explicit
operator inventory policy; there are now twelve declared key-reference columns.

An exact retry checks the immutable completed operation before checking changed current
state. It returns the original event, hash, timestamps and receipt. A changed request using
the same operation ID is refused. Simultaneous exact retries produce one operation and one
event. Ordinary database updates/deletes of the operation and completion records are refused.
This does not constrain a database owner who deliberately disables enforcement or restores
different database bytes; infrastructure custody remains a separate trust boundary.

Canonicalization stays in the existing TypeScript canonicalizer. The database checks the
actual request-byte hash, rejects duplicate JSON keys and compares the separately retained
inventory bytes as JSON against the complete prepared facts except observation time. The
event's dependency hash names those exact canonical inventory bytes. The retained-material
hash is still a supplied reference; it is not proof of private-file or off-host custody.

`tests/integration/key-lifecycle-apply.postgres.test.ts` executes eleven cases covering real
commit/replay, missing audit/completion rollback, altered and forged audit refusal, immutable
rows, earlier-only compromise history, duplicate JSON fields, runtime role denial, unsupported
purposes, concurrent retries and post-receipt metadata changes. The duplicate-field and
metadata-change defects were reproduced before repair. Two stale test assumptions were also
repaired: the extra declared foreign key and a timestamp expression's parentheses.

The final affected run passed 53 tests across eight files, followed by typecheck and lint.
The audit-chain suite now passes its 137-event catalog check. Three earlier documentation
closure failures remain open; the complete lifecycle, release qualification, native Linux,
deployment and human-agent trials remain unfinished.
