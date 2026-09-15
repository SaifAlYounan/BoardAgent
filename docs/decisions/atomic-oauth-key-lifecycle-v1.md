# Changing connection-signing keys — 9 September 2026

Migration 0133 adds OAuth key replacement, retirement and compromise reporting to the
existing operator transaction. It preserves the earlier evidence-key behavior and old
migration bytes. Exact requests, locked inventories, immutable audit/completion records
and deferred commit checks remain required.

Routine replacement retires the old signer and registers a distinct P-256 public identity.
Unexpired access tokens signed before retirement remain valid. Refresh must use the new
signer. Historical public keys remain available to verify old signatures. SQL rejects
renamed copies of the same cryptographic material, private or extra public-key fields,
incorrect fingerprints and inconsistent identifiers.

Reporting a signing key compromised revokes every active refresh family with a retained
access-token record signed by that key. This includes a family already renewed under a
new signer: all its tokens lose authority. Unrelated families continue working. Browser
identity sessions remain separate; signing-key compromise alone does not revoke those
sessions or delete a person's passkeys.

Each affected family has an immutable operation-bound before/after digest. The database
derives the allowed change and checks the actual complete rows, affected count, audit and
receipt before commit. Extra unrelated families and post-receipt alterations roll back
the operation. Runtime roles cannot write this ledger. Exact completed retries return
the original receipt without repeating revocation.

The expanded test first found a circular row-policy dependency preventing legitimate
family locking. The corrected operator policy permits the lock under the actual current
operation and permits the update only with its effect record. A rollback test now also
asserts that it reached a successful receipt before injecting its intended fault.

The final affected run passed 69 tests across eight files plus typecheck and lint.
`tests/integration/oauth-key-lifecycle.postgres.test.ts` has seven cases covering the
actual database transition, access-context resolution, refresh rotation, unrelated-family
continuity, rollback and denied writes. These use explicit synthetic authorized-actor
fixtures; they are not personal enrollment or released-client acceptance evidence.

Private-file possession, staged installation, runtime fencing, restart and operator CLI
remain unfinished. Public identity validation does not prove possession of the matching
private file. Browser, data and backup key transitions, full/native qualification and
deployment remain required work. Existing transaction retries handle serialization and
deadlock errors; that is not evidence that running services have been drained for maintenance.
