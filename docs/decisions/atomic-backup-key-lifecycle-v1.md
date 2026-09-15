# Backup key maintenance — 9 September 2026

Migration 0135 adds backup key replacement, retirement and compromise reporting to the
protected operator lifecycle. Historical key identities, fingerprints, activation times
and existing retirement/compromise warnings remain intact. A distinct replacement becomes
the only current backup writer. The existing active-key lookup refuses a retired or
compromised writer; initialization is still unable to replace one silently.

The replacement must have the exact `backup-<key UUID>` identifier, A256GCM algorithm,
no public JWK and a `sha256:<full fingerprint>` locator matching its declared material.
SQL rejects material fingerprints already registered for a backup key, including retired
keys. The operator file procedure must still verify the actual protected bytes and prevent
reuse across other purposes; database metadata alone cannot prove custody.

The existing immutable operation, audit, completion and complete-key-row checks apply.
Missing audit/completion rolls back both old and replacement key changes. Exact completed
retries return the original receipt. Reporting compromise preserves the historical key;
it does not erase archives or pretend that exposed plaintext becomes confidential again.

`tests/integration/backup-key-lifecycle.postgres.test.ts` checks all three operations,
old warning preservation, active writer selection, malformed/reused identities, rollback
and exact replay. It also uses the real backup artifact encryption/decryption functions
and immutable registration-receipt writer: both old and new encrypted artifacts decrypt
with their own keys; a wrong key fails; old artifact and receipt bytes remain unchanged.
Those artifacts contain explicit synthetic text. They are not a PostgreSQL restore test
or evidence of off-host retention, WAL coverage, protected custody or deployment readiness.

The initial run had three unsupported-operation failures and one refusal case passing.
The first implementation passed twenty-nine tests across four files plus typecheck/lint.
Data key transitions, the operator command/file procedure, service fencing, complete
backup/WAL inventory and actual old/new database restore qualification remain required.
