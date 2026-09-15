# Preparing a key change — 9 September 2026

The operator prepares an exact change before applying it. Preparation reads the current
installation, key identity, audit head, declared database dependencies and work in progress
in one serializable read-only transaction. It returns a strict request and its canonical
SHA-256 hash. It changes no key, account, audit record or file.

`prepareKeyLifecycleInTransaction` in `lib/db/src/transactions/key-lifecycle-request.ts`
implements this database step. The request covers replacement, retirement and compromise
for all five key purposes. Its validity window is thirty minutes from the database
observation, preserving microseconds. Expiry limits how long an unattended proposal can
remain usable; the eventual apply operation must also recheck every relevant current fact.
Fresh preparation is required after expiry or a relevant change.

The replacement must have a different identity and actual public key. OAuth fingerprints
hash canonical JSON containing only `crv`, `kty`, `x` and `y`; evidence fingerprints contain
only `crv`, `kty` and `x`. Fields such as `kid`, `alg` and `use` do not change the cryptographic
material. Renaming an unchanged OAuth key is therefore refused. Coordinates must be
canonical base64url and the public key must parse as the expected curve. Private and extra
JWK fields are rejected. Symmetric fingerprints refer to SHA-256 of the raw 32-byte key;
database preparation alone cannot verify those supplied fingerprints against private files.

Earlier retirement and compromise times cannot be in the future. A new compromise report
may move the suspected time earlier, never later. Replacement can follow retirement or
compromise without erasing either historical warning. The apply operation must additionally
refuse a stale target when a different current key already exists.

Migration 0129 shares the existing inventory implementation between read-only inspection
and an eventual writing transaction. The public inspection wrappers still require read-only
mode. Both shared snapshot functions require the operator role, bootstrap scope, serializable
isolation and exact installation/organization/key. Server, worker and backup roles cannot
execute them, even with a claimed bootstrap flag. Unknown dependency tables still cause
refusal; inventory access does not grant key-changing authority.

This request is an internal prerequisite, not a finished operator procedure. The supplied
retained-material hash is not proof that backup files exist or that someone holds the keys.
The operator command must inspect actual protected files, retained generations and backup/WAL
manifests before application. Protected atomic application, immutable retry receipts,
revocation, rewrap lineage, installation and restart checks remain separate unfinished work.

Executing tests are `tests/integration/key-lifecycle-preparation.postgres.test.ts` and
`tests/integration/key-maintenance-snapshot.postgres.test.ts`. They cover all fifteen
purpose/operation combinations, unchanged database/audit records, malformed identities and
public projections, expiry and historical timestamps, changed queued work, shared snapshots
and actual denied database roles. The unchanged-key rename and future-history defects were
reproduced before repair. After restoring the stopped local Docker test database, the affected
suite passed 41 tests across seven files, followed by typecheck and lint. The earlier run's
32 connection failures remain preserved as environment failures. This is focused local
evidence; it does not qualify the full release or any deployment.
