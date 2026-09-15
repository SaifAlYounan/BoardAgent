# Installing recovery support when signing debt is full — 9 September 2026

The actual completion instruction delegates this repair to the implementer. SQL0126 and
`lib/db/src/migrate.ts` solve a reproduced deadlock in the maintenance procedure: the old
runner appended a migration audit event before loading the next migration, while a full
unsigned audit queue refused the event needed to install recovery support.

Recovery-aware bundles contain `0126_migration_audit_admission.sql`. For these bundles,
after initial roles and ownership through 0025, pending DDL is applied in one transaction
before each new ledger entry and its exact audit receipt. Either the whole pending upgrade
commits or none of it does. Older bundles retain their established per-file behavior.
Existing migration checksums, order checks, advisory lock and compatibility refusal remain.
No historical SQL or ledger field is rewritten. A failed upgrade remains eligible for the
same unchanged command after the underlying fault is corrected.

SQL0126 records the actual transaction, server start and next audit sequence on each new
bootstrapped ledger entry. Runtime roles cannot insert or update ledger metadata. Its
single matching `migration_applied` event may cross full signing debt; copying an older
receipt or changing a scope setting cannot. A deferred constraint forbids committing an
unaudited new migration. Bounds on version, filename and build identifier keep receipts
small. This exception does not establish ordinary business admission or restore readiness.
The operator must then perform the documented signing-outage recovery.

The executing cases are `tests/integration/audit-recovery-upgrade.postgres.test.ts`:
actual old 121 schema and 1,000 aged events; upgrade preserving every original byte and
original ledger field; exact audit receipts; ordinary runtime refusal; completed recovery;
failed later DDL rollback; competing upgrades; missing receipt and runtime ledger-write
refusal. Existing migration/catalog/administrative upgrade cases remain part of validation.
Initial two tests failed at the old capacity guard. This document alone does not
establish a pass or authorize deployment.
