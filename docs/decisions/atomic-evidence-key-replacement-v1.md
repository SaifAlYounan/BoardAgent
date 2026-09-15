# Replacing an evidence signer — 9 September 2026

Migration 0132 extends the atomic lifecycle with evidence-signing key replacement. The same
strict request, locked inventory comparison, real operator transaction, audit event,
completion receipt and deferred commit checks apply. The previous migration is unchanged.
OAuth, browser-session, data-encryption and backup key transitions remain unimplemented.

Replacement creates a distinct key record and retires the previous signer in one transaction.
An already retired or compromised signer can be replaced while preserving its original
retirement and compromise times. A historical key cannot be replaced if another current
signer already exists. Competing replacements produce one current signer; the losing request
must be prepared again for the actual current key.

SQL independently checks the exact public Ed25519 fields, canonical base64url coordinate,
public-material fingerprint, derived key identifier and distinct identity/material. Private
or extra JWK fields, mismatched hashes and unnormalized file references are refused. The
operator must still check that the actual protected private file matches this public identity
before exposing a finished maintenance command. A public record is not private-file custody.

The immutable operation records the replacement key through a deferred foreign key. The
existing explicit operator inventory policy includes this new reference, bringing the current
declared key-reference inventory to thirteen columns. Completion checks the complete old key
row, allowing only its declared lifecycle timestamps to change, and the complete new key row,
including its file reference and creation time. A discrepancy rolls back both key changes,
the operation and its audit receipt.

`tests/integration/key-lifecycle-replacement.postgres.test.ts` executes five cases. The main
case creates an actual checkpoint with the original key, replaces that key, refuses a new
checkpoint using the retired signer, creates a checkpoint using the replacement private key,
verifies the persisted audit chain and checks that the original checkpoint row is unchanged.
Other cases cover prior retirement/compromise warnings, replacement-row changes after the
receipt, competing replacements, stale historical targets and malformed/reused/private
replacement fields passed directly to the database entry point.

The initial unsupported-operation failure is preserved. The first implementation passed
twelve tests across two files plus typecheck/lint. The expanded affected run passed fifty
tests across seven files plus typecheck/lint. These prove local database and signing behavior,
not service restart, private-file installation, full qualification or deployment. The remaining
four key types, operator inspect/CLI, retained files and backup/WAL inventory, runtime fencing,
staged installation and restore proof remain required work.
