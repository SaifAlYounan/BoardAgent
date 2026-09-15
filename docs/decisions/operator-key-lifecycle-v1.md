# Operator key commands and retained-file inspection — 9 September 2026

This implements the command portion of F7 under the delegated operational-completion
instruction. `scripts/src/operator.ts` now dispatches `key-lifecycle` to
`scripts/src/key-lifecycle-operator.ts`. Company administrators, secretaries and agents gain
no maintenance permission. Every database read/write uses the existing actual migrator role,
bootstrap scope, serializable transaction and exact instance/organization identity.

The supported compiled commands are `inspect [OPERATION_ID RECEIPT.json]`,
`prepare PLAN.json REQUEST.json`, and `apply REQUEST.json SHA256 RECEIPT.json`.
Preparation creates a fresh private key at a new explicit path when replacement is requested;
it never overwrites an existing file. Re-preparation may reuse that same unregistered staged
file. No database key changes during preparation. The strict request contains the current
key/work/dependency snapshot, thirty-minute expiry, proposed public identity and a hash of
the actual retained-material inventory. The proposal retains the complete inventory and plan.
The current field-by-field procedure is runbook 08.

`scripts/src/operator-key-files.ts` validates physical absolute paths and root/current-user
owned directories, with an explicit root-owned sticky-temporary-directory exception.
Symlinks, hardlinks, nonregular files, unsafe modes, untrusted ownership and changing inodes
are refused. Reads open once with NOFOLLOW/NONBLOCK and bound bytes before parsing. Private
keys are at most 64 KiB; proposal/manifest reads are at most 16 MiB. New key publication uses
an exclusive temporary file, fsync, link without overwrite, unlink and directory fsync.
No protection against host root or the trusted owning operator replacing directories is claimed.

OAuth P-256 public coordinates must match the actual private scalar, calculated with ECDH.
Evidence keys must parse as private Ed25519 keys. Symmetric values are exactly 32 raw bytes or
canonical 43-character base64url, optionally followed by one newline. Fingerprints use actual
normalized material, independently of its purpose label. Replacement is checked against
available keys and known historical fingerprints; deriving both legacy browser/data IDs from
the new raw value also detects reuse when an old private file is unavailable. Public-only
projections and hashes are serialized; private bytes are not. Owned temporary byte buffers
are erased, without promising perfect erasure of JavaScript strings or native key objects.

The plan names every registered key ID. Explicit `file:null` records unavailable private
material. This is permitted for incident containment, already compromised keys and retired
OAuth/evidence/browser keys whose historical verification does not require private material.
Ordinary replacement refuses missing required decryption keys. A lost private file must not
prevent recording compromise and revoking the affected authority. Missing material remains
visible in the immutable inventory; it is not renamed as verified custody or repaired data.
After containment, replacement can issue a distinct new key while preserving that history.

`scripts/src/key-maintenance-inventory.ts` streams all actual files under explicit,
non-overlapping local recovery roots. It records paths, lengths and SHA-256; checks directory
and file stability; parses supported logical/base/WAL/export manifests; checks actual adjacent
ciphertext/chunks, IDs, installation and available full fingerprints. Export locators follow
the real store format and its canonical chunk-set digest. Legacy manifests remain explicitly
ID-only. Retired base-manifest tombstones are metadata-only, not restorable artifacts.
Unknown reserved manifest schemas refuse. Other retained files are hashed without pretending
to interpret them. Limits are 64 roots,20,000 files,depth32,8TiBtotal and ten minutes; hitting a
limit refuses instead of silently truncating. These are local operational bounds, not native
performance claims at the maximum.

Local roots are an explicit inventory scope. An empty list does not prove that no other
backups exist. Off-host custody remains `not_verified`; a custody reference is attribution,
not a fabricated witness or successful restore. Hash validation is not authenticated
plaintext decryption or PostgreSQL restore. Full retained-generation qualification remains.

Apply validates the exact digest and installation, then first checks for an already committed
operation. Exact completed replay and read-only inspection need no private files or current
key-state revalidation. For a new operation the complete file/material inventory is rebuilt
and must match. SQL0137 refuses while production server/worker leases or guarded in-flight
transactions remain. The data-key branch supplies the actual AES rewrap adapter; missing
required old material/failed authentication aborts the transaction. Database operation,
actual effects, audit and completion commit together. Pre-existing receipt collisions or
unsafe output parents refuse before the database change. Published receipts never overwrite
other evidence. Interrupted/uncertain application reports the original operation ID and
requires its inspection before a different proposal is attempted.

Database completion deliberately reports runtime installation as pending. The command does
not change mounted active files, secret-volume permissions, service configuration or the
VPS. Existing secret initialization overwrites fixed filenames and must not be reused for
rotation. Production completion still requires versioned role-separated installation,
retained-data-key manifests, stopped offline backup/WAL writers, restart/readiness and old/new
logical/physical/WAL restore proof. Runtime SQL leases currently cover server/worker, not an
offline standalone WAL archiver. No broader process-fencing claim is made here.

Executing tests: `tests/unit/operator-key-files.test.ts`,
`tests/unit/key-maintenance-inventory.test.ts`, the actual store/retention cases in
`tests/unit/export-artifact-store.test.ts` and `tests/unit/base-backup-retention.test.ts`, and
sixteen cases in `tests/integration/key-lifecycle-operator.postgres.test.ts`. They exercise
actual compiled command dispatch, all five replacements, retirement/compromise, actual runtime
principal refusal, server exclusion, stale files, receipt collisions, concurrent retries,
lost-file incident/replacement and real database webhook rewrapping. These automated fixtures
do not perform human enrollment or claim commissioned external security review.
