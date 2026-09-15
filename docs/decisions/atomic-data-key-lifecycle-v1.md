# Atomic data-key maintenance — 9 September 2026

Implements the delegated completion instruction in
[operational-completion-instruction-2026-09-08.md](operational-completion-instruction-2026-09-08.md).
Original plans and historical migrations remain unchanged. SQL0136 extends the existing
operator transaction and completion mechanism; it grants no agent or company administrator
infrastructure authority. This checkpoint does not complete production key-file installation,
custody, service fencing, full qualification or deployment.

For the operator and secretary, the intended consequences are:

| Maintenance                | Existing authenticator codes                                                                                                                                                               | Notification connections                                                                                                                                                  | Protected contact records                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Replace the encryption key | Working TOTP credentials keep their original encrypted bytes and use retained decryption material. Unfinished enrollment is cancelled so it can start with the current key.                | Active endpoints and external secrets are authenticated and re-encrypted under the replacement key. Their values, subscriptions and verification evidence stay unchanged. | Retain the original encrypted bytes and key reference.                    |
| Retire without replacement | Preserve active TOTP and its required retained key; cancel unfinished enrollment. No new encryption writer is available.                                                                   | Disable connections using the retired key, preserving their encrypted history.                                                                                            | Preserve the original records and required retained key.                  |
| Report compromise          | Disable active and unfinished TOTP using the exposed key. Revoke existing sessions, refresh families and pending approvals for affected members; preserve passkeys for supported recovery. | Disable exposed connections, including those whose unchanged external secret was re-encrypted under a later key.                                                          | Revoke their trusted status while retaining the exact encrypted evidence. |

A replacement does not change a person's TOTP seed. A compromise cannot make an exposed seed
safe: fresh TOTP enrollment or the existing passkey ceremony is required. Session history does
not identify its authentication method. Containment therefore includes any member with a
retained credential tied to the compromised key, including previously replaced or disabled
credentials. Other members' sessions and factors remain outside the incident. Exact replay of
a completed maintenance operation preserves logins created afterward.

Re-encryption preserves a notification's external secret. Its immutable lineage records the
actual operation, webhook, old generation, original/replacement key identities, endpoint and
secret fingerprints, ciphertext fingerprints and complete before/after row digests. A later
incident involving an ancestor key still finds an unchanged secret. A real external-secret
rotation changes its fingerprint and ends that old-secret exposure; merely relabelling a key
does not. Historical ordinary retirement with current successor connections is refused with
a specific explanation; retain the old key or use the compromise procedure when appropriate.

The application has no active protected-contact encryption writer in v1. This change does not
invent an encryption format or claim a contact re-enrollment ceremony exists. Routine changes
retain those bytes; incident containment records each exact revoked contact in its immutable
operation-bound ledger. Its count comes from the prepared contact inventory, and completion
checks every resulting row. The existing event's dependency digest binds that inventory.

`applyKeyLifecycleInTransaction` accepts an operator encryption port separately from the
canonical request. The concrete `Aes256GcmWebhookSecurity.rewrapStoredMaterial` authenticates
both old ciphertexts and their organization/member/webhook/key bindings, checks recorded
plaintext fingerprints, rejects identical or renamed raw key material, and encrypts using
the new key. It does not contact the notification endpoint or return plaintext. The database
reader returns at most 128 encrypted connections per batch to the actual operator transaction.
Private keys never enter SQL, audit events or request manifests.

PostgreSQL enforces the operation, target, generation, allowed changed fields and exact row
projections. It cannot authenticate AES ciphertext without the private key. Cryptographic
validation is performed by the concrete operator adapter; private-file validation and secure
installation remain required. A custom trusted operator port is not independent cryptographic
proof. Missing private material, failed decryption, missing effects/audit/completion, unrelated
effects and post-receipt row changes must roll back the entire transaction.

Four additional immutable ledgers cover TOTP, contacts, webhook re-encryption and disablement.
The existing browser/family ledgers cover member-scoped revocations. Their rows bind the actual
operator transaction and server instance; runtime/worker/backup roles cannot write them or call
the private re-encryption functions. Two new key foreign-key columns have explicit inventory
coverage, giving fifteen declared key-reference columns. The existing sixteen work groups are
preserved, with purpose-aware member and historical-webhook selection.

Executing coverage:

- `tests/unit/webhook-rewrap.test.ts`: authenticated value preservation, wrong bindings/hashes,
  altered ciphertext, missing old keys and renamed identical raw material.
- `tests/integration/data-key-lifecycle.postgres.test.ts`: thirteen cases covering the three
  operations, active/pending TOTP, actual notification re-encryption across two replacements,
  historical compromise, genuine external-secret rotation, contact retention/disposition,
  exact retry, unavailable/failed private decryption, runtime denial, unrelated-effect refusal,
  missing-completion rollback and full-row checks after a receipt.
- `tests/protocol/data-key-maintenance.postgres.test.ts`: actual TOTP enrollment and HTTPS
  passkey/OAuth sessions, incident and replacement, application restart, old access/code/refresh
  refusal, unrelated client continuity, unchanged passkeys, fresh login and harmless replay.
  Private files and injected matching runtime keys belong to the synthetic fixture; this is
  not the production installer or a person's acceptance test.

The first HTTPS check used an incomplete raw MCP request for the unaffected client and received
406; the corrected test uses the real SDK and proves `whoami`. Local affected tests are evidence
for these paths, not full/native qualification. The production command, actual service fence,
retained-file/backup/WAL custody and pre/post-generation restore proof remain next.
