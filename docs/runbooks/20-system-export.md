# 20 — System export

**Owner:** organization admin with deployment/security custody. **Purpose:** create a
bounded encrypted whole-system portability/compliance artifact without bypassing access or
turning export storage into a second live system.

1. Establish the lawful/governance purpose, recipient/custodian, exact scope, retention,
   transfer method, and data KEK custody. Full-system export is high-trust and admin-only.
2. Check readiness, worker health, export ceiling/chunk size, storage capacity, current
   source/image digest, key registration, audit head, and active conflicting work.
3. Call `export_system_data` and personally complete confirmation over the exact scope.
4. Poll `get_export_status`. Queued/processing/failed is not completion. On success, read
   every chunk in order and verify declared total bytes/chunks and encrypted artifact hash.
5. Store the ciphertext and manifest in the approved destination; transfer the KEK through
   a separate channel. Test decryption/structural verification in an isolated environment.
6. Use `delete_export_artifact` only after the custodian confirms the copy and retention
   decision. Use `cancel_export` for a pending export that is no longer authorized.

The export does not grant a recipient governance authority and does not prove client-side
deletion.

## Evidence

Record approval, scope/snapshot/head hashes, key ID, job and artifact IDs,
size/chunk/hash checks, custody transfer, isolated verification, cleanup receipt, and any
failed/cancelled state.
