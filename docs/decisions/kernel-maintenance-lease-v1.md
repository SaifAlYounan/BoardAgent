# Linux process exclusion for key maintenance — 9 September 2026

The completion instruction authorizes this production implementation of SR-028/068/082
and TH-40. It supplements SQL0137; committed migrations and authority rules are unchanged.

Production server/worker entrypoints, logical/base-backup commands, continuous/one-shot
WAL archive commands and audit-recovery signing hold a shared Linux kernel file lock.
Key-lifecycle apply acquires its exclusive counterpart before parsing a new request.
A running process keeps the lock through its operation and shutdown, including database
or network loss. The operating system releases the lock on process exit. A process killed
while holding it does not release another process's independent shared lock.

The Compose initializer creates one empty root-owned inode, group 10001, mode 0440, inside
a root-owned mode 0750 coordination volume. Every production participant mounts that same
volume read-only. Initialization verifies an existing inode; it never replaces it. Unsafe
entries, links, ownership, mode, size or multiple hardlinks refuse. Interrupted creation
may require operator inspection; startup must not silently replace a suspect lock.

The Node helper opens the inode once without following links, verifies all physical parent
directories and passes a duplicate file descriptor to the pinned image's existing BusyBox
flock. Linux associates this lock with the shared open-file description. The parent retains
its descriptor after the flock helper exits. It rechecks identity and metadata before
accepting the lease. No new package, image capability or secret is introduced.

Production WAL startup additionally checks its actual key bytes and preserved receipt
against the current database registry using the backup principal. A retired, compromised
or mismatched key cannot start even if its historical receipt is internally valid. A writer
that already passed startup can continue through a database outage; its kernel lease still
excludes key maintenance. The recovery Compose profile supplies the backup database URL.

These controls apply to the supported single Linux host using the shared local Docker
volume. Do not substitute NFS, separate lock volumes, separate Docker hosts or a copied
inode. Applications cannot replace the inode. A trusted host-root or database-owner operator
can intentionally defeat deployment controls; no protection against that operator is
claimed. Custom embedding and test-mode primitives are not production entrypoints.

The production apply command now requires stopped writers even for an already completed
request. Use read-only `key-lifecycle inspect OPERATION_ID RECEIPT.json` to recover its
original result while services run. Low-level completed SQL retries retain their existing
semantics; this does not authorize bypassing the production wrapper.

Executing coverage:

- `tests/operations/kernel-maintenance-lease.spec.ts`: actual Linux shared/exclusive
  processes, forced death, application replacement denial and unsafe path/inode refusals.
- `tests/operations/production-compose.spec.ts`: real cold start, separated credentials,
  server/worker readiness and maintenance refusal until both stop.
- `tests/operations/recovered-audit-backup.spec.ts`: actual encrypted PostgreSQL backup and
  restore, production WAL process, network loss with continuing maintenance refusal,
  orderly stop and restart refusal for a retired key whose old receipt remains valid.
- `tests/operations/physical-backup-restore.spec.ts`: actual dump/restore invariants and
  corruption refusal through the production wrapper. Disposable recovery fixtures create
  their own coordination volume using the actual Compose initializer.

Versioned key-file installation, retained-generation restoration, complete/native release
qualification, independent review and synthetic deployment remain separate requirements.
