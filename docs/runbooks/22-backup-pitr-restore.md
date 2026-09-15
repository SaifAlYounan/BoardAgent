# 22 — Backup, PITR, and restore

**Owners:** deployment administrator and recovery custodian, with two-person observation.
**Purpose:** produce encrypted logical/physical recovery material, continuous WAL custody,
and a verified restore receipt outside the live failure domain.

## Required recovery inputs

- exact source application image digest (`sha256:...`);
- registered backup-key UUID and matching 32-byte backup KEK file;
- exact organization UUID and protected key-registration receipt for physical backup/WAL;
- `boardagent_backup_login` connection for snapshot/base-backup authority;
- a distinct receipt-writer connection for recording completion/restore evidence;
- an off-host mounted recovery directory owned by the container operator process
  (`10001:10001` in the documented non-remapped Docker profile), with mode `0700`;
- enough space for one full generation plus WAL and verification working space.

Provide password-free database URLs plus owner-only files through the operator's private
environment: `BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE` for the backup principal,
`BOARDAGENT_RECEIPT_DATABASE_PASSWORD_FILE` for the distinct receipt writer, and
`BOARDAGENT_RESTORE_DATABASE_PASSWORD_FILE` for the isolated restore target. Do not put
password-bearing URLs in source control, general logs, or shared command history.
Production backup and receipt URLs must name distinct database principals.

Native Linux bind mounts preserve numeric ownership. Provision a new, dedicated recovery
root and its `wal`, `base`, and isolated restore subdirectories with owner `10001:10001`
and mode `0700` before starting the recovery overlay. Keep the input KEK/password files
in separate administrator custody for the root one-shot secret-copy ceremony. Do not
change ownership recursively on an existing backup collection, and do not use `0777` or
make manifests/ciphertext world-readable for convenient inspection. Inspect through the
authorized recovery principal or administrator. A user-namespace-remapped installation
must establish its corresponding host UID mapping before use.

Commission a fresh database without the recovery overlay first. Enabling archiving before
bootstrap and key registration creates a dependency cycle: initialization shutdown can
wait for an archiver whose registration does not exist yet. Readiness checks must connect
over TCP to the final PostgreSQL server; the temporary initialization socket is insufficient.

## Logical backup and restore proof

Before the first backup, generate a separate random 32-byte backup KEK under the recovery
custodian's control. Use an owner-only regular file and preserve an independently held
encrypted recovery copy; never reuse an application key. Register its nonsecret identity
using the trusted migrator's password-file connection after instance bootstrap:

```sh
node scripts/dist/operator.js register-backup-key
```

Provide `BOARDAGENT_ENV`, `BOARDAGENT_DATABASE_URL`, the migrator's
`BOARDAGENT_DATABASE_PASSWORD_FILE`, the exact `BOARDAGENT_ORGANIZATION_ID`, a new UUIDv7
`BOARDAGENT_BACKUP_KEY_ID`, `BOARDAGENT_BACKUP_KEK_FILE`, and
`BOARDAGENT_BACKUP_KEY_RECEIPT_DIRECTORY` through the private operator
environment. This command needs no application signing or data keys. It reads the KEK
to compute a SHA-256 fingerprint, then zeroes that buffer; only the ID/fingerprint are
registered and reported. The writer requires a private directory owned by its UID and
publishes an immutable `0400` file named `KEY_UUID.json`. Retain this file, its reported
SHA-256 and the command receipt under recovery custody. It binds instance, organization,
key UUID/kid, activation time, purpose, algorithm and actual key fingerprint. Its canonical
hash detects changes; it is not a signature or proof of remote authorship. Protect its
source and mounts as operator inputs. An identical retry returns `replayed: true` while
preserving receipt bytes. If registration committed but file publication failed, the command
fails; an exact retry can publish the missing receipt. A different active key ID or fingerprint is
refused; this initial-registration command does not perform key rotation. Application,
worker and backup principals cannot execute the registration function. Do not edit SQL
rows to work around a mismatch. Registration alone is not a successful backup or restore.

The production `backup-key` profile provides this command with only the migrator password
and backup KEK in a separate secret volume. After bootstrap, set exact
`BOARDAGENT_ORGANIZATION_ID`, `BACKUP_KEY_ID`, `BACKUP_KEK_HOST_FILE` and the production
inputs, then run under the same Compose project used for the database:

```sh
docker compose -f compose.yaml -f compose.production.yaml \
  --profile backup-key run --rm backup-key-registrar
```

The registrar writes the `backup-key-receipts` volume. Application containers do not receive
its secrets. Keep the receipt volume and a protected independent copy for recovery. This
initial-registration command cannot rotate, retire or mark a key compromised. Use the
implemented key-lifecycle and versioned-installation procedure in runbook 08 for those
operations. Never substitute a different key under an existing UUID.

1. Confirm readiness, clock/checkpoint health, source image digest, key ID, off-host mount,
   and previous backup/restore receipt.
2. Run the one-shot operator with its private recovery environment:

   ```sh
   node scripts/dist/operator.js backup /recovery/logical
   ```

3. Require `status: succeeded`, receipt ID, manifest/content/artifact SHA-256, snapshot LSN,
   exact source image digest, and files in the mounted destination. Copy the pair off-host
   before counting the backup as durable.
4. Create an exact empty isolated PostgreSQL database whose name differs from the source.
   Supply it as `BOARDAGENT_RESTORE_DATABASE_URL` and run:

   ```sh
   node scripts/dist/operator.js restore-check \
     /recovery/logical/EXACT-MANIFEST.json
   ```

5. Require `ready: true`, a restore receipt, matching content-set/manifest hashes, restored
   database name, and evidence persisted back to the source receipt authority. Run
   synthetic identity, board snapshot, audit, certificate, and RLS checks against the
   isolated target. Destroy the isolated target only under the test environment's approved
   cleanup procedure.

## Physical base backup and continuous WAL

1. Complete migrations, bootstrap and backup-key registration without the recovery overlay.
   Set the exact `BOARDAGENT_ORGANIZATION_ID` and run the trusted operator's
   `check-bootstrap` command. Require `checks: onboarding_terms`, `allSeatRolesCovered: true`
   and a current version/hash for each of voting_member, management and observer.
   This read does not migrate, publish missing terms, create attestations or prove human
   readiness. `already_initialized` from bootstrap is not a term-inventory check. If the
   inventory is incomplete, preserve the instance and publish reviewed missing terms
   through its supported administration workflow; never erase data or SQL-patch records.
   An old instance must pass this check before an upgrade is called ready. Keep human
   activity closed during fresh commissioning.
   Set exact `RECOVERY_ROOT`, `BACKUP_KEK_HOST_FILE`, `RECOVERY_DATABASE_PASSWORD_HOST_FILE`,
   `BACKUP_KEY_ID` and `BOARDAGENT_ORGANIZATION_ID`. Use the same project and receipt volume.
2. Run the offline preflight explicitly **before** applying the overlay with `up`:

   ```sh
   docker compose -f compose.yaml -f compose.production.yaml -f compose.recovery.yaml \
     run --rm backup-key-check
   ```

   Require `status: valid` and expected instance/organization/key/receipt hash. This command
   needs no database or network. An absent, changed or mismatched receipt/key must fail
   before the existing PostgreSQL container is replaced. The overlay also enforces this
   dependency, but dependency ordering alone is not a promise that Compose leaves old
   containers running during a failed convergence.

3. Quiesce application traffic, then restart PostgreSQL and start `wal-archiver` using all
   three files. Preserve existing data/volumes. On a fresh instance, finish the first base
   backup and isolated WAL recovery exercise before opening human activity. Record this
   verified base/WAL boundary as the first recoverable point; registration alone does not
   make earlier initialization recoverable.
4. Monitor staging age/capacity, archived continuity, container health and off-host retention.
   Each archiver pass checks actual KEK bytes against the protected receipt. Failed passes
   retain unarchived staging data, publish blocked health and emit `wal_archive_blocked`
   immediately and at most once per minute. Fix the underlying input/storage issue; never
   clear staged WAL. A successful subsequent pass emits `wal_archive_resumed`. Missing,
   blocked or stale health is unhealthy. Structured logs are local signals; route them to
   the commissioned alert destination and exercise delivery before claiming monitoring.
   Use `check-backup-key` to isolate key/receipt validation, then `archive-wal-once` with
   the same private inputs to retry one pass. Both return a nonzero exit on failure;
   the public CLI deliberately redacts exception text.
5. Create an encrypted base backup:

   ```sh
   node scripts/dist/operator.js base-backup /recovery/base
   ```

6. Require manifest, encrypted artifact hash, observed start/end LSN, source image digest,
   registered key fingerprint/identity, PostgreSQL version, and retention disposition.
   Physical writers require `BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE`; base backup additionally
   compares that receipt to the live registry under the backup database role. WAL startup also
   checks the current registry; an already running writer retains its kernel maintenance lock
   through database/network loss. Offline recovery does not require the original database.
   Never prune the last known-good
   generation or any key/WAL required by a retained generation.

## PITR exercise

1. Allocate exact empty `PGDATA` and WAL target directories in an isolated recovery host.
2. Verify and extract the base backup:

   ```sh
   node scripts/dist/operator.js base-restore-check \
     EXACT-BASE-MANIFEST.json /isolated/empty-pgdata
   ```

   `ready: false` with `isolated_start_and_replay_required` is expected here; it prevents a
   verified archive from being mistaken for a running recovery.

3. Decrypt/copy the exact contiguous WAL set and write recovery configuration:

   ```sh
   node scripts/dist/operator.js prepare-pitr \
     EXACT-BASE-MANIFEST.json /recovery/wal \
     /isolated/empty-pgdata /isolated/empty-wal-target
   ```

4. Inspect the returned LSN/timeline/files and start the pinned PostgreSQL image in an
   isolated network with no application traffic. Observe recovery completion and target
   boundary; never promote an ambiguous timeline.
5. Run integrity, audit/checkpoint, key-registry, content-set, and synthetic governance
   checks. Record a restore receipt before any contemplated cutover.

## Failure rules and evidence

### Restore across a backup-key replacement

**Responsible person:** the deployment administrator or designated recovery operator.
Keep the previous keys when replacing a backup key. A base backup may need later database
journal (WAL) files encrypted with the next key; neither a new key nor a new base backup
can decrypt the older files by itself.

1. Select the actual base manifest and preserved WAL archive. Set
   `BOARDAGENT_BACKUP_KEY_ID` and `BOARDAGENT_BACKUP_KEK_FILE` to the key that encrypted
   **that base backup**, even if the running service now uses another key. The same rule
   applies to a logical `restore-check`: use the key named by its selected manifest.
2. Prepare a private `recovery-keys.json` file for this isolated restore. Its exact format is:

   ```json
   {
     "schemaVersion": "boardagent.backup-recovery-keys.v1",
     "instanceId": "COPY_THE_ORIGINAL_INSTANCE_UUID",
     "organizationId": "COPY_THE_ORIGINAL_ORGANIZATION_UUID",
     "keys": [
       {
         "keyId": "COPY_THE_BASE_BACKUP_KEY_UUID",
         "keyFile": "/recovery/keys/previous.key",
         "fingerprintSha256": "COPY_ITS_64_CHARACTER_REGISTERED_FINGERPRINT"
       },
       {
         "keyId": "COPY_THE_NEXT_BACKUP_KEY_UUID",
         "keyFile": "/recovery/keys/replacement.key",
         "fingerprintSha256": "COPY_ITS_64_CHARACTER_REGISTERED_FINGERPRINT"
       }
     ]
   }
   ```

   Replace the capitalized example values using the preserved registration receipts and
   key-generation records. Include the base key and every key named by the selected WAL
   manifests. Cross-check those IDs and fingerprints against your custody records; a
   copied archive's metadata alone is not a trusted source. Do not paste private key bytes
   into this JSON. The file accepts at most 4,096 distinct keys and 1 MiB of JSON; exceeding
   either bound refuses the request. This matches the supported key-registry size.

3. Mount the list and actual keys read-only into the isolated recovery container. Use
   physical absolute paths in `keyFile`, with protected parents and files owned by root
   or that recovery user. Keep the files private (mode 0400 or 0600), without symlinks or
   hardlinks. The old keys belong in recovery custody; do not add them to the running
   server or worker merely to perform this restore.
4. Run `base-restore-check` as above, then set the list for `prepare-pitr`:

   ```sh
   env BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE=/recovery/recovery-keys.json \
     node scripts/dist/operator.js prepare-pitr \
     EXACT-BASE-MANIFEST.json /recovery/wal \
     /isolated/empty-pgdata /isolated/empty-wal-target
   ```

   With one key throughout, the extra list is optional. With multiple keys, omission
   refuses rather than guessing. All declared files and the complete WAL key set are
   checked before decrypted WAL is written. The result and preparation receipt retain
   `recoveryKeyringSha256` and `recoveryKeyIds` for comparison with the preserved inputs.
   A successful preparation still has `ready:false`; finish the isolated PostgreSQL
   startup and application verification steps above.

If `recovery_wal_key_missing` or `recovery_base_key_missing` appears, compare the list with
the selected manifests and retrieve the missing key from protected custody. For
`recovery_private_key_mismatch` or `recovery_base_key_mismatch`, check that the selected
file is the recorded key for that ID; do not change an expected fingerprint to conceal
a mismatch. `recovery_key_target_mismatch` means the list is for a different installation
or company. `recovery_key_list_has_duplicates` means IDs, paths or fingerprints were
reused. Correct the list and retry only against suitable empty targets, preserving any
partial recovery and its error record. A genuinely lost key requires incident handling;
the program cannot reconstruct it. Compromise warnings and historical audit findings
remain part of the recovered evidence and are not cleared by successful decryption.

### General recovery checks

New manifests include key fingerprints. Offline base/WAL/PITR readers verify those against
the actual KEK without requiring the original database. Older manifests remain readable
with GCM authentication and an explicit `legacyIdOnlyCount`; that count records missing
registration binding, not a verified fingerprint. Each key must match its own declared
fingerprint, and the archive must have one consistent instance/organization identity.
Preserve original manifests; do not remove
metadata to bypass a refusal. A positive legacy count belongs in the recovery report.

Hash/key mismatch, ciphertext tamper, missing WAL, nonempty target, source-target name
collision, wrong image/PostgreSQL version, unverifiable checkpoint, or absent receipt is a
failed recovery. Do not retry by overwriting evidence; preserve the generation and diagnose.

Record operator/witness, start/end, source/image/database IDs, key ID (never key), snapshot
and WAL bounds, all manifest/artifact hashes and sizes, off-host verification, retained/
pruned generations, isolated target, verification tests, receipt IDs, recovery-point and
recovery-time observations, and exceptions.

### Interrupted archive writers and operational diagnostics

A WAL or base writer may leave an uncommitted file after interruption. Archive readers and
base retention preserve only recognized regular temporary filenames, report their count
and at most 20 basenames, and continue validating committed artifact/manifest pairs. This
is not a declaration that the writer has stopped. Symlinks and unrecognized files still
cause refusal. Hook-copy temporaries remain in staging; the archiver reports a throttled
warning even when there are no complete segments to process. Inspect backlog and free
space along with health; a healthy pass does not mean every temporary has been resolved.

Before housekeeping, stop the relevant writers and confirm no other writer is using the
collection. Preserve incomplete files outside the active recovery collection for diagnosis.
Do not delete complete staged WAL or overwrite an existing committed manifest to force a
pass. A malformed committed manifest or an orphan base artifact needs operator recovery,
not automatic promotion. No age/PID rule safely proves a file is abandoned.

New encrypted artifacts and manifests publish exclusively after complete-file fsync;
archive directory entries are fsynced before staging is acknowledged, and staging deletion
is fsynced. Local tests cover a killed writer, competing publishers and restart behavior.
They do not constitute a host power-cut or storage-controller durability guarantee.

The continuous archiver reports fixed `stage` and `reasonCode` values in blocked health
and throttled error logs. Stages distinguish paths, staging, key material, key registration
and archive validation/publication. Recognized filesystem failures report missing files,
permissions, full/quota storage, I/O, read-only storage, publication conflicts or symlinks.
Other failures report `validation_or_operation_failed` at the observed stage. No arbitrary
error text, credentials or paths enter these logs. Restore missing configured material or
storage first; retain all staging while investigating. Alert delivery and off-host custody
still require commissioning and an actual recovery trial.

Run exactly one continuous archiver for each staging/destination pair. Exclusive publication
prevents overwrites but concurrent archivers can race on staging acknowledgement and produce
blocked health. The Compose profile starts one archiver; do not scale it horizontally.
Destination temporaries are inspected on the first continuous pass and at most once per
minute thereafter; a one-shot pass inspects them by default. The warning includes both
staging and destination temporary basenames, with the same preservation rule. Health only
includes a complete temporary count and observation timestamp on an inspection pass.

An orphaned WAL collection now refuses with `archive_pairs_incomplete`, full counts and at
most 20 validated basenames for each unpaired side. Arbitrary unknown filenames are not logged;
only their count is reported. Preserve the collection and consult the retained staging
source before repair. Do not promote an orphan without its authenticated matching source.

If a base backup completes but retention refuses, the CLI exits 1 and writes a structured
`published_retention_refused` outcome to stdout with the actual backup ID, manifest path,
retention stage and fixed reason code. The completed generation is retained. Verify that
manifest and preserve the retention blocker before remediation. Then run
`operator prune-base-backups DIRECTORY` to retry the existing 7 daily/4 weekly/12 monthly policy
without creating another backup. This command does not delete governance records. Its
refusals remain nonzero. Other operator failures report a fixed command/stage and sanitized
filesystem or validation reason; no raw error text or secret-bearing paths are emitted.

Before a proposed fresh synthetic cutover, run `operator inspect-pilot-state` with the exact
`BOARDAGENT_ORGANIZATION_ID`, the restricted backup login URL and its password-file reference.
It uses a repeatable-read, read-only backup transaction, returns every public table's row count
and member-state counts, and refuses any unreadable table or wrong instance. The output contains
counts and nonsecret IDs, not personal record contents. Compare the complete inventory to the
approved initial setup and retain it with the actual host/image observation. A missing count is
not zero. Any human credential, activation, consent, submitted governance record or unexplained
extra state requires a preserving upgrade or explicit resolution. The command itself grants
no deletion/replacement authority. Repeat the observation immediately before a cutover; elapsed
time or an older empty observation is insufficient.

Logical backup and restore verification can also finish publishing their private manifest
before the worker database receipt is confirmed. These cases exit 1 with
`published_recording_unconfirmed`, the actual receipt ID and manifest path, and `ready:false`.
Preserve the artifact/manifest and reconcile that exact receipt with the database before
repeating the operation or claiming a recorded success. A connection failure cannot prove
whether a transaction committed; the status deliberately makes no such claim. Restore target
data is retained for verification and is not automatically dropped after this outcome.

## A published journal file is retried after key replacement

A stopped writer can leave a complete encrypted file and manifest in the archive while
its original journal file remains in staging. After changing keys, the normal writer
refuses to acknowledge that old pair using the new key. Preserve both copies.

The operator can run `archive-wal-once` with the same protected recovery-key list used
above for PITR. Include the current backup key and the retained key named by the old
manifest. The list and private files must belong to this installation and pass the
fingerprint checks. The old key only authenticates an already published old file; new
journal files still use the current registered key. Current database registration and
the shared maintenance lease are still required in production.

1. Stop the continuous `wal-archiver`; keep PostgreSQL available for the current-key
   check. Keep exactly one writer for this staging/archive pair.
2. Prepare a private directory for the recovery list and copied key files. Inside the
   container the list must name files under `/replay-inputs/`. Allow only service UID 10001
   to read them (directory 0700, files 0400 owned by 10001); mount the directory read-only.
   Preserve original custody files. Never paste key bytes into a shell command.
3. Run the command below from the selected release directory using the current production
   environment and versioned generation. The mounted directory must already exist.
4. Check for success and `previousGenerationReplayed`. The receipt also records
   `recoveryKeyringSha256`. Successful replay verifies encrypted size/hash, actual
   authenticated decryption and the staged plaintext size/hash before acknowledgement;
   it does not rewrite the archived file or its manifest.
5. Restart the normal continuous writer without the recovery-key mount. Verify fresh
   archive progress and health. Retain the operation receipt with the incident record.

```sh
BA_ENV='/srv/boardagent/production.env'
BA_CURRENT='/srv/boardagent/key-generations/generation-0002/compose.yaml'
BA_REPLAY_INPUTS='/srv/boardagent/private-replay-inputs'
docker compose --env-file "$BA_ENV" -f compose.yaml -f compose.production.yaml \
  -f compose.recovery.yaml -f "$BA_CURRENT" stop wal-archiver
docker compose --env-file "$BA_ENV" -f compose.yaml -f compose.production.yaml \
  -f compose.recovery.yaml -f "$BA_CURRENT" run --rm --no-deps \
  --volume "$BA_REPLAY_INPUTS:/replay-inputs:ro" \
  -e BOARDAGENT_BACKUP_RECOVERY_KEYS_FILE=/replay-inputs/recovery-keys.json \
  wal-archiver node scripts/dist/operator.js archive-wal-once /wal-staging /recovery/wal
docker compose --env-file "$BA_ENV" -f compose.yaml -f compose.production.yaml \
  -f compose.recovery.yaml -f "$BA_CURRENT" up -d --no-deps wal-archiver
```

Replace the example environment, generation and private-directory paths with the
existing installation's paths. An optional old-key list is accepted only by the one-shot
operator recovery command, not silently loaded by the continuous writer. Missing keys,
wrong installation, modified ciphertext or mismatched staging cause refusal and preserve
the affected staged file. Other earlier files in the same pass may already be acknowledged;
retries inspect their retained published pairs. Never clear staging to hide a failure.
The `recovery_keys` diagnostic names a fixed reason without exposing paths or key bytes.
