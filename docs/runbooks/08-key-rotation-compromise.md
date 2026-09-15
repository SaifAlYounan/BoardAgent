# 08 — Replace a key or report its compromise

**Owner:** the technical deployment administrator, with the designated security/custody
contact. A company-administrator login or secretary's agent cannot run these commands.

**Purpose:** replace, retire or report compromise of the correct key, preserve its history
and recovery material, and return the service to verified operation.

Each deployment needs its own recorded installation, restart and restore checks before
relying on this procedure.

## What people need to know

For a routine key change, the administrator prepares a new key, stops the affected services,
records the change and installs the new files before restarting. Old evidence and needed
old decryption keys are retained. If a key may have been copied or lost, the administrator
records **compromise first**. This contains affected access and preserves an honest incident
record; simply replacing a file is insufficient.

The production service refuses key apply while its server, worker or any backup/WAL writer
is still active. Stop each process and let it finish before changing keys. A
successful database command means the change was recorded. It does not mean the new files
were installed or the service restarted. Each stage has its own evidence.

| Key               | Ordinary replacement                                                                                                                                       | Reporting compromise                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| OAuth signing     | New tokens use the new signer; historical public keys remain.                                                                                              | Affected token families are revoked, including their later tokens.                                                                             |
| Evidence signing  | New checkpoints use the new signer; old signatures keep their original identity.                                                                           | The suspected time stays recorded. Old signatures do not become trustworthy merely because a new key exists.                                   |
| Browser sessions  | Members sign in again; registered passkeys remain.                                                                                                         | Protected sessions and pending approval stages are cancelled.                                                                                  |
| Data encryption   | Active authenticator data retains its old decryption key; notification connections are re-encrypted without changing their destinations or shared secrets. | Exposed authenticator/access state and notification connections are contained. Preserved ciphertext still needs its original key for recovery. |
| Backup encryption | New backups use the replacement; retained generations keep their original key IDs.                                                                         | Exposure remains an incident. A new key cannot make already exposed backups secret again.                                                      |

## Prepare the operator environment

Use the exact reviewed release image and its technical operator database credentials. The
environment must identify `BOARDAGENT_INSTANCE_ID`, `BOARDAGENT_ORGANIZATION_ID` and the
existing operator database connection/password-file configuration. Never give these
credentials to an agent or mount them into the server/worker.

The operator needs a private writable maintenance directory, read access to the registered
key files and access to the local backup/base/WAL/export roots being inspected. Use physical
absolute paths with no symlink components. Files must be owned by root or the operator,
without world access, group write or executable permissions. A new maintenance directory
should be mode 0700 and JSON input files mode 0600. Private key files may be 0400/0600 or
readable by their protected service group.

In that configured operator environment, inspect the exact installation:

```sh
node scripts/dist/operator.js key-lifecycle inspect
```

Expected output is JSON with `status:"inspected"`, installation IDs and registered keys.
Check the installation before proceeding. This read does not establish file custody or
service readiness.

## Create the plan and request

Create a private plan JSON containing these fields. UUIDs and paths must come from the
actual installation; the command refuses unknown or omitted registered key IDs.

| Field                   | What to put there                                                                                                                                                                                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `schemaVersion`         | `boardagent.operator-key-plan.v1`                                                                                                                                                                                                                                        |
| `keyId`                 | The registered key being changed.                                                                                                                                                                                                                                        |
| `operation`             | `replace`, `retire`, or `mark_compromised`.                                                                                                                                                                                                                              |
| `declaredCompromisedAt` | `null` for ordinary changes. For compromise, the earliest supported suspected time in UTC with six fractional digits; it cannot precede activation or be in the future.                                                                                                  |
| `operatorReference`     | The maintenance/incident ticket reference.                                                                                                                                                                                                                               |
| `reason`                | A short factual explanation; no private key or password.                                                                                                                                                                                                                 |
| `keyFiles`              | One `{ "keyId": "…", "file": "/physical/path" }` entry for **every** registered key, including historical keys. Use `file:null` to explicitly record unavailable material where permitted below.                                                                         |
| `recoveryRoots`         | Actual local directories containing retained logical backups, base backups, WAL and exports. Include each root once; roots must not overlap.                                                                                                                             |
| `replacement`           | For `replace`, `{ "keyFile": "/maintenance/new-key-file", "runtimeFile": "/run/boardagent-secrets/versioned/new-key-file" }`. Otherwise `null`. The first path is the staged file visible to the operator; the second is its intended path inside the runtime container. |
| `custodyReference`      | The actual custody/inventory reference. It does not count as an off-host verification or a second person's approval.                                                                                                                                                     |

For `file:null`, incident containment remains possible even if private material is missing.
Already compromised keys and retired OAuth/evidence/browser keys may also be listed this
way. Ordinary replacement of an unexposed data/backup key requires the retained decryption
material. If that material is lost, record the incident; do not claim that old data is
recoverable. Copies held elsewhere must be obtained and verified before being called local
custody.

Keep the new key, request and maintenance records outside the recovery roots being hashed.
The command generates appropriate fresh material if `replacement.keyFile` does not exist;
it never overwrites an existing file. If it already exists, it must contain valid distinct
staged material. This supports re-preparation after expiry without generating keys repeatedly.

```sh
node scripts/dist/operator.js key-lifecycle prepare /maintenance/plan.json /maintenance/request.json
```

Expected output: `status:"prepared"`, `operationId`, `requestSha256`, `expiresAt` and the
staged replacement path. Review the saved request: it contains the proposed effect,
database dependencies and actual local-file inventory. Nothing in the database changes at
this step. A preparation failure may leave a newly generated **unregistered** staged file;
preserve it and correct the reported cause. Never overwrite an earlier request to hide it.

The request lasts thirty minutes and must still match relevant database/file state. Stop
server, worker and all standalone backup/base-backup/WAL writers; allow in-flight work to
finish. Use the existing project and file list as described under “If maintenance will
not start” below. If ordinary activity changed the snapshot, prepare a fresh request while
services are stopped, retaining
the earlier request as superseded evidence.

## Record the change

Use the exact hash printed by preparation:

```sh
node scripts/dist/operator.js key-lifecycle apply /maintenance/request.json REQUEST_SHA256 /maintenance/receipt.json
```

`REQUEST_SHA256` is a placeholder for the actual 64-character digest, not a secret.
Expected output is `status:"database_applied"`, operation/audit identifiers and
`runtimeInstallation:"pending"`. The database key transition, revocation/rewrap effects,
audit event and immutable completion record commit together. Old private files are unchanged.

**Installation is still pending.** Do not run `register-runtime-keys`, `register-backup-key`
or the old `application-secret-init` to imitate rotation. The old initializer replaces fixed
paths and is not the versioned installer. Keep services stopped until the exact replacement
files, purpose-separated mounts, retained-data manifest and backup registration receipt are
installed using “Install the replacement files” below and restart/restore checks are
complete. A successful apply receipt alone does not complete those steps.

For a suspected compromise followed by replacement, first prepare/apply `mark_compromised`.
Then prepare a **new** `replace` request against the recorded state. The earlier compromise
time remains. A missing old data key is not restored by generating a new one.

## If a command fails or the terminal closes

Do not assume that a lost response means no database change occurred. Preserve the original
request, operation ID and staged files. Inspect that operation before creating another one:

```sh
node scripts/dist/operator.js key-lifecycle inspect OPERATION_ID /maintenance/recovered-receipt.json
```

A completed operation returns its original receipt even if keys have since changed or files
are unavailable. `operation_not_committed` means this installation has no completed operation
with that ID. A connection error means the outcome is still unknown: restore connectivity
and inspect again. Never remove a database record to make a retry work.

| Reported reason                                                                              | Practical response                                                                                                                                                                                                                                                                                                |
| -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_signing_backlog`                                                                      | Stop retrying unchanged preparation. Inspect the operation and confirm the installed migrations include the maintenance admission repair. Supported key-loss containment and replacement can record their own exact receipts at full signing debt; ordinary work remains blocked until signing/recovery succeeds. |
| `stop_server_and_worker`                                                                     | Finish stopping/draining those services, inspect the original operation, then retry the same request if still applicable.                                                                                                                                                                                         |
| `retained_material_changed` / `state_changed_prepare_again` / `request_no_longer_applicable` | Inspect the original operation. If it did not commit, preserve the old request and prepare a new one from the current facts.                                                                                                                                                                                      |
| `complete_registered_key_files_required`                                                     | Include every registered key ID. Explicitly distinguish an available path from unavailable material.                                                                                                                                                                                                              |
| `required_private_material_unavailable`                                                      | Locate and verify the required old key, or use the documented incident route if it was lost. Do not relabel lost data as recovered.                                                                                                                                                                               |
| `private_material_registry_mismatch` / `replacement_material_reused`                         | Check that the correct installation's files were selected. Use genuinely fresh replacement material.                                                                                                                                                                                                              |
| `output_file_already_exists` / `receipt_file_conflict`                                       | Preserve the existing file and choose a new output name. A completed operation can reproduce an identical receipt.                                                                                                                                                                                                |
| `protected_file_unavailable` / `protected_material_or_operation_invalid`                     | Check mounted paths, physical directories, ownership, permissions and supported file/manifest format; do not relax permissions to world-readable.                                                                                                                                                                 |
| `operator_authority_required` / `installation_target_mismatch`                               | Correct the technical operator connection or installation IDs. Do not grant the application an operator role.                                                                                                                                                                                                     |
| `connection_unavailable` or `status:"inspect_required"`                                      | Restore the connection and inspect the original operation ID before doing anything else.                                                                                                                                                                                                                          |

Exact reapplication of an already completed request returns `replayed:true` and the same
receipt; it does not revoke newly created sessions again. It still does not certify the
current mounted files or readiness.

## Evidence and remaining production acceptance

Retain the plan, all requests, staged and historical keys needed for recovery, full local
inventories, original/recovered receipts, incident reference, actual custody witnesses,
installation/restart logs and restore results. No private bytes belong in tickets or logs.

The local inventory checks hashes and supported manifest/key relationships. It does not
prove off-host custody, authenticated decryption, successful PostgreSQL restore or complete
coverage outside the listed roots. An empty root list is **not** a verified absence of backups.
Its bound is 64 roots,20,000 files,depth32,8TiBtotal and ten minutes; reaching a bound refuses
without truncating. Native performance at those maxima has not been qualified.

Before production closure, prove the correct new signer/encryption writer, fresh member
login where required, old public-signature verification, retained authenticator access,
old/new encrypted export and database/base/WAL recovery, stopped old writers and operational
custody. These remain separate from the locally passing command tests and from any
manual role trial.

## If maintenance will not start

Use the same reviewed Compose project and configuration files used to start the service.
Stop `server`, `worker` and, when the recovery profile is enabled, `wal-archiver`. Also let
one-off `backup`, `base-backup` and audit-recovery commands finish. Run `docker compose ps`
with those same project/files to check the result. The operator must arrange this short
maintenance window; a secretary does not need server credentials.

| Message                                        | Meaning and next action                                                                                                                                                                                                                                                           |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `maintenance_lock_busy`                        | A participating process is still running. Check that project's containers and one-off maintenance commands, stop or finish them, then retry the original request.                                                                                                                 |
| `maintenance_lock_invalid`                     | The coordination file is absent or its ownership, permissions or links are unsafe. Check the project's `maintenance-lock-init` result and configured volume. Preserve the volume for inspection. Do not delete or replace the lock while anything can still run.                  |
| `maintenance_lock_unavailable`                 | The supported Linux lock helper could not run. Confirm the exact release image and Linux host; do not disable the check.                                                                                                                                                          |
| `connection_unavailable` at `key_registration` | A starting WAL writer cannot reach PostgreSQL. Restore that connection and restart the writer. Already running writers keep their lock through a database outage.                                                                                                                 |
| `backup_key_registry_check_failed`             | The WAL writer's configured key did not pass the current registry check. Compare its key ID, registered receipt and mounted key generation with the completed maintenance receipt, install the current generation and restart. An old receipt alone cannot authorize new backups. |

All participants must mount the **same original coordination volume**. Do not create a
second volume to get past a busy result. Read-only inspection and recovery of the original
operation receipt remain available while services run. A refused key-apply attempt is not
a completed key change. Keep its result with the maintenance record.

## Install the replacement files

**Responsible person:** the technical deployment administrator. This is a short server
maintenance operation. The secretary and directors keep their ordinary accounts.

After `apply` reports `database_applied`, use the new `install` mode. It prepares a new
set of private directories and a deployment file. It preserves the original keys and
does not start the service. The current replacement must still match the operation you
are finishing. Read-only `inspect` supplies actual key IDs and `installationRequirements`; use the successful apply or
recovered receipt for the operation ID and request digest.

If `unavailablePurposes` is nonempty, finish the replacement for each listed purpose first.
If `unusableRetainedKeyIds` is nonempty, resolve those affected credentials/connections
before installation. Inspection does not certify that private files are available.

The first move from fixed-name secret files to versioned directories also needs a completed
`replace` operation. There is no install-only shortcut or fabricated receipt. Retain the
original fixed-name files and follow the replacement steps above before installation.

Prepare a root-owned private `INSTALL.json` with these fields:

| Field                          | Value                                                                                                                                                                                                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schemaVersion`                | `boardagent.key-generation-plan.v1`                                                                                                                                                                                                                        |
| `operationId`, `requestSha256` | The exact values from the completed replacement receipt.                                                                                                                                                                                                   |
| `generationRoot`               | A new, nonexistent directory inside the operator's protected key-generation storage. Its parent must already exist.                                                                                                                                        |
| `keyFiles`                     | `{ "keyId": "…", "file": "/physical/operator/path" }` entries for all five current keys and every required retained data key. Sources remain unchanged.                                                                                                    |
| `retainedDataKeyIds`           | Copy `installationRequirements.retainedDataKeyIds` from the current `key-lifecycle inspect` result. These are old keys still needed by authenticator records or notification connections. An empty array means none are required by those runtime records. |
| `passwordFiles`                | An object with `migrator`, `server`, `worker`, `backup`, each naming its actual private password file. These are files, never password values. The installer checks the four logins.                                                                       |

Use physical absolute paths. Prepare root-owned mode 0700 input directories and mode 0600
input files. If working from existing service-owned files, copy them into the protected
operator input directory; retain the original files. The installer intentionally refuses
untrusted owners, symlinks, missing keys, mixed-purpose material and wrong passwords.

Run in the reviewed production operator container as root. Keep its existing maintenance
coordination mount. Add read-only mounts for the private input directories and a writable
mount for the generation parent, using the **same absolute host and container path** for
that parent. Override `BOARDAGENT_DATABASE_PASSWORD_FILE` to the protected root-readable
migrator password. Give the container only the additional `CHOWN` capability; do not mount
the Docker socket. The configured command is:

```sh
node scripts/dist/operator.js key-lifecycle install /physical/operator/path/INSTALL.json
```

For the standard Linux production/recovery profile, the following is the complete Compose
invocation. Set the first five variables to your existing installation and prepared inputs.
`BA_GENERATIONS` must name the already-created parent of `generationRoot`, and every source
path in `INSTALL.json` must be below `BA_INPUTS`. Both directories must already be protected
as described above. Include any previously selected generation override in `BA_CURRENT`.
Run this from the release directory containing the three Compose files.

```sh
BA_PROJECT='your-existing-compose-project'
BA_ENV='/srv/boardagent/your-existing-deployment.env'
BA_CURRENT='/srv/boardagent/key-generations/generation-0001/compose.yaml'
BA_INPUTS='/srv/boardagent/key-maintenance/inputs'
BA_GENERATIONS='/srv/boardagent/key-generations'

sudo docker compose -p "$BA_PROJECT" --env-file "$BA_ENV" \
  -f compose.yaml -f compose.production.yaml -f compose.recovery.yaml \
  -f "$BA_CURRENT" run --rm --no-deps --user 0:0 --cap-add CHOWN \
  --volume "$BA_INPUTS:$BA_INPUTS:ro" \
  --volume "$BA_GENERATIONS:$BA_GENERATIONS:rw" \
  --env "BOARDAGENT_DATABASE_PASSWORD_FILE=$BA_INPUTS/migrator.password" \
  operator key-lifecycle install "$BA_INPUTS/INSTALL.json"
```

For the first installation, omit `-f "$BA_CURRENT"`; later installations use the actual
previous generation file. The example's `generation-0001` segment is a placeholder for
that physical generation directory. `--no-deps` keeps stopped writers
stopped; PostgreSQL and the existing maintenance coordination volume must already be ready.
This is the only step run as container root. Normal services continue as their restricted
service user. `database_password_check_failed` means a supplied password did not authenticate
its assigned database login: correct the named source files in the plan from your protected
credential store, then retry with a new generation path. Do not reset all passwords blindly.

Expected success is `status:"generation_prepared"`. Its `composeFile` and `manifestFile`
identify the actual prepared files. `runtimeInstallation:"restart_and_verify_required"`
means the restart is still yours to perform.

Add the returned `compose.yaml` **last** to the same project, deployment environment and
`compose.yaml`, `compose.production.yaml`, `compose.recovery.yaml` files already in use.
Inspect `docker compose config` with those exact files, then start `server`, `worker` and
`wal-archiver` with the same configuration. The override disables the old secret
initializers for normal startup and selects the new role-specific directories. Preserve
the previous configuration as recovery evidence; reverting only the files will not undo
a recorded key change and the service will refuse mismatched old keys.

Check server readiness, worker health and WAL archiver health. Confirm a new signed
checkpoint and a new backup using the current key ID, then restore retained old and new
backup generations using their respective preserved keys. Record actual outcomes. Members
must sign in again after browser-session key replacement; their passkeys remain registered.
Finish by updating the installation's selected Compose file list so routine restarts use
the same verified generation.

If the result is `generation_directory_already_exists`, inspect and preserve that directory.
If the result is `storage_full`, the destination ran out of space or exceeded its quota.
Ask the deployment administrator to restore capacity without deleting keys or backup evidence.
Preserve the partial directory and choose a new generation path for the retry below.
For an interrupted attempt, select a **new empty generationRoot** and rerun the same recorded
operation; do not delete partial files or overwrite the previous generation. If an active
key or required retained key is unavailable, keep the service stopped and follow the
compromise/replacement steps above. A prepared directory is not proof of a successful
restart or restore. The whole installation flow remains subject to release qualification.

## Lost signing key while the audit backlog is full

Stop the writers and preserve their files and logs. Use `mark_compromised` with the lost
key's `file:null` entry, then the supported `replace` procedure. Each operation records
one exact, permanent receipt even when ordinary work has reached the signing limit.
This does not permit governance actions, reset the backlog, erase an incident or invent
an old signature. Install the replacement, then follow runbook 29 for an overdue audit
recovery if required. A recovery finding remains visible permanently.

The initial `register-runtime-keys` and `register-backup-key` commands are for the first
key of each purpose and exact retries of the active initial registration. Once a purpose
has any retained history, those commands refuse to create a successor after retirement
or compromise. Use `key-lifecycle prepare/apply`; never alter the registry manually.

Ordinary OAuth signing-key retirement, including retirement without an immediate
replacement, does not revoke already issued unexpired access tokens. They retain their
original ledger expiry (at most fifteen minutes); no fresh token may use the retired
signer. If the key may be exposed and immediate token revocation is required, record
`mark_compromised`. Retirement is not the incident-containment operation.

The versioned Compose override moves the old backup registrar and all old secret
initializers to the same initial-setup-only profile. The normal operator and backup
profiles do not start them. Do not explicitly target the old registrar after key history
exists; SQL0138 refuses that successor shortcut in any case.
