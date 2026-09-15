# 29 — Recover after an audit-signing interruption

**Owner:** the technical operator. A secretary or company-administrator
account cannot run these commands. Follow the installation's incident and observer record.

**Purpose:** recover when the retained audit history is intact, but the background worker missed
its fifteen-minute signing deadline. Recovery restores the ability to work and permanently
records the delay. It does not alter old records or pretend they were signed on time.

## Before starting

Use the installation record for the exact host, project, verified release/image, deployment
environment file, instance UUID, organization UUID, operator credentials and signing-key
file. Do not substitute a sample UUID or reuse another installation's project. The operator
service must have its normal migrator password and Ed25519 evidence key mounted. It needs
no person's browser login, passkey or consent. Preparation and inspection do not read the
private evidence key; applying a new recovery does.

Preserve the original failure, database/volume state, keys and existing backups. Identify
and fix the cause of the interruption first: for example, a stopped worker, missing mounted
file, storage exhaustion or clock fault. Damaged history or a compromised/unavailable key
requires the incident/key procedure; this command must refuse to bless it.

The installer fills these nonsecret values in the installation record. Set them in the
operator's shell before copying the commands below:

- `BA_RELEASE_DIR`: absolute directory of the verified candidate.
- `BA_DEPLOY_ENV_FILE`: absolute Compose environment file for this installation.
- `BA_COMPOSE_PROJECT`: exact existing Compose project name.
- `BA_INSTANCE_ID` and `BA_ORG_ID`: exact UUIDs from the bootstrap/installation receipt.
- `BA_WORK_DIR`: a new absolute private directory for this incident's request and receipts.

Create the incident directory for the operator container's UID, then define two shell
helpers. These helpers use the existing installation's network and secrets; `--no-deps`
avoids rerunning secret initialization during maintenance.

```sh
sudo install -d -m 0700 -o 10001 -g 10001 "$BA_WORK_DIR"

ba_compose() {
  docker compose --project-directory "$BA_RELEASE_DIR" \
    --env-file "$BA_DEPLOY_ENV_FILE" -p "$BA_COMPOSE_PROJECT" \
    -f "$BA_RELEASE_DIR/compose.yaml" \
    -f "$BA_RELEASE_DIR/compose.production.yaml" "$@"
}

ba_recovery() {
  ba_compose --profile operator run --rm --no-deps \
    --volume "$BA_WORK_DIR:/recovery" \
    -e BOARDAGENT_INSTANCE_ID="$BA_INSTANCE_ID" \
    -e BOARDAGENT_ORGANIZATION_ID="$BA_ORG_ID" \
    operator audit-recovery "$@"
}
```

Prepare a local `incident.json` containing only these two fields, using your real incident
reference and a short explanation. Include no passwords, tokens, invitation links or keys.

```json
{
  "operatorReference": "YOUR-INCIDENT-REFERENCE",
  "reason": "Explain what stopped signing and what the operator repaired."
}
```

```sh
sudo install -m 0600 -o 10001 -g 10001 incident.json "$BA_WORK_DIR/incident.json"
```

## Perform and check recovery

1. Stop ordinary service traffic and background writers for the maintenance interval.
   Keep PostgreSQL running and preserve all volumes.

   ```sh
   ba_compose stop server worker
   ```

2. If this is an upgrade, follow the release procedure first. With existing principals
   already provisioned, the verified candidate's operator can apply pending migrations:

   ```sh
   ba_compose --profile operator run --rm --no-deps operator migrate
   ```

   Recovery-aware bundles can install their repair even when signing debt is full.
   Each migration still produces its exact audit receipt; failed pending upgrades roll
   back together. This does not clear the signing backlog or make the service ready.

3. Inspect the actual retained history:

   ```sh
   ba_recovery inspect
   ```

   `status: "inspected"` identifies a completed inspection. For this procedure, expect
   `verification.valid: true` and `verification.ready: false`. Exit 1 is expected while
   overdue. If integrity is invalid, preserve the result and use the incident procedure.
   If already ready, there is no overdue interval to recover; investigate the actual
   symptom instead. Do not force recovery by editing times or records.

4. Prepare the exact proposal:

   ```sh
   ba_recovery prepare /recovery/incident.json /recovery/request.json
   sudo cat "$BA_WORK_DIR/request.json"
   ```

   Expect `status: "prepared"`, a recovery ID, request digest and expiry. This step writes
   a private proposal file and changes no database record. Check the installation, original
   record range, incident explanation and signing key. The proposal lasts thirty minutes.
   Copy its exact `requestSha256` into `BA_REQUEST_SHA256` and its recovery ID into
   `BA_RECOVERY_ID`. These identifiers are not passwords.

5. Apply that exact proposal and save its completion receipt:

   ```sh
   ba_recovery apply /recovery/request.json "$BA_REQUEST_SHA256" /recovery/receipt.json
   ```

   Expect `status: "committed"` and a permanent historical-delay warning. The database
   commits all recovery segments, their audit attestations and the completion together.
   A signing failure, cancellation or stale request rolls the transaction back. An exact
   retry after a lost reply reports `replayed: true` and preserves the same receipt.

6. Read the saved result back from the database:

   ```sh
   ba_recovery inspect "$BA_RECOVERY_ID" /recovery/receipt-checked.json
   ```

   Expect `verification.valid: true`, `verification.ready: true`, and the retained warning.
   The inspected receipt must match the original. This step never signs again. Keep both
   files, the proposal and the original incident evidence with the maintenance record.

7. Start the service and worker using the same verified configuration:

   ```sh
   ba_compose up --no-deps -d server worker
   ```

   Check actual server readiness and worker signing progress using runbooks 01 and 17.
   Perform the synthetic role/confirmation check, create an encrypted backup and verify
   a restore into an isolated target using runbook 22. The restored/exported evidence must
   still disclose the delay. Only then close the maintenance record and reopen normal use.

   Backup and restore success messages use version 2 when history includes a recovery.
   Their `warnings` list retains `historical_checkpoint_deadline_missed`, and the saved
   manifests contain the original signed finding. A successful restore does not erase
   that incident. Ordinary histories retain the existing version 1 output.

## If the result is unclear or refused

| Result                                                        | What to do                                                                                                                                              |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `request_digest_mismatch` or `input_invalid`                  | Read the saved proposal and use its exact digest. Do not edit a prepared request.                                                                       |
| `request_no_longer_applicable`                                | The head, key or time window changed. Inspect, then prepare a new request under a new filename. Keep the old proposal.                                  |
| `operator_authority_required`                                 | Use the installation's technical operator connection. Do not give the secretary or worker database-owner credentials.                                   |
| `installation_target_mismatch`                                | Stop and correct the installation record/target. Do not replace UUIDs by guessing.                                                                      |
| `one_active_evidence_key_required` or `evidence_key_mismatch` | Check the registered evidence key and its mounted file using the key procedure. No recovery was committed by that refused attempt.                      |
| `retained_evidence_invalid`                                   | Preserve the evidence and investigate integrity. This procedure cannot repair missing or changed records.                                               |
| `private_file_invalid` or `required_private_file_unavailable` | Check the recorded path, ownership and permissions. Requests/receipts must be private regular files; symlinks are refused.                              |
| `output_file_already_exists`                                  | Preserve the existing file. Preparation needs a fresh filename. Inspect its contents before deciding the next action.                                   |
| `committed_receipt_publication_unconfirmed`                   | The database committed, but the receipt file was not confirmed. Run `inspect RECOVERY_ID /recovery/a-new-receipt.json` in a writable private directory. |
| `completion_unconfirmed`, a dropped connection, or no reply   | Do not assume failure. Inspect the same recovery ID first; an exact retry of the original request is safe if a completed receipt is unavailable.        |

A different request is a different operation. Never delete old evidence, disable database
guards, change timestamps, clear failed-job history, or rotate a key merely to make this
procedure pass. A successful current check always retains the historical interruption.

Record the operator and observer, incident reference, original failure, exact recovery ID
and request digest, receipt paths, service restart time, subsequent checkpoint IDs and
actual backup/restore results. Keep that record with the preserved incident evidence.
