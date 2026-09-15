# BoardAgent deployment guide

## Release boundary

This guide covers the frozen single-server profile. BoardAgent is an open-source beta:
production acceptance (Gate 3) and independent external review (T10) remain required
before any public-production claim. Following this guide does not itself authorize a
deployment or the use of real board data. Read [the open items](SECURITY.md#open-items)
before commissioning. These procedures describe the supported profile, not a receipt
that a host or account is ready.

The supported topology is:

- one Linux virtual private server (VPS) controlled by the deployment owner;
- one BoardAgent organization;
- one Caddy edge process terminating HTTPS;
- one BoardAgent server and one worker built from the same source tree;
- one PostgreSQL 18.6 instance on an internal Compose network;
- encrypted recovery material on operator-selected storage outside the VPS failure domain.

Automatic failover, horizontal scale, shared/multi-tenant hosting, Kubernetes, and managed
database variants are not verified release profiles.

## Required operator roles

Keep these responsibilities explicit even if one person initially holds several roles:

- **Project owner:** approves production acceptance (Gate 3) and any change to a frozen product decision.
- **Deployment administrator:** owns the VPS, DNS, Compose configuration, runtime secrets,
  monitoring, upgrades, and recovery.
- **Company administrator:** owns organization-level application authority, constitutional
  configuration, privileged account administration and any exact board delegation.
- **Secretariat:** organizes board business, enrollment and record correction through
  BoardAgent tools. Registering directors requires company-admin authority or an explicit
  current board delegation; a secretary title grants no server login or automatic vote.
- **Security contact:** receives suspected-compromise reports and directs containment.
- **Independent reviewer:** performs T10 without relying on the implementer's conclusions.

Do not give the server or worker the database owner, migrator, or backup credential.

## Immutable release inputs

Use only images produced and checked from one unchanged source tree:

```sh
corepack pnpm verify:private-beta
```

The verification orchestrator builds application, PostgreSQL, and Caddy images with an
`org.boardagent.source-tree-sha256` label, records immutable image IDs, produces SBOM and
license artifacts, and runs the configured vulnerability scan. Before a deployment,
record at least:

- source-tree SHA-256;
- lockfile, registry, migration, and SBOM digests;
- immutable IDs for all three images;
- scan receipt and scanner-database freshness;
- the exact release manifest and the project owner's acceptance decision;
- the independent T10 receipt if the release will be described as public production.

Never deploy mutable upstream tags in place of the recorded immutable image IDs.

## Host prerequisites

The deployment administrator must provide:

- a supported Linux host with Docker Engine and Compose v2;
- an exact DNS name resolving only to the intended host;
- inbound TCP 80/443 and UDP 443 as required by the Caddy profile;
- no public PostgreSQL port;
- time synchronization and an alert for clock drift;
- enough encrypted disk for PostgreSQL, blob, export, and retained recovery data;
- an off-host recovery destination with independent access control;
- a private incident channel and an out-of-band invitation handoff route.

Harden and patch the host independently. BoardAgent's container controls do not protect a
compromised host, Docker daemon, operator account, DNS zone, reverse proxy, or client.

## Production secret set

Create each item in an offline or otherwise controlled operator ceremony. Store each in a
separate owner-controlled regular file and never in `.env`, source control, tickets, chat,
or Compose YAML.

| Secret file                | Required content                                       | Consumer                       |
| -------------------------- | ------------------------------------------------------ | ------------------------------ |
| database owner password    | unique 43–128 character canonical base64url value      | PostgreSQL initialization only |
| database migrator password | distinct 43–128 character canonical base64url value    | migration/operator role        |
| database server password   | distinct 43–128 character canonical base64url value    | server role                    |
| database worker password   | distinct 43–128 character canonical base64url value    | worker role                    |
| database backup password   | distinct 43–128 character canonical base64url value    | backup/restore role            |
| OAuth signing key          | P-256 private JWK with `kid`, `use: sig`, `alg: ES256` | token signer                   |
| evidence signing key       | Ed25519 PKCS8 private PEM                              | checkpoints/certificates       |
| browser-session key        | exactly 32 random raw bytes or canonical base64url     | browser sessions               |
| data KEK                   | exactly 32 random raw bytes or canonical base64url     | encrypted exports              |
| backup KEK                 | exactly 32 random raw bytes or canonical base64url     | backup and WAL artifacts       |
| OIDC client secret         | provider-issued value, only in OIDC mode               | OIDC client                    |

Keep the backup KEK outside the runtime secret volumes. Losing a KEK can make its
ciphertext unrecoverable; disclosure can expose all ciphertext protected by it. Preserve
retired asymmetric public keys so historical signatures remain verifiable.

Production Compose copies these files into separate named volumes, not a shared runtime
secret directory. Each consumer mounts only its own volume read-only, with directory
mode `0700` and file mode `0400` under its runtime UID:

| Consumer                      | Mounted secret custody                                                                 |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| PostgreSQL                    | owner password only (UID 70)                                                           |
| One-shot database initializer | five database passwords needed to provision the principals; no application keys        |
| One-shot operator/bootstrap   | migrator password and four application keys, needed to register their exact identities |
| Server                        | server password, OAuth signing, evidence signing, browser-session key, data KEK        |
| Worker                        | worker password, evidence signing, data KEK                                            |
| Recovery/backup overlay       | backup password and backup KEK only                                                    |

The server signs OAuth tokens and synchronous certificates, maintains browser sessions,
and decrypts artifacts. The worker signs certificates/checkpoints and encrypts exports
and webhook secrets; it does not load or mount OAuth or browser-session keys. Bootstrap
registers all four key identities before either runtime can start. The root secret-copy
initializer is a trusted, one-shot provisioning service; it is not an application runtime.
An OIDC deployment must likewise mount its provider client secret into the server only.

Stop the server, worker and operator before replacing a secret set. The initializer
preflights every required source and rejects empty, oversized, symlinked or unexpected
target files. It marks every consumer volume incomplete, stages and verifies all copies,
then publishes the files before removing the markers. Every failed copy or publication
stops initialization. Database-password and application-key loaders refuse a volume with
`.initialization-incomplete`, including a dangling symlink at that marker path.

If initialization is interrupted, preserve the volumes and inspect the non-secret error.
Correct the source or storage problem and rerun the initializer with the complete set;
it replaces its known partial staging files and clears the markers only after successful
publication. Never remove the marker manually to force startup. Unexpected files require
operator investigation. The initializer does not silently delete unknown secret residue.

When upgrading from the former shared `application-secrets` volume, stop the old server,
worker and operator containers before recreating them with the verified new Compose
configuration. Do not alias any per-consumer volume to the old shared volume. After
verifying the new mounts and recovery custody, retire the now-unmounted old volume using
the administrator's approved secret-retirement procedure. Do not delete source key files
or recovery keys as part of that cleanup. Reusing an old container retains its old access.

Create the initial set in an offline administrator ceremony using the organization's
approved CSPRNG, HSM, KMS or secret manager. BoardAgent intentionally has no secret-
generation CLI: the frozen command registry does not include one, and runtime custody
must remain separate from generation and recovery custody.

1. Create a new secret directory on encrypted storage with mode `0700`; refuse an existing
   target rather than merging or overwriting it.
2. Generate every table row independently. Use at least 32 random bytes for each database
   password before canonical base64url encoding; do not derive one password from another.
3. Generate the P-256 and Ed25519 keys in the approved HSM/KMS or offline key tool and
   export only the exact formats in the table when file-backed keys are used.
4. Write each file once with mode `0600`. Never print secret values into a receipt, terminal
   transcript or shell history.
5. Record only purpose, key identifier, custodian, creation time, algorithm/length and file
   digest in the ceremony receipt. Do not record private material or password hashes.
6. Move the backup KEK to separate recovery custody before Compose initialization. Retain
   the old public verification keys across rotations. Provider-issued OIDC secrets are
   never locally generated.
7. Have a second operator verify file ownership, permissions, purpose separation and the
   non-secret receipt. Production configuration/startup then validates formats and rejects
   missing, duplicated, weak or placeholder material.

## Configuration

Copy `.env.production.example` to an operator-controlled non-secret file outside source
control. Replace every placeholder. The application rejects unknown `BOARDAGENT_*`
variables and fails closed on incomplete or production-incompatible settings.

Application settings:

| Setting                                | Mode, bound, and refusal behavior                                                                                |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `BOARDAGENT_ENV`                       | required; exactly `production` here                                                                              |
| `BOARDAGENT_DATABASE_URL`              | per-process PostgreSQL URL with explicit principal and no production password                                    |
| `BOARDAGENT_DATABASE_PASSWORD_FILE`    | required in production; owner-only regular file, distinct from purpose keys                                      |
| `BOARDAGENT_ORGANIZATION_ID`           | exact UUID returned by bootstrap; bootstrap supplies it internally on first creation                             |
| `BOARDAGENT_PUBLIC_BASE_URL`           | exact HTTPS origin, with no path, credentials, query, or fragment                                                |
| `BOARDAGENT_AUTHORIZATION_MODE`        | `builtin` or `oidc`; switching is a controlled identity change                                                   |
| `BOARDAGENT_BLOB_ROOT`                 | writable persistent application path; Compose uses `/var/lib/boardagent/blobs`                                   |
| `BOARDAGENT_DEV_MASTER_SECRET`         | development/test only and expressly forbidden in production                                                      |
| `BOARDAGENT_OAUTH_SIGNING_KEY_FILE`    | required distinct P-256 private JWK file                                                                         |
| `BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE` | required distinct Ed25519 PKCS8 private PEM file                                                                 |
| `BOARDAGENT_BROWSER_SESSION_KEY_FILE`  | required distinct 32-byte key file                                                                               |
| `BOARDAGENT_DATA_KEK_FILE`             | required distinct 32-byte export-encryption key file                                                             |
| `BOARDAGENT_RETAINED_DATA_KEYS_FILE`   | optional manifest of retired data keys kept for decryption; see `docs/decisions/retained-data-key-runtime-v1.md` |
| `BOARDAGENT_OIDC_ISSUER`               | required only in `oidc` mode; exact discovered issuer URL                                                        |
| `BOARDAGENT_OIDC_CLIENT_ID`            | required only in `oidc` mode; exact registered client ID                                                         |
| `BOARDAGENT_OIDC_CLIENT_SECRET_FILE`   | required only in `oidc` mode; provider secret regular file                                                       |
| `BOARDAGENT_CLIENT_ALLOWLIST`          | optional comma-separated exact client IDs or verified metadata URLs; empty means no deployment allowlist         |
| `BOARDAGENT_ACCESS_TOKEN_TTL_SECONDS`  | exactly `900`; other values are refused because issued tokens use this fixed lifetime                            |
| `BOARDAGENT_STAGE_TTL_SECONDS`         | exactly `600`; other values are refused because persisted consent uses this fixed lifetime                       |
| `BOARDAGENT_TRUSTED_PROXY_HOPS`        | 0–4; verified one-Caddy topology uses `1`                                                                        |
| `BOARDAGENT_WEBHOOKS_ENABLED`          | exactly `true`/`false`; default and recommended initial value `false`                                            |
| `BOARDAGENT_EXPORT_MAX_BYTES`          | 1 MiB–1 GiB; default 256 MiB                                                                                     |
| `BOARDAGENT_EXPORT_CHUNK_BYTES`        | 64 KiB–10 MiB; default 4 MiB                                                                                     |
| `BOARDAGENT_LOG_LEVEL`                 | `error`, `warn`, or `info`; never enables body/content logging                                                   |

Production forbids `BOARDAGENT_DEV_MASTER_SECRET`, plaintext public origins, credentials in
the database URL, and reused purpose-key paths.

Set the Compose inputs to exact host paths and verified image references:

- `APP_ENV_FILE`
- `RELEASE_IMAGE`, `POSTGRES_IMAGE`, `CADDY_IMAGE`
- `DATABASE_OWNER_PASSWORD_HOST_FILE`
- `DATABASE_MIGRATOR_PASSWORD_HOST_FILE`
- `DATABASE_SERVER_PASSWORD_HOST_FILE`
- `DATABASE_WORKER_PASSWORD_HOST_FILE`
- `DATABASE_BACKUP_PASSWORD_HOST_FILE`
- `OAUTH_SIGNING_KEY_HOST_FILE`
- `EVIDENCE_SIGNING_KEY_HOST_FILE`
- `BROWSER_SESSION_KEY_HOST_FILE`
- `DATA_KEK_HOST_FILE`
- `CADDY_DOMAIN`

The recovery overlay additionally uses exact `RECOVERY_ROOT`,
`BACKUP_KEK_HOST_FILE`, `RECOVERY_DATABASE_PASSWORD_HOST_FILE`, and registered
`BACKUP_KEY_ID` and `BOARDAGENT_ORGANIZATION_ID`. Commission the instance without the
recovery overlay, then use the `backup-key` production profile to register the separate KEK
and publish its private receipt volume. Explicitly run the recovery `backup-key-check`
before applying the overlay or replacing PostgreSQL; follow the full startup and isolated
restore sequence in [runbook 22](docs/runbooks/22-backup-pitr-restore.md). The password host file is mounted read-only and copied into the
owner-only recovery secret volume; its matching database URL remains password-free.
One-shot backup/restore operator
commands require their documented source/receipt/target database connections, backup KEK
path/key ID, source image digest, protected `BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE` for
physical writers, and the corresponding
`BOARDAGENT_{BACKUP,RECEIPT,RESTORE}_DATABASE_PASSWORD_FILE`. Database URLs remain
password-free; keep that recovery environment private and separate from the application
environment.

Run `docker compose config` against the merged files and inspect the rendered non-secret
configuration before creating containers. Do not paste its output if the local Compose
version renders secret material.

## First initialization

All commands below run from the checked release tree. The production overlay must always
follow the base file:

```sh
docker compose -f compose.yaml -f compose.production.yaml \
  --profile initialize up application-secret-init postgres database-initializer
```

Require the database initializer to exit successfully. Do not start the server after a
partial migration or principal-provisioning result.

Prepare a reviewed bootstrap input from `docs/examples/bootstrap.example.json` in a private
operator directory. Native Linux bind mounts preserve numeric ownership: the operator
container runs as UID/GID `10001:10001`, so an administrator-owned `0600` source file is
unreadable there. Create a separate, new handoff directory and copy the reviewed input
with explicit ownership; retain the administrator's original under its existing custody:

```sh
set -eu
test ! -e /absolute/operator-input
test ! -L /absolute/operator-input
sudo install -d -o 10001 -g 10001 -m 0700 /absolute/operator-input
sudo install -o 10001 -g 10001 -m 0400 \
  /absolute/reviewed/bootstrap.json /absolute/operator-input/bootstrap.json
```

Verify the copied file's digest against the reviewed source, and verify the directory is
`10001:10001 0700` and the regular file is `10001:10001 0400`. Stop if the destination
already exists, is a symlink, or differs from the reviewed bytes. These numeric owners
assume the documented Docker profile without user-namespace remapping; a remapped host
must establish and verify its equivalent UID mapping before use. Never make the input
group/world-readable or run the operator as root to compensate. Mount the handoff
directory read-only:

```sh
docker compose -f compose.yaml -f compose.production.yaml \
  --profile operator run --rm \
  --volume /absolute/operator-input:/operator-input:ro \
  operator bootstrap /operator-input/bootstrap.json
```

Bootstrap is one-use and returns the initial setup administrator's enrollment handoff.
The input fields are named `firstSecretary*` for historical reasons; inspect the actual
roles and board seat in the receipt. This setup person is separate from the intended
ordinary secretary.
Treat the handoff as a
credential. Save the canonical hashes and non-secret identifiers in the initialization
receipt; transfer the secret through the declared out-of-band method. Put the returned
organization UUID into the production environment file before starting the runtime.

Start the runtime and HTTPS edge:

```sh
docker compose -f compose.yaml -f compose.production.yaml \
  --profile https up -d server worker caddy
```

Verify from both the host and a separate network location:

```sh
curl --fail https://boardagent.example.com/health/live
curl --fail https://boardagent.example.com/health/ready
```

Replace the example origin with the exact configured origin. Readiness must remain false
when migrations, runtime-key registration, database authority, worker health, or clock
requirements are not satisfied. A live-but-unready service must not receive MCP traffic.

## Authentication commissioning

Built-in mode is the default authentication path. Each person redeems their own short-lived,
single-use enrollment and registers their own passkey in the browser. The issuer verifies
identity and completes the matching activation; the secretary does not register passkeys
for directors. Arrange that handoff before registration and finish it within ten minutes.
Complete personal onboarding, then connect each person's separate agent. TOTP is a
deliberate fallback, not a silent downgrade.

Untouched first-invitation renewal stops being available once registration completes.
Expired or exhausted activation for a registered pending person is restarted with the
one-use restart handoff: `reissue_activation` by the issuer, or
`bootstrap reissue-first-activation` by the operator for the first administrator. The
person re-proves with their existing passkey and receives a fresh ten-minute code; the
issuer still confirms it. Do not treat ordinary active-person recovery as a remedy for
that unfinished setup. Follow the [bootstrap](docs/runbooks/02-bootstrap.md),
[member handoff](docs/runbooks/03-members-and-ai-observers.md) and
[activation restart](docs/runbooks/32-activation-restart.md) runbooks.

OIDC mode requires issuer discovery, exact redirect registration, a secret file, and a
company-administrator-confirmed link between the exact external issuer/subject and an
existing member.
The client secret must be 32 through 4096 UTF-8 bytes after trailing whitespace is removed;
its regular file may contain at most 4098 bytes, including an optional CRLF. Keep it out of
world-readable files and finish provisioning before startup: an
`.initialization-incomplete` marker in its directory blocks loading. The server opens the
file without following a final symlink; approved runtime group-read access remains supported.
BoardAgent never provisions a member from an unrecognized OIDC subject. Provider-specific
claims—including UAE Pass suitability—must be separately validated before use; this
repository makes no provider certification claim.

Apply a client allowlist only to exact identifiers you have verified. Do not trust a
displayed app name or a self-asserted client label. An allowlist does not replace
qualification of your deployment's outbound transport.

The supplied Caddyfile defines the supported edge configuration. An alternate reverse
proxy must
preserve the exact Host and HTTPS origin, replace—not append to—untrusted forwarding
headers, set the configured proxy-hop count exactly, stream request/response bodies without
reinterpretation, preserve the MCP path, enforce equivalent size/time limits and security
headers, expose no internal port, and pass the full browser/OAuth/MCP net. Until that is
proved and recorded in an ADR, it is outside the verified deployment profile.

## Runtime operation

The server and worker handle `SIGTERM` and have a 30-second Compose grace period. During
maintenance, stop new edge traffic, wait for readiness/drain evidence, then stop processes.
Never kill PostgreSQL during a migration, backup boundary capture, or restore receipt.

Monitor:

- `/health/live` and `/health/ready` separately;
- container restarts and crash loops;
- PostgreSQL availability, storage, locks, and connection pressure;
- worker lease/heartbeat health and overdue jobs;
- clock health and audit-checkpoint age;
- failed or dead-lettered notifications;
- export size/age and cleanup backlog;
- backup/WAL freshness and restore-test age;
- key expiry/retirement/compromise state;
- HTTPS certificate and DNS state.

Logs are operational signals, not the governance record. Keep them access-controlled and
do not increase logging to include tokens, confirmation payloads, document content, or
secret material.

Canonical document versions are at most 10 MiB and accept only reviewed Markdown, plain
text, or declared strict JSON. The hardened-beta capacity objective—not a scale promise—is
25 boards, 1,000 seats, 100 concurrent MCP requests, 100,000 document versions, and one
million audit plus one million feed events. Exceeding it requires load evidence and an
architecture decision, not merely a larger VPS.

MCP HTTP requests have a 61 MiB wire ceiling: up to six JSON wire bytes for each byte
of the 10 MiB canonical source, plus a 1 MiB envelope allowance. Public certificate
verification remains capped at 1 MiB. Each HTTP runtime reserves at most 64 MiB of
in-flight body bytes; declared lengths reserve before reading and chunked requests
reserve as bytes arrive. Capacity exhaustion returns 503 with Retry-After: 1;
over-limit requests return 413. Early connection closure can surface as an upload error
in some clients. Never retry a binding action without checking its idempotent result.

Reservations release on completion, parsing/dispatch failure and connection interruption,
including interrupted response backpressure. This bounds retained wire payloads, not
process memory: decoding, JSON objects and database work add allocations. Load and
memory qualification of your deployment remain required; the 100-request objective is
unchanged.

Resource reads record preparation, and the HTTP transport observer records completion
or interruption as the server sees it. Do not use the inbound byte reservation or the
configured export chunk size as evidence of a safe total memory bound; see the response
memory policy in [known limitations](docs/KNOWN_LIMITATIONS.md).

## Upgrade and rollback

1. Freeze the candidate source and run the complete required verification tier.
2. Capture and verify a fresh logical backup, physical base backup, WAL continuity, and
   off-host copy before migration.
3. Record current image IDs, source digest, migration head, registry digest, and readiness.
4. Build/obtain candidate images bound to the new source digest and verify all three.
5. Drain traffic and stop both server and worker. Keep PostgreSQL and recovery controls
   running, apply the candidate's complete migration bundle once, then start the candidate
   server and worker together. Follow the [upgrade runbook](docs/runbooks/23-migrations-upgrade-rollback.md).
6. Verify readiness, worker job/alert state and synthetic role journeys before reopening
   traffic. A successful foreground action alone does not prove background work succeeded.
7. Record the post-upgrade evidence receipt.

Upgrades through migrations 0161–0163 preserve question and minutes history while
correcting how feed entries link to audit evidence. Migration 0163 retires only pending
signature/re-sign requests bound to a provably superseded minutes package. It changes
their disposition and feed-sync metadata; it does not delete notices, signatures or audit
records. Apply the complete ordered bundle through the supported initializer, rather
than running selected SQL files or manually changing pending actions. Check feed
consistency and verify that current signature requests remain available after upgrading.

Migrations are forward-fix by default. Do not run an older application against a newer
schema unless the release evidence explicitly proves that exact pairing. A rollback that
requires schema reversal is a recovery event: restore the pre-upgrade backup into an
isolated target, verify it, then deliberately cut over. Never improvise down-migrations.

## Backup, PITR, and restore

Use [docs/runbooks/22-backup-pitr-restore.md](docs/runbooks/22-backup-pitr-restore.md) for
the complete ceremony. The operator CLI exposes distinct commands for logical backup,
physical base backup, WAL archival, PITR preparation, and restore verification. A backup
is not accepted merely because a file exists: require its manifest, encryption key ID,
hashes, database boundary, image digest, and a successfully persisted receipt.

Restores happen into an exact empty isolated target. `base-restore-check` verifies and
extracts but deliberately reports `ready: false` until isolated PostgreSQL start and WAL
replay are completed. `restore-check` verifies the restored governance/audit/evidence set
and records the restore receipt. Never point a test restore at the live data directory.
The frozen production objectives are RPO 15 minutes and RTO 4 hours, supported by continuous
encrypted WAL, daily encrypted off-host base backup, 7 daily/4 weekly/12 monthly generations,
and a quarterly clean-room full restore. These are objectives to measure in exercises, not
guarantees.

## Shutdown and decommissioning

No v1 command physically purges governance records. A service shutdown or member removal
does not erase evidence. Before decommissioning, complete a final verified system export,
logical backup, physical backup, WAL archive boundary, key inventory, and custody handoff.
Retain or destroy host volumes and keys only under a separately approved records and legal
process; those actions are outside BoardAgent's v1 application workflow.

## Go-live decision

No version of BoardAgent carries a qualified release label. A deployment for real use
needs all deterministic verification tiers (T0 to T9) green on an unchanged source tree
and production acceptance (Gate 3) signed for that exact source. Public-production
language also requires the independent T10 review. Any missing, skipped, stale, or
quarantined evidence is a blocker, not a pass.

Before the first authorized private deployment, confirm and record:

- [ ] Production acceptance (Gate 3) signed for the exact manifest and release label.
- [ ] All three immutable image IDs/source labels and SBOM/scan receipts match.
- [ ] DNS, TLS, origin, proxy count, firewall, internal PostgreSQL network, and host clock
      pass.
- [ ] All database and purpose secrets are nondefault, distinct, owner-only, backed up under
      the custody plan, and runtime key IDs are registered.
- [ ] Built-in or OIDC login, unknown identity, recovery, session/client revocation, and
      onboarding work with synthetic principals.
- [ ] One modern action-capable client and the frozen compatibility clients pass their exact
      read/action limits; test clients are blocked or removed.
- [ ] Unsupported content rejection leaves no durable bytes and no outbound provider exists.
- [ ] Webhooks remain off, or their SSRF/secret/delivery controls are commissioned.
- [ ] Audit/certificate export verifies offline with independently held public keys.
- [ ] Logical backup, physical backup, WAL continuity, and clean-room restore receipts are
      current and off-host.
- [ ] Alert routes, security contact, secretariat support, incident owner, capacity thresholds,
      and recovery responsibilities are exercised.
- [ ] Known limitations—including client/agent memory risk and no comprehension/legal-effect
      claim—have been presented to participants.

For a handover to a real board, record each installation separately. Retain a separate
setup administrator and end its extra board seat through the supported handoff. Record
the actual enrolled and onboarded people and their role journeys, the reviewed charter,
the exact installed version, operator contacts and recovery custody. A disposable test
database or a scripted signature does not complete that handover.

Public-production language additionally requires an independent T10 receipt bound to the
exact source. Deployment remains a separately authorized external action.

The full verifier writes a release manifest, evidence ledger, outcome comparison, and
human-readable handoff beside its immutable result receipt. `goLiveAuthorized` remains
`false` and `gate3Decision` remains `pending` until the project owner makes the exact
decision; generated evidence never self-approves a release. The pack cross-binds the exact
commit, unchanged clean worktree, frozen surface counts, registry, lockfile, toolchain,
image scan, mutation report and deterministic test summaries. Any mismatch blocks the
release and makes the verifier exit unsuccessfully.
