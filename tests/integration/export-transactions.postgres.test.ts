import { createCipheriv, createDecipheriv, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool, Query } from "pg";
import { describe, expect, it, vi } from "vitest";

import {
  BoardAgentCoreWorkerHandlers,
  BoardAgentTypedWorker,
  TypedJobExecutionError,
  LocalExportArtifactStore,
  decryptExportEnvelope,
  loadBoardAgentKeyMaterial,
  type BoardAgentRuntimeBinding
} from "../../artifacts/server/src/index.js";
import { parseConfig } from "../../lib/config/src/index.js";
import { verifyOfflineAuditExport } from "../../lib/audit/src/index.js";
import { UuidV7Schema, canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  confirmExportRequestInTransaction,
  claimTypedJobInTransaction,
  completeTypedJobInTransaction,
  ExportArtifactManifestSchema,
  buildFrozenExportSnapshotInTransaction,
  enqueueRequestJobInTransaction,
  migrate,
  stageExportRequestInTransaction,
  scheduleAuditCheckpointInTransaction,
  runOperationalRetentionInTransaction,
  verifyPersistedAuditEvidence,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { fixtureExportAttestation } from "../helpers/export-attestation-fixture.js";
import { runOperator } from "../../scripts/src/operator.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_exports_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "export-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

const capabilities = { elicitation: { form: {} } };
const originalArguments = { first_sequence: "1", last_sequence: "2" };

// A recipient has the data key. Authentication of the exported records must survive
// that recipient rewriting the encrypted container, not just random ciphertext damage.
function rewriteEncryptedPackage(
  encrypted: Buffer,
  key: Uint8Array,
  mutate: (value: Record<string, unknown>) => void
): Buffer {
  const headerStart = Buffer.byteLength("BOARDAGENT-EXPORT-AES256GCM-V1\n") + 4;
  const headerLength = encrypted.readUInt32BE(headerStart - 4);
  const headerBytes = encrypted.subarray(headerStart, headerStart + headerLength);
  const header = JSON.parse(headerBytes.toString("utf8")) as {
    nonce: string;
    snapshotSha256: string;
  };
  const nonce = Buffer.from(header.nonce, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(headerBytes);
  decipher.setAuthTag(encrypted.subarray(-16));
  const plaintext = Buffer.concat([
    decipher.update(encrypted.subarray(headerStart + headerLength, -16)),
    decipher.final()
  ]);
  const value = JSON.parse(plaintext.toString("utf8")) as Record<string, unknown>;
  mutate(value);
  const snapshot = value["snapshot"] as Record<string, unknown>;
  snapshot["scopeSha256"] = canonicalSha256(value["scope"] as never);
  header.snapshotSha256 = canonicalSha256(snapshot as never);
  const newHeaderBytes = Buffer.from(canonicalJson(header));
  const newHeaderLength = Buffer.alloc(4);
  newHeaderLength.writeUInt32BE(newHeaderBytes.length);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(newHeaderBytes);
  const rewritten = Buffer.concat([cipher.update(canonicalJson(value as never)), cipher.final()]);
  return Buffer.concat([
    encrypted.subarray(0, headerStart - 4),
    newHeaderLength,
    newHeaderBytes,
    rewritten,
    cipher.getAuthTag()
  ]);
}

describe("frozen repeatable-read export transaction", () => {
  it.each([
    "normal",
    "wrong_instance",
    "hidden_corruption",
    "lag_projection",
    "lag_retry_exhausted",
    "lag_retained_job_expired",
    "checkpoint_permanent",
    "job_scope_mismatch"
  ] as const)("verifies export completion and preparation failure: %s", async (mode) => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["audit:read", "secretariat:admin"],
        isSecretary: true
      });
      const authSessionId = testId(40_000);
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://client.example',
                   transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [authSessionId, actor.organizationId, testHash(40), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        authSessionId,
        actor.accessTokenRecordId
      ]);
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','Export integration authority')`,
        [testId(40_001), actor.organizationId, actor.memberId]
      );
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: actor.organizationId,
              event: {
                eventId: testId(40_002),
                eventType: "context_read",
                actorMemberId: actor.memberId,
                actorClientId: actor.clientId,
                tokenJti: actor.tokenJti,
                entityType: "context",
                entityId: testId(40_003),
                boardId: actor.boardId,
                origin: "mcp",
                details: { result: "authorized" },
                schemaVersion: 1
              }
            },
            {
              organizationId: actor.organizationId,
              event: {
                eventId: testId(40_004),
                eventType: "context_read",
                actorMemberId: actor.memberId,
                actorClientId: actor.clientId,
                tokenJti: actor.tokenJti,
                entityType: "context",
                entityId: testId(40_005),
                boardId: null,
                origin: "mcp",
                details: { result: "synthetic organization-only record" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );

      const scope = {
        schemaVersion: "boardagent.export-scope.v1" as const,
        exportType: "audit_chain" as const,
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        firstSequence: "1",
        lastSequence: "2",
        includeCheckpoints: true as const,
        includePublicKeys: true as const
      };
      const stageInput = {
        exportRequestId: testId(40_010),
        publicId: Buffer.alloc(32, 41),
        scope,
        stage: {
          stageId: testId(40_011),
          inputRequiredAttemptId: testId(40_012),
          nonce: Buffer.alloc(32, 42),
          confirmationCode: "EXP7K2Q9",
          accessTokenRecordId: actor.accessTokenRecordId,
          exactOrigin: "https://client.example",
          originalArguments,
          clientCapabilities: capabilities,
          embeddedForm: { type: "object", required: ["approve", "confirmation_code"] },
          embeddedResult: { message: "Confirm exact frozen audit export", code: "EXP7K2Q9" },
          requestStateBytes: Buffer.alloc(48, 43),
          preparedRequestId: Buffer.from("prepared-export-request"),
          auditEventIds: {
            stageReplaced: testId(40_013),
            stageCreated: testId(40_014),
            elicitationSent: testId(40_015)
          }
        }
      };
      const staged = await withRequestTransaction(
        pool,
        actor.context,
        (client) => stageExportRequestInTransaction(client, stageInput),
        { assumeRole: "boardagent_server" }
      );
      expect(staged.scopeSha256).toBe(canonicalSha256(scope));

      const confirmed = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          confirmExportRequestInTransaction(client, {
            exportRequestId: stageInput.exportRequestId,
            jobId: testId(40_020),
            jobIdempotencyKey: "export-build-job-0001",
            exportRequestedAuditEventId: testId(40_021),
            confirmation: {
              stageId: staged.stageId,
              consentRecordId: testId(40_022),
              retryRequestId: Buffer.from("retry-export-confirm"),
              originalArguments,
              clientCapabilities: capabilities,
              exactOrigin: "https://client.example",
              requestStateBytes: stageInput.stage.requestStateBytes,
              responseAction: "accept",
              inputResponse: { approve: true, confirmation_code: "EXP7K2Q9" },
              auditEventIds: {
                consentRecorded: testId(40_023),
                consentRejected: testId(40_024)
              }
            }
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(confirmed.confirmed).toBe(true);
      if (!confirmed.confirmed) throw new Error("export confirmation unexpectedly failed");
      expect(confirmed.value).toMatchObject({
        exportRequestId: stageInput.exportRequestId,
        state: "queued",
        jobId: testId(40_020)
      });

      const evidence = generateKeyPairSync("ed25519");
      const evidenceKeyId = testId(40_030);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
         ) values ($1,$2,'export-checkpoint-key','evidence_signing','EdDSA',$3,
                   'local-export-checkpoint',transaction_timestamp()-interval '1 minute')`,
        [evidenceKeyId, actor.organizationId, evidence.publicKey.export({ format: "jwk" })]
      );
      expect(
        (await pool.query("select count(*)::int as count from audit_checkpoints")).rows[0]?.count
      ).toBe(0);

      const encryptionKeyId = testId(40_050);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,nonsecret_locator,activated_at
         ) values ($1,$2,'export-data-key','data_kek','A256GCM','local-export-data-key',
                   transaction_timestamp()-interval '1 minute')`,
        [encryptionKeyId, actor.organizationId]
      );
      const artifactRoot = await mkdtemp(path.join(tmpdir(), "boardagent-export-worker-"));
      try {
        const config = parseConfig({
          BOARDAGENT_ENV: "test",
          BOARDAGENT_DATABASE_URL: "postgresql://unused",
          BOARDAGENT_ORGANIZATION_ID: actor.organizationId,
          BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
          BOARDAGENT_AUTHORIZATION_MODE: "builtin",
          BOARDAGENT_BLOB_ROOT: artifactRoot,
          BOARDAGENT_DEV_MASTER_SECRET: "export-worker-test-secret-material-is-long-enough",
          BOARDAGENT_EXPORT_MAX_BYTES: "10485760",
          BOARDAGENT_EXPORT_CHUNK_BYTES: "65536"
        });
        const keys = await loadBoardAgentKeyMaterial(config);
        const binding: BoardAgentRuntimeBinding = {
          instanceId: testId(15),
          organizationId: actor.organizationId,
          canonicalResourceUri: "https://boardagent.test/mcp",
          keyIds: {
            oauth_signing: testId(8),
            evidence_signing: evidenceKeyId,
            browser_session: testId(40_049),
            data_kek: encryptionKeyId
          },
          keyLocators: {
            oauth_signing: "test:oauth",
            evidence_signing: "local-export-checkpoint",
            browser_session: "test:browser",
            data_kek: "local-export-data-key"
          }
        };
        const store = new LocalExportArtifactStore(artifactRoot, {
          maximumArtifactBytes: config.exportMaximumBytes,
          chunkBytes: config.exportChunkBytes
        });
        let nextId = 40_040;
        const alerts: string[] = [];
        const handlerPool =
          mode === "lag_projection" ||
          mode === "lag_retry_exhausted" ||
          mode === "lag_retained_job_expired"
            ? new Proxy(pool, {
                get(target, key) {
                  if (key === "connect")
                    return async () => {
                      const client = await target.connect();
                      return new Proxy(client, {
                        get(connection, property) {
                          if (property === "query")
                            return (...args: unknown[]) => {
                              const query = args[0];
                              if (query instanceof Query) {
                                // Controlled verifier-clock projection only. Real rows/hashes/
                                // signatures remain unchanged; this is not a16-minute outage trial.
                                query.prependListener(
                                  "row",
                                  (row: {
                                    stream_kind: number;
                                    metadata: Record<string, unknown>;
                                  }) => {
                                    if (row.stream_kind === 0)
                                      row.metadata["now"] = new Date(
                                        Date.parse(String(row.metadata["now"])) + 16 * 60 * 1000
                                      ).toISOString();
                                  }
                                );
                              }
                              return Reflect.apply(connection.query, connection, args);
                            };
                          const value: unknown = Reflect.get(connection, property);
                          return typeof value === "function" ? value.bind(connection) : value;
                        }
                      });
                    };
                  const value: unknown = Reflect.get(target, key);
                  return typeof value === "function" ? value.bind(target) : value;
                }
              })
            : pool;
        const core = new BoardAgentCoreWorkerHandlers(handlerPool, {
          config,
          binding: mode === "wrong_instance" ? { ...binding, instanceId: testId(40_099) } : binding,
          onOperationalAlert: (alertClass) => {
            alerts.push(alertClass);
          },
          keys: { ...keys, evidencePrivateKey: evidence.privateKey },
          exportArtifacts: store,
          newId: () => testId(nextId++),
          randomBytes: (length) => Buffer.alloc(length, 0x73),
          assumeRole: "boardagent_worker"
        });
        if (mode === "checkpoint_permanent") {
          // Controlled permanent failure at the pre-snapshot checkpoint boundary.
          // Actual worker claim, request failure transaction and audit remain real.
          vi.spyOn(
            core as unknown as { signCurrentAuditHead(): Promise<unknown> },
            "signCurrentAuditHead"
          ).mockRejectedValueOnce(
            new TypedJobExecutionError("audit_checkpoint_binding_mismatch", true)
          );
        }
        const handlers = core.handlers();
        const workerHandlers = new Map(handlers);
        if (mode === "job_scope_mismatch") {
          const original = handlers.get("export_build")!;
          // Controlled worker-message corruption after an actual claim. The real
          // request/snapshot scope must win, with no stranded running export.
          workerHandlers.set("export_build", (context) =>
            original({
              ...context,
              job: {
                ...context.job,
                envelope: { ...context.job.envelope, boardId: UuidV7Schema.parse(testId(40_098)) }
              }
            })
          );
        }
        const worker = new BoardAgentTypedWorker(pool, {
          handlers: workerHandlers,
          workerId: "export-worker-integration-test",
          assumeRole: "boardagent_worker"
        });
        if (mode !== "normal") {
          if (mode === "hidden_corruption") {
            const client = await pool.connect();
            try {
              await client.query("begin");
              await client.query("set local session_replication_role=replica");
              const row = (
                await client.query("select canonical_payload from audit_events where id=$1", [
                  testId(40_004)
                ])
              ).rows[0]!;
              const body = JSON.parse((row.canonical_payload as Buffer).toString("utf8")) as Record<
                string,
                unknown
              >;
              body["details"] = { changed: true };
              await client.query("update audit_events set canonical_payload=$2 where id=$1", [
                testId(40_004),
                Buffer.from(canonicalJson(body as never))
              ]);
              await client.query("commit");
            } catch (error) {
              await client.query("rollback");
              throw error;
            } finally {
              client.release();
            }
          }
          if (mode === "lag_retry_exhausted" || mode === "lag_retained_job_expired") {
            expect(
              (
                await pool.query(`select
              has_function_privilege('boardagent_worker','public.boardagent_stopped_export_requests(uuid)','execute') as worker,
              has_function_privilege('boardagent_server','public.boardagent_stopped_export_requests(uuid)','execute') as server,
              has_function_privilege('boardagent_backup','public.boardagent_stopped_export_requests(uuid)','execute') as backup,
              has_table_privilege('boardagent_worker','public.jobs','select') as queue_read`)
              ).rows[0]
            ).toEqual({ worker: true, server: false, backup: false, queue_read: false });
            await expect(
              withWorkerTransaction(
                pool,
                (client) =>
                  client.query("select * from public.boardagent_stopped_export_requests($1)", [
                    actor.organizationId
                  ]),
                { assumeRole: "boardagent_worker" }
              )
            ).rejects.toMatchObject({ code: "25000" });
            await expect(
              withWorkerTransaction(
                pool,
                (client) =>
                  client.query("select * from public.boardagent_stopped_export_requests($1)", [
                    testId(910_999)
                  ]),
                { assumeRole: "boardagent_worker", isolation: "serializable" }
              )
            ).rejects.toMatchObject({ code: "22023" });
            let reconciliation = 0;
            const reconcile = async () => {
              reconciliation += 1;
              const jobId = testId(910_000 + reconciliation);
              await withRequestTransaction(
                pool,
                actor.context,
                (client) =>
                  enqueueRequestJobInTransaction(client, {
                    jobId,
                    idempotencyKey: `export-dead-reconcile-${reconciliation}`,
                    envelope: {
                      schemaVersion: "boardagent.job.export_reconcile.v1",
                      organizationId: actor.organizationId,
                      boardId: null,
                      jobType: "export_reconcile",
                      subjectType: "organization",
                      subjectId: actor.organizationId,
                      parameters: {}
                    }
                  }),
                { assumeRole: "boardagent_server" }
              );
              expect(await worker.runOnce()).toMatchObject({
                status: "succeeded",
                jobId,
                jobType: "export_reconcile"
              });
            };
            expect(await worker.runOnce()).toMatchObject({ status: "retry_scheduled", attempt: 1 });
            await reconcile();
            expect(
              (
                await pool.query("select state from export_requests where id=$1", [
                  stageInput.exportRequestId
                ])
              ).rows[0]
            ).toEqual({ state: "queued" });
            expect(alerts).not.toContain("export_preparation_failed");
            // Execute all real attempts; only the backoff clock is advanced by the
            // disposable owner. This is not a four-hour elapsed outage exercise.
            for (let attempt = 2; attempt <= 10; attempt += 1) {
              await pool.query(
                "update jobs set available_at=transaction_timestamp()-interval '1 second' where id=$1",
                [testId(40_020)]
              );
              expect(await worker.runOnce()).toMatchObject({
                status: attempt === 10 ? "dead" : "retry_scheduled",
                attempt,
                errorClass: "export_audit_checkpoint_overdue"
              });
            }
            if (mode === "lag_retry_exhausted") {
              const replacementId = testId(920_000);
              await withRequestTransaction(
                pool,
                actor.context,
                (client) =>
                  enqueueRequestJobInTransaction(client, {
                    jobId: replacementId,
                    idempotencyKey: "export-live-replacement",
                    availableAt: new Date(Date.now() + 60_000).toISOString(),
                    envelope: {
                      schemaVersion: "boardagent.job.export_build.v1",
                      organizationId: actor.organizationId,
                      boardId: actor.boardId,
                      jobType: "export_build",
                      subjectType: "export_request",
                      subjectId: stageInput.exportRequestId,
                      parameters: { exportRequestId: stageInput.exportRequestId }
                    }
                  }),
                { assumeRole: "boardagent_server" }
              );
              await reconcile();
              expect(
                (
                  await pool.query("select state from export_requests where id=$1", [
                    stageInput.exportRequestId
                  ])
                ).rows[0]
              ).toEqual({ state: "queued" });
              await pool.query(
                "update jobs set available_at=transaction_timestamp()-interval '1 second' where id=$1",
                [replacementId]
              );
              const claim = await withWorkerTransaction(
                pool,
                (client) =>
                  claimTypedJobInTransaction(client, {
                    leaseOwner: "export-live-replacement",
                    leaseSeconds: 120
                  }),
                { assumeRole: "boardagent_worker" }
              );
              if (!claim.claimed) throw new Error("replacement export job was not claimed");
              expect(claim.job.jobId).toBe(replacementId);
              await reconcile();
              expect(
                (
                  await pool.query("select state from export_requests where id=$1", [
                    stageInput.exportRequestId
                  ])
                ).rows[0]
              ).toEqual({ state: "queued" });
              expect(alerts).not.toContain("export_preparation_failed");
              expect(
                await withWorkerTransaction(
                  pool,
                  (client) =>
                    completeTypedJobInTransaction(client, {
                      jobId: claim.job.jobId,
                      leaseOwner: claim.job.leaseOwner,
                      attempt: claim.job.attempt,
                      leaseToken: claim.job.leaseToken,
                      result: "permanent_failure",
                      errorClass: "synthetic_replacement_failure",
                      resultSha256: canonicalSha256({ result: "synthetic_replacement_failure" })
                    }),
                  { assumeRole: "boardagent_worker" }
                )
              ).toMatchObject({ completed: true, state: "dead" });
            }
            if (mode === "lag_retained_job_expired") {
              // Controlled aging only; execute the actual30-day operational retention
              // function and preserve permanent request/audit rows.
              await pool.query(
                "update jobs set completed_at=transaction_timestamp()-interval '31 days' where id=$1",
                [testId(40_020)]
              );
              const aging = await pool.connect();
              try {
                await aging.query("begin");
                // Disposable owner aging fixture, not a supported mutation of the
                // immutable request. The real retention/reconciliation calls follow.
                await aging.query("set local session_replication_role=replica");
                await aging.query(
                  "update export_requests set created_at=transaction_timestamp()-interval '32 days',expires_at=transaction_timestamp()-interval '31 days' where id=$1",
                  [stageInput.exportRequestId]
                );
                await aging.query("commit");
              } catch (error) {
                await aging.query("rollback");
                throw error;
              } finally {
                aging.release();
              }
              expect(
                await withWorkerTransaction(
                  pool,
                  (client) =>
                    runOperationalRetentionInTransaction(client, {
                      jobType: "job_retention",
                      organizationId: actor.organizationId,
                      limit: 100
                    }),
                  { assumeRole: "boardagent_worker" }
                )
              ).toMatchObject({ deletedJobs: 1, deletedJobAttempts: 10 });
              expect(
                (
                  await pool.query("select count(*)::int as count from jobs where id=$1", [
                    testId(40_020)
                  ])
                ).rows[0]?.count
              ).toBe(0);
            }
            await reconcile();
            expect(
              (
                await pool.query(
                  "select state,failure_class,snapshot_manifest from export_requests where id=$1",
                  [stageInput.exportRequestId]
                )
              ).rows[0]
            ).toEqual({
              state: "failed",
              failure_class: "export_build_stopped",
              snapshot_manifest: null
            });
            expect(
              (
                await pool.query(
                  "select count(*)::int as count from audit_events where event_type='export_failed' and object_id=$1",
                  [stageInput.exportRequestId]
                )
              ).rows[0]?.count
            ).toBe(1);
            expect(alerts.filter((value) => value === "export_preparation_failed")).toHaveLength(1);
            await reconcile();
            expect(
              (
                await pool.query(
                  "select count(*)::int as count from audit_events where event_type='export_failed' and object_id=$1",
                  [stageInput.exportRequestId]
                )
              ).rows[0]?.count
            ).toBe(1);
            expect(alerts.filter((value) => value === "export_preparation_failed")).toHaveLength(1);
            expect(await store.scanArtifacts()).toEqual([]);
            return;
          }
          if (mode === "lag_projection") {
            expect(await worker.runOnce()).toMatchObject({
              status: "retry_scheduled",
              jobType: "export_build",
              errorClass: "export_audit_checkpoint_overdue"
            });
            expect(
              (
                await pool.query(
                  "select state,snapshot_manifest,started_at from export_requests where id=$1",
                  [stageInput.exportRequestId]
                )
              ).rows[0]
            ).toEqual({ state: "queued", snapshot_manifest: null, started_at: null });
            expect(
              (
                await pool.query(
                  "select count(*)::int as count from audit_events where event_type='export_failed'"
                )
              ).rows[0]?.count
            ).toBe(0);
            expect(await store.scanArtifacts()).toEqual([]);
            expect(alerts).not.toContain("export_preparation_failed");
            return;
          }
          const errorClass =
            mode === "checkpoint_permanent"
              ? "audit_checkpoint_binding_mismatch"
              : mode === "wrong_instance"
                ? "export_attestation_binding_mismatch"
                : mode === "job_scope_mismatch"
                  ? "export_build_scope_mismatch"
                  : "export_audit_evidence_invalid";
          expect(await worker.runOnce()).toMatchObject({
            status: "dead",
            jobType: "export_build",
            errorClass
          });
          expect(
            (
              await pool.query(
                "select state,failure_class,snapshot_manifest,started_at from export_requests where id=$1",
                [stageInput.exportRequestId]
              )
            ).rows[0]
          ).toEqual({
            state: "failed",
            failure_class: errorClass,
            snapshot_manifest: null,
            started_at: null
          });
          expect(
            (await pool.query("select count(*)::int as count from export_artifacts")).rows[0]?.count
          ).toBe(0);
          expect(await store.scanArtifacts()).toEqual([]);
          expect(alerts).toContain("export_preparation_failed");
          expect(
            (
              await pool.query(
                "select count(*)::int as count from audit_events where event_type='export_failed' and object_id=$1",
                [stageInput.exportRequestId]
              )
            ).rows[0]?.count
          ).toBe(1);
          return;
        }
        const deferredBuildAvailableAt = new Date(Date.now() + 24 * 60 * 60 * 1_000).toISOString();
        const scheduled = await withWorkerTransaction(
          pool,
          (client) => scheduleAuditCheckpointInTransaction(client, testId(400_000)),
          { assumeRole: "boardagent_worker" }
        );
        expect(scheduled.scheduling_status).toBe("scheduled");
        const checkpointWorker = new BoardAgentTypedWorker(pool, {
          handlers,
          workerId: "export-concurrent-checkpoint-worker",
          assumeRole: "boardagent_worker"
        });
        // Both jobs are claimed through normal exclusive leases; export's own signing
        // transaction races a separately produced checkpoint through the same head lock.
        expect(await Promise.all([worker.runOnce(), checkpointWorker.runOnce()])).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              status: "succeeded",
              jobId: testId(40_020),
              jobType: "export_build"
            }),
            expect.objectContaining({
              status: "succeeded",
              jobId: scheduled.result_job_id,
              jobType: "audit_checkpoint"
            })
          ])
        );
        expect(
          await withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).toMatchObject({ valid: true, ready: true, checkpointCount: 2 });
        // The runtime role must retrieve its own completed output, not merely
        // leave evidence that the worker wrote it under a privileged connection.
        const knownArtifactId = (
          await pool.query<{ id: string }>(
            "select id from export_artifacts where export_request_id=$1",
            [stageInput.exportRequestId]
          )
        ).rows[0]!.id;
        const visibleOutput = (context: typeof actor.context) =>
          withRequestTransaction(
            pool,
            context,
            async (client) => {
              const artifacts = await client.query(
                "select id from export_artifacts where export_request_id=$1",
                [stageInput.exportRequestId]
              );
              const chunks = await client.query(
                "select id from export_chunks where artifact_id=$1",
                [knownArtifactId]
              );
              return { artifacts: artifacts.rowCount, chunks: chunks.rowCount };
            },
            { assumeRole: "boardagent_server" }
          );
        const ownOutput = await visibleOutput(actor.context);
        expect(ownOutput.artifacts).toBe(1);
        expect(ownOutput.chunks).toBeGreaterThan(0);
        for (const context of [
          { ...actor.context, memberId: testId(49_901) },
          { ...actor.context, clientId: testId(49_902) },
          { ...actor.context, tokenJti: testId(49_903) },
          { ...actor.context, boardIds: [] }
        ])
          expect(await visibleOutput(context)).toEqual({ artifacts: 0, chunks: 0 });
        // Simulate lifecycle/time changes only inside a rolled-back owner fixture
        // transaction. Assertions themselves execute as the restricted server role.
        for (const scenario of [
          {
            table: "export_artifacts",
            sql: "update export_artifacts set created_at=transaction_timestamp()-interval '24 hours 1 second',expires_at=transaction_timestamp()-interval '1 second' where id=$1",
            id: knownArtifactId
          },
          {
            table: "export_requests",
            sql: "update export_requests set created_at=transaction_timestamp()-interval '2 hours',expires_at=transaction_timestamp()-interval '1 second' where id=$1",
            id: stageInput.exportRequestId
          },
          {
            table: "export_requests",
            sql: "update export_requests set state='deleted' where id=$1",
            id: stageInput.exportRequestId
          },
          {
            table: "auth_sessions",
            sql: "update auth_sessions set last_authenticated_at=transaction_timestamp()-interval '16 minutes' where id=$1",
            id: authSessionId
          },
          {
            table: "access_token_records",
            sql: "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
            id: actor.accessTokenRecordId
          },
          {
            table: "oauth_clients",
            sql: "update oauth_clients set state='suspended' where id=$1",
            id: actor.clientId
          }
        ]) {
          const rolledBack = new Error("rollback isolated expiry/revocation fixture");
          await expect(
            withRequestTransaction(pool, actor.context, async (client) => {
              await client.query(`alter table ${scenario.table} disable trigger user`);
              await client.query(scenario.sql, [scenario.id]);
              await client.query("set local role boardagent_server");
              expect(
                (
                  await client.query("select id from export_chunks where artifact_id=$1", [
                    knownArtifactId
                  ])
                ).rowCount,
                scenario.sql
              ).toBe(0);
              throw rolledBack;
            })
          ).rejects.toBe(rolledBack);
        }
        expect(await visibleOutput(actor.context)).toEqual(ownOutput);
        const artifact = await pool.query<{ manifest: Buffer }>(
          "select manifest from export_artifacts where export_request_id=$1",
          [stageInput.exportRequestId]
        );
        const artifactManifest = ExportArtifactManifestSchema.parse(
          JSON.parse(artifact.rows[0]!.manifest.toString("utf8"))
        );
        const encryptedBytes = Buffer.concat(
          await Promise.all(
            artifactManifest.chunks.map(async (chunk) =>
              Buffer.from(
                await store.readExactChunk({
                  exportRequestId: artifactManifest.exportRequestId,
                  artifactId: artifactManifest.artifactId,
                  ordinal: chunk.ordinal,
                  storageLocator: chunk.storageLocator,
                  byteLength: chunk.byteLength,
                  expectedSha256: chunk.chunkSha256
                })
              )
            )
          )
        );
        const decrypted = decryptExportEnvelope(encryptedBytes, keys.dataEncryptionKey);
        expect(decrypted.auditAttestation).toBeDefined();
        const missingProof = rewriteEncryptedPackage(
          encryptedBytes,
          keys.dataEncryptionKey,
          (value) => {
            expect(value["schemaVersion"]).toBe("boardagent.export-package.v2");
            delete value["auditAttestation"];
          }
        );
        expect(() => decryptExportEnvelope(missingProof, keys.dataEncryptionKey)).toThrow();
        const futureVersion = rewriteEncryptedPackage(
          encryptedBytes,
          keys.dataEncryptionKey,
          (value) => {
            value["schemaVersion"] = "boardagent.export-package.v999";
          }
        );
        expect(() => decryptExportEnvelope(futureVersion, keys.dataEncryptionKey)).toThrow();
        expect(decrypted.snapshot.scopeSha256).toBe(staged.scopeSha256);
        expect(decrypted.components.map(({ name }) => name)).toEqual([
          "audit:checkpoints",
          "audit:events",
          "audit:public_keys"
        ]);
        const eventComponent = decrypted.components.find(({ name }) => name === "audit:events");
        const checkpointComponent = decrypted.components.find(
          ({ name }) => name === "audit:checkpoints"
        );
        if (
          !eventComponent ||
          !checkpointComponent ||
          decrypted.scope.exportType !== "audit_chain"
        ) {
          throw new Error("audit export components are unavailable");
        }
        const checkpointRows = JSON.parse(checkpointComponent.bytes.toString("utf8")) as {
          rows: Record<string, unknown>[];
        };
        expect(checkpointRows.rows.length).toBeGreaterThan(0);
        for (const row of checkpointRows.rows) {
          expect(Object.keys(row).toSorted()).toEqual(
            [
              "id",
              "organization_id",
              "first_sequence",
              "last_sequence",
              "first_event_sha256",
              "last_event_sha256",
              "canonical_manifest",
              "manifest_sha256",
              "signature",
              "signing_key_id",
              "created_at"
            ].toSorted()
          );
        }
        const trustedEvidenceKeys = {
          schema_version: "boardagent.trusted-evidence-keys.v1" as const,
          keys: [
            {
              id: evidenceKeyId,
              kid: "export-checkpoint-key",
              algorithm: "EdDSA" as const,
              public_jwk: evidence.publicKey.export({ format: "jwk" })
            }
          ]
        };
        const offlineVerification = verifyOfflineAuditExport(
          eventComponent.bytes,
          checkpointComponent.bytes,
          {
            organizationId: decrypted.snapshot.organizationId,
            boardId: decrypted.snapshot.boardId,
            rangeFirstSequence: decrypted.scope.firstSequence,
            rangeLastSequence: decrypted.scope.lastSequence,
            auditHeadSequence: decrypted.snapshot.auditHeadSequence,
            auditHeadSha256: decrypted.snapshot.auditHeadSha256,
            latestCheckpointSha256: decrypted.snapshot.latestCheckpointSha256
          },
          trustedEvidenceKeys,
          {
            signed: decrypted.auditAttestation!,
            exportRequestId: decrypted.snapshot.exportRequestId,
            scopeSha256: decrypted.snapshot.scopeSha256,
            snapshotSha256: decrypted.header.snapshotSha256
          }
        );
        expect(offlineVerification.valid, JSON.stringify(offlineVerification)).toBe(true);
        expect(offlineVerification).toMatchObject({
          valid: true,
          eventCount: "2",
          firstSequence: "1",
          lastSequence: "2",
          checkpointCount: expect.any(Number),
          proof: "signed_export_snapshot",
          attestedRangeLastSequence: "2"
        });

        const encryptedExportFile = path.join(artifactRoot, "offline-audit-export.bin");
        const exportKeyFile = path.join(artifactRoot, "offline-audit-export.key");
        const trustedKeysFile = path.join(artifactRoot, "trusted-evidence-keys.json");
        await writeFile(encryptedExportFile, encryptedBytes, { mode: 0o600 });
        await writeFile(exportKeyFile, keys.dataEncryptionKey, { mode: 0o600 });
        await writeFile(trustedKeysFile, canonicalJson(trustedEvidenceKeys), {
          encoding: "utf8",
          mode: 0o600
        });
        const downgradedBytes = rewriteEncryptedPackage(
          encryptedBytes,
          keys.dataEncryptionKey,
          (value) => {
            value["schemaVersion"] = "boardagent.export-package.v1";
            delete value["auditAttestation"];
            const scope = value["scope"] as Record<string, unknown>;
            scope["boardId"] = null;
            scope["lastSequence"] = "1";
            const snapshot = value["snapshot"] as Record<string, unknown>;
            snapshot["boardId"] = null;
            const checkpointRows = JSON.parse(checkpointComponent.bytes.toString("utf8")) as {
              rows: { manifest_sha256: string }[];
            };
            snapshot["latestCheckpointSha256"] = checkpointRows.rows[0]!.manifest_sha256.slice(2);
            const components = value["components"] as Record<string, unknown>[];
            const events = components.find((c) => c["name"] === "audit:events")!;
            const eventValue = JSON.parse(
              Buffer.from(events["bytes"] as string, "base64url").toString("utf8")
            ) as { rows: unknown[] };
            eventValue.rows = eventValue.rows.slice(0, 1);
            const bytes = Buffer.from(canonicalJson(eventValue as never));
            Object.assign(events, {
              bytes: bytes.toString("base64url"),
              rowCount: "1",
              sha256: canonicalSha256(eventValue as never)
            });
            const descriptors = snapshot["components"] as Record<string, unknown>[];
            Object.assign(
              descriptors.find((c) => c["name"] === "audit:events")!,
              { rowCount: "1", byteLength: String(bytes.length), sha256: events["sha256"] }
            );
            snapshot["plaintextContentSetSha256"] = canonicalSha256({
              schemaVersion: "boardagent.export-content-set.v1",
              components: descriptors
            } as never);
          }
        );
        const downgraded = decryptExportEnvelope(downgradedBytes, keys.dataEncryptionKey);
        expect(
          verifyOfflineAuditExport(
            downgraded.components.find((c) => c.name === "audit:events")!.bytes,
            downgraded.components.find((c) => c.name === "audit:checkpoints")!.bytes,
            {
              organizationId: actor.organizationId,
              boardId: null,
              rangeFirstSequence: "1",
              rangeLastSequence: "1",
              auditHeadSequence: downgraded.snapshot.auditHeadSequence,
              auditHeadSha256: downgraded.snapshot.auditHeadSha256,
              latestCheckpointSha256: downgraded.snapshot.latestCheckpointSha256
            },
            trustedEvidenceKeys
          )
        ).toMatchObject({ valid: true });
        const downgradedFile = path.join(artifactRoot, "downgraded-export.bin");
        await writeFile(downgradedFile, downgradedBytes, { mode: 0o600 });
        const refusedOutput: string[] = [];
        expect(
          await runOperator(
            ["verify-chain", downgradedFile, exportKeyFile, trustedKeysFile],
            {},
            {
              stdout: (line) => refusedOutput.push(line),
              stderr: (line) => refusedOutput.push(line)
            }
          )
        ).toBe(1);
        expect(JSON.parse(refusedOutput.join(""))).toMatchObject({
          valid: false,
          reason: "legacy_export_attestation_required"
        });
        const offlineOutput: string[] = [];
        expect(
          await runOperator(
            ["verify-chain", encryptedExportFile, exportKeyFile, trustedKeysFile],
            {},
            {
              stdout: (line) => offlineOutput.push(line),
              stderr: (line) => offlineOutput.push(line)
            }
          )
        ).toBe(0);
        expect(JSON.parse(offlineOutput.join(""))).toMatchObject({
          schemaVersion: "boardagent.operator-chain-verification.v1",
          command: "verify-chain",
          valid: true,
          firstSequence: "1",
          lastSequence: "2",
          anchorSequence: offlineVerification.valid ? offlineVerification.anchorSequence : undefined
        });

        await pool.query(
          `update export_artifacts
              set created_at=transaction_timestamp()-interval '25 hours',
                  expires_at=transaction_timestamp()-interval '1 hour'
            where id=$1`,
          [artifactManifest.artifactId]
        );
        const expiryJobId = testId(40_900);
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId: expiryJobId,
              idempotencyKey: "export-artifact-expiry-integration",
              envelope: {
                schemaVersion: "boardagent.job.export_artifact_expiry.v1",
                organizationId: actor.organizationId,
                boardId: null,
                jobType: "export_artifact_expiry",
                subjectType: "organization",
                subjectId: actor.organizationId,
                parameters: {}
              }
            }),
          { assumeRole: "boardagent_server" }
        );
        expect(await worker.runOnce()).toMatchObject({
          status: "succeeded",
          jobId: expiryJobId,
          jobType: "export_artifact_expiry"
        });
        const stored = await pool.query<{
          artifact_state: string;
          chunks: string;
          is_expired: boolean;
          request_state: string;
        }>(
          `select request.state as request_state,artifact.state as artifact_state,
                  artifact.expires_at<=transaction_timestamp() as is_expired,
                  count(chunk.id)::text as chunks
             from export_requests as request
             join export_artifacts as artifact on artifact.export_request_id=request.id
             join export_chunks as chunk on chunk.artifact_id=artifact.id
            where request.id=$1
            group by request.state,artifact.state,artifact.expires_at`,
          [stageInput.exportRequestId]
        );
        expect(stored.rows[0]).toEqual({
          artifact_state: "deleted",
          chunks: artifactManifest.chunks.length.toString(10),
          is_expired: true,
          request_state: "deleted"
        });
        await expect(
          store.readExactChunk({
            exportRequestId: artifactManifest.exportRequestId,
            artifactId: artifactManifest.artifactId,
            ordinal: artifactManifest.chunks[0]!.ordinal,
            storageLocator: artifactManifest.chunks[0]!.storageLocator,
            byteLength: artifactManifest.chunks[0]!.byteLength,
            expectedSha256: artifactManifest.chunks[0]!.chunkSha256
          })
        ).rejects.toThrow();

        const crashRequestId = testId(40_910);
        await pool.query(
          `insert into export_requests(
             id,public_id,organization_id,board_id,requester_member_id,export_type,
             scope_manifest,scope_sha256,state,consent_record_id,recent_auth_at,expires_at
           )
           select $1,$2,organization_id,board_id,requester_member_id,export_type,
                  scope_manifest,scope_sha256,'queued',consent_record_id,
                  transaction_timestamp(),transaction_timestamp()+interval '24 hours'
             from export_requests where id=$3`,
          [crashRequestId, Buffer.alloc(32, 0x55), stageInput.exportRequestId]
        );
        const abandonedBuildJobId = testId(40_911);
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId: abandonedBuildJobId,
              idempotencyKey: "export-abandoned-build-integration",
              availableAt: deferredBuildAvailableAt,
              envelope: {
                schemaVersion: "boardagent.job.export_build.v1",
                organizationId: actor.organizationId,
                boardId: actor.boardId,
                jobType: "export_build",
                subjectType: "export_request",
                subjectId: crashRequestId,
                parameters: { exportRequestId: crashRequestId }
              }
            }),
          { assumeRole: "boardagent_server" }
        );
        const crashFrozen = await withWorkerTransaction(
          pool,
          async (client) => {
            await client.query("set local bytea_output='escape'");
            const directProjection = await client.query<{ table_rows: Record<string, string>[] }>(
              "select table_rows from public.boardagent_export_audit_event_rows($1)",
              [crashRequestId]
            );
            expect(directProjection.rows[0]?.table_rows[0]?.["canonical_payload"]).toMatch(
              /^\\x[0-9a-f]+$/u
            );
            expect((await client.query("show bytea_output")).rows[0]?.bytea_output).toBe("escape");
            const captured = await buildFrozenExportSnapshotInTransaction(client, {
              exportRequestId: crashRequestId,
              exportStartedAuditEventId: testId(40_912)
            });
            const rows = JSON.parse(
              captured.components
                .find(({ name }) => name === "audit:events")!
                .bytes.toString("utf8")
            ).rows as Record<string, string>[];
            expect(rows[0]?.["canonical_payload"]).toMatch(/^\\x[0-9a-f]+$/u);
            expect(rows.every((row) => row["event_sha256"]?.startsWith("\\x"))).toBe(true);
            const checkpoints = JSON.parse(
              captured.components
                .find(({ name }) => name === "audit:checkpoints")!
                .bytes.toString("utf8")
            ).rows as Record<string, string>[];
            expect(checkpoints.length).toBeGreaterThan(0);
            expect(checkpoints.every((row) => row["canonical_manifest"]?.startsWith("\\x"))).toBe(
              true
            );
            return captured;
          },
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        );
        const crashManifest = await store.publish({
          frozen: crashFrozen,
          auditAttestation: fixtureExportAttestation(
            crashFrozen,
            evidence.privateKey,
            evidenceKeyId,
            "export-checkpoint-key"
          ),
          artifactId: testId(40_913),
          encryptionKeyId,
          encryptionKey: keys.dataEncryptionKey,
          newChunkId: () => testId(nextId++),
          randomBytes: (length) => Buffer.alloc(length, 0x74)
        });
        expect(
          (await store.scanArtifacts()).some(
            (entry) => entry.state === "committed" && entry.artifactId === crashManifest.artifactId
          )
        ).toBe(true);

        const reconcileJobId = testId(40_914);
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId: reconcileJobId,
              idempotencyKey: "export-reconcile-integration",
              envelope: {
                schemaVersion: "boardagent.job.export_reconcile.v1",
                organizationId: actor.organizationId,
                boardId: null,
                jobType: "export_reconcile",
                subjectType: "organization",
                subjectId: actor.organizationId,
                parameters: {}
              }
            }),
          { assumeRole: "boardagent_server" }
        );
        expect(await worker.runOnce()).toMatchObject({
          status: "succeeded",
          jobId: reconcileJobId,
          jobType: "export_reconcile"
        });
        const reconciled = await pool.query<{
          artifact_id: string;
          artifact_state: string;
          build_job_state: string;
          request_state: string;
        }>(
          `select request.state as request_state,artifact.id as artifact_id,
                  artifact.state as artifact_state,job.state as build_job_state
             from export_requests as request
             join export_artifacts as artifact on artifact.export_request_id=request.id
             join jobs as job on job.id=$2
            where request.id=$1`,
          [crashRequestId, abandonedBuildJobId]
        );
        expect(reconciled.rows[0]).toEqual({
          artifact_id: crashManifest.artifactId,
          artifact_state: "ready",
          build_job_state: "cancelled",
          request_state: "succeeded"
        });

        const partialRequestId = testId(40_920);
        await pool.query(
          `insert into export_requests(
             id,public_id,organization_id,board_id,requester_member_id,export_type,
             scope_manifest,scope_sha256,state,consent_record_id,recent_auth_at,expires_at
           )
           select $1,$2,organization_id,board_id,requester_member_id,export_type,
                  scope_manifest,scope_sha256,'queued',consent_record_id,
                  transaction_timestamp(),transaction_timestamp()+interval '24 hours'
             from export_requests where id=$3`,
          [partialRequestId, Buffer.alloc(32, 0x56), stageInput.exportRequestId]
        );
        const partialBuildJobId = testId(40_921);
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId: partialBuildJobId,
              idempotencyKey: "export-partial-build-integration",
              availableAt: deferredBuildAvailableAt,
              envelope: {
                schemaVersion: "boardagent.job.export_build.v1",
                organizationId: actor.organizationId,
                boardId: actor.boardId,
                jobType: "export_build",
                subjectType: "export_request",
                subjectId: partialRequestId,
                parameters: { exportRequestId: partialRequestId }
              }
            }),
          { assumeRole: "boardagent_server" }
        );
        const partialFrozen = await withWorkerTransaction(
          pool,
          (client) =>
            buildFrozenExportSnapshotInTransaction(client, {
              exportRequestId: partialRequestId,
              exportStartedAuditEventId: testId(40_922)
            }),
          { assumeRole: "boardagent_worker", isolation: "repeatable read" }
        );
        await pool.query(
          `update export_requests
              set started_at=transaction_timestamp()-interval '10 minutes',
                  row_version=row_version+1
            where id=$1`,
          [partialRequestId]
        );
        const interrupted = new AbortController();
        const partialArtifactId = testId(40_923);
        await expect(
          store.publish({
            frozen: partialFrozen,
            auditAttestation: fixtureExportAttestation(
              partialFrozen,
              evidence.privateKey,
              evidenceKeyId,
              "export-checkpoint-key"
            ),
            artifactId: partialArtifactId,
            encryptionKeyId,
            encryptionKey: keys.dataEncryptionKey,
            newChunkId: () => {
              interrupted.abort();
              return testId(nextId++);
            },
            randomBytes: (length) => Buffer.alloc(length, 0x75),
            signal: interrupted.signal
          })
        ).rejects.toThrow("interrupted");
        expect(
          (await store.scanArtifacts()).some(
            (entry) => entry.state === "partial" && entry.artifactId === partialArtifactId
          )
        ).toBe(true);

        const partialReconcileJobId = testId(40_924);
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId: partialReconcileJobId,
              idempotencyKey: "export-partial-reconcile-integration",
              envelope: {
                schemaVersion: "boardagent.job.export_reconcile.v1",
                organizationId: actor.organizationId,
                boardId: null,
                jobType: "export_reconcile",
                subjectType: "organization",
                subjectId: actor.organizationId,
                parameters: {}
              }
            }),
          { assumeRole: "boardagent_server" }
        );
        expect(await worker.runOnce()).toMatchObject({
          status: "succeeded",
          jobId: partialReconcileJobId,
          jobType: "export_reconcile"
        });
        expect(await store.scanArtifacts()).toHaveLength(1);
        const partialProof = await pool.query<{
          artifact_count: string;
          build_job_state: string;
          failure_class: string;
          request_state: string;
        }>(
          `select request.state as request_state,request.failure_class,
                  job.state as build_job_state,
                  (select count(*)::text from export_artifacts as artifact
                    where artifact.export_request_id=request.id) as artifact_count
             from export_requests as request
             join jobs as job on job.id=$2
            where request.id=$1`,
          [partialRequestId, partialBuildJobId]
        );
        expect(partialProof.rows[0]).toEqual({
          artifact_count: "0",
          build_job_state: "cancelled",
          failure_class: "artifact_publication_incomplete",
          request_state: "failed"
        });
      } finally {
        await rm(artifactRoot, { recursive: true, force: true });
      }
    });
  });
});
