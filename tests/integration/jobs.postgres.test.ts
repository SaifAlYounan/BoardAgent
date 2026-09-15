import { createHash, randomBytes } from "node:crypto";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  JobTransactionError,
  TYPED_JOB_TYPES,
  TypedJobEnvelopeSchema,
  claimTypedJobInTransaction,
  completeTypedJobInTransaction,
  enqueueRequestJobInTransaction,
  heartbeatJobLeaseInTransaction,
  migrate,
  reapExpiredJobLeasesInTransaction,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import {
  seedAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_jobs_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "job-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function workerTransaction<T>(
  pool: Pool,
  run: (client: PoolClient) => Promise<T>
): Promise<T> {
  return withWorkerTransaction(pool, run, { assumeRole: "boardagent_worker" });
}

async function beginWorker(client: PoolClient): Promise<void> {
  await client.query("begin");
  await client.query("set local role boardagent_worker");
  await client.query("select set_config('boardagent.transaction_scope','worker',true)");
}

async function migratorJobUpdate(
  pool: Pool,
  jobId: string,
  setClause: string,
  values: readonly unknown[] = []
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("set local role boardagent_migrator");
    await client.query(`update jobs set ${setClause} where id=$1`, [jobId, ...values]);
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

function scanEnvelope(
  actor: AuthorizedActorFixture,
  through = "2026-09-02T00:00:00Z"
): {
  readonly schemaVersion: "boardagent.job.question_due_scan.v1";
  readonly organizationId: string;
  readonly boardId: string;
  readonly jobType: "question_due_scan";
  readonly subjectType: "board";
  readonly subjectId: string;
  readonly parameters: { readonly through: string };
} {
  return {
    schemaVersion: "boardagent.job.question_due_scan.v1",
    organizationId: actor.organizationId,
    boardId: actor.boardId,
    jobType: "question_due_scan",
    subjectType: "board",
    subjectId: actor.boardId,
    parameters: { through }
  };
}

function resultHash(label: string): string {
  return canonicalSha256({ schemaVersion: "boardagent.test-job-result.v1", label });
}

function requireClaimed(
  result: Awaited<ReturnType<typeof claimTypedJobInTransaction>>
): Extract<Awaited<ReturnType<typeof claimTypedJobInTransaction>>, { claimed: true }> {
  expect(result.claimed).toBe(true);
  if (!result.claimed) throw new Error("expected a claimed job");
  return result;
}

describe("typed transactional jobs", () => {
  it("keeps queue rows behind protected functions and rejects unknown or cross-board producers", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });

      await expect(
        workerTransaction(pool, (client) => client.query("select id from jobs"))
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) => client.query("select id from jobs"),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      const allowedEnvelope = scanEnvelope(actor);
      const allowedPayload = Buffer.from(canonicalJson(allowedEnvelope), "utf8");
      const allowedArguments = [
        testId(19_890),
        allowedEnvelope.organizationId,
        allowedEnvelope.boardId,
        allowedEnvelope.jobType,
        allowedEnvelope.schemaVersion,
        allowedEnvelope.subjectType,
        allowedEnvelope.subjectId,
        allowedPayload,
        Buffer.from(canonicalSha256(allowedEnvelope), "hex"),
        "worker-cannot-enqueue-request-job",
        null
      ];
      await expect(
        workerTransaction(pool, (client) =>
          client.query(
            "select * from boardagent_enqueue_request_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            allowedArguments
          )
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            await client.query("select set_config('boardagent.transaction_scope','worker',true)");
            return client.query(
              "select * from boardagent_enqueue_request_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
              allowedArguments
            );
          },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "25000" });
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) => client.query("select * from boardagent_claim_typed_job('server',30)"),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      const executeMatrix = await pool.query<{
        server_claim: boolean;
        server_enqueue: boolean;
        worker_claim: boolean;
        worker_enqueue: boolean;
      }>(
        `select
           has_function_privilege(
             'boardagent_server',
             'public.boardagent_enqueue_request_job(uuid,uuid,uuid,text,text,text,uuid,bytea,bytea,text,timestamp with time zone)',
             'EXECUTE'
           ) as server_enqueue,
           has_function_privilege(
             'boardagent_worker',
             'public.boardagent_enqueue_request_job(uuid,uuid,uuid,text,text,text,uuid,bytea,bytea,text,timestamp with time zone)',
             'EXECUTE'
           ) as worker_enqueue,
           has_function_privilege(
             'boardagent_server','public.boardagent_claim_typed_job(text,integer)','EXECUTE'
           ) as server_claim,
           has_function_privilege(
             'boardagent_worker','public.boardagent_claim_typed_job(text,integer)','EXECUTE'
           ) as worker_claim`
      );
      expect(executeMatrix.rows[0]).toEqual({
        server_enqueue: true,
        worker_enqueue: false,
        server_claim: false,
        worker_claim: true
      });

      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            client.query(
              `insert into jobs(
                 id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
                 canonical_payload,payload_sha256,idempotency_key
               ) values ($1,$2,$3,'document_extraction','boardagent.job.document_extraction.v1',
                         'board',$3,'{}'::text::bytea,$4,'unknown-job-must-be-denied')`,
              [testId(19_900), actor.organizationId, actor.boardId, Buffer.alloc(32, 1)]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });

      const forged = {
        ...scanEnvelope(actor),
        subjectId: testId(19_901)
      };
      const forgedPayload = Buffer.from(canonicalJson(forged), "utf8");
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            client.query(
              "select * from boardagent_enqueue_request_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
              [
                testId(19_902),
                forged.organizationId,
                forged.boardId,
                forged.jobType,
                forged.schemaVersion,
                forged.subjectType,
                forged.subjectId,
                forgedPayload,
                Buffer.from(canonicalSha256(forged), "hex"),
                "forged-cross-board-job",
                null
              ]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "23514" });

      const unknown = {
        schemaVersion: "boardagent.job.document_extraction.v1",
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        jobType: "document_extraction",
        subjectType: "board",
        subjectId: actor.boardId,
        parameters: {}
      };
      const unknownPayload = Buffer.from(canonicalJson(unknown), "utf8");
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            client.query(
              "select * from boardagent_enqueue_request_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
              [
                testId(19_903),
                unknown.organizationId,
                unknown.boardId,
                unknown.jobType,
                unknown.schemaVersion,
                unknown.subjectType,
                unknown.subjectId,
                unknownPayload,
                Buffer.from(canonicalSha256(unknown), "hex"),
                "unknown-protected-job",
                null
              ]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "23514" });

      const registry = await pool.query<{ types: string[] }>(
        "select boardagent_typed_job_types() as types"
      );
      expect(registry.rows[0]?.types).toEqual([...TYPED_JOB_TYPES]);
      expect(TYPED_JOB_TYPES.some((type) => /(?:ai|extract|purge)/u.test(type))).toBe(false);
    });
  });

  it("binds feed reconciliation to a real membership despite a temp-schema shadow", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const feedEnvelope = {
        schemaVersion: "boardagent.job.feed_reconcile.v1",
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        jobType: "feed_reconcile",
        subjectType: "member",
        subjectId: actor.memberId,
        parameters: { memberId: actor.memberId }
      } as const;
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId: testId(19_910),
              envelope: feedEnvelope,
              idempotencyKey: "valid-feed-reconciliation-job"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ replayed: false });

      const unboundMemberId = testId(19_911);
      await pool.query(
        `insert into members(
           id,organization_id,member_kind,legal_name,display_name,state
         ) values ($1,$2,'human','Unbound member','Unbound member','active')`,
        [unboundMemberId, actor.organizationId]
      );
      const forgedEnvelope = {
        ...feedEnvelope,
        subjectId: unboundMemberId,
        parameters: { memberId: unboundMemberId }
      };
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            await client.query(
              `create temporary table board_memberships(
                 organization_id uuid not null,
                 board_id uuid not null,
                 member_id uuid not null
               )`
            );
            await client.query(
              `insert into pg_temp.board_memberships(organization_id,board_id,member_id)
               values ($1,$2,$3)`,
              [actor.organizationId, actor.boardId, unboundMemberId]
            );
            return enqueueRequestJobInTransaction(client, {
              jobId: testId(19_912),
              envelope: forgedEnvelope,
              idempotencyKey: "temp-shadow-feed-job-must-fail"
            });
          },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "job_invalid" } satisfies Partial<JobTransactionError>);
    });
  });

  it("atomically replays concurrent enqueue and conflicts on different canonical bytes", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const envelope = scanEnvelope(actor);
      const enqueue = (jobId: string) =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId,
              envelope,
              idempotencyKey: "concurrent-board-scan-job"
            }),
          { assumeRole: "boardagent_server" }
        );
      const outcomes = await Promise.all([enqueue(testId(20_000)), enqueue(testId(20_001))]);
      expect(outcomes.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);
      expect(new Set(outcomes.map(({ jobId }) => jobId)).size).toBe(1);

      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId: testId(20_002),
              envelope: scanEnvelope(actor, "2026-09-03T00:00:00Z"),
              idempotencyKey: "concurrent-board-scan-job"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "job_conflict" } satisfies Partial<JobTransactionError>);
    });
  });

  it("claims with skip-locked, heartbeats monotonically and replays one immutable result", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const queued = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: testId(21_000),
            envelope: scanEnvelope(actor),
            idempotencyKey: "claim-heartbeat-result-job"
          }),
        { assumeRole: "boardagent_server" }
      );

      const first = await pool.connect();
      const second = await pool.connect();
      let claimed;
      try {
        await beginWorker(first);
        claimed = requireClaimed(
          await claimTypedJobInTransaction(first, { leaseOwner: "worker-a", leaseSeconds: 30 })
        );
        await beginWorker(second);
        expect(
          await claimTypedJobInTransaction(second, { leaseOwner: "worker-b", leaseSeconds: 30 })
        ).toEqual({ claimed: false });
        await second.query("commit");
        await first.query("commit");
      } finally {
        first.release();
        second.release();
      }

      const heartbeat = await workerTransaction(pool, (client) =>
        heartbeatJobLeaseInTransaction(client, {
          jobId: queued.jobId,
          leaseOwner: claimed.job.leaseOwner,
          attempt: claimed.job.attempt,
          leaseToken: claimed.job.leaseToken,
          leaseSeconds: 5
        })
      );
      expect(heartbeat.extended).toBe(true);
      expect(Date.parse(heartbeat.leaseExpiresAt ?? "")).toBeGreaterThanOrEqual(
        Date.parse(claimed.job.leaseExpiresAt)
      );

      const completionInput = {
        jobId: queued.jobId,
        leaseOwner: claimed.job.leaseOwner,
        attempt: claimed.job.attempt,
        leaseToken: claimed.job.leaseToken,
        result: "succeeded" as const,
        resultSha256: resultHash("claim-success")
      };
      const completed = await workerTransaction(pool, (client) =>
        completeTypedJobInTransaction(client, completionInput)
      );
      expect(completed).toEqual({
        completed: true,
        jobId: queued.jobId,
        state: "succeeded",
        replayed: false
      });
      const replay = await workerTransaction(pool, (client) =>
        completeTypedJobInTransaction(client, completionInput)
      );
      expect(replay).toEqual({ ...completed, replayed: true });
      await expect(
        workerTransaction(pool, (client) =>
          completeTypedJobInTransaction(client, {
            ...completionInput,
            resultSha256: resultHash("conflicting-success")
          })
        )
      ).rejects.toMatchObject({ code: "job_conflict" } satisfies Partial<JobTransactionError>);

      const stored = await pool.query<{ attempts: number; result_count: string; state: string }>(
        `select job.state,job.attempts,
                (select count(*)::text from job_attempt_results where job_id=job.id) as result_count
           from jobs as job where job.id=$1`,
        [queued.jobId]
      );
      expect(stored.rows[0]).toEqual({ state: "succeeded", attempts: 1, result_count: "1" });
    });
  });

  it("rejects same-owner lease ABA and preserves each attempt result", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const jobId = testId(22_000);
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId,
            envelope: scanEnvelope(actor),
            idempotencyKey: "same-owner-aba-job"
          }),
        { assumeRole: "boardagent_server" }
      );
      const first = requireClaimed(
        await workerTransaction(pool, (client) =>
          claimTypedJobInTransaction(client, { leaseOwner: "worker-same", leaseSeconds: 30 })
        )
      );
      await workerTransaction(pool, (client) =>
        completeTypedJobInTransaction(client, {
          jobId,
          leaseOwner: first.job.leaseOwner,
          attempt: first.job.attempt,
          leaseToken: first.job.leaseToken,
          result: "retryable_failure",
          resultSha256: resultHash("attempt-one-retry"),
          errorClass: "temporary_dependency"
        })
      );
      await migratorJobUpdate(pool, jobId, "available_at=clock_timestamp()-interval '1 second'");
      const second = requireClaimed(
        await workerTransaction(pool, (client) =>
          claimTypedJobInTransaction(client, { leaseOwner: "worker-same", leaseSeconds: 30 })
        )
      );
      expect(second.job.attempt).toBe(2);
      expect(second.job.leaseToken).not.toBe(first.job.leaseToken);

      const staleHeartbeat = await workerTransaction(pool, (client) =>
        heartbeatJobLeaseInTransaction(client, {
          jobId,
          leaseOwner: first.job.leaseOwner,
          attempt: first.job.attempt,
          leaseToken: first.job.leaseToken,
          leaseSeconds: 60
        })
      );
      expect(staleHeartbeat).toEqual({ extended: false });
      await expect(
        workerTransaction(pool, (client) =>
          completeTypedJobInTransaction(client, {
            jobId,
            leaseOwner: first.job.leaseOwner,
            attempt: first.job.attempt,
            leaseToken: first.job.leaseToken,
            result: "succeeded",
            resultSha256: resultHash("late-attempt-one-success")
          })
        )
      ).rejects.toMatchObject({ code: "job_conflict" } satisfies Partial<JobTransactionError>);

      const final = await workerTransaction(pool, (client) =>
        completeTypedJobInTransaction(client, {
          jobId,
          leaseOwner: second.job.leaseOwner,
          attempt: second.job.attempt,
          leaseToken: second.job.leaseToken,
          result: "succeeded",
          resultSha256: resultHash("attempt-two-success")
        })
      );
      expect(final).toMatchObject({ completed: true, state: "succeeded", replayed: false });
      const results = await pool.query<{ attempt: number; resulting_state: string }>(
        "select attempt,resulting_state from job_attempt_results where job_id=$1 order by attempt",
        [jobId]
      );
      expect(results.rows).toEqual([
        { attempt: 1, resulting_state: "retry" },
        { attempt: 2, resulting_state: "succeeded" }
      ]);
    });
  });

  it("dead-letters noncanonical storage corruption and reaps expired leases at the fixed ceiling", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const corruptJobId = testId(23_000);
      const corruptEnvelope = scanEnvelope(actor);
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: corruptJobId,
            envelope: corruptEnvelope,
            idempotencyKey: "canonical-corruption-job"
          }),
        { assumeRole: "boardagent_server" }
      );
      const noncanonical = Buffer.from(JSON.stringify(corruptEnvelope, null, 2), "utf8");
      await migratorJobUpdate(pool, corruptJobId, "canonical_payload=$2,payload_sha256=$3", [
        noncanonical,
        createHash("sha256").update(noncanonical).digest()
      ]);
      const rejected = await workerTransaction(pool, (client) =>
        claimTypedJobInTransaction(client, { leaseOwner: "worker-validator", leaseSeconds: 30 })
      );
      expect(rejected).toMatchObject({ claimed: false, rejectedJobId: corruptJobId });

      const reapJobId = testId(23_010);
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: reapJobId,
            envelope: scanEnvelope(actor, "2026-09-04T00:00:00Z"),
            idempotencyKey: "expired-lease-reaper-job"
          }),
        { assumeRole: "boardagent_server" }
      );
      const firstLease = requireClaimed(
        await workerTransaction(pool, (client) =>
          claimTypedJobInTransaction(client, { leaseOwner: "worker-expired", leaseSeconds: 5 })
        )
      );
      await migratorJobUpdate(
        pool,
        reapJobId,
        "lease_started_at=clock_timestamp()-interval '2 seconds',lease_expires_at=clock_timestamp()-interval '1 second'"
      );
      expect(
        await workerTransaction(pool, (client) => reapExpiredJobLeasesInTransaction(client))
      ).toEqual({ retried: 1, dead: 0 });

      await migratorJobUpdate(
        pool,
        reapJobId,
        "attempts=9,available_at=clock_timestamp()-interval '1 second'"
      );
      const finalLease = requireClaimed(
        await workerTransaction(pool, (client) =>
          claimTypedJobInTransaction(client, { leaseOwner: "worker-expired", leaseSeconds: 5 })
        )
      );
      expect(finalLease.job.attempt).toBe(10);
      await migratorJobUpdate(
        pool,
        reapJobId,
        "lease_started_at=clock_timestamp()-interval '2 seconds',lease_expires_at=clock_timestamp()-interval '1 second'"
      );
      expect(
        await workerTransaction(pool, (client) => reapExpiredJobLeasesInTransaction(client))
      ).toEqual({ retried: 0, dead: 1 });
      expect(
        await workerTransaction(pool, (client) =>
          heartbeatJobLeaseInTransaction(client, {
            jobId: reapJobId,
            leaseOwner: firstLease.job.leaseOwner,
            attempt: firstLease.job.attempt,
            leaseToken: firstLease.job.leaseToken,
            leaseSeconds: 60
          })
        )
      ).toEqual({ extended: false });

      const states = await pool.query<{
        id: string;
        result_classes: string[];
        state: string;
      }>(
        `select job.id,job.state,
                coalesce(array_agg(result.result_class order by result.attempt)
                  filter (where result.job_id is not null),'{}') as result_classes
           from jobs as job
           left join job_attempt_results as result on result.job_id=job.id
          where job.id=any($1::uuid[])
          group by job.id,job.state
          order by job.id`,
        [[corruptJobId, reapJobId]]
      );
      expect(states.rows).toEqual([
        {
          id: corruptJobId,
          state: "dead",
          result_classes: ["permanent_failure"]
        },
        {
          id: reapJobId,
          state: "dead",
          result_classes: ["lease_expired", "lease_expired"]
        }
      ]);
    });
  });
});

describe("checkpoint SQL parameter type boundary", () => {
  it.each([
    { label: "JSON null", value: null },
    { label: "JSON number", value: 1 },
    { label: "decimal string", value: "1" }
  ])("requires a string watermark instead of $label", async ({ value }) => {
    await withMigratedDatabase("checkpoint-json-boundary", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const envelope = {
        schemaVersion: "boardagent.job.audit_checkpoint.v1",
        organizationId: actor.organizationId,
        boardId: null,
        jobType: "audit_checkpoint",
        subjectType: "organization",
        subjectId: actor.organizationId,
        parameters: { throughSequence: value }
      };
      expect(TypedJobEnvelopeSchema.safeParse(envelope).success).toBe(value === "1");
      const payload = Buffer.from(canonicalJson(envelope));
      const payloadHash = Buffer.from(canonicalSha256(envelope), "hex");
      const before = await sqlJobBoundarySnapshot(pool);
      const outcome = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          expect(
            (
              await client.query(`select current_user as role,
            row_security_active('public.jobs'::regclass) as jobs_rls`)
            ).rows[0]
          ).toEqual({
            role: "boardagent_server",
            jobs_rls: true
          });
          return client.query(
            `select * from boardagent_enqueue_request_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
            [
              testId(792_000),
              actor.organizationId,
              null,
              envelope.jobType,
              envelope.schemaVersion,
              envelope.subjectType,
              actor.organizationId,
              payload,
              payloadHash,
              "checkpoint-json-boundary-request",
              null
            ]
          );
        },
        { assumeRole: "boardagent_server" }
      ).then(
        () => ({ accepted: true, code: null }),
        (error: unknown) => ({
          accepted: false,
          code: typeof error === "object" && error !== null && "code" in error ? error.code : null
        })
      );
      const after = await sqlJobBoundarySnapshot(pool);
      if (value === "1") {
        expect(outcome).toEqual({ accepted: true, code: null });
        expect(
          (await pool.query("select state,canonical_payload,payload_sha256 from jobs")).rows
        ).toEqual([{ state: "queued", canonical_payload: payload, payload_sha256: payloadHash }]);
        expect({ ...after, jobs: before.jobs }).toEqual(before);
      } else {
        expect({ outcome, after }).toEqual({
          outcome: { accepted: false, code: "23514" },
          after: before
        });
      }
    });
  });
});

async function sqlJobBoundarySnapshot(pool: Pool) {
  return {
    jobs: (await pool.query("select row_to_json(r)::text as row from jobs r order by id")).rows,
    attempts: (
      await pool.query(
        "select row_to_json(r)::text as row from job_attempt_results r order by job_id,attempt"
      )
    ).rows,
    audit: (await pool.query("select row_to_json(r)::text as row from audit_events r order by id"))
      .rows,
    checkpoints: (
      await pool.query("select row_to_json(r)::text as row from audit_checkpoints r order by id")
    ).rows
  };
}

describe("expired job SQL reaper limit boundary", () => {
  it.each(["null", "one", "default"] as const)(
    "applies the %s limit only to eligible expired leases",
    async (limitCase) => {
      await withMigratedDatabase("job-reaper-null-boundary", async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["secretariat:admin"],
          isSecretary: true
        });
        const ids = [testId(793_000), testId(793_001), testId(793_002), testId(793_003)];
        const leases: Array<
          Extract<Awaited<ReturnType<typeof claimTypedJobInTransaction>>, { claimed: true }>["job"]
        > = [];
        for (let index = 0; index < ids.length; index += 1) {
          const jobId = ids[index]!;
          await withRequestTransaction(
            pool,
            actor.context,
            (client) =>
              enqueueRequestJobInTransaction(client, {
                jobId,
                envelope: scanEnvelope(actor),
                idempotencyKey: `null-reaper-boundary-${String(index)}`
              }),
            { assumeRole: "boardagent_server" }
          );
          if (index < 3) {
            const claimed = requireClaimed(
              await workerTransaction(pool, (client) =>
                claimTypedJobInTransaction(client, {
                  leaseOwner: `reaper-boundary-${String(index)}`,
                  leaseSeconds: index < 2 ? 5 : 60
                })
              )
            );
            expect(claimed.job.jobId).toBe(jobId);
            leases.push(claimed.job);
          }
        }
        // Let real worker leases expire. Do not rewrite queue history or the database clock.
        const deadline = Date.now() + 10_000;
        while (true) {
          const expired = (
            await pool.query<{ count: number }>(
              "select count(*)::int as count from jobs where id=any($1::uuid[]) and lease_expires_at<=clock_timestamp()",
              [ids.slice(0, 2)]
            )
          ).rows[0]!.count;
          if (expired === 2) break;
          if (Date.now() >= deadline)
            throw new Error("fixture worker leases did not expire within ten seconds");
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        const before = await sqlJobBoundarySnapshot(pool);
        const outcome = await workerTransaction(pool, async (client) => {
          expect(
            (
              await client.query(`select current_user as role,
            row_security_active('public.jobs'::regclass) as jobs_rls`)
            ).rows[0]
          ).toEqual({
            role: "boardagent_worker",
            jobs_rls: true
          });
          return limitCase === "default"
            ? client.query<{ retried: number; dead: number }>(
                "select * from boardagent_reap_expired_typed_jobs()"
              )
            : client.query<{ retried: number; dead: number }>(
                "select * from boardagent_reap_expired_typed_jobs($1)",
                [limitCase === "null" ? null : 1]
              );
        }).then(
          (result) => ({ accepted: true, code: null, rows: result.rows }),
          (error: unknown) => ({
            accepted: false,
            code:
              typeof error === "object" && error !== null && "code" in error ? error.code : null,
            rows: []
          })
        );
        const after = await sqlJobBoundarySnapshot(pool);
        if (limitCase === "null") {
          expect({ outcome, after }).toEqual({
            outcome: { accepted: false, code: "22023", rows: [] },
            after: before
          });
          return;
        }
        const reaped = limitCase === "one" ? 1 : 2;
        expect(outcome).toEqual({
          accepted: true,
          code: null,
          rows: [{ retried: reaped, dead: 0 }]
        });
        expect(after.jobs.slice(2)).toEqual(before.jobs.slice(2));
        expect(after.audit).toEqual(before.audit);
        expect(after.checkpoints).toEqual(before.checkpoints);
        expect((await pool.query("select state from jobs order by id")).rows).toEqual([
          { state: "retry" },
          { state: reaped === 2 ? "retry" : "leased" },
          { state: "leased" },
          { state: "queued" }
        ]);
        expect(
          (
            await pool.query(`select job_id,attempt,lease_owner,lease_token,result_class,resulting_state,
          octet_length(result_sha256) as hash_bytes from job_attempt_results order by job_id,attempt`)
          ).rows
        ).toEqual(
          leases.slice(0, reaped).map((lease) => ({
            job_id: lease.jobId,
            attempt: 1,
            lease_owner: lease.leaseOwner,
            lease_token: lease.leaseToken,
            result_class: "lease_expired",
            resulting_state: "retry",
            hash_bytes: 32
          }))
        );
      });
    },
    20_000
  );
});

describe("typed job boundary forward upgrade from schema 159", () => {
  it("preserves queued payload history and rejects legacy malformed payloads at normal claim", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-job-boundary-upgrade-"));
    const database = `boardagent_job_upgrade_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    const databaseUrl = new URL(BASE_URL);
    databaseUrl.pathname = "/postgres";
    const admin = new Pool({ connectionString: databaseUrl.toString(), max: 1 });
    let pool: Pool | undefined;
    let created = false;
    try {
      // Real byte-identical old migrations admit the legacy rows naturally.
      // No trigger, role, RLS policy or immutable history is modified.
      for (const name of await readdir(MIGRATIONS)) {
        if (/^\d{4}_[a-z0-9_]+\.sql$/u.test(name) && Number(name.slice(0, 4)) <= 159) {
          await copyFile(path.join(MIGRATIONS, name), path.join(directory, name));
        }
      }
      await admin.query(`create database "${database}"`);
      created = true;
      databaseUrl.pathname = `/${database}`;
      const legacyPool = new Pool({ connectionString: databaseUrl.toString(), max: 2 });
      pool = legacyPool;
      expect(await migrate(legacyPool, directory, "job-boundary-legacy-test")).toBe(159);
      const actor = await seedAuthorizedActor(legacyPool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const values = [null, 1, "1"];
      const ids = values.map((_, index) => testId(794_000 + index));
      for (let index = 0; index < values.length; index += 1) {
        const envelope = {
          schemaVersion: "boardagent.job.audit_checkpoint.v1",
          organizationId: actor.organizationId,
          boardId: null,
          jobType: "audit_checkpoint",
          subjectType: "organization",
          subjectId: actor.organizationId,
          parameters: { throughSequence: values[index]! }
        };
        await withRequestTransaction(
          legacyPool,
          actor.context,
          async (client) => {
            expect((await client.query("select current_user as role")).rows[0]).toEqual({
              role: "boardagent_server"
            });
            return client.query(
              "select * from boardagent_enqueue_request_job($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
              [
                ids[index],
                actor.organizationId,
                null,
                envelope.jobType,
                envelope.schemaVersion,
                envelope.subjectType,
                actor.organizationId,
                Buffer.from(canonicalJson(envelope)),
                Buffer.from(canonicalSha256(envelope), "hex"),
                `legacy-checkpoint-boundary-${String(index)}`,
                null
              ]
            );
          },
          { assumeRole: "boardagent_server" }
        );
      }
      const before = await sqlJobBoundarySnapshot(legacyPool);
      const beforeLedger = (
        await legacyPool.query(
          "select row_to_json(r)::text as row from schema_migrations r order by version"
        )
      ).rows;
      const payloads = async () =>
        (await legacyPool.query("select id,canonical_payload,payload_sha256 from jobs order by id"))
          .rows;
      const beforePayloads = await payloads();
      expect(before.jobs).toHaveLength(3);
      expect(beforeLedger).toHaveLength(159);
      const migration = "0160_null_safe_minutes_and_job_boundaries.sql";
      await copyFile(path.join(MIGRATIONS, migration), path.join(directory, migration));
      expect(await migrate(legacyPool, directory, "job-boundary-upgrade-test")).toBe(1);

      const after = await sqlJobBoundarySnapshot(legacyPool);
      expect(after.jobs).toEqual(before.jobs);
      expect(after.attempts).toEqual(before.attempts);
      expect(after.checkpoints).toEqual(before.checkpoints);
      expect(after.audit).toEqual(expect.arrayContaining(before.audit));
      expect(after.audit).toHaveLength(before.audit.length + 1);
      const afterLedger = (
        await legacyPool.query(
          "select row_to_json(r)::text as row from schema_migrations r order by version"
        )
      ).rows;
      expect(afterLedger.slice(0, 159)).toEqual(beforeLedger);
      expect(afterLedger).toHaveLength(160);
      expect(
        (await legacyPool.query("select version,name from schema_migrations where version=160"))
          .rows
      ).toEqual([{ version: 160, name: migration }]);
      expect(
        (
          await legacyPool.query(
            `select count(*)::int as count from audit_events
        where event_type='migration_applied'
          and convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'name'=$1`,
            [migration]
          )
        ).rows[0]?.count
      ).toBe(1);

      for (const jobId of ids.slice(0, 2)) {
        const claimed = await workerTransaction(legacyPool, (client) =>
          claimTypedJobInTransaction(client, {
            leaseOwner: "legacy-boundary-validator",
            leaseSeconds: 30
          })
        );
        expect(claimed).toMatchObject({ claimed: false, rejectedJobId: jobId });
      }
      const valid = requireClaimed(
        await workerTransaction(legacyPool, (client) =>
          claimTypedJobInTransaction(client, {
            leaseOwner: "legacy-boundary-validator",
            leaseSeconds: 30
          })
        )
      );
      expect(valid.job.jobId).toBe(ids[2]);
      expect(valid.job.envelope).toMatchObject({
        jobType: "audit_checkpoint",
        parameters: { throughSequence: "1" }
      });
      expect(await payloads()).toEqual(beforePayloads);
      expect((await legacyPool.query("select state from jobs order by id")).rows).toEqual([
        { state: "dead" },
        { state: "dead" },
        { state: "leased" }
      ]);
      expect(
        (
          await legacyPool.query(
            "select job_id,result_class,error_class,resulting_state from job_attempt_results order by job_id"
          )
        ).rows
      ).toEqual(
        ids.slice(0, 2).map((jobId) => ({
          job_id: jobId,
          result_class: "permanent_failure",
          error_class: "invalid_typed_payload",
          resulting_state: "dead"
        }))
      );
      expect((await sqlJobBoundarySnapshot(legacyPool)).checkpoints).toEqual(before.checkpoints);
    } finally {
      await pool?.end();
      if (created) await dropClosedTestDatabase(admin, database);
      await admin.end();
      await rm(directory, { recursive: true, force: true });
    }
  });
});
