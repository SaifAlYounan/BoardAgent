import { describe, expect, it } from "vitest";

import {
  BoardAgentCoreWorkerHandlers,
  BoardAgentTypedWorker,
  CORE_WORKER_JOB_TYPES,
  loadBoardAgentKeyMaterial,
  type BoardAgentRuntimeBinding
} from "../../artifacts/server/src/index.js";
import { parseConfig } from "../../lib/config/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { enqueueRequestJobInTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("core worker handler composition", () => {
  it("claims and completes real expiry and clock jobs through the worker role", async () => {
    await withMigratedDatabase("core-worker-handlers", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const config = parseConfig({
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: "postgresql://unused",
        BOARDAGENT_ORGANIZATION_ID: actor.organizationId,
        BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
        BOARDAGENT_AUTHORIZATION_MODE: "builtin",
        BOARDAGENT_BLOB_ROOT: "/tmp/boardagent-core-worker-test",
        BOARDAGENT_DEV_MASTER_SECRET: "core-worker-test-secret-material-is-long-enough"
      });
      const keys = await loadBoardAgentKeyMaterial(config);
      const binding: BoardAgentRuntimeBinding = {
        instanceId: testId(15),
        organizationId: actor.organizationId,
        canonicalResourceUri: "https://boardagent.test/mcp",
        keyIds: {
          oauth_signing: testId(8),
          evidence_signing: testId(39_000),
          browser_session: testId(39_001),
          data_kek: testId(39_002)
        },
        keyLocators: {
          oauth_signing: "test:oauth",
          evidence_signing: "test:evidence",
          browser_session: "test:browser",
          data_kek: "test:data"
        }
      };
      const operationalAlerts: { alertClass: string; details: unknown }[] = [];
      const handlers = new BoardAgentCoreWorkerHandlers(pool, {
        config,
        binding,
        keys,
        onOperationalAlert: (alertClass, details) => {
          operationalAlerts.push({ alertClass, details });
        },
        assumeRole: "boardagent_worker"
      }).handlers();
      expect([...handlers.keys()]).toEqual(CORE_WORKER_JOB_TYPES);

      const expiredDraftId = testId(39_003);
      await pool.query(
        `insert into wizard_drafts(
           id,organization_id,board_id,draft_type,creator_member_id,current_step,
           signed_context,context_sha256,state,expires_at,created_at
         ) values ($1,$2,$3,'vote',$4,0,$5,$6,'active',
                   transaction_timestamp()-interval '10 minutes',
                   transaction_timestamp()-interval '20 minutes')`,
        [
          expiredDraftId,
          actor.organizationId,
          actor.boardId,
          actor.memberId,
          Buffer.alloc(32, 1),
          Buffer.alloc(32, 2)
        ]
      );
      const dueTaskId = testId(39_011);
      const dueTaskSha256 = "74".repeat(32);
      await pool.query(
        `insert into tasks(
           id,organization_id,board_id,owner_member_id,due_at,description_schema,
           canonical_description,required_evidence,task_sha256,state,row_version,
           created_by,created_at
         ) values ($1,$2,$3,$4,'2026-09-03T11:00:00Z','boardagent.task.v1',
                   'Prepare the due-state fixture',jsonb_build_object('items',jsonb_build_array()),
                   $5,'open',1,$4,'2026-09-02T11:00:00Z')`,
        [
          dueTaskId,
          actor.organizationId,
          actor.boardId,
          actor.memberId,
          Buffer.from(dueTaskSha256, "hex")
        ]
      );

      const enqueueOrganizationJob = async (
        jobId: string,
        jobType:
          | "wizard_expiry"
          | "clock_health"
          | "compatibility_alert"
          | "dependency_compatibility_alert"
          | "feed_consistency_check"
          | "job_retention"
          | "key_compatibility_alert"
          | "log_retention"
          | "protocol_compatibility_alert"
          | "restore_due_alert",
        idempotencyKey: string
      ): Promise<void> => {
        await withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            enqueueRequestJobInTransaction(client, {
              jobId,
              idempotencyKey,
              envelope: {
                schemaVersion: `boardagent.job.${jobType}.v1`,
                organizationId: actor.organizationId,
                boardId: null,
                jobType,
                subjectType: "organization",
                subjectId: actor.organizationId,
                parameters: {}
              }
            }),
          { assumeRole: "boardagent_server" }
        );
      };
      const expiryJobId = testId(39_004);
      const clockJobId = testId(39_005);
      const alertJobs = [
        [testId(39_006), "compatibility_alert"],
        [testId(39_007), "dependency_compatibility_alert"],
        [testId(39_008), "key_compatibility_alert"],
        [testId(39_009), "protocol_compatibility_alert"],
        [testId(39_010), "restore_due_alert"]
      ] as const;
      await enqueueOrganizationJob(expiryJobId, "wizard_expiry", "core-worker-wizard-expiry");
      await enqueueOrganizationJob(clockJobId, "clock_health", "core-worker-clock-health");
      for (const [jobId, jobType] of alertJobs) {
        await enqueueOrganizationJob(jobId, jobType, `core-worker-${jobType}`);
      }
      const actionScanJobId = testId(39_017);
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: actionScanJobId,
            idempotencyKey: "core-worker-action-due-scan",
            envelope: {
              schemaVersion: "boardagent.job.action_due_scan.v1",
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              jobType: "action_due_scan",
              subjectType: "board",
              subjectId: actor.boardId,
              parameters: { through: "2026-09-03T12:00:00.000Z" }
            }
          }),
        { assumeRole: "boardagent_server" }
      );
      const taskScanJobId = testId(39_012);
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: taskScanJobId,
            idempotencyKey: "core-worker-task-due-scan",
            envelope: {
              schemaVersion: "boardagent.job.task_due_scan.v1",
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              jobType: "task_due_scan",
              subjectType: "board",
              subjectId: actor.boardId,
              parameters: { through: "2026-09-03T12:00:00.000Z" }
            }
          }),
        { assumeRole: "boardagent_server" }
      );
      const jobRetentionJobId = testId(39_013);
      const logRetentionJobId = testId(39_014);
      const feedReconcileJobId = testId(39_015);
      const feedConsistencyJobId = testId(39_016);
      await enqueueOrganizationJob(jobRetentionJobId, "job_retention", "core-worker-job-retention");
      await enqueueOrganizationJob(logRetentionJobId, "log_retention", "core-worker-log-retention");
      await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: feedReconcileJobId,
            idempotencyKey: "core-worker-feed-reconcile",
            envelope: {
              schemaVersion: "boardagent.job.feed_reconcile.v1",
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              jobType: "feed_reconcile",
              subjectType: "member",
              subjectId: actor.memberId,
              parameters: { memberId: actor.memberId }
            }
          }),
        { assumeRole: "boardagent_server" }
      );
      await enqueueOrganizationJob(
        feedConsistencyJobId,
        "feed_consistency_check",
        "core-worker-feed-consistency"
      );

      const worker = new BoardAgentTypedWorker(pool, {
        handlers,
        workerId: "core-worker-integration-test",
        assumeRole: "boardagent_worker"
      });
      expect(worker.missingHandlerTypes()).toHaveLength(5);
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: expiryJobId,
        jobType: "wizard_expiry"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: clockJobId,
        jobType: "clock_health"
      });
      for (const [jobId, jobType] of alertJobs) {
        expect(await worker.runOnce()).toMatchObject({ status: "succeeded", jobId, jobType });
      }
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: actionScanJobId,
        jobType: "action_due_scan"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: taskScanJobId,
        jobType: "task_due_scan"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: jobRetentionJobId,
        jobType: "job_retention"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: logRetentionJobId,
        jobType: "log_retention"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: feedReconcileJobId,
        jobType: "feed_reconcile"
      });
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: feedConsistencyJobId,
        jobType: "feed_consistency_check"
      });

      expect(operationalAlerts).toEqual(
        alertJobs.map(([jobId, jobType]) => ({
          alertClass: jobType,
          details: {
            schemaVersion: "boardagent.operational-alert.v1",
            alertJobRef: canonicalSha256({
              schemaVersion: "boardagent.operational-reference.v1",
              kind: "job",
              id: jobId
            }),
            alertClass: jobType,
            organizationRef: canonicalSha256({
              schemaVersion: "boardagent.operational-reference.v1",
              kind: "organization",
              id: actor.organizationId
            })
          }
        }))
      );

      expect(
        (
          await pool.query("select state,row_version::text from wizard_drafts where id=$1", [
            expiredDraftId
          ])
        ).rows
      ).toEqual([{ state: "expired", row_version: "2" }]);
      expect(
        (
          await pool.query(
            "select count(*)::integer as count from clock_health_samples where organization_id=$1",
            [actor.organizationId]
          )
        ).rows
      ).toEqual([{ count: 1 }]);
      expect(
        (
          await pool.query(
            "select id,state,attempts from jobs where id=any($1::uuid[]) order by id",
            [
              [
                expiryJobId,
                clockJobId,
                ...alertJobs.map(([jobId]) => jobId),
                actionScanJobId,
                taskScanJobId,
                jobRetentionJobId,
                logRetentionJobId,
                feedReconcileJobId,
                feedConsistencyJobId
              ]
            ]
          )
        ).rows
      ).toEqual(
        [
          expiryJobId,
          clockJobId,
          ...alertJobs.map(([jobId]) => jobId),
          actionScanJobId,
          taskScanJobId,
          jobRetentionJobId,
          logRetentionJobId,
          feedReconcileJobId,
          feedConsistencyJobId
        ]
          .toSorted()
          .map((id) => ({ id, state: "succeeded", attempts: 1 }))
      );
      const dueProjection = await pool.query<{
        action_type: string;
        canonical_payload: Buffer;
        event_type: string;
        notice_type: string;
        task_state: string;
      }>(
        `select task.state as task_state,notice.notice_type,feed.action_type,
                feed.canonical_payload,audit.event_type
           from tasks as task
           join notices as notice
             on notice.object_type='task' and notice.object_id=task.id
            and notice.notice_type='task_due'
           join pending_action_feed as feed on feed.notice_id=notice.id
           join audit_events as audit on audit.id=notice.audit_event_id
          where task.id=$1`,
        [dueTaskId]
      );
      expect(dueProjection.rows).toHaveLength(1);
      expect(dueProjection.rows[0]).toMatchObject({
        task_state: "open",
        notice_type: "task_due",
        action_type: "task_due",
        event_type: "notice_delivered"
      });
      expect(JSON.parse(dueProjection.rows[0]!.canonical_payload.toString("utf8"))).toMatchObject({
        schemaVersion: "boardagent.pending-action.v1",
        deltaType: "task_due",
        objectType: "task",
        objectId: dueTaskId,
        objectVersion: 1,
        actionState: "pending",
        safeRefs: {
          dueAt: "2026-09-03T11:00:00.000000Z",
          taskSha256: dueTaskSha256
        }
      });
    });
  });
});
