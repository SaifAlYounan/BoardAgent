import { describe, expect, it } from "vitest";
import { withConfiguredFixtureWorker } from "../helpers/configured-worker.js";

import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  projectDueActionItemsInTransaction,
  projectDueTasksInTransaction,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("task and minutes-action due projection", () => {
  it("the production worker projects a due task without completing it or injecting a scan", async () => {
    await withMigratedDatabase("task-runtime-scheduler", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "management",
        scopes: ["task:act"]
      });
      const taskId = testId(81_000);
      await pool.query(
        `insert into tasks(id,organization_id,board_id,owner_member_id,due_at,description_schema,
        canonical_description,required_evidence,task_sha256,state,row_version,created_by,created_at)
        values($1,$2,$3,$4,transaction_timestamp()-interval '1 minute','boardagent.task.v1','Synthetic due task',
          '{"items":[]}',decode($5,'hex'),'open',1,$4,transaction_timestamp()-interval '2 minutes')`,
        [taskId, actor.organizationId, actor.boardId, actor.memberId, canonicalSha256({ taskId })]
      );
      expect((await pool.query("select count(*)::int as count from jobs")).rows[0]?.count).toBe(0);
      await withConfiguredFixtureWorker(pool, actor.organizationId, async (worker) => {
        const abort = new AbortController();
        let error: unknown;
        const loop = worker.run(abort.signal).catch((value: unknown) => {
          error = value;
        });
        try {
          await expect
            .poll(
              async () => {
                if (error) throw error;
                return (
                  await pool.query(
                    "select count(*)::int as count from notices where object_id=$1 and notice_type='task_due'",
                    [taskId]
                  )
                ).rows[0]?.count;
              },
              { timeout: 5_000, interval: 50 }
            )
            .toBe(1);
          expect((await pool.query("select state from tasks where id=$1", [taskId])).rows).toEqual([
            { state: "open" }
          ]);
        } finally {
          abort.abort();
          await loop;
        }
      });
    });
  }, 20_000);

  it("keeps the two typed scans isolated, worker-only, idempotent and state preserving", async () => {
    await withMigratedDatabase("task-due-scheduler", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "management",
        scopes: ["task:act"]
      });
      const meetingId = testId(80_000);
      const minutesId = testId(80_001);
      const minutesVersionId = testId(80_002);
      const minutesText = "# Minutes\nApproved action source.\n";
      const minutesSha256 = canonicalSha256({ text: minutesText });
      const setupClient = await pool.connect();
      try {
        await setupClient.query("begin");
        await setupClient.query(
          `insert into meetings(
             id,organization_id,board_id,title,scheduled_start,scheduled_end,created_by
           ) values ($1,$2,$3,'Due projection meeting',
                     transaction_timestamp()+interval '1 hour',
                     transaction_timestamp()+interval '2 hours',$4)`,
          [meetingId, actor.organizationId, actor.boardId, actor.memberId]
        );
        await setupClient.query(
          `insert into minutes(id,organization_id,board_id,meeting_id,created_by)
           values ($1,$2,$3,$4,$5)`,
          [minutesId, actor.organizationId, actor.boardId, meetingId, actor.memberId]
        );
        await setupClient.query(
          `insert into minutes_versions(
             id,organization_id,board_id,minutes_id,version,canonical_schema,canonical_text,
             canonical_sha256,package_base_sha256,created_by
           ) values ($1,$2,$3,$4,1,'boardagent.minutes.v1',$5,$6,$7,$8)`,
          [
            minutesVersionId,
            actor.organizationId,
            actor.boardId,
            minutesId,
            minutesText,
            Buffer.from(minutesSha256, "hex"),
            Buffer.from(canonicalSha256({ minutesId, version: 1, minutesSha256 }), "hex"),
            actor.memberId
          ]
        );
        await setupClient.query(
          "update minutes set current_version_id=$1,state='published_review',row_version=2 where id=$2",
          [minutesVersionId, minutesId]
        );
        await setupClient.query(
          "update meetings set current_minutes_id=$1,row_version=2 where id=$2",
          [minutesId, meetingId]
        );
        await setupClient.query("commit");
      } catch (error) {
        await setupClient.query("rollback").catch(() => undefined);
        throw error;
      } finally {
        setupClient.release();
      }

      const actionItemId = testId(80_010);
      const standaloneTaskId = testId(80_011);
      const draftActionItemId = testId(80_012);
      const futureActionItemId = testId(80_013);
      const taskRows = [
        {
          id: actionItemId,
          source: true,
          dueAt: "2026-09-03T11:00:00Z",
          state: "open"
        },
        {
          id: standaloneTaskId,
          source: false,
          dueAt: "2026-09-03T11:15:00Z",
          state: "open"
        },
        {
          id: draftActionItemId,
          source: true,
          dueAt: "2026-09-03T11:30:00Z",
          state: "draft"
        },
        {
          id: futureActionItemId,
          source: true,
          dueAt: "2026-09-05T11:30:00Z",
          state: "open"
        }
      ] as const;
      for (const [index, task] of taskRows.entries()) {
        const taskSha256 = canonicalSha256({
          schemaVersion: "boardagent.task.v1",
          taskId: task.id,
          dueAt: task.dueAt
        });
        await pool.query(
          `insert into tasks(
             id,organization_id,board_id,source_meeting_id,source_minutes_id,
             source_minutes_version_id,source_minutes_sha256,source_locator,
             owner_member_id,due_at,description_schema,canonical_description,
             required_evidence,task_sha256,state,row_version,created_by,created_at
           ) values (
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'boardagent.task.v1',$11,
             jsonb_build_object('items',jsonb_build_array()),$12,$13,1,$9,
             '2026-09-02T11:00:00Z'
           )`,
          [
            task.id,
            actor.organizationId,
            actor.boardId,
            task.source ? meetingId : null,
            task.source ? minutesId : null,
            task.source ? minutesVersionId : null,
            task.source ? Buffer.from(minutesSha256, "hex") : null,
            task.source ? { section: `action-${String(index + 1)}` } : null,
            actor.memberId,
            task.dueAt,
            `Due projection fixture ${String(index + 1)}`,
            Buffer.from(taskSha256, "hex"),
            task.state
          ]
        );
      }

      const through = "2026-09-03T12:00:00.000Z";
      let nextId = 80_100;
      const newId = (): string => testId(nextId++);
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            projectDueActionItemsInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              through,
              newId
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied/i);
      await expect(
        withWorkerTransaction(
          pool,
          (client) => client.query("update tasks set row_version=row_version+1"),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toThrow(/permission denied/i);

      const actions = await withWorkerTransaction(
        pool,
        (client) =>
          projectDueActionItemsInTransaction(client, {
            organizationId: actor.organizationId,
            boardId: actor.boardId,
            through,
            newId
          }),
        { assumeRole: "boardagent_worker" }
      );
      expect(actions.map(({ taskId }) => taskId)).toEqual([actionItemId]);
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            projectDueActionItemsInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              through,
              newId
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).resolves.toEqual([]);

      const tasks = await withWorkerTransaction(
        pool,
        (client) =>
          projectDueTasksInTransaction(client, {
            organizationId: actor.organizationId,
            boardId: actor.boardId,
            through,
            newId
          }),
        { assumeRole: "boardagent_worker" }
      );
      expect(tasks.map(({ taskId }) => taskId)).toEqual([standaloneTaskId]);
      await expect(
        withWorkerTransaction(
          pool,
          (client) =>
            projectDueTasksInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              through,
              newId
            }),
          { assumeRole: "boardagent_worker" }
        )
      ).resolves.toEqual([]);

      const readback = await pool.query<{
        action_type: string | null;
        canonical_payload: Buffer | null;
        id: string;
        notice_type: string | null;
        state: string;
      }>(
        `select task.id,task.state,notice.notice_type,feed.action_type,feed.canonical_payload
           from tasks as task
           left join notices as notice
             on notice.object_type='task' and notice.object_id=task.id
            and notice.notice_type='task_due'
           left join pending_action_feed as feed on feed.notice_id=notice.id
          order by task.id`
      );
      expect(
        readback.rows.map((row) => ({
          id: row.id,
          state: row.state,
          noticeType: row.notice_type,
          actionType: row.action_type
        }))
      ).toEqual([
        { id: actionItemId, state: "open", noticeType: "task_due", actionType: "task_due" },
        {
          id: standaloneTaskId,
          state: "open",
          noticeType: "task_due",
          actionType: "task_due"
        },
        { id: draftActionItemId, state: "draft", noticeType: null, actionType: null },
        { id: futureActionItemId, state: "open", noticeType: null, actionType: null }
      ]);
      for (const row of readback.rows.filter(
        ({ canonical_payload }) => canonical_payload !== null
      )) {
        expect(JSON.parse(row.canonical_payload!.toString("utf8"))).toMatchObject({
          schemaVersion: "boardagent.pending-action.v1",
          deltaType: "task_due",
          objectType: "task",
          objectId: row.id,
          objectVersion: 1,
          actionState: "pending"
        });
      }
    });
  });
});
