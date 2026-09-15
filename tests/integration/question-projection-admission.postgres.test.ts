import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import {
  answerManagementQuestionInTransaction,
  withRequestTransaction,
  type ManagementQuestionView
} from "../../lib/db/src/index.js";
import {
  QUESTION_PROJECTION_PREFLIGHT_SQL,
  QUESTION_PROJECTION_CONTENT_SQL,
  type ManagementQuestionProjectionMetadata
} from "../../lib/db/src/question-queries.js";
import { prepareManagementQuestionTurn } from "../../lib/domain/src/question.js";
import {
  loadAdmittedManagementQuestion,
  questionProjectionCost,
  questionProjectionPlan
} from "../../artifacts/server/src/question-projection-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedQuestionFixture } from "../helpers/question-fixture.js";
import { seedAdditionalAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { readOriginalQuestionProjection } from "../helpers/question-projection-original-oracle.js";
import { seedQuestionProjectionLink } from "../helpers/question-projection-link-fixture.js";

const hash = (text: string) => createHash("sha256").update(text).digest();
function shape(value: unknown) {
  const stack: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (stack.length) {
    const item = stack.pop();
    if (item && typeof item === "object") {
      containers += 1;
      if (!Array.isArray(item)) properties += Object.keys(item).length;
      for (const child of Object.values(item)) stack.push(child);
    }
  }
  return { properties, containers };
}
function flatBytes(q: ManagementQuestionView) {
  const values: unknown[] = [
    q.questionId,
    q.boardId,
    q.askerMemberId,
    q.dueAt,
    q.state,
    q.currentTurnId,
    q.rowVersion,
    q.turnCount,
    q.answerCount,
    q.createdAt
  ];
  for (const t of q.turns)
    values.push(
      t.turnId,
      t.ordinal,
      t.turnKind,
      t.authorMemberId,
      t.authorRole,
      t.canonicalText,
      t.textSha256,
      t.answerRecordId,
      t.createdAt
    );
  for (const n of q.deliveries)
    values.push(
      n.noticeId,
      n.noticeType,
      n.objectVersion,
      n.recipientMemberId,
      n.feedSequence,
      n.state,
      n.auditEventId,
      n.createdAt
    );
  for (const l of q.decisionLinks)
    values.push(
      l.linkId,
      l.inclusiveTurnOrdinal,
      l.inclusiveTurnSha256,
      l.decisionPackageId,
      l.decisionPackageVersion,
      l.decisionPackageSha256,
      l.createdAt
    );
  return values.reduce<number>(
    (total, value) => total + (value === null ? 0 : Buffer.byteLength(String(value))),
    0
  );
}

it("admits the measured question graph and gates fresh construction under the actual server role", async () => {
  await withMigratedDatabase("question_projection", async (pool) => {
    const fixture = await seedQuestionFixture(pool, 220000),
      qid = fixture.prepared.questionId;
    const actor = fixture.asker;
    await withRequestTransaction(
      pool,
      fixture.manager.context,
      (client) =>
        answerManagementQuestionInTransaction(client, {
          organizationId: actor.organizationId,
          prepared: prepareManagementQuestionTurn({
            questionId: qid,
            turnKind: "answer",
            text: "Answer Δ 🙂\n",
            citations: []
          }),
          turnId: testId(221000),
          answerRecordId: testId(221001),
          auditEventId: testId(221002),
          idempotencyRecordId: testId(221003),
          idempotencyKey: "question-projection-answer-0001",
          askerDelivery: {
            recipientMemberId: actor.memberId,
            noticeId: testId(221004),
            feedId: testId(221005)
          },
          ownerResolutions: [
            { ownerMemberId: fixture.manager.memberId, tombstoneId: testId(221006) }
          ],
          sourceUpdateAuditEvents: []
        }),
      { assumeRole: "boardagent_server" }
    );
    // Normal constrained immutable storage fixture for arbitrary legacy JSONB.
    // This is not a public citation schema/writer or a complete workflow ceremony.
    const citationText =
      '[{"wide":1e40,"tiny":1e-40,"nested":[{},[],{"text":"Δ🙂\\n\\\"\\\\","null":null,"flag":false}]}]';
    await pool.query(
      `insert into management_question_turns(id,organization_id,board_id,question_id,ordinal,
      turn_kind,author_member_id,author_role,canonical_text,text_sha256,citation_snapshot,idempotency_record_id)
      select $1,organization_id,board_id,question_id,3,'follow_up',author_member_id,author_role,
        $2,$3,$4::jsonb,idempotency_record_id from management_question_turns where id=$5`,
      [
        testId(221010),
        "Stored citation sample Δ\n",
        hash("Stored citation sample Δ\n"),
        citationText,
        testId(220201)
      ]
    );
    const link = await seedQuestionProjectionLink(pool, actor, qid);
    await pool.query(`create function question_projection_fault() returns uuid language plpgsql volatile as $$
      begin raise exception 'question projection construction fault'; end $$`);
    type Context = typeof actor.context;
    interface Options {
      context?: Context;
      representation?: "tool" | "resource";
      boardId?: string;
      afterPreflight?: (metadata: ManagementQuestionProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      fault?: boolean;
      boundReduction?: boolean;
    }
    const manager = new ResponseAllocationManager();
    let latest: ManagementQuestionProjectionMetadata | undefined;
    let contentCalls = 0,
      contentRows = 0,
      metadataCalls = 0;
    let sequence = 0;
    async function read(options: Options = {}) {
      const owner = manager.openRequest(new AbortController().signal);
      const initialUnits = manager.accounting.usedUnits;
      let chargedUnits: number | undefined;
      try {
        return await withRequestTransaction(
          pool,
          options.context ?? actor.context,
          async (client) => {
            if (options.mode) await client.query(`set local plan_cache_mode = ${options.mode}`);
            const proxy = new Proxy(client, {
              get(target, key) {
                if (key !== "query") return Reflect.get(target, key, target);
                return async (sql: string, values?: unknown[]) => {
                  if (sql === QUESTION_PROJECTION_CONTENT_SQL) {
                    contentCalls += 1;
                    chargedUnits = questionProjectionPlan(
                      latest!,
                      options.representation ?? "tool"
                    ).units;
                    expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      const needle = "'questionId',question.question_id";
                      expect(text.includes(needle)).toBe(true);
                      text = text.replace(needle, "'questionId',question_projection_fault()");
                    }
                    if (options.boundReduction) {
                      parameters = [...(values ?? [])];
                      parameters[10] = "0";
                    }
                    const result = options.mode
                      ? await target.query({
                          name: `question-projection-${String(sequence++)}`,
                          text,
                          ...(parameters === undefined ? {} : { values: parameters })
                        })
                      : await target.query(text, parameters);
                    contentRows += result.rows.filter(
                      (row: { question: unknown }) => row.question !== null
                    ).length;
                    return result;
                  }
                  const result = await target.query(sql, values);
                  if (sql === QUESTION_PROJECTION_PREFLIGHT_SQL) {
                    metadataCalls += 1;
                    latest = result.rows[0] as ManagementQuestionProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            const found = await owner.produce(() =>
              loadAdmittedManagementQuestion(
                proxy,
                qid,
                options.representation ?? "tool",
                options.boardId
              )
            );
            if (chargedUnits !== undefined)
              expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
            return found;
          },
          { assumeRole: "boardagent_server" }
        );
      } catch (error) {
        if (chargedUnits !== undefined)
          expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
        throw error;
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        expect(manager.accounting.usedUnits).toBe(initialUnits);
      }
    }
    // Full raw-value and original JSONB-text oracle runs BEFORE saturation.
    const original = await withRequestTransaction(
      pool,
      actor.context,
      (client) => readOriginalQuestionProjection(client, qid),
      { assumeRole: "boardagent_server" }
    );
    expect(original).not.toBeNull();
    const ordinary = await read();
    expect(ordinary).toEqual(original);
    const q = original!;
    expect(Object.keys(q)).toHaveLength(15);
    expect(q.turns).toHaveLength(3);
    expect(q.turnCount).toBe(3);
    expect(q.answerCount).toBe(1);
    expect(q.turns.some((turn) => turn.answerRecordId === testId(221001))).toBe(true);
    expect(q.deliveries.length).toBeGreaterThan(0);
    expect(q.decisionLinks).toHaveLength(1);
    expect(q.decisionLinks[0]?.linkId).toBe(link.linkId);
    expect(q.decisionLinks[0]?.decisionPackageId).toBe(link.packageId);
    expect(Object.keys(q.decisionLinks[0]!)).toHaveLength(7);
    for (const turn of q.turns) expect(Object.keys(turn)).toHaveLength(10);
    for (const notice of q.deliveries) expect(Object.keys(notice)).toHaveLength(8);
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const original = await client.query<{ value: string }>(
          `select acl_policy::text as value from management_questions where id=$1
        union all select to_jsonb(assigned_owner_ids)::text from management_questions where id=$1
        union all select citation_snapshot::text from management_question_turns where question_id=$1`,
          [qid]
        );
        const measured = await client.query<ManagementQuestionProjectionMetadata>(
          QUESTION_PROJECTION_PREFLIGHT_SQL,
          [qid, null]
        );
        return { raw: original.rows.map((row) => row.value), metadata: measured.rows[0]! };
      },
      { assumeRole: "boardagent_server" }
    );
    expect(oracle.metadata.scalar_utf8).toBe(String(flatBytes(q)));
    expect(oracle.metadata.json_utf8).toBe(
      String(oracle.raw.reduce((sum, value) => sum + Buffer.byteLength(value), 0))
    );
    const shapes = oracle.raw.map((value) => shape(JSON.parse(value)));
    expect(oracle.metadata.json_properties).toBe(
      String(shapes.reduce((sum, value) => sum + value.properties, 0))
    );
    expect(oracle.metadata.json_containers).toBe(
      String(shapes.reduce((sum, value) => sum + value.containers, 0))
    );
    expect(oracle.metadata.projected_turn_count).toBe(String(q.turns.length));
    expect(oracle.metadata.delivery_count).toBe(String(q.deliveries.length));
    expect(oracle.metadata.link_count).toBe(String(q.decisionLinks.length));
    expect(
      oracle.raw.some((value) => value.includes("10000000000000000000000000000000000000000"))
    ).toBe(true);
    expect(
      oracle.raw.some(
        (value) => Buffer.byteLength(value) !== Buffer.byteLength(JSON.stringify(JSON.parse(value)))
      )
    ).toBe(true);
    const cost = questionProjectionCost(oracle.metadata),
      actualShape = shape(q);
    expect(BigInt(Buffer.byteLength(JSON.stringify(q)))).toBeLessThanOrEqual(
      BigInt(cost.jsonUpperBytes)
    );
    expect(BigInt(actualShape.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(actualShape.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    expect(await read({ representation: "resource", boardId: actor.boardId })).toEqual(q);
    const previousContent = contentCalls;
    expect(await read({ representation: "resource", boardId: testId(229999) })).toBeNull();
    expect(contentCalls).toBe(previousContent);
    const held = Array.from({ length: 2048 }, () =>
      manager.tryReserve(
        responseAllocationPlan({
          kind: "document",
          representation: "tool",
          sourceId: "small",
          sourceVersion: "1",
          sha256: "a".repeat(64),
          canonicalBytes: 1
        })
      )
    );
    const beforeMeta = metadataCalls,
      beforeContent = contentCalls;
    try {
      await expect(read()).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(metadataCalls - beforeMeta).toBe(1);
      expect(contentCalls - beforeContent).toBe(0);
    } finally {
      for (const lease of held) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
    for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
      const beforeRows = contentRows;
      await expect(read({ mode, fault: true, boundReduction: true })).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(contentRows).toBe(beforeRows);
      expect(manager.accounting.usedUnits).toBe(0);
      // True-branch fault is a required positive control; it aborts only this
      // request transaction, not the private fixture database.
      await expect(read({ mode, fault: true })).rejects.toThrow(
        "question projection construction fault"
      );
      expect(manager.accounting.usedUnits).toBe(0);
    }
    const notice = q.deliveries.find((value) => value.state === "committed");
    expect(notice).toBeDefined();
    const unchangedRoot = async (expected: ManagementQuestionProjectionMetadata) => {
      const found = await pool.query<{ row_version: string; current_turn_id: string }>(
        `select row_version::text,current_turn_id from management_questions where id=$1`,
        [qid]
      );
      expect(found.rows[0]).toEqual({
        row_version: expected.row_version,
        current_turn_id: expected.current_turn_id
      });
    };
    // Normal constrained notice storage effects, not a delivery public ceremony.
    // Both states have nine UTF-8 bytes, so this current read must be admitted.
    const sameCost = await read({
      afterPreflight: async (metadata) => {
        const changed = await pool.query(
          `update notices set state='delivered',delivered_at=transaction_timestamp()
        where id=$1 and state='committed' returning id`,
          [notice!.noticeId]
        );
        expect(changed.rowCount).toBe(1);
        await unchangedRoot(metadata);
      }
    });
    expect(sameCost!.deliveries.find((value) => value.noticeId === notice!.noticeId)?.state).toBe(
      "delivered"
    );
    // Same child identity/count, one wider state string; root observation stays
    // unchanged. This specifically needs the repeated fresh scalar-width gate.
    await expect(
      read({
        afterPreflight: async (metadata) => {
          const changed = await pool.query(
            `update notices set state='superseded' where id=$1 and state='delivered' returning id`,
            [notice!.noticeId]
          );
          expect(changed.rowCount).toBe(1);
          await unchangedRoot(metadata);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
    await expect(
      read({
        afterPreflight: async (metadata) => {
          const changed = await pool.query<{ row_version: string }>(
            `update management_questions set row_version=row_version+1
        where id=$1 and row_version=$2::bigint returning row_version::text`,
            [qid, metadata.row_version]
          );
          expect(changed.rowCount).toBe(1);
          expect(changed.rows[0]!.row_version.length).toBe(metadata.row_version.length);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(await read()).not.toBeNull();
    const beforeSubset = await read();
    expect(beforeSubset!.decisionLinks).toHaveLength(1);
    const subset = await read({
      afterPreflight: async (metadata) => {
        expect(metadata.link_count).toBe("1");
        await link.exclude();
        await unchangedRoot(metadata);
      }
    });
    expect(subset).toEqual({ ...beforeSubset, decisionLinks: [] });
    expect(manager.accounting.usedUnits).toBe(0);
    // Observer grant/exclusion timing is tested under existing role/RLS. This
    // does not certify every principal or an initial public-request token check.
    await pool.query(
      `insert into question_visibility(id,organization_id,board_id,question_id,grantee_member_id,effect,reason,created_by)
      values($1,$2,$3,$4,$5,'grant','projection fixture visibility',$6)`,
      [
        testId(221020),
        actor.organizationId,
        actor.boardId,
        qid,
        fixture.observer.memberId,
        actor.memberId
      ]
    );
    expect(await read({ context: fixture.observer.context })).not.toBeNull();
    expect(
      await read({
        context: fixture.observer.context,
        afterPreflight: async () => {
          await pool.query(
            `insert into question_visibility(id,organization_id,board_id,question_id,grantee_member_id,effect,reason,created_by)
        values($1,$2,$3,$4,$5,'exclude','projection fixture deny wins',$6)`,
            [
              testId(221021),
              actor.organizationId,
              actor.boardId,
              qid,
              fixture.observer.memberId,
              actor.memberId
            ]
          );
        }
      })
    ).not.toBeNull();
    // The default active_from is later than the already-running request's
    // transaction_timestamp(). The next request observes that exclusion.
    expect(await read({ context: fixture.observer.context })).toBeNull();
    const effectiveObserver = await seedAdditionalAuthorizedActor(pool, actor, {
      idBase: 223000,
      seatRole: "observer",
      scopes: ["governance:read", "management:question"]
    });
    await pool.query(
      `insert into question_visibility(id,organization_id,board_id,question_id,grantee_member_id,effect,reason,created_by)
      values($1,$2,$3,$4,$5,'grant','already-effective projection fixture grant',$6)`,
      [
        testId(223020),
        actor.organizationId,
        actor.boardId,
        qid,
        effectiveObserver.memberId,
        actor.memberId
      ]
    );
    // A separately committed exclusion already effective at request start is
    // visible to the fresh content statement. No access policy is changed.
    const rowsBeforeEffectiveExclusion = contentRows;
    expect(
      await read({
        context: effectiveObserver.context,
        afterPreflight: async () => {
          await pool.query(
            `insert into question_visibility(id,organization_id,board_id,question_id,grantee_member_id,effect,reason,created_by,active_from)
          values($1,$2,$3,$4,$5,'exclude','already-effective projection fixture exclusion',$6,'2000-01-01T00:00:00Z')`,
            [
              testId(223021),
              actor.organizationId,
              actor.boardId,
              qid,
              effectiveObserver.memberId,
              actor.memberId
            ]
          );
        }
      })
    ).toBeNull();
    expect(contentRows).toBe(rowsBeforeEffectiveExclusion);
    expect(await read({ context: effectiveObserver.context })).toBeNull();
    expect(manager.accounting.usedUnits).toBe(0);
    expect(questionProjectionPlan(oracle.metadata, "tool").units).toBeGreaterThan(0);
  });
});
