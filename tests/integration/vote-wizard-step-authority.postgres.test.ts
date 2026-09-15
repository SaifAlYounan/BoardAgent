import { describe, expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testId,
  testHash
} from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("vote wizard step database authority", () => {
  it("allows only the live secretary's own final preparation step and keeps it immutable", async () => {
    await withMigratedDatabase("vote-wizard-authority", async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const other = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 100,
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const member = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 200,
        seatRole: "voting_member",
        scopes: ["secretariat:admin"]
      });
      for (const [offset, type, state] of [
        [0, "vote", "ready_to_confirm"],
        [1, "vote", "cancelled"],
        [2, "meeting", "ready_to_confirm"],
        [3, "vote", "ready_to_confirm"]
      ] as const) {
        await pool.query(
          `insert into wizard_drafts(id,organization_id,board_id,draft_type,creator_member_id,
          signed_context,context_sha256,state,created_at,expires_at)
          values($1,$2,$3,$4,$5,$6,$7,$8,transaction_timestamp()-interval '20 minutes',
            transaction_timestamp()+case when $9 then interval '-10 minutes' else interval '10 minutes' end)`,
          [
            testId(900 + offset),
            secretary.organizationId,
            secretary.boardId,
            type,
            secretary.memberId,
            Buffer.alloc(32),
            testHash(88),
            state,
            offset === 3
          ]
        );
      }
      let nextId = 1000;
      const insert = (actor: typeof secretary, draftId = testId(900)) =>
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            client.query(
              `insert into wizard_steps(id,draft_id,ordinal,question_code,value_schema,canonical_value,value_sha256,citation_snapshot,attempt)
        values($1,$2,0,'final_package','boardagent.vote-wizard-final-review.v1',$3,$4,'[]',1)`,
              [testId(nextId++), draftId, Buffer.from("{}"), testHash(89)]
            ),
          { assumeRole: "boardagent_server" }
        );
      // These are direct database requests using the application's actual role.
      for (const actor of [
        other,
        member,
        { ...secretary, context: { ...secretary.context, boardIds: [] } }
      ]) {
        await expect(insert(actor)).rejects.toMatchObject({ code: "42501" });
      }
      await expect(insert(secretary, testId(901))).rejects.toMatchObject({ code: "42501" });
      await expect(insert(secretary, testId(902))).rejects.toMatchObject({ code: "42501" });
      await expect(insert(secretary, testId(903))).rejects.toMatchObject({ code: "42501" });
      await expect(insert(secretary)).resolves.toMatchObject({ rowCount: 1 });
      for (const statement of [
        "update wizard_steps set canonical_value=$1",
        "delete from wizard_steps"
      ]) {
        await expect(
          withRequestTransaction(
            pool,
            secretary.context,
            (client) =>
              client.query(
                statement,
                statement.startsWith("update") ? [Buffer.from("changed")] : []
              ),
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toMatchObject({ code: "42501" });
      }
      expect((await pool.query("select count(*)::int as count from wizard_steps")).rows).toEqual([
        { count: 1 }
      ]);
      await pool.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [secretary.accessTokenRecordId]
      );
      await expect(insert(secretary)).rejects.toMatchObject({ code: "42501" });
    });
  });
});
