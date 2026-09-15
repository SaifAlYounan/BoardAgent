import { describe, expect, it } from "vitest";

import { withRequestTransaction } from "../../lib/db/src/context.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("TH-54 pooled RLS context bleed", () => {
  it("clears transaction-local identity and board state before the connection is reused", async () => {
    await withMigratedDatabase(
      "rls_context_bleed",
      async (pool) => {
        const organizationA = testId(54_001);
        const organizationB = testId(54_002);
        const memberA = testId(54_003);
        const memberB = testId(54_004);
        const boardA = testId(54_005);
        const boardB = testId(54_006);
        await pool.query(
          `insert into organizations(id,legal_name,display_name,slug,timezone) values
             ($1,'Org A','Org A','org-a','UTC'),($2,'Org B','Org B','org-b','UTC')`,
          [organizationA, organizationB]
        );
        await pool.query(
          `insert into members(id,organization_id,member_kind,legal_name,display_name,state) values
             ($1,$2,'human','A','A','active'),($3,$4,'human','B','B','active')`,
          [memberA, organizationA, memberB, organizationB]
        );
        await pool.query(
          `insert into boards(id,organization_id,slug,name,timezone) values
             ($1,$2,'board-a','Board A','UTC'),($3,$4,'board-b','Board B','UTC')`,
          [boardA, organizationA, boardB, organizationB]
        );
        const context = {
          clientId: testId(54_007),
          tokenJti: testId(54_008)
        };
        const first = await withRequestTransaction(
          pool,
          {
            ...context,
            organizationId: organizationA,
            memberId: memberA,
            boardIds: [boardA]
          },
          (client) => client.query<{ id: string }>("select id from boards order by id"),
          { assumeRole: "boardagent_server" }
        );
        expect(first.rows).toEqual([{ id: boardA }]);

        const reused = await pool.connect();
        try {
          await reused.query("begin");
          await reused.query("set local role boardagent_server");
          expect((await reused.query("select id from boards order by id")).rows).toEqual([]);
          await reused.query("commit");
        } finally {
          reused.release();
        }

        const second = await withRequestTransaction(
          pool,
          {
            ...context,
            organizationId: organizationB,
            memberId: memberB,
            boardIds: [boardB]
          },
          (client) => client.query<{ id: string }>("select id from boards order by id"),
          { assumeRole: "boardagent_server" }
        );
        expect(second.rows).toEqual([{ id: boardB }]);
      },
      1
    );
  });
});
