import { describe, expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

describe("AC21 administrative function temporary-schema isolation", () => {
  it.each(["uuid", "jsonb", "text"] as const)(
    "ignores caller-owned temporary %s types when first compiling privileged code",
    async (typeName) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool);
        // Hold the migration/fixture connection so the function is first called on a fresh backend.
        const reserved = await pool.connect();
        try {
          const result = await withRequestTransaction(
            pool,
            issuer.context,
            async (client) => {
              await client.query(
                "create temporary table test_schema_marker(id integer) on commit drop"
              );
              // A harmless failing domain detects accidental type resolution in the temporary schema.
              // It does not create functions, read secrets or change any board record.
              await client.query(
                `create domain pg_temp.${typeName} as pg_catalog.${typeName} check (false)`
              );
              return client.query(
                "select public.boardagent_company_admin_snapshot($1::pg_catalog.jsonb) as snapshot",
                [
                  {
                    schema_version: "boardagent.tool-input.v1",
                    idempotency_key: "temp-schema-authority-check",
                    change: {
                      operation: "grant",
                      proposal_id: testId(112801),
                      member_id: target.memberId,
                      expected_member_version: 1,
                      reason: "Synthetic temporary-schema isolation check"
                    }
                  }
                ]
              );
            },
            { assumeRole: "boardagent_server", isolation: "serializable" }
          );
          expect(result.rows[0]?.snapshot.operation).toBe("grant");
          expect(
            (await pool.query("select count(*)::int as n from company_admin_proposals")).rows[0]
          ).toEqual({ n: 0 });
        } finally {
          reserved.release();
        }
      });
    }
  );
});
