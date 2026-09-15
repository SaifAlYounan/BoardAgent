import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { loadAdmittedBoardProjection } from "../../artifacts/server/src/board-projection-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

// The two old SQL expressions are independent byte oracles. No board-version
// payload, governance mutation ceremony, task/admin diagnostic or native transport
// runs in this named case. Storage fixtures retain all ordinary constraints.
const toolOracle = `select jsonb_build_object(
  'board_id',board.id,'slug',board.slug,'name',board.name,'timezone',board.timezone,
  'state',board.state,'current_version_id',board.current_version_id,
  'governance_profile_id',board.current_governance_profile_id,
  'ruleset_id',board.current_ruleset_id,'row_version',board.row_version::text,
  'created_at',to_char(board.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
) as payload from boards as board where board.id=$1`;
const resourceOracle = `select jsonb_build_object('schema_version','boardagent.board-resource.v1',
  'board_id',board.id,'slug',board.slug,'name',board.name,
  'timezone',board.timezone,'state',board.state,
  'current_version_id',board.current_version_id,
  'governance_profile_id',board.current_governance_profile_id,
  'ruleset_id',board.current_ruleset_id,'row_version',board.row_version::text) as payload
  from boards as board where board.id=$1`;

it("admits exact fixed board views under actual server-role RLS and fresh visibility", async () => {
  await withMigratedDatabase("board_projection", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["governance:read"]
    });
    const otherBoard = testId(1800);
    await pool.query(
      "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'other','Other','UTC')",
      [otherBoard, actor.organizationId]
    );
    const manager = new ResponseAllocationManager();
    const smallPlan = responseAllocationPlan({
      kind: "document",
      representation: "resource",
      canonicalBytes: 1,
      sourceId: actor.boardId,
      sourceVersion: "1",
      sha256: "a".repeat(64)
    });
    async function read(
      lane: "tool" | "resource",
      options: {
        board?: string;
        emptyBoardScope?: boolean;
        afterMetadata?: () => Promise<void>;
        saturated?: boolean;
      } = {}
    ) {
      let content = 0,
        metadata = 0;
      const owner = manager.openRequest(new AbortController().signal);
      try {
        const value = await owner.produce(() =>
          withRequestTransaction(
            pool,
            options.emptyBoardScope ? { ...actor.context, boardIds: [] } : actor.context,
            async (client) => {
              expect((await client.query("select current_user")).rows[0].current_user).toBe(
                "boardagent_server"
              );
              const observed = {
                query: async (sql: string, values?: unknown[]) => {
                  const scalar = sql.includes("as admitted_board_id");
                  if (!scalar) {
                    content += 1;
                    expect(manager.accounting.usedUnits).toBeGreaterThan(0);
                  }
                  const result = await client.query(sql, values);
                  if (scalar) {
                    metadata += 1;
                    for (const row of result.rows) {
                      expect(Object.keys(row).sort()).toEqual(["admitted_board_id", "row_version"]);
                      expect(typeof row.admitted_board_id).toBe("string");
                      expect(typeof row.row_version).toBe("string");
                    }
                    await options.afterMetadata?.();
                  }
                  return result;
                }
              } as unknown as PoolClient;
              return loadAdmittedBoardProjection(observed, options.board ?? actor.boardId, lane);
            },
            { assumeRole: "boardagent_server" }
          )
        );
        expect(metadata).toBe(1);
        return { value, content };
      } catch (error) {
        if (options.saturated) {
          expect(error).toBeInstanceOf(ResponseAllocationUnavailable);
          expect(metadata).toBe(1);
          expect(content).toBe(0);
        }
        throw error;
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
    for (const lane of ["tool", "resource"] as const) {
      for (const character of ["🙂", "界", "\u0001", '"', "\\"]) {
        // Maximum storage character lengths, not a claim that the public board
        // configuration accepts an arbitrary timezone. Each update increments the
        // existing optimistic row version; no constraint or trigger is disabled.
        await pool.query(
          `update boards set slug=$2,name=$3,timezone=$4,row_version=row_version+1 where id=$1`,
          [actor.boardId, "a".repeat(80), character.repeat(512), character.repeat(128)]
        );
        const oracle = await withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            const found = await client.query(lane === "tool" ? toolOracle : resourceOracle, [
              actor.boardId
            ]);
            expect(found.rows).toHaveLength(1);
            return found.rows[0].payload;
          },
          { assumeRole: "boardagent_server" }
        );
        expect(Object.keys(oracle)).toHaveLength(10);
        expect(Buffer.byteLength(JSON.stringify(oracle))).toBeLessThan(32768);
        const actual = await read(lane);
        expect(actual.content).toBe(1);
        if (!actual.value) throw new Error("authorized board disappeared");
        expect(canonicalJson(actual.value.payload)).toBe(canonicalJson(oracle));
        expect(manager.accounting.usedUnits).toBe(0);
      }
      expect(await read(lane, { board: otherBoard })).toEqual({ value: null, content: 0 });
      expect(await read(lane, { board: testId(1801) })).toEqual({ value: null, content: 0 });
      const held = Array.from({ length: 2048 }, () => manager.tryReserve(smallPlan));
      try {
        await expect(read(lane, { saturated: true })).rejects.toThrow(
          ResponseAllocationUnavailable
        );
      } finally {
        held.forEach((lease) => lease.release());
      }

      const changed = await read(lane, {
        afterMetadata: async () => {
          await pool.query(
            "update boards set name='Fresh Mining board',row_version=row_version+1 where id=$1",
            [actor.boardId]
          );
        }
      });
      expect(changed.value?.payload).toMatchObject({ name: "Fresh Mining board" });
      expect(changed.content).toBe(1);
      const hidden = await read(lane, {
        afterMetadata: async () => {
          await pool.query(
            "update board_memberships set state='ended',active_until=transaction_timestamp() where board_id=$1 and member_id=$2",
            [actor.boardId, actor.memberId]
          );
        }
      });
      // The boards SELECT policy consults the installed request board scope,
      // not the membership table again. This direct helper deliberately retains
      // that old scope: it does not exercise public fresh-request authentication.
      expect(hidden.value?.payload).toMatchObject({ name: "Fresh Mining board" });
      expect(hidden.content).toBe(1);
      expect(await read(lane, { emptyBoardScope: true })).toEqual({ value: null, content: 0 });
      await pool.query(
        "update board_memberships set state='active',active_until=null where board_id=$1 and member_id=$2",
        [actor.boardId, actor.memberId]
      );
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
