import { createHash } from "node:crypto";
import type { JsonValue } from "@boardagent/contracts";
import type { PoolClient } from "pg";
import { loadWithResponseAllocation, responseAllocationPlan } from "./response-allocation.js";

// Only the two fixed ten-field point views belong here. Both retain the original
// RLS scope and public JSON shape. No board-version payload or nested graph is
// included in the constant-size plan. PostgreSQL/RLS workspace is not bounded.
export async function loadAdmittedBoardProjection(
  client: PoolClient,
  boardId: string,
  representation: "tool" | "resource"
): Promise<Readonly<{ id: string; row_version: string; payload: JsonValue }> | null> {
  const metadata = await client.query<{ admitted_board_id: string; row_version: string }>(
    `select id as admitted_board_id,row_version::text from boards where id=$1`,
    [boardId]
  );
  const admitted = metadata.rows[0];
  if (!admitted) return null;
  const plan = responseAllocationPlan({
    kind: "board_projection",
    representation,
    canonicalBytes: 0,
    sourceId: admitted.admitted_board_id,
    sourceVersion: admitted.row_version,
    // A private reservation identity, not a canonical content commitment. Boards
    // are mutable: the fresh authorized version still fits the same fixed plan.
    sha256: createHash("sha256")
      .update(JSON.stringify([admitted.admitted_board_id, admitted.row_version, representation]))
      .digest("hex")
  });
  const projection =
    representation === "tool"
      ? `jsonb_build_object(
          'board_id',board.id,'slug',board.slug,'name',board.name,'timezone',board.timezone,
          'state',board.state,'current_version_id',board.current_version_id,
          'governance_profile_id',board.current_governance_profile_id,
          'ruleset_id',board.current_ruleset_id,'row_version',board.row_version::text,
          'created_at',to_char(board.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        )`
      : `jsonb_build_object('schema_version','boardagent.board-resource.v1',
                  'board_id',board.id,'slug',board.slug,'name',board.name,
                  'timezone',board.timezone,'state',board.state,
                  'current_version_id',board.current_version_id,
                  'governance_profile_id',board.current_governance_profile_id,
                  'ruleset_id',board.current_ruleset_id,'row_version',board.row_version::text)`;
  const found = await loadWithResponseAllocation(plan, () =>
    client.query<{ id: string; row_version: string; payload: JsonValue }>(
      `select board.id,board.row_version::text,${projection} as payload
       from boards as board where board.id=$1`,
      [boardId]
    )
  );
  return found.rows[0] ?? null;
}
