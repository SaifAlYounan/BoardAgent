import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { loadWithResponseAllocation, responseAllocationPlan } from "./response-allocation.js";

// These existing JSONB columns have no canonical byte-size maximum. Measure the
// actual serialized value rather than treating it as a 10 MiB document. PostgreSQL
// text/digest/detoast workspace precedes admission and is not bounded here.
export async function loadAdmittedGovernanceJson(
  client: PoolClient,
  input: Readonly<{ kind: "governance_profile" | "ruleset"; boardId: string; version: number }>
): Promise<Readonly<{ id: string; version: number; payload: unknown }> | null> {
  const table = input.kind === "governance_profile" ? "governance_profiles" : "rulesets";
  const scope = `from ${table} where board_id=$1 and version=$2`;
  const found = await client.query<{
    id: string;
    version: number;
    byte_length: number;
    sha256: string;
  }>(
    `select id,version,octet_length(convert_to(canonical_payload::text,'UTF8')) as byte_length,
            encode(sha256(convert_to(canonical_payload::text,'UTF8')),'hex') as sha256
       ${scope}`,
    [input.boardId, input.version]
  );
  const row = found.rows[0];
  if (!row) return null;
  const plan = responseAllocationPlan({
    kind: "json_resource",
    representation: "resource",
    sourceId: row.id,
    sourceVersion: `${input.kind}:${input.boardId}:${String(row.version)}`,
    sha256: row.sha256,
    canonicalBytes: row.byte_length
  });
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<{ raw_bytes: Buffer }>(
      `select convert_to(canonical_payload::text,'UTF8') as raw_bytes ${scope}
       and id=$3 and octet_length(convert_to(canonical_payload::text,'UTF8'))=$4
       and sha256(convert_to(canonical_payload::text,'UTF8'))=$5`,
      [input.boardId, input.version, row.id, row.byte_length, Buffer.from(row.sha256, "hex")]
    )
  );
  const bytes = loaded.rows[0]?.raw_bytes;
  if (!bytes) return null;
  if (
    bytes.length !== row.byte_length ||
    createHash("sha256").update(bytes).digest("hex") !== row.sha256
  )
    throw new Error("JSON resource failed integrity verification");
  // Equivalent to pg's ordinary JSONB parser, now after reservation. The caller
  // retains its existing JsonValue validation and canonical resource serialization.
  return {
    id: row.id,
    version: row.version,
    payload: JSON.parse(bytes.toString("utf8")) as unknown
  };
}
