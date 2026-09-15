import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { loadWithResponseAllocation, responseAllocationPlan } from "./response-allocation.js";

type GovernanceCanonicalResourceInput = Readonly<
  { boardId: string; parentId: string } & (
    | { kind: "minutes"; version: number }
    | { kind: "minutes_review"; itemId: string }
    | { kind: "decision_package"; version: number }
  )
>;

// Three raw aliases only. Keep the same parent/version/recusal scope in both
// statements, letting each statement apply the existing role's RLS again.
// PostgreSQL scalar/detoast/convert_to work is outside this Node allocation policy.
export async function loadAdmittedGovernanceCanonicalResource(
  client: PoolClient,
  input: GovernanceCanonicalResourceInput
): Promise<Readonly<{ id: string; version: number; bytes: Buffer }> | null> {
  const minutes = input.kind === "minutes";
  const review = input.kind === "minutes_review";
  const record = minutes ? "version_row" : review ? "item" : "package";
  const bytesExpression = minutes
    ? "convert_to(version_row.canonical_text,'UTF8')"
    : `${record}.canonical_payload`;
  const digestColumn = minutes ? "canonical_sha256" : review ? "payload_sha256" : "package_sha256";
  const scope = minutes
    ? `from minutes join minutes_versions as version_row on version_row.minutes_id=minutes.id
       where minutes.board_id=$1 and minutes.id=$2 and version_row.version=$3`
    : review
      ? `from minutes join minutes_review_items as item on item.minutes_id=minutes.id
         where minutes.board_id=$1 and minutes.id=$2 and item.id=$3`
      : `from votes as vote join decision_packages as package on package.vote_id=vote.id
         where vote.board_id=$1 and vote.id=$2 and package.version=$3
           and not boardagent_member_vote_recused(vote.id,
             boardagent_context_uuid('boardagent.member_id'))`;
  const parameters = [input.boardId, input.parentId, review ? input.itemId : input.version];
  const found = await client.query<{
    id: string;
    version: number;
    byte_length: number;
    sha256: string;
  }>(
    `select ${record}.id,${review ? "1::integer" : `${record}.version`} as version,
       octet_length(${bytesExpression}) as byte_length,
       encode(${record}.${digestColumn},'hex') as sha256 ${scope}`,
    parameters
  );
  const row = found.rows[0];
  if (!row) return null;
  // The review-item table has its own tighter byte bound. Minutes' stored limit
  // is in characters: up to four UTF-8 bytes each, not an invented 10 MiB cap.
  if (review && row.byte_length > 1_048_576)
    throw new RangeError("authorized response byte length is invalid");
  const plan = responseAllocationPlan({
    kind: minutes ? "minutes_text" : "canonical_resource",
    representation: "resource",
    sourceId: row.id,
    sourceVersion: `${input.kind}:${input.parentId}:${String(row.version)}`,
    sha256: row.sha256,
    canonicalBytes: row.byte_length
  });
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<{ canonical_bytes: Buffer }>(
      `select ${bytesExpression} as canonical_bytes ${scope}
         and ${record}.id=$4
         and octet_length(${bytesExpression})=$5
         and ${record}.${digestColumn}=$6`,
      [...parameters, row.id, row.byte_length, Buffer.from(row.sha256, "hex")]
    )
  );
  const bytes = loaded.rows[0]?.canonical_bytes;
  if (!bytes) return null;
  if (
    bytes.length !== row.byte_length ||
    createHash("sha256").update(bytes).digest("hex") !== row.sha256
  )
    throw new Error("governance canonical resource failed integrity verification");
  return { id: row.id, version: row.version, bytes };
}
