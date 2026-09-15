import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { loadWithResponseAllocation, responseAllocationPlan } from "./response-allocation.js";

// Only these two existing bytea resources share this loader. Their stored canonical
// payloads have a 2..10 MiB constraint; their composite tool views are not covered.
export async function loadAdmittedCanonicalVersion(
  client: PoolClient,
  input: Readonly<{
    kind: "submission" | "agenda";
    boardId: string;
    parentId: string;
    version: number;
    memberId: string;
  }>
): Promise<Readonly<{ id: string; version: number; bytes: Buffer }> | null> {
  const submission = input.kind === "submission";
  // Static alternatives only. Keep all original parent joins and explicit access
  // predicates in both queries, in addition to their ordinary table RLS policies.
  const scope = submission
    ? `from management_submission_threads as thread
       join management_submission_versions as version_row on version_row.thread_id=thread.id
      where thread.board_id=$1 and thread.id=$2 and version_row.version=$3
        and ($4::uuid=any(thread.management_owner_ids) or thread.assigned_secretary_id=$4
          or exists (select 1 from board_memberships as membership
            where membership.board_id=thread.board_id and membership.member_id=$4
              and membership.state='active' and membership.is_secretary))`
    : `from meetings as meeting
       join agenda_versions as version_row on version_row.meeting_id=meeting.id
      where meeting.board_id=$1 and meeting.id=$2 and version_row.version=$3`;
  const digestColumn = submission ? "payload_sha256" : "canonical_sha256";
  const parameters: unknown[] = [input.boardId, input.parentId, input.version];
  if (submission) parameters.push(input.memberId);
  const found = await client.query<{
    id: string;
    version: number;
    byte_length: number;
    sha256: string;
  }>(
    `select version_row.id,version_row.version,
            octet_length(version_row.canonical_payload) as byte_length,
            encode(version_row.${digestColumn},'hex') as sha256
       ${scope}`,
    parameters
  );
  const row = found.rows[0];
  if (!row) return null;
  const plan = responseAllocationPlan({
    kind: "canonical_resource",
    representation: "resource",
    sourceId: row.id,
    sourceVersion: `${input.kind}:${input.parentId}:${String(row.version)}`,
    sha256: row.sha256,
    canonicalBytes: row.byte_length
  });
  const first = parameters.length + 1;
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<{ canonical_payload: Buffer }>(
      `select version_row.canonical_payload ${scope}
         and version_row.id=$${first}
         and octet_length(version_row.canonical_payload)=$${first + 1}
         and version_row.${digestColumn}=$${first + 2}`,
      [...parameters, row.id, row.byte_length, Buffer.from(row.sha256, "hex")]
    )
  );
  const bytes = loaded.rows[0]?.canonical_payload;
  if (!bytes) return null;
  if (
    bytes.length !== row.byte_length ||
    createHash("sha256").update(bytes).digest("hex") !== row.sha256
  )
    throw new Error("canonical version failed integrity verification");
  return { id: row.id, version: row.version, bytes };
}
