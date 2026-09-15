import type { Pool } from "pg";
import { canonicalSha256, sha256Hex } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import { administrativeActors } from "./administrative-authority.js";
import { testId } from "./authorized-actor.js";

export async function delegationFixture(pool: Pool, admin = true) {
  const { issuer, target } = await administrativeActors(pool, admin);
  await pool.query(
    "update access_token_records set scope_set=array['secretariat:admin','governance:read','documents:read'] where id=$1",
    [issuer.accessTokenRecordId]
  );
  await pool.query("update board_memberships set is_secretary=true where member_id=$1", [
    target.memberId
  ]);
  const initialAuthority = {
    schemaVersion: "boardagent.membership-authority.v1",
    memberId: target.memberId,
    boardId: target.boardId,
    seatRole: "voting_member",
    isSecretary: true,
    votingWeight: 1
  };
  await pool.query(
    "insert into membership_versions(id,organization_id,board_id,member_id,membership_id,version,seat_role,is_secretary,voting_weight,authority_snapshot,snapshot_sha256,change_reason,actor_member_id) select $1,organization_id,board_id,member_id,id,1,seat_role,is_secretary,voting_weight,$2,$3,'Initial synthetic secretary appointment',$4 from board_memberships where member_id=$5",
    [
      testId(76_000),
      initialAuthority,
      Buffer.from(canonicalSha256(initialAuthority), "hex"),
      issuer.memberId,
      target.memberId
    ]
  );
  const bytes = Buffer.from(
    "# Appointment authority\n\nClause 4: the secretary administers appointed director seats.\n"
  );
  const digest = sha256Hex(bytes);
  await pool.query(
    "insert into documents(id,organization_id,board_id,title,created_by) values($1,$2,$3,'Appointment authority',$4)",
    [testId(76_001), issuer.organizationId, issuer.boardId, issuer.memberId]
  );
  await pool.query(
    "insert into document_access_grants(id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by) values($1,$2,$3,$4,$5,'read',$6)",
    [
      testId(76_004),
      issuer.organizationId,
      issuer.boardId,
      testId(76_001),
      target.memberId,
      issuer.memberId
    ]
  );
  await pool.query(
    "insert into document_versions(id,organization_id,board_id,document_id,version,media_type,canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by) values($1,$2,$3,$4,1,'text/markdown; charset=utf-8','RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)",
    [
      testId(76_002),
      issuer.organizationId,
      issuer.boardId,
      testId(76_001),
      bytes,
      bytes.length,
      Buffer.from(digest, "hex"),
      issuer.memberId
    ]
  );
  const input = {
    schema_version: "boardagent.tool-input.v1",
    idempotency_key: "secretary-delegation-grant-0001",
    change: {
      operation: "grant",
      delegation_id: testId(76_003),
      member_id: target.memberId,
      board_id: issuer.boardId,
      expected_member_version: 1,
      expires_at: new Date(Date.now() + 86400_000).toISOString(),
      reason: "Manage appointed ordinary directors",
      authority_evidence: [
        {
          document_version_id: testId(76_002),
          sha256: digest,
          clause: "4",
          locator: "Appointment authority"
        }
      ]
    }
  };
  const prepare = (request: unknown = input) =>
    withRequestTransaction(
      pool,
      issuer.context,
      async (client) =>
        (
          await client.query(
            "select boardagent_member_admin_delegation_snapshot($1::jsonb) as snapshot",
            [request]
          )
        ).rows[0]?.snapshot,
      { assumeRole: "boardagent_server", isolation: "serializable" }
    );
  return { issuer, target, input, prepare };
}
