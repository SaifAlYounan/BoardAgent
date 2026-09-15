import type { Pool } from "pg";

import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "./authorized-actor.js";

/** Disposable synthetic records; never evidence of human enrollment or acceptance. */
export async function seedCapacitySeats(
  pool: Pool,
  secretary: AuthorizedActorFixture,
  count: number,
  options: { readonly readyForVote?: boolean } = {}
): Promise<string[]> {
  const memberIds = Array.from({ length: count }, (_, index) =>
    testId(options.readyForVote ? 7_000_000 + index * 20 + 1 : 7_000_000 + index)
  );
  const membershipIds = memberIds.map((_, index) =>
    testId(options.readyForVote ? 7_000_000 + index * 20 + 2 : 7_010_000 + index)
  );
  const versionIds = memberIds.map((_, index) => testId(7_020_000 + index));
  const snapshots = memberIds.map((memberId) => ({
    memberId,
    eligible: true,
    reason: "active voting seat"
  }));
  if (options.readyForVote) {
    for (let index = 0; index < count; index += 1) {
      await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 7_000_000 + index * 20,
        uniqueHashes: true,
        seatRole: "voting_member",
        scopes: ["governance:read", "vote:act"]
      });
    }
  } else {
    await pool.query(
      `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
     select id,$1,'human','Synthetic capacity seat','Synthetic capacity seat','active'
       from unnest($2::uuid[]) as seat(id)`,
      [secretary.organizationId, memberIds]
    );
    await pool.query(
      `insert into board_memberships(id,organization_id,board_id,member_id,seat_role,
      is_secretary,voting_weight,state)
     select id,$1,$2,member_id,'voting_member',false,1,'active'
       from unnest($3::uuid[],$4::uuid[]) as seat(id,member_id)`,
      [secretary.organizationId, secretary.boardId, membershipIds, memberIds]
    );
  }
  await pool.query(
    `insert into membership_versions(id,organization_id,board_id,member_id,membership_id,
      version,seat_role,is_secretary,voting_weight,authority_snapshot,snapshot_sha256,
      change_reason,actor_member_id)
     select id,$1,$2,member_id,membership_id,1,'voting_member',false,1,snapshot::jsonb,
       decode(snapshot_hash,'hex'),'Synthetic capacity fixture',$3
       from unnest($4::uuid[],$5::uuid[],$6::uuid[],$7::text[],$8::text[])
         as seat(id,member_id,membership_id,snapshot,snapshot_hash)`,
    [
      secretary.organizationId,
      secretary.boardId,
      secretary.memberId,
      versionIds,
      memberIds,
      membershipIds,
      snapshots.map((snapshot) => JSON.stringify(snapshot)),
      snapshots.map((snapshot) => canonicalSha256(snapshot))
    ]
  );
  return memberIds;
}
