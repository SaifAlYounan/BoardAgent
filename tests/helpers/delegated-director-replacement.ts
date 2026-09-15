import type { Pool } from "pg";
import { expect } from "vitest";
import { sha256Hex } from "../../lib/contracts/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "./authorized-actor.js";
import {
  freshAdministrativeTestCredential,
  stageAdministrativeAction
} from "./administrative-service.js";

/** Hash exact PostgreSQL JSON rows, retaining microsecond timestamps and bytea contents. */
export async function preserveHistoricRecords(pool: Pool, tables: readonly string[]) {
  async function fingerprints(table: string) {
    if (!/^[a-z_]+$/.test(table)) throw new Error("invalid test table name");
    return (
      await pool.query<{ digest: string }>(
        `select encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') as digest from ${table} t order by digest`
      )
    ).rows.map((row) => row.digest);
  }
  const original = new Map<string, string[]>();
  for (const table of tables) original.set(table, await fingerprints(table));
  return {
    counts: Object.fromEntries([...original].map(([table, rows]) => [table, rows.length])),
    assertPreserved: async () => {
      for (const [table, rows] of original) {
        // New immutable lineage may be appended; every exact original row must survive.
        expect(await fingerprints(table), `historic ${table} rows`).toEqual(
          expect.arrayContaining(rows)
        );
      }
    }
  };
}

/** Supported H actions after disposable admin/identity/citation setup; no real-person claim. */
export async function replaceDirectorThroughDelegate(
  pool: Pool,
  originalSecretary: AuthorizedActorFixture,
  departingDirector: AuthorizedActorFixture,
  assertHistory: () => Promise<void>
) {
  const id = (offset: number) => testId(196_000 + offset);
  const oldPerson = (
    await pool.query("select id,legal_name,display_name,member_kind from members where id=$1", [
      departingDirector.memberId
    ])
  ).rows[0];
  await pool.query(
    "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Synthetic history-test administrator')",
    [id(0), originalSecretary.organizationId, originalSecretary.memberId]
  );
  const admin = await freshAdministrativeTestCredential(pool, originalSecretary, 196_010);
  const initialDelegate = await seedAdditionalAuthorizedActor(pool, originalSecretary, {
    idBase: 196_100,
    seatRole: "voting_member",
    scopes: ["secretariat:admin", "governance:read", "documents:read"]
  });
  expect(
    (
      await (
        await stageAdministrativeAction(pool, admin, "manage_member", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "history-appoint-secretary-0001",
          change: {
            operation: "change_seat",
            member_id: initialDelegate.memberId,
            board_id: admin.boardId,
            seat_role: "voting_member",
            voting_weight: 1,
            is_secretary: true,
            reason: "Appoint the secretary for director succession"
          }
        })
      ).confirm()
    ).confirmed
  ).toBe(true);
  const bytes = Buffer.from(
    "# Director succession\n\nClause 6: record the outgoing director and invite their separately appointed successor.\n"
  );
  await pool.query(
    "insert into documents(id,organization_id,board_id,title,created_by) values($1,$2,$3,'Director succession authority',$4)",
    [id(200), admin.organizationId, admin.boardId, admin.memberId]
  );
  await pool.query(
    "insert into document_versions(id,organization_id,board_id,document_id,version,media_type,canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by) values($1,$2,$3,$4,1,'text/markdown; charset=utf-8','RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)",
    [
      id(201),
      admin.organizationId,
      admin.boardId,
      id(200),
      bytes,
      bytes.length,
      Buffer.from(sha256Hex(bytes), "hex"),
      admin.memberId
    ]
  );
  await pool.query(
    "insert into document_access_grants(id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by) values($1,$2,$3,$4,$5,'read',$6)",
    [
      id(202),
      admin.organizationId,
      admin.boardId,
      id(200),
      initialDelegate.memberId,
      admin.memberId
    ]
  );
  const authority_evidence = [
    {
      document_version_id: id(201),
      sha256: sha256Hex(bytes),
      clause: "6",
      locator: "Director succession authority"
    }
  ];
  expect(
    (
      await (
        await stageAdministrativeAction(pool, admin, "manage_member_admin_delegation", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "history-delegate-secretary-0001",
          change: {
            operation: "grant",
            delegation_id: id(203),
            member_id: initialDelegate.memberId,
            board_id: admin.boardId,
            expected_member_version: 2,
            expires_at: new Date(Date.now() + 86400_000).toISOString(),
            reason: "Record appointed director succession",
            authority_evidence
          }
        })
      ).confirm()
    ).confirmed
  ).toBe(true);
  const delegate = await freshAdministrativeTestCredential(pool, initialDelegate, 196_210);
  await assertHistory();
  expect(
    (
      await (
        await stageAdministrativeAction(pool, delegate, "manage_member", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "history-director-departure-0001",
          authority_evidence,
          change: {
            operation: "remove",
            member_id: departingDirector.memberId,
            board_id: delegate.boardId,
            reason: "Record the appointed director's departure"
          }
        })
      ).confirm()
    ).confirmed
  ).toBe(true);
  await assertHistory();
  expect(
    (
      await pool.query(
        "select state from board_memberships where member_id=$1 and board_id=$2 order by created_at desc limit 1",
        [departingDirector.memberId, delegate.boardId]
      )
    ).rows[0]
  ).toEqual({ state: "ended" });
  expect(
    (
      await pool.query(
        "select revoked_at is not null as revoked from access_token_records where id=$1",
        [departingDirector.accessTokenRecordId]
      )
    ).rows[0]
  ).toEqual({ revoked: true });
  const invitation = {
    schema_version: "boardagent.tool-input.v1",
    idempotency_key: "history-director-successor-0001",
    authority_evidence,
    change: {
      operation: "invite",
      member_id: id(220),
      board_id: delegate.boardId,
      member_kind: "human",
      seat_role: "voting_member",
      legal_name: "Separately appointed successor",
      display_name: "Successor",
      voting_weight: 1,
      accountable_principal_id: null,
      reason: "Register the separately appointed successor"
    }
  };
  await expect(
    stageAdministrativeAction(pool, delegate, "manage_member", {
      ...invitation,
      change: { ...invitation.change, member_id: departingDirector.memberId }
    })
  ).rejects.toMatchObject({ code: "member_invite_unavailable" });
  expect(
    (await (await stageAdministrativeAction(pool, delegate, "manage_member", invitation)).confirm())
      .confirmed
  ).toBe(true);
  await assertHistory();
  expect(
    (
      await pool.query("select id,legal_name,display_name,member_kind from members where id=$1", [
        departingDirector.memberId
      ])
    ).rows[0]
  ).toEqual(oldPerson);
  expect((await pool.query("select id,state from members where id=$1", [id(220)])).rows[0]).toEqual(
    { id: id(220), state: "invited" }
  );
  expect(id(220)).not.toBe(departingDirector.memberId);
  return { delegate, successorId: id(220) };
}
