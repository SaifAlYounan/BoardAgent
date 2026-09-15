import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import { migrate, withWorkerTransaction } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_export_scope_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "export-scope-isolation-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function insertQueuedExport(
  pool: Pool,
  input: {
    readonly id: string;
    readonly publicByte: number;
    readonly organizationId: string;
    readonly boardId: string | null;
    readonly requesterMemberId: string;
    readonly consentRecordId: string;
    readonly scope: unknown;
  }
): Promise<void> {
  const scopeBytes = Buffer.from(canonicalJson(input.scope), "utf8");
  await pool.query(
    `insert into export_requests(
       id,public_id,organization_id,board_id,requester_member_id,export_type,
       scope_manifest,scope_sha256,state,consent_record_id,recent_auth_at,expires_at
     ) values ($1,$2,$3,$4,$5,'system_data',$6,$7,'queued',$8,
               transaction_timestamp(),transaction_timestamp()+interval '1 hour')`,
    [
      input.id,
      Buffer.alloc(32, input.publicByte),
      input.organizationId,
      input.boardId,
      input.requesterMemberId,
      scopeBytes,
      Buffer.from(canonicalSha256(input.scope), "hex"),
      input.consentRecordId
    ]
  );
}

async function exportedRows(
  pool: Pool,
  requestId: string,
  dataClass: string,
  table: string
): Promise<readonly Record<string, string>[]> {
  return withWorkerTransaction(
    pool,
    async (client) => {
      const result = await client.query<{ table_rows: Record<string, string>[] }>(
        `select table_rows from boardagent_export_system_table_rows($1,$2,$3)`,
        [requestId, dataClass, table]
      );
      return result.rows[0]?.table_rows ?? [];
    },
    { assumeRole: "boardagent_worker", isolation: "repeatable read" }
  );
}

describe("system export scope isolation", () => {
  it("never crosses organization, board, or member boundaries, including child tables", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["secretariat:admin"],
        isSecretary: true
      });
      const secondBoardId = testId(190_000);
      const secondMemberId = testId(190_001);
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'other-board','Other board','UTC')",
        [secondBoardId, actor.organizationId]
      );
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Other member','Other member','active')",
        [secondMemberId, actor.organizationId]
      );
      await pool.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,voting_weight,state
         ) values ($1,$2,$3,$4,'voting_member',1,'active')`,
        [testId(190_002), actor.organizationId, secondBoardId, secondMemberId]
      );
      const foreignOrganizationId = testId(190_010);
      const foreignBoardId = testId(190_011);
      const foreignMemberId = testId(190_012);
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Foreign','Foreign','foreign','UTC')",
        [foreignOrganizationId]
      );
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'foreign-board','Foreign board','UTC')",
        [foreignBoardId, foreignOrganizationId]
      );
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Foreign member','Foreign member','active')",
        [foreignMemberId, foreignOrganizationId]
      );

      const organizationScope = {
        schemaVersion: "boardagent.export-scope.v1" as const,
        exportType: "system_data" as const,
        organizationId: actor.organizationId,
        boardId: null,
        scope: "organization" as const,
        memberId: null,
        purpose: "Prove exact organization export isolation.",
        dataClasses: ["governance", "identity_authority"] as const,
        includeCanonicalContent: true as const,
        excludeSecretMaterial: true as const
      };
      const organizationRequestId = testId(190_020);
      await insertQueuedExport(pool, {
        id: organizationRequestId,
        publicByte: 201,
        organizationId: actor.organizationId,
        boardId: null,
        requesterMemberId: actor.memberId,
        consentRecordId: actor.consentRecordId,
        scope: organizationScope
      });
      expect(
        (await exportedRows(pool, organizationRequestId, "governance", "organizations")).map(
          (row) => row["id"]
        )
      ).toEqual([actor.organizationId]);
      expect(
        (await exportedRows(pool, organizationRequestId, "governance", "boards")).map(
          (row) => row["id"]
        )
      ).toEqual(expect.arrayContaining([actor.boardId, secondBoardId]));
      expect(
        (await exportedRows(pool, organizationRequestId, "governance", "boards")).map(
          (row) => row["id"]
        )
      ).not.toContain(foreignBoardId);

      const boardScope = {
        ...organizationScope,
        boardId: actor.boardId,
        scope: "board" as const
      };
      const boardRequestId = testId(190_021);
      await insertQueuedExport(pool, {
        id: boardRequestId,
        publicByte: 202,
        organizationId: actor.organizationId,
        boardId: actor.boardId,
        requesterMemberId: actor.memberId,
        consentRecordId: actor.consentRecordId,
        scope: boardScope
      });
      expect(
        (await exportedRows(pool, boardRequestId, "governance", "boards")).map((row) => row["id"])
      ).toEqual([actor.boardId]);
      expect(
        (await exportedRows(pool, boardRequestId, "identity_authority", "members")).map(
          (row) => row["id"]
        )
      ).toEqual([actor.memberId]);

      const memberScope = {
        ...organizationScope,
        scope: "member_portability" as const,
        memberId: actor.memberId
      };
      const memberRequestId = testId(190_022);
      await insertQueuedExport(pool, {
        id: memberRequestId,
        publicByte: 203,
        organizationId: actor.organizationId,
        boardId: null,
        requesterMemberId: actor.memberId,
        consentRecordId: actor.consentRecordId,
        scope: memberScope
      });
      expect(
        (await exportedRows(pool, memberRequestId, "identity_authority", "members")).map(
          (row) => row["id"]
        )
      ).toEqual([actor.memberId]);
      expect(
        (await exportedRows(pool, memberRequestId, "governance", "boards")).map((row) => row["id"])
      ).toEqual([actor.boardId]);
    });
  });
});
