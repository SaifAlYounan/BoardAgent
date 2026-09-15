import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { migrate, withRequestTransaction, withWorkerTransaction } from "../../lib/db/src/index.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_rls_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 2 });
  try {
    await migrate(pool, MIGRATIONS, "rls-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedScope(client: PoolClient | Pool): Promise<{
  boardA: string;
  boardB: string;
  documentA: string;
  documentB: string;
  memberA: string;
  organizationA: string;
  organizationB: string;
}> {
  const organizationA = id(1);
  const organizationB = id(2);
  const boardA = id(3);
  const boardB = id(4);
  const memberA = id(5);
  const memberB = id(6);
  const documentA = id(7);
  const documentB = id(8);
  await client.query(
    `insert into organizations(id,legal_name,display_name,slug,timezone)
       values ($1,'Org A','Org A','org-a','UTC'),($2,'Org B','Org B','org-b','UTC')`,
    [organizationA, organizationB]
  );
  await client.query(
    `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
       values ($1,$2,'human','Member A','Member A','active'),
              ($3,$4,'human','Member B','Member B','active')`,
    [memberA, organizationA, memberB, organizationB]
  );
  await client.query(
    `insert into boards(id,organization_id,slug,name,timezone)
       values ($1,$2,'board-a','Board A','UTC'),($3,$4,'board-b','Board B','UTC')`,
    [boardA, organizationA, boardB, organizationB]
  );
  await client.query(
    `insert into documents(id,organization_id,board_id,title,created_by)
       values ($1,$2,$3,'Document A',$4),($5,$6,$7,'Document B',$8)`,
    [documentA, organizationA, boardA, memberA, documentB, organizationB, boardB, memberB]
  );
  return { boardA, boardB, documentA, documentB, memberA, organizationA, organizationB };
}

describe("PostgreSQL forced-RLS and evidence integrity walls", () => {
  it("creates distinct non-bypass service roles and forces RLS on every product table", async () => {
    await withDatabase(async (pool) => {
      const roles = await pool.query<{
        rolbypassrls: boolean;
        rolname: string;
        rolsuper: boolean;
      }>(
        "select rolname, rolsuper, rolbypassrls from pg_roles where rolname = any($1) order by rolname",
        [["boardagent_backup", "boardagent_migrator", "boardagent_server", "boardagent_worker"]]
      );
      expect(roles.rows).toEqual([
        { rolbypassrls: false, rolname: "boardagent_backup", rolsuper: false },
        { rolbypassrls: false, rolname: "boardagent_migrator", rolsuper: false },
        { rolbypassrls: false, rolname: "boardagent_server", rolsuper: false },
        { rolbypassrls: false, rolname: "boardagent_worker", rolsuper: false }
      ]);
      const unprotected = await pool.query<{ relname: string }>(
        `select c.relname
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
          where n.nspname = 'public' and c.relkind = 'r'
            and c.relname <> 'schema_migrations'
            and (not c.relrowsecurity or not c.relforcerowsecurity)
          order by c.relname`
      );
      expect(unprotected.rows).toEqual([]);
    });
  });

  it("denies runtime DML outside the implemented Phase-1 transaction allowlist", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedScope(pool);
      const requestContext = {
        organizationId: seeded.organizationA,
        memberId: seeded.memberA,
        clientId: id(10),
        tokenJti: id(11),
        boardIds: [seeded.boardA]
      };
      await expect(
        withRequestTransaction(
          pool,
          requestContext,
          (client) => client.query("insert into meetings(id) values ($1)", [id(12)]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/row-level security policy for table "meetings"/u);
      await expect(
        withRequestTransaction(
          pool,
          requestContext,
          (client) =>
            client.query("update organizations set display_name=display_name where id=$1", [
              seeded.organizationA
            ]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied for table organizations/u);
      await expect(
        withWorkerTransaction(
          pool,
          (client) => client.query("insert into jobs(id) values ($1)", [id(13)]),
          {
            assumeRole: "boardagent_worker"
          }
        )
      ).rejects.toThrow(/permission denied for table jobs/u);

      const forbiddenRequestUpdates = [
        "update action_stages set canonical_payload=canonical_payload where false",
        "update idempotency_records set request_sha256=request_sha256 where false",
        "update input_required_attempts set request_state_bytes=request_state_bytes where false",
        "update minutes set meeting_id=meeting_id where false",
        "update task_evidence set canonical_text=canonical_text where false",
        "update votes set approval_rule_id=approval_rule_id where false",
        "update board_memberships set state=state where false",
        "update boards set name=name where false",
        "update management_questions set asker_member_id=asker_member_id where false",
        "update wizard_drafts set current_step=current_step where false"
      ];
      for (const statement of forbiddenRequestUpdates) {
        await expect(
          withRequestTransaction(pool, requestContext, (client) => client.query(statement), {
            assumeRole: "boardagent_server"
          })
        ).rejects.toThrow(/permission denied for table/u);
      }
      await expect(
        withRequestTransaction(
          pool,
          requestContext,
          (client) =>
            client.query("update members set state='suspended' where id=$1", [seeded.memberA]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied for table members/u);
      await expect(
        withRequestTransaction(
          pool,
          requestContext,
          (client) =>
            client.query("update documents set title='rewritten' where id=$1", [seeded.documentA]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied for table documents/u);

      const permittedProjection = await withRequestTransaction(
        pool,
        requestContext,
        (client) =>
          client.query(
            "update documents set row_version=row_version where false returning row_version::text"
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(permittedProjection.rows).toEqual([]);
      const unchangedBindings = await pool.query<{
        document_title: string;
        member_state: string;
      }>(
        `select document.title as document_title,member.state as member_state
           from documents as document
           join members as member on member.id=$2
          where document.id=$1`,
        [seeded.documentA, seeded.memberA]
      );
      expect(unchangedBindings.rows).toEqual([
        { document_title: "Document A", member_state: "active" }
      ]);
    });
  });

  it("fails closed and never carries organization or board context across pooled transactions", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedScope(pool);
      const baseContext = {
        clientId: id(10),
        tokenJti: id(11)
      };
      const first = await withRequestTransaction(
        pool,
        {
          ...baseContext,
          organizationId: seeded.organizationA,
          memberId: seeded.memberA,
          boardIds: [seeded.boardA]
        },
        async (client) => client.query<{ id: string }>("select id from boards order by id"),
        { assumeRole: "boardagent_server" }
      );
      expect(first.rows.map(({ id: boardId }) => boardId)).toEqual([seeded.boardA]);
      const client = await pool.connect();
      try {
        await client.query("begin");
        await client.query("set local role boardagent_server");
        const empty = await client.query<{ id: string }>("select id from boards order by id");
        expect(empty.rows).toEqual([]);
        await client.query("commit");
      } finally {
        client.release();
      }
      const second = await withRequestTransaction(
        pool,
        {
          ...baseContext,
          organizationId: seeded.organizationB,
          memberId: id(6),
          boardIds: [seeded.boardB]
        },
        async (requestClient) =>
          requestClient.query<{ id: string }>("select id from boards order by id"),
        { assumeRole: "boardagent_server" }
      );
      expect(second.rows.map(({ id: boardId }) => boardId)).toEqual([seeded.boardB]);
    });
  });

  it("rejects mutation of evidence and illegal aggregate state transitions", async () => {
    await withDatabase(async (pool) => {
      const seeded = await seedScope(pool);
      const versionId = id(9);
      await pool.query(
        `insert into board_versions(
           id,organization_id,board_id,version,canonical_schema,canonical_payload,
           canonical_sha256,change_reason,created_by
         ) values ($1,$2,$3,1,'boardagent.board.v1','{}',decode(repeat('00',32),'hex'),'initial',$4)`,
        [versionId, seeded.organizationA, seeded.boardA, seeded.memberA]
      );
      await expect(
        pool.query("update board_versions set change_reason = 'rewritten' where id = $1", [
          versionId
        ])
      ).rejects.toThrow(/immutable evidence/u);
      await expect(
        pool.query("delete from board_versions where id = $1", [versionId])
      ).rejects.toThrow(/immutable evidence/u);

      await pool.query("update boards set state = 'archived', row_version = 2 where id = $1", [
        seeded.boardA
      ]);
      await expect(
        pool.query("update boards set state = 'active', row_version = 3 where id = $1", [
          seeded.boardA
        ])
      ).rejects.toThrow(/illegal boards state transition/u);
    });
  });
});
