import { randomBytes } from "node:crypto";
import { copyFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";

import {
  migrate,
  withRequestTransaction,
  type RequestDatabaseContext
} from "../../lib/db/src/index.js";
import { loadMigrations } from "../../lib/db/src/migrate.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
  testId
} from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { withDirectResponseAllocation } from "../helpers/direct-response-allocation.js";

async function fixture(
  pool: Pool,
  seatRole: "voting_member" | "management" | "observer" = "management"
) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole,
    scopes: ["documents:read", "documents:contribute"]
  });
  const other = await seedAdditionalAuthorizedActor(pool, actor, {
    idBase: 81_000,
    seatRole,
    scopes: ["documents:read", "documents:contribute"]
  });
  const foreignBoard = testId(82_000);
  await pool.query(
    "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'other-board','Other board','UTC')",
    [foreignBoard, actor.organizationId]
  );
  const ids = Array.from({ length: 7 }, (_, i) => testId(82_100 + i));
  for (const [index, documentId] of ids.entries()) {
    const boardId = index === 6 ? foreignBoard : actor.boardId;
    const creator = index === 1 || index === 2 ? other.memberId : actor.memberId;
    const state = index === 4 ? "archived" : index === 5 ? "soft_deleted" : "active";
    const versionId = testId(82_200 + index);
    const bytes = Buffer.from(`statement-permission-canary-${String(index)}`);
    await pool.query(
      "insert into documents(id,organization_id,board_id,title,state,created_by) values($1,$2,$3,$4,$5,$6)",
      [documentId, actor.organizationId, boardId, bytes.toString(), state, creator]
    );
    await pool.query(
      `insert into document_versions(id,organization_id,board_id,document_id,version,
         media_type,document_schema,canonicalization_version,canonical_bytes,byte_length,
         sha256,canonical_metadata,created_by)
       values($1,$2,$3,$4,1,'text/plain; charset=utf-8',null,'RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)`,
      [
        versionId,
        actor.organizationId,
        boardId,
        documentId,
        bytes,
        bytes.length,
        testHash(31),
        creator
      ]
    );
    await pool.query(
      "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
      [versionId, documentId]
    );
    await pool.query(
      "insert into document_search(document_id,board_id,current_version_id,canonical_text_sha256,search_text) values($1,$2,$3,$4,$5)",
      [documentId, boardId, versionId, testHash(31), bytes.toString()]
    );
  }
  const grantId = testId(82_300);
  const exclusionId = testId(82_301);
  await pool.query(
    `insert into document_access_grants(id,organization_id,board_id,document_id,
       grantee_member_id,permission,granted_by,active_from)
     values($1,$2,$3,$4,$5,'read',$6,transaction_timestamp()-interval '1 day')`,
    [grantId, actor.organizationId, actor.boardId, ids[2], actor.memberId, other.memberId]
  );
  await pool.query(
    `insert into document_exclusions(id,organization_id,board_id,document_id,member_id,
       version,reason,created_by,active_from)
     values($1,$2,$3,$4,$5,1,'Synthetic current exclusion',$5,transaction_timestamp()-interval '1 day')`,
    [exclusionId, actor.organizationId, actor.boardId, ids[3], actor.memberId]
  );
  return { actor, other, ids, grantId, exclusionId };
}

async function observe(pool: Pool, context: RequestDatabaseContext, ids: readonly string[]) {
  return withRequestTransaction(
    pool,
    context,
    async (client) => {
      const identity = await client.query<{ pid: number; actor: string }>(
        "select pg_backend_pid() as pid,current_user as actor"
      );
      const original = await client.query<{ id: string }>(
        `select candidate as id from unnest($1::uuid[]) as candidate
          where public.boardagent_document_permission(candidate,'read') order by candidate`,
        [ids]
      );
      const batch = await client.query<{ id: string }>(
        "select id from public.boardagent_search_readable_document_ids() as id order by id"
      );
      const search = await client.query<{ id: string }>(
        `select document_id as id from public.document_search
          where search_vector @@ plainto_tsquery('simple','statement-permission-canary')
          order by document_id`
      );
      return {
        identity: identity.rows[0],
        original: original.rows.map((row) => row.id),
        batch: batch.rows.map((row) => row.id),
        search: search.rows.map((row) => row.id)
      };
    },
    { assumeRole: "boardagent_server" }
  );
}

function expectSame(
  observed: Awaited<ReturnType<typeof observe>>,
  expected: readonly (string | undefined)[]
) {
  expect(observed.identity?.actor).toBe("boardagent_server");
  expect(observed.original).toEqual(expected);
  expect(observed.batch).toEqual(expected);
  expect(observed.search).toEqual(expected);
}

describe("SR-023/SR-025 statement-scoped search authority", () => {
  it("returns exact plain search snippets through the current repository query", async () => {
    await withMigratedDatabase(
      "search_plain_snippet",
      async (pool) => {
        const scopes = ["documents:read", "documents:contribute"];
        const actor = await seedAuthorizedActor(pool, { seatRole: "voting_member", scopes });
        const documentId = testId(83_000);
        const versionId = testId(83_001);
        const sessionId = testId(83_002);
        const text = "needle " + "x".repeat(20) + " tail";
        const bytes = Buffer.from(text, "utf8");
        const sha256 = sha256Hex(bytes);
        expect(bytes.length).toBe(32);
        await pool.query(
          "insert into documents(id,organization_id,board_id,title,state,created_by) values($1,$2,$3,'Plain search snippet','active',$4)",
          [documentId, actor.organizationId, actor.boardId, actor.memberId]
        );
        await pool.query(
          `insert into document_versions(id,organization_id,board_id,document_id,version,
           media_type,document_schema,canonicalization_version,canonical_bytes,byte_length,
           sha256,canonical_metadata,created_by)
         values($1,$2,$3,$4,1,'text/plain; charset=utf-8',null,'RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)`,
          [
            versionId,
            actor.organizationId,
            actor.boardId,
            documentId,
            bytes,
            bytes.length,
            Buffer.from(sha256, "hex"),
            actor.memberId
          ]
        );
        await pool.query(
          "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
          [versionId, documentId]
        );
        await pool.query(
          "insert into document_search(document_id,board_id,current_version_id,canonical_text_sha256,search_text) values($1,$2,$3,$4,$5)",
          [documentId, actor.boardId, versionId, Buffer.from(sha256, "hex"), text]
        );
        await pool.query(
          `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
         values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
          [sessionId, actor.organizationId, testHash(83), actor.memberId, actor.clientId]
        );
        await pool.query("update access_token_records set session_id=$1 where id=$2", [
          sessionId,
          actor.accessTokenRecordId
        ]);
        const principal: SurfacePrincipal = {
          organizationId: actor.organizationId,
          memberId: actor.memberId,
          serviceOrigin: "https://boardagent.test",
          clientId: actor.clientId,
          protocolClientId: "authorized-test-client",
          accessTokenRecordId: actor.accessTokenRecordId,
          tokenJti: actor.tokenJti,
          keyId: "test-oauth",
          scopes,
          roles: ["member"],
          boardIds: [actor.boardId]
        };
        const reader = new PgSurfaceReadRepository(pool, {
          cursorKey: Buffer.alloc(32, 0x53),
          transaction: { assumeRole: "boardagent_server" }
        });
        const response = await withDirectResponseAllocation(() =>
          reader.executeRead(principal, "search_documents", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: actor.boardId,
            query: "needle",
            cursor: null,
            limit: 1
          })
        );
        expect(response).toMatchObject({
          schema_version: "boardagent.tool-result.v1",
          tool: "search_documents",
          status: "ok",
          reference: null,
          resource_uri: null
        });
        const data = response.data as Record<string, JsonValue>;
        const items = data["items"] as Record<string, JsonValue>[];
        expect(items).toHaveLength(1);
        expect(data["next_cursor"]).toBeNull();
        expect(items[0]).toMatchObject({
          document_id: documentId,
          version_id: versionId,
          title: "Plain search snippet",
          media_type: "text/plain; charset=utf-8",
          document_schema: null,
          byte_length: 32,
          sha256,
          snippet: text,
          resource_uri: `board://${actor.boardId}/documents/${documentId}/versions/1`
        });
        expect(Number.isFinite(items[0]!["rank"])).toBe(true);
        expect(items[0]!["snippet"]).not.toMatch(/,StopSel=|<[^>]*>/u);
      },
      1
    );
  });

  for (const seatRole of ["voting_member", "management", "observer"] as const)
    it(`preserves role-grant permissions and time bounds for ${seatRole}`, async () => {
      await withMigratedDatabase(
        "search_role_acl",
        async (pool) => {
          const { actor, ids, grantId } = await fixture(pool, seatRole);
          await pool.query(
            "update document_access_grants set grantee_member_id=null,grantee_seat_role=$1 where id=$2",
            [seatRole, grantId]
          );
          for (const permission of ["read", "contribute", "circulate"]) {
            await pool.query("update document_access_grants set permission=$1 where id=$2", [
              permission,
              grantId
            ]);
            expectSame(await observe(pool, actor.context, ids), [ids[0], ids[2], ids[4]]);
          }
          await pool.query("update document_access_grants set grantee_seat_role=$1 where id=$2", [
            seatRole === "observer" ? "management" : "observer",
            grantId
          ]);
          expectSame(await observe(pool, actor.context, ids), [ids[0], ids[4]]);
          await pool.query(
            "update document_access_grants set grantee_seat_role=$1,active_from=transaction_timestamp()+interval '1 day' where id=$2",
            [seatRole, grantId]
          );
          expectSame(await observe(pool, actor.context, ids), [ids[0], ids[4]]);
          await pool.query(
            "update document_access_grants set active_from=transaction_timestamp()-interval '2 days',active_until=transaction_timestamp()-interval '1 day' where id=$1",
            [grantId]
          );
          expectSame(await observe(pool, actor.context, ids), [ids[0], ids[4]]);
        },
        1
      );
    });

  it("preserves live document permissions across real principals and narrowed contexts on one reused backend", async () => {
    await withMigratedDatabase(
      "search_context",
      async (pool) => {
        const { actor, other, ids } = await fixture(pool);
        const first = await observe(pool, actor.context, ids);
        expectSame(first, [ids[0], ids[2], ids[4]]);
        for (let attempt = 0; attempt < 8; attempt += 1) {
          const second = await observe(pool, other.context, ids);
          expectSame(second, [ids[1], ids[2]]);
          expect(second.identity?.pid).toBe(first.identity?.pid);
          expectSame(await observe(pool, { ...actor.context, boardIds: [] }, ids), []);
          expectSame(await observe(pool, { ...actor.context, memberId: other.memberId }, ids), []);
          const restored = await observe(pool, actor.context, ids);
          expectSame(restored, [ids[0], ids[2], ids[4]]);
          expect(restored.identity?.pid).toBe(first.identity?.pid);
        }
      },
      1
    );
  });

  it("recomputes ACL and exclusion changes after warming the same connection without reviving a removed grant", async () => {
    await withMigratedDatabase(
      "search_acl",
      async (pool) => {
        const { actor, ids, grantId, exclusionId } = await fixture(pool);
        for (let attempt = 0; attempt < 8; attempt += 1)
          expectSame(await observe(pool, actor.context, ids), [ids[0], ids[2], ids[4]]);
        await pool.query(
          "update document_access_grants set active_until=transaction_timestamp() where id=$1",
          [grantId]
        );
        expectSame(await observe(pool, actor.context, ids), [ids[0], ids[4]]);
        await pool.query(
          "update document_exclusions set active_until=transaction_timestamp() where id=$1",
          [exclusionId]
        );
        expectSame(await observe(pool, actor.context, ids), [ids[0], ids[3], ids[4]]);
        await pool.query(
          "update documents set state='soft_deleted',row_version=row_version+1 where id=$1",
          [ids[0]]
        );
        expectSame(await observe(pool, actor.context, ids), [ids[3], ids[4]]);
      },
      1
    );
  });

  for (const reason of [
    "token revoked",
    "scope lost",
    "client revoked",
    "seat suspended",
    "onboarding stale"
  ] as const)
    it(`refuses ${reason} after a previously permitted search on the same backend`, async () => {
      await withMigratedDatabase(
        "search_revocation",
        async (pool) => {
          const { actor, ids } = await fixture(pool);
          for (let attempt = 0; attempt < 8; attempt += 1)
            expectSame(await observe(pool, actor.context, ids), [ids[0], ids[2], ids[4]]);
          switch (reason) {
            case "token revoked":
              await pool.query(
                "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
                [actor.accessTokenRecordId]
              );
              break;
            case "scope lost":
              await pool.query(
                "update access_token_records set scope_set=array['governance:read'] where id=$1",
                [actor.accessTokenRecordId]
              );
              break;
            case "client revoked":
              await pool.query("update oauth_clients set state='revoked' where id=$1", [
                actor.clientId
              ]);
              break;
            case "seat suspended":
              await pool.query(
                "update board_memberships set state='suspended',entitlement_generation=entitlement_generation+1 where member_id=$1",
                [actor.memberId]
              );
              break;
            case "onboarding stale":
              await pool.query(
                `insert into onboarding_terms_versions(id,organization_id,seat_role,version,
                 schema_version,canonical_text,canonical_sha256,material_change,effective_at,created_by)
               values($1,$2,'management',2,'boardagent.onboarding-terms.v1','Changed terms',$3,true,
                 transaction_timestamp(),$4)`,
                [testId(82_400), actor.organizationId, testHash(44), actor.memberId]
              );
              break;
          }
          expectSame(await observe(pool, actor.context, ids), []);
        },
        1
      );
    });

  it("compiles against trusted tables even when caller temporary names exist before its first execution", async () => {
    await withMigratedDatabase(
      "search_namespace",
      async (pool) => {
        const { actor, ids } = await fixture(pool);
        for (const table of [
          "documents",
          "board_memberships",
          "members",
          "document_access_grants",
          "document_exclusions"
        ])
          await pool.query(`create temporary table ${table} (like public.${table})`);
        expectSame(await observe(pool, actor.context, ids), [ids[0], ids[2], ids[4]]);
      },
      1
    );
  });

  it("does not grant worker or unrelated runtime roles a new document-discovery entry point", async () => {
    await withMigratedDatabase(
      "search_execute",
      async (pool) => {
        await fixture(pool);
        const metadata = await pool.query(`
          select pg_get_userbyid(p.proowner) as owner,p.prosecdef,p.provolatile,p.proleakproof,p.proconfig,
            exists(select 1 from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
              where acl.grantee=0 and acl.privilege_type='EXECUTE') as public_execute
          from pg_proc p where p.oid='public.boardagent_search_readable_document_ids()'::regprocedure`);
        expect(metadata.rows).toEqual([
          {
            owner: "boardagent_migrator",
            prosecdef: true,
            provolatile: "s",
            proleakproof: false,
            proconfig: ["search_path=pg_catalog, public, pg_temp"],
            public_execute: false
          }
        ]);
        for (const role of ["boardagent_worker", "boardagent_backup"]) {
          const client = await pool.connect();
          try {
            await client.query("begin");
            await client.query(`set local role ${role}`);
            await expect(
              client.query("select * from public.boardagent_search_readable_document_ids()")
            ).rejects.toMatchObject({ code: "42501" });
          } finally {
            await client.query("rollback");
            client.release();
          }
        }
      },
      1
    );
  });

  it("upgrades schema99 without changing prior migration records and refreshes a warmed search plan on the same backend", async () => {
    const migrations = path.resolve(import.meta.dirname, "../../lib/db/migrations");
    const old = await mkdtemp(path.join(tmpdir(), "ba-search-99-"));
    const base = new URL(
      process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
        "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent"
    );
    const database = `ba_search_upgrade_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
    base.pathname = "/postgres";
    const admin = new Pool({ connectionString: base.toString(), max: 1 });
    await admin.query(`create database "${database}"`);
    base.pathname = `/${database}`;
    const pool = new Pool({ connectionString: base.toString(), max: 1 });
    try {
      for (const migration of (await loadMigrations(migrations)).slice(0, 99))
        await copyFile(path.join(migrations, migration.name), path.join(old, migration.name));
      expect(await migrate(pool, old, "search-original99")).toBe(99);
      const before = await pool.query(
        "select version,name,sha256 from schema_migrations order by version"
      );
      const { actor, other, ids } = await fixture(pool);
      let priorPid: number | undefined;
      for (let attempt = 0; attempt < 8; attempt += 1) {
        const result = await withRequestTransaction(
          pool,
          actor.context,
          async (client) => ({
            pid: (await client.query<{ pid: number }>("select pg_backend_pid() as pid")).rows[0]
              ?.pid,
            rows: (
              await client.query<{ id: string }>(
                "select document_id as id from public.document_search order by document_id"
              )
            ).rows
          }),
          { assumeRole: "boardagent_server" }
        );
        priorPid = result.pid;
        expect(result.rows.map((row) => row.id)).toEqual([ids[0], ids[2], ids[4]]);
      }
      await migrate(pool, migrations, "search-upgrade");
      expect(
        (
          await pool.query(
            "select version,name,sha256 from schema_migrations where version<=99 order by version"
          )
        ).rows
      ).toEqual(before.rows);
      const after = await observe(pool, actor.context, ids);
      expect(after.identity?.pid).toBe(priorPid);
      expectSame(after, [ids[0], ids[2], ids[4]]);
      const second = await observe(pool, other.context, ids);
      expect(second.identity?.pid).toBe(priorPid);
      expectSame(second, [ids[1], ids[2]]);
    } finally {
      await pool.end();
      await admin.query(`drop database "${database}" with (force)`);
      await admin.end();
      await rm(old, { recursive: true, force: true });
    }
  });
});
