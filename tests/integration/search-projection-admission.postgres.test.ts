import type { PoolClient } from "pg";
import { describe, expect, it } from "vitest";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  SEARCH_PREFLIGHT_SQL,
  SEARCH_CONTENT_SQL,
  loadAdmittedSearchProjection,
  type SearchProjectionMetadata,
  type SearchPageRow
} from "../../artifacts/server/src/search-projection-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable
} from "../../artifacts/server/src/response-allocation.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

// Frozen quoted-marker application query from the reviewed search branch.
const ORIGINAL_SEARCH_SQL = `with matched as materialized (
           select document_id,search_vector,search_text
             from document_search
            where board_id=$1 and search_vector @@ plainto_tsquery('simple',$2)
         ), entitled as materialized (
           select document.id,document.title,document.state,document.current_version_id,
                  version_row.version,version_row.media_type,version_row.document_schema,version_row.byte_length,
                  version_row.sha256,version_row.created_at,search.search_vector,search.search_text
             from documents as document
             join document_versions as version_row on version_row.id=document.current_version_id
             join matched as search on search.document_id=document.id
            where document.board_id=$1 and document.state='active'
         ), ranked as (
           select entitled.*,
                  ts_rank_cd(entitled.search_vector,plainto_tsquery('simple',$2)) as rank,
                  ts_headline('simple',entitled.search_text,plainto_tsquery('simple',$2),
                    'MaxFragments=2,MaxWords=30,MinWords=10,StartSel="",StopSel=""') as snippet
             from entitled
         )
         select jsonb_build_object(
           'document_id',ranked.id,'version_id',ranked.current_version_id,'title',ranked.title,
           'media_type',ranked.media_type,'document_schema',ranked.document_schema,
           'byte_length',ranked.byte_length,'sha256',encode(ranked.sha256,'hex'),
           'rank',ranked.rank,'snippet',ranked.snippet,
           'resource_uri','board://' || $1::text || '/documents/' || ranked.id::text ||
             '/versions/' || ranked.version::text
         ) as item,
         to_char(ranked.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         ranked.id::text as cursor_id
         from ranked
        where ($3::timestamptz is null or (ranked.created_at,ranked.id)<($3::timestamptz,$4::uuid))
        order by ranked.created_at desc,ranked.id desc limit $5`;

describe("search projection admission under actual PostgreSQL RLS", () => {
  it("measures exact selected fields and globally refuses growth before full search construction", async () => {
    await withMigratedDatabase(
      "search_projection",
      async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["documents:read", "documents:contribute"]
        });
        const input = {
          boardId: actor.boardId,
          query: "needle",
          cursorAt: null,
          cursorId: null,
          limit: 2
        };
        const parameters = [actor.boardId, "needle", null, null, 3];
        const plain = "needle " + "x".repeat(20) + " tail";
        const json = canonicalJson({
          schemaVersion: "boardagent.board-pack.v1",
          title: "needle Ω",
          sections: [{ heading: "needle", body: 'needle quote " slash \\ 漢 😀' }]
        });
        async function seedDocument(n: number, text: string, jsonDocument = false) {
          const documentId = testId(84_000 + n * 2);
          const versionId = testId(84_001 + n * 2);
          const bytes = Buffer.from(text);
          const hash = Buffer.from(sha256Hex(bytes), "hex");
          await pool.query(
            "insert into documents(id,organization_id,board_id,title,state,created_by) values($1,$2,$3,$4,'active',$5)",
            [
              documentId,
              actor.organizationId,
              actor.boardId,
              `needle title ${n} Ω \\ "`,
              actor.memberId
            ]
          );
          await pool.query(
            `insert into document_versions(id,organization_id,board_id,document_id,version,
          media_type,document_schema,canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by)
          values($1,$2,$3,$4,1,$5,$6,'RFC8785+NFC-LF-v1',$7,$8,$9,'{}',$10)`,
            [
              versionId,
              actor.organizationId,
              actor.boardId,
              documentId,
              jsonDocument ? "application/json" : "text/plain; charset=utf-8",
              jsonDocument ? "boardagent.board-pack.v1" : null,
              bytes,
              bytes.length,
              hash,
              actor.memberId
            ]
          );
          await pool.query(
            "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
            [versionId, documentId]
          );
          await pool.query(
            "insert into document_search(document_id,board_id,current_version_id,canonical_text_sha256,search_text) values($1,$2,$3,$4,$5)",
            [documentId, actor.boardId, versionId, hash, text]
          );
          return documentId;
        }
        const first = await seedDocument(0, plain);
        await seedDocument(1, json, true);
        const read = <T>(work: (client: PoolClient) => Promise<T>) =>
          withRequestTransaction(pool, actor.context, work, { assumeRole: "boardagent_server" });
        const manager = new ResponseAllocationManager();
        const owner = manager.openRequest(new AbortController().signal);
        try {
          await owner.produce(() =>
            read(async (client) => {
              const rows = await loadAdmittedSearchProjection(client, input);
              const original = await client.query<SearchPageRow>(ORIGINAL_SEARCH_SQL, parameters);
              expect(rows).toEqual(original.rows);
              expect(rows).toHaveLength(2);
              expect(rows.find((row) => row.cursor_id === first)?.item).toMatchObject({
                snippet: plain
              });
              const measured = await client.query<SearchProjectionMetadata>(
                SEARCH_PREFLIGHT_SQL,
                parameters
              );
              const rankBytes = await client.query<{ cursor_id: string; rank_bytes: string }>(
                `select cursor_id,octet_length((item->'rank')::text)::text as rank_bytes
             from (${ORIGINAL_SEARCH_SQL}) as original`,
                parameters
              );
              for (const row of rows) {
                const item = row.item as Record<string, JsonValue>;
                expect(Object.keys(item)).toHaveLength(10);
                const scalarValues = [
                  item["document_id"],
                  item["version_id"],
                  item["title"],
                  item["media_type"],
                  item["document_schema"] ?? "",
                  String(item["byte_length"]),
                  item["sha256"],
                  item["resource_uri"],
                  row.cursor_at,
                  row.cursor_id
                ];
                const scalarBytes = scalarValues.reduce<number>((sum, value) => {
                  expect(typeof value).toBe("string");
                  return sum + Buffer.byteLength(value as string);
                }, 0);
                const metadata = measured.rows.find((entry) => entry.id === row.cursor_id)!;
                expect(metadata.scalar_utf8).toBe(String(scalarBytes));
                expect(metadata.snippet_utf8).toBe(
                  String(Buffer.byteLength(item["snippet"] as string))
                );
                expect(metadata.rank_json_bytes).toBe(
                  rankBytes.rows.find((entry) => entry.cursor_id === row.cursor_id)?.rank_bytes
                );
                expect(metadata.version_id).toBe(item["version_id"]);
                expect(metadata.sha256).toBe(item["sha256"]);
              }
            })
          );
          expect(manager.accounting.usedUnits).toBeGreaterThan(0);
        } finally {
          owner.nativeTerminal();
          owner.collectorSettled();
        }
        expect(manager.accounting.usedUnits).toBe(0);

        // The fault is confined to this disposable fixture database. Replace only
        // the separate full-item expression, retaining the actual gate/parameters.
        await pool.query(`create function public.search_projection_construction_fault()
        returns jsonb language plpgsql volatile as $$begin
          raise exception 'search-full-construction'; end$$`);
        await pool.query(
          "grant execute on function public.search_projection_construction_fault() to boardagent_server"
        );
        const start = SEARCH_CONTENT_SQL.indexOf("select jsonb_build_object(");
        const end = SEARCH_CONTENT_SQL.indexOf(
          " from projected where projected.id=checked.id",
          start
        );
        expect(start).toBeGreaterThan(0);
        expect(end).toBeGreaterThan(start);
        const faultSql =
          SEARCH_CONTENT_SQL.slice(0, start) +
          "select public.search_projection_construction_fault()" +
          SEARCH_CONTENT_SQL.slice(end);
        await read(async (client) => {
          const before = await client.query<SearchProjectionMetadata>(
            SEARCH_PREFLIGHT_SQL,
            parameters
          );
          for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
            await client.query(`set local plan_cache_mode=${mode}`);
            await client.query("savepoint search_positive_fault");
            await expect(
              client.query({
                name: `search-full-${mode}`,
                text: faultSql,
                values: [...parameters, JSON.stringify(before.rows)]
              })
            ).rejects.toThrow("search-full-construction");
            await client.query("rollback to savepoint search_positive_fault");
            await client.query("release savepoint search_positive_fault");
            // Only the second identity is undercharged. A per-row gate could
            // construct the first; the global gate must suppress both objects.
            const undercharged = before.rows.map((row, n) =>
              n === 1 ? { ...row, snippet_utf8: "0" } : row
            );
            const refused = await client.query({
              name: `search-full-${mode}`,
              text: faultSql,
              values: [...parameters, JSON.stringify(undercharged)]
            });
            expect(refused.rows).toHaveLength(2);
            expect(
              refused.rows.every(
                (row: { fits: boolean; item: unknown }) => row.fits === false && row.item === null
              )
            ).toBe(true);
          }
        });

        // Deliberately privileged index inconsistency, not a supported writer:
        // all persisted identity/hash fields remain unchanged while snippet width
        // grows. This directly checks that fresh scalar lengths also participate.
        await read(async (client) => {
          const before = await client.query<SearchProjectionMetadata>(
            SEARCH_PREFLIGHT_SQL,
            parameters
          );
          await pool.query("update document_search set search_text=$2 where document_id=$1", [
            first,
            "needle " + Array.from({ length: 30 }, () => "x".repeat(1024)).join(" ") + " tail"
          ]);
          const after = await client.query<SearchProjectionMetadata>(
            SEARCH_PREFLIGHT_SQL,
            parameters
          );
          const oldRow = before.rows.find((row) => row.id === first)!;
          const newRow = after.rows.find((row) => row.id === first)!;
          expect(BigInt(newRow.snippet_utf8)).toBeGreaterThan(BigInt(oldRow.snippet_utf8));
          expect({
            ...newRow,
            snippet_utf8: oldRow.snippet_utf8,
            rank_json_bytes: oldRow.rank_json_bytes
          }).toEqual(oldRow);
          const refused = await client.query(SEARCH_CONTENT_SQL, [
            ...parameters,
            JSON.stringify(before.rows)
          ]);
          expect(
            refused.rows.every(
              (row: { fits: boolean; item: unknown }) => row.fits === false && row.item === null
            )
          ).toBe(true);
        });
        await pool.query("update document_search set search_text=$2 where document_id=$1", [
          first,
          plain
        ]);

        const growthManager = new ResponseAllocationManager();
        const growthOwner = growthManager.openRequest(new AbortController().signal);
        let added: string | undefined;
        try {
          await expect(
            growthOwner.produce(() =>
              read(async (client) => {
                const boundary = {
                  query: async (sql: string, values: unknown[]) => {
                    const result = await client.query(sql, values);
                    if (sql === SEARCH_PREFLIGHT_SQL)
                      added = await seedDocument(2, "needle new root");
                    return result;
                  }
                } as unknown as PoolClient;
                return loadAdmittedSearchProjection(boundary, input);
              })
            )
          ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
          expect(growthManager.accounting.usedUnits).toBeGreaterThan(0);
        } finally {
          growthOwner.nativeTerminal();
          growthOwner.collectorSettled();
        }
        expect(added).toBeDefined();
        await pool.query(
          "update documents set state='archived',row_version=row_version+1 where id=$1",
          [added]
        );

        // A committed exact token-row revocation occurs after the real-role
        // preflight inside one read. This is a direct-loader RLS observation,
        // not permission for a revoked token to begin a new public request.
        const revokedManager = new ResponseAllocationManager();
        const revokedOwner = revokedManager.openRequest(new AbortController().signal);
        try {
          const rows = await revokedOwner.produce(() =>
            read(async (client) => {
              const boundary = {
                query: async (sql: string, values: unknown[]) => {
                  const result = await client.query(sql, values);
                  if (sql === SEARCH_PREFLIGHT_SQL) {
                    expect(result.rows).toHaveLength(2);
                    const revoked = await pool.query(
                      "update access_token_records set revoked_at=transaction_timestamp() where jti=$1 and revoked_at is null returning jti",
                      [actor.tokenJti]
                    );
                    expect(revoked.rowCount).toBe(1);
                  }
                  return result;
                }
              } as unknown as PoolClient;
              return loadAdmittedSearchProjection(boundary, input);
            })
          );
          expect(rows).toEqual([]);
          expect(revokedManager.accounting.usedUnits).toBeGreaterThan(0);
          revokedOwner.nativeTerminal();
          expect(revokedManager.accounting.usedUnits).toBeGreaterThan(0);
        } finally {
          revokedOwner.nativeTerminal();
          revokedOwner.collectorSettled();
        }
        expect(revokedManager.accounting.usedUnits).toBe(0);
      },
      4
    );
  });
});
