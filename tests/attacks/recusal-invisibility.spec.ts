import { describe, expect, it } from "vitest";

import {
  fetchDocumentVersionInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("TH-09 recusal invisibility", () => {
  it("removes the object from reads, counts, search, and fetch without a differential trace", async () => {
    await withMigratedDatabase("recusal_invisibility", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["documents:read"]
      });
      const documentId = testId(9_100);
      const versionId = testId(9_101);
      const body = Buffer.from("recusal-sensitive board material", "utf8");
      await pool.query(
        `insert into documents(id,organization_id,board_id,title,created_by)
         values ($1,$2,$3,'Recusal-sensitive pack',$4)`,
        [documentId, actor.organizationId, actor.boardId, actor.memberId]
      );
      await pool.query(
        `insert into document_versions(
           id,organization_id,board_id,document_id,version,media_type,document_schema,
           canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by
         ) values ($1,$2,$3,$4,1,'text/plain; charset=utf-8',null,
           'RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)`,
        [
          versionId,
          actor.organizationId,
          actor.boardId,
          documentId,
          body,
          body.byteLength,
          testHash(91),
          actor.memberId
        ]
      );
      await pool.query(
        "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
        [versionId, documentId]
      );
      await pool.query(
        `insert into document_search(
           document_id,board_id,current_version_id,canonical_text_sha256,search_text
         ) values ($1,$2,$3,$4,'recusal-sensitive board material')`,
        [documentId, actor.boardId, versionId, testHash(91)]
      );
      await pool.query(
        `insert into document_access_grants(
           id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by
         ) values ($1,$2,$3,$4,$5,'read',$5)`,
        [testId(9_102), actor.organizationId, actor.boardId, documentId, actor.memberId]
      );

      const visible = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => ({
          documents: await client.query("select id from documents where id=$1", [documentId]),
          count: await client.query<{ count: string }>(
            "select count(*)::text as count from documents where board_id=$1",
            [actor.boardId]
          ),
          search: await client.query(
            "select document_id from document_search where search_vector @@ plainto_tsquery('simple',$1)",
            ["recusal-sensitive"]
          )
        }),
        { assumeRole: "boardagent_server" }
      );
      expect(visible.documents.rows).toEqual([{ id: documentId }]);
      expect(visible.count.rows).toEqual([{ count: "1" }]);
      expect(visible.search.rows).toEqual([{ document_id: documentId }]);

      await pool.query(
        `insert into document_exclusions(
           id,organization_id,board_id,document_id,member_id,version,reason,created_by
         ) values ($1,$2,$3,$4,$5,1,'live recusal',$5)`,
        [testId(9_103), actor.organizationId, actor.boardId, documentId, actor.memberId]
      );
      const hidden = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => ({
          documents: await client.query("select id from documents where id=$1", [documentId]),
          count: await client.query<{ count: string }>(
            "select count(*)::text as count from documents where board_id=$1",
            [actor.boardId]
          ),
          search: await client.query(
            "select document_id from document_search where search_vector @@ plainto_tsquery('simple',$1)",
            ["recusal-sensitive"]
          )
        }),
        { assumeRole: "boardagent_server" }
      );
      expect(hidden.documents.rows).toEqual([]);
      expect(hidden.count.rows).toEqual([{ count: "0" }]);
      expect(hidden.search.rows).toEqual([]);
      const auditCount = (await pool.query("select id from audit_events")).rowCount;
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            fetchDocumentVersionInTransaction(client, {
              organizationId: actor.organizationId,
              boardId: actor.boardId,
              documentId,
              version: 1,
              auditEventId: testId(9_104),
              requestOrigin: "https://client.example"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("document version is unavailable");
      expect((await pool.query("select id from audit_events")).rowCount).toBe(auditCount);
    });
  });
});
