import { describe, expect, it } from "vitest";

import {
  fetchDocumentVersionInTransaction,
  recordResourceFetchOutcomeInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testHash, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

describe("TH-51 interrupted resource delivery", () => {
  it("records prepared and interrupted evidence without claiming completion or receipt", async () => {
    await withMigratedDatabase("resource_interruption", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["documents:read"]
      });
      const documentId = testId(51_000);
      const versionId = testId(51_001);
      const body = Buffer.from("exact bytes that are only partly delivered", "utf8");
      await pool.query(
        `insert into documents(id,organization_id,board_id,title,created_by)
         values ($1,$2,$3,'Interrupted resource',$4)`,
        [documentId, actor.organizationId, actor.boardId, actor.memberId]
      );
      await pool.query(
        `insert into document_versions(
           id,organization_id,board_id,document_id,version,media_type,
           canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by
         ) values ($1,$2,$3,$4,1,'text/plain; charset=utf-8','RFC8785+NFC-LF-v1',
           $5,$6,$7,'{}',$8)`,
        [
          versionId,
          actor.organizationId,
          actor.boardId,
          documentId,
          body,
          body.byteLength,
          testHash(51),
          actor.memberId
        ]
      );
      await pool.query(
        "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
        [versionId, documentId]
      );
      await pool.query(
        `insert into document_access_grants(
           id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by
         ) values ($1,$2,$3,$4,$5,'read',$5)`,
        [testId(51_002), actor.organizationId, actor.boardId, documentId, actor.memberId]
      );

      const prepared = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          fetchDocumentVersionInTransaction(client, {
            organizationId: actor.organizationId,
            boardId: actor.boardId,
            documentId,
            version: 1,
            auditEventId: testId(51_003),
            requestOrigin: "https://client.example"
          }),
        { assumeRole: "boardagent_server" }
      );
      const transferred = Math.floor(body.byteLength / 2);
      const interrupted = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          recordResourceFetchOutcomeInTransaction(client, {
            preparedEventId: prepared.preparedEvent.eventId,
            outcomeEventId: testId(51_004),
            outcome: "interrupted",
            bytesTransferred: transferred
          }),
        { assumeRole: "boardagent_server" }
      );

      expect(prepared.preparedEvent.details).toMatchObject({
        phase: "prepared",
        byteLength: body.byteLength,
        resourceUri: `board://${actor.boardId}/documents/${documentId}/versions/1`
      });
      expect(interrupted.details).toMatchObject({
        phase: "interrupted",
        preparedEventId: prepared.preparedEvent.eventId,
        bytesTransferred: transferred
      });
      expect(interrupted.details["phase"]).not.toBe("completed");
      expect(interrupted.eventType).toBe("resource_fetch");

      const phases = await pool.query<{ phase: string }>(
        `select convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'phase' as phase
           from audit_events
          where event_type='resource_fetch'
          order by sequence`
      );
      expect(phases.rows).toEqual([{ phase: "prepared" }, { phase: "interrupted" }]);
      expect(
        await pool.query(
          `select id from audit_events
            where event_type in ('notice_delivered','export_download_completed')`
        )
      ).toMatchObject({ rowCount: 0 });

      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            recordResourceFetchOutcomeInTransaction(client, {
              preparedEventId: prepared.preparedEvent.eventId,
              outcomeEventId: testId(51_005),
              outcome: "completed",
              bytesTransferred: transferred
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("fetch outcome does not match prepared evidence");

      const unknown = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          recordResourceFetchOutcomeInTransaction(client, {
            preparedEventId: prepared.preparedEvent.eventId,
            outcomeEventId: testId(51_006),
            outcome: "interrupted",
            bytesTransferred: null,
            observation: {
              basis: "node_response_interruption",
              responseBytesQueued: body.byteLength + 200
            }
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(unknown.schemaVersion).toBe(1);
      expect(unknown.details).toMatchObject({
        phase: "interrupted",
        bytesTransferred: null,
        outcomeObservationVersion: 1,
        observationBasis: "node_response_interruption",
        responseBytesQueued: body.byteLength + 200,
        byteLength: body.byteLength,
        preparedEventId: prepared.preparedEvent.eventId
      });
      await expect(
        withRequestTransaction(
          pool,
          actor.context,
          (client) =>
            recordResourceFetchOutcomeInTransaction(client, {
              preparedEventId: prepared.preparedEvent.eventId,
              outcomeEventId: testId(51_007),
              outcome: "completed",
              bytesTransferred: null,
              observation: {
                basis: "node_response_finish",
                responseBytesQueued: body.byteLength + 200
              }
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("fetch outcome byte count");
    });
  });
});
