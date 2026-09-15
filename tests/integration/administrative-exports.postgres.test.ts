import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import { signCheckpoint } from "../../lib/audit/src/index.js";
import {
  LocalExportArtifactStore,
  decryptExportEnvelope
} from "../../artifacts/server/src/index.js";
import {
  buildFrozenExportSnapshotInTransaction,
  prepareAuditCheckpointInTransaction,
  commitAuditCheckpointInTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";
import { administrativeHistory as exportFixture } from "../helpers/administrative-history.js";

const TABLES = [
  "company_admin_proposals",
  "member_admin_delegations",
  "administrative_authority_changes"
] as const;
async function queue(
  pool: Pool,
  f: Awaited<ReturnType<typeof exportFixture>>,
  index: number,
  kind: "organization" | "board" | "member_portability",
  memberId: string | null = null,
  boardId: string | null = null,
  organizationId = f.issuer.organizationId,
  requesterId = f.issuer.memberId
) {
  const id = testId(94_200 + index);
  const scope = {
    schemaVersion: "boardagent.export-scope.v1",
    exportType: "system_data",
    organizationId,
    boardId,
    scope: kind,
    memberId,
    purpose: "Verify administrative history scope",
    dataClasses: ["identity_authority"],
    includeCanonicalContent: true,
    excludeSecretMaterial: true
  };
  await pool.query(
    "insert into export_requests(id,public_id,organization_id,board_id,requester_member_id,export_type,scope_manifest,scope_sha256,state,consent_record_id,recent_auth_at,expires_at) values($1,$2,$3,$4,$5,'system_data',$6,$7,'queued',$8,transaction_timestamp(),transaction_timestamp()+interval '1 hour')",
    [
      id,
      Buffer.alloc(32, index + 1),
      organizationId,
      boardId,
      requesterId,
      Buffer.from(canonicalJson(scope), "utf8"),
      Buffer.from(canonicalSha256(scope), "hex"),
      f.issuer.consentRecordId
    ]
  );
  return id;
}
async function rows(pool: Pool, id: string, table: string, dataClass = "identity_authority") {
  return withWorkerTransaction(
    pool,
    async (client) =>
      (
        await client.query<{ table_rows: Record<string, string>[] }>(
          "select table_rows from boardagent_export_system_table_rows($1,$2,$3)",
          [id, dataClass, table]
        )
      ).rows[0]!.table_rows,
    { assumeRole: "boardagent_worker", isolation: "repeatable read" }
  );
}
describe("AC22 administrative authority export retention and isolation", () => {
  it("exports complete org history, exact board records and only the selected member's involved records", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await exportFixture(pool);
      const organization = await queue(pool, f, 1, "organization");
      expect((await rows(pool, organization, TABLES[0])).map((r) => r["id"])).toEqual(
        expect.arrayContaining([testId(94_100), testId(94_101)])
      );
      expect(await rows(pool, organization, TABLES[1])).toMatchObject([
        { id: f.input.change.delegation_id, state: "revoked", row_version: "2" }
      ]);
      expect(await rows(pool, organization, TABLES[2])).toHaveLength(4);
      const board = await queue(pool, f, 2, "board", null, f.issuer.boardId);
      expect(await rows(pool, board, TABLES[0])).toEqual([]);
      expect(await rows(pool, board, TABLES[1])).toHaveLength(1);
      expect(await rows(pool, board, TABLES[2])).toHaveLength(2);
      const otherBoard = testId(94_304);
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'empty-export-board','Other board','UTC')",
        [otherBoard, f.issuer.organizationId]
      );
      const otherBoardRequest = await queue(pool, f, 7, "board", null, otherBoard);
      for (const table of TABLES) expect(await rows(pool, otherBoardRequest, table)).toEqual([]);
      const member = await queue(pool, f, 3, "member_portability", f.target.memberId);
      expect((await rows(pool, member, TABLES[0])).map((r) => r["id"])).toEqual([testId(94_100)]);
      expect(await rows(pool, member, TABLES[1])).toHaveLength(1);
      expect(await rows(pool, member, TABLES[2])).toHaveLength(3);
      expect(JSON.stringify(await rows(pool, member, TABLES[2]))).not.toContain(testId(94_101));
      const unrelated = await queue(pool, f, 4, "member_portability", f.other.memberId);
      expect(await rows(pool, unrelated, TABLES[1])).toEqual([]);
      expect(await rows(pool, unrelated, TABLES[2])).toHaveLength(1);
      for (const table of TABLES)
        await expect(rows(pool, organization, table, "documents")).rejects.toMatchObject({
          code: "42501"
        });
      for (const secretTable of ["auth_sessions", "oauth_authorization_codes", "refresh_families"])
        await expect(rows(pool, organization, secretTable)).rejects.toMatchObject({
          code: "42501"
        });
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values($1,'Foreign','Foreign','foreign-export','UTC')",
        [testId(94_301)]
      );
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Foreign','Foreign','active')",
        [testId(94_302), testId(94_301)]
      );
      const foreign = await queue(
        pool,
        f,
        5,
        "organization",
        null,
        null,
        testId(94_301),
        testId(94_302)
      );
      for (const table of TABLES) expect(await rows(pool, foreign, table)).toEqual([]);
    });
  });
  it("the production export producer retains authority history through encrypted publication and decryption", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await exportFixture(pool);
      const id = await queue(pool, f, 6, "organization");
      const keys = generateKeyPairSync("ed25519");
      const keyId = testId(94_400);
      await pool.query(
        "insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at) values($1,$2,'admin-export-test','evidence_signing','EdDSA',$3,'disposable-export-test',transaction_timestamp()-interval '1 minute')",
        [keyId, f.issuer.organizationId, keys.publicKey.export({ format: "jwk" })]
      );
      const prepared = await withWorkerTransaction(
        pool,
        (c) =>
          prepareAuditCheckpointInTransaction(c, {
            checkpointId: testId(94_401),
            signingKeyId: keyId
          }),
        { assumeRole: "boardagent_worker" }
      );
      await withWorkerTransaction(
        pool,
        (c) =>
          commitAuditCheckpointInTransaction(c, {
            checkpoint: signCheckpoint(prepared.payload, keys.privateKey),
            auditEventId: testId(94_402)
          }),
        { assumeRole: "boardagent_worker" }
      );
      const frozen = await withWorkerTransaction(
        pool,
        (c) =>
          buildFrozenExportSnapshotInTransaction(c, {
            exportRequestId: id,
            exportStartedAuditEventId: testId(94_403)
          }),
        { assumeRole: "boardagent_worker", isolation: "repeatable read" }
      );
      for (const table of TABLES) {
        const component = frozen.components.find((c) => c.name === `identity_authority:${table}`);
        expect(component, table).toBeDefined();
        expect(component!.sha256).toBe(
          canonicalSha256(JSON.parse(component!.bytes.toString("utf8")))
        );
        expect(Number(component!.rowCount)).toBe(
          table === "company_admin_proposals" ? 2 : table === "member_admin_delegations" ? 1 : 4
        );
      }
      const artifactRoot = await mkdtemp(path.join(tmpdir(), "boardagent-admin-export-"));
      const encryptionKey = randomBytes(32);
      try {
        const store = new LocalExportArtifactStore(artifactRoot, {
          maximumArtifactBytes: 16_777_216,
          chunkBytes: 65_536
        });
        let nextId = 94_500;
        const manifest = await store.publish({
          frozen,
          artifactId: testId(94_404),
          encryptionKeyId: testId(94_405),
          encryptionKey,
          newChunkId: () => testId(nextId++),
          randomBytes
        });
        const encrypted = Buffer.concat(
          await Promise.all(
            manifest.chunks.map(async (chunk) =>
              Buffer.from(
                await store.readExactChunk({
                  exportRequestId: id,
                  artifactId: manifest.artifactId,
                  ordinal: chunk.ordinal,
                  storageLocator: chunk.storageLocator,
                  byteLength: chunk.byteLength,
                  expectedSha256: chunk.chunkSha256
                })
              )
            )
          )
        );
        expect(encrypted.includes(Buffer.from("Retain revoked authority in the export"))).toBe(
          false
        );
        const restored = decryptExportEnvelope(encrypted, encryptionKey);
        expect(restored.snapshot).toEqual(frozen.snapshot);
        for (const original of frozen.components)
          expect(restored.components.find((c) => c.name === original.name)?.bytes).toEqual(
            original.bytes
          );
        const changes = restored.components.find(
          (c) => c.name === "identity_authority:administrative_authority_changes"
        );
        const records = JSON.parse(changes!.bytes.toString("utf8")).rows as Record<
          string,
          string
        >[];
        for (const record of records) {
          const payload = Buffer.from(record["canonical_payload"]!.slice(2), "hex");
          expect(canonicalSha256(JSON.parse(payload.toString("utf8")))).toBe(
            record["payload_sha256"]!.slice(2)
          );
        }
        expect(() => decryptExportEnvelope(encrypted, Buffer.alloc(32, 0))).toThrow();
      } finally {
        encryptionKey.fill(0);
        await rm(artifactRoot, { recursive: true, force: true });
      }
    });
  });
});
