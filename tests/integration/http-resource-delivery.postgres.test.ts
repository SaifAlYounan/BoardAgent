import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import path from "node:path";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { decodeJwt } from "jose";
import { eventHash, type AuditEventBody } from "../../lib/audit/src/index.js";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { sha256Hex, TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import { loadMigrations, migrate } from "../../lib/db/src/migrate.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId, type AuthorizedActorFixture } from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

interface AuditRow {
  id: string;
  organization_id: string;
  sequence: string;
  canonical_hex: string;
  event_hash: string;
  previous_hash: string;
  body: AuditEventBody;
}

async function auditSnapshot(pool: Pool): Promise<AuditRow[]> {
  return (
    await pool.query<AuditRow>(
      `select id,organization_id,sequence::text,
         encode(canonical_payload,'hex') as canonical_hex,
         encode(event_sha256,'hex') as event_hash,
         encode(previous_event_sha256,'hex') as previous_hash,
         convert_from(canonical_payload,'UTF8')::jsonb as body
       from audit_events order by sequence`
    )
  ).rows;
}

function resourceRows(rows: readonly AuditRow[], versionId: string): AuditRow[] {
  return rows.filter(
    ({ body }) => body.eventType === "resource_fetch" && body.entityId === versionId
  );
}

function expectImmutable(before: readonly AuditRow[], after: readonly AuditRow[]) {
  const byId = new Map(after.map((row) => [row.id, row]));
  for (const row of before) expect(byId.get(row.id)).toEqual(row);
}

async function seedDocument(pool: Pool, actor: AuthorizedActorFixture, canonical: string) {
  const documentId = testId(871_001);
  const versionId = testId(871_002);
  const bytes = Buffer.from(canonical, "utf8");
  await pool.query(
    "insert into documents(id,organization_id,board_id,title,created_by) values ($1,$2,$3,'Synthetic HTTP delivery document',$4)",
    [documentId, actor.organizationId, actor.boardId, actor.memberId]
  );
  await pool.query(
    `insert into document_versions(id,organization_id,board_id,document_id,version,media_type,
       canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by)
     values ($1,$2,$3,$4,1,'text/plain; charset=utf-8','RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)`,
    [
      versionId,
      actor.organizationId,
      actor.boardId,
      documentId,
      bytes,
      bytes.byteLength,
      Buffer.from(sha256Hex(bytes), "hex"),
      actor.memberId
    ]
  );
  await pool.query(
    "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
    [versionId, documentId]
  );
  await pool.query(
    `insert into document_access_grants(id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by)
     values ($1,$2,$3,$4,$5,'read',$5)`,
    [testId(871_003), actor.organizationId, actor.boardId, documentId, actor.memberId]
  );
  return {
    documentId,
    versionId,
    bytes,
    uri: `board://${actor.boardId}/documents/${documentId}/versions/1`
  };
}

describe("SR071 actual HTTPS and PostgreSQL resource outcomes", () => {
  it.each(["completed", "interrupted"] as const)(
    "binds immutable prepared evidence to the actual %s response outcome",
    async (phase) => {
      const base = new URL(
        process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
          "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent"
      );
      if (!["127.0.0.1", "localhost"].includes(base.hostname))
        throw new Error("resource delivery acceptance requires disposable local PostgreSQL");
      const database = `boardagent_http_delivery_${process.pid}_${randomBytes(4).toString("hex")}`;
      const outputRoot =
        process.env["BOARDAGENT_DELIVERY_EVIDENCE_DIRECTORY"] ??
        path.resolve("artifacts/verification/execution-runs/sr071-http-db");
      if (!path.isAbsolute(outputRoot))
        throw new Error("delivery evidence directory must be absolute");
      await mkdir(outputRoot, { recursive: true, mode: 0o700 });
      const directory = await mkdtemp(path.join(outputRoot, `${phase}-`));
      const record = (name: string, value: unknown) =>
        writeFile(path.join(directory, name), JSON.stringify(value, null, 2) + "\n", {
          mode: 0o600
        });
      const ownerUrl = new URL(base);
      ownerUrl.pathname = "/postgres";
      const owner = new Pool({ connectionString: ownerUrl.toString(), max: 1 });
      base.pathname = `/${database}`;
      const pool = new Pool({ connectionString: base.toString(), max: 8 });
      let created = false;
      let passed = false;
      let dropped = false;
      let f: Awaited<ReturnType<typeof administrativeOAuthFixture>> | undefined;
      let interruptClient: Client | undefined;
      let receivedBytes = 0;
      let clientEnded = false;
      let clientAborted = false;
      let clientClosed = false;
      const interruption = new Error("synthetic native client socket interruption");
      try {
        await owner.query(`create database "${database}"`);
        created = true;
        await record("fixture.json", {
          database,
          host: base.hostname,
          port: base.port,
          phase,
          synthetic: true
        });
        const migrations = path.resolve("lib/db/migrations");
        await migrate(pool, migrations, "http-resource-delivery-acceptance");
        const applied = (
          await pool.query("select version,name,sha256 from schema_migrations order by version")
        ).rows;
        const expected = await loadMigrations(migrations);
        expect(applied).toEqual(
          expected.map(({ version, name, sha256 }) => ({ version, name, sha256 }))
        );
        await record("schema.json", applied);
        // Existing ordinary synthetic login/setup only. No administrative or recovery action is invoked.
        f = await administrativeOAuthFixture(pool);
        const actor = f.target;
        const canonical =
          phase === "completed"
            ? 'Exact synthetic document: "Mining Δ"\n'
            : "\\".repeat(2 * 1024 * 1024);
        const document = await seedDocument(pool, actor, canonical);
        const token = await f.login(actor.memberId, false, ["documents:read"]);
        // Claims are only expected test data: the real application verifies the issued JWT on HTTP.
        const jti = decodeJwt(token.access_token).jti;
        expect(jti).toEqual(expect.any(String));
        const liveToken = (
          await pool.query<{
            jti: string;
            member_id: string;
            client_id: string;
            organization_id: string;
            resource_uri: string;
            scope_set: string[];
          }>(
            "select jti,member_id,client_id,organization_id,resource_uri,scope_set from access_token_records where jti=$1",
            [jti]
          )
        ).rows[0]!;
        expect(liveToken).toMatchObject({
          member_id: actor.memberId,
          organization_id: actor.organizationId,
          resource_uri: f.resource,
          scope_set: ["documents:read"]
        });
        const before = await auditSnapshot(pool);
        await record("audit-before.json", before);
        expect(resourceRows(before, document.versionId)).toEqual([]);
        const call = {
          name: "read_document",
          arguments: {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            document_id: document.documentId,
            version_id: document.versionId
          }
        };
        let preparedDuringPause: AuditRow[] | undefined;
        if (phase === "completed") {
          const client = await f.connect(token);
          const response = await client.callTool(call);
          expect(response.isError).not.toBe(true);
          expect(response.structuredContent).toMatchObject({
            resource_uri: document.uri,
            data: {
              document_id: document.documentId,
              version_id: document.versionId,
              version: 1,
              canonical_body: canonical,
              media_type: "text/plain; charset=utf-8",
              byte_length: document.bytes.byteLength,
              sha256: sha256Hex(document.bytes)
            }
          });
        } else {
          const certificate = await readFile(
            path.resolve("tests/fixtures/tls/released-client-matrix.crt")
          );
          const application = f;
          let armed = false;
          let intercepted = 0;
          const transportFetch: typeof fetch = async (input, init) => {
            const request = new Request(input, init);
            if (new URL(request.url).origin !== application.origin)
              throw new Error("nonlocal delivery request refused");
            if (!armed) return application.trustedFetch(request);
            armed = false;
            intercepted++;
            const body = Buffer.from(await request.arrayBuffer());
            expect(JSON.parse(body.toString("utf8"))).toMatchObject({
              method: "tools/call",
              params: call
            });
            return new Promise<Response>((_resolve, reject) => {
              const outgoing = httpsRequest(
                request.url,
                {
                  ca: certificate,
                  family: 4,
                  agent: false,
                  method: request.method,
                  headers: Object.fromEntries(request.headers),
                  signal: request.signal
                },
                (incoming) => {
                  if (incoming.statusCode !== 200) {
                    incoming.resume();
                    reject(new Error(`native read returned HTTP ${String(incoming.statusCode)}`));
                    return;
                  }
                  incoming.once("end", () => {
                    clientEnded = true;
                    reject(new Error("native response ended before interruption"));
                  });
                  incoming.once("aborted", () => {
                    clientAborted = true;
                  });
                  incoming.once("close", () => {
                    clientClosed = true;
                  });
                  incoming.once("error", reject);
                  incoming.once("data", (chunk: Buffer) => {
                    receivedBytes += chunk.byteLength;
                    incoming.pause();
                    // The actual response remains paused while an independent DB connection observes its committed preparation.
                    void auditSnapshot(pool)
                      .then(async (rows) => {
                        preparedDuringPause = resourceRows(rows, document.versionId);
                        await record("audit-during-paused-socket.json", rows);
                        expect(preparedDuringPause).toHaveLength(1);
                        expect(preparedDuringPause[0]!.body.details["phase"]).toBe("prepared");
                        incoming.destroy(interruption);
                        outgoing.destroy(interruption);
                        reject(interruption);
                      })
                      .catch((error: unknown) => {
                        incoming.destroy();
                        outgoing.destroy();
                        reject(error);
                      });
                  });
                }
              );
              outgoing.once("error", reject);
              outgoing.end(body);
              // No reconstructed or substituted Response: this actual request is deliberately interrupted before receipt.
            });
          };
          interruptClient = new Client(
            { name: "resource-delivery-interruption", version: "1" },
            {
              capabilities: {},
              versionNegotiation: { mode: { pin: "2026-07-28" } }
            }
          );
          await interruptClient.connect(
            new StreamableHTTPClientTransport(new URL(f.resource), {
              requestInit: { headers: { authorization: `Bearer ${token.access_token}` } },
              fetch: transportFetch
            })
          );
          armed = true;
          await expect(interruptClient.callTool(call)).rejects.toThrow(interruption.message);
          expect(intercepted).toBe(1);
          expect(receivedBytes).toBeGreaterThan(0);
          expect(clientEnded).toBe(false);
          await expect.poll(() => clientAborted && clientClosed).toBe(true);
        }
        await expect
          .poll(async () => resourceRows(await auditSnapshot(pool), document.versionId).length, {
            timeout: 10_000
          })
          .toBe(2);
        const after = await auditSnapshot(pool);
        await record("audit-after.json", after);
        expectImmutable(before, after);
        if (preparedDuringPause) expectImmutable(preparedDuringPause, after);
        const rows = resourceRows(after, document.versionId);
        const prepared = rows.find(({ body }) => body.details["phase"] === "prepared")!;
        const outcome = rows.find(({ body }) => body.details["phase"] === phase)!;
        expect(rows).toHaveLength(2);
        expect(prepared).toBeDefined();
        expect(outcome).toBeDefined();
        for (const row of rows) {
          expect(row.organization_id).toBe(actor.organizationId);
          expect(eventHash(BigInt(row.sequence), row.previous_hash, row.body)).toBe(row.event_hash);
          expect(row.body).toMatchObject({
            eventId: row.id,
            eventType: "resource_fetch",
            actorMemberId: actor.memberId,
            actorClientId: liveToken.client_id,
            tokenJti: jti,
            entityType: "document_version",
            entityId: document.versionId,
            boardId: actor.boardId,
            origin: "mcp",
            details: {
              resourceUri: document.uri,
              representation: "text/plain; charset=utf-8",
              sha256: sha256Hex(document.bytes),
              byteLength: document.bytes.byteLength,
              memberId: actor.memberId,
              clientId: liveToken.client_id,
              tokenJti: jti,
              requestOrigin: f.origin,
              version: 1
            }
          });
        }
        expect(outcome.body.details).toMatchObject({
          phase,
          preparedEventId: prepared.id,
          preparedEventHash: prepared.event_hash,
          outcomeObservationVersion: 1,
          observationBasis:
            phase === "completed" ? "node_response_finish" : "node_response_interruption",
          bytesTransferred: phase === "completed" ? document.bytes.byteLength : null
        });
        expect(outcome.body.details["responseBytesQueued"]).toBeGreaterThan(0);
        if (phase === "interrupted")
          expect(receivedBytes).toBeLessThan(outcome.body.details["responseBytesQueued"] as number);
        expect(
          (
            await pool.query<{ canonical_bytes: Buffer }>(
              "select canonical_bytes from document_versions where id=$1",
              [document.versionId]
            )
          ).rows[0]!.canonical_bytes
        ).toEqual(document.bytes);
        await record("outcome.json", {
          phase,
          canonicalBytes: document.bytes.byteLength,
          receivedBytes,
          clientEnded,
          clientAborted,
          clientClosed,
          preparedId: prepared.id,
          outcomeId: outcome.id,
          outcomeDetails: outcome.body.details,
          applicationErrors: f.errors.map((error) => ({
            name: error.name,
            message: error.message,
            code: (error as Error & { code?: string }).code
          }))
        });
        // Native disconnect is expected only in the interrupted case; storage/auth/other server errors still fail.
        if (phase === "completed") expect(f.errors).toEqual([]);
        else {
          expect(f.errors).toHaveLength(1);
          expect(f.errors[0]).toMatchObject({
            name: "Error",
            message: "downstream connection closed"
          });
        }
        await interruptClient?.close();
        interruptClient = undefined;
        await f.close();
        f = undefined;
        passed = true;
      } catch (error) {
        await record("failure.json", {
          name: error instanceof Error ? error.name : "unknown",
          message: error instanceof Error ? error.message : String(error)
        });
        if (created)
          await record("audit-at-failure.json", await auditSnapshot(pool)).catch(() => undefined);
        throw error;
      } finally {
        try {
          await interruptClient?.close();
          await f?.close();
        } finally {
          await pool.end();
          try {
            if (created && passed) {
              await dropClosedTestDatabase(owner, database);
              dropped = true;
            }
          } finally {
            await owner.end();
            await record("lifecycle.json", { database, passed, preserved: created && !dropped });
            console.info(
              JSON.stringify({
                probe: "native-https-postgres-delivery",
                phase,
                database,
                passed,
                preserved: created && !dropped,
                directory
              })
            );
          }
        }
      }
    },
    120_000
  );
});
