import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  loadAdmittedTranscriptProjection,
  TRANSCRIPT_CONTENT_SQL,
  TRANSCRIPT_PREFLIGHT_SQL
} from "../../artifacts/server/src/transcript-projection-read.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  type BoardAgentSurfaceService,
  type PreparedHumanAction,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  canonicalJson,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import {
  askManagementQuestionInTransaction,
  migrate,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { prepareManagementQuestion } from "../../lib/domain/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_surface_transcript_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  let passed = false;
  try {
    await migrate(pool, MIGRATIONS, "surface-transcript-lifecycle-test");
    const result = await run(pool);
    passed = true;
    return result;
  } finally {
    try {
      await pool.end();
      if (passed) await dropClosedTestDatabase(admin, database);
      else console.error(`Preserved failed transcript fixture database: ${database}`);
    } finally {
      await admin.end();
    }
  }
}

function principal(
  actor: AuthorizedActorFixture,
  roles: readonly ("admin" | "member" | "observer" | "secretariat")[],
  scopes: readonly string[]
): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://transcript-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes,
    roles,
    boardIds: [actor.boardId]
  };
}

let confirmationSequence = 0;

async function prepareAndPersist(
  service: BoardAgentSurfaceService,
  actorPrincipal: SurfacePrincipal,
  tool: string,
  input: JsonValue
): Promise<{ readonly prepared: PreparedHumanAction; readonly requestState: string }> {
  confirmationSequence += 1;
  const requestLabel = `surface-transcript-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const prepared = await service.prepareHumanAction(actorPrincipal, tool, input);
  const clientCapabilities = { elicitation: { form: {} } } as const;
  const requestState = `${requestLabel}-request-state-bound-by-client`;
  await service.persistHumanStage({
    principal: actorPrincipal,
    tool,
    input,
    prepared,
    client_capabilities: clientCapabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm exact ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${requestLabel}-prepare`)
  });
  return { prepared, requestState };
}

async function confirmSurfaceAction(
  service: BoardAgentSurfaceService,
  actorPrincipal: SurfacePrincipal,
  tool: string,
  input: JsonValue
) {
  const { prepared, requestState } = await prepareAndPersist(service, actorPrincipal, tool, input);
  const resolution = await service.resolveHumanAction({
    principal: actorPrincipal,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: { elicitation: { form: {} } },
    request_state: requestState,
    retry_request_id: Buffer.from(`surface-transcript-${tool}-retry-${prepared.stage_id}`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolution.confirmed) throw new Error(`${tool} failed: ${resolution.reason}`);
  return resolution.result;
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by transcript lifecycle test");
  },
  readResource: async () => {
    throw new Error("resource read not used by transcript lifecycle test");
  }
};

function meetingInput(boardId: string, meetingId: string, attendees: readonly string[]): JsonValue {
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    board_id: boardId,
    meeting_id: meetingId,
    title: "Exploration committee transcript test",
    scheduled_start_at: "2026-10-01T09:00:00Z",
    scheduled_end_at: "2026-10-01T10:30:00Z",
    timezone: "Asia/Dubai",
    agenda: {
      schema_version: "boardagent.agenda.v1",
      values: {
        items: [
          {
            title: "Review drilling safeguards",
            source_document_version_id: null,
            source_document_sha256: null
          }
        ]
      }
    },
    attendee_member_ids: attendees,
    idempotency_key: "surface-transcript-meeting-0001"
  };
}

// Direct repository fixtures model owner settlement and record preparation only.
async function withTranscriptReadOwner<T>(read: () => Promise<T>): Promise<T> {
  const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
  try {
    return await owner.produce(read);
  } finally {
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}

describe("meeting transcript annex lifecycle surface", () => {
  it("admits the complete transcript projection and refuses before construction on saturation or fresh child growth", async () => {
    await withDatabase(async (pool) => {
      const verificationUniqueness = await pool.query<{ one_per_version: boolean }>(`
        select exists (
          select 1 from pg_catalog.pg_index as idx
          join pg_catalog.pg_attribute as attribute
            on attribute.attrelid=idx.indrelid and attribute.attnum=any(idx.indkey)
          where idx.indrelid='public.transcript_verifications'::regclass
            and idx.indisunique and idx.indisvalid and idx.indisready
            and idx.indnkeyatts=1 and idx.indnatts=1
            and idx.indpred is null and idx.indexprs is null
            and attribute.attname='transcript_version_id'
            and attribute.attnotnull and not attribute.attisdropped
        ) as one_per_version`);
      expect(verificationUniqueness.rows).toEqual([{ one_per_version: true }]);
      const scopes = ["secretariat:admin", "secretariat:message", "meeting:act", "governance:read"];
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes,
        isSecretary: true
      });
      const caller = principal(actor, ["member", "secretariat"], scopes);
      let nextId = 168_000;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const meetingId = testId(168_800);
      const transcriptId = testId(168_801);
      const turnIds = [testId(168_802), testId(168_803)];
      const texts = ['Exact "record" Δ', "Second synthetic record."];
      await confirmSurfaceAction(
        surface,
        caller,
        "create_meeting",
        meetingInput(actor.boardId, meetingId, [actor.memberId])
      );
      const body = canonicalJson({
        schema_version: "boardagent.transcript-turns.v1",
        values: {
          turns: texts.map((canonical_text, i) => ({
            canonical_text,
            ends_at_ms: (i + 1) * 2000,
            starts_at_ms: (i + 1) * 1000,
            speaker_label: "Secretary",
            speaker_member_id: actor.memberId,
            turn_id: turnIds[i]!
          }))
        }
      });
      const created = await surface.executeDirect(caller, "create_meeting_transcript_version", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        transcript_id: transcriptId,
        media_type: "application/json",
        canonical_body: body,
        coverage_statement: "Complete synthetic composite transcript.",
        supersedes_version_id: null,
        idempotency_key: "transcript-composite-admission-0001"
      });
      if (!created.reference) throw new Error("synthetic transcript version missing");
      const versionId = created.reference;
      const comment = "Initial supported synthetic challenge.";
      const challenge = await surface.executeDirect(caller, "challenge_transcript_turn", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_version_id: versionId,
        turn_id: turnIds[0]!,
        comment,
        idempotency_key: "transcript-composite-challenge-0001"
      });
      if (!challenge.reference) throw new Error("synthetic challenge missing");
      await confirmSurfaceAction(surface, caller, "verify_meeting_transcript", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_id: transcriptId,
        version_id: versionId,
        sha256: sha256Hex(body),
        verification_statement: "secretary_verified_annex_hash",
        idempotency_key: "transcript-composite-verify-0001"
      });
      const sessionId = testId(168_804);
      await pool.query(
        `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
         values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, testHash(168), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);
      const reader = new PgSurfaceReadRepository(pool, {
        cursorKey: Buffer.alloc(32, 0x58),
        transaction: { assumeRole: "boardagent_server" }
      });
      const readCaller = { ...caller, protocolClientId: "authorized-test-client" };
      const manager = new ResponseAllocationManager();
      const admitted = manager.openRequest(new AbortController().signal);
      try {
        const read = await admitted.produce(() =>
          reader.executeRead(readCaller, "get_meeting_transcript", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            transcript_id: transcriptId,
            version_id: versionId
          })
        );
        const transcript = (read.data as { transcript: Record<string, unknown> }).transcript;
        expect(Object.keys(transcript).sort()).toEqual(
          [
            "transcript_id",
            "meeting_id",
            "state",
            "version_id",
            "version",
            "canonical_schema",
            "media_type",
            "canonical_body",
            "sha256",
            "source_type",
            "verification_state",
            "supersedes_id",
            "turns",
            "challenges",
            "verification"
          ].sort()
        );
        expect(transcript).toMatchObject({
          transcript_id: transcriptId,
          meeting_id: meetingId,
          state: expect.any(String),
          version_id: versionId,
          version: 1,
          canonical_schema: "boardagent.transcript-turns.v1",
          media_type: "application/json",
          canonical_body: body,
          sha256: sha256Hex(body),
          source_type: "agent_prepared",
          // Immutable version metadata retains its preparation state; the root
          // and separate verification row record the later verification.
          verification_state: "agent_prepared_unverified",
          supersedes_id: null
        });
        expect(transcript["turns"]).toEqual(
          texts.map((canonical_text, i) => ({
            turn_id: turnIds[i],
            ordinal: i + 1,
            speaker_member_id: actor.memberId,
            speaker_label: "Secretary",
            starts_at_ms: String((i + 1) * 1000),
            ends_at_ms: String((i + 1) * 2000),
            canonical_text,
            sha256: sha256Hex(canonical_text)
          }))
        );
        const challenges = transcript["challenges"] as Array<Record<string, unknown>>;
        expect(challenges).toHaveLength(1);
        expect(challenges[0]).toEqual({
          challenge_id: challenge.reference,
          turn_id: turnIds[0],
          challenger_member_id: actor.memberId,
          canonical_comment: comment,
          comment_sha256: sha256Hex(comment),
          state: "pending",
          created_at: expect.any(String)
        });
        const verification = transcript["verification"] as Record<string, unknown>;
        expect(verification).toEqual({
          verification_id: expect.any(String),
          sha256: sha256Hex(body),
          secretary_member_id: actor.memberId,
          status: "secretary_verified",
          verified_at: expect.any(String)
        });
        const scalarBytes = (object: Record<string, unknown>, omitCanonicalBody = false) =>
          Object.entries(object).reduce(
            (total, [key, value]) =>
              total +
              ((omitCanonicalBody && key === "canonical_body") ||
              value === null ||
              typeof value === "object"
                ? 0
                : Buffer.byteLength(String(value), "utf8")),
            0
          );
        let actualScalars: Record<string, unknown> | undefined;
        const oracle = manager.openRequest(new AbortController().signal);
        try {
          const actual = await oracle.produce(() =>
            withRequestTransaction(
              pool,
              actor.context,
              async (client) => {
                const observed = {
                  query: async (sql: string, values?: unknown[]) => {
                    const selected = await client.query(sql, values);
                    if (sql === TRANSCRIPT_PREFLIGHT_SQL) {
                      expect(selected.rows).toHaveLength(1);
                      actualScalars = selected.rows[0] as Record<string, unknown>;
                    }
                    return selected;
                  }
                } as unknown as PoolClient;
                return loadAdmittedTranscriptProjection(observed, transcriptId, versionId);
              },
              { assumeRole: "boardagent_server" }
            )
          );
          expect(actual).not.toBeNull();
          expect(actual?.canonical_bytes.toString("utf8")).toBe(transcript["canonical_body"]);
          // Enumerate the actual public flat values independently of the SQL
          // expressions and bound formula; canonical_body is excluded from root_utf8; its separate length is N.
          expect(actualScalars).toMatchObject({
            canonical_length: actual!.canonical_bytes.length,
            root_utf8: String(scalarBytes(transcript, true)),
            turn_count: String(texts.length),
            turn_utf8: String(
              (transcript["turns"] as Array<Record<string, unknown>>).reduce(
                (sum, turn) => sum + scalarBytes(turn),
                0
              )
            ),
            challenge_count: String(challenges.length),
            challenge_utf8: String(challenges.reduce((sum, item) => sum + scalarBytes(item), 0)),
            verification_count: "1",
            verification_utf8: String(scalarBytes(verification))
          });
        } finally {
          oracle.nativeTerminal();
          oracle.collectorSettled();
        }
        expect(manager.accounting.usedUnits).toBeGreaterThan(0);
        const prepared = await pool.query<{ body: unknown }>(
          "select convert_from(canonical_payload,'UTF8')::jsonb as body from audit_events where event_type='resource_fetch'"
        );
        expect(prepared.rows).toHaveLength(1);
        expect(prepared.rows[0]?.body).toMatchObject({
          entityType: "meeting_transcript_version",
          entityId: versionId,
          boardId: actor.boardId,
          details: {
            phase: "prepared",
            resourceUri: `board://${actor.boardId}/meetings/${meetingId}/transcripts/1`,
            representation: "application/json",
            sha256: sha256Hex(body),
            byteLength: Buffer.byteLength(body),
            version: "1"
          }
        });
      } finally {
        // Direct repository fixture: preparation only, no native delivery claim.
        admitted.nativeTerminal();
        admitted.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);

      const boundary = manager.tryReserve(
        responseAllocationPlan({
          kind: "transcript_tool",
          representation: "tool",
          sourceId: versionId,
          sourceVersion: "boundary-fixture",
          sha256: sha256Hex(body),
          canonicalBytes: 1_048_576,
          transcriptProjection: {
            rootUtf8Bytes: "512",
            turnCount: "1",
            turnUtf8Bytes: "256",
            challengeCount: "16",
            challengeUtf8Bytes: "39142525",
            verificationCount: "0",
            verificationUtf8Bytes: "0"
          }
        })
      );
      const smallPlan = responseAllocationPlan({
        kind: "document",
        representation: "tool",
        sourceId: versionId,
        sourceVersion: "small-fixture",
        sha256: sha256Hex(body),
        canonicalBytes: 4096
      });
      const heldSmall = Array.from({ length: 128 }, () => manager.tryReserve(smallPlan));
      const refused = manager.openRequest(new AbortController().signal);
      let refusedMetadata = 0;
      let refusedContent = 0;
      try {
        await expect(
          refused.produce(() =>
            withRequestTransaction(
              pool,
              actor.context,
              async (client) => {
                const monitored = {
                  query: async (sql: string, values?: unknown[]) => {
                    if (sql === TRANSCRIPT_PREFLIGHT_SQL) refusedMetadata += 1;
                    if (sql === TRANSCRIPT_CONTENT_SQL) {
                      refusedContent += 1;
                      throw new Error("content ran before capacity refusal");
                    }
                    return client.query(sql, values);
                  }
                } as unknown as PoolClient;
                return loadAdmittedTranscriptProjection(monitored, transcriptId, versionId);
              },
              { assumeRole: "boardagent_server" }
            )
          )
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(refusedMetadata).toBe(1);
        expect(refusedContent).toBe(0);
      } finally {
        refused.nativeTerminal();
        refused.collectorSettled();
        for (const lease of heldSmall) lease.release();
        boundary.release();
      }

      // Both content-only failure functions execute under the actual request role
      // in the positive controls. A false CASE must skip each separate subquery.
      await pool.query(`create function public.transcript_probe_text_fault() returns text language plpgsql as $$ begin
        raise exception 'transcript-content-text-evaluated'; end $$`);
      await pool.query(`create function public.transcript_probe_bytea_fault() returns bytea language plpgsql as $$ begin
        raise exception 'transcript-content-bytea-evaluated'; end $$`);
      const textFault = TRANSCRIPT_CONTENT_SQL.replace(
        "convert_from(version_row.canonical_bytes,'UTF8')",
        "public.transcript_probe_text_fault()"
      );
      const byteaFault = TRANSCRIPT_CONTENT_SQL.replace(
        "select version_row.canonical_bytes",
        "select public.transcript_probe_bytea_fault()"
      );
      const bothFaults = textFault.replace(
        "select version_row.canonical_bytes",
        "select public.transcript_probe_bytea_fault()"
      );
      expect(textFault).not.toBe(TRANSCRIPT_CONTENT_SQL);
      expect(byteaFault).not.toBe(TRANSCRIPT_CONTENT_SQL);
      for (const [faultSql, message] of [
        [textFault, "transcript-content-text-evaluated"],
        [byteaFault, "transcript-content-bytea-evaluated"]
      ] as const) {
        const control = manager.openRequest(new AbortController().signal);
        try {
          await expect(
            control.produce(() =>
              withRequestTransaction(
                pool,
                actor.context,
                async (client) => {
                  const faulted = {
                    query: (sql: string, values?: unknown[]) =>
                      client.query(sql === TRANSCRIPT_CONTENT_SQL ? faultSql : sql, values)
                  } as unknown as PoolClient;
                  return loadAdmittedTranscriptProjection(faulted, transcriptId, versionId);
                },
                { assumeRole: "boardagent_server" }
              )
            )
          ).rejects.toThrow(message);
        } finally {
          control.nativeTerminal();
          control.collectorSettled();
        }
      }

      let preflightCount = 0;
      let guardedCount = 0;
      const growing = manager.openRequest(new AbortController().signal);
      try {
        await expect(
          growing.produce(() =>
            withRequestTransaction(
              pool,
              actor.context,
              async (client) => {
                const gated = {
                  query: async (sql: string, values?: unknown[]) => {
                    if (sql === TRANSCRIPT_PREFLIGHT_SQL) {
                      const before = await client.query(sql, values);
                      preflightCount += 1;
                      expect(before.rows).toHaveLength(1);
                      expect(before.rows[0]?.challenge_count).toBe("1");
                      const growth = await surface.executeDirect(
                        readCaller,
                        "challenge_transcript_turn",
                        {
                          schema_version: TOOL_INPUT_SCHEMA_VERSION,
                          transcript_version_id: versionId,
                          turn_id: turnIds[1]!,
                          comment: "g".repeat(65_536),
                          idempotency_key: "transcript-composite-growth-0001"
                        }
                      );
                      expect(growth.status).toBe("accepted");
                      expect(growth.reference).not.toBeNull();
                      return before;
                    }
                    if (sql === TRANSCRIPT_CONTENT_SQL) {
                      guardedCount += 1;
                      const fresh = await client.query(bothFaults, values);
                      expect(fresh.rows).toHaveLength(1);
                      expect(fresh.rows[0]).toMatchObject({
                        challenge_count: "2",
                        fits: false,
                        view: null,
                        canonical_bytes: null
                      });
                      return fresh;
                    }
                    return client.query(sql, values);
                  }
                } as unknown as PoolClient;
                return loadAdmittedTranscriptProjection(gated, transcriptId, versionId);
              },
              { assumeRole: "boardagent_server", isolation: "read committed" }
            )
          )
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(preflightCount).toBe(1);
        expect(guardedCount).toBe(1);
        expect(manager.accounting.usedUnits).toBeGreaterThan(0);
        growing.nativeTerminal();
        expect(manager.accounting.usedUnits).toBeGreaterThan(0);
      } finally {
        growing.nativeTerminal();
        growing.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
      let revocationPreflight = 0;
      let revokedContent = 0;
      const revoked = manager.openRequest(new AbortController().signal);
      try {
        await expect(
          revoked.produce(() =>
            withRequestTransaction(
              pool,
              actor.context,
              async (client) => {
                const gated = {
                  query: async (sql: string, values?: unknown[]) => {
                    const rows = await client.query(sql, values);
                    if (sql === TRANSCRIPT_PREFLIGHT_SQL) {
                      revocationPreflight += 1;
                      expect(rows.rows).toHaveLength(1);
                      const effect = await pool.query<{ jti: string }>(
                        "update access_token_records set revoked_at=transaction_timestamp() where jti=$1 and revoked_at is null returning jti",
                        [actor.tokenJti]
                      );
                      expect(effect.rowCount).toBe(1);
                      expect(effect.rows[0]?.jti).toBe(actor.tokenJti);
                    }
                    if (sql === TRANSCRIPT_CONTENT_SQL) {
                      revokedContent += 1;
                      expect(rows.rows).toHaveLength(0);
                    }
                    return rows;
                  }
                } as unknown as PoolClient;
                return loadAdmittedTranscriptProjection(gated, transcriptId, versionId);
              },
              { assumeRole: "boardagent_server", isolation: "read committed" }
            )
          )
        ).resolves.toBeNull();
        expect(revocationPreflight).toBe(1);
        expect(revokedContent).toBe(1);
        expect(manager.accounting.usedUnits).toBeGreaterThan(0);
        revoked.nativeTerminal();
        expect(manager.accounting.usedUnits).toBeGreaterThan(0);
      } finally {
        revoked.nativeTerminal();
        revoked.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
      expect(
        await pool.query("select id from audit_events where event_type='resource_fetch'")
      ).toMatchObject({ rowCount: 1 });
    });
  });
  it("admits the exact transcript alias and rechecks actual RLS after committed token revocation", async () => {
    await withDatabase(async (pool) => {
      const scopes = ["secretariat:admin", "meeting:act", "governance:read"];
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes,
        isSecretary: true
      });
      const caller = principal(actor, ["member", "secretariat"], scopes);
      let nextId = 166_000;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const meetingId = testId(166_800);
      const transcriptId = testId(166_801);
      await confirmSurfaceAction(
        surface,
        caller,
        "create_meeting",
        meetingInput(actor.boardId, meetingId, [actor.memberId])
      );
      const body = canonicalJson({
        schema_version: "boardagent.transcript-turns.v1",
        values: {
          turns: [
            {
              canonical_text: 'Exact admitted "record" Δ',
              ends_at_ms: 2000,
              starts_at_ms: 1000,
              speaker_label: "Secretary",
              speaker_member_id: actor.memberId,
              turn_id: testId(166_802)
            }
          ]
        }
      });
      const created = await surface.executeDirect(caller, "create_meeting_transcript_version", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        transcript_id: transcriptId,
        media_type: "application/json",
        canonical_body: body,
        coverage_statement: "Complete synthetic transcript for alias admission.",
        supersedes_version_id: null,
        idempotency_key: "transcript-resource-admission-0001"
      });
      if (!created.reference) throw new Error("synthetic transcript version missing");
      const sessionId = testId(166_803);
      await pool.query(
        `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
         values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, testHash(166), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);
      const reader = new PgSurfaceReadRepository(pool, {
        cursorKey: Buffer.alloc(32, 0x58),
        transaction: { assumeRole: "boardagent_server" }
      });
      const readCaller = { ...caller, protocolClientId: "authorized-test-client" };
      const uri = new URL(`board://${actor.boardId}/meetings/${meetingId}/transcripts/1`);
      const manager = new ResponseAllocationManager();
      const admitted = manager.openRequest(new AbortController().signal);
      try {
        await expect(
          admitted.produce(() => reader.readResource(readCaller, uri))
        ).resolves.toMatchObject({
          uri: uri.href,
          media_type: "application/json",
          text: body
        });
        expect(manager.accounting.usedUnits).toBe(1);
        const prepared = await pool.query<{ body: unknown }>(
          "select convert_from(canonical_payload,'UTF8')::jsonb as body from audit_events where event_type='resource_fetch'"
        );
        expect(prepared.rows).toHaveLength(1);
        expect(prepared.rows[0]?.body).toMatchObject({
          entityType: "meeting_transcript_version",
          entityId: created.reference,
          boardId: actor.boardId,
          details: {
            phase: "prepared",
            resourceUri: uri.href,
            representation: "application/json",
            sha256: sha256Hex(body),
            byteLength: Buffer.byteLength(body),
            version: "1"
          }
        });
      } finally {
        // This direct repository fixture models settlement; it does not send over
        // HTTP or record a completed delivery outcome for this prepared response.
        admitted.nativeTerminal();
        admitted.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);

      const seam = reader as unknown as {
        loadBoardResource(
          client: PoolClient,
          principal: SurfacePrincipal,
          uri: URL
        ): Promise<unknown>;
      };
      let metadataSelections = 0;
      let contentSelections = 0;
      const losing = manager.openRequest(new AbortController().signal);
      try {
        await expect(
          losing.produce(() =>
            withRequestTransaction(
              pool,
              actor.context,
              async (client) => {
                const gated = {
                  query: async (sql: string, values?: unknown[]) => {
                    // All SQL executes on the actual role/context connection. The
                    // only interception is the committed row effect between queries.
                    const result = await client.query(sql, values);
                    if (sql.includes("octet_length(version_row.canonical_bytes) as byte_length")) {
                      metadataSelections += 1;
                      expect(result.rows).toHaveLength(1);
                      expect(result.rows[0]).toMatchObject({
                        id: created.reference,
                        version: 1,
                        media_type: "application/json",
                        byte_length: Buffer.byteLength(body),
                        sha256: sha256Hex(body)
                      });
                      const revoked = await pool.query<{ jti: string }>(
                        "update access_token_records set revoked_at=transaction_timestamp() where jti=$1 and revoked_at is null returning jti",
                        [actor.tokenJti]
                      );
                      expect(revoked.rowCount).toBe(1);
                      expect(revoked.rows[0]?.jti).toBe(actor.tokenJti);
                    }
                    if (/^\s*select version_row\.canonical_bytes\s/u.test(sql)) {
                      contentSelections += 1;
                      expect(result.rows).toHaveLength(0);
                    }
                    return result;
                  }
                } as unknown as PoolClient;
                return seam.loadBoardResource(gated, readCaller, uri);
              },
              { assumeRole: "boardagent_server", isolation: "read committed" }
            )
          )
        ).resolves.toBeNull();
        expect(metadataSelections).toBe(1);
        expect(contentSelections).toBe(1);
        expect(manager.accounting.usedUnits).toBe(1);
        losing.nativeTerminal();
        expect(manager.accounting.usedUnits).toBe(1);
      } finally {
        losing.nativeTerminal();
        losing.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
      const revoked = manager.openRequest(new AbortController().signal);
      try {
        await expect(revoked.produce(() => reader.readResource(readCaller, uri))).rejects.toThrow();
        expect(manager.accounting.usedUnits).toBe(0);
      } finally {
        revoked.nativeTerminal();
        revoked.collectorSettled();
      }
      expect(
        await pool.query("select id from audit_events where event_type='resource_fetch'")
      ).toMatchObject({ rowCount: 1 });
    });
  });

  it("prepares exact transcript read evidence and refuses an unauditable transcript", async () => {
    await withDatabase(async (pool) => {
      const scopes = ["secretariat:admin", "meeting:act", "governance:read"];
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes,
        isSecretary: true
      });
      const caller = principal(actor, ["member", "secretariat"], scopes);
      let nextId = 164_000;
      const surface = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const meetingId = testId(164_800);
      const transcriptId = testId(164_801);
      await confirmSurfaceAction(
        surface,
        caller,
        "create_meeting",
        meetingInput(actor.boardId, meetingId, [actor.memberId])
      );
      const body = canonicalJson({
        schema_version: "boardagent.transcript-turns.v1",
        values: {
          turns: [
            {
              canonical_text: 'Exact "record" Δ',
              ends_at_ms: 2000,
              starts_at_ms: 1000,
              speaker_label: "Secretary",
              speaker_member_id: actor.memberId,
              turn_id: testId(164_802)
            }
          ]
        }
      });
      const created = await surface.executeDirect(caller, "create_meeting_transcript_version", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        transcript_id: transcriptId,
        media_type: "application/json",
        canonical_body: body,
        coverage_statement: "Complete synthetic transcript.",
        supersedes_version_id: null,
        idempotency_key: "transcript-read-evidence-0001"
      });
      if (!created.reference) throw new Error("synthetic transcript version missing");
      const sessionId = testId(164_803);
      await pool.query(
        `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
         values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, testHash(164), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);
      const reader = new PgSurfaceReadRepository(pool, {
        cursorKey: Buffer.alloc(32, 0x58),
        transaction: { assumeRole: "boardagent_server" }
      });
      const readCaller = { ...caller, protocolClientId: "authorized-test-client" };
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_id: transcriptId,
        version_id: created.reference
      };
      const read = await withTranscriptReadOwner(() =>
        reader.executeRead(readCaller, "get_meeting_transcript", input)
      );
      expect(read.data).toMatchObject({
        transcript: { canonical_body: body, sha256: sha256Hex(body) }
      });
      const events = await pool.query<{ body: unknown }>(
        "select convert_from(canonical_payload,'UTF8')::jsonb as body from audit_events where event_type='resource_fetch'"
      );
      expect(events.rows).toHaveLength(1);
      expect(events.rows[0]?.body).toMatchObject({
        actorMemberId: actor.memberId,
        actorClientId: actor.clientId,
        tokenJti: actor.tokenJti,
        entityType: "meeting_transcript_version",
        entityId: created.reference,
        boardId: actor.boardId,
        details: {
          phase: "prepared",
          resourceUri: `board://${actor.boardId}/meetings/${meetingId}/transcripts/1`,
          representation: "application/json",
          sha256: sha256Hex(body),
          byteLength: Buffer.byteLength(body),
          requestOrigin: caller.serviceOrigin
        }
      });
      await pool.query(`create function reject_transcript_fetch_audit() returns trigger language plpgsql as $$ begin
        if new.event_type='resource_fetch' then raise exception 'synthetic transcript audit unavailable'; end if;
        return new; end $$; create trigger reject_transcript_fetch_audit before insert on audit_events for each row execute function reject_transcript_fetch_audit()`);
      await expect(
        withTranscriptReadOwner(() =>
          reader.executeRead(readCaller, "get_meeting_transcript", input)
        )
      ).rejects.toThrow("synthetic transcript audit unavailable");
      expect(
        await pool.query("select id from audit_events where event_type='resource_fetch'")
      ).toMatchObject({ rowCount: 1 });
    });
  });

  it("creates, verifies, challenges, corrects and links immutable turns while invalidating stale minutes", async () => {
    await withDatabase(async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: [
          "secretariat:admin",
          "secretariat:message",
          "governance:read",
          "meeting:act",
          "minutes:act",
          "management:question"
        ],
        isSecretary: true
      });
      const member = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 160_100,
        seatRole: "voting_member",
        scopes: [
          "governance:read",
          "meeting:act",
          "minutes:act",
          "secretariat:message",
          "management:question"
        ]
      });
      const observer = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 160_200,
        seatRole: "observer",
        scopes: ["governance:read", "meeting:act", "secretariat:message"]
      });
      const management = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 160_300,
        seatRole: "management",
        scopes: ["governance:read", "management:question"]
      });
      const adminOnly = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 160_400,
        seatRole: "voting_member",
        scopes: ["secretariat:admin", "governance:read", "meeting:act"]
      });
      await pool.query(
        `insert into organization_role_assignments(
           id,organization_id,member_id,role,change_reason
         ) values ($1,$2,$3,'admin','Exact transcript secretary boundary test.')`,
        [testId(160_450), secretary.organizationId, adminOnly.memberId]
      );

      let nextId = 160_500;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const secretaryPrincipal = principal(
        secretary,
        ["member", "secretariat"],
        [
          "secretariat:admin",
          "secretariat:message",
          "governance:read",
          "meeting:act",
          "minutes:act",
          "management:question"
        ]
      );
      const memberPrincipal = principal(
        member,
        ["member"],
        [
          "governance:read",
          "meeting:act",
          "minutes:act",
          "secretariat:message",
          "management:question"
        ]
      );
      const observerPrincipal = principal(
        observer,
        ["observer"],
        ["governance:read", "meeting:act", "secretariat:message"]
      );
      const adminOnlyPrincipal = principal(
        adminOnly,
        ["admin", "member"],
        ["secretariat:admin", "governance:read", "meeting:act"]
      );

      const meetingId = testId(161_000);
      await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "create_meeting",
        meetingInput(secretary.boardId, meetingId, [member.memberId, observer.memberId])
      );

      const transcriptId = testId(161_010);
      const firstTurnId = testId(161_011);
      const secondTurnId = testId(161_012);
      const firstBody = canonicalJson({
        schema_version: "boardagent.transcript-turns.v1",
        values: {
          turns: [
            {
              canonical_text: "What is the groundwater safeguard?",
              ends_at_ms: 4500,
              speaker_label: "Director A",
              speaker_member_id: member.memberId,
              starts_at_ms: 1200,
              turn_id: firstTurnId
            },
            {
              canonical_text: "Management will install nested monitoring wells.",
              ends_at_ms: 9100,
              speaker_label: "Exploration manager",
              speaker_member_id: management.memberId,
              starts_at_ms: 5000,
              turn_id: secondTurnId
            }
          ]
        }
      });
      const firstInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: meetingId,
        transcript_id: transcriptId,
        media_type: "application/json",
        canonical_body: firstBody,
        coverage_statement: "Covers the complete called meeting from opening to adjournment.",
        supersedes_version_id: null,
        idempotency_key: "surface-transcript-version-0001"
      } as const;

      await expect(
        service.executeDirect(adminOnlyPrincipal, "create_meeting_transcript_version", {
          ...firstInput,
          transcript_id: testId(161_013),
          idempotency_key: "surface-transcript-admin-denied-0001"
        })
      ).rejects.toThrow("transcript annex contribution is unavailable");
      const first = await service.executeDirect(
        secretaryPrincipal,
        "create_meeting_transcript_version",
        firstInput
      );
      const replay = await service.executeDirect(
        secretaryPrincipal,
        "create_meeting_transcript_version",
        firstInput
      );
      expect(first).toMatchObject({
        status: "accepted",
        data: {
          transcript_id: transcriptId,
          version: 1,
          canonical_sha256: sha256Hex(firstBody),
          verification_state: "agent_prepared_unverified",
          turn_ids: [firstTurnId, secondTurnId],
          replayed: false
        }
      });
      expect(replay).toMatchObject({
        status: "already_applied",
        reference: first.reference,
        data: { replayed: true }
      });
      if (first.reference === null) throw new Error("first transcript version is missing");

      await expect(
        service.executeDirect(observerPrincipal, "challenge_transcript_turn", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          transcript_version_id: first.reference,
          turn_id: firstTurnId,
          comment: "Observer challenge must not be accepted.",
          idempotency_key: "surface-transcript-observer-challenge-0001"
        })
      ).rejects.toThrow("transcript turn challenge is unavailable");
      const challengeInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_version_id: first.reference,
        turn_id: firstTurnId,
        comment: "The question referred to both groundwater and surface-water monitoring.",
        idempotency_key: "surface-transcript-member-challenge-0001"
      } as const;
      const challenge = await service.executeDirect(
        memberPrincipal,
        "challenge_transcript_turn",
        challengeInput
      );
      const challengeReplay = await service.executeDirect(
        memberPrincipal,
        "challenge_transcript_turn",
        challengeInput
      );
      expect(challenge).toMatchObject({ status: "accepted", data: { state: "pending" } });
      expect(challengeReplay).toMatchObject({
        status: "already_applied",
        reference: challenge.reference,
        data: { replayed: true }
      });
      if (challenge.reference === null) throw new Error("transcript challenge is missing");

      const verifiedFirst = await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "verify_meeting_transcript",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          transcript_id: transcriptId,
          version_id: first.reference,
          sha256: sha256Hex(firstBody),
          verification_statement: "secretary_verified_annex_hash",
          idempotency_key: "surface-transcript-verify-0001"
        }
      );
      expect(verifiedFirst).toMatchObject({
        data: {
          transcript_id: transcriptId,
          version_id: first.reference,
          state: "secretary_verified"
        }
      });

      const minutesId = testId(161_020);
      const minutesText = "# Minutes\n\nThe committee reviewed groundwater safeguards.\n";
      const minutes = await service.executeDirect(secretaryPrincipal, "create_minutes_version", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutesId,
        meeting_id: meetingId,
        canonical_text: minutesText,
        transcript_version_id: first.reference,
        expected_current_version_id: null,
        idempotency_key: "surface-transcript-minutes-0001"
      });
      if (minutes.reference === null) throw new Error("minutes version is missing");
      await confirmSurfaceAction(service, secretaryPrincipal, "publish_minutes", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        minutes_id: minutesId,
        version_id: minutes.reference,
        minutes_sha256: sha256Hex(minutesText),
        signer_member_ids: [member.memberId],
        idempotency_key: "surface-transcript-minutes-publish-0001"
      });
      await confirmSurfaceAction(service, secretaryPrincipal, "declare_no_minutes_action_items", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        manifest: {
          schemaVersion: "boardagent.minutes-action-manifest.v1",
          minutesId,
          minutesVersion: 1,
          minutesSha256: sha256Hex(minutesText),
          declaration: "no_action_items"
        },
        idempotency_key: "surface-transcript-minutes-actions-0001"
      });
      const signaturePackage = await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "prepare_minutes_for_signature",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutesId,
          expected_version_id: minutes.reference,
          signer_member_ids: [member.memberId],
          idempotency_key: "surface-transcript-minutes-package-0001"
        }
      );
      if (signaturePackage.reference === null) throw new Error("signature package is missing");
      const pendingSignature = await prepareAndPersist(
        service,
        memberPrincipal,
        "stage_minutes_signature",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          minutes_id: minutesId,
          package_id: signaturePackage.reference,
          reservation: null,
          idempotency_key: "surface-transcript-pending-signature-0001"
        }
      );

      const correctedBody = canonicalJson({
        schema_version: "boardagent.transcript-turns.v1",
        values: {
          turns: [
            {
              canonical_text: "What are the groundwater and surface-water monitoring safeguards?",
              ends_at_ms: 4500,
              speaker_label: "Director A",
              speaker_member_id: member.memberId,
              starts_at_ms: 1200,
              turn_id: testId(161_014)
            },
            {
              canonical_text: "Management will install nested monitoring wells.",
              ends_at_ms: 9100,
              speaker_label: "Exploration manager",
              speaker_member_id: management.memberId,
              starts_at_ms: 5000,
              turn_id: testId(161_015)
            }
          ]
        }
      });
      const corrected = await service.executeDirect(
        secretaryPrincipal,
        "create_meeting_transcript_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          meeting_id: meetingId,
          transcript_id: transcriptId,
          media_type: "application/json",
          canonical_body: correctedBody,
          coverage_statement:
            "Corrected typed turns; BoardAgent stores no recording and performed no transcription.",
          supersedes_version_id: first.reference,
          idempotency_key: "surface-transcript-version-0002"
        }
      );
      expect(corrected).toMatchObject({
        status: "accepted",
        data: {
          transcript_id: transcriptId,
          version: 2,
          canonical_sha256: sha256Hex(correctedBody),
          minutes_refresh: { minutes_id: minutesId, version: 2, state: "published_review" }
        }
      });
      if (corrected.reference === null) throw new Error("corrected transcript version is missing");

      const invalidation = await pool.query<{
        minutes_state: string;
        minutes_versions: string;
        transcript_version_id: string;
        package_state: string;
        signature_stage_state: string;
      }>(
        `select minutes.state as minutes_state,
                (select count(*)::text from minutes_versions where minutes_id=minutes.id)
                  as minutes_versions,
                version.transcript_version_id,
                package.state as package_state,
                stage.state as signature_stage_state
           from minutes
           join minutes_versions as version on version.id=minutes.current_version_id
           join minutes_signature_packages as package on package.id=$2
           join action_stages as stage on stage.id=$3
          where minutes.id=$1`,
        [minutesId, signaturePackage.reference, pendingSignature.prepared.stage_id]
      );
      expect(invalidation.rows[0]).toEqual({
        minutes_state: "published_review",
        minutes_versions: "2",
        transcript_version_id: corrected.reference,
        package_state: "superseded",
        signature_stage_state: "replaced"
      });

      const questionId = testId(161_030);
      const preparedQuestion = prepareManagementQuestion({
        questionId,
        boardId: secretary.boardId,
        question: "What monitoring evidence will management provide?",
        assignedOwnerIds: [management.memberId],
        dueAt: "2030-01-01T12:00:00Z",
        citations: [],
        visibility: [
          { granteeType: "member", memberId: secretary.memberId },
          { granteeType: "member", memberId: member.memberId },
          { granteeType: "member", memberId: management.memberId }
        ]
      });
      await withRequestTransaction(
        pool,
        member.context,
        (client) =>
          askManagementQuestionInTransaction(client, {
            organizationId: member.organizationId,
            prepared: preparedQuestion,
            initialTurnId: testId(161_031),
            auditEventId: testId(161_032),
            idempotencyRecordId: testId(161_033),
            idempotencyKey: "surface-transcript-question-0001",
            visibilityRecordIds: [testId(161_034), testId(161_035), testId(161_036)],
            ownerDeliveries: [
              {
                ownerMemberId: management.memberId,
                noticeId: testId(161_037),
                feedId: testId(161_038)
              }
            ]
          }),
        { assumeRole: "boardagent_server" }
      );

      const correctedTurnIds = [testId(161_014), testId(161_015)];
      const linked = await confirmSurfaceAction(service, secretaryPrincipal, "link_meeting_qna", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_version_id: corrected.reference,
        turn_ids: correctedTurnIds,
        question_id: questionId,
        idempotency_key: "surface-transcript-link-qna-0001"
      });
      expect(linked).toMatchObject({
        data: {
          transcript_version_id: corrected.reference,
          turn_ids: correctedTurnIds,
          question_id: questionId,
          management_action_preserved: true
        }
      });

      const resolved = await confirmSurfaceAction(
        service,
        secretaryPrincipal,
        "resolve_transcript_challenge",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          challenge_id: challenge.reference,
          disposition: "accept",
          reason: "The successor annex preserves the member's exact correction.",
          corrected_version_id: corrected.reference,
          idempotency_key: "surface-transcript-resolve-0001"
        }
      );
      expect(resolved).toMatchObject({
        data: {
          challenge_id: challenge.reference,
          state: "accepted",
          corrected_version_id: corrected.reference
        }
      });

      await confirmSurfaceAction(service, secretaryPrincipal, "verify_meeting_transcript", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_id: transcriptId,
        version_id: corrected.reference,
        sha256: sha256Hex(correctedBody),
        verification_statement: "secretary_verified_annex_hash",
        idempotency_key: "surface-transcript-verify-0002"
      });

      const evidence = await pool.query<{
        transcript_versions: string;
        turns: string;
        verifications: string;
        challenges: string;
        dispositions: string;
        links: string;
        pending_management_actions: string;
        transcript_events: string;
      }>(
        `select
           (select count(*)::text from meeting_transcript_versions where transcript_id=$1)
             as transcript_versions,
           (select count(*)::text from transcript_turns as turn
             join meeting_transcript_versions as version
               on version.id=turn.transcript_version_id
            where version.transcript_id=$1) as turns,
           (select count(*)::text from transcript_verifications as verification
             join meeting_transcript_versions as version
               on version.id=verification.transcript_version_id
            where version.transcript_id=$1) as verifications,
           (select count(*)::text from transcript_challenges where transcript_version_id=$2)
             as challenges,
           (select count(*)::text from transcript_challenge_dispositions) as dispositions,
           (select count(*)::text from transcript_question_links where transcript_version_id=$3)
             as links,
           (select count(*)::text from pending_action_feed
             where object_type='question' and object_id=$4 and state='pending')
             as pending_management_actions,
           (select count(*)::text from audit_events
             where event_type in (
               'transcript_version_created','transcript_secretary_verified',
               'transcript_turn_challenged','transcript_challenge_resolved',
               'transcript_qna_linked'
             )) as transcript_events`,
        [transcriptId, first.reference, corrected.reference, questionId]
      );
      expect(evidence.rows[0]).toEqual({
        transcript_versions: "2",
        turns: "4",
        verifications: "2",
        challenges: "1",
        dispositions: "1",
        links: "1",
        pending_management_actions: "1",
        transcript_events: "7"
      });
      const oldTurn = await pool.query<{ canonical_text: string }>(
        "select canonical_text from transcript_turns where id=$1",
        [firstTurnId]
      );
      expect(oldTurn.rows[0]?.canonical_text).toBe("What is the groundwater safeguard?");
    });
  });
});
