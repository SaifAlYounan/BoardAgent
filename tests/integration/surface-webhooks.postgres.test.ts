import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  Aes256GcmWebhookSecurity,
  PgBoardAgentSurfaceService,
  type BoardAgentSurfaceService,
  type SurfacePrincipal,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { migrate, withRequestTransaction } from "../../lib/db/src/index.js";
import {
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
  const database = `boardagent_surface_webhooks_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "surface-webhooks-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function principal(actor: AuthorizedActorFixture): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: "https://observer-agent.test/client.json",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes: ["notifications:manage"],
    roles: ["observer"],
    boardIds: [actor.boardId]
  };
}

const unavailableReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by webhook lifecycle test");
  },
  readResource: async () => {
    throw new Error("resource read not used by webhook lifecycle test");
  }
};

let confirmationSequence = 0;
async function confirm(
  service: BoardAgentSurfaceService,
  actor: SurfacePrincipal,
  tool: string,
  input: JsonValue
): Promise<{ readonly result: SurfaceToolResult; readonly stageId: string }> {
  confirmationSequence += 1;
  const label = `surface-webhook-${tool}-${String(confirmationSequence).padStart(4, "0")}`;
  const prepared = await service.prepareHumanAction(actor, tool, input);
  expect(prepared.action_code).toBe(tool);
  const clientCapabilities = { elicitation: { form: {} } } as const;
  const requestState = `${label}-request-state-is-bound-to-the-client`;
  await service.persistHumanStage({
    principal: actor,
    tool,
    input,
    prepared,
    client_capabilities: clientCapabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm exact ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${label}-prepare`)
  });
  const resolved = await service.resolveHumanAction({
    principal: actor,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: clientCapabilities,
    request_state: requestState,
    retry_request_id: Buffer.from(`${label}-retry`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolved.confirmed) throw new Error(`${tool} failed: ${resolved.reason}`);
  return { result: resolved.result, stageId: prepared.stage_id };
}

describe("encrypted own-member webhook surface", () => {
  it("configures, rotates, queues a contentless test, refuses replayed secret, and disables", async () => {
    await withDatabase(async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "observer",
        scopes: ["notifications:manage"]
      });
      const sessionId = testId(310_001);
      const dataKeyId = testId(310_002);
      await pool.query(
        `insert into auth_sessions(
           id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
           expires_at,last_authenticated_at
         ) values ($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
           transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
        [sessionId, actor.organizationId, testHash(310_001), actor.memberId, actor.clientId]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        sessionId,
        actor.accessTokenRecordId
      ]);
      await pool.query(
        `insert into crypto_key_registry(
           id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
         ) values ($1,$2,'webhook-data-kek','data_kek','A256GCM',null,
                   'test://webhook-data-kek',transaction_timestamp()-interval '1 minute')`,
        [dataKeyId, actor.organizationId]
      );
      let securityByte = 61;
      let dnsUnavailable = false;
      const webhookSecurity = new Aes256GcmWebhookSecurity({
        activeKeyId: dataKeyId,
        keys: new Map([[dataKeyId, Buffer.alloc(32, 60)]]),
        randomBytes: (length) => Buffer.alloc(length, securityByte++),
        resolve: async () => {
          if (dnsUnavailable) throw new Error("synthetic DNS unavailable after presentation");
          return [{ address: "93.184.216.34", family: 4 }];
        }
      });
      let nextId = 315_000;
      let entropyByte = 80;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++),
        entropy: (length) => Buffer.alloc(length, entropyByte++),
        webhookSecurity
      });
      const caller = principal(actor);
      const webhookId = testId(310_010);
      const endpoint = "https://hooks.example.com/boardagent";
      const configured = await confirm(service, caller, "configure_webhook", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "configure-observer-webhook-0001",
        webhook_id: webhookId,
        endpoint,
        event_classes: ["security", "notice", "pending_action"],
        recent_auth_proof: Buffer.alloc(32, 1).toString("base64url")
      });
      const configuredData = configured.result.data as Readonly<Record<string, JsonValue>>;
      const firstSecret = configuredData["secret"];
      expect(firstSecret).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(configuredData["secret_once"]).toBe(true);

      const stored = await pool.query<{
        endpoint_ciphertext: Buffer;
        secret_ciphertext: Buffer;
        secret_sha256: Buffer;
        event_classes: string[];
        generation: string;
      }>(
        `select endpoint_ciphertext,secret_ciphertext,secret_sha256,event_classes,
                generation::text
           from member_webhooks where id=$1`,
        [webhookId]
      );
      expect(stored.rows[0]?.endpoint_ciphertext.includes(Buffer.from(endpoint))).toBe(false);
      expect(stored.rows[0]?.secret_ciphertext.includes(Buffer.from(String(firstSecret)))).toBe(
        false
      );
      expect(stored.rows[0]?.event_classes).toEqual(["notice", "pending_action", "security"]);
      expect(stored.rows[0]?.generation).toBe("1");
      expect(stored.rows[0]?.secret_sha256.toString("hex")).toBe(
        sha256Hex(Buffer.from(String(firstSecret), "base64url"))
      );
      const leakedStage = await pool.query<{ leaked: boolean }>(
        `select convert_from(canonical_payload,'UTF8') like '%'||$1||'%' as leaked
           from action_stages where id=$2`,
        [endpoint, configured.stageId]
      );
      expect(leakedStage.rows[0]?.leaked).toBe(false);

      // Declining an already-presented action must remain possible if its DNS
      // destination subsequently disappears. These calls use the actual stage,
      // consent and audit repositories; no webhook is configured or delivered.
      for (const responseAction of ["decline", "cancel"] as const) {
        const abandonedId = testId(responseAction === "decline" ? 310_020 : 310_021);
        const label = `webhook-${responseAction}-after-dns-loss`;
        const abandonedInput = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: label,
          webhook_id: abandonedId,
          endpoint,
          event_classes: ["security"],
          recent_auth_proof: Buffer.alloc(32, 3).toString("base64url")
        };
        const prepared = await service.prepareHumanAction(
          caller,
          "configure_webhook",
          abandonedInput
        );
        const clientCapabilities = { elicitation: { form: {} } } as const;
        const requestState = `${label}-request-state-is-bound-to-the-client`;
        await service.persistHumanStage({
          principal: caller,
          tool: "configure_webhook",
          input: abandonedInput,
          prepared,
          client_capabilities: clientCapabilities,
          embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
          embedded_result: { message: "Confirm this exact synthetic endpoint" },
          request_state: requestState,
          prepared_request_id: Buffer.from(`${label}-prepare`)
        });
        dnsUnavailable = true;
        try {
          await expect(
            service.resolveHumanAction({
              principal: caller,
              tool: "configure_webhook",
              input: abandonedInput,
              stage_id: prepared.stage_id,
              client_capabilities: clientCapabilities,
              request_state: requestState,
              retry_request_id: Buffer.from(`${label}-retry`),
              response_action: responseAction,
              input_response: null
            })
          ).resolves.toEqual({ confirmed: false, reason: "declined" });
        } finally {
          dnsUnavailable = false;
        }
        expect(
          (await pool.query("select state from action_stages where id=$1", [prepared.stage_id]))
            .rows
        ).toEqual([{ state: responseAction === "cancel" ? "cancelled" : "rejected" }]);
        expect(
          (
            await pool.query("select count(*)::int as n from member_webhooks where id=$1", [
              abandonedId
            ])
          ).rows
        ).toEqual([{ n: 0 }]);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from audit_events where event_type='webhook_configured' and object_id=$1",
              [abandonedId]
            )
          ).rows
        ).toEqual([{ n: 0 }]);
      }

      const replay = await service.resolveHumanAction({
        principal: caller,
        tool: "configure_webhook",
        input: {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          idempotency_key: "configure-observer-webhook-0001",
          webhook_id: webhookId,
          endpoint,
          event_classes: ["security", "notice", "pending_action"],
          recent_auth_proof: Buffer.alloc(32, 1).toString("base64url")
        },
        stage_id: configured.stageId,
        client_capabilities: { elicitation: { form: {} } },
        request_state:
          "surface-webhook-configure_webhook-0001-request-state-is-bound-to-the-client",
        retry_request_id: Buffer.from("surface-webhook-configure-replay"),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: "AAAAAAAA" }
      });
      expect(replay).toEqual({ confirmed: false, reason: "stage_not_active" });

      const rotated = await confirm(service, caller, "rotate_webhook_secret", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "rotate-observer-webhook-0001",
        webhook_id: webhookId,
        recent_auth_proof: Buffer.alloc(32, 2).toString("base64url")
      });
      const secondSecret = (rotated.result.data as Readonly<Record<string, JsonValue>>)["secret"];
      expect(secondSecret).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(secondSecret).not.toBe(firstSecret);
      const rotatedRow = await pool.query<{ generation: string; secret_sha256: Buffer }>(
        "select generation::text,secret_sha256 from member_webhooks where id=$1",
        [webhookId]
      );
      expect(rotatedRow.rows[0]?.generation).toBe("2");
      expect(rotatedRow.rows[0]?.secret_sha256.toString("hex")).toBe(
        sha256Hex(Buffer.from(String(secondSecret), "base64url"))
      );

      const testInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "test-observer-webhook-0001",
        webhook_id: webhookId
      } as const;
      const tested = await service.executeDirect(caller, "test_webhook", testInput);
      expect(tested.data).toMatchObject({ state: "queued", contentless: true, replayed: false });
      const replayedTest = await service.executeDirect(caller, "test_webhook", testInput);
      expect(replayedTest).toMatchObject({
        status: "already_applied",
        reference: tested.reference,
        data: { replayed: true, contentless: true }
      });
      const notification = await pool.query<{
        count: string;
        notice_id: string | null;
        source_kind: string;
        wake_class: string;
      }>(
        `select count(*) over()::text as count,notice_id,source_kind,wake_class
           from notification_jobs where webhook_id=$1`,
        [webhookId]
      );
      expect(notification.rows[0]).toEqual({
        count: "1",
        notice_id: null,
        source_kind: "test",
        wake_class: "security"
      });

      const dispatch = await pool.query(
        `select id,board_id,subject_id,job_type,state from jobs
          where subject_id=$1 and job_type='webhook_delivery'`,
        [tested.reference]
      );
      expect(dispatch.rows).toEqual([
        {
          id: tested.reference,
          board_id: null,
          subject_id: tested.reference,
          job_type: "webhook_delivery",
          state: "queued"
        }
      ]);
      // Exercise the actual INSERT trigger using a rolled-back owner fixture, beyond
      // the request enqueue helper's own checks. Exact existing row bytes would pass
      // the typed binding; these cases must fail before the duplicate-ID constraint.
      for (const condition of ["outside_request", "non_security_webhook"] as const) {
        await expect(
          withRequestTransaction(pool, actor.context, async (client) => {
            if (condition === "outside_request") {
              await client.query("select set_config('boardagent.transaction_scope','worker',true)");
            } else {
              await client.query("alter table member_webhooks disable trigger user");
              await client.query(
                "update member_webhooks set event_classes=array['notice']::text[] where id=$1",
                [webhookId]
              );
            }
            await client.query(
              `insert into jobs(id,organization_id,board_id,job_type,schema_version,
              subject_type,subject_id,canonical_payload,payload_sha256,idempotency_key)
            select id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
              canonical_payload,payload_sha256,idempotency_key from jobs where id=$1`,
              [tested.reference]
            );
          })
        ).rejects.toMatchObject({
          code: "23514",
          message: "notification job does not bind a notification on the exact board"
        });
      }
      expect(
        (await pool.query("select event_classes from member_webhooks where id=$1", [webhookId]))
          .rows
      ).toEqual([{ event_classes: ["notice", "pending_action", "security"] }]);
      expect(
        (await pool.query("select count(*)::int as n from jobs where id=$1", [tested.reference]))
          .rows
      ).toEqual([{ n: 1 }]);
      const disabled = await confirm(service, caller, "disable_webhook", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "disable-observer-webhook-0001",
        webhook_id: webhookId,
        reason: "Replace this endpoint outside BoardAgent."
      });
      expect(disabled.result.data).toMatchObject({ state: "disabled", secret: null });
      await expect(
        service.executeDirect(caller, "test_webhook", {
          ...testInput,
          idempotency_key: "test-disabled-webhook-0002"
        })
      ).rejects.toThrow("active owned webhook is unavailable");

      const events = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where object_id=$1 and event_type like 'webhook_%' order by sequence`,
        [webhookId]
      );
      expect(events.rows.map(({ event_type }) => event_type)).toEqual([
        "webhook_configured",
        "webhook_secret_rotated",
        "webhook_tested",
        "webhook_disabled"
      ]);
    });
  });
});
