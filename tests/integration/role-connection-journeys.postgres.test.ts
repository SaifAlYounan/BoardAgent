import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { generateKeyPair, SignJWT } from "jose";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  PgTokenContextStore,
  createBoardAgentMcpHandler,
  createProtectedMcpHandler,
  createTokenVerifier,
  type ActiveTokenContext,
  type SurfaceToolResult
} from "../../artifacts/server/src/index.js";
import { fetchWithDirectRequestOwner } from "../helpers/direct-response-allocation.js";
import { TOOL_INPUT_SCHEMA_VERSION, type JsonValue } from "../../lib/contracts/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
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
const ISSUER = "https://boardagent.test";
const RESOURCE = `${ISSUER}/mcp`;
const READ_SCOPES = ["governance:read", "onboarding:read"] as const;
let databaseCounter = 0;

interface ConnectedRole {
  readonly actor: AuthorizedActorFixture;
  readonly client: Client;
  readonly context: ActiveTokenContext;
  readonly token: string;
}

async function withDatabase<T>(run: (owner: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_role_journeys_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const ownerUrl = new URL(BASE_URL);
  ownerUrl.pathname = `/${database}`;
  const owner = new Pool({ connectionString: ownerUrl.toString(), max: 6 });
  try {
    await migrate(owner, MIGRATIONS, "role-connection-journeys-test");
    return await run(owner);
  } finally {
    await owner.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function attachSession(
  owner: Pool,
  actor: AuthorizedActorFixture,
  offset: number
): Promise<void> {
  const sessionId = testId(800 + offset);
  await owner.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated',$6,
               transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
    [
      sessionId,
      actor.organizationId,
      testHash(160 + offset),
      actor.memberId,
      actor.clientId,
      ISSUER
    ]
  );
  await owner.query("update access_token_records set session_id=$1 where id=$2", [
    sessionId,
    actor.accessTokenRecordId
  ]);
}

async function mintAccessToken(
  actor: AuthorizedActorFixture,
  context: ActiveTokenContext,
  privateKey: CryptoKey
): Promise<string> {
  return new SignJWT({
    client_id: context.internalClientId,
    resource: RESOURCE,
    scope: context.scopes.join(" ")
  })
    .setProtectedHeader({ alg: "ES256", kid: context.signingKeyKid })
    .setIssuer(ISSUER)
    .setAudience(RESOURCE)
    .setSubject(context.memberId)
    .setJti(actor.tokenJti)
    .setIssuedAt()
    .setExpirationTime(context.expiresAt)
    .sign(privateKey);
}

async function connectRole(
  handler: ReturnType<typeof createProtectedMcpHandler>,
  actor: AuthorizedActorFixture,
  context: ActiveTokenContext,
  token: string
): Promise<ConnectedRole> {
  const client = new Client(
    { name: `role-agent-${context.roles.join("-")}`, version: "1.0.0" },
    {
      capabilities: {},
      versionNegotiation: { mode: { pin: "2026-07-28" } },
      cachePartition: actor.memberId
    }
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(RESOURCE), {
      fetch: async (input, init) => {
        const base = new Request(input, init);
        const headers = new Headers(base.headers);
        headers.set("authorization", `Bearer ${token}`);
        // One request owner per exchange, as the HTTP runtime opens around the handler.
        return fetchWithDirectRequestOwner(() => handler.fetch(new Request(base, { headers })));
      }
    })
  );
  return { actor, client, context, token };
}

function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new TypeError("expected structured result data");
  }
  return value as Readonly<Record<string, JsonValue>>;
}

async function call(
  client: Client,
  name: string,
  args: Readonly<Record<string, JsonValue>>
): Promise<Readonly<Record<string, JsonValue>>> {
  const response = await client.callTool({ name, arguments: args });
  if (response.isError) {
    const message = response.content
      .filter(
        (item): item is Extract<(typeof response.content)[number], { type: "text" }> =>
          item.type === "text"
      )
      .map(({ text }) => text)
      .join("\n");
    throw new Error(message || `BoardAgent tool failed: ${name}`);
  }
  const structured = response.structuredContent as SurfaceToolResult | undefined;
  if (!structured || structured.tool !== name) throw new Error("missing BoardAgent tool result");
  return record(structured.data);
}

describe("four role connection journeys", () => {
  it("binds each real MCP client to its own live role and denies a stranger", async () => {
    await withDatabase(async (owner) => {
      const secretary = await seedAuthorizedActor(owner, {
        seatRole: "voting_member",
        scopes: READ_SCOPES,
        isSecretary: true
      });
      const member = await seedAdditionalAuthorizedActor(owner, secretary, {
        idBase: 100,
        seatRole: "voting_member",
        scopes: READ_SCOPES
      });
      const management = await seedAdditionalAuthorizedActor(owner, secretary, {
        idBase: 200,
        seatRole: "management",
        scopes: READ_SCOPES
      });
      const observer = await seedAdditionalAuthorizedActor(owner, secretary, {
        idBase: 300,
        seatRole: "observer",
        scopes: READ_SCOPES
      });
      const actors = [secretary, member, management, observer] as const;
      await Promise.all(actors.map((actor, index) => attachSession(owner, actor, index)));

      const tokenStore = new PgTokenContextStore(owner, { assumeRole: "boardagent_server" });
      const contexts = await Promise.all(
        actors.map(async (actor) => {
          const context = await tokenStore.findActiveByJti(actor.tokenJti);
          if (!context) throw new Error("role token did not resolve from the live ledger");
          return context;
        })
      );
      expect(contexts.map(({ roles }) => roles)).toEqual([
        ["member", "secretariat"],
        ["member"],
        ["management"],
        ["observer"]
      ]);

      const { privateKey, publicKey } = await generateKeyPair("ES256");
      const tokens = await Promise.all(
        actors.map((actor, index) => mintAccessToken(actor, contexts[index]!, privateKey))
      );
      const service = new PgBoardAgentSurfaceService(owner, {
        reads: new PgSurfaceReadRepository(owner, {
          cursorKey: new Uint8Array(32).fill(0x52),
          transaction: { assumeRole: "boardagent_server" }
        }),
        transaction: { assumeRole: "boardagent_server" }
      });
      const mcp = createBoardAgentMcpHandler({
        service,
        requestStateKey: new Uint8Array(32).fill(0x53),
        requestStateTtlSeconds: 600
      });
      const protectedMcp = createProtectedMcpHandler({
        handler: mcp,
        resourceUri: RESOURCE,
        verifier: {
          verifyAccessToken: createTokenVerifier({
            issuer: ISSUER,
            audience: RESOURCE,
            publicKey,
            tokens: tokenStore
          })
        }
      });
      const connected: ConnectedRole[] = [];
      try {
        for (const [index, actor] of actors.entries()) {
          connected.push(await connectRole(protectedMcp, actor, contexts[index]!, tokens[index]!));
        }

        const expected = [
          { roles: ["member", "secretariat"], seatRole: "voting_member", secretary: true },
          { roles: ["member"], seatRole: "voting_member", secretary: false },
          { roles: ["management"], seatRole: "management", secretary: false },
          { roles: ["observer"], seatRole: "observer", secretary: false }
        ] as const;

        for (const [index, role] of connected.entries()) {
          const whoami = await call(role.client, "whoami", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION
          });
          const boards = await call(role.client, "list_my_boards", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            cursor: null,
            limit: 100
          });
          const board = await call(role.client, "get_board", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: role.actor.boardId
          });
          const onboarding = await call(role.client, "get_onboarding", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: role.actor.boardId
          });
          const boardItems = boards["items"];
          if (!Array.isArray(boardItems)) throw new Error("board page is unavailable");
          const ownBoard = record(boardItems[0] as JsonValue);
          const onboardingView = record(onboarding["onboarding"] as JsonValue);
          const boardView = record(board["board"] as JsonValue);

          expect(whoami).toMatchObject({
            member_id: role.actor.memberId,
            roles: expected[index]!.roles,
            board_ids: [role.actor.boardId]
          });
          expect(ownBoard).toMatchObject({
            board_id: role.actor.boardId,
            seat_role: expected[index]!.seatRole,
            is_secretary: expected[index]!.secretary
          });
          expect(boardView["board_id"]).toBe(role.actor.boardId);
          expect(onboardingView).toMatchObject({
            board_id: role.actor.boardId,
            seat_role: expected[index]!.seatRole,
            attested: true,
            presentation_choice: "structured",
            local_memory_choice: "local-only"
          });

          const visible = JSON.stringify({ whoami, boards, board, onboarding });
          for (const other of actors.filter(({ memberId }) => memberId !== role.actor.memberId)) {
            expect(visible).not.toContain(other.memberId);
          }
        }

        await owner.query(
          `insert into onboarding_terms_versions(
             id,organization_id,seat_role,version,schema_version,canonical_text,
             canonical_sha256,material_change,effective_at,created_by
           ) values ($1,$2,'management',2,'boardagent.onboarding-terms.v1',
                     'Updated management terms',$3,true,
                     transaction_timestamp()-interval '1 second',$4)`,
          [testId(950), secretary.organizationId, testHash(240), secretary.memberId]
        );
        const staleOnboarding = await call(connected[2]!.client, "get_onboarding", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: management.boardId
        });
        expect(record(staleOnboarding["onboarding"] as JsonValue)).toMatchObject({
          seat_role: "management",
          attested: false,
          presentation_choice: null,
          local_memory_choice: null
        });
        await expect(
          call(connected[2]!.client, "list_my_boards", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            cursor: null,
            limit: 100
          })
        ).rejects.toThrow("onboarding_required");

        const forged = await new SignJWT({
          client_id: testId(980),
          resource: RESOURCE,
          scope: READ_SCOPES.join(" ")
        })
          .setProtectedHeader({ alg: "ES256", kid: contexts[0]!.signingKeyKid })
          .setIssuer(ISSUER)
          .setAudience(RESOURCE)
          .setSubject(testId(981))
          .setJti(testId(982))
          .setIssuedAt()
          .setExpirationTime("10m")
          .sign(privateKey);
        const stranger = await protectedMcp.fetch(
          new Request(RESOURCE, {
            method: "POST",
            headers: { authorization: `Bearer ${forged}` }
          })
        );
        expect(stranger.status).toBe(401);
        await expect(stranger.json()).resolves.toEqual({
          error: "invalid_token",
          error_description: "Bearer token is invalid"
        });
      } finally {
        await Promise.allSettled(connected.map(({ client }) => client.close()));
        await protectedMcp.close();
      }
    });
  });
});
