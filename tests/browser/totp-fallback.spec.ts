import { createServer, type RequestListener, type ServerResponse } from "node:http";
import path from "node:path";

import { chromium } from "playwright";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  AuthRequestBoundary,
  createBoardAgentOAuthInteractionHandler,
  generateTotpCodeFromBase32,
  PgRateLimiter,
  PgTotpService,
  type BoardAgentOAuthProvider,
  type OidcInteractionBinding,
  type OidcInteractionBindingStore
} from "../../artifacts/server/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const ORGANIZATION_ID = testId(70_001);
const SECRETARY_ID = testId(70_002);
const MEMBER_ID = testId(70_003);
const KEY_ID = testId(70_004);
const CLIENT_ID = testId(70_005);
const SESSION_ID = testId(70_006);
const INTERACTION_UID = Buffer.alloc(24, 0xc1).toString("base64url");
const CSRF_TOKEN = Buffer.alloc(32, 0xc2).toString("base64url");
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_totp_browser_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "totp-browser-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedIdentity(pool: Pool): Promise<void> {
  await pool.query(
    "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
    [ORGANIZATION_ID]
  );
  await pool.query(
    `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
     values ($1,$3,'human','Secretary','Secretary','active'),
            ($2,$3,'human','Member','Member','active')`,
    [SECRETARY_ID, MEMBER_ID, ORGANIZATION_ID]
  );
  await pool.query(
    `insert into organization_role_assignments(
       id,organization_id,member_id,role,change_reason
     ) values ($1,$2,$3,'secretariat','Browser TOTP test authority')`,
    [testId(70_007), ORGANIZATION_ID, SECRETARY_ID]
  );
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,'totp-browser-kek','data_kek','A256GCM',null,
               'test://totp-browser-kek',transaction_timestamp())`,
    [KEY_ID, ORGANIZATION_ID]
  );
}

describe("BoardAgent browser TOTP fallback", () => {
  it("keeps passkey primary and authenticates only an explicitly enabled fallback", async () => {
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      let nextId = 70_100;
      let entropyByte = 0x41;
      const policy = { windowSeconds: 60, maxRequests: 50, blockSeconds: 60 } as const;
      const totp = new PgTotpService(pool, {
        issuer: "BoardAgent",
        activeKeyId: KEY_ID,
        keys: new Map([[KEY_ID, Buffer.alloc(32, 0xd1)]]),
        rateLimiter: new PgRateLimiter(pool, {
          hmacKey: Buffer.alloc(32, 0xd2),
          assumeRole: "boardagent_server"
        }),
        rateLimits: { ip: policy, client: policy, member: policy, token: policy },
        maxFailedAttempts: 5,
        lockoutSeconds: 300,
        assumeRole: "boardagent_server",
        newId: () => testId(nextId++),
        randomBytes: (size) => Buffer.alloc(size, entropyByte++)
      });
      const enrollment = await totp.beginEnrollment({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        authorizedByMemberId: SECRETARY_ID
      });
      const nowSeconds = Math.floor(Date.now() / 1000);
      await totp.completeEnrollment({
        organizationId: ORGANIZATION_ID,
        credentialId: enrollment.credentialId,
        authorizedByMemberId: SECRETARY_ID,
        code: generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds)
      });
      const loginCode = generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds + 30);

      const binding: OidcInteractionBinding = {
        interactionUid: INTERACTION_UID,
        authorizationRequestId: testId(70_008),
        sessionId: SESSION_ID,
        clientId: CLIENT_ID,
        protocolClientId: "https://portable-client.test/client.json",
        clientDisplayName: "Portable client",
        resourceUri: "https://boardagent.test/mcp",
        scopes: ["documents:read"],
        csrfToken: CSRF_TOKEN,
        expiresAt: new Date(Date.now() + 300_000)
      };
      const bindingStore: OidcInteractionBindingStore = {
        load: async () => binding,
        verifyCsrf: (candidate, token) => {
          if (candidate !== binding || token !== CSRF_TOKEN) throw new Error("CSRF rejected");
        }
      };
      let approvedMember: string | undefined;
      const provider: BoardAgentOAuthProvider = {
        issuer: "https://boardagent.test",
        resourceUri: "https://boardagent.test/mcp",
        callback: () => {
          throw new Error("provider callback is outside this browser fixture");
        },
        interactionDetails: async () =>
          ({
            uid: INTERACTION_UID,
            prompt: { name: "login", reasons: [], details: {} },
            params: {
              client_id: binding.protocolClientId,
              resource: binding.resourceUri,
              scope: "documents:read"
            }
          }) as never,
        approveInteraction: async (_request, responseValue, input) => {
          approvedMember = input.memberId;
          const response = responseValue as ServerResponse;
          response.writeHead(303, { location: "/approved" });
          response.end();
        },
        denyInteraction: async (_request, responseValue) => {
          const response = responseValue as ServerResponse;
          response.writeHead(303, { location: "/denied" });
          response.end();
        }
      };

      let interactionHandler: RequestListener | undefined;
      const server = createServer((request, response) => {
        if (request.url === "/approved") {
          response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
          response.end("approved");
          return;
        }
        if (interactionHandler) interactionHandler(request, response);
        else response.destroy();
      });
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("browser server has no port");
      const origin = `http://localhost:${String(address.port)}`;
      interactionHandler = createBoardAgentOAuthInteractionHandler({
        organizationId: ORGANIZATION_ID,
        boundary: new AuthRequestBoundary({
          origin,
          allowInsecureLoopbackDevelopment: true
        }),
        provider,
        bindingStore,
        webauthn: {
          beginAuthentication: () => {
            throw new Error("passkey should remain unused in the explicit fallback test");
          },
          completeAuthentication: () => {
            throw new Error("passkey should remain unused in the explicit fallback test");
          }
        },
        totp,
        includeHsts: false
      });

      const browser = await chromium.launch({ headless: true });
      try {
        const page = await browser.newPage();
        page.setDefaultTimeout(5_000);
        page.setDefaultNavigationTimeout(5_000);
        const loginUrl = `${origin}/auth/interactions/${INTERACTION_UID}`;
        await page.goto(loginUrl);
        await expect(page.locator("[data-passkey-button]").count()).resolves.toBe(1);
        await expect(page.locator('input[name="code"]').count()).resolves.toBe(0);
        await expect(page.locator('input[name="password"]').count()).resolves.toBe(0);
        await page.locator("[data-totp-fallback-link]").click();
        await expect(page.locator('input[name="fallback_handle"]').count()).resolves.toBe(1);
        await expect(page.locator('input[name="code"]').count()).resolves.toBe(1);
        await expect(page.locator('input[type="password"]').count()).resolves.toBe(0);

        await page.locator('input[name="fallback_handle"]').fill(enrollment.fallbackHandle);
        await page.locator('input[name="code"]').fill(loginCode);
        await Promise.all([
          page.waitForURL(`${origin}/approved`),
          page.locator("[data-totp-submit]").click()
        ]);
        expect(await page.textContent("body")).toBe("approved");
        expect(approvedMember).toBe(MEMBER_ID);

        approvedMember = undefined;
        await page.goto(`${loginUrl}/totp`);
        await page.locator('input[name="fallback_handle"]').fill(enrollment.fallbackHandle);
        await page.locator('input[name="code"]').fill(loginCode);
        await page.locator("[data-totp-submit]").click();
        await page.waitForLoadState("load");
        expect(page.url()).toBe(`${loginUrl}/totp/complete`);
        expect(await page.textContent("body")).toBe('{"error":"invalid_auth_request"}');
        expect(approvedMember).toBeUndefined();
      } finally {
        await browser.close();
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve()))
        );
      }
    });
  }, 30_000);
});
