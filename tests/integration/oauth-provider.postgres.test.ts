import { createHash } from "node:crypto";
import path from "node:path";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK } from "jose";
import { Pool } from "pg";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { withDirectResponseAllocation } from "../helpers/direct-response-allocation.js";

import {
  AuthRequestBoundary,
  createBoardAgentOAuthInteractionHandler,
  createBoardAgentOAuthProvider,
  createPgOAuthTokenEndpoint,
  createPgOidcProviderPersistence,
  createTokenVerifier,
  PgWebAuthnStore,
  PgTokenContextStore,
  PgSurfaceReadRepository,
  WebAuthnCeremony,
  type BoardAgentOAuthProvider,
  type PgOidcProviderPersistence
} from "../../artifacts/server/src/index.js";
import {
  activateEnrollmentInTransaction,
  migrate,
  withIdentityTransaction,
  withRequestTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import {
  allowAllWebAuthnAttempts,
  authenticationResponse,
  CREDENTIAL_ID,
  fakeWebAuthnCrypto,
  idSequence,
  RAW_CREDENTIAL_ID
} from "../browser/webauthn-harness.js";
import { testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const ISSUER = "https://boardagent.test";
const RESOURCE = `${ISSUER}/mcp`;
const CLIENT_PROTOCOL_ID = "https://portable-client.test/client.json";
const REDIRECT_URI = "https://portable-client.test/callback";
const MEMBER_ID = testId(3);
const ORGANIZATION_ID = testId(1);
const CLIENT_ID = testId(7);
const PKCE_VERIFIER = "v".repeat(43);
const STATE = "state-0123456789abcdef";
let databaseCounter = 0;
let privateJwk: Readonly<Record<string, unknown>>;
let publicJwk: Readonly<Record<string, unknown>>;
const activeServers: Server[] = [];

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const exported = await exportJWK(privateKey);
  privateJwk = {
    ...exported,
    kid: "oauth-es256-1",
    use: "sig",
    alg: "ES256"
  };
  const { d: _privateMaterial, ...publicMaterial } = privateJwk;
  publicJwk = publicMaterial;
});

afterEach(async () => {
  await Promise.all(
    activeServers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve()))
          )
      )
  );
});

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_oauth_provider_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "oauth-provider-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}"`);
    await admin.end();
  }
}

async function seedIdentity(
  pool: Pool,
  memberState: "active" | "pending_activation" = "active",
  redirectUri = REDIRECT_URI
): Promise<void> {
  await pool.query(
    "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
    [ORGANIZATION_ID]
  );
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,'oauth-es256-1','oauth_signing','ES256',$3,'local-test-key',
               transaction_timestamp()-interval '1 minute')`,
    [testId(8), ORGANIZATION_ID, publicJwk]
  );
  await pool.query(
    "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Actor','Actor',$3)",
    [MEMBER_ID, ORGANIZATION_ID, memberState]
  );
  await pool.query(
    "insert into system_instance(instance_id,organization_id,canonical_resource_uri) values ($1,$2,$3)",
    [testId(2), ORGANIZATION_ID, RESOURCE]
  );
  await pool.query(
    `insert into oauth_clients(
       id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,state
     ) values ($1,$2,'verified_cimd_url',$3,$4,$5,'active')`,
    [CLIENT_ID, ORGANIZATION_ID, CLIENT_PROTOCOL_ID, { name: "Portable client" }, testHash(7)]
  );
  await pool.query(
    "insert into oauth_client_redirect_uris(client_id,redirect_uri,redirect_uri_sha256) values ($1,$2,$3)",
    [CLIENT_ID, redirectUri, createHash("sha256").update(redirectUri).digest()]
  );
  for (const grantType of ["authorization_code", "refresh_token"] as const) {
    for (const scope of ["documents:read", "governance:read", "onboarding:read"] as const) {
      await pool.query(
        "insert into oauth_client_grants(client_id,grant_type,scope) values ($1,$2,$3)",
        [CLIENT_ID, grantType, scope]
      );
    }
  }
  await pool.query(
    `insert into webauthn_credentials(
       id,organization_id,member_id,credential_id,public_key,signature_counter,transports,
       backup_eligible,backup_state,state
     ) values ($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')`,
    [testId(9), ORGANIZATION_ID, MEMBER_ID, Buffer.from(RAW_CREDENTIAL_ID), Buffer.alloc(64, 7)]
  );
}

async function seedPendingActivationAuthority(pool: Pool): Promise<{
  readonly boardId: string;
  readonly invitationId: string;
  readonly activationChallengeId: string;
  readonly activationCodeSha256: string;
  readonly secretaryMemberId: string;
  readonly secretarySessionId: string;
}> {
  const boardId = testId(73_001);
  const targetMembershipId = testId(73_002);
  const secretaryMemberId = testId(73_003);
  const secretaryMembershipId = testId(73_004);
  const invitationId = testId(73_005);
  const activationChallengeId = testId(73_006);
  const secretarySessionId = testId(73_007);
  const activationCodeSha256 = createHash("sha256").update("ACT-2V4Q").digest("hex");
  await pool.query(
    "insert into boards(id,organization_id,slug,name,timezone) values ($1,$2,'board','Board','UTC')",
    [boardId, ORGANIZATION_ID]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
    [targetMembershipId, ORGANIZATION_ID, boardId, MEMBER_ID]
  );
  await pool.query(
    "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Secretary','Secretary','active')",
    [secretaryMemberId, ORGANIZATION_ID]
  );
  await pool.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'voting_member',true,1,'active')`,
    [secretaryMembershipId, ORGANIZATION_ID, boardId, secretaryMemberId]
  );
  await pool.query(
    `insert into enrollment_invitations(
       id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at,
       consumed_at,pending_activation_member_id
     ) values ($1,$2,$3,$4,$5,'operator_qr',transaction_timestamp()+interval '1 hour',
               transaction_timestamp(),$3)`,
    [invitationId, ORGANIZATION_ID, MEMBER_ID, testHash(73), secretaryMemberId]
  );
  await pool.query(
    `insert into enrollment_activation_challenges(
       id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,
       expires_at
     ) values ($1,$2,$3,$4,$5,'verified_number_call','issued',
               transaction_timestamp()+interval '10 minutes')`,
    [
      activationChallengeId,
      ORGANIZATION_ID,
      MEMBER_ID,
      invitationId,
      Buffer.from(activationCodeSha256, "hex")
    ]
  );
  await pool.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,
       expires_at,last_authenticated_at
     ) values ($1,$2,$3,$4,$5,'authenticated',$6,
               transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
    [secretarySessionId, ORGANIZATION_ID, testHash(74), secretaryMemberId, CLIENT_ID, ISSUER]
  );
  return {
    boardId,
    invitationId,
    activationChallengeId,
    activationCodeSha256,
    secretaryMemberId,
    secretarySessionId
  };
}

interface CookieValue {
  readonly name: string;
  readonly value: string;
  readonly path: string;
}

class PathCookieJar {
  private readonly cookies = new Map<string, CookieValue>();

  public clone(): PathCookieJar {
    const clone = new PathCookieJar();
    for (const [key, cookie] of this.cookies) clone.cookies.set(key, { ...cookie });
    return clone;
  }

  public tamperOidcContinuation(): void {
    const entries = [...this.cookies.entries()].filter(([, cookie]) =>
      cookie.name.startsWith("__Secure-boardagent_oidc_")
    );
    if (entries.length === 0) throw new Error("OIDC continuation cookie is unavailable");
    for (const [key, cookie] of entries) {
      const parts = cookie.value.split(".");
      if (parts.length !== 4 || !parts[2]) throw new Error("OIDC continuation is malformed");
      const first = parts[2][0];
      parts[2] = `${first === "A" ? "B" : "A"}${parts[2].slice(1)}`;
      this.cookies.set(key, {
        ...cookie,
        value: parts.join(".")
      });
    }
  }

  public aliasOidcContinuationEncoding(): void {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const entries = [...this.cookies.entries()].filter(([, cookie]) =>
      cookie.name.startsWith("__Secure-boardagent_oidc_")
    );
    if (entries.length === 0) throw new Error("OIDC continuation cookie is unavailable");
    for (const [key, cookie] of entries) {
      const parts = cookie.value.split(".");
      if (parts.length !== 4 || !parts[3]) throw new Error("OIDC continuation is malformed");
      const lastIndex = alphabet.indexOf(parts[3].at(-1)!);
      if (lastIndex < 0) throw new Error("OIDC continuation tag is malformed");
      const aliasIndex = (lastIndex & 0b11_0000) | ((lastIndex + 1) & 0b00_1111);
      parts[3] = `${parts[3].slice(0, -1)}${alphabet[aliasIndex]}`;
      this.cookies.set(key, { ...cookie, value: parts.join(".") });
    }
  }

  public add(response: Response): void {
    const headers = response.headers as Headers & { getSetCookie?: () => string[] };
    for (const setCookie of headers.getSetCookie?.() ?? []) {
      const parts = setCookie.split(";").map((part) => part.trim());
      const separator = parts[0]?.indexOf("=") ?? -1;
      if (!parts[0] || separator <= 0) continue;
      const name = parts[0].slice(0, separator);
      const value = parts[0].slice(separator + 1);
      const pathPart = parts.find((part) => part.toLowerCase().startsWith("path="));
      const cookiePath = pathPart?.slice(5) ?? "/";
      const key = `${name}\0${cookiePath}`;
      if (value === "") this.cookies.delete(key);
      else this.cookies.set(key, { name, value, path: cookiePath });
    }
  }

  public header(pathname: string): string {
    return [...this.cookies.values()]
      .filter(({ path: cookiePath }) => pathname.startsWith(cookiePath))
      .map(({ name, value }) => `${name}=${value}`)
      .join("; ");
  }
}

async function fetchWithCookies(
  jar: PathCookieJar,
  url: URL,
  init: RequestInit = {}
): Promise<Response> {
  const cookie = jar.header(url.pathname);
  const response = await fetch(url, {
    ...init,
    headers: {
      host: new URL(ISSUER).host,
      ...init.headers,
      ...(cookie === "" ? {} : { cookie })
    },
    redirect: "manual"
  });
  jar.add(response);
  return response;
}

function csrfFromPage(body: string): string {
  const match = /name="csrf_token" value="([A-Za-z0-9_-]{43})"/u.exec(body);
  if (!match) throw new Error("OAuth interaction page has no CSRF token");
  return match[1]!;
}

async function postForm(
  jar: PathCookieJar,
  target: URL,
  values: Readonly<Record<string, string>>
): Promise<Response> {
  return fetchWithCookies(jar, target, {
    method: "POST",
    headers: {
      origin: ISSUER,
      "sec-fetch-site": "same-origin",
      "content-type": "application/x-www-form-urlencoded; charset=utf-8"
    },
    body: new URLSearchParams(values).toString()
  });
}

async function listen(
  runtime: BoardAgentOAuthProvider,
  interactionHandler?: (request: IncomingMessage, response: ServerResponse) => void
): Promise<URL> {
  const callback = runtime.callback();
  const server = createServer((request, response) => {
    Object.defineProperty(request.socket, "encrypted", { configurable: true, value: true });
    request.headers.host = new URL(runtime.issuer).host;
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      if (request.rawHeaders[index]?.toLowerCase() === "host") {
        request.rawHeaders[index + 1] = new URL(runtime.issuer).host;
      }
    }
    if (request.url?.startsWith("/auth/interactions/") && interactionHandler) {
      interactionHandler(request, response);
      return;
    }
    callback(request, response);
  });
  activeServers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("OAuth server has no port");
  return new URL(`http://127.0.0.1:${String(address.port)}`);
}

function runtime(
  pool: Pool,
  redirectUri = REDIRECT_URI,
  extraClients: readonly { clientId: string; redirectUris: readonly string[] }[] = []
): {
  readonly provider: BoardAgentOAuthProvider;
  readonly persistence: PgOidcProviderPersistence;
} {
  const persistence = createPgOidcProviderPersistence({
    pool,
    organizationId: ORGANIZATION_ID,
    issuer: ISSUER,
    resourceUri: RESOURCE,
    stateEncryptionKey: Buffer.alloc(32, 9),
    assumeRole: "boardagent_server"
  });
  const provider = createBoardAgentOAuthProvider({
    issuer: ISSUER,
    resourceUri: RESOURCE,
    scopes: ["documents:read", "governance:read", "onboarding:read"],
    clients: [{ clientId: CLIENT_PROTOCOL_ID, redirectUris: [redirectUri] }, ...extraClients],
    privateJwk,
    cookieKeys: ["c".repeat(32), "d".repeat(32)],
    adapter: persistence.adapter,
    interactionStateStore: persistence.interactionStateStore,
    tokenEndpoint: createPgOAuthTokenEndpoint({
      pool,
      organizationId: ORGANIZATION_ID,
      resourceUri: RESOURCE,
      signingKeyId: testId(8),
      privateJwk,
      assumeRole: "boardagent_server"
    })
  });
  return { provider, persistence };
}

function authorize(
  base: URL,
  scope = "documents:read governance:read",
  redirectUri = REDIRECT_URI,
  clientId = CLIENT_PROTOCOL_ID
): URL {
  const url = new URL("/authorize", base);
  const challenge = createHash("sha256").update(PKCE_VERIFIER).digest("base64url");
  for (const [key, value] of Object.entries({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    state: STATE,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE
  })) {
    url.searchParams.set(key, value);
  }
  return url;
}

describe("PostgreSQL oidc-provider persistence", () => {
  it.each(["", "/totp", "/totp/complete", "/oidc/google/start", "/oidc/complete"])(
    "loads the original sealed login binding on each advertised authentication route: %s",
    async (suffix) => {
      await withDatabase(async (pool) => {
        await seedIdentity(pool);
        const activeRuntime = runtime(pool);
        const base = await listen(activeRuntime.provider);
        const jar = new PathCookieJar();
        const started = await fetchWithCookies(jar, authorize(base));
        expect(started.status).toBe(303);
        const location = started.headers.get("location")!;
        expect(location).toMatch(/^\/auth\/interactions\/[A-Za-z0-9_-]+$/u);
        const pathname = `${location}${suffix}`;
        const incoming = {
          url: pathname,
          headers: { cookie: jar.header(pathname) }
        } as IncomingMessage;
        const before = (
          await pool.query(
            "select id,member_id,session_id,state_hash,request_state,expires_at from oauth_authorization_requests"
          )
        ).rows;
        expect(before).toHaveLength(1);
        const binding = await activeRuntime.persistence.interactionBindingStore.load(incoming);
        expect(binding).toMatchObject({
          interactionUid: location.split("/").at(-1),
          authorizationRequestId: before[0]!.id,
          sessionId: before[0]!.session_id,
          clientId: CLIENT_ID,
          resourceUri: RESOURCE,
          scopes: ["documents:read", "governance:read"]
        });
        const details = await activeRuntime.persistence.interactionStateStore.run(incoming, () =>
          new activeRuntime.persistence.adapter("Interaction").find(binding.interactionUid)
        );
        expect(details).toMatchObject({
          jti: binding.interactionUid,
          prompt: { name: "login" },
          params: { client_id: CLIENT_PROTOCOL_ID, resource: RESOURCE }
        });
        expect(
          (
            await pool.query(
              "select id,member_id,session_id,state_hash,request_state,expires_at from oauth_authorization_requests"
            )
          ).rows
        ).toEqual(before);
        expect(
          (await pool.query("select count(*)::int as count from access_token_records")).rows
        ).toEqual([{ count: 0 }]);
      });
    }
  );

  it("refuses continuation cookies on noncanonical or unsupported authentication routes", async () => {
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      const activeRuntime = runtime(pool);
      const base = await listen(activeRuntime.provider);
      const jar = new PathCookieJar();
      const started = await fetchWithCookies(jar, authorize(base));
      expect(started.status).toBe(303);
      const location = started.headers.get("location")!;
      const cookie = jar.header(location);
      for (const pathname of [
        `${location}/totp/`,
        `${location}/totp?next=complete`,
        `${location}/totp/complete/extra`,
        `${location}/oidc/GOOGLE/start`,
        `${location}/oidc/google/start/`,
        `${location}/oidc/google%2fother/start`,
        `${location}/oidc/complete?other=1`,
        `${location}/oidc/unknown`,
        `${location}/unknown`,
        `${location.replace("/auth/", "/auth//")}/totp`,
        `${ISSUER}${location}/totp`
      ]) {
        await expect(
          activeRuntime.persistence.interactionBindingStore.load({
            url: pathname,
            headers: { cookie }
          } as IncomingMessage)
        ).rejects.toThrow("OIDC interaction binding is unavailable");
      }
      expect(
        (await pool.query("select member_id,request_state from oauth_authorization_requests")).rows
      ).toEqual([{ member_id: null, request_state: "pending" }]);
      expect(
        (await pool.query("select count(*)::int as count from access_token_records")).rows
      ).toEqual([{ count: 0 }]);
    });
  });

  it("binds a loopback callback registered on one port to a request on any other port, and nothing else", async () => {
    // RFC 8252 §7.3: a native client (Claude Code 2.1.270 in practice) binds an ephemeral
    // loopback port at every login, so the registered `http://localhost:<port>/callback`
    // must match the same host and path on any port. Host, path and query stay exact,
    // and a non-loopback registration keeps byte-exact matching.
    await withDatabase(async (pool) => {
      const registered = "http://localhost:1/callback";
      await seedIdentity(pool, "active", registered);
      const activeRuntime = runtime(pool, registered);
      const base = await listen(activeRuntime.provider);
      const jar = new PathCookieJar();
      const started = await fetchWithCookies(
        jar,
        authorize(base, undefined, "http://localhost:49153/callback")
      );
      expect(started.status).toBe(303);
      expect(started.headers.get("location")).toMatch(/^\/auth\/interactions\//u);
      expect(
        (await pool.query("select redirect_uri,request_state from oauth_authorization_requests"))
          .rows
      ).toEqual([{ redirect_uri: "http://localhost:49153/callback", request_state: "pending" }]);
      for (const refused of [
        "http://localhost:49153/other",
        "http://localhost:49153/callback?next=1",
        "http://127.0.0.1:49153/callback",
        "https://localhost:49153/callback"
      ]) {
        const response = await fetchWithCookies(jar, authorize(base, undefined, refused));
        expect(response.status, refused).toBe(400);
        expect(response.headers.get("location"), refused).toBeNull();
        await expect(response.json()).resolves.toMatchObject({ error: "invalid_redirect_uri" });
      }
      expect(
        (await pool.query("select count(*)::int as count from oauth_authorization_requests")).rows
      ).toEqual([{ count: 1 }]);
    });
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      const activeRuntime = runtime(pool);
      const base = await listen(activeRuntime.provider);
      const response = await fetchWithCookies(
        new PathCookieJar(),
        authorize(base, undefined, "https://portable-client.test:8443/callback")
      );
      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toMatchObject({ error: "invalid_redirect_uri" });
      expect(
        (await pool.query("select count(*)::int as count from oauth_authorization_requests")).rows
      ).toEqual([{ count: 0 }]);
    });
  });

  it.each([REDIRECT_URI, "http://127.0.0.1:49152/callback", "com.boardagent.client:/callback"])(
    "recovers normalized login, consent and token exchange after restart for %s",
    async (redirectUri) => {
      await withDatabase(async (pool) => {
        await seedIdentity(pool, "active", redirectUri);
        const firstRuntime = runtime(pool, redirectUri);
        const firstBase = await listen(firstRuntime.provider);
        const jar = new PathCookieJar();
        const firstResponse = await fetchWithCookies(
          jar,
          authorize(firstBase, undefined, redirectUri)
        );
        expect(firstResponse.status).toBe(303);
        expect(
          (firstResponse.headers as Headers & { getSetCookie(): string[] })
            .getSetCookie()
            .join("\n")
        ).not.toContain(STATE);
        const firstLocation = firstResponse.headers.get("location");
        expect(firstLocation).toMatch(/^\/auth\/interactions\//u);

        const restartedRuntime = runtime(pool, redirectUri);
        const webauthnCrypto = fakeWebAuthnCrypto();
        const webauthn = new WebAuthnCeremony({
          rpName: "BoardAgent",
          rpId: "boardagent.test",
          origin: ISSUER,
          store: new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" }),
          attemptLimiter: allowAllWebAuthnAttempts,
          crypto: webauthnCrypto.crypto,
          newId: idSequence(67_000)
        });
        const interactionHandler = createBoardAgentOAuthInteractionHandler({
          organizationId: ORGANIZATION_ID,
          boundary: new AuthRequestBoundary({ origin: ISSUER }),
          provider: restartedRuntime.provider,
          bindingStore: restartedRuntime.persistence.interactionBindingStore,
          webauthn,
          includeHsts: true
        });
        const restartedBase = await listen(restartedRuntime.provider, interactionHandler);
        const aliasedJar = jar.clone();
        aliasedJar.aliasOidcContinuationEncoding();
        const aliased = await fetchWithCookies(aliasedJar, new URL(firstLocation!, restartedBase));
        expect(aliased.status).toBe(400);
        expect(await aliased.json()).toEqual({ error: "invalid_auth_request" });
        const tamperedJar = jar.clone();
        tamperedJar.tamperOidcContinuation();
        const tampered = await fetchWithCookies(
          tamperedJar,
          new URL(firstLocation!, restartedBase)
        );
        expect(tampered.status).toBe(400);
        expect(await tampered.json()).toEqual({ error: "invalid_auth_request" });
        expect(
          await pool.query(
            `select member_id,request_state from oauth_authorization_requests
            where organization_id=$1`,
            [ORGANIZATION_ID]
          )
        ).toMatchObject({ rows: [{ member_id: null, request_state: "pending" }] });
        const loginTarget = new URL(firstLocation!, restartedBase);
        await pool.query("update oauth_clients set state='suspended' where id=$1", [CLIENT_ID]);
        const suspendedClient = await fetchWithCookies(jar, loginTarget);
        expect(suspendedClient.status).toBe(400);
        expect(
          await pool.query("select count(*)::int as count from webauthn_challenges")
        ).toMatchObject({ rows: [{ count: 0 }] });
        await pool.query("update oauth_clients set state='active' where id=$1", [CLIENT_ID]);
        const loginPage = await fetchWithCookies(jar, loginTarget);
        expect(loginPage.status).toBe(200);
        const loginHtml = await loginPage.text();
        expect(loginHtml).toContain("data-webauthn-login");
        const loginCsrf = csrfFromPage(loginHtml);
        const wrongCsrf = await postForm(
          jar,
          new URL(`${loginTarget.pathname}/passkey/begin`, restartedBase),
          { csrf_token: Buffer.alloc(32, 0xff).toString("base64url") }
        );
        expect(wrongCsrf.status).toBe(400);
        expect(
          await pool.query("select count(*)::int as count from webauthn_challenges")
        ).toMatchObject({ rows: [{ count: 0 }] });
        const begin = await postForm(
          jar,
          new URL(`${loginTarget.pathname}/passkey/begin`, restartedBase),
          { csrf_token: loginCsrf }
        );
        expect(begin.status).toBe(200);
        expect(await begin.json()).toMatchObject({
          rpId: "boardagent.test",
          userVerification: "required"
        });
        let response = await postForm(
          jar,
          new URL(`${loginTarget.pathname}/passkey/complete`, restartedBase),
          { csrf_token: loginCsrf, credential: JSON.stringify(authenticationResponse) }
        );
        expect(response.status).toBe(303);
        expect(webauthnCrypto.authenticationCalls).toHaveLength(1);
        expect(webauthnCrypto.authenticationCalls[0]).toMatchObject({
          expectedOrigin: ISSUER,
          expectedRPID: "boardagent.test",
          requireUserVerification: true,
          credential: { id: CREDENTIAL_ID, counter: 0 }
        });

        const loginResume = new URL(response.headers.get("location")!, ISSUER);
        let target = new URL(`${loginResume.pathname}${loginResume.search}`, restartedBase);
        response = await fetchWithCookies(jar, target);
        expect(response.status).toBe(303);
        const consentLocation = response.headers.get("location");
        expect(consentLocation).toMatch(/^\/auth\/interactions\//u);
        // A restarted provider must preserve the absolute browser-session lifetime rather
        // than attempting a fresh eight-hour lease on the next wall-clock second.
        await new Promise((resolve) => setTimeout(resolve, 1_100));
        const consentTarget = new URL(consentLocation!, restartedBase);
        await pool.query(
          "update members set state='suspended',row_version=row_version+1 where id=$1",
          [MEMBER_ID]
        );
        const suspendedMember = await fetchWithCookies(jar, consentTarget);
        expect(suspendedMember.status).toBe(400);
        expect(await pool.query("select count(*)::int as count from oauth_consents")).toMatchObject(
          {
            rows: [{ count: 0 }]
          }
        );
        await pool.query(
          "update members set state='active',row_version=row_version+1 where id=$1",
          [MEMBER_ID]
        );
        const consentPage = await fetchWithCookies(jar, consentTarget);
        expect(consentPage.status).toBe(200);
        const consentHtml = await consentPage.text();
        expect(consentHtml).toContain("documents:read");
        expect(consentHtml).toContain("governance:read");
        response = await postForm(
          jar,
          new URL(`${consentTarget.pathname}/consent`, restartedBase),
          {
            csrf_token: csrfFromPage(consentHtml)
          }
        );

        let callback: URL | undefined;
        for (let redirects = 0; redirects < 8; redirects += 1) {
          expect(response.status).toBe(303);
          const location = response.headers.get("location");
          if (!location) throw new Error("OAuth continuation has no location");
          const logicalTarget = new URL(location, ISSUER);
          if (logicalTarget.origin === new URL(redirectUri).origin) {
            callback = logicalTarget;
            break;
          }
          target = new URL(`${logicalTarget.pathname}${logicalTarget.search}`, restartedBase);
          response = await fetchWithCookies(jar, target);
        }
        expect(callback?.searchParams.get("state")).toBe(STATE);
        const code = callback?.searchParams.get("code");
        expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/u);

        const requests = await pool.query<{
          request_state: string;
          member_id: string;
          scope_set: string[];
          state_sha256: string;
        }>(
          `select request_state,member_id,scope_set,encode(state_hash,'hex') as state_sha256
           from oauth_authorization_requests where organization_id=$1`,
          [ORGANIZATION_ID]
        );
        expect(requests.rows).toEqual([
          {
            request_state: "approved",
            member_id: MEMBER_ID,
            scope_set: ["documents:read", "governance:read"],
            state_sha256: createHash("sha256").update(STATE).digest("hex")
          }
        ]);
        expect(
          await pool.query(
            "select count(*)::int as count from auth_sessions where organization_id=$1",
            [ORGANIZATION_ID]
          )
        ).toMatchObject({ rows: [{ count: 2 }] });
        expect(
          await pool.query(
            "select count(*)::int as count from oauth_consents where organization_id=$1",
            [ORGANIZATION_ID]
          )
        ).toMatchObject({ rows: [{ count: 1 }] });
        expect(
          await pool.query(
            `select purpose,member_id,consumed_at is not null as consumed,rp_id,exact_origin
             from webauthn_challenges where organization_id=$1`,
            [ORGANIZATION_ID]
          )
        ).toMatchObject({
          rows: [
            {
              purpose: "authentication",
              member_id: null,
              consumed: true,
              rp_id: "boardagent.test",
              exact_origin: ISSUER
            }
          ]
        });
        expect(
          await pool.query(
            `select signature_counter::text as signature_counter,last_used_at is not null as used
             from webauthn_credentials where id=$1`,
            [testId(9)]
          )
        ).toMatchObject({ rows: [{ signature_counter: "1", used: true }] });
        const codes = await pool.query<{ code_sha256: string }>(
          `select encode(code_sha256,'hex') as code_sha256
           from oauth_authorization_codes where organization_id=$1`,
          [ORGANIZATION_ID]
        );
        expect(codes.rows).toEqual([
          { code_sha256: createHash("sha256").update(code!).digest("hex") }
        ]);

        const exchange = (body: URLSearchParams) =>
          fetch(new URL("/token", restartedBase), {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body
          });
        const queryRoute = await fetch(new URL("/token?shadow=1", restartedBase), {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: CLIENT_PROTOCOL_ID,
            redirect_uri: redirectUri,
            code: code!,
            code_verifier: PKCE_VERIFIER,
            resource: RESOURCE
          })
        });
        expect(queryRoute.status).toBe(400);
        await expect(queryRoute.json()).resolves.toEqual({ error: "invalid_request" });
        const unsupported = await exchange(
          new URLSearchParams({
            grant_type: "client_credentials",
            client_id: CLIENT_PROTOCOL_ID,
            resource: RESOURCE
          })
        );
        expect(unsupported.status).toBe(400);
        await expect(unsupported.json()).resolves.toEqual({
          error: "unsupported_grant_type"
        });
        const codeForm = new URLSearchParams({
          grant_type: "authorization_code",
          client_id: CLIENT_PROTOCOL_ID,
          redirect_uri: redirectUri,
          code: code!,
          code_verifier: PKCE_VERIFIER,
          resource: RESOURCE
        });
        const duplicateClient = new URLSearchParams(codeForm);
        duplicateClient.append("client_id", CLIENT_PROTOCOL_ID);
        const duplicateRejected = await exchange(duplicateClient);
        expect(duplicateRejected.status).toBe(400);
        await expect(duplicateRejected.json()).resolves.toEqual({ error: "invalid_request" });
        const wrongResource = new URLSearchParams(codeForm);
        wrongResource.set("resource", "https://other.test/mcp");
        const targetRejected = await exchange(wrongResource);
        expect(targetRejected.status).toBe(400);
        await expect(targetRejected.json()).resolves.toEqual({ error: "invalid_target" });
        const wrongVerifier = new URLSearchParams(codeForm);
        wrongVerifier.set("code_verifier", "x".repeat(43));
        const rejectedVerifier = await exchange(wrongVerifier);
        expect(rejectedVerifier.status).toBe(400);
        await expect(rejectedVerifier.json()).resolves.toEqual({ error: "invalid_grant" });

        const racedExchanges = await Promise.all([
          exchange(new URLSearchParams(codeForm)),
          exchange(new URLSearchParams(codeForm))
        ]);
        expect(racedExchanges.map(({ status }) => status).toSorted()).toEqual([200, 400]);
        const tokenResponse = racedExchanges.find(({ status }) => status === 200);
        const rejectedRace = racedExchanges.find(({ status }) => status === 400);
        if (!tokenResponse || !rejectedRace) throw new Error("code race result is incomplete");
        await expect(rejectedRace.json()).resolves.toEqual({ error: "invalid_grant" });
        const tokenBody = (await tokenResponse.json()) as Record<string, unknown>;
        expect(tokenBody).toMatchObject({
          access_token: expect.any(String),
          refresh_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
          token_type: "Bearer",
          expires_in: 900,
          scope: "documents:read governance:read"
        });
        const verificationKey = await importJWK(publicJwk as JWK & { readonly kty: "EC" }, "ES256");
        const verified = await jwtVerify(tokenBody["access_token"] as string, verificationKey, {
          algorithms: ["ES256"],
          issuer: ISSUER,
          audience: RESOURCE
        });
        expect(verified.payload).toMatchObject({
          sub: MEMBER_ID,
          client_id: CLIENT_ID,
          resource: RESOURCE,
          scope: "documents:read governance:read",
          jti: expect.stringMatching(/^[0-9a-f-]{36}$/u)
        });
        const authenticate = createTokenVerifier({
          issuer: ISSUER,
          audience: RESOURCE,
          publicKey: verificationKey,
          tokens: new PgTokenContextStore(pool, { assumeRole: "boardagent_server" })
        });
        await expect(authenticate(tokenBody["access_token"] as string)).resolves.toMatchObject({
          clientId: CLIENT_PROTOCOL_ID,
          scopes: ["documents:read", "governance:read"],
          extra: {
            organizationId: ORGANIZATION_ID,
            memberId: MEMBER_ID,
            internalClientId: CLIENT_ID,
            accessTokenRecordId: expect.stringMatching(/^[0-9a-f-]{36}$/u)
          }
        });
        const tokenContext = await new PgTokenContextStore(pool, {
          assumeRole: "boardagent_server"
        }).findActiveByJti(verified.payload.jti!);
        if (!tokenContext) throw new Error("newly issued token context unavailable");
        const readPrincipal = {
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          clientId: CLIENT_ID,
          serviceOrigin: ISSUER,
          protocolClientId: CLIENT_PROTOCOL_ID,
          accessTokenRecordId: tokenContext.tokenRecordId,
          tokenJti: verified.payload.jti!,
          keyId: "test-oauth",
          scopes: tokenContext.scopes,
          roles: tokenContext.roles,
          boardIds: tokenContext.boardIds
        };
        const reads = new PgSurfaceReadRepository(pool, {
          cursorKey: Buffer.alloc(32, 8),
          transaction: { assumeRole: "boardagent_server" }
        });
        const who = await withDirectResponseAllocation(() =>
          reads.executeRead(readPrincipal, "whoami", {
            schema_version: "boardagent.tool-input.v1"
          })
        );
        expect(who.data).toMatchObject({
          recent_auth: {
            proof: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
            session_id: expect.any(String),
            expires_at: expect.any(String)
          }
        });
        const ownSessions = await reads.executeRead(readPrincipal, "list_my_sessions", {
          schema_version: "boardagent.tool-input.v1",
          cursor: null,
          limit: 20
        });
        expect(ownSessions.data).toMatchObject({
          items: expect.arrayContaining([
            expect.objectContaining({ state: "authenticated", client_id: CLIENT_ID })
          ])
        });
        expect(JSON.stringify(ownSessions.data)).not.toContain("opaque_session_sha256");
        const requestScopeVisibility = await withRequestTransaction(
          pool,
          {
            organizationId: ORGANIZATION_ID,
            memberId: MEMBER_ID,
            clientId: CLIENT_ID,
            tokenJti: verified.payload.jti!,
            boardIds: []
          },
          async (client) => {
            const result = await client.query<{ count: string }>(
              `select (
               (select count(*) from auth_sessions)+
               (select count(*) from oauth_authorization_requests)+
               (select count(*) from oauth_authorization_codes)+
               (select count(*) from oauth_consents)
             )::text as count`
            );
            return result.rows[0]?.count;
          },
          { assumeRole: "boardagent_server" }
        );
        expect(requestScopeVisibility).toBe("0");

        const codeReplay = await exchange(codeForm);
        expect(codeReplay.status).toBe(400);
        await expect(codeReplay.json()).resolves.toEqual({ error: "invalid_grant" });

        // Move only the browser authority into the past; the refresh grant remains live.
        await pool.query(
          `update auth_sessions set created_at=transaction_timestamp()-interval '9 hours',
             expires_at=transaction_timestamp()-interval '1 hour',
             last_authenticated_at=transaction_timestamp()-interval '9 hours'
           where id in (select session_id from access_token_records where jti=$1)`,
          [verified.payload.jti]
        );
        await withWorkerTransaction(
          pool,
          (client) =>
            client.query(
              "select boardagent_run_worker_maintenance('oauth_ephemera_expiry',$1,100)",
              [ORGANIZATION_ID]
            ),
          { assumeRole: "boardagent_worker" }
        );
        expect(
          (
            await pool.query<{ state: string }>(
              `select state from auth_sessions where id in
           (select session_id from access_token_records where jti=$1)`,
              [verified.payload.jti]
            )
          ).rows
        ).toEqual([{ state: "expired" }]);
        await expect(authenticate(tokenBody["access_token"] as string)).resolves.toBeDefined();
        const oldAuthentication = await withDirectResponseAllocation(() =>
          reads.executeRead(readPrincipal, "whoami", {
            schema_version: "boardagent.tool-input.v1"
          })
        );
        expect(oldAuthentication.data).toMatchObject({ recent_auth: null });

        const firstRefreshToken = tokenBody["refresh_token"] as string;
        const refreshResponse = await exchange(
          new URLSearchParams({
            grant_type: "refresh_token",
            client_id: CLIENT_PROTOCOL_ID,
            refresh_token: firstRefreshToken,
            resource: RESOURCE
          })
        );
        expect(refreshResponse.status).toBe(200);
        const refreshedBody = (await refreshResponse.json()) as Record<string, unknown>;
        expect(refreshedBody).toMatchObject({
          access_token: expect.any(String),
          refresh_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
          token_type: "Bearer",
          expires_in: 900
        });
        expect(refreshedBody["refresh_token"]).not.toBe(firstRefreshToken);
        await expect(authenticate(refreshedBody["access_token"] as string)).resolves.toBeDefined();

        const reuse = await exchange(
          new URLSearchParams({
            grant_type: "refresh_token",
            client_id: CLIENT_PROTOCOL_ID,
            refresh_token: firstRefreshToken,
            resource: RESOURCE
          })
        );
        expect(reuse.status).toBe(400);
        await expect(reuse.json()).resolves.toEqual({ error: "invalid_grant" });
        const family = await pool.query<{
          state: string;
          live_refresh: string;
          live_access: string;
        }>(
          `select family.state,
                (select count(*)::text from refresh_tokens as token
                  where token.family_id=family.id and token.used_at is null
                    and token.revoked_at is null) as live_refresh,
                (select count(*)::text from access_token_records as access
                  where access.refresh_family_id=family.id and access.revoked_at is null)
                  as live_access
           from refresh_families as family where family.organization_id=$1`,
          [ORGANIZATION_ID]
        );
        expect(family.rows).toEqual([
          { state: "compromised", live_refresh: "0", live_access: "0" }
        ]);
      });
    }
  );

  it("does not reuse a browser session authenticated for one client when another client authorizes", async () => {
    // Observed live on 14 September 2026: Claude Code re-registered (a new DCR client) while
    // the admin's browser still held the provider session from the first client; /authorize
    // answered 500 ("OIDC session principal binding failed"). A provider session belongs to
    // the client it was authenticated for; another client must get a fresh login.
    const SECOND_CLIENT_ID = testId(7_700);
    const SECOND_PROTOCOL_ID = "https://second-client.test/client.json";
    const SECOND_REDIRECT_URI = "https://second-client.test/callback";
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      await pool.query(
        `insert into oauth_clients(
           id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,state
         ) values ($1,$2,'verified_cimd_url',$3,$4,$5,'active')`,
        [
          SECOND_CLIENT_ID,
          ORGANIZATION_ID,
          SECOND_PROTOCOL_ID,
          { name: "Second client" },
          testHash(77)
        ]
      );
      await pool.query(
        "insert into oauth_client_redirect_uris(client_id,redirect_uri,redirect_uri_sha256) values ($1,$2,$3)",
        [
          SECOND_CLIENT_ID,
          SECOND_REDIRECT_URI,
          createHash("sha256").update(SECOND_REDIRECT_URI).digest()
        ]
      );
      for (const grantType of ["authorization_code", "refresh_token"] as const) {
        for (const scope of ["documents:read", "governance:read", "onboarding:read"] as const) {
          await pool.query(
            "insert into oauth_client_grants(client_id,grant_type,scope) values ($1,$2,$3)",
            [SECOND_CLIENT_ID, grantType, scope]
          );
        }
      }
      const activeRuntime = runtime(pool, REDIRECT_URI, [
        { clientId: SECOND_PROTOCOL_ID, redirectUris: [SECOND_REDIRECT_URI] }
      ]);
      const webauthnCrypto = fakeWebAuthnCrypto();
      const webauthn = new WebAuthnCeremony({
        rpName: "BoardAgent",
        rpId: "boardagent.test",
        origin: ISSUER,
        store: new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" }),
        attemptLimiter: allowAllWebAuthnAttempts,
        crypto: webauthnCrypto.crypto,
        newId: idSequence(77_100)
      });
      const interactionHandler = createBoardAgentOAuthInteractionHandler({
        organizationId: ORGANIZATION_ID,
        boundary: new AuthRequestBoundary({ origin: ISSUER }),
        provider: activeRuntime.provider,
        bindingStore: activeRuntime.persistence.interactionBindingStore,
        webauthn,
        includeHsts: true
      });
      const base = await listen(activeRuntime.provider, interactionHandler);
      const jar = new PathCookieJar();

      const loginAndConsent = async (
        clientId: string,
        redirectUri: string
      ): Promise<{ readonly callback: URL; readonly loginPage: string }> => {
        const started = await fetchWithCookies(
          jar,
          authorize(base, "documents:read governance:read", redirectUri, clientId)
        );
        expect(started.status).toBe(303);
        const interactionTarget = new URL(started.headers.get("location")!, base);
        expect(interactionTarget.pathname).toMatch(/^\/auth\/interactions\//u);
        const page = await fetchWithCookies(jar, interactionTarget);
        expect(page.status).toBe(200);
        const loginPage = await page.text();
        const csrfToken = csrfFromPage(loginPage);
        expect(
          (
            await postForm(jar, new URL(`${interactionTarget.pathname}/passkey/begin`, base), {
              csrf_token: csrfToken
            })
          ).status
        ).toBe(200);
        let response = await postForm(
          jar,
          new URL(`${interactionTarget.pathname}/passkey/complete`, base),
          { csrf_token: csrfToken, credential: JSON.stringify(authenticationResponse) }
        );
        expect(response.status).toBe(303);
        const loginResume = new URL(response.headers.get("location")!, ISSUER);
        response = await fetchWithCookies(
          jar,
          new URL(`${loginResume.pathname}${loginResume.search}`, base)
        );
        expect(response.status).toBe(303);
        const consentTarget = new URL(response.headers.get("location")!, base);
        const consentPage = await fetchWithCookies(jar, consentTarget);
        expect(consentPage.status).toBe(200);
        const consentHtml = await consentPage.text();
        expect(consentHtml).toContain("Authorize access");
        response = await postForm(jar, new URL(`${consentTarget.pathname}/consent`, base), {
          csrf_token: csrfFromPage(consentHtml)
        });
        for (let redirects = 0; redirects < 8; redirects += 1) {
          expect(response.status).toBe(303);
          const logicalTarget = new URL(response.headers.get("location")!, ISSUER);
          if (logicalTarget.origin === new URL(redirectUri).origin) {
            return { callback: logicalTarget, loginPage };
          }
          response = await fetchWithCookies(
            jar,
            new URL(`${logicalTarget.pathname}${logicalTarget.search}`, base)
          );
        }
        throw new Error("OAuth continuation never reached the client");
      };

      const first = await loginAndConsent(CLIENT_PROTOCOL_ID, REDIRECT_URI);
      expect(first.callback.searchParams.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(webauthnCrypto.authenticationCalls).toHaveLength(1);

      // The fake authenticator answers a fixed challenge with a fixed signature counter;
      // the consumed row and the advanced counter from the first ceremony would otherwise
      // make the second look like a replay. Reset only those two fixture artefacts.
      await pool.query("delete from webauthn_challenges where consumed_at is not null");
      await pool.query("update webauthn_credentials set signature_counter=0 where member_id=$1", [
        MEMBER_ID
      ]);

      // Same browser (same cookie jar), a different client: a fresh passkey login is
      // required; the first client's session is neither reused nor a server error.
      const second = await loginAndConsent(SECOND_PROTOCOL_ID, SECOND_REDIRECT_URI);
      expect(second.loginPage).toContain("/auth/webauthn.js");
      expect(second.callback.searchParams.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(webauthnCrypto.authenticationCalls).toHaveLength(2);
      expect(
        (
          await pool.query(
            `select client_id,member_id from auth_sessions
              where state='authenticated' order by created_at`
          )
        ).rows
      ).toEqual([
        { client_id: CLIENT_ID, member_id: MEMBER_ID },
        { client_id: SECOND_CLIENT_ID, member_id: MEMBER_ID }
      ]);
      expect(
        (
          await pool.query(
            `select request_state,member_id is not null as bound from oauth_authorization_requests
              order by created_at`
          )
        ).rows
      ).toEqual([
        { request_state: "approved", bound: true },
        { request_state: "approved", bound: true }
      ]);
    });
  });

  it("keeps the initiating PKCE request pending until secretary activation, then resumes it", async () => {
    await withDatabase(async (pool) => {
      await seedIdentity(pool, "pending_activation");
      const activation = await seedPendingActivationAuthority(pool);
      const activeRuntime = runtime(pool);
      const webauthnCrypto = fakeWebAuthnCrypto();
      const webauthn = new WebAuthnCeremony({
        rpName: "BoardAgent",
        rpId: "boardagent.test",
        origin: ISSUER,
        store: new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" }),
        attemptLimiter: allowAllWebAuthnAttempts,
        crypto: webauthnCrypto.crypto,
        newId: idSequence(73_100)
      });
      const interactionHandler = createBoardAgentOAuthInteractionHandler({
        organizationId: ORGANIZATION_ID,
        boundary: new AuthRequestBoundary({ origin: ISSUER }),
        provider: activeRuntime.provider,
        bindingStore: activeRuntime.persistence.interactionBindingStore,
        webauthn,
        includeHsts: true
      });
      const base = await listen(activeRuntime.provider, interactionHandler);
      const jar = new PathCookieJar();
      const started = await fetchWithCookies(jar, authorize(base, "onboarding:read"));
      expect(started.status).toBe(303);
      const interactionLocation = started.headers.get("location");
      expect(interactionLocation).toMatch(/^\/auth\/interactions\//u);
      const interactionTarget = new URL(interactionLocation!, base);
      const page = await fetchWithCookies(jar, interactionTarget);
      expect(page.status).toBe(200);
      const csrfToken = csrfFromPage(await page.text());
      const begin = await postForm(
        jar,
        new URL(`${interactionTarget.pathname}/passkey/begin`, base),
        { csrf_token: csrfToken }
      );
      expect(begin.status).toBe(200);

      const pendingAttempt = await postForm(
        jar,
        new URL(`${interactionTarget.pathname}/passkey/complete`, base),
        { csrf_token: csrfToken, credential: JSON.stringify(authenticationResponse) }
      );
      expect(pendingAttempt.status).toBe(400);
      await expect(pendingAttempt.json()).resolves.toEqual({ error: "invalid_auth_request" });
      expect(webauthnCrypto.authenticationCalls).toHaveLength(0);
      expect(
        await pool.query(
          `select request.request_state,request.member_id,
                  (select count(*)::int from oauth_authorization_codes) as codes,
                  (select signature_counter::text from webauthn_credentials
                    where member_id=$2) as counter,
                  (select consumed_at from webauthn_challenges
                    where purpose='authentication') as challenge_consumed_at
             from oauth_authorization_requests as request
            where request.organization_id=$1`,
          [ORGANIZATION_ID, MEMBER_ID]
        )
      ).toMatchObject({
        rows: [
          {
            request_state: "pending",
            member_id: null,
            codes: 0,
            counter: "0",
            challenge_consumed_at: null
          }
        ]
      });

      const activated = await withIdentityTransaction(
        pool,
        { organizationId: ORGANIZATION_ID, boardIds: [activation.boardId] },
        (client) =>
          activateEnrollmentInTransaction(client, {
            organizationId: ORGANIZATION_ID,
            memberId: MEMBER_ID,
            invitationId: activation.invitationId,
            challengeId: activation.activationChallengeId,
            protectedCodeSha256: activation.activationCodeSha256,
            proofingMethod: "verified_number_call",
            secretaryMemberId: activation.secretaryMemberId,
            secretarySessionId: activation.secretarySessionId,
            feedEntries: [{ boardId: activation.boardId, feedId: testId(73_008) }],
            auditEventId: testId(73_009)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(activated).toMatchObject({ activated: true, memberId: MEMBER_ID });

      let response = await postForm(
        jar,
        new URL(`${interactionTarget.pathname}/passkey/complete`, base),
        { csrf_token: csrfToken, credential: JSON.stringify(authenticationResponse) }
      );
      expect(response.status).toBe(303);
      expect(webauthnCrypto.authenticationCalls).toHaveLength(1);
      const loginResume = new URL(response.headers.get("location")!, ISSUER);
      response = await fetchWithCookies(
        jar,
        new URL(`${loginResume.pathname}${loginResume.search}`, base)
      );
      expect(response.status).toBe(303);
      const consentLocation = response.headers.get("location");
      expect(consentLocation).toMatch(/^\/auth\/interactions\//u);
      const consentTarget = new URL(consentLocation!, base);
      const consentPage = await fetchWithCookies(jar, consentTarget);
      expect(consentPage.status).toBe(200);
      const consentHtml = await consentPage.text();
      expect(consentHtml).toContain("onboarding:read");
      response = await postForm(jar, new URL(`${consentTarget.pathname}/consent`, base), {
        csrf_token: csrfFromPage(consentHtml)
      });

      let callback: URL | undefined;
      for (let redirects = 0; redirects < 8; redirects += 1) {
        expect(response.status).toBe(303);
        const location = response.headers.get("location");
        if (!location) throw new Error("OAuth continuation has no location");
        const logicalTarget = new URL(location, ISSUER);
        if (logicalTarget.origin === new URL(REDIRECT_URI).origin) {
          callback = logicalTarget;
          break;
        }
        response = await fetchWithCookies(
          jar,
          new URL(`${logicalTarget.pathname}${logicalTarget.search}`, base)
        );
      }
      expect(callback?.searchParams.get("state")).toBe(STATE);
      const code = callback?.searchParams.get("code");
      expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      const tokenResponse = await fetch(new URL("/token", base), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: CLIENT_PROTOCOL_ID,
          redirect_uri: REDIRECT_URI,
          code: code!,
          code_verifier: PKCE_VERIFIER,
          resource: RESOURCE
        })
      });
      expect(tokenResponse.status).toBe(200);
      const token = (await tokenResponse.json()) as Record<string, unknown>;
      expect(token).toMatchObject({
        access_token: expect.any(String),
        refresh_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
        scope: "onboarding:read"
      });
      const verificationKey = await importJWK(publicJwk as JWK & { readonly kty: "EC" }, "ES256");
      await expect(
        jwtVerify(token["access_token"] as string, verificationKey, {
          algorithms: ["ES256"],
          issuer: ISSUER,
          audience: RESOURCE
        })
      ).resolves.toMatchObject({ payload: { sub: MEMBER_ID, scope: "onboarding:read" } });
      expect(
        await pool.query<{ event_type: string }>(
          "select event_type from audit_events order by sequence"
        )
      ).toMatchObject({
        rows: [{ event_type: "member_activated" }, { event_type: "token_issued" }]
      });
    });
  });

  it("gives an uninvited stranger neither an OAuth principal nor a token", async () => {
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      const activeRuntime = runtime(pool);
      const webauthnCrypto = fakeWebAuthnCrypto();
      const webauthn = new WebAuthnCeremony({
        rpName: "BoardAgent",
        rpId: "boardagent.test",
        origin: ISSUER,
        store: new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" }),
        attemptLimiter: allowAllWebAuthnAttempts,
        crypto: webauthnCrypto.crypto,
        newId: idSequence(74_100)
      });
      const interactionHandler = createBoardAgentOAuthInteractionHandler({
        organizationId: ORGANIZATION_ID,
        boundary: new AuthRequestBoundary({ origin: ISSUER }),
        provider: activeRuntime.provider,
        bindingStore: activeRuntime.persistence.interactionBindingStore,
        webauthn,
        includeHsts: true
      });
      const base = await listen(activeRuntime.provider, interactionHandler);
      const jar = new PathCookieJar();
      const started = await fetchWithCookies(jar, authorize(base));
      expect(started.status).toBe(303);
      const interactionLocation = started.headers.get("location");
      expect(interactionLocation).toMatch(/^\/auth\/interactions\//u);
      const interactionTarget = new URL(interactionLocation!, base);
      const page = await fetchWithCookies(jar, interactionTarget);
      const csrfToken = csrfFromPage(await page.text());
      const begin = await postForm(
        jar,
        new URL(`${interactionTarget.pathname}/passkey/begin`, base),
        { csrf_token: csrfToken }
      );
      expect(begin.status).toBe(200);
      const unknownCredentialId = Buffer.alloc(32, 0xee).toString("base64url");
      const unknownCredential = {
        ...authenticationResponse,
        id: unknownCredentialId,
        rawId: unknownCredentialId
      };
      const login = await postForm(
        jar,
        new URL(`${interactionTarget.pathname}/passkey/complete`, base),
        { csrf_token: csrfToken, credential: JSON.stringify(unknownCredential) }
      );
      expect(login.status).toBe(400);
      await expect(login.json()).resolves.toEqual({ error: "invalid_auth_request" });
      expect(webauthnCrypto.authenticationCalls).toHaveLength(0);

      const guessedCode = Buffer.alloc(32, 0xef).toString("base64url");
      const exchange = await fetch(new URL("/token", base), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: CLIENT_PROTOCOL_ID,
          redirect_uri: REDIRECT_URI,
          code: guessedCode,
          code_verifier: PKCE_VERIFIER,
          resource: RESOURCE
        })
      });
      expect(exchange.status).toBe(400);
      await expect(exchange.json()).resolves.toEqual({ error: "invalid_grant" });
      expect(
        await pool.query(
          `select request.request_state,request.member_id,
                  (select count(*)::int from oauth_authorization_codes) as codes,
                  (select count(*)::int from oauth_consents) as consents,
                  (select count(*)::int from access_token_records) as access_tokens,
                  (select count(*)::int from refresh_families) as refresh_families,
                  (select consumed_at from webauthn_challenges
                    where purpose='authentication') as challenge_consumed_at
             from oauth_authorization_requests as request
            where request.organization_id=$1`,
          [ORGANIZATION_ID]
        )
      ).toMatchObject({
        rows: [
          {
            request_state: "pending",
            member_id: null,
            codes: 0,
            consents: 0,
            access_tokens: 0,
            refresh_families: 0,
            challenge_consumed_at: null
          }
        ]
      });
    });
  });

  it("persists an explicit browser denial and returns only the bound OAuth error", async () => {
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      const activeRuntime = runtime(pool);
      const webauthn = new WebAuthnCeremony({
        rpName: "BoardAgent",
        rpId: "boardagent.test",
        origin: ISSUER,
        store: new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" }),
        attemptLimiter: allowAllWebAuthnAttempts,
        crypto: fakeWebAuthnCrypto().crypto,
        newId: idSequence(68_000)
      });
      const interactionHandler = createBoardAgentOAuthInteractionHandler({
        organizationId: ORGANIZATION_ID,
        boundary: new AuthRequestBoundary({ origin: ISSUER }),
        provider: activeRuntime.provider,
        bindingStore: activeRuntime.persistence.interactionBindingStore,
        webauthn,
        includeHsts: true
      });
      const base = await listen(activeRuntime.provider, interactionHandler);
      const jar = new PathCookieJar();
      const started = await fetchWithCookies(jar, authorize(base));
      expect(started.status).toBe(303);
      const interactionLocation = started.headers.get("location");
      expect(interactionLocation).toMatch(/^\/auth\/interactions\//u);
      const interactionTarget = new URL(interactionLocation!, base);
      const page = await fetchWithCookies(jar, interactionTarget);
      expect(page.status).toBe(200);
      const denied = await postForm(jar, new URL(`${interactionTarget.pathname}/cancel`, base), {
        csrf_token: csrfFromPage(await page.text())
      });
      expect(denied.status).toBe(303);
      const resume = new URL(denied.headers.get("location")!, ISSUER);
      const callbackResponse = await fetchWithCookies(
        jar,
        new URL(`${resume.pathname}${resume.search}`, base)
      );
      expect(callbackResponse.status).toBe(303);
      const callback = new URL(callbackResponse.headers.get("location")!, ISSUER);
      expect(callback.origin).toBe(new URL(REDIRECT_URI).origin);
      expect(callback.searchParams.get("error")).toBe("access_denied");
      expect(callback.searchParams.get("state")).toBe(STATE);
      expect(callback.searchParams.get("code")).toBeNull();
      expect(
        await pool.query(
          `select request_state,member_id from oauth_authorization_requests
            where organization_id=$1`,
          [ORGANIZATION_ID]
        )
      ).toMatchObject({ rows: [{ request_state: "denied", member_id: null }] });
      expect(
        await pool.query(
          `select (select count(*)::int from oauth_authorization_codes) as codes,
                  (select count(*)::int from oauth_consents) as consents`
        )
      ).toMatchObject({ rows: [{ codes: 0, consents: 0 }] });

      const replayedPage = await fetchWithCookies(jar, interactionTarget);
      expect(replayedPage.status).toBe(400);
      await expect(replayedPage.json()).resolves.toEqual({ error: "invalid_auth_request" });
    });
  });
});
