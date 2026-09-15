import path from "node:path";
import { createServer, type Server } from "node:http";

import { exportJWK, generateKeyPair } from "jose";
import { Pool } from "pg";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  AuthRequestBoundary,
  ClientRegistrationError,
  clientAdmissionAllowed,
  createBoardAgentOAuthProvider,
  createOAuthClientRegistrationEndpoint,
  createPgOidcProviderPersistence,
  isPublicCimdAddress,
  parseClientAllowlist,
  parseDcrClientMetadata,
  PgOAuthClientRegistrar,
  PgRateLimiter,
  resolveCimdClientMetadata,
  validateCimdClientId,
  validateOAuthRedirectUri,
  type CimdDocumentFetcher,
  type CimdHostResolver
} from "../../artifacts/server/src/index.js";
import { migrate, withIdentityTransaction } from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

const CIMD_ID = "https://client.example/.well-known/oauth-client";
const WEB_REDIRECT = "https://client.example/oauth/callback";
const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const ORGANIZATION_ID = testId(75_001);
let databaseCounter = 0;
let registrarIdCounter = 75_100;
let registrarEntropyCounter = 0x41;
let privateJwk: Readonly<Record<string, unknown>>;
const activeServers: Server[] = [];

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  privateJwk = {
    ...(await exportJWK(privateKey)),
    kid: "registration-oauth-key",
    use: "sig",
    alg: "ES256"
  };
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

function metadata(clientId: string = CIMD_ID): Readonly<Record<string, unknown>> {
  return {
    client_id: clientId,
    client_name: "Portable client",
    redirect_uris: [WEB_REDIRECT],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope: "documents:read governance:read",
    software_id: "self-asserted-only"
  };
}

function dcrMetadata(): Readonly<Record<string, unknown>> {
  const { client_id: _clientId, ...dcr } = metadata();
  return dcr;
}

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_client_registration_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "client-registration-test");
    await pool.query(
      "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
      [ORGANIZATION_ID]
    );
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

function registrar(
  pool: Pool,
  overrides: Partial<ConstructorParameters<typeof PgOAuthClientRegistrar>[1]> = {}
): PgOAuthClientRegistrar {
  return new PgOAuthClientRegistrar(pool, {
    organizationId: ORGANIZATION_ID,
    allowedScopes: ["documents:read", "governance:read"],
    maxClients: 10,
    rateLimiter: new PgRateLimiter(pool, {
      hmacKey: Buffer.alloc(32, 0x52),
      assumeRole: "boardagent_server"
    }),
    rateLimit: { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 },
    assumeRole: "boardagent_server",
    newId: () => testId(registrarIdCounter++),
    randomBytes: (size) => Buffer.alloc(size, registrarEntropyCounter++ % 256),
    ...overrides
  });
}

async function listen(
  callback: ReturnType<typeof createBoardAgentOAuthProvider>["callback"] extends () => infer T
    ? T
    : never
): Promise<URL> {
  const server = createServer((request, response) => {
    Object.defineProperty(request.socket, "encrypted", { configurable: true, value: true });
    request.headers.host = "boardagent.test";
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      if (request.rawHeaders[index]?.toLowerCase() === "host") {
        request.rawHeaders[index + 1] = "boardagent.test";
      }
    }
    callback(request, response);
  });
  activeServers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("registration server has no port");
  return new URL(`http://127.0.0.1:${String(address.port)}`);
}

describe("typed OAuth client registration boundaries", () => {
  it("accepts exact HTTPS, loopback, and private-use native redirects only", () => {
    expect(validateOAuthRedirectUri(WEB_REDIRECT)).toBe(WEB_REDIRECT);
    expect(validateOAuthRedirectUri("http://127.0.0.1:49152/callback")).toBe(
      "http://127.0.0.1:49152/callback"
    );
    // `localhost` with an explicit port is a loopback callback too (RFC 8252 §7.3); it is
    // what Claude Code registers.
    expect(validateOAuthRedirectUri("http://localhost:49152/callback")).toBe(
      "http://localhost:49152/callback"
    );
    expect(validateOAuthRedirectUri("com.example.client:/oauth/callback")).toBe(
      "com.example.client:/oauth/callback"
    );
    for (const refused of [
      "http://client.example/callback",
      "http://localhost/callback",
      "http://app.localhost:49152/callback",
      "http://127.0.0.1/callback",
      "https://user@client.example/callback",
      "https://client.example/callback#fragment",
      "example:/callback"
    ]) {
      expect(() => validateOAuthRedirectUri(refused)).toThrow(ClientRegistrationError);
    }
  });

  it("rejects local, special-purpose, mapped, and ambiguous CIMD addresses", () => {
    expect(isPublicCimdAddress("8.8.8.8")).toBe(true);
    expect(isPublicCimdAddress("2606:4700:4700::1111")).toBe(true);
    for (const refused of [
      "0.0.0.0",
      "10.0.0.1",
      "100.64.0.1",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "192.168.0.1",
      "198.18.0.1",
      "203.0.113.20",
      "224.0.0.1",
      "::",
      "::1",
      "::ffff:127.0.0.1",
      "64:ff9b::7f00:1",
      "2001:db8::1",
      "fc00::1",
      "fe80::1",
      "ff02::1",
      "not-an-address"
    ]) {
      expect(isPublicCimdAddress(refused), refused).toBe(false);
    }
  });

  it("requires one canonical fetchable CIMD URL", () => {
    expect(validateCimdClientId(CIMD_ID)).toBe(CIMD_ID);
    for (const refused of [
      "http://client.example/meta",
      "https://127.0.0.1/meta",
      "https://localhost/meta",
      "https://client.example:444/meta",
      "https://client.example/meta?version=1",
      "https://client.example/meta#fragment",
      "https://USER@client.example/meta",
      "https://CLIENT.example/meta"
    ]) {
      expect(() => validateCimdClientId(refused)).toThrow(ClientRegistrationError);
    }
  });

  it("strictly parses DCR metadata and never accepts an asserted client_id", () => {
    const { client_id: _clientId, ...dcr } = metadata();
    expect(
      parseDcrClientMetadata(JSON.stringify(dcr), ["documents:read", "governance:read"])
    ).toMatchObject({
      clientName: "Portable client",
      redirectUris: [WEB_REDIRECT],
      scopes: ["documents:read", "governance:read"]
    });
    // A released native client (Claude Code 2.1.270) registers with a `localhost`
    // loopback callback and copies the authorization-server metadata's scope list, which
    // the OpenID library pads with `openid`. The callback is accepted, `openid` is dropped
    // and the registered scopes are stated; any other unknown scope still refuses.
    // Captured verbatim from Claude Code 2.1.270 on 14 September 2026 (only the scope
    // list and port differ per instance): the informational `application_type` field is
    // part of the request and must be accepted, as must the other RFC 7591 §2 fields.
    const claudeCode = {
      client_name: "Claude Code (boardagent)",
      redirect_uris: ["http://localhost:52341/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      application_type: "native",
      scope: "documents:read governance:read openid"
    };
    expect(
      parseDcrClientMetadata(
        JSON.stringify({
          ...claudeCode,
          client_uri: "https://claude.com/claude-code",
          logo_uri: "https://claude.com/logo.png",
          tos_uri: "https://claude.com/terms",
          policy_uri: "https://claude.com/privacy",
          contacts: ["support@example.com"],
          software_version: "2.1.270"
        }),
        ["documents:read", "governance:read"]
      )
    ).toMatchObject({ clientName: "Claude Code (boardagent)" });
    for (const refused of [
      { application_type: "spa" },
      { client_uri: "http://claude.com/claude-code" },
      { contacts: Array.from({ length: 11 }, () => "x@example.com") },
      { software_statement: "eyJ..." },
      { jwks_uri: "https://claude.com/jwks.json" }
    ]) {
      expect(() =>
        parseDcrClientMetadata(JSON.stringify({ ...claudeCode, ...refused }), [
          "documents:read",
          "governance:read"
        ])
      ).toThrow(ClientRegistrationError);
    }
    expect(
      parseDcrClientMetadata(JSON.stringify(claudeCode), ["documents:read", "governance:read"])
    ).toMatchObject({
      clientName: "Claude Code (boardagent)",
      redirectUris: ["http://localhost:52341/callback"],
      scopes: ["documents:read", "governance:read"]
    });
    expect(() =>
      parseDcrClientMetadata(JSON.stringify({ ...claudeCode, scope: "openid" }), ["documents:read"])
    ).toThrow(ClientRegistrationError);
    expect(() =>
      parseDcrClientMetadata(
        JSON.stringify({ ...claudeCode, scope: "documents:read offline_access" }),
        ["documents:read", "governance:read"]
      )
    ).toThrow(ClientRegistrationError);
    expect(() =>
      parseDcrClientMetadata(JSON.stringify(metadata()), ["documents:read", "governance:read"])
    ).toThrow(ClientRegistrationError);
    expect(() =>
      parseDcrClientMetadata('{"client_name":"one","client_name":"two","redirect_uris":[]}', [
        "documents:read"
      ])
    ).toThrow(ClientRegistrationError);
  });

  it("pins one all-public DNS snapshot and refuses redirect, oversize, and ID mismatch", async () => {
    const resolver: CimdHostResolver = async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "2606:4700:4700::1111", family: 6 }
    ];
    const seen: Array<readonly string[]> = [];
    const fetcher: CimdDocumentFetcher = async ({ pinnedAddresses }) => {
      seen.push(pinnedAddresses.map(({ address }) => address));
      return {
        statusCode: 200,
        contentType: "application/json",
        body: Buffer.from(JSON.stringify(metadata()), "utf8")
      };
    };
    await expect(
      resolveCimdClientMetadata(CIMD_ID, ["documents:read", "governance:read"], {
        resolver,
        fetcher
      })
    ).resolves.toMatchObject({ clientId: CIMD_ID, clientName: "Portable client" });
    expect(seen).toEqual([["8.8.8.8", "2606:4700:4700::1111"]]);

    const privateResolver: CimdHostResolver = async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "10.0.0.2", family: 4 }
    ];
    await expect(
      resolveCimdClientMetadata(CIMD_ID, ["documents:read", "governance:read"], {
        resolver: privateResolver,
        fetcher
      })
    ).rejects.toMatchObject({ code: "cimd_address_refused" });

    // Public static hosts add the redundant charset parameter; only that one is tolerated.
    await expect(
      resolveCimdClientMetadata(CIMD_ID, ["documents:read", "governance:read"], {
        resolver,
        fetcher: async () => ({
          statusCode: 200,
          contentType: "application/json; charset=utf-8",
          body: Buffer.from(JSON.stringify(metadata()), "utf8")
        })
      })
    ).resolves.toMatchObject({ clientId: CIMD_ID });

    for (const response of [
      { statusCode: 302, contentType: "application/json", body: Buffer.alloc(0) },
      {
        statusCode: 200,
        contentType: "application/json",
        body: Buffer.alloc(32 * 1024 + 1)
      },
      {
        statusCode: 200,
        contentType: "application/json",
        body: Buffer.from(JSON.stringify(metadata("https://other.example/client")), "utf8")
      },
      {
        statusCode: 200,
        contentType: "text/plain; charset=utf-8",
        body: Buffer.from(JSON.stringify(metadata()), "utf8")
      },
      {
        statusCode: 200,
        contentType: "application/json; charset=iso-8859-1",
        body: Buffer.from(JSON.stringify(metadata()), "utf8")
      },
      {
        statusCode: 200,
        contentType: "application/json; charset=utf-8; boundary=x",
        body: Buffer.from(JSON.stringify(metadata()), "utf8")
      },
      {
        statusCode: 200,
        contentType: "application/json+x",
        body: Buffer.from(JSON.stringify(metadata()), "utf8")
      }
    ]) {
      await expect(
        resolveCimdClientMetadata(CIMD_ID, ["documents:read", "governance:read"], {
          resolver,
          fetcher: async () => response
        })
      ).rejects.toBeInstanceOf(ClientRegistrationError);
    }
  });

  it("allowlists only the exact typed protocol identifier", () => {
    const allowlist = parseClientAllowlist([
      { kind: "verified_cimd_url", value: CIMD_ID },
      { kind: "dcr_opaque", value: `ba_dcr_${"A".repeat(43)}` }
    ]);
    expect(
      clientAdmissionAllowed(
        { kind: "verified_cimd_url", value: CIMD_ID },
        allowlist,
        "self-asserted-only"
      )
    ).toBe(true);
    expect(
      clientAdmissionAllowed(
        { kind: "verified_cimd_url", value: CIMD_ID },
        parseClientAllowlist([{ kind: "preregistered", value: CIMD_ID }]),
        "self-asserted-only"
      )
    ).toBe(false);
    expect(
      clientAdmissionAllowed(
        { kind: "verified_cimd_url", value: CIMD_ID },
        parseClientAllowlist([{ kind: "verified_cimd_url", value: "https://other.example/c" }]),
        "self-asserted-only"
      )
    ).toBe(false);
  });

  it("persists DCR under a narrow database function and emits canonical audit evidence", async () => {
    await withDatabase(async (pool) => {
      const registration = await registrar(pool).registerDcr({
        clientIpClass: "ipv4:198.51.100.0/24",
        body: Buffer.from(JSON.stringify(dcrMetadata()), "utf8")
      });
      expect(registration).toMatchObject({
        internalClientId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
        protocolIdKind: "dcr_opaque",
        protocolClientId: expect.stringMatching(/^ba_dcr_[A-Za-z0-9_-]{43}$/u),
        clientName: "Portable client",
        redirectUris: [WEB_REDIRECT],
        scopes: ["documents:read", "governance:read"],
        registered: true
      });
      expect(registration.internalClientId).not.toBe(registration.protocolClientId);

      const rows = await pool.query<{
        id: string;
        protocol_id_kind: string;
        protocol_id_value: string;
        safe_metadata: Record<string, unknown>;
        metadata_sha256: Buffer;
      }>(
        `select id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256
           from oauth_clients`
      );
      expect(rows.rows).toEqual([
        expect.objectContaining({
          id: registration.internalClientId,
          protocol_id_kind: "dcr_opaque",
          protocol_id_value: registration.protocolClientId,
          safe_metadata: {
            name: "Portable client",
            registrationMethod: "dcr",
            schemaVersion: 1,
            softwareId: "self-asserted-only"
          },
          metadata_sha256: expect.any(Buffer)
        })
      ]);
      expect(rows.rows[0]!.metadata_sha256).toHaveLength(32);
      expect(JSON.stringify(rows.rows[0]!.safe_metadata)).not.toContain(WEB_REDIRECT);

      const children = await pool.query<{ kind: string; value: string }>(
        `select 'redirect' as kind,redirect_uri as value from oauth_client_redirect_uris
         union all
         select grant_type as kind,scope as value from oauth_client_grants
         order by kind,value`
      );
      expect(children.rows).toHaveLength(5);
      expect(children.rows).toContainEqual({ kind: "redirect", value: WEB_REDIRECT });

      const audit = await pool.query<{ event_type: string; payload: string }>(
        `select event_type,convert_from(canonical_payload,'UTF8') as payload
           from audit_events order by sequence`
      );
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]!.event_type).toBe("client_registered");
      expect(JSON.parse(audit.rows[0]!.payload)).toMatchObject({
        eventType: "client_registered",
        actorMemberId: null,
        actorClientId: null,
        entityType: "oauth_client",
        entityId: registration.internalClientId,
        origin: "oauth",
        details: {
          protocolIdKind: "dcr_opaque",
          protocolIdSha256: expect.stringMatching(/^[0-9a-f]{64}$/u)
        }
      });

      const persistence = createPgOidcProviderPersistence({
        pool,
        organizationId: ORGANIZATION_ID,
        issuer: "https://boardagent.test",
        resourceUri: "https://boardagent.test/mcp",
        stateEncryptionKey: Buffer.alloc(32, 0x73),
        assumeRole: "boardagent_server"
      });
      const client = await new persistence.adapter("Client").find(registration.protocolClientId);
      expect(client).toMatchObject({
        client_id: registration.protocolClientId,
        redirect_uris: [WEB_REDIRECT],
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: "none"
      });

      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: ORGANIZATION_ID },
          (databaseClient) =>
            databaseClient.query(
              `insert into oauth_clients(
                 id,organization_id,protocol_id_kind,protocol_id_value,
                 safe_metadata,metadata_sha256,state
               ) values ($1,$2,'preregistered','raw-bypass','{}',$3,'active')`,
              [testId(75_999), ORGANIZATION_ID, Buffer.alloc(32)]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied/u);
    });
  });

  it("registers CIMD once, pins resolution, and serializes the organization cap", async () => {
    await withDatabase(async (pool) => {
      let resolutions = 0;
      const resolver: CimdHostResolver = async () => {
        resolutions += 1;
        return [{ address: "8.8.8.8", family: 4 }];
      };
      const fetcher: CimdDocumentFetcher = async ({ pinnedAddresses }) => {
        expect(pinnedAddresses).toEqual([{ address: "8.8.8.8", family: 4 }]);
        return {
          statusCode: 200,
          contentType: "application/json",
          body: Buffer.from(JSON.stringify(metadata()), "utf8")
        };
      };
      const service = registrar(pool, {
        maxClients: 1,
        cimdResolver: resolver,
        cimdFetcher: fetcher
      });
      const first = await service.ensureCimd({
        clientIpClass: "ipv4:8.8.8.0/24",
        clientId: CIMD_ID
      });
      const existing = await service.ensureCimd({
        clientIpClass: "ipv4:8.8.8.0/24",
        clientId: CIMD_ID
      });
      expect(first).toMatchObject({ protocolIdKind: "verified_cimd_url", registered: true });
      expect(existing).toMatchObject({
        internalClientId: first.internalClientId,
        protocolClientId: CIMD_ID,
        registered: false
      });
      expect(resolutions).toBe(1);

      const contenders = [registrar(pool, { maxClients: 1 }), registrar(pool, { maxClients: 1 })];
      const settled = await Promise.allSettled(
        contenders.map((candidate, index) =>
          candidate.registerDcr({
            clientIpClass: `ipv4:1.1.${String(index)}.0/24`,
            body: Buffer.from(JSON.stringify(dcrMetadata()), "utf8")
          })
        )
      );
      expect(settled.every(({ status }) => status === "rejected")).toBe(true);
      for (const outcome of settled) {
        if (outcome.status === "rejected") {
          expect(outcome.reason).toMatchObject({ code: "client_capacity_reached" });
        }
      }
      expect((await pool.query("select 1 from oauth_clients")).rowCount).toBe(1);
      expect(
        (
          await pool.query(
            "select 1 from audit_events where event_type='client_registration_rejected'"
          )
        ).rowCount
      ).toBe(2);
    });
  });

  it("persists the anonymous registration rate across failures and audits every refusal", async () => {
    await withDatabase(async (pool) => {
      const rateLimit = { windowSeconds: 60, maxRequests: 1, blockSeconds: 60 } as const;
      await expect(
        registrar(pool, { rateLimit }).registerDcr({
          clientIpClass: "ipv4:9.9.9.0/24",
          body: Buffer.from("{not-json", "utf8")
        })
      ).rejects.toMatchObject({ code: "invalid_client_metadata" });
      await expect(
        registrar(pool, { rateLimit }).registerDcr({
          clientIpClass: "ipv4:9.9.9.0/24",
          body: Buffer.from(JSON.stringify(dcrMetadata()), "utf8")
        })
      ).rejects.toMatchObject({
        code: "registration_rate_limited",
        statusCode: 429,
        retryAfterSeconds: expect.any(Number)
      });

      expect((await pool.query("select 1 from oauth_clients")).rowCount).toBe(0);
      const bucket = await pool.query<{
        blocked_until: Date | null;
        request_count: number;
      }>(
        `select blocked_until,request_count from rate_limit_buckets
          where bucket_class='registration'`
      );
      expect(bucket.rows).toEqual([{ blocked_until: expect.any(Date), request_count: 2 }]);
      const audit = await pool.query<{ payload: string }>(
        `select convert_from(canonical_payload,'UTF8') as payload
           from audit_events where event_type='client_registration_rejected'
          order by sequence`
      );
      expect(audit.rows.map(({ payload }) => JSON.parse(payload).details.reason)).toEqual([
        "invalid_client_metadata",
        "registration_rate_limited"
      ]);
    });
  });

  it("publishes and serves the bounded DCR endpoint, then resolves CIMD before authorization", async () => {
    await withDatabase(async (pool) => {
      const service = registrar(pool, {
        cimdResolver: async () => [{ address: "8.8.8.8", family: 4 }],
        cimdFetcher: async () => ({
          statusCode: 200,
          contentType: "application/json",
          body: Buffer.from(JSON.stringify(metadata()), "utf8")
        })
      });
      const persistence = createPgOidcProviderPersistence({
        pool,
        organizationId: ORGANIZATION_ID,
        issuer: "https://boardagent.test",
        resourceUri: "https://boardagent.test/mcp",
        stateEncryptionKey: Buffer.alloc(32, 0x73),
        assumeRole: "boardagent_server"
      });
      const registration = createOAuthClientRegistrationEndpoint({
        registrar: service,
        boundary: new AuthRequestBoundary({ origin: "https://boardagent.test" })
      });
      const oauth = createBoardAgentOAuthProvider({
        issuer: "https://boardagent.test",
        resourceUri: "https://boardagent.test/mcp",
        scopes: ["documents:read", "governance:read"],
        clients: [],
        privateJwk,
        cookieKeys: ["c".repeat(32), "d".repeat(32)],
        adapter: persistence.adapter,
        interactionStateStore: persistence.interactionStateStore,
        clientRegistration: registration
      });
      const base = await listen(oauth.callback());

      const discovery = (await (
        await fetch(new URL("/.well-known/openid-configuration", base))
      ).json()) as Record<string, unknown>;
      expect(discovery["registration_endpoint"]).toBe("https://boardagent.test/register");

      const dcrResponse = await fetch(new URL("/register", base), {
        method: "POST",
        headers: { host: "boardagent.test", "content-type": "application/json" },
        body: JSON.stringify(dcrMetadata())
      });
      expect(dcrResponse.status).toBe(201);
      expect(dcrResponse.headers.get("cache-control")).toBe("no-store");
      await expect(dcrResponse.json()).resolves.toMatchObject({
        client_id: expect.stringMatching(/^ba_dcr_[A-Za-z0-9_-]{43}$/u),
        redirect_uris: [WEB_REDIRECT],
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: "none"
      });

      const refused = await fetch(new URL("/register?ignored=true", base), {
        method: "POST",
        headers: { host: "boardagent.test", "content-type": "application/json" },
        body: JSON.stringify(dcrMetadata())
      });
      expect(refused.status).toBe(404);

      const authorization = new URL("/authorize", base);
      for (const [name, value] of Object.entries({
        client_id: CIMD_ID,
        redirect_uri: WEB_REDIRECT,
        response_type: "code",
        scope: "documents:read governance:read",
        state: "state-0123456789abcdef",
        code_challenge: "A".repeat(43),
        code_challenge_method: "S256",
        resource: "https://boardagent.test/mcp"
      })) {
        authorization.searchParams.set(name, value);
      }
      const authorizationResponse = await fetch(authorization, {
        headers: { host: "boardagent.test" },
        redirect: "manual"
      });
      expect(authorizationResponse.status).toBe(303);
      expect(authorizationResponse.headers.get("location")).toMatch(
        /^\/auth\/interactions\/[A-Za-z0-9_-]+$/u
      );
      expect((await pool.query("select 1 from oauth_clients")).rowCount).toBe(2);
    });
  });
});
