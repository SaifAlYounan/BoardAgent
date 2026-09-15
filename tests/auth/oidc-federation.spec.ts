import { createHash } from "node:crypto";
import path from "node:path";

import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { ClientSecretPost, Configuration, customFetch, type CustomFetch } from "openid-client";
import { Pool } from "pg";
import { beforeAll, describe, expect, it } from "vitest";

import {
  discoverUpstreamOidcProfile,
  OidcFederationError,
  OidcFederationService,
  PgOidcFederationStore,
  type OidcInteractionBinding,
  type UpstreamOidcProfile
} from "../../artifacts/server/src/index.js";
import { migrate, withIdentityTransaction } from "../../lib/db/src/index.js";
import { testHash, testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const ORGANIZATION_ID = testId(81_001);
const MEMBER_ID = testId(81_002);
const CLIENT_ID = testId(81_003);
const SESSION_ID = testId(81_004);
const REQUEST_ID = testId(81_005);
const LINK_ID = testId(81_006);
const ISSUER = "https://accounts.identity.example";
const BOARDAGENT_ISSUER = "https://boardagent.test";
const RESOURCE_URI = `${BOARDAGENT_ISSUER}/mcp`;
const PROTOCOL_CLIENT_ID = "https://portable-client.example/client.json";
const INTERACTION_UID = "oidc-interaction-0123456789";
const EXTERNAL_SUBJECT = "stable-external-subject";
let databaseCounter = 0;
let signingKey: CryptoKey;
let publicJwk: Readonly<Record<string, unknown>>;

beforeAll(async () => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  signingKey = pair.privateKey;
  publicJwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: "upstream-signing-key",
    use: "sig",
    alg: "ES256"
  };
});

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_oidc_federation_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    await migrate(pool, MIGRATIONS, "oidc-federation-test");
    await seed(pool);
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seed(pool: Pool): Promise<void> {
  await pool.query(
    "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
    [ORGANIZATION_ID]
  );
  await pool.query(
    "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Member','Member','active')",
    [MEMBER_ID, ORGANIZATION_ID]
  );
  await pool.query(
    `insert into oauth_clients(
       id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,metadata_sha256,state
     ) values ($1,$2,'verified_cimd_url',$3,'{"name":"Client"}',$4,'active')`,
    [CLIENT_ID, ORGANIZATION_ID, PROTOCOL_CLIENT_ID, testHash(81_003)]
  );
  await pool.query(
    `insert into auth_sessions(
       id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at
     ) values ($1,$2,$3,null,$4,'anonymous',$5,transaction_timestamp()+interval '10 minutes')`,
    [SESSION_ID, ORGANIZATION_ID, testHash(81_004), CLIENT_ID, BOARDAGENT_ISSUER]
  );
  await pool.query(
    `insert into oauth_authorization_requests(
       id,organization_id,client_id,resource_uri,redirect_uri,scope_set,member_id,session_id,
       state_hash,request_state,expires_at
     ) values ($1,$2,$3,$4,'https://portable-client.example/callback',
               array['documents:read'],null,$5,$6,'pending',
               transaction_timestamp()+interval '10 minutes')`,
    [REQUEST_ID, ORGANIZATION_ID, CLIENT_ID, RESOURCE_URI, SESSION_ID, testHash(81_005)]
  );
  await pool.query(
    `insert into external_identity_links(
       id,organization_id,member_id,issuer,subject,state,confirmed_by,confirmed_at
     ) values ($1,$2,$3,$4,$5,'active',$3,transaction_timestamp())`,
    [LINK_ID, ORGANIZATION_ID, MEMBER_ID, ISSUER, EXTERNAL_SUBJECT]
  );
}

function binding(overrides: Partial<OidcInteractionBinding> = {}): OidcInteractionBinding {
  return {
    interactionUid: INTERACTION_UID,
    authorizationRequestId: REQUEST_ID,
    sessionId: SESSION_ID,
    clientId: CLIENT_ID,
    protocolClientId: PROTOCOL_CLIENT_ID,
    clientDisplayName: "Portable client",
    resourceUri: RESOURCE_URI,
    scopes: ["documents:read"],
    csrfToken: "c".repeat(43),
    expiresAt: new Date(Date.now() + 600_000),
    ...overrides
  };
}

function cookiePair(setCookie: string): string {
  return setCookie.split(";", 1)[0]!;
}

async function profile(
  options: {
    readonly id?: string;
    readonly kind?: "generic" | "uae_pass";
    readonly subject?: string;
    readonly tokenNonce?: string;
  } = {}
): Promise<{
  readonly profile: UpstreamOidcProfile;
  readonly observed: {
    idToken?: string;
    nonce?: string;
    verifier?: string;
    tokenCalls: number;
  };
}> {
  const providerId = options.id ?? "google";
  const callbackUri = `${BOARDAGENT_ISSUER}/auth/oidc/callback/${providerId}`;
  const observed: {
    idToken?: string;
    nonce?: string;
    verifier?: string;
    tokenCalls: number;
  } = { tokenCalls: 0 };
  const fetcher: CustomFetch = async (input, init) => {
    const request = new Request(input, {
      body: init.body === undefined ? null : (init.body as BodyInit),
      headers: init.headers,
      method: init.method,
      redirect: init.redirect,
      ...(init.signal === undefined ? {} : { signal: init.signal })
    });
    if (request.url === `${ISSUER}/token`) {
      observed.tokenCalls += 1;
      const body = new URLSearchParams(await request.text());
      const verifier = body.get("code_verifier");
      if (verifier !== null) observed.verifier = verifier;
      const idToken = await new SignJWT({
        nonce: options.tokenNonce ?? observed.nonce,
        email: "collision@example.test"
      })
        .setProtectedHeader({ alg: "ES256", kid: "upstream-signing-key" })
        .setIssuer(ISSUER)
        .setSubject(options.subject ?? EXTERNAL_SUBJECT)
        .setAudience("boardagent-upstream-client")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(signingKey);
      observed.idToken = idToken;
      return Response.json({
        access_token: "server-side-upstream-access-token",
        token_type: "Bearer",
        expires_in: 300,
        id_token: idToken
      });
    }
    if (request.url === `${ISSUER}/jwks`) {
      return Response.json({ keys: [publicJwk] });
    }
    return new Response(null, { status: 404 });
  };
  const configuration = new Configuration(
    {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: `${ISSUER}/jwks`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      code_challenge_methods_supported: ["S256"]
    },
    "boardagent-upstream-client",
    {
      client_secret: "upstream-client-secret",
      redirect_uris: [callbackUri],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post"
    },
    ClientSecretPost("upstream-client-secret")
  );
  configuration[customFetch] = fetcher;
  return {
    profile: {
      id: providerId,
      kind: options.kind ?? "generic",
      label: providerId === "google" ? "Google" : "UAE Pass",
      issuer: ISSUER,
      callbackUri,
      configuration
    },
    observed
  };
}

function quotedIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function expectDatabaseToExclude(
  pool: Pool,
  forbiddenValues: readonly string[]
): Promise<void> {
  const columns = await pool.query<{
    column_name: string;
    table_name: string;
    type_name: "bytea" | "json" | "jsonb" | "text" | "varchar" | "bpchar";
  }>(
    `select relation.relname as table_name,attribute.attname as column_name,
            type.typname as type_name
       from pg_catalog.pg_class as relation
       join pg_catalog.pg_namespace as namespace on namespace.oid=relation.relnamespace
       join pg_catalog.pg_attribute as attribute on attribute.attrelid=relation.oid
       join pg_catalog.pg_type as type on type.oid=attribute.atttypid
      where namespace.nspname='public' and relation.relkind in ('r','p')
        and attribute.attnum>0 and not attribute.attisdropped
        and type.typname in ('bytea','json','jsonb','text','varchar','bpchar')
      order by relation.relname,attribute.attname`
  );
  for (const value of forbiddenValues) {
    expect(value.length).toBeGreaterThan(0);
    for (const column of columns.rows) {
      const table = quotedIdentifier(column.table_name);
      const name = quotedIdentifier(column.column_name);
      const expression =
        column.type_name === "bytea" ? `encode(${name},'escape')` : `${name}::text`;
      const found = await pool.query<{ found: boolean }>(
        `select exists(select 1 from public.${table} where ${expression}= $1 or ${expression} like $2) as found`,
        [value, `%${value}%`]
      );
      expect(found.rows[0]?.found, `${column.table_name}.${column.column_name}`).toBe(false);
    }
  }
}

function service(
  pool: Pool,
  upstream: UpstreamOidcProfile,
  firstId = 81_100
): OidcFederationService {
  let id = firstId;
  return new OidcFederationService({
    profiles: [upstream],
    store: new PgOidcFederationStore(pool, {
      organizationId: ORGANIZATION_ID,
      assumeRole: "boardagent_server"
    }),
    cookieEncryptionKey: Buffer.alloc(32, 0x4f),
    newId: () => testId(id++),
    randomBytes: (size) => Buffer.alloc(size, 0x51)
  });
}

function callbackUrl(providerId: string, state: string, issuer = ISSUER): URL {
  const callback = new URL(`${BOARDAGENT_ISSUER}/auth/oidc/callback/${providerId}`);
  callback.searchParams.set("code", "one-use-upstream-code");
  callback.searchParams.set("state", state);
  callback.searchParams.set("iss", issuer);
  return callback;
}

describe("upstream OIDC federation", () => {
  it("discovers only an exact configured issuer with code and S256 support", async () => {
    const requests: string[] = [];
    const fetcher: CustomFetch = async (input) => {
      const url = new Request(input).url;
      requests.push(url);
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        code_challenge_methods_supported: ["S256"]
      });
    };

    await expect(
      discoverUpstreamOidcProfile({
        id: "google",
        kind: "generic",
        label: "Google",
        issuer: ISSUER,
        callbackUri: `${BOARDAGENT_ISSUER}/auth/oidc/callback/google`,
        clientId: "boardagent-upstream-client",
        clientSecret: "s".repeat(32),
        fetch: fetcher
      })
    ).resolves.toMatchObject({ id: "google", issuer: ISSUER });
    expect(requests).toEqual([`${ISSUER}/.well-known/openid-configuration`]);
  });

  it("authenticates only an exact prelinked issuer and subject with state, nonce, and PKCE", async () => {
    await withDatabase(async (pool) => {
      const upstream = await profile();
      const oidc = service(pool, upstream.profile);

      const started = await oidc.start({ providerId: "google", binding: binding() });
      const authorization = new URL(started.location);
      expect(authorization.origin).toBe(ISSUER);
      expect(authorization.searchParams.get("response_type")).toBe("code");
      expect(authorization.searchParams.get("scope")).toBe("openid");
      expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authorization.searchParams.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(authorization.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      upstream.observed.nonce = authorization.searchParams.get("nonce")!;

      const callback = callbackUrl("google", authorization.searchParams.get("state")!);
      const completed = await oidc.callback({
        providerId: "google",
        currentUrl: callback,
        cookieHeader: cookiePair(started.setCookie)
      });
      expect(completed).toMatchObject({
        status: "authenticated",
        location: `/auth/interactions/${INTERACTION_UID}/oidc/complete`
      });
      expect(upstream.observed.tokenCalls).toBe(1);
      expect(upstream.observed.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/u);

      await expect(
        oidc.callback({
          providerId: "google",
          currentUrl: callback,
          cookieHeader: cookiePair(started.setCookie)
        })
      ).rejects.toBeInstanceOf(OidcFederationError);
      expect(upstream.observed.tokenCalls).toBe(2);

      await expect(
        oidc.consumeCompletion({
          interactionUid: INTERACTION_UID,
          cookieHeader: cookiePair(completed.setCookie!)
        })
      ).resolves.toEqual({ memberId: MEMBER_ID });
      await expect(
        oidc.consumeCompletion({
          interactionUid: INTERACTION_UID,
          cookieHeader: cookiePair(completed.setCookie!)
        })
      ).rejects.toBeInstanceOf(OidcFederationError);

      expect((await pool.query("select count(*)::int as count from members")).rows).toEqual([
        { count: 1 }
      ]);
      const stored = await pool.query<{
        consumed: boolean;
        completion_consumed: boolean;
        exact_issuer: string;
        linked_member_id: string | null;
        nonce_sha256: Buffer;
        state_sha256: Buffer;
      }>(
        `select exact_issuer,nonce_sha256,state_sha256,linked_member_id,
                consumed_at is not null as consumed,
                completion_consumed_at is not null as completion_consumed
           from oidc_login_transactions`
      );
      expect(stored.rows).toEqual([
        {
          exact_issuer: ISSUER,
          nonce_sha256: createHash("sha256").update(upstream.observed.nonce!).digest(),
          state_sha256: createHash("sha256")
            .update(authorization.searchParams.get("state")!)
            .digest(),
          linked_member_id: MEMBER_ID,
          consumed: true,
          completion_consumed: true
        }
      ]);
      await expectDatabaseToExclude(pool, [
        "one-use-upstream-code",
        "server-side-upstream-access-token",
        upstream.observed.idToken!,
        upstream.observed.nonce!,
        upstream.observed.verifier!,
        authorization.searchParams.get("state")!
      ]);
    });
  });

  it("refuses issuer mix-up without consuming the valid continuation", async () => {
    await withDatabase(async (pool) => {
      const upstream = await profile();
      const oidc = service(pool, upstream.profile, 81_200);
      const started = await oidc.start({ providerId: "google", binding: binding() });
      const state = new URL(started.location).searchParams.get("state")!;
      upstream.observed.nonce = new URL(started.location).searchParams.get("nonce")!;

      await expect(
        oidc.callback({
          providerId: "google",
          currentUrl: callbackUrl("google", state, "https://attacker.identity.test"),
          cookieHeader: cookiePair(started.setCookie)
        })
      ).rejects.toBeInstanceOf(OidcFederationError);
      expect(upstream.observed.tokenCalls).toBe(0);

      await expect(
        oidc.callback({
          providerId: "google",
          currentUrl: callbackUrl("google", state),
          cookieHeader: cookiePair(started.setCookie)
        })
      ).resolves.toMatchObject({ status: "authenticated" });
    });
  });

  it("consumes and audits a transaction when the upstream nonce is wrong", async () => {
    await withDatabase(async (pool) => {
      const upstream = await profile({ tokenNonce: "wrong-upstream-nonce" });
      const oidc = service(pool, upstream.profile, 81_300);
      const started = await oidc.start({ providerId: "google", binding: binding() });
      const authorization = new URL(started.location);
      upstream.observed.nonce = authorization.searchParams.get("nonce")!;

      await expect(
        oidc.callback({
          providerId: "google",
          currentUrl: callbackUrl("google", authorization.searchParams.get("state")!),
          cookieHeader: cookiePair(started.setCookie)
        })
      ).rejects.toBeInstanceOf(OidcFederationError);

      expect(
        (
          await pool.query(
            "select failure_code,consumed_at is not null as consumed from oidc_login_transactions"
          )
        ).rows
      ).toEqual([{ failure_code: "protocol_refused", consumed: true }]);
      expect(
        (
          await pool.query(
            `select event_type,
                    convert_from(canonical_payload,'utf8')::jsonb #>> '{details,reason}' as reason
               from audit_events
              where object_type='oidc_login_transaction'`
          )
        ).rows
      ).toEqual([{ event_type: "authorization_denied", reason: "protocol_refused" }]);
    });
  });

  it("ignores colliding email claims and rejects an unknown generic subject without provisioning", async () => {
    await withDatabase(async (pool) => {
      const upstream = await profile({ subject: "unknown-external-subject" });
      const oidc = service(pool, upstream.profile, 81_400);
      const started = await oidc.start({ providerId: "google", binding: binding() });
      const authorization = new URL(started.location);
      upstream.observed.nonce = authorization.searchParams.get("nonce")!;

      await expect(
        oidc.callback({
          providerId: "google",
          currentUrl: callbackUrl("google", authorization.searchParams.get("state")!),
          cookieHeader: cookiePair(started.setCookie)
        })
      ).rejects.toBeInstanceOf(OidcFederationError);

      expect((await pool.query("select count(*)::int as count from members")).rows).toEqual([
        { count: 1 }
      ]);
      expect(
        (await pool.query("select issuer,subject,state from external_identity_links")).rows
      ).toEqual([{ issuer: ISSUER, subject: EXTERNAL_SUBJECT, state: "active" }]);
      expect(
        (
          await pool.query(
            "select failure_code,consumed_at is not null as consumed from oidc_login_transactions"
          )
        ).rows
      ).toEqual([{ failure_code: "unknown_subject", consumed: true }]);
    });
  });

  it("lets an unknown UAE Pass subject create only a pending invited link with zero grant", async () => {
    await withDatabase(async (pool) => {
      const invitedMemberId = testId(81_501);
      const invitationId = testId(81_502);
      const invitationToken = "invitation-token-" + "x".repeat(32);
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values ($1,$2,'human','Invitee','Invitee','invited')",
        [invitedMemberId, ORGANIZATION_ID]
      );
      await pool.query(
        `insert into enrollment_invitations(
           id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at
         ) values ($1,$2,$3,$4,$5,'verified call',transaction_timestamp()+interval '1 hour')`,
        [
          invitationId,
          ORGANIZATION_ID,
          invitedMemberId,
          createHash("sha256").update(invitationToken).digest(),
          MEMBER_ID
        ]
      );
      const upstream = await profile({
        id: "uae_pass",
        kind: "uae_pass",
        subject: "new-uae-pass-subject"
      });
      const oidc = service(pool, upstream.profile, 81_510);
      const started = await oidc.start({
        providerId: "uae_pass",
        binding: binding(),
        invitationToken
      });
      const authorization = new URL(started.location);
      upstream.observed.nonce = authorization.searchParams.get("nonce")!;

      await expect(
        oidc.callback({
          providerId: "uae_pass",
          currentUrl: callbackUrl("uae_pass", authorization.searchParams.get("state")!),
          cookieHeader: cookiePair(started.setCookie)
        })
      ).resolves.toEqual({ status: "pending_link", location: null, setCookie: null });

      expect(
        (
          await pool.query(
            `select member.state as member_state,link.state as link_state,
                    link.confirmed_by,link.confirmed_at,link.invitation_id
               from members as member
               join external_identity_links as link on link.member_id=member.id
              where member.id=$1`,
            [invitedMemberId]
          )
        ).rows
      ).toEqual([
        {
          member_state: "invited",
          link_state: "pending",
          confirmed_by: null,
          confirmed_at: null,
          invitation_id: invitationId
        }
      ]);
    });
  });

  it("denies raw server-role mutation of federation rows", async () => {
    await withDatabase(async (pool) => {
      const upstream = await profile();
      const oidc = service(pool, upstream.profile, 81_600);
      await oidc.start({ providerId: "google", binding: binding() });

      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: ORGANIZATION_ID },
          (client) =>
            client.query(
              "update oidc_login_transactions set failure_code='protocol_refused' where organization_id=$1",
              [ORGANIZATION_ID]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: ORGANIZATION_ID },
          (client) =>
            client.query(
              `insert into external_identity_links(
                 id,organization_id,member_id,issuer,subject,state
               ) values ($1,$2,$3,$4,'forged-subject','pending')`,
              [testId(81_601), ORGANIZATION_ID, MEMBER_ID, ISSUER]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
    });
  });
});
