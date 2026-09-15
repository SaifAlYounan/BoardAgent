import { setTimeout as delay } from "node:timers/promises";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import type { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";
import type { RequestListener } from "node:http";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { Pool } from "pg";
import Provider from "oidc-provider";
import { expect, vi } from "vitest";

import { parseConfig } from "../../lib/config/src/index.js";
import { keyLifecyclePublicMaterialSha256 } from "../../lib/audit/src/index.js";
import {
  KeyLifecyclePreparationSchema,
  registerRuntimeKeysInTransaction,
  prepareKeyLifecycleInTransaction,
  applyKeyLifecycleInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import {
  loadBoardAgentKeyMaterial,
  runtimeKeyRegistrations,
  PgTotpService,
  PgRateLimiter,
  generateTotpCodeFromBase32
} from "../../artifacts/server/src/index.js";
import { createBoardAgentServerApplication } from "../../artifacts/server/src/server-application.js";
import { symmetricKeyId } from "../../artifacts/server/src/symmetric-key-id.js";
import { delegationFixture } from "./administrative-delegation.js";
import {
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "./authorized-actor.js";
import {
  BoardAgentBootstrapOperator,
  type FirstSecretaryBootstrapResult
} from "../../scripts/src/bootstrap.js";

const SCOPES = [
  "documents:read",
  "documents:contribute",
  "governance:read",
  "onboarding:read",
  "secretariat:admin"
];
const REDIRECT = "https://agent-callback.test/callback";

class CookieJar {
  private readonly cookies = new Map<string, { name: string; value: string; path: string }>();
  public add(response: Response): void {
    for (const cookie of response.headers.getSetCookie()) {
      const parts = cookie.split(";").map((part) => part.trim());
      const separator = parts[0]!.indexOf("=");
      const name = parts[0]!.slice(0, separator);
      const value = parts[0]!.slice(separator + 1);
      const cookiePath =
        parts.find((part) => part.toLowerCase().startsWith("path="))?.slice(5) ?? "/";
      const key = `${name}\0${cookiePath}`;
      if (value) this.cookies.set(key, { name, value, path: cookiePath });
      else this.cookies.delete(key);
    }
  }
  public header(target: URL): string {
    return [...this.cookies.values()]
      .filter((c) => target.pathname.startsWith(c.path))
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");
  }
}

function csrf(html: string): string {
  const token = /name="csrf_token" value="([A-Za-z0-9_-]{43})"/u.exec(html)?.[1];
  if (!token) throw new Error("OAuth page lacks a CSRF token");
  return token;
}

/** Test-only authenticator: real EC key and signed assertion, production verifier. */
export function testAuthenticator() {
  const keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = keys.publicKey.export({ format: "jwk" });
  const id = randomBytes(32);
  const cose = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    Buffer.from(jwk.x!, "base64url"),
    Buffer.from([0x22, 0x58, 0x20]),
    Buffer.from(jwk.y!, "base64url")
  ]);
  let counter = 0;
  return {
    id,
    cose,
    registration(challenge: string, origin: string) {
      const clientData = Buffer.from(
        JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false })
      );
      const header = Buffer.alloc(37);
      createHash("sha256").update(new URL(origin).hostname).digest().copy(header);
      header[32] = 0x45; // User present/verified plus attested credential data.
      const credentialLength = Buffer.alloc(2);
      credentialLength.writeUInt16BE(id.length);
      const authData = Buffer.concat([header, Buffer.alloc(16), credentialLength, id, cose]);
      if (authData.length > 255) throw new Error("test authenticator CBOR bound exceeded");
      const text = (value: string) =>
        Buffer.concat([Buffer.from([0x60 + value.length]), Buffer.from(value)]);
      const attestation = Buffer.concat([
        Buffer.from([0xa3]),
        text("fmt"),
        text("none"),
        text("authData"),
        Buffer.from([0x58, authData.length]),
        authData,
        text("attStmt"),
        Buffer.from([0xa0])
      ]);
      return {
        id: id.toString("base64url"),
        rawId: id.toString("base64url"),
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientData.toString("base64url"),
          attestationObject: attestation.toString("base64url"),
          transports: ["internal"]
        }
      };
    },
    assertion(challenge: string, origin: string) {
      const clientData = Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false })
      );
      const data = Buffer.alloc(37);
      createHash("sha256").update(new URL(origin).hostname).digest().copy(data);
      data[32] = 0x05; // User present and verified; no backup flags.
      data.writeUInt32BE(++counter, 33);
      const signature = sign(
        "sha256",
        Buffer.concat([data, createHash("sha256").update(clientData).digest()]),
        keys.privateKey
      );
      return {
        id: id.toString("base64url"),
        rawId: id.toString("base64url"),
        type: "public-key",
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: clientData.toString("base64url"),
          authenticatorData: data.toString("base64url"),
          signature: signature.toString("base64url")
        }
      };
    }
  };
}

/** Existing enrolled people are explicit fixtures for authority regression cases. */
export async function administrativeOAuthFixture(pool: Pool, includeThirdPerson = false) {
  const f = await delegationFixture(pool);
  const third = includeThirdPerson
    ? await seedAdditionalAuthorizedActor(pool, f.issuer, {
        idBase: 104_000,
        seatRole: "voting_member",
        scopes: SCOPES
      })
    : null;
  const app = await oauthApplication(pool, async () => ({
    organizationId: f.issuer.organizationId,
    people: [f.issuer, f.target, ...(third ? [third] : [])]
  }));
  return { ...f, third, ...app };
}

/** Empty migrated database; initial identity is created only by the supported bootstrap. */
export async function bootstrapOAuthFixture(pool: Pool) {
  let initialized: Extract<FirstSecretaryBootstrapResult, { status: "created" }> | undefined;
  let operator: BoardAgentBootstrapOperator | undefined;
  const app = await oauthApplication(pool, async (origin) => {
    operator = new BoardAgentBootstrapOperator(pool, {
      assumeRole: "boardagent_migrator",
      expectedCanonicalResourceUri: `${origin}/mcp`
    });
    const setup = {
      organizationLegalName: "Aster Ridge Synthetic Mining Ltd",
      organizationDisplayName: "Aster Ridge Synthetic",
      organizationSlug: "aster-ridge-synthetic",
      timezone: "UTC",
      canonicalResourceUri: `${origin}/mcp`,
      boardSlug: "main-board",
      boardName: "Synthetic Main Board",
      boardCanonicalPayload: {
        schemaVersion: "boardagent.board.v1",
        name: "Synthetic Main Board",
        slug: "main-board",
        timezone: "UTC"
      },
      firstSecretaryLegalName: "Setup Custodian",
      firstSecretaryDisplayName: "Setup Custodian",
      votingWeight: 1,
      supportName: "Synthetic secretary",
      supportContactMethods: [{ kind: "operator_reference", value: "synthetic-handoff" }],
      onboardingTermsText: "Review the canonical record and secure your agent and local copies.",
      invitationHandoffMethod: "in-person QR"
    };
    const result = await operator.initialize(setup);
    if (result.status !== "created") throw new Error("fresh bootstrap was not created");
    initialized = result;
    expect(await operator.initialize(setup)).toEqual({
      status: "already_initialized",
      secretOnce: true
    });
    return { organizationId: result.organizationId, people: [] };
  });
  if (!initialized || !operator) throw new Error("bootstrap fixture unavailable");
  return { ...app, initialized, operator };
}

/** Full application on real TLS; only the fixture certificate is trusted. */
async function oauthApplication(
  pool: Pool,
  prepare: (
    origin: string
  ) => Promise<{ organizationId: string; people: readonly AuthorizedActorFixture[] }>
) {
  const certificate = await readFile(path.resolve("tests/fixtures/tls/released-client-matrix.crt"));
  const key = await readFile(path.resolve("tests/fixtures/tls/released-client-matrix.key"));
  let handler: RequestListener = (_request, response) => response.writeHead(503).end();
  const server = createServer({ cert: certificate, key }, (request, response) =>
    handler(request, response)
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("TLS fixture has no port");
  const origin = `https://localhost:${address.port}`;
  const resource = `${origin}/mcp`;
  const directory = await mkdtemp(path.join(tmpdir(), "boardagent-oauth-mcp-"));
  const clients: Client[] = [];
  const errors: Error[] = [];
  let restoreProviderDiagnostics: (() => void) | undefined;
  let app: Awaited<ReturnType<typeof createBoardAgentServerApplication>> | undefined;
  const close = async () => {
    await Promise.allSettled(clients.map((client) => client.close()));
    await app?.close();
    restoreProviderDiagnostics?.();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
    await rm(directory, { recursive: true, force: true });
  };
  try {
    // Any pre-enrolled people belong only to the explicit regression fixture.
    // The bootstrap fixture starts without a credential or OAuth client.
    const fixture = await prepare(origin);
    await pool.query("update system_instance set canonical_resource_uri=$1", [resource]);
    await pool.query(
      "update access_token_records set revoked_at=transaction_timestamp() where revoked_at is null"
    );
    let config = parseConfig({
      BOARDAGENT_ENV: "test",
      BOARDAGENT_DATABASE_URL: pool.options.connectionString,
      BOARDAGENT_ORGANIZATION_ID: fixture.organizationId,
      BOARDAGENT_PUBLIC_BASE_URL: origin,
      BOARDAGENT_AUTHORIZATION_MODE: "builtin",
      BOARDAGENT_BLOB_ROOT: directory,
      BOARDAGENT_DEV_MASTER_SECRET: randomBytes(48).toString("base64url"),
      BOARDAGENT_TRUSTED_PROXY_HOPS: "0"
    });
    let keys = await loadBoardAgentKeyMaterial(config);
    let nextId = 101_000;
    const initialRegistrations = runtimeKeyRegistrations(config, keys, () => testId(nextId++));
    const initialStub = (
      await pool.query(
        "select id,purpose,kid,public_jwk,retired_at,compromised_at from crypto_key_registry order by id"
      )
    ).rows;
    if (initialStub.length > 0) {
      // Complete only the explicit never-cryptographic placeholder from seedAuthorizedActor.
      // No retired history or real signed record is changed by this isolated fixture setup.
      expect(initialStub).toHaveLength(fixture.people.length);
      for (const stub of initialStub)
        expect(stub).toMatchObject({
          purpose: "oauth_signing",
          kid: expect.stringMatching(/^test-oauth(?:-[0-9]+)?$/u),
          public_jwk: {},
          retired_at: null,
          compromised_at: null
        });
      for (const stub of initialStub) expect(stub.public_jwk).toEqual({});
      expect(initialStub.some((stub) => stub.id === testId(8))).toBe(true);
      // Additional people's dummy token keys stay retained but were never real signers.
      await pool.query(
        "update crypto_key_registry set retired_at=transaction_timestamp() where id<>$1",
        [testId(8)]
      );
      const oauth = initialRegistrations.find((r) => r.purpose === "oauth_signing")!;
      await pool.query(
        "update crypto_key_registry set kid=$2,public_jwk=$3,nonsecret_locator=$4 where id=$1",
        [testId(8), oauth.kid, oauth.publicJwk, oauth.nonsecretLocator]
      );
    }
    await withBootstrapTransaction(
      pool,
      (client) =>
        registerRuntimeKeysInTransaction(
          client,
          fixture.organizationId,
          initialRegistrations.map((r) =>
            initialStub.length > 0 && r.purpose === "oauth_signing" ? { ...r, keyId: testId(8) } : r
          )
        ),
      { assumeRole: "boardagent_migrator" }
    );
    const people = new Map<
      string,
      { protocolId: string; authenticator: ReturnType<typeof testAuthenticator> }
    >();
    for (const person of fixture.people) {
      const auth = testAuthenticator();
      await pool.query("update oauth_clients set safe_metadata=$1,metadata_sha256=$2 where id=$3", [
        { name: "Private test agent" },
        createHash("sha256").update('{"name":"Private test agent"}').digest(),
        person.clientId
      ]);
      const protocolId = String(
        (
          await pool.query("select protocol_id_value from oauth_clients where id=$1", [
            person.clientId
          ])
        ).rows[0]?.protocol_id_value
      );
      for (const grantType of ["authorization_code", "refresh_token"])
        for (const scope of SCOPES)
          await pool.query(
            "insert into oauth_client_grants(client_id,grant_type,scope) values($1,$2,$3) on conflict do nothing",
            [person.clientId, grantType, scope]
          );
      await pool.query(
        "insert into oauth_client_redirect_uris(client_id,redirect_uri,redirect_uri_sha256) values($1,$2,$3)",
        [person.clientId, REDIRECT, createHash("sha256").update(REDIRECT).digest()]
      );
      await pool.query(
        "insert into webauthn_credentials(id,organization_id,member_id,credential_id,public_key,signature_counter,transports,backup_eligible,backup_state,state) values($1,$2,$3,$4,$5,0,array['internal'],false,false,'active')",
        [testId(nextId++), person.organizationId, person.memberId, auth.id, auth.cose]
      );
      people.set(person.memberId, { protocolId, authenticator: auth });
    }
    // Test-only diagnostics: keep exception stacks, never request/cookie/token objects.
    const providerEvents = Provider.prototype as InstanceType<typeof Provider> & EventEmitter;
    const emit = providerEvents.emit;
    const diagnostic = vi.spyOn(providerEvents, "emit").mockImplementation(function (
      this: InstanceType<typeof Provider> & EventEmitter,
      event: string | symbol,
      ...args: unknown[]
    ) {
      if (event === "server_error" && args[1] instanceof Error) errors.push(args[1]);
      return emit.call(this, event, ...args);
    });
    restoreProviderDiagnostics = () => diagnostic.mockRestore();
    app = await createBoardAgentServerApplication(pool, config, {
      assumeRole: "boardagent_server",
      keys,
      onError: (error) => errors.push(error)
    });
    handler = app.handler;

    // Actual database lifecycle and application restart, using fixture-owned private files.
    // This is automated TLS/login proof, not the unfinished production operator CLI.
    async function changeBrowserKey(operation: "replace" | "retire" | "mark_compromised") {
      handler = (_request, response) => response.writeHead(503).end();
      await app?.close();
      const old = (
        await pool.query<{ id: string; activated: string }>(
          `select id,to_char(activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as activated
         from crypto_key_registry where purpose='browser_session' and retired_at is null and compromised_at is null`
        )
      ).rows[0]!;
      const instance = (
        await pool.query<{ instance_id: string }>("select instance_id from system_instance")
      ).rows[0]!;
      const nextIdValue = testId(nextId++);
      const filename = path.join(directory, `browser-${nextIdValue}.key`);
      await writeFile(filename, randomBytes(32), { mode: 0o600, flag: "wx" });
      const material = await readFile(filename);
      const nextKeys = {
        ...keys,
        browserSessionKey: material,
        browserSessionKid: symmetricKeyId("browser", material)
      };
      const run = async (action: typeof operation) => {
        const input = await withBootstrapTransaction(
          pool,
          (client) =>
            prepareKeyLifecycleInTransaction(client, {
              instanceId: instance.instance_id,
              organizationId: fixture.organizationId,
              keyId: old.id,
              operationId: testId(nextId++),
              operation: action,
              replacement:
                action === "replace"
                  ? {
                      keyId: nextIdValue,
                      kid: nextKeys.browserSessionKid,
                      algorithm: "HMAC-SHA256",
                      publicJwk: null,
                      nonsecretLocator: `file:${filename}`,
                      materialSha256: createHash("sha256").update(material).digest("hex")
                    }
                  : null,
              declaredCompromisedAt: action === "mark_compromised" ? old.activated : null,
              retainedMaterialSha256: "a".repeat(64),
              operatorReference: "Synthetic TLS operator",
              reason: "Automated browser key and fresh-login regression"
            }),
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
        const receipt = await withBootstrapTransaction(
          pool,
          (client) => applyKeyLifecycleInTransaction(client, input),
          { assumeRole: "boardagent_migrator" }
        );
        return { input, receipt };
      };
      const first = await run(operation);
      if (operation !== "replace") await run("replace");
      config = { ...config, keySources: { ...config.keySources, browserSession: filename } };
      app = await createBoardAgentServerApplication(pool, config, {
        assumeRole: "boardagent_server",
        keys: nextKeys,
        onError: (error) => errors.push(error)
      });
      keys = nextKeys;
      handler = app.handler;
      return { ...first, oldKeyId: old.id, newKeyId: nextIdValue };
    }

    // Isolated operator/data-compromise fixture: actual SQL transitions and TLS restart.
    async function recoverSyntheticDataKey() {
      handler = (_request, response) => response.writeHead(503).end();
      await app?.close();
      const old = (
        await pool.query<{ id: string; activated: string }>(
          `select id,to_char(activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as activated
         from crypto_key_registry where purpose='data_kek' and retired_at is null and compromised_at is null`
        )
      ).rows[0]!;
      const instance = (
        await pool.query<{ instance_id: string }>("select instance_id from system_instance")
      ).rows[0]!;
      const nextIdValue = testId(nextId++);
      const filename = path.join(directory, `data-${nextIdValue}.key`);
      await writeFile(filename, randomBytes(32), { mode: 0o600, flag: "wx" });
      const material = await readFile(filename);
      const nextKeys = {
        ...keys,
        dataEncryptionKey: material,
        dataEncryptionKid: symmetricKeyId("data", material)
      };
      const run = async (action: "replace" | "mark_compromised") => {
        const input = await withBootstrapTransaction(
          pool,
          (client) =>
            prepareKeyLifecycleInTransaction(client, {
              instanceId: instance.instance_id,
              organizationId: fixture.organizationId,
              keyId: old.id,
              operationId: testId(nextId++),
              operation: action,
              replacement:
                action === "replace"
                  ? {
                      keyId: nextIdValue,
                      kid: nextKeys.dataEncryptionKid,
                      algorithm: "A256GCM",
                      publicJwk: null,
                      nonsecretLocator: `file:${filename}`,
                      materialSha256: createHash("sha256").update(material).digest("hex")
                    }
                  : null,
              declaredCompromisedAt: action === "mark_compromised" ? old.activated : null,
              retainedMaterialSha256: "a".repeat(64),
              operatorReference: "Synthetic TLS operator",
              reason: "Automated compromised data key and fresh-login regression"
            }),
          { assumeRole: "boardagent_migrator", readOnly: true }
        );
        const receipt = await withBootstrapTransaction(
          pool,
          (client) => applyKeyLifecycleInTransaction(client, input),
          { assumeRole: "boardagent_migrator" }
        );
        return { input, receipt };
      };
      const first = await run("mark_compromised");
      await run("replace");
      config = { ...config, keySources: { ...config.keySources, dataEncryption: filename } };
      app = await createBoardAgentServerApplication(pool, config, {
        assumeRole: "boardagent_server",
        keys: nextKeys,
        onError: (error) => errors.push(error)
      });
      keys = nextKeys;
      handler = app.handler;
      return { ...first, oldKeyId: old.id, newKeyId: nextIdValue };
    }

    async function enrollSyntheticTotp(memberId: string) {
      const authorizedByMemberId = fixture.people[0]!.memberId;
      const keyId = (
        await pool.query(
          "select id from crypto_key_registry where purpose='data_kek' and retired_at is null and compromised_at is null"
        )
      ).rows[0].id as string;
      const policy = { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 };
      const service = new PgTotpService(pool, {
        issuer: "Synthetic HTTPS key lifecycle",
        activeKeyId: keyId,
        keys: new Map([[keyId, keys.dataEncryptionKey]]),
        rateLimiter: new PgRateLimiter(pool, {
          hmacKey: keys.browserSessionKey,
          assumeRole: "boardagent_server"
        }),
        rateLimits: { ip: policy, client: policy, member: policy, token: policy },
        maxFailedAttempts: 5,
        lockoutSeconds: 300,
        assumeRole: "boardagent_server"
      });
      const enrollment = await service.beginEnrollment({
        organizationId: fixture.organizationId,
        memberId,
        authorizedByMemberId
      });
      const now = Number(
        (await pool.query("select floor(extract(epoch from clock_timestamp())) as now")).rows[0].now
      );
      await service.completeEnrollment({
        organizationId: fixture.organizationId,
        credentialId: enrollment.credentialId,
        authorizedByMemberId,
        code: generateTotpCodeFromBase32(enrollment.secretBase32, now)
      });
      return { credentialId: enrollment.credentialId };
    }

    // Actual audited database replacement and TLS restart with generated private material.
    // This is an automated fixture, not personal enrollment or operator custody evidence.
    async function installSyntheticOAuthReplacement() {
      handler = (_request, response) => response.writeHead(503).end();
      await app?.close();
      const previous = await pool.query<{ id: string; purpose: string; kid: string }>(
        `select id,purpose,kid from crypto_key_registry where organization_id=$1
          and retired_at is null and compromised_at is null`,
        [fixture.organizationId]
      );
      const oldOAuth = previous.rows.find((row) => row.purpose === "oauth_signing")!;
      const replacement = await loadBoardAgentKeyMaterial({
        ...config,
        keySources: { ...config.keySources, oauth: randomBytes(32) }
      });
      const nextFile = path.join(directory, `oauth-${testId(nextId++)}.jwk`);
      await writeFile(nextFile, JSON.stringify(replacement.oauthPrivateJwk), {
        mode: 0o600,
        flag: "wx"
      });
      config = { ...config, keySources: { ...config.keySources, oauth: nextFile } };
      const next = runtimeKeyRegistrations(config, replacement, () => testId(nextId++)).find(
        (r) => r.purpose === "oauth_signing"
      )!;
      const instance = (await pool.query("select instance_id from system_instance")).rows[0];
      const publicJwk = KeyLifecyclePreparationSchema.shape.replacement
        .unwrap()
        .shape.publicJwk.parse(replacement.oauthPublicJwk);
      if (publicJwk?.kty !== "EC") throw new Error("expected generated OAuth public key");
      const request = await withBootstrapTransaction(
        pool,
        (c) =>
          prepareKeyLifecycleInTransaction(c, {
            instanceId: instance.instance_id,
            organizationId: fixture.organizationId,
            keyId: oldOAuth.id,
            operationId: testId(nextId++),
            operation: "replace",
            declaredCompromisedAt: null,
            replacement: {
              keyId: next.keyId,
              kid: next.kid,
              algorithm: next.algorithm,
              publicJwk,
              nonsecretLocator: next.nonsecretLocator,
              materialSha256: keyLifecyclePublicMaterialSha256(publicJwk)
            },
            retainedMaterialSha256: "a".repeat(64),
            operatorReference: "Synthetic HTTPS fixture",
            reason: "Exercise OAuth continuity through an audited replacement"
          }),
        { assumeRole: "boardagent_migrator", readOnly: true }
      );
      await withBootstrapTransaction(pool, (c) => applyKeyLifecycleInTransaction(c, request), {
        assumeRole: "boardagent_migrator"
      });
      app = await createBoardAgentServerApplication(pool, config, {
        assumeRole: "boardagent_server",
        keys: replacement,
        onError: (error) => errors.push(error)
      });
      keys = replacement;
      handler = app.handler;
      return {
        oldKeyId: oldOAuth.id,
        oldKid: oldOAuth.kid,
        newKeyId: next.keyId,
        newKid: replacement.oauthKid
      };
    }

    const trustedFetch = async (
      input: string | URL | Request,
      init?: RequestInit
    ): Promise<Response> => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.origin !== origin)
        throw new Error("test request tried to leave the local TLS origin");
      const body = request.body ? Buffer.from(await request.arrayBuffer()) : undefined;
      return new Promise<Response>((resolve, reject) => {
        const outgoing = httpsRequest(
          url,
          {
            ca: certificate,
            family: 4,
            method: request.method,
            headers: Object.fromEntries(request.headers),
            signal: request.signal
          },
          (incoming) => {
            const chunks: Buffer[] = [];
            incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
            incoming.once("error", reject);
            incoming.once("end", () => {
              const headers = new Headers();
              for (let i = 0; i < incoming.rawHeaders.length; i += 2)
                headers.append(incoming.rawHeaders[i]!, incoming.rawHeaders[i + 1]!);
              resolve(
                new Response(
                  [204, 205, 304].includes(incoming.statusCode!) ? null : Buffer.concat(chunks),
                  { status: incoming.statusCode!, headers }
                )
              );
            });
          }
        );
        outgoing.once("error", reject);
        outgoing.end(body);
      });
    };
    async function authorizeCode(
      memberId: string,
      rejectTamperedSignatureFirst = false,
      scopes: readonly string[] = SCOPES,
      beforeResume?: () => void
    ) {
      const person = people.get(memberId);
      if (!person) throw new Error("unknown fixture person");
      const jar = new CookieJar();
      const verifier = randomBytes(32).toString("base64url");
      const state = randomBytes(24).toString("base64url");
      const fetchCookie = async (url: URL, init: RequestInit = {}) => {
        const headers = new Headers(init.headers);
        headers.set("cookie", jar.header(url));
        const response = await trustedFetch(url, { ...init, headers });
        jar.add(response);
        return response;
      };
      const post = (url: URL, values: Record<string, string>) =>
        fetchCookie(url, {
          method: "POST",
          headers: {
            origin,
            "sec-fetch-site": "same-origin",
            "content-type": "application/x-www-form-urlencoded; charset=utf-8"
          },
          body: new URLSearchParams(values).toString()
        });
      const authorize = new URL("/authorize", origin);
      authorize.search = new URLSearchParams({
        client_id: person.protocolId,
        redirect_uri: REDIRECT,
        response_type: "code",
        scope: scopes.join(" "),
        state,
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
        resource
      }).toString();
      let response = await fetchCookie(authorize);
      expect(response.status, response.status === 303 ? "" : await response.clone().text()).toBe(
        303
      );
      const loginUrl = new URL(response.headers.get("location")!, origin);
      response = await fetchCookie(loginUrl);
      expect(response.status).toBe(200);
      const loginCsrf = csrf(await response.text());
      const beginLogin = () =>
        post(new URL(`${loginUrl.pathname}/passkey/begin`, origin), {
          csrf_token: loginCsrf
        });
      response = await beginLogin();
      if (response.status === 429) {
        // Several synthetic people share loopback and the real production rate budget.
        // Retry only the nonbinding begin request, respecting the server's exact delay.
        const retrySeconds = Number(response.headers.get("retry-after"));
        expect(retrySeconds).toBeGreaterThan(0);
        expect(retrySeconds).toBeLessThanOrEqual(60);
        await delay(retrySeconds * 1000);
        response = await beginLogin();
      }
      expect(response.status).toBe(200);
      const options = (await response.json()) as {
        challenge: string;
        userVerification: string;
        rpId: string;
      };
      expect(options).toMatchObject({ userVerification: "required", rpId: "localhost" });
      if (rejectTamperedSignatureFirst) {
        const tampered = person.authenticator.assertion(options.challenge, origin);
        const signature = Buffer.from(tampered.response.signature, "base64url");
        signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
        tampered.response.signature = signature.toString("base64url");
        const rejected = await post(new URL(`${loginUrl.pathname}/passkey/complete`, origin), {
          csrf_token: loginCsrf,
          credential: JSON.stringify(tampered)
        });
        expect(rejected.status).toBe(400);
      }
      response = await post(new URL(`${loginUrl.pathname}/passkey/complete`, origin), {
        csrf_token: loginCsrf,
        credential: JSON.stringify(person.authenticator.assertion(options.challenge, origin))
      });
      expect(response.status, errors.map((error) => error.stack).join("\n")).toBe(303);
      beforeResume?.();
      let callback: URL | undefined;
      for (let i = 0; i < 10; i++) {
        expect(response.status, errors.map((error) => error.stack).join("\n")).toBe(303);
        const next = new URL(response.headers.get("location")!, origin);
        if (next.origin === new URL(REDIRECT).origin) {
          callback = next;
          break;
        }
        response = await fetchCookie(next);
        if (response.status === 200) {
          const html = await response.text();
          for (const scope of scopes) expect(html).toContain(scope);
          response = await post(new URL(`${next.pathname}/consent`, origin), {
            csrf_token: csrf(html)
          });
        }
      }
      expect(callback?.searchParams.get("state")).toBe(state);
      const code = callback?.searchParams.get("code");
      expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      return { code: code!, verifier, protocolId: person.protocolId, jar };
    }
    async function exchangeAuthorization(authorization: Awaited<ReturnType<typeof authorizeCode>>) {
      return trustedFetch(new URL("/token", origin), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: authorization.protocolId,
          redirect_uri: REDIRECT,
          code: authorization.code,
          code_verifier: authorization.verifier,
          resource
        }).toString()
      });
    }
    async function login(
      memberId: string,
      rejectTamperedSignatureFirst = false,
      scopes: readonly string[] = SCOPES,
      beforeResume?: () => void
    ) {
      const authorization = await authorizeCode(
        memberId,
        rejectTamperedSignatureFirst,
        scopes,
        beforeResume
      );
      const response = await exchangeAuthorization(authorization);
      expect(response.status, response.ok ? "" : await response.clone().text()).toBe(200);
      const token = (await response.json()) as { access_token: string; refresh_token: string };
      expect(token.access_token.split(".")).toHaveLength(3);
      expect(token.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      return { ...token, protocolId: authorization.protocolId, jar: authorization.jar };
    }
    const wire: { request: Record<string, unknown>; response: string; status: number }[] = [];
    async function connect(token: Awaited<ReturnType<typeof login>>) {
      const client = new Client(
        { name: "administrative-integration-agent", version: "1.0.0" },
        {
          capabilities: { elicitation: { form: {} } },
          versionNegotiation: { mode: { pin: "2026-07-28" } },
          inputRequired: { autoFulfill: true, maxRounds: 2 }
        }
      );
      clients.push(client);
      await client.connect(
        new StreamableHTTPClientTransport(new URL(resource), {
          requestInit: { headers: { authorization: `Bearer ${token.access_token}` } },
          fetch: async (input, init) => {
            const request = new Request(input, init);
            const body = request.body ? await request.clone().text() : "{}";
            const response = await trustedFetch(request);
            wire.push({
              request: JSON.parse(body) as Record<string, unknown>,
              response: await response.clone().text(),
              status: response.status
            });
            return response;
          }
        })
      );
      client.setRequestHandler("elicitation/create", async (request) => {
        const message = String(request.params.message);
        const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(message)?.[1];
        if (!code) throw new Error("production H form omitted protected code");
        return { action: "accept", content: { approve: true, confirmation_code: code } };
      });
      return client;
    }
    function browserSession() {
      const jar = new CookieJar();
      const request = async (pathname: string, init: RequestInit = {}) => {
        const target = new URL(pathname, origin);
        const headers = new Headers(init.headers);
        headers.set("cookie", jar.header(target));
        const response = await trustedFetch(target, { ...init, headers });
        jar.add(response);
        return response;
      };
      return {
        get: (pathname: string) => request(pathname),
        post: (pathname: string, values: Record<string, string>) =>
          request(pathname, {
            method: "POST",
            headers: {
              origin,
              "sec-fetch-site": "same-origin",
              "content-type": "application/x-www-form-urlencoded; charset=utf-8"
            },
            body: new URLSearchParams(values).toString()
          })
      };
    }
    async function registerAgent(memberId: string, auth: ReturnType<typeof testAuthenticator>) {
      const response = await trustedFetch(new URL("/register", origin), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "Private synthetic enrollment agent",
          redirect_uris: [REDIRECT],
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          scope: SCOPES.join(" ")
        })
      });
      expect(response.status).toBe(201);
      const client = (await response.json()) as { client_id: string };
      expect(client.client_id).toEqual(expect.any(String));
      people.set(memberId, { protocolId: client.client_id, authenticator: auth });
    }
    return {
      origin,
      resource,
      scopes: SCOPES,
      login,
      authorizeCode,
      exchangeAuthorization,
      connect,
      trustedFetch,
      browserSession,
      registerAgent,
      installSyntheticOAuthReplacement,
      changeBrowserKey,
      recoverSyntheticDataKey,
      enrollSyntheticTotp,
      wire,
      errors,
      close
    };
  } catch (error) {
    await close();
    throw error;
  }
}
