import { createHash, randomBytes } from "node:crypto";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";

const SCHEMA = "boardagent.tool-input.v1";
const REDIRECT = "https://agent-callback.test/callback";

async function snapshot(pool: Pool, tables: readonly string[]) {
  const result: Record<string, unknown> = {};
  for (const table of tables)
    result[table] = (
      await pool.query(
        `select encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex') as digest from ${table} r order by digest`
      )
    ).rows;
  return result;
}
const AUTHORITY = [
  "organization_role_assignments",
  "company_admin_proposals",
  "member_admin_delegations",
  "administrative_authority_changes",
  "members",
  "board_memberships",
  "consent_records"
];
const LOGIN_EFFECTS = [
  "oauth_authorization_codes",
  "access_token_records",
  "refresh_families",
  "oauth_consents",
  ...AUTHORITY
];

function authorize(origin: string, resource: string, protocolId: string, redirectUri = REDIRECT) {
  const state = randomBytes(24).toString("base64url");
  const url = new URL("/authorize", origin);
  url.search = new URLSearchParams({
    client_id: protocolId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "governance:read secretariat:admin",
    state,
    code_challenge: createHash("sha256").update(randomBytes(32)).digest("base64url"),
    code_challenge_method: "S256",
    resource
  }).toString();
  return { url, state };
}

describe("AC26 actual OAuth/MCP client-consent boundaries", () => {
  it("an authenticated reader without form elicitation cannot stage an administrative act", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      const client = new Client(
        { name: "incapable-synthetic-client", version: "1" },
        {
          capabilities: {},
          versionNegotiation: { mode: { pin: "2026-07-28" } }
        }
      );
      try {
        const token = await f.login(f.issuer.memberId);
        await client.connect(
          new StreamableHTTPClientTransport(new URL(f.resource), {
            requestInit: { headers: { authorization: `Bearer ${token.access_token}` } },
            fetch: f.trustedFetch
          })
        );
        expect(
          (await client.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } })).isError
        ).not.toBe(true);
        const tables = [...AUTHORITY, "action_stages", "input_required_attempts"];
        const before = await snapshot(pool, tables);
        await expect(
          client.callTool({ name: "manage_member_admin_delegation", arguments: f.input })
        ).rejects.toMatchObject({ code: -32021 });
        expect(await snapshot(pool, tables)).toEqual(before);
      } finally {
        await client.close();
        await f.close();
      }
    });
  });

  it.each(["cancel", "decline"] as const)(
    "a capable client's %s leaves no administrative change or confirmed consent",
    async (action) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await administrativeOAuthFixture(pool);
        try {
          const client = await f.connect(await f.login(f.issuer.memberId));
          let forms = 0;
          client.setRequestHandler("elicitation/create", async () => {
            forms += 1;
            return { action };
          });
          const before = await snapshot(pool, AUTHORITY);
          expect(
            (await client.callTool({ name: "manage_member_admin_delegation", arguments: f.input }))
              .isError
          ).toBe(true);
          expect(forms).toBe(1);
          expect(await snapshot(pool, AUTHORITY)).toEqual(before);
          const attempts = (
            await pool.query(
              "select state from input_required_attempts where original_name='manage_member_admin_delegation'"
            )
          ).rows;
          expect(attempts).toHaveLength(1);
          expect(attempts[0].state).not.toBe("confirmed");
        } finally {
          await f.close();
        }
      });
    }
  );

  it("an unregistered authorization callback receives no redirect, code or authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const protocolId = String(
          (
            await pool.query("select protocol_id_value from oauth_clients where id=$1", [
              f.issuer.clientId
            ])
          ).rows[0].protocol_id_value
        );
        const before = await snapshot(pool, LOGIN_EFFECTS);
        const request = authorize(
          f.origin,
          f.resource,
          protocolId,
          "https://agent-callback.test/unregistered"
        );
        const result = await f.trustedFetch(request.url);
        expect(result.status).toBe(400);
        expect(result.headers.get("location")).toBeNull();
        expect(await snapshot(pool, LOGIN_EFFECTS)).toEqual(before);
      } finally {
        await f.close();
      }
    });
  });

  it("a valid authorization code cannot be exchanged with a different callback", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const authorization = await f.authorizeCode(f.issuer.memberId);
        const tables = ["access_token_records", "refresh_families", ...AUTHORITY];
        const before = await snapshot(pool, tables);
        const denied = await f.trustedFetch(new URL("/token", f.origin), {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: authorization.protocolId,
            code: authorization.code,
            code_verifier: authorization.verifier,
            redirect_uri: "https://agent-callback.test/different",
            resource: f.resource
          }).toString()
        });
        expect(denied.status).toBe(400);
        expect(await denied.json()).toEqual({ error: "invalid_grant" });
        expect(await snapshot(pool, tables)).toEqual(before);
        const connected = await f.connect(await f.login(f.issuer.memberId));
        expect(
          (await connected.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .isError
        ).not.toBe(true);
      } finally {
        await f.close();
      }
    });
  });

  it("cancelling the actual browser login returns only its bound denial and cannot issue a token", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const protocolId = String(
          (
            await pool.query("select protocol_id_value from oauth_clients where id=$1", [
              f.issuer.clientId
            ])
          ).rows[0].protocol_id_value
        );
        const before = await snapshot(pool, LOGIN_EFFECTS);
        const browser = f.browserSession();
        const request = authorize(f.origin, f.resource, protocolId);
        const started = await browser.get(request.url.pathname + request.url.search);
        expect(started.status).toBe(303);
        const login = new URL(started.headers.get("location")!, f.origin);
        expect(login.origin).toBe(f.origin);
        const page = await browser.get(login.pathname + login.search);
        expect(page.status).toBe(200);
        const csrf = /name="csrf_token" value="([A-Za-z0-9_-]{43})"/u.exec(await page.text())?.[1];
        expect(csrf).toBeDefined();
        let response = await browser.post(`${login.pathname}/cancel`, { csrf_token: csrf! });
        let callback: URL | undefined;
        for (let i = 0; i < 5; i++) {
          expect(response.status).toBe(303);
          const next = new URL(response.headers.get("location")!, f.origin);
          if (next.origin === new URL(REDIRECT).origin) {
            callback = next;
            break;
          }
          expect(next.origin).toBe(f.origin);
          response = await browser.get(next.pathname + next.search);
        }
        expect(callback?.origin + (callback?.pathname ?? "")).toBe(REDIRECT);
        expect(callback?.searchParams.get("state")).toBe(request.state);
        expect(callback?.searchParams.get("error")).toBe("access_denied");
        expect(callback?.searchParams.has("code")).toBe(false);
        expect(await snapshot(pool, LOGIN_EFFECTS)).toEqual(before);
        expect((await browser.get(login.pathname + login.search)).status).toBe(400);
      } finally {
        await f.close();
      }
    });
  });

  it("documents the client trust limit: automatic code echo records attribution, not proof of human involvement", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const client = await f.connect(await f.login(f.issuer.memberId));
        // This fixture automatically extracts and echoes a valid code. No person is
        // present and no manual acceptance may be inferred from this successful act.
        const result = await client.callTool({
          name: "manage_member_admin_delegation",
          arguments: f.input
        });
        expect(result.isError).not.toBe(true);
        const consent = (
          await pool.query(
            `select c.actor_member_id,c.client_id,c.exact_origin,c.canonical_schema,
                  c.access_token_record_id=t.id as bound_token,c.token_jti=t.jti as bound_jti,
                  a.state,a.response_action,a.protocol_version,
                  encode(c.record_sha256,'hex') as record_sha256
             from consent_records c join access_token_records t on t.id=c.access_token_record_id
             join input_required_attempts a on a.id=c.input_required_attempt_id
            where c.action_code='manage_member_admin_delegation'`
          )
        ).rows;
        expect(consent).toEqual([
          {
            actor_member_id: f.issuer.memberId,
            client_id: f.issuer.clientId,
            exact_origin: f.origin,
            canonical_schema: "boardagent.consent-record.v1",
            bound_token: true,
            bound_jti: true,
            state: "confirmed",
            response_action: "accept",
            protocol_version: "2026-07-28",
            record_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u)
          }
        ]);
        expect(
          (
            await pool.query("select state from member_admin_delegations where id=$1", [
              f.input.change.delegation_id
            ])
          ).rows
        ).toEqual([{ state: "active" }]);
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });
});
