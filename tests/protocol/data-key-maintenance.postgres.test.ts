import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import {
  applyKeyLifecycleInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";

describe("data key incident through the HTTPS application", () => {
  it("revokes exposed members' existing OAuth authority and preserves passkeys and unrelated connections across restart", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const factor = await f.enrollSyntheticTotp(f.target.memberId);
        const original = await f.login(f.target.memberId),
          unrelated = await f.login(f.issuer.memberId);
        const pending = await f.authorizeCode(f.target.memberId);
        const credentials = (
          await pool.query(
            "select id,credential_id,public_key,state from webauthn_credentials order by id"
          )
        ).rows;
        const changed = await f.recoverSyntheticDataKey();
        expect(Number(changed.receipt.details.effects.revokedRefreshFamilies)).toBeGreaterThan(0);
        expect(Number(changed.receipt.details.effects.revokedSessions)).toBeGreaterThan(0);
        expect(
          (
            await pool.query("select state from totp_credentials where id=$1", [
              factor.credentialId
            ])
          ).rows[0].state
        ).toBe("compromised");
        expect(
          (
            await pool.query(
              "select id,credential_id,public_key,state from webauthn_credentials order by id"
            )
          ).rows
        ).toEqual(credentials);
        const invoke = (token: string) =>
          f.trustedFetch(f.resource, {
            method: "POST",
            headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", id: "data-incident", method: "initialize" })
          });
        expect((await invoke(original.access_token)).status).toBe(401);
        const unrelatedClient = await f.connect(unrelated);
        expect(
          (
            await unrelatedClient.callTool({
              name: "whoami",
              arguments: { schema_version: "boardagent.tool-input.v1" }
            })
          ).isError
        ).not.toBe(true);
        const code = await f.exchangeAuthorization(pending);
        expect(code.status).toBe(400);
        expect(await code.json()).toMatchObject({ error: "invalid_grant" });
        const refresh = await f.trustedFetch(new URL("/token", f.origin), {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: original.protocolId,
            refresh_token: original.refresh_token,
            resource: f.resource
          }).toString()
        });
        expect(refresh.status).toBe(400);
        expect(await refresh.json()).toMatchObject({ error: "invalid_grant" });
        const fresh = await f.login(f.target.memberId),
          client = await f.connect(fresh);
        expect(
          (
            await client.callTool({
              name: "whoami",
              arguments: { schema_version: "boardagent.tool-input.v1" }
            })
          ).isError
        ).not.toBe(true);
        const replay = await withBootstrapTransaction(
          pool,
          (c) => applyKeyLifecycleInTransaction(c, changed.input),
          { assumeRole: "boardagent_migrator" }
        );
        expect(replay).toEqual({ ...changed.receipt, replayed: true });
        expect(
          (
            await client.callTool({
              name: "whoami",
              arguments: { schema_version: "boardagent.tool-input.v1" }
            })
          ).isError
        ).not.toBe(true);
      } finally {
        await f.close();
      }
    });
  });
});
