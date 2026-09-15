import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";
import { createHash } from "node:crypto";
import {
  applyKeyLifecycleInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";

describe("browser key maintenance through the HTTPS application", () => {
  it.each(["replace", "retire", "mark_compromised"] as const)(
    "%s invalidates old grants and codes, preserves passkeys and permits fresh login",
    async (operation) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await administrativeOAuthFixture(pool);
        try {
          const original = await f.login(f.target.memberId);
          const initialClient = await f.connect(original);
          const pending = await f.authorizeCode(f.target.memberId);
          const termsId = testId(198_100);
          const terms = "Updated synthetic terms for key maintenance regression";
          await pool.query(
            `insert into onboarding_terms_versions(id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,material_change,effective_at,created_by)
             values($1,$2,'voting_member',2,'boardagent.onboarding-terms.v1',$3,$4,true,transaction_timestamp()-interval '1 second',$5)`,
            [
              termsId,
              f.target.organizationId,
              terms,
              createHash("sha256").update(terms).digest(),
              f.issuer.memberId
            ]
          );
          const stageArguments = {
            schema_version: "boardagent.tool-input.v1",
            board_id: f.target.boardId,
            terms_version_id: termsId,
            support_version_id: f.target.supportVersionId,
            presentation_choice: "Structured sources",
            local_memory_choice: "Encrypted local cache",
            idempotency_key: "browser-key-before-onboarding"
          };
          const staged = await initialClient.callTool({
            name: "prepare_onboarding_attestation",
            arguments: stageArguments
          });
          expect(staged.isError, JSON.stringify(staged)).not.toBe(true);
          const oldStages = (
            await pool.query("select id from onboarding_browser_stages where state='active'")
          ).rows;
          expect(oldStages).toHaveLength(1);
          const oldActionStages = (
            await pool.query("select id from action_stages where state='active'")
          ).rows;
          expect(oldActionStages.length).toBeGreaterThan(0);
          const credentials = (
            await pool.query(
              "select id,credential_id,public_key,state from webauthn_credentials order by id"
            )
          ).rows;
          const changed = await f.changeBrowserKey(operation);
          const effects = (
            await pool.query(
              "select details->'effects' as effects from key_lifecycle_operations where id=$1",
              [changed.input.request.operationId]
            )
          ).rows[0].effects;
          expect(Number(effects.revokedSessions)).toBeGreaterThan(0);
          expect(Number(effects.revokedRefreshFamilies)).toBeGreaterThan(0);
          expect(Number(effects.cancelledStages)).toBeGreaterThan(0);
          expect(Number(effects.cancelledStages)).toBe(oldActionStages.length + oldStages.length);
          for (const stage of oldActionStages) {
            const row = (
              await pool.query(
                "select state,to_char(cancelled_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as cancelled_at from action_stages where id=$1",
                [stage.id]
              )
            ).rows[0];
            expect(row).toEqual({
              state: "cancelled",
              cancelled_at: changed.receipt.details.recordedAt
            });
          }
          expect(
            (
              await pool.query("select state from onboarding_browser_stages where id=$1", [
                oldStages[0].id
              ])
            ).rows[0].state
          ).toBe("expired");
          expect(
            (
              await pool.query(
                "select id,credential_id,public_key,state from webauthn_credentials order by id"
              )
            ).rows
          ).toEqual(credentials);
          const denied = await f.trustedFetch(f.resource, {
            method: "POST",
            headers: {
              authorization: `Bearer ${original.access_token}`,
              "content-type": "application/json"
            },
            body: JSON.stringify({ jsonrpc: "2.0", id: "retired-browser", method: "initialize" })
          });
          expect(denied.status).toBe(401);
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
          // ADR 0011: a fresh login with the ordinary scopes succeeds but, until onboarding
          // is current, the token is narrowed to onboarding:read and says so.
          const narrowed = await f.login(f.target.memberId);
          expect((narrowed as { scope?: string }).scope).toBe("onboarding:read");
          const fresh = await f.login(f.target.memberId, false, ["onboarding:read"]);
          const connected = await f.connect(fresh);
          const who = await connected.callTool({
            name: "whoami",
            arguments: { schema_version: "boardagent.tool-input.v1" }
          });
          expect(who.isError).not.toBe(true);
          // A revoked browser must not leave an active stage blocking immediate re-onboarding.
          const restarted = await connected.callTool({
            name: "prepare_onboarding_attestation",
            arguments: { ...stageArguments, idempotency_key: "browser-key-after-onboarding" }
          });
          expect(restarted.isError, JSON.stringify(restarted)).not.toBe(true);
          expect(
            (await pool.query("select id from onboarding_browser_stages where state='active'")).rows
          ).toHaveLength(1);
          const replay = await withBootstrapTransaction(
            pool,
            (c) => applyKeyLifecycleInTransaction(c, changed.input),
            { assumeRole: "boardagent_migrator" }
          );
          expect(replay).toEqual({ ...changed.receipt, replayed: true });
          // Retrying an old completed maintenance request must not revoke the fresh grant.
          expect(
            (
              await connected.callTool({
                name: "whoami",
                arguments: { schema_version: "boardagent.tool-input.v1" }
              })
            ).isError
          ).not.toBe(true);
        } finally {
          await f.close();
        }
      });
    }
  );
});
