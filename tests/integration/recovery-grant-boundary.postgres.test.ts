import { withIdentityTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import { describe, expect, it } from "vitest";
import { PgWebAuthnStore } from "../../artifacts/server/src/pg-webauthn-store.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

describe("recovery grant database boundary", () => {
  it("refuses unbound credential insertion by the server role and the legacy store path", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { target } = await administrativeActors(pool);
      const store = new PgWebAuthnStore(pool, { assumeRole: "boardagent_server" });
      const challengeId = testId(109001);
      await store.saveChallenge({
        id: challengeId,
        organizationId: target.organizationId,
        sessionId: null,
        memberId: target.memberId,
        purpose: "recovery",
        challengeSha256: "aa".repeat(32),
        rpId: "boardagent.test",
        exactOrigin: "https://boardagent.test",
        expiresAt: new Date(Date.now() + 300_000),
        consumedAt: null
      });
      expect(
        await store.completeRegistration({
          organizationId: target.organizationId,
          challengeId,
          expectedChallengeSha256: "aa".repeat(32),
          credential: {
            id: testId(109002),
            organizationId: target.organizationId,
            memberId: target.memberId,
            credentialId: Buffer.alloc(32, 11),
            publicKey: Buffer.alloc(64, 12),
            counter: 0,
            transports: ["internal"],
            backupEligible: false,
            backupState: false,
            state: "active"
          }
        })
      ).toBe(false);
      expect(
        (
          await pool.query(
            "select has_table_privilege('boardagent_server','webauthn_credentials','INSERT') as allowed"
          )
        ).rows[0].allowed
      ).toBe(false);
    });
  });
  it("keeps recovery secrets private and exposes only fixed-owner, fixed-search-path helpers to the server", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer } = await administrativeActors(pool);
      const functions = (
        await pool.query(
          `select p.proname,p.oid::regprocedure::text as signature,
        r.rolname as owner,p.prosecdef,p.proconfig
        from pg_proc p join pg_roles r on r.oid=p.proowner where p.pronamespace='public'::regnamespace
        and p.proname=any($1) order by p.proname`,
          [
            [
              "boardagent_issue_recovery_registration",
              "boardagent_lookup_recovery_registration",
              "boardagent_prepare_recovery_registration",
              "boardagent_complete_recovery_registration",
              "boardagent_prepare_recovery_activation",
              "boardagent_plan_recovery_activation",
              "boardagent_finalize_recovery_activation"
            ]
          ]
        )
      ).rows;
      expect(functions).toHaveLength(7);
      for (const fn of functions) {
        expect(fn.owner).toBe("boardagent_migrator");
        expect(fn.prosecdef).toBe(true);
        expect(fn.proconfig).toEqual(["search_path=pg_catalog, public, pg_temp"]);
        for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
          expect(
            (
              await pool.query("select has_function_privilege($1,$2,'EXECUTE') as allowed", [
                role,
                fn.signature
              ])
            ).rows[0].allowed
          ).toBe(role === "boardagent_server");
        }
      }
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
        expect(
          (
            await pool.query(
              "select has_table_privilege($1,'recovery_registration_grants','INSERT,UPDATE,DELETE,TRUNCATE') as allowed",
              [role]
            )
          ).rows[0].allowed
        ).toBe(false);
      }
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: issuer.organizationId },
          (client) =>
            client.query(
              "select token_sha256,pending_credential,activation_code_sha256 from recovery_registration_grants"
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withRequestTransaction(
          pool,
          issuer.context,
          (client) =>
            client.query("select boardagent_issue_recovery_registration($1,$2)", [
              testId(109003),
              Buffer.alloc(32, 20)
            ]),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withIdentityTransaction(
          pool,
          { organizationId: issuer.organizationId },
          (client) =>
            client.query("select boardagent_prepare_recovery_activation($1::jsonb)", [{}]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
    });
  });
});
