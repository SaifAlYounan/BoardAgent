import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { recoveryTotp } from "../helpers/recovery-totp.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("SR-026 recovery contains the current TOTP lifecycle", () => {
  it.each([true, false])(
    "retires pending enrollment and unselected active credentials (active=%s)",
    async (includeActive) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await administrativeOAuthFixture(pool);
        try {
          const admin = await f.connect(await f.login(f.issuer.memberId));
          const targetToken = await f.login(f.target.memberId);
          const totp = await recoveryTotp(pool, f.issuer.organizationId, f.issuer.memberId);
          const unaffected = await totp.begin(f.issuer.memberId);
          await totp.activate(unaffected);
          if (includeActive) {
            const active = await totp.begin(f.target.memberId);
            await totp.activate(active);
          }
          const pending = await totp.begin(f.target.memberId);
          const profile = await admin.callTool({
            name: "get_member",
            arguments: {
              schema_version: SCHEMA,
              member_id: f.target.memberId
            }
          });
          expect(profile.isError).not.toBe(true);
          const metadata = profile.structuredContent as {
            data: {
              member: {
                recovery_credentials: {
                  items: Array<{ kind: string; credential_record_id: string }>;
                };
              };
            };
          };
          const passkey = metadata.data.member.recovery_credentials.items.find(
            (item) => item.kind === "passkey"
          );
          expect(passkey).toBeDefined();
          const result = await admin.callTool({
            name: "initiate_identity_recovery",
            arguments: {
              schema_version: SCHEMA,
              member_id: f.target.memberId,
              reason: "Contain unselected authenticators after verified synthetic recovery",
              proofing_method: "in_person",
              credential_disposition: "preserve_named",
              preserved_credential_ids: [passkey!.credential_record_id],
              idempotency_key: "recovery-retire-totp-lifecycle"
            }
          });
          expect(result.isError).not.toBe(true);
          const rows = (
            await pool.query(
              `select state,failed_attempts,locked_until,
          terminal_at is not null as terminal from totp_credentials where member_id=$1 order by id`,
              [f.target.memberId]
            )
          ).rows;
          expect(rows).toEqual(
            Array.from({ length: includeActive ? 2 : 1 }, () => ({
              state: "disabled",
              failed_attempts: 0,
              locked_until: null,
              terminal: true
            }))
          );
          await expect(totp.activate(pending)).rejects.toMatchObject({
            code: "invalid_enrollment"
          });
          expect(
            (
              await pool.query("select state from totp_credentials where id=$1", [
                unaffected.credentialId
              ])
            ).rows[0].state
          ).toBe("active");
          const denied = await f.trustedFetch(f.resource, {
            method: "POST",
            headers: {
              authorization: `Bearer ${targetToken.access_token}`,
              "content-type": "application/json"
            },
            body: "{}"
          });
          expect(denied.status).toBe(401);
          const reconnected = await f.connect(await f.login(f.target.memberId));
          expect(
            (await reconnected.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
              .isError
          ).not.toBe(true);
          expect(
            (await admin.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
              .isError
          ).not.toBe(true);
          expect(f.errors).toEqual([]);
        } finally {
          await f.close();
        }
      });
    }
  );

  it("preserves an explicitly selected locked active TOTP without clearing its lock or retaining a pending seed", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const admin = await f.connect(await f.login(f.issuer.memberId));
        const totp = await recoveryTotp(pool, f.issuer.organizationId, f.issuer.memberId);
        const active = await totp.begin(f.target.memberId);
        await totp.activate(active);
        const pending = await totp.begin(f.target.memberId);
        for (let attempt = 0; attempt < 3; attempt++)
          await pool.query(
            `update totp_credentials set failed_attempts=failed_attempts+1,
            locked_until=case when failed_attempts+1=max_failed_attempts
              then transaction_timestamp()+make_interval(secs=>lockout_seconds) else null end
            where id=$1`,
            [active.credentialId]
          );
        const before = (
          await pool.query("select * from totp_credentials where id=$1", [active.credentialId])
        ).rows[0];
        const result = await admin.callTool({
          name: "initiate_identity_recovery",
          arguments: {
            schema_version: SCHEMA,
            member_id: f.target.memberId,
            reason: "Preserve only the independently verified fallback credential",
            proofing_method: "verified_number_call",
            credential_disposition: "preserve_named",
            preserved_credential_ids: [active.credentialId],
            idempotency_key: "recovery-preserve-locked-totp"
          }
        });
        expect(result.isError).not.toBe(true);
        expect(
          (await pool.query("select * from totp_credentials where id=$1", [active.credentialId]))
            .rows[0]
        ).toEqual(before);
        expect(
          (
            await pool.query("select state from totp_credentials where id=$1", [
              pending.credentialId
            ])
          ).rows[0].state
        ).toBe("disabled");
        expect(
          (
            await pool.query(
              "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
              [f.target.memberId]
            )
          ).rows[0].n
        ).toBe(0);
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });
});
