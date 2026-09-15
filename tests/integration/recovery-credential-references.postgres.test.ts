import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { recoveryTotp } from "../helpers/recovery-totp.js";
import { testId } from "../helpers/authorized-actor.js";

describe("SR-026/SR-102 bounded private recovery references", () => {
  it("returns only preservable metadata and denies wrong scope, person, organization and revoked authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      for (const [index, state] of ["active", "suspect", "revoked"].entries()) {
        await pool.query(
          "insert into webauthn_credentials(id,organization_id,member_id,credential_id,public_key,signature_counter,transports,backup_eligible,backup_state,state) values($1,$2,$3,$4,$5,0,'{}',false,false,$6)",
          [
            testId(110_001 + index),
            issuer.organizationId,
            target.memberId,
            Buffer.alloc(32, 0xa1 + index),
            Buffer.alloc(64, 0xb1 + index),
            state
          ]
        );
      }
      const totp = await recoveryTotp(pool, issuer.organizationId, issuer.memberId);
      const replaced = await totp.begin(target.memberId);
      await totp.activate(replaced);
      const active = await totp.begin(target.memberId);
      await totp.activate(active);
      const pending = await totp.begin(target.memberId);
      // Lockout is a field on an active credential, not a separate lifecycle state.
      for (let attempt = 0; attempt < 3; attempt++)
        await pool.query(
          `update totp_credentials set failed_attempts=failed_attempts+1,
          locked_until=case when failed_attempts+1=max_failed_attempts
            then transaction_timestamp()+make_interval(secs=>lockout_seconds) else null end
          where id=$1`,
          [active.credentialId]
        );
      const read = (context = issuer.context, memberId = target.memberId) =>
        withRequestTransaction(
          pool,
          context,
          async (client) =>
            (
              await client.query("select boardagent_member_recovery_credentials($1) as result", [
                memberId
              ])
            ).rows[0]?.result,
          { assumeRole: "boardagent_server" }
        );
      const result = await read();
      expect(result.complete).toBe(true);
      expect(
        result.items.map((item: { credential_record_id: string; kind: string; state: string }) => [
          item.credential_record_id,
          item.kind,
          item.state
        ])
      ).toEqual([
        [testId(110_001), "passkey", "active"],
        [active.credentialId, "totp", "active"]
      ]);
      for (const item of result.items)
        expect(Object.keys(item).sort()).toEqual([
          "created_at",
          "credential_record_id",
          "kind",
          "last_used_at",
          "state"
        ]);
      for (const bytes of [
        Buffer.alloc(32, 0xa1),
        Buffer.alloc(64, 0xb1),
        Buffer.alloc(64, 0xc1)
      ]) {
        expect(JSON.stringify(result)).not.toContain(bytes.toString("base64"));
        expect(JSON.stringify(result)).not.toContain(bytes.toString("hex"));
      }
      expect(JSON.stringify(result)).not.toContain(active.secretBase32);
      expect(JSON.stringify(result)).not.toContain(active.fallbackHandle);
      expect(JSON.stringify(result)).not.toContain(replaced.credentialId);
      expect(JSON.stringify(result)).not.toContain(pending.credentialId);
      expect(await read(target.context)).toBeNull();
      expect(await read({ ...issuer.context, clientId: target.clientId })).toBeNull();
      expect(await read({ ...issuer.context, memberId: target.memberId })).toBeNull();
      await pool.query(
        `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
         values($1,$2,$3,'secretariat','Synthetic existing organization recovery authority')`,
        [testId(113_000), issuer.organizationId, target.memberId]
      );
      expect((await read(target.context)).items).toHaveLength(2);
      await pool.query(
        "update organization_role_assignments set active_until=transaction_timestamp() where id=$1",
        [testId(113_000)]
      );
      expect(await read(target.context)).toBeNull();
      expect(await read(issuer.context, testId(110_999))).toBeNull();
      const foreignOrg = testId(111_000),
        foreignMember = testId(111_001);
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values($1,'Other','Other','other','UTC')",
        [foreignOrg]
      );
      await pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Other','Other','active')",
        [foreignMember, foreignOrg]
      );
      expect(await read(issuer.context, foreignMember)).toBeNull();
      await pool.query(
        "update access_token_records set scope_set=array['governance:read'] where id=$1",
        [issuer.accessTokenRecordId]
      );
      expect(await read()).toBeNull();
      await pool.query(
        "update access_token_records set scope_set=array['governance:read','secretariat:admin'] where id=$1",
        [issuer.accessTokenRecordId]
      );
      expect((await read()).items).toHaveLength(2);
      await pool.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [issuer.accessTokenRecordId]
      );
      expect(await read()).toBeNull();
      for (const role of ["boardagent_worker", "boardagent_backup"])
        expect(
          (
            await pool.query(
              "select has_function_privilege($1,'boardagent_member_recovery_credentials(uuid)','EXECUTE') as allowed",
              [role]
            )
          ).rows[0]?.allowed
        ).toBe(false);
      await expect(
        pool.query("select boardagent_member_recovery_credentials($1)", [target.memberId])
      ).rejects.toMatchObject({ code: "42501" });
    });
  });
  it("bounds a large inventory and marks it incomplete without selecting secret material", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      for (let index = 0; index < 129; index++) {
        const id = testId(112_000 + index);
        await pool.query(
          "insert into webauthn_credentials(id,organization_id,member_id,credential_id,public_key,signature_counter,transports,backup_eligible,backup_state,state) values($1,$2,$3,$4,$5,0,'{}',false,false,'active')",
          [
            id,
            issuer.organizationId,
            target.memberId,
            createHash("sha256").update(id).digest(),
            Buffer.alloc(64, 0xbc)
          ]
        );
      }
      const result = await withRequestTransaction(
        pool,
        issuer.context,
        async (client) =>
          (
            await client.query("select boardagent_member_recovery_credentials($1) as result", [
              target.memberId
            ])
          ).rows[0]?.result,
        { assumeRole: "boardagent_server" }
      );
      expect(result.complete).toBe(false);
      expect(result.items).toHaveLength(128);
      expect(result.items[0].credential_record_id).toBe(testId(112_000));
      expect(result.items[127].credential_record_id).toBe(testId(112_127));
    });
  });
});
