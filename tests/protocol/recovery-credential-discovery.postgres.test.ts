import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("SR-102 private recovery credential discovery", () => {
  it("lets an existing human administrator select a retained passkey through MCP without disclosing credential material", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const admin = await f.connect(await f.login(f.issuer.memberId));
        const secretary = await f.connect(await f.login(f.target.memberId));
        const profile = await admin.callTool({
          name: "get_member",
          arguments: { schema_version: SCHEMA, member_id: f.target.memberId }
        });
        expect(profile.isError).not.toBe(true);
        const member = (
          profile.structuredContent as {
            data: {
              member: {
                recovery_credentials: {
                  items: Array<{ credential_record_id: string; kind: string; state: string }>;
                  complete: boolean;
                };
              };
            };
          }
        ).data.member;
        expect(member.recovery_credentials).toMatchObject({
          complete: true,
          items: [{ kind: "passkey", state: "active" }]
        });
        const selected = member.recovery_credentials.items[0]!.credential_record_id;
        const text = JSON.stringify(profile.structuredContent);
        for (const name of [
          "public_key",
          "encrypted_secret",
          "signature_counter",
          "credential_id_base64url",
          "opaque_session_sha256"
        ])
          expect(text).not.toContain(name);
        const own = await secretary.callTool({
          name: "get_member",
          arguments: { schema_version: SCHEMA, member_id: f.target.memberId }
        });
        expect(own.isError).not.toBe(true);
        expect(own.structuredContent).toMatchObject({
          data: { member: { recovery_credentials: null } }
        });
        expect(JSON.stringify(own.structuredContent)).not.toContain(selected);
        const delegation = await admin.callTool({
          name: "manage_member_admin_delegation",
          arguments: f.input
        });
        expect(delegation.isError).not.toBe(true);
        const delegatedSecretary = await f.connect(await f.login(f.target.memberId));
        const delegatedView = await delegatedSecretary.callTool({
          name: "get_member",
          arguments: { schema_version: SCHEMA, member_id: f.target.memberId }
        });
        expect(delegatedView.isError).not.toBe(true);
        expect(delegatedView.structuredContent).toMatchObject({
          data: { member: { recovery_credentials: null } }
        });
        expect(JSON.stringify(delegatedView.structuredContent)).not.toContain(selected);
        const recovered = await admin.callTool({
          name: "initiate_identity_recovery",
          arguments: {
            schema_version: SCHEMA,
            member_id: f.target.memberId,
            reason: "Retain the independently verified synthetic passkey",
            proofing_method: "verified_number_call",
            credential_disposition: "preserve_named",
            preserved_credential_ids: [selected],
            idempotency_key: "recovery-discovery-preserve-key"
          }
        });
        expect(recovered.isError).not.toBe(true);
        const reconnected = await f.connect(await f.login(f.target.memberId));
        expect(
          (await reconnected.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .structuredContent
        ).toMatchObject({ data: { member_id: f.target.memberId } });
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });
});
