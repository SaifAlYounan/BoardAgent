import { describe, expect, it } from "vitest";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";

describe("AC06/AC24 administrative identity recovery", () => {
  it.each(["unchanged", "substituted"])(
    "MR-IDENTITY-001 rejects completed consent reuse with %s arguments at the protected database helper",
    async (variant) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await administrativeOAuthFixture(pool);
        try {
          const issuer = await f.connect(await f.login(f.issuer.memberId));
          const profile = await issuer.callTool({
            name: "get_member",
            arguments: { schema_version: SCHEMA, member_id: f.target.memberId }
          });
          expect(profile.isError).not.toBe(true);
          const credentials = (
            profile.structuredContent as {
              data: {
                member: {
                  recovery_credentials: {
                    items: Array<{ credential_record_id: string; kind: string }>;
                  };
                };
              };
            }
          ).data.member.recovery_credentials.items;
          const passkey = credentials.find((credential) => credential.kind === "passkey");
          if (!passkey) throw new Error("target fixture has no recovery credential");
          const original = {
            schema_version: SCHEMA,
            member_id: f.target.memberId,
            reason: "Contain a synthetic connection while retaining the verified passkey",
            proofing_method: "verified_number_call",
            credential_disposition: "preserve_named",
            preserved_credential_ids: [passkey.credential_record_id],
            idempotency_key: `identity-consent-original-${variant}`
          } as const;
          const recovery = await issuer.callTool({
            name: "initiate_identity_recovery",
            arguments: original
          });
          expect(recovery.isError).not.toBe(true);
          const data = (
            recovery.structuredContent as {
              data: { recoveryRequestId: string; newIdentityGeneration: string };
            }
          ).data;
          expect(data.newIdentityGeneration).toBe("2");
          const binding = (
            await pool.query<{
              consent_id: string;
              payload_sha256: Buffer;
              client_id: string;
              token_jti: string;
              stage_state: string;
            }>(
              `select consent.id as consent_id,consent.payload_sha256,
                      consent.client_id,consent.token_jti,stage.state as stage_state
                 from identity_recovery_requests recovery
                 join consent_records consent on consent.id=recovery.consent_record_id
                 join action_stages stage on stage.id=consent.stage_id
                where recovery.id=$1`,
              [data.recoveryRequestId]
            )
          ).rows[0];
          if (!binding) throw new Error("completed public recovery has no consent binding");
          expect(binding.stage_state).toBe("confirmed");
          expect(
            (await issuer.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
              .isError
          ).not.toBe(true);
          const projection = async () =>
            (
              await pool.query(
                `select member.state,member.identity_generation::text,member.row_version::text,
                        (select jsonb_agg(jsonb_build_object('id',credential.id,'state',credential.state)
                                order by credential.id)
                           from webauthn_credentials credential where credential.member_id=member.id)
                          as credentials,
                        (select count(*)::int from identity_recovery_requests recovery
                          where recovery.member_id=member.id) as recovery_count,
                        (select count(*)::int from audit_events) as audit_count
                   from members member where member.id=$1`,
                [f.target.memberId]
              )
            ).rows[0];
          const before = await projection();
          expect(before.identity_generation).toBe("2");
          expect(before.credentials).toEqual([
            { id: passkey.credential_record_id, state: "active" }
          ]);
          const repeatedArguments = {
            memberId: f.target.memberId,
            reason: original.reason,
            proofingMethod: original.proofing_method,
            credentialDisposition: variant === "unchanged" ? "preserve_named" : "revoke_all",
            preservedCredentialIds: variant === "unchanged" ? [passkey.credential_record_id] : []
          };
          // This deliberately tests the protected server-role SQL boundary after a real
          // public H action. It is not a claim that the MCP handler replays the action.
          const attempted = await withRequestTransaction(
            pool,
            { ...f.issuer.context, clientId: binding.client_id, tokenJti: binding.token_jti },
            (client) =>
              client.query(
                "select boardagent_apply_identity_admin_action($1,$2,$3::jsonb,$4,$5,$6)",
                [
                  "initiate_identity_recovery",
                  f.target.memberId,
                  repeatedArguments,
                  binding.payload_sha256,
                  binding.consent_id,
                  testId(109700)
                ]
              ),
            { assumeRole: "boardagent_server", isolation: "serializable" }
          ).then(
            () => ({ succeeded: true }),
            () => ({ succeeded: false })
          );
          expect(
            { helperSucceeded: attempted.succeeded, after: await projection() },
            "a completed human consent must neither authorize another helper mutation nor change its credential disposition"
          ).toEqual({ helperSucceeded: false, after: before });
          expect(f.errors).toEqual([]);
        } finally {
          await f.close();
        }
      });
    }
  );

  it("invalidates a waiting offer after issuer recovery, reconnects with the preserved passkey and refuses bootstrap promotion after total credential loss", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool, true);
      try {
        if (!f.third) throw new Error("third-person fixture missing");
        const issuerToken = await f.login(f.issuer.memberId);
        const recipientToken = await f.login(f.third.memberId);
        const issuer = await f.connect(issuerToken);
        const recipient = await f.connect(recipientToken);
        const second = await f.connect(await f.login(f.target.memberId));
        const secondProposal = testId(105_001);
        expect(
          (
            await issuer.callTool({
              name: "manage_company_admin",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: "recovery-second-admin-proposal",
                change: {
                  operation: "grant",
                  proposal_id: secondProposal,
                  member_id: f.target.memberId,
                  expected_member_version: 1,
                  reason: "Establish a separately accountable recovery administrator"
                }
              }
            })
          ).isError
        ).not.toBe(true);
        expect(
          (
            await second.callTool({
              name: "manage_company_admin",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: "recovery-second-admin-acceptance",
                change: {
                  operation: "accept",
                  proposal_id: secondProposal,
                  expected_proposal_version: 1,
                  reason: "Personally accept recovery administration responsibility"
                }
              }
            })
          ).isError
        ).not.toBe(true);
        const recoveryAdmin = await f.connect(await f.login(f.target.memberId));
        const expectedAdmins = [f.issuer.memberId, f.target.memberId]
          .sort()
          .map((member_id) => ({ member_id }));
        const proposalId = testId(105_000);
        expect(
          (
            await issuer.callTool({
              name: "manage_company_admin",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: "recovery-pending-admin-proposal",
                change: {
                  operation: "grant",
                  proposal_id: proposalId,
                  member_id: f.third.memberId,
                  expected_member_version: 1,
                  reason: "Offer authority before the issuer reports a lost device"
                }
              }
            })
          ).isError
        ).not.toBe(true);

        let release: () => void = () => {};
        let presented: () => void = () => {};
        const awaitingPresentation = new Promise<void>((resolve) => {
          presented = resolve;
        });
        const awaitingRelease = new Promise<void>((resolve) => {
          release = resolve;
        });
        recipient.setRequestHandler("elicitation/create", async (request) => {
          const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(
            String(request.params.message)
          )?.[1];
          if (!code) throw new Error("waiting form has no code");
          presented();
          await awaitingRelease;
          return { action: "accept", content: { approve: true, confirmation_code: code } };
        });
        const pending = recipient.callTool({
          name: "manage_company_admin",
          arguments: {
            schema_version: SCHEMA,
            idempotency_key: "recovery-stale-admin-acceptance",
            change: {
              operation: "accept",
              proposal_id: proposalId,
              expected_proposal_version: 1,
              reason: "Accept the exact pending offer"
            }
          }
        });
        // Install a rejection consumer immediately; release the pending client even
        // if recovery fails, so this test cannot leave a held protocol request.
        const settled = pending.then(
          (result) => ({ result }),
          (error: unknown) => ({ error })
        );
        try {
          await Promise.race([
            awaitingPresentation,
            settled.then(() => {
              throw new Error("acceptance ended before elicitation");
            })
          ]);
          const profile = await recoveryAdmin.callTool({
            name: "get_member",
            arguments: { schema_version: SCHEMA, member_id: f.issuer.memberId }
          });
          expect(profile.isError).not.toBe(true);
          const credentials = (
            profile.structuredContent as {
              data: {
                member: {
                  recovery_credentials: {
                    items: Array<{ credential_record_id: string; kind: string }>;
                  };
                };
              };
            }
          ).data.member.recovery_credentials.items;
          expect(credentials).toHaveLength(1);
          expect(credentials[0]!.kind).toBe("passkey");
          const recovery = await recoveryAdmin.callTool({
            name: "initiate_identity_recovery",
            arguments: {
              schema_version: SCHEMA,
              idempotency_key: "recovery-preserve-known-authenticator",
              member_id: f.issuer.memberId,
              reason: "Contain a lost connection while preserving the verified backup passkey",
              proofing_method: "verified_number_call",
              credential_disposition: "preserve_named",
              preserved_credential_ids: [credentials[0]!.credential_record_id]
            }
          });
          expect(recovery.isError).not.toBe(true);
          expect(recovery.structuredContent).toMatchObject({
            data: { state: "initiated", newIdentityGeneration: "2" }
          });
        } finally {
          release();
        }
        const outcome = await settled;
        expect("result" in outcome && outcome.result.isError).toBe(true);
        expect(
          (
            await pool.query(
              "select member_id from organization_role_assignments where role='admin' and active_until is null order by member_id"
            )
          ).rows
        ).toEqual(expectedAdmins);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from administrative_authority_changes where operation='accept' and record_id=$1",
              [proposalId]
            )
          ).rows[0]?.n
        ).toBe(0);
        expect(
          (await recoveryAdmin.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .isError
        ).not.toBe(true);
        const oldConnection = await f.trustedFetch(f.resource, {
          method: "POST",
          headers: {
            authorization: `Bearer ${issuerToken.access_token}`,
            "content-type": "application/json"
          },
          body: "{}"
        });
        expect(oldConnection.status).toBe(401);
        const restored = await f.connect(await f.login(f.issuer.memberId));
        expect(
          (
            await restored.callTool({
              name: "list_administrative_access",
              arguments: { schema_version: SCHEMA, mode: "organization" }
            })
          ).isError
        ).not.toBe(true);
        expect(
          (await recipient.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .isError
        ).not.toBe(true);
        const contained = await restored.callTool({
          name: "initiate_identity_recovery",
          arguments: {
            schema_version: SCHEMA,
            idempotency_key: "recovery-contain-all-authenticators",
            member_id: f.issuer.memberId,
            reason: "Incident containment after loss of every remaining authenticator",
            proofing_method: "in_person",
            credential_disposition: "revoke_all",
            preserved_credential_ids: []
          }
        });
        expect(contained.isError).not.toBe(true);
        // Explicit incident containment removes the other administrator's final
        // authenticator too. Existing role records cannot prove a new person's identity.
        expect(
          (
            await recoveryAdmin.callTool({
              name: "initiate_identity_recovery",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: "recovery-contain-second-admin-authenticators",
                member_id: f.target.memberId,
                reason: "Contain the final administrator's lost authenticator",
                proofing_method: "in_person",
                credential_disposition: "revoke_all",
                preserved_credential_ids: []
              }
            })
          ).isError
        ).not.toBe(true);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from webauthn_credentials where member_id=any($1::uuid[]) and state='active'",
              [[f.issuer.memberId, f.target.memberId]]
            )
          ).rows[0]?.n
        ).toBe(0);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
              [f.issuer.memberId]
            )
          ).rows[0]?.n
        ).toBe(0);
        await expect(
          new BoardAgentBootstrapOperator(pool, {
            assumeRole: "boardagent_migrator",
            expectedCanonicalResourceUri: f.resource
          }).activateFirstSecretary({ activationCode: "ABC-DEFG", proofingMethod: "in_person" })
        ).rejects.toMatchObject({ code: "bootstrap_activation_unavailable" });
        expect(
          (
            await pool.query(
              "select member_id from organization_role_assignments where role='admin' and active_until is null order by member_id"
            )
          ).rows
        ).toEqual(expectedAdmins);
        expect(
          (await pool.query("select count(*)::int as n from identity_recovery_requests")).rows[0]?.n
        ).toBe(3);
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  }, 120_000);
});
