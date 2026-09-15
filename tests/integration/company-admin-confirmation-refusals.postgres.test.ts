import { describe, expect, it } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import {
  administrativeService,
  stageAdministrativeAction
} from "../helpers/administrative-service.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
const cases = [
  ["wrong_code", "code_mismatch"],
  ["cancel", "declined"],
  ["expired", "expired"],
  ["changed_arguments", "request_mismatch"],
  ["changed_state", "state_mismatch"],
  ["changed_payload_digest", "canonical_stale"],
  ["extra_form_field", "declined"],
  ["extra_argument", "schema"],
  ["stale_target", "authority"]
] as const;

describe("AC04 exact administrator confirmation refusal contract", () => {
  for (const phase of ["proposal", "acceptance"] as const) {
    it.each(cases)(
      `${phase} refuses %s without an appointment or successful consent`,
      async (variant, reason) => {
        await withAdministrativeDatabase(async (pool) => {
          const { issuer, target } = await administrativeActors(pool);
          const proposalId = testId(112201);
          const offerInput = {
            schema_version: SCHEMA,
            idempotency_key: "tamper-test-administrator-offer",
            change: {
              operation: "grant",
              proposal_id: proposalId,
              member_id: target.memberId,
              expected_member_version: 1,
              reason: "Appoint a second synthetic administrator"
            }
          };
          const acceptanceInput = {
            schema_version: SCHEMA,
            idempotency_key: "tamper-test-administrator-accept",
            change: {
              operation: "accept",
              proposal_id: proposalId,
              expected_proposal_version: 1,
              reason: "Personally accept the exact appointment"
            }
          };
          if (phase === "acceptance") {
            expect(
              (
                await (
                  await stageAdministrativeAction(pool, issuer, "manage_company_admin", offerInput)
                ).confirm()
              ).confirmed
            ).toBe(true);
          }
          const actor = phase === "proposal" ? issuer : target;
          const input = phase === "proposal" ? offerInput : acceptanceInput;
          const staged = await stageAdministrativeAction(
            pool,
            actor,
            "manage_company_admin",
            input
          );
          const { principal, service } = await administrativeService(pool, actor);
          if (variant === "expired") {
            const client = await pool.connect();
            try {
              await client.query("begin");
              // Owned disposable date fixture only; restore the production guard before confirmation.
              await client.query(
                "alter table action_stages disable trigger boardagent_action_stage_binding_guard"
              );
              await client.query(
                "update action_stages set created_at=transaction_timestamp()-interval '10 minutes 1 second', expires_at=transaction_timestamp()-interval '1 second' where id=$1",
                [staged.prepared.stage_id]
              );
              await client.query(
                "alter table action_stages enable trigger boardagent_action_stage_binding_guard"
              );
              await client.query("commit");
            } catch (error) {
              await client.query("rollback");
              throw error;
            } finally {
              client.release();
            }
          }
          if (variant === "stale_target") {
            await pool.query("update members set row_version=row_version+1 where id=$1", [
              target.memberId
            ]);
          }
          if (variant === "changed_payload_digest") {
            const client = await pool.connect();
            try {
              await client.query("begin");
              // Deliberate corruption in an owned disposable fixture. A changed stored
              // digest must also fail canonical revalidation when the action resumes.
              await client.query(
                "alter table action_stages disable trigger boardagent_action_stage_binding_guard"
              );
              await client.query("update action_stages set payload_sha256=$2 where id=$1", [
                staged.prepared.stage_id,
                Buffer.alloc(32, 137)
              ]);
              await client.query(
                "alter table action_stages enable trigger boardagent_action_stage_binding_guard"
              );
              await client.query("commit");
            } catch (error) {
              await client.query("rollback");
              throw error;
            } finally {
              client.release();
            }
          }
          const before = {
            roles: (await pool.query("select * from organization_role_assignments order by id"))
              .rows,
            proposals: (await pool.query("select * from company_admin_proposals order by id")).rows,
            changes: (
              await pool.query("select * from administrative_authority_changes order by id")
            ).rows,
            consents: (await pool.query("select * from consent_records order by id")).rows,
            effects: (
              await pool.query(
                "select * from audit_events where event_type like 'company_admin_%' order by sequence"
              )
            ).rows
          };
          const changedInput: JsonValue =
            variant === "extra_argument"
              ? { ...input, bypass: true }
              : variant === "changed_arguments"
                ? {
                    ...input,
                    change: {
                      ...input.change,
                      reason: "Changed after the person reviewed the form"
                    }
                  }
                : input;
          const resolution = service.resolveHumanAction({
            principal,
            tool: "manage_company_admin",
            input: changedInput,
            stage_id: staged.prepared.stage_id,
            client_capabilities: { elicitation: { form: {} } },
            request_state: `administrative-test-state-${staged.prepared.stage_id}${variant === "changed_state" ? "-tampered" : ""}`,
            retry_request_id: Buffer.from("retry-0001"),
            response_action: variant === "cancel" ? "cancel" : "accept",
            input_response: {
              approve: true,
              confirmation_code:
                variant === "wrong_code"
                  ? `${staged.prepared.confirmation_code[0] === "Z" ? "Y" : "Z"}${staged.prepared.confirmation_code.slice(1)}`
                  : staged.prepared.confirmation_code,
              ...(variant === "extra_form_field" ? { bypass: true } : {})
            }
          });
          if (reason === "schema")
            await expect(resolution).rejects.toMatchObject({ name: "ZodError" });
          else if (reason === "authority")
            await expect(resolution).rejects.toMatchObject({ code: "42501" });
          else await expect(resolution).resolves.toEqual({ confirmed: false, reason });
          expect(
            (await pool.query("select * from organization_role_assignments order by id")).rows
          ).toEqual(before.roles);
          expect(
            (await pool.query("select * from company_admin_proposals order by id")).rows
          ).toEqual(before.proposals);
          expect(
            (await pool.query("select * from administrative_authority_changes order by id")).rows
          ).toEqual(before.changes);
          expect((await pool.query("select * from consent_records order by id")).rows).toEqual(
            before.consents
          );
          expect(
            (
              await pool.query(
                "select * from audit_events where event_type like 'company_admin_%' order by sequence"
              )
            ).rows
          ).toEqual(before.effects);
          if (reason !== "schema" && reason !== "authority") {
            expect(
              (
                await pool.query(
                  "select convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'reason' as reason from audit_events where event_type='consent_rejected' and object_id=$1",
                  [staged.prepared.stage_id]
                )
              ).rows
            ).toEqual([{ reason }]);
            expect(await staged.confirm()).toEqual({
              confirmed: false,
              reason: "stage_not_active"
            });
          }
        });
      }
    );
  }
  it("refuses the exact old acceptance after the issuer cancels the proposal", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const proposalId = testId(112202);
      expect(
        (
          await (
            await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
              schema_version: SCHEMA,
              idempotency_key: "changed-proposal-offer",
              change: {
                operation: "grant",
                proposal_id: proposalId,
                member_id: target.memberId,
                expected_member_version: 1,
                reason: "Create the synthetic pending appointment"
              }
            })
          ).confirm()
        ).confirmed
      ).toBe(true);
      const acceptance = await stageAdministrativeAction(pool, target, "manage_company_admin", {
        schema_version: SCHEMA,
        idempotency_key: "changed-proposal-accept",
        change: {
          operation: "accept",
          proposal_id: proposalId,
          expected_proposal_version: 1,
          reason: "Accept the pending appointment"
        }
      });
      expect(
        (
          await (
            await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
              schema_version: SCHEMA,
              idempotency_key: "changed-proposal-cancel",
              change: {
                operation: "cancel",
                proposal_id: proposalId,
                expected_proposal_version: 1,
                reason: "Withdraw before the recipient accepts"
              }
            })
          ).confirm()
        ).confirmed
      ).toBe(true);
      const roles = (await pool.query("select * from organization_role_assignments order by id"))
        .rows;
      const changes = (
        await pool.query("select * from administrative_authority_changes order by id")
      ).rows;
      await expect(acceptance.confirm()).rejects.toMatchObject({ code: "42501" });
      expect(
        (await pool.query("select * from organization_role_assignments order by id")).rows
      ).toEqual(roles);
      expect(
        (await pool.query("select * from administrative_authority_changes order by id")).rows
      ).toEqual(changes);
      expect(
        (
          await pool.query(
            "select state,row_version::text from company_admin_proposals where id=$1",
            [proposalId]
          )
        ).rows[0]
      ).toEqual({ state: "cancelled", row_version: "2" });
    });
  });
});
