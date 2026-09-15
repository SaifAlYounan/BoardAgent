import { describe, expect, it } from "vitest";
import {
  appendAuditEventsInTransaction,
  confirmStagedActionInTransaction,
  finalizeAdministrativeAuthorityInTransaction,
  planAdministrativeAuthorityInTransaction,
  prepareAdministrativeAuthorityInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { assertAdministrativeCatalog } from "../helpers/administrative-catalog.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { delegationFixture } from "../helpers/administrative-delegation.js";
import { stageAdministrativeAction } from "../helpers/administrative-service.js";
import { testId } from "../helpers/authorized-actor.js";

describe("AC19/AC21 database administrative authority", () => {
  it("has no raw write, role escalation or unintended helper capability on a fresh database", async () => {
    await withAdministrativeDatabase(assertAdministrativeCatalog);
  });
  it.each(["boardagent_server", "boardagent_worker"] as const)(
    "%s cannot insert or alter authority directly",
    async (role) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await delegationFixture(pool);
        const originalConsents = (await pool.query("select * from consent_records order by id"))
          .rows;
        const before = (await pool.query("select * from organization_role_assignments order by id"))
          .rows;
        for (const table of [
          "organization_role_assignments",
          "company_admin_proposals",
          "member_admin_delegations",
          "administrative_authority_changes",
          "consent_records"
        ]) {
          // Names are a fixed test-owned allowlist, never request data.
          await expect(
            withRequestTransaction(
              pool,
              f.issuer.context,
              (client) => client.query(`insert into ${table} default values`),
              { assumeRole: role, isolation: "serializable" }
            )
          ).rejects.toMatchObject({ code: "42501" });
        }
        await expect(
          withRequestTransaction(
            pool,
            f.issuer.context,
            (client) =>
              client.query("update organization_role_assignments set member_id=$1 where id=$2", [
                f.target.memberId,
                testId(72000)
              ]),
            { assumeRole: role, isolation: "serializable" }
          )
        ).rejects.toMatchObject({ code: "42501" });
        expect(
          (await pool.query("select * from organization_role_assignments order by id")).rows
        ).toEqual(before);
        expect((await pool.query("select * from consent_records order by id")).rows).toEqual(
          originalConsents
        );
        for (const table of [
          "company_admin_proposals",
          "member_admin_delegations",
          "administrative_authority_changes"
        ])
          expect((await pool.query(`select count(*)::int as n from ${table}`)).rows[0]).toEqual({
            n: 0
          });
      });
    }
  );
  for (const tool of ["manage_company_admin", "manage_member_admin_delegation"] as const)
    it.each(["missing_audit", "altered_audit", "wrong_consent"] as const)(
      `${tool} direct finalizer refuses %s and rolls back verified consent`,
      async (variant) => {
        await withAdministrativeDatabase(async (pool) => {
          const f = await delegationFixture(pool);
          const originalConsents = (await pool.query("select * from consent_records order by id"))
            .rows;
          const input =
            tool === "manage_member_admin_delegation"
              ? f.input
              : {
                  schema_version: "boardagent.tool-input.v1",
                  idempotency_key: "raw-finalizer-audit-boundary",
                  change: {
                    operation: "grant",
                    proposal_id: testId(112701),
                    member_id: f.target.memberId,
                    expected_member_version: 1,
                    reason: "Synthetic database finalizer audit check"
                  }
                };
          const staged = await stageAdministrativeAction(pool, f.issuer, tool, input);
          const before = (await pool.query("select * from audit_events order by sequence")).rows;
          await expect(
            withRequestTransaction(
              pool,
              f.issuer.context,
              async (client) => {
                const prepared = await prepareAdministrativeAuthorityInTransaction(
                  client,
                  input,
                  tool
                );
                const row = (
                  await client.query("select exact_origin from action_stages where id=$1", [
                    staged.prepared.stage_id
                  ])
                ).rows[0];
                await confirmStagedActionInTransaction(
                  client,
                  {
                    stageId: staged.prepared.stage_id,
                    consentRecordId: testId(112702),
                    retryRequestId: Buffer.from("retry-0001"),
                    originalArguments: input,
                    clientCapabilities: { elicitation: { form: {} } },
                    exactOrigin: row.exact_origin,
                    requestStateBytes: Buffer.from(
                      `administrative-test-state-${staged.prepared.stage_id}`
                    ),
                    responseAction: "accept",
                    inputResponse: {
                      approve: true,
                      confirmation_code: staged.prepared.confirmation_code
                    },
                    auditEventIds: {
                      consentRecorded: testId(112703),
                      consentRejected: testId(112704)
                    }
                  },
                  async () => ({ payloadSha256: prepared.payloadSha256, packageSha256: null }),
                  async (requestClient, consentId) => {
                    // Prove the private verifier accepted the real response before testing finalization.
                    expect(
                      (
                        await requestClient.query(
                          "select count(*)::int as n from consent_records where id=$1",
                          [consentId]
                        )
                      ).rows[0]
                    ).toEqual({ n: 1 });
                    let next = 112710;
                    const plan = await planAdministrativeAuthorityInTransaction(
                      requestClient,
                      prepared,
                      consentId,
                      () => testId(next++)
                    );
                    if (variant !== "missing_audit")
                      await appendAuditEventsInTransaction(requestClient, [
                        variant === "altered_audit"
                          ? {
                              ...plan.auditEvent,
                              event: {
                                ...plan.auditEvent.event,
                                details: { ...plan.auditEvent.event.details, operation: "revoke" }
                              }
                            }
                          : plan.auditEvent
                      ]);
                    await finalizeAdministrativeAuthorityInTransaction(
                      requestClient,
                      variant === "wrong_consent"
                        ? { ...plan, consentRecordId: testId(112720) }
                        : plan
                    );
                    return { value: null, auditEvents: [] };
                  }
                );
              },
              { assumeRole: "boardagent_server", isolation: "serializable" }
            )
          ).rejects.toMatchObject({ code: "42501" });
          expect((await pool.query("select * from audit_events order by sequence")).rows).toEqual(
            before
          );
          for (const table of [
            "company_admin_proposals",
            "member_admin_delegations",
            "administrative_authority_changes"
          ])
            expect((await pool.query(`select count(*)::int as n from ${table}`)).rows[0]).toEqual({
              n: 0
            });
          expect(
            (
              await pool.query("select state from action_stages where id=$1", [
                staged.prepared.stage_id
              ])
            ).rows[0]
          ).toEqual({ state: "active" });
          expect((await pool.query("select * from consent_records order by id")).rows).toEqual(
            originalConsents
          );
          // The refusal did not consume valid consent or poison the ordinary supported retry.
          expect((await staged.confirm()).confirmed).toBe(true);
        });
      }
    );
});
