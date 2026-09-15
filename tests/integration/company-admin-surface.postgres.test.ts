import { describe, expect, it } from "vitest";
import type { Pool } from "pg";
import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import type { JsonValue } from "../../lib/contracts/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

type Actor = Awaited<ReturnType<typeof administrativeActors>>["issuer"];
function serviceFor(pool: Pool, actor: Actor, admin: boolean) {
  const principal: SurfacePrincipal = {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    clientId: actor.clientId,
    protocolClientId: "authorized-test-client",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    serviceOrigin: "https://boardagent.test",
    roles: admin ? ["admin", "member", "secretariat"] : ["member"],
    scopes: ["secretariat:admin", "governance:read"],
    boardIds: [actor.boardId]
  };
  const service = new PgBoardAgentSurfaceService(pool, {
    reads: new PgSurfaceReadRepository(pool, {
      cursorKey: Buffer.alloc(32, 7),
      transaction: { assumeRole: "boardagent_server" }
    }),
    transaction: { assumeRole: "boardagent_server" }
  });
  return { service, principal };
}
async function staged(
  pool: Pool,
  actor: Actor,
  admin: boolean,
  input: JsonValue,
  tool = "manage_company_admin"
) {
  const { service, principal } = serviceFor(pool, actor, admin);
  const prepared = await service.prepareHumanAction(principal, tool, input);
  const client_capabilities = { elicitation: { form: {} } };
  const request_state = `company-admin-state-${prepared.stage_id}`;
  await service.persistHumanStage({
    principal,
    tool,
    input,
    prepared,
    client_capabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: "Confirm exact administrative authority" },
    request_state,
    prepared_request_id: Buffer.from("prepare-0001")
  });
  return {
    prepared,
    confirm: (code = prepared.confirmation_code) =>
      service.resolveHumanAction({
        principal,
        tool,
        input,
        stage_id: prepared.stage_id,
        client_capabilities,
        request_state,
        retry_request_id: Buffer.from("retry-0001"),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: code }
      })
  };
}
function proposal(memberId: string, operation: "grant" | "transfer" = "grant"): JsonValue {
  return {
    schema_version: "boardagent.tool-input.v1",
    idempotency_key: "company-admin-proposal-0001",
    change: {
      operation,
      proposal_id: testId(74_000),
      member_id: memberId,
      expected_member_version: 1,
      reason: "Appoint the named human administrator"
    }
  };
}
const acceptance: JsonValue = {
  schema_version: "boardagent.tool-input.v1",
  idempotency_key: "company-admin-acceptance-0001",
  change: {
    operation: "accept",
    proposal_id: testId(74_000),
    expected_proposal_version: 1,
    reason: "I accept this administrative responsibility"
  }
};

describe("SR095/SR096 real administrator H confirmation flow", () => {
  it.each(["grant", "transfer"] as const)(
    "%s requires two personal confirmations and invalidates affected old credentials",
    async (operation) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool);
        const offer = await staged(pool, issuer, true, proposal(target.memberId, operation));
        expect(
          (await pool.query("select count(*)::int as n from company_admin_proposals")).rows[0]
        ).toEqual({ n: 0 });
        expect((await offer.confirm()).confirmed).toBe(true);
        expect(
          (
            await pool.query(
              "select state,row_version::text,expires_at-created_at=interval '24 hours' as lifetime from company_admin_proposals"
            )
          ).rows[0]
        ).toEqual({ state: "pending", row_version: "1", lifetime: true });
        expect(
          (
            await pool.query(
              "select count(*)::int as n from organization_role_assignments where member_id=$1 and role='admin'",
              [target.memberId]
            )
          ).rows[0]
        ).toEqual({ n: 0 });
        const accept = await staged(pool, target, false, acceptance);
        expect((await accept.confirm()).confirmed).toBe(true);
        expect(
          (await pool.query("select state,row_version::text from company_admin_proposals")).rows[0]
        ).toEqual({ state: "accepted", row_version: "2" });
        const roles = await pool.query(
          "select member_id from organization_role_assignments where role='admin' and active_from<=transaction_timestamp() and (active_until is null or active_until>transaction_timestamp()) order by member_id"
        );
        expect(roles.rows.map((row) => row.member_id).sort()).toEqual(
          (operation === "grant" ? [issuer.memberId, target.memberId] : [target.memberId]).sort()
        );
        for (const person of operation === "grant" ? [target] : [issuer, target]) {
          expect(
            (
              await pool.query(
                "select identity_generation::text,row_version::text from members where id=$1",
                [person.memberId]
              )
            ).rows[0]
          ).toEqual({ identity_generation: "2", row_version: "2" });
          expect(
            (
              await pool.query(
                "select revoked_at is not null as revoked from access_token_records where id=$1",
                [person.accessTokenRecordId]
              )
            ).rows[0]
          ).toEqual({ revoked: true });
          expect(
            (
              await pool.query("select state from auth_sessions where member_id=$1", [
                person.memberId
              ])
            ).rows[0]
          ).toEqual({ state: "revoked" });
          expect(
            (
              await pool.query(
                "select state,revoked_at is not null as revoked from refresh_families where member_id=$1",
                [person.memberId]
              )
            ).rows[0]
          ).toEqual({ state: "revoked", revoked: true });
          expect(
            (
              await pool.query(
                "select revoked_at is not null as revoked from oauth_authorization_codes where member_id=$1",
                [person.memberId]
              )
            ).rows[0]
          ).toEqual({ revoked: true });
        }
        expect(
          (
            await pool.query(
              "select count(*)::int as n from administrative_authority_changes where consent_record_id is not null and audit_event_id is not null"
            )
          ).rows[0]
        ).toEqual({ n: 2 });
        expect(
          (
            await pool.query(
              "select count(*)::int as n from idempotency_records where operation='manage_company_admin' and state='succeeded'"
            )
          ).rows[0]
        ).toEqual({ n: 2 });
        const committedEffects = (
          await pool.query("select * from administrative_authority_changes order by id")
        ).rows;
        const committedAssignments = (
          await pool.query("select * from organization_role_assignments order by id")
        ).rows;
        const committedEvents = (
          await pool.query(
            "select * from audit_events where event_type like 'company_admin_%' order by sequence"
          )
        ).rows;
        await expect(accept.confirm()).rejects.toMatchObject({ code: "42501" });
        expect(
          (await pool.query("select * from administrative_authority_changes order by id")).rows
        ).toEqual(committedEffects);
        expect(
          (await pool.query("select * from organization_role_assignments order by id")).rows
        ).toEqual(committedAssignments);
        expect(
          (
            await pool.query(
              "select * from audit_events where event_type like 'company_admin_%' order by sequence"
            )
          ).rows
        ).toEqual(committedEvents);
      });
    }
  );
  it("rejects a wrong confirmation code without creating an offer", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const offer = await staged(pool, issuer, true, proposal(target.memberId));
      expect(await offer.confirm("ZZZZZZZZ")).toEqual({
        confirmed: false,
        reason: "code_mismatch"
      });
      expect(
        (await pool.query("select count(*)::int as n from company_admin_proposals")).rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it("cannot turn the final human administrator into an observer through the existing member tool", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      // Another secretary preserves the separate last-secretary invariant, isolating
      // the missing last-effective-administrator rule in this regression.
      await pool.query("update board_memberships set is_secretary=true where member_id=$1", [
        target.memberId
      ]);
      const change: JsonValue = {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "last-admin-observer-0001",
        change: {
          operation: "change_seat",
          member_id: issuer.memberId,
          board_id: issuer.boardId,
          seat_role: "observer",
          voting_weight: 0,
          is_secretary: false,
          reason: "Change my board capacity"
        }
      };
      await expect(
        (async () => {
          const action = await staged(pool, issuer, true, change, "manage_member");
          await action.confirm();
        })()
      ).rejects.toMatchObject({ code: "23514" });
      expect(
        (
          await pool.query("select seat_role from board_memberships where member_id=$1", [
            issuer.memberId
          ])
        ).rows[0]
      ).toEqual({ seat_role: "voting_member" });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='member_changed'"
          )
        ).rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it.each(["cancel", "decline"] as const)(
    "%s terminates an offer without granting authority",
    async (operation) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool);
        expect(
          (await (await staged(pool, issuer, true, proposal(target.memberId))).confirm()).confirmed
        ).toBe(true);
        const input: JsonValue = {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: `company-admin-${operation}-0001`,
          change: {
            operation,
            proposal_id: testId(74_000),
            expected_proposal_version: 1,
            reason: "End this offer"
          }
        };
        const action = await staged(
          pool,
          operation === "cancel" ? issuer : target,
          operation === "cancel",
          input
        );
        expect((await action.confirm()).confirmed).toBe(true);
        expect((await pool.query("select state from company_admin_proposals")).rows[0]).toEqual({
          state: operation === "cancel" ? "cancelled" : "declined"
        });
        await expect(staged(pool, target, false, acceptance)).rejects.toMatchObject({
          code: "42501"
        });
        expect(
          (
            await pool.query("select identity_generation::text from members where id=$1", [
              target.memberId
            ])
          ).rows[0]
        ).toEqual({ identity_generation: "1" });
      });
    }
  );
  it("denies another person's acceptance and refuses stale recipient authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      expect(
        (await (await staged(pool, issuer, true, proposal(target.memberId))).confirm()).confirmed
      ).toBe(true);
      await expect(staged(pool, issuer, true, acceptance)).rejects.toMatchObject({ code: "42501" });
      const accept = await staged(pool, target, false, acceptance);
      await pool.query("update members set row_version=row_version+1 where id=$1", [
        target.memberId
      ]);
      await expect(accept.confirm()).rejects.toMatchObject({ code: "42501" });
      expect((await pool.query("select state from company_admin_proposals")).rows[0]).toEqual({
        state: "pending"
      });
    });
  });
  it("revokes an accepted assignment and all affected credentials while preserving another administrator", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      expect(
        (await (await staged(pool, issuer, true, proposal(target.memberId))).confirm()).confirmed
      ).toBe(true);
      expect((await (await staged(pool, target, false, acceptance)).confirm()).confirmed).toBe(
        true
      );
      const revoke: JsonValue = {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "company-admin-revoke-0001",
        change: {
          operation: "revoke",
          assignment_id: testId(74_000),
          member_id: target.memberId,
          expected_member_version: 2,
          reason: "End the additional appointment"
        }
      };
      expect((await (await staged(pool, issuer, true, revoke)).confirm()).confirmed).toBe(true);
      expect(
        (
          await pool.query(
            "select member_id from organization_role_assignments where role='admin' and active_until is null"
          )
        ).rows
      ).toEqual([{ member_id: issuer.memberId }]);
      expect(
        (
          await pool.query(
            "select identity_generation::text,row_version::text from members where id=$1",
            [target.memberId]
          )
        ).rows[0]
      ).toEqual({ identity_generation: "3", row_version: "3" });
      const last: JsonValue = {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "company-admin-revoke-last-0001",
        change: {
          operation: "revoke",
          assignment_id: testId(72_000),
          member_id: issuer.memberId,
          expected_member_version: 1,
          reason: "End final appointment"
        }
      };
      await expect(staged(pool, issuer, true, last)).rejects.toMatchObject({ code: "23514" });
    });
  });
  it("rolls consent, receipt and proposal back if audit append fails", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const offer = await staged(pool, issuer, true, proposal(target.memberId));
      const tables = [
        "company_admin_proposals",
        "administrative_authority_changes",
        "consent_records",
        "idempotency_records"
      ];
      const before = new Map<string, unknown>();
      for (const table of tables)
        before.set(table, (await pool.query(`select count(*)::int as n from ${table}`)).rows[0]);
      await pool.query(`create function test_fail_admin_audit() returns trigger language plpgsql as $$ begin raise exception 'synthetic unavailable audit'; end $$;
        create trigger test_admin_audit_failure before insert on audit_events for each row when (new.event_type='company_admin_proposed') execute function test_fail_admin_audit()`);
      await expect(offer.confirm()).rejects.toThrow("synthetic unavailable audit");
      for (const table of tables)
        expect((await pool.query(`select count(*)::int as n from ${table}`)).rows[0]).toEqual(
          before.get(table)
        );
      expect(
        (await pool.query("select state from action_stages where id=$1", [offer.prepared.stage_id]))
          .rows[0]
      ).toEqual({ state: "active" });
    });
  });
  it("acceptance racing cancellation commits exactly one terminal transition", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      expect(
        (await (await staged(pool, issuer, true, proposal(target.memberId))).confirm()).confirmed
      ).toBe(true);
      const cancel: JsonValue = {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "company-admin-racing-cancel-0001",
        change: {
          operation: "cancel",
          proposal_id: testId(74_000),
          expected_proposal_version: 1,
          reason: "Cancel this offer"
        }
      };
      const accepting = await staged(pool, target, false, acceptance);
      const cancelling = await staged(pool, issuer, true, cancel);
      const resolutions = await Promise.allSettled([accepting.confirm(), cancelling.confirm()]);
      expect(resolutions.filter((r) => r.status === "fulfilled" && r.value.confirmed)).toHaveLength(
        1
      );
      expect(resolutions.filter((r) => r.status === "rejected")).toHaveLength(1);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from administrative_authority_changes where record_version=2"
          )
        ).rows[0]
      ).toEqual({ n: 1 });
      const terminal = (await pool.query("select state from company_admin_proposals")).rows[0]
        ?.state;
      expect(["accepted", "cancelled"]).toContain(terminal);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from organization_role_assignments where member_id=$1 and role='admin'",
            [target.memberId]
          )
        ).rows[0]
      ).toEqual({ n: terminal === "accepted" ? 1 : 0 });
    });
  });
  it("expires an unaccepted offer after 24 hours and rejects acceptance even with a still-live actor token", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      expect(
        (await (await staged(pool, issuer, true, proposal(target.memberId))).confirm()).confirmed
      ).toBe(true);
      // Disposable superuser time fixture only: move both fixed lineage timestamps
      // together so the 24-hour database constraint still holds. Runtime cannot do this.
      await pool.query(
        "alter table company_admin_proposals disable trigger boardagent_company_admin_proposal_transition"
      );
      await pool.query(
        "update company_admin_proposals set created_at=created_at-interval '25 hours',expires_at=expires_at-interval '25 hours'"
      );
      await pool.query(
        "alter table company_admin_proposals enable trigger boardagent_company_admin_proposal_transition"
      );
      expect(
        (
          await pool.query(
            "select expires_at<transaction_timestamp() as expired from company_admin_proposals"
          )
        ).rows[0]
      ).toEqual({ expired: true });
      await expect(staged(pool, target, false, acceptance)).rejects.toMatchObject({
        code: "42501"
      });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from organization_role_assignments where member_id=$1 and role='admin'",
            [target.memberId]
          )
        ).rows[0]
      ).toEqual({ n: 0 });
    });
  });
});
