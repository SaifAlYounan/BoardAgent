import { describe, expect, it } from "vitest";
import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/index.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testId
} from "../helpers/authorized-actor.js";

describe("complete declared member administration lifecycle", () => {
  it.each(["suspend", "remove", "reactivate", "change_seat"] as const)(
    "prepares a valid %s operation through the production surface",
    async (operation) => {
      await withMigratedDatabase("member_lifecycle", async (pool) => {
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          isSecretary: true,
          scopes: ["secretariat:admin"]
        });
        await pool.query(
          "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Synthetic lifecycle test')",
          [testId(191000), actor.organizationId, actor.memberId]
        );
        const target = await seedAdditionalAuthorizedActor(pool, actor, {
          idBase: 191100,
          seatRole: "voting_member",
          scopes: ["governance:read"]
        });
        for (const [index, person] of [actor, target].entries()) {
          await pool.query(
            "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())",
            [
              testId(191300 + index),
              person.organizationId,
              Buffer.alloc(32, 90 + index),
              person.memberId,
              person.clientId
            ]
          );
          await pool.query("update access_token_records set session_id=$1 where id=$2", [
            testId(191300 + index),
            person.accessTokenRecordId
          ]);
        }
        if (operation === "reactivate")
          await pool.query(
            "update board_memberships set state='suspended' where board_id=$1 and member_id=$2",
            [actor.boardId, target.memberId]
          );
        // Existing time-limited seats are valid persisted input. An unrelated authority
        // change must not turn that limited grant into indefinite access.
        const windowBefore = await pool.query<{ active_from: string; active_until: string }>(
          "update board_memberships set active_until=transaction_timestamp()+interval '7 days' where board_id=$1 and member_id=$2 returning active_from::text,active_until::text",
          [actor.boardId, target.memberId]
        );
        const principal: SurfacePrincipal = {
          organizationId: actor.organizationId,
          memberId: actor.memberId,
          clientId: actor.clientId,
          protocolClientId: "authorized-test-client",
          accessTokenRecordId: actor.accessTokenRecordId,
          tokenJti: actor.tokenJti,
          keyId: "test-oauth",
          serviceOrigin: "https://boardagent.test",
          roles: ["admin", "member", "secretariat"],
          scopes: ["secretariat:admin"],
          boardIds: [actor.boardId]
        };
        const reads = new PgSurfaceReadRepository(pool, {
          cursorKey: Buffer.alloc(32, 7),
          transaction: { assumeRole: "boardagent_server" }
        });
        const service = new PgBoardAgentSurfaceService(pool, {
          reads,
          transaction: { assumeRole: "boardagent_server" }
        });
        const change =
          operation === "change_seat"
            ? {
                operation,
                member_id: target.memberId,
                board_id: actor.boardId,
                seat_role: "management",
                voting_weight: 0,
                is_secretary: false,
                reason: "Synthetic changed role"
              }
            : {
                operation,
                member_id: target.memberId,
                board_id: actor.boardId,
                reason: "Synthetic lifecycle operation"
              };
        const prepared = await service.prepareHumanAction(principal, "manage_member", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          change,
          idempotency_key: `member-lifecycle-${operation}-0001`
        });
        expect(prepared).toMatchObject({
          action_code: "manage_member",
          target_type: "member",
          target_id: target.memberId,
          board_id: actor.boardId
        });
        expect(prepared.confirmation_code).toMatch(/^[A-Z2-9]{8}$/u);
        const persisted = await pool.query(
          "select state,seat_role from board_memberships where board_id=$1 and member_id=$2",
          [actor.boardId, target.memberId]
        );
        expect(persisted.rows[0]).toEqual({
          state: operation === "reactivate" ? "suspended" : "active",
          seat_role: "voting_member"
        });
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          change,
          idempotency_key: `member-lifecycle-${operation}-0001`
        };
        const capabilities = { elicitation: { form: {} } };
        const requestState = `member-lifecycle-${operation}-request-state-0001`;
        await service.persistHumanStage({
          principal,
          tool: "manage_member",
          input,
          prepared,
          client_capabilities: capabilities,
          embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
          embedded_result: { message: "Confirm exact member authority" },
          request_state: requestState,
          prepared_request_id: Buffer.from("prepare-0001")
        });
        const resolved = await service.resolveHumanAction({
          principal,
          tool: "manage_member",
          input,
          stage_id: prepared.stage_id,
          client_capabilities: capabilities,
          request_state: requestState,
          retry_request_id: Buffer.from("retry-0001"),
          response_action: "accept",
          input_response: { approve: true, confirmation_code: prepared.confirmation_code }
        });
        expect(resolved.confirmed).toBe(true);
        if (operation !== "remove") {
          const windowAfter = await pool.query<{
            active_from: string;
            active_until: string | null;
          }>(
            "select active_from::text,active_until::text from board_memberships where board_id=$1 and member_id=$2",
            [actor.boardId, target.memberId]
          );
          expect(windowAfter.rows[0]).toEqual(windowBefore.rows[0]);
        }
        const changed = await pool.query(
          "select state,seat_role,entitlement_generation::text from board_memberships where board_id=$1 and member_id=$2",
          [actor.boardId, target.memberId]
        );
        expect(changed.rows[0]).toEqual({
          state:
            operation === "suspend" ? "suspended" : operation === "remove" ? "ended" : "active",
          seat_role: operation === "change_seat" ? "management" : "voting_member",
          entitlement_generation: "2"
        });
        expect(
          (
            await pool.query(
              "select revoked_at is not null as revoked from access_token_records where id=$1",
              [target.accessTokenRecordId]
            )
          ).rows[0]
        ).toEqual({ revoked: true });
        expect(
          (await pool.query("select state from auth_sessions where id=$1", [testId(191301)]))
            .rows[0]
        ).toEqual({ state: "revoked" });
        expect(
          (
            await pool.query(
              "select count(*)::integer as n from membership_versions where member_id=$1 and consent_record_id is not null and audit_event_id is not null",
              [target.memberId]
            )
          ).rows[0]
        ).toEqual({ n: 1 });
        expect(
          (
            await pool.query(
              "select count(*)::integer as n from audit_events where event_type='member_changed' and object_id=$1",
              [target.memberId]
            )
          ).rows[0]
        ).toEqual({ n: 1 });
      });
    }
  );
});
