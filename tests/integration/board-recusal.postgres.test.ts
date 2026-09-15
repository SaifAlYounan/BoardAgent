import { describe, it, expect } from "vitest";
import {
  PgBoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { TOOL_INPUT_SCHEMA_VERSION, sha256Hex } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { confirmSyntheticSurfaceAction } from "../helpers/confirmed-surface-action.js";

function principal(actor: AuthorizedActorFixture): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    clientId: actor.clientId,
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    serviceOrigin: "https://boardagent.test",
    protocolClientId: "board-recusal-test",
    keyId: "test-oauth",
    boardIds: [actor.boardId],
    roles: ["member", "secretariat"],
    scopes: ["secretariat:admin", "governance:read", "documents:read", "documents:contribute"]
  };
}

describe("confirmed board recusal", () => {
  it("preserves the appointment while denying board access, recipient fanout and runtime forgery, then lifts without restoring stages", async () => {
    await withMigratedDatabase("board_recusal", async (pool) => {
      const secretary = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        isSecretary: true,
        scopes: ["secretariat:admin", "governance:read", "documents:read", "documents:contribute"]
      });
      const member = await seedAdditionalAuthorizedActor(pool, secretary, {
        idBase: 290000,
        seatRole: "voting_member",
        scopes: ["governance:read", "documents:read"]
      });
      const before = await pool.query(
        "select row_to_json(m)::text as bytes from board_memberships m where member_id=$1",
        [member.memberId]
      );
      let n = 291000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: {
          executeRead: async () => {
            throw new Error("unused read");
          },
          readResource: async () => {
            throw new Error("unused resource");
          }
        },
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(n++)
      });
      const documentId = testId(292000);
      const body = "# Synthetic board document\nA member must stop receiving this once recused.\n";
      const document = await service.executeDirect(
        principal(secretary),
        "create_document_version",
        {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: secretary.boardId,
          document_id: documentId,
          title: "Synthetic recusal evidence",
          media_type: "text/markdown; charset=utf-8",
          schema_name: null,
          canonical_body: body,
          expected_current_version_id: null,
          idempotency_key: "board-recusal-document-create-0001"
        }
      );
      await confirmSyntheticSurfaceAction(service, principal(secretary), "manage_document_access", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: secretary.boardId,
        document_id: documentId,
        operation: "grant",
        member_id: member.memberId,
        permission: "read",
        reason: "Initial explicit read grant",
        idempotency_key: "board-recusal-read-grant-0001"
      });
      await confirmSyntheticSurfaceAction(service, principal(secretary), "circulate_document", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: secretary.boardId,
        document_id: documentId,
        version_id: document.reference,
        document_sha256: sha256Hex(body),
        recipient_member_ids: [member.memberId],
        completeness_statement: "canonical_version_stands_alone",
        idempotency_key: "board-recusal-circulate-0001"
      });
      const oldStages = (
        await pool.query(
          "select id from action_stages where actor_member_id=$1 and state='active'",
          [member.memberId]
        )
      ).rows;
      expect(oldStages.length).toBeGreaterThan(0);
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: secretary.boardId,
        object_type: "board",
        object_id: secretary.boardId,
        member_id: member.memberId,
        operation: "add",
        reason: "Standing board conflict",
        idempotency_key: "board-recusal-add-synthetic-0001"
      } as const;
      const added = await confirmSyntheticSurfaceAction(
        service,
        principal(secretary),
        "manage_recusal",
        input
      );
      expect(added.prepared).toMatchObject({
        action_code: "manage_recusal",
        target_type: "board",
        target_id: secretary.boardId
      });
      expect(added.result.data).toMatchObject({ state: "excluded", member_id: member.memberId });
      expect(added.result.data).toMatchObject({
        invalidated_stages: oldStages.length,
        tombstones: 1
      });
      const removedFeed = (
        await pool.query(
          "select id,state from pending_action_feed where member_id=$1 and object_id=$2",
          [member.memberId, documentId]
        )
      ).rows[0];
      expect(removedFeed.state).toBe("superseded");
      expect(
        (
          await pool.query("select reason_class from feed_tombstones where removed_feed_id=$1", [
            removedFeed.id
          ])
        ).rows
      ).toEqual([{ reason_class: "recused" }]);

      const read = () =>
        withRequestTransaction(
          pool,
          member.context,
          async (c) => ({
            boards: (await c.query("select id from boards where id=$1", [member.boardId])).rows,
            gate: (
              await c.query("select boardagent_context_board_allowed($1) as allowed", [
                member.boardId
              ])
            ).rows[0].allowed,
            token: (
              await c.query("select revoked_at from access_token_records where id=$1", [
                member.accessTokenRecordId
              ])
            ).rows
          }),
          { assumeRole: "boardagent_server" }
        );
      expect(await read()).toMatchObject({
        boards: [],
        gate: false,
        token: [{ revoked_at: null }]
      });
      expect(
        (
          await pool.query(
            "select row_to_json(m)::text as bytes from board_memberships m where member_id=$1",
            [member.memberId]
          )
        ).rows
      ).toEqual(before.rows);
      await withRequestTransaction(
        pool,
        secretary.context,
        async (c) => {
          const recipients = await c.query(
            "select member_id from boardagent_lock_vote_creation_recipients($1)",
            [secretary.boardId]
          );
          expect(recipients.rows.map((r) => r.member_id)).not.toContain(member.memberId);
          const electorate = await c.query(
            "select member_id from boardagent_lock_vote_creation_electorate($1)",
            [secretary.boardId]
          );
          expect(electorate.rows.map((r) => r.member_id)).not.toContain(member.memberId);
        },
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          (c) => c.query("delete from board_exclusions where board_id=$1", [secretary.boardId]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied/);
      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          (c) =>
            c.query("select boardagent_apply_board_recusal($1,$2,$3)", [
              secretary.consentRecordId,
              testId(n++),
              testId(n++)
            ]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/confirmed|unavailable/);
      const sourceNotice = (
        await pool.query("select id from notices where object_id=$1 and recipient_member_id=$2", [
          documentId,
          member.memberId
        ])
      ).rows[0];
      const deniedNoticeId = testId(n++);
      let insertedBeforeCommit = false;
      await expect(
        withRequestTransaction(
          pool,
          secretary.context,
          async (c) => {
            await c.query(
              `insert into notices(id,organization_id,board_id,notice_type,object_type,object_id,object_version,
          recipient_member_id,content_sha256,feed_sequence,audit_event_id)
          select $1,organization_id,board_id,'recusal_guard_probe',object_type,object_id,object_version,
            recipient_member_id,content_sha256,99000,audit_event_id from notices where id=$2`,
              [deniedNoticeId, sourceNotice.id]
            );
            insertedBeforeCommit = true;
          },
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("board recipient is unavailable");
      expect(insertedBeforeCommit).toBe(true);
      expect(
        (await pool.query("select id from notices where id=$1", [deniedNoticeId])).rows
      ).toEqual([]);
      const lifted = await confirmSyntheticSurfaceAction(
        service,
        principal(secretary),
        "manage_recusal",
        {
          ...input,
          operation: "lift",
          reason: "Conflict has ended",
          idempotency_key: "board-recusal-lift-synthetic-0001"
        }
      );
      expect(lifted.result.data).toMatchObject({ state: "lifted" });
      expect(
        (
          await pool.query("select state from action_stages where id=any($1::uuid[])", [
            oldStages.map((r) => r.id)
          ])
        ).rows.every((r) => r.state === "replaced")
      ).toBe(true);
      expect(
        (await pool.query("select state from pending_action_feed where id=$1", [removedFeed.id]))
          .rows[0].state
      ).toBe("superseded");

      expect(await read()).toMatchObject({ boards: [{ id: member.boardId }], gate: true });
      expect(
        (await pool.query("select state,version from board_exclusions order by version")).rows
      ).toEqual([
        { state: "excluded", version: 1 },
        { state: "lifted", version: 2 }
      ]);
      expect(
        (
          await pool.query(
            "select row_to_json(m)::text as bytes from board_memberships m where member_id=$1",
            [member.memberId]
          )
        ).rows
      ).toEqual(before.rows);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='recusal_changed' and object_type='board'"
          )
        ).rows[0].n
      ).toBe(2);
    });
  });
  it("allows self-recusal and requires another entitled secretary to lift it", async () => {
    await withMigratedDatabase("board_self_recusal", async (pool) => {
      const a = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        isSecretary: true,
        scopes: ["secretariat:admin", "governance:read", "documents:read", "documents:contribute"]
      });
      const b = await seedAdditionalAuthorizedActor(pool, a, {
        idBase: 293000,
        seatRole: "voting_member",
        isSecretary: true,
        scopes: ["secretariat:admin", "governance:read", "documents:read", "documents:contribute"]
      });
      let n = 294000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: {
          executeRead: async () => {
            throw new Error("unused read");
          },
          readResource: async () => {
            throw new Error("unused resource");
          }
        },
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(n++)
      });
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: a.boardId,
        object_type: "board",
        object_id: a.boardId,
        member_id: a.memberId,
        operation: "add",
        reason: "Secretary declares conflict",
        idempotency_key: "self-board-recusal-add-0001"
      } as const;
      await confirmSyntheticSurfaceAction(service, principal(a), "manage_recusal", input);
      await expect(
        service.prepareHumanAction(principal(a), "manage_recusal", {
          ...input,
          operation: "lift",
          idempotency_key: "self-board-recusal-lift-0001"
        })
      ).rejects.toThrow(/unavailable/);
      await confirmSyntheticSurfaceAction(service, principal(b), "manage_recusal", {
        ...input,
        operation: "lift",
        idempotency_key: "other-secretary-recusal-lift-0001"
      });
      expect(
        (
          await pool.query(
            "select state from board_exclusions where member_id=$1 order by version",
            [a.memberId]
          )
        ).rows
      ).toEqual([{ state: "excluded" }, { state: "lifted" }]);
    });
  });
});
