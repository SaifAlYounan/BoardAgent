import { describe, it, expect } from "vitest";
import {
  PgBoardAgentSurfaceService,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  sha256Hex,
  canonicalJson,
  canonicalSha256
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction, withWorkerTransaction } from "../../lib/db/src/index.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";
import { confirmSyntheticSurfaceAction } from "../helpers/confirmed-surface-action.js";
const scopes = [
  "secretariat:admin",
  "governance:read",
  "management:question",
  "meeting:act",
  "minutes:act"
] as const;
function principal(
  a: AuthorizedActorFixture,
  secretary = false,
  management = false
): SurfacePrincipal {
  return {
    organizationId: a.organizationId,
    memberId: a.memberId,
    clientId: a.clientId,
    accessTokenRecordId: a.accessTokenRecordId,
    tokenJti: a.tokenJti,
    serviceOrigin: "https://boardagent.test",
    protocolClientId: "object-recusal-synthetic",
    keyId: "test-oauth",
    boardIds: [a.boardId],
    scopes: management
      ? ["governance:read", "management:question"]
      : secretary
        ? scopes
        : scopes.filter((s) => s !== "secretariat:admin"),
    roles: secretary ? ["member", "secretariat"] : management ? ["management"] : ["member"]
  };
}

describe("named object recusal authority", () => {
  it.each([
    ["question", false],
    ["meeting", false],
    ["minutes", false],
    ["question", true],
    ["meeting", true]
  ] as const)(
    "%s future activity=%s: add/lift hides root and child records while preserving canonical bytes and the board appointment",
    async (kind, future) => {
      await withMigratedDatabase("object-recusal", async (pool) => {
        const secretary = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          isSecretary: true,
          scopes
        });
        const member = await seedAdditionalAuthorizedActor(pool, secretary, {
          idBase: 310000,
          seatRole: "voting_member",
          scopes: scopes.filter((s) => s !== "secretariat:admin")
        });
        const manager = await seedAdditionalAuthorizedActor(pool, secretary, {
          idBase: 311000,
          seatRole: "management",
          scopes: ["governance:read", "management:question"]
        });
        let n = 312000;
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
        const meetingId = testId(313000),
          minutesId = testId(313001),
          questionId = testId(313002);
        const targetId =
          kind === "meeting" ? meetingId : kind === "minutes" ? minutesId : questionId;
        if (kind === "question") {
          await service.executeDirect(principal(member), "ask_management", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: secretary.boardId,
            question_id: questionId,
            owner_member_id: manager.memberId,
            due_at: "2099-10-01T09:00:00Z",
            question: "What assumptions support the next exploration budget?",
            citations: [],
            idempotency_key: "object-recusal-question-create-0001"
          });
        } else {
          await confirmSyntheticSurfaceAction(
            service,
            principal(secretary, true),
            "create_meeting",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              board_id: secretary.boardId,
              meeting_id: meetingId,
              title: "Synthetic exploration programme meeting",
              scheduled_start_at: "2099-10-01T09:00:00Z",
              scheduled_end_at: "2099-10-01T10:00:00Z",
              timezone: "Asia/Dubai",
              agenda: {
                schema_version: "boardagent.agenda.v1",
                values: {
                  items: [
                    {
                      title: "Review the exploration programme",
                      source_document_version_id: null,
                      source_document_sha256: null
                    }
                  ]
                }
              },
              attendee_member_ids: [secretary.memberId, member.memberId],
              idempotency_key: "object-recusal-meeting-create-0001"
            }
          );
          if (kind === "minutes") {
            const text = "# Minutes\nThe board reviewed the exploration programme.\n";
            const draft = await service.executeDirect(
              principal(secretary, true),
              "create_minutes_version",
              {
                schema_version: TOOL_INPUT_SCHEMA_VERSION,
                minutes_id: minutesId,
                meeting_id: meetingId,
                canonical_text: text,
                transcript_version_id: null,
                expected_current_version_id: null,
                idempotency_key: "object-recusal-minutes-create-0001"
              }
            );
            await confirmSyntheticSurfaceAction(
              service,
              principal(secretary, true),
              "publish_minutes",
              {
                schema_version: TOOL_INPUT_SCHEMA_VERSION,
                minutes_id: minutesId,
                version_id: draft.reference,
                minutes_sha256: sha256Hex(text),
                signer_member_ids: [secretary.memberId, member.memberId],
                idempotency_key: "object-recusal-minutes-publish-0001"
              }
            );
          }
        }
        const root =
          kind === "question"
            ? "management_questions"
            : kind === "meeting"
              ? "meetings"
              : "minutes";
        const child =
          kind === "question"
            ? "management_question_turns"
            : kind === "meeting"
              ? "meeting_versions"
              : "minutes_versions";
        const foreignKey =
          kind === "question" ? "question_id" : kind === "meeting" ? "meeting_id" : "minutes_id";
        const appointment = (
          await pool.query(
            "select row_to_json(m)::text bytes from board_memberships m where member_id=$1",
            [member.memberId]
          )
        ).rows;
        const original = (
          await pool.query(
            `select row_to_json(v)::text bytes from ${child} v where ${foreignKey}=$1 order by id`,
            [targetId]
          )
        ).rows;
        const visible = () =>
          withRequestTransaction(
            pool,
            member.context,
            async (c) => ({
              roots: (await c.query(`select id from ${root} where id=$1`, [targetId])).rows,
              children: (
                await c.query(`select id from ${child} where ${foreignKey}=$1`, [targetId])
              ).rows,
              board: (await c.query("select id from boards where id=$1", [member.boardId])).rows
            }),
            { assumeRole: "boardagent_server" }
          );
        const before = await visible();
        expect(before.roots).toHaveLength(1);
        expect(before.children).toHaveLength(1);
        const action = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: secretary.boardId,
          object_type: kind,
          object_id: targetId,
          member_id: member.memberId,
          operation: "add",
          reason: "Declared conflict on this named record",
          idempotency_key: `object-${kind}-recusal-add-0001`
        } as const;
        const excluded = await confirmSyntheticSurfaceAction(
          service,
          principal(secretary, true),
          "manage_recusal",
          action
        );
        expect(excluded.prepared.target_type).toBe(kind);
        expect(excluded.result.data).toMatchObject({ state: "excluded" });
        await expect(
          withRequestTransaction(
            pool,
            secretary.context,
            (c) =>
              c.query("select boardagent_apply_record_recusal($1,$2,$3)", [
                secretary.consentRecordId,
                testId(313099),
                testId(313098)
              ]),
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toThrow(/exact confirmed authority/);
        for (const table of ["meeting_exclusions", "minutes_exclusions"]) {
          expect(
            (
              await pool.query(
                "select has_table_privilege('boardagent_server',$1,'INSERT,UPDATE,DELETE') as writable",
                [table]
              )
            ).rows[0].writable
          ).toBe(false);
        }
        if (kind !== "question" && !future) {
          const exportId = testId(313097);
          const exportScope = {
            schemaVersion: "boardagent.export-scope.v1",
            exportType: "system_data",
            organizationId: secretary.organizationId,
            boardId: secretary.boardId,
            scope: "board",
            memberId: null,
            purpose: "Synthetic recusal evidence retention",
            dataClasses: [kind === "meeting" ? "meetings" : "minutes_tasks"],
            includeCanonicalContent: true,
            excludeSecretMaterial: true
          };
          await pool.query(
            "insert into export_requests(id,public_id,organization_id,board_id,requester_member_id,export_type,scope_manifest,scope_sha256,state,consent_record_id,recent_auth_at,expires_at) values($1,$2,$3,$4,$5,'system_data',$6,$7,'queued',$8,transaction_timestamp(),transaction_timestamp()+interval '1 hour')",
            [
              exportId,
              Buffer.alloc(32, 91),
              secretary.organizationId,
              secretary.boardId,
              secretary.memberId,
              Buffer.from(canonicalJson(exportScope)),
              Buffer.from(canonicalSha256(exportScope), "hex"),
              secretary.consentRecordId
            ]
          );
          const exported = await withWorkerTransaction(
            pool,
            async (c) =>
              (
                await c.query(
                  "select table_rows from boardagent_export_system_table_rows($1,$2,$3)",
                  [exportId, exportScope.dataClasses[0], `${kind}_exclusions`]
                )
              ).rows[0]?.table_rows,
            { assumeRole: "boardagent_worker", isolation: "repeatable read" }
          );
          expect(exported).toMatchObject([{ member_id: member.memberId, state: "excluded" }]);
        }
        const hidden = await visible();
        expect(
          await withWorkerTransaction(
            pool,
            async (c) =>
              (
                await c.query("select boardagent_member_record_recused($1,$2,$3) as denied", [
                  kind,
                  targetId,
                  member.memberId
                ])
              ).rows[0]?.denied,
            { assumeRole: "boardagent_worker" }
          )
        ).toBe(true);
        expect(hidden.roots).toEqual([]);
        expect(hidden.children).toEqual([]);
        expect(hidden.board).toEqual(before.board);
        if (future) {
          const noticeCount = (
            await pool.query(
              "select id from notices where recipient_member_id=$1 and object_type=$2 and object_id=$3",
              [member.memberId, kind, targetId]
            )
          ).rowCount;
          if (kind === "question") {
            const answer = await service.executeDirect(
              principal(manager, false, true),
              "answer_management_question",
              {
                schema_version: TOOL_INPUT_SCHEMA_VERSION,
                question_id: questionId,
                answer: "The programme assumes staged permitting and a capped phase-one budget.",
                idempotency_key: "recusal-future-answer-0001"
              }
            );
            expect(answer.status).toBe("accepted");
          } else {
            await confirmSyntheticSurfaceAction(
              service,
              principal(secretary, true),
              "amend_meeting",
              {
                schema_version: TOOL_INPUT_SCHEMA_VERSION,
                meeting_id: meetingId,
                expected_row_version: 1,
                title: "Updated programme meeting",
                scheduled_start_at: "2099-10-01T09:30:00Z",
                scheduled_end_at: "2099-10-01T10:30:00Z",
                timezone: "Asia/Dubai",
                agenda: {
                  schema_version: "boardagent.agenda.v1",
                  values: {
                    items: [
                      {
                        title: "Review permitting assumptions",
                        source_document_version_id: null,
                        source_document_sha256: null
                      }
                    ]
                  }
                },
                reason: "Clarify the agenda",
                idempotency_key: "recusal-future-meeting-0001"
              }
            );
          }
          expect((await visible()).roots).toEqual([]);
          expect(
            (
              await pool.query(
                "select id from notices where recipient_member_id=$1 and object_type=$2 and object_id=$3",
                [member.memberId, kind, targetId]
              )
            ).rowCount
          ).toBe(noticeCount);
        }
        await confirmSyntheticSurfaceAction(service, principal(secretary, true), "manage_recusal", {
          ...action,
          operation: "lift",
          reason: "Declared conflict has ended",
          idempotency_key: `object-${kind}-recusal-lift-0001`
        });
        const restored = await visible();
        expect(restored.roots).toEqual(before.roots);
        expect(restored.board).toEqual(before.board);
        expect(restored.children).toHaveLength(future ? 2 : 1);
        expect(
          (
            await pool.query(
              `select row_to_json(v)::text bytes from ${child} v where id=any($1::uuid[]) order by id`,
              [before.children.map((r: { id: string }) => r.id)]
            )
          ).rows
        ).toEqual(original);
        expect(
          (
            await pool.query(
              "select row_to_json(m)::text bytes from board_memberships m where member_id=$1",
              [member.memberId]
            )
          ).rows
        ).toEqual(appointment);
        if (kind === "question" && !future) {
          await confirmSyntheticSurfaceAction(
            service,
            principal(secretary, true),
            "manage_recusal",
            {
              ...action,
              member_id: manager.memberId,
              idempotency_key: "question-owner-recusal-add-0001"
            }
          );
          await expect(
            service.executeDirect(principal(manager, false, true), "answer_management_question", {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              question_id: questionId,
              answer: "An excluded owner cannot answer.",
              idempotency_key: "question-owner-denied-answer-0001"
            })
          ).rejects.toThrow();
          await confirmSyntheticSurfaceAction(
            service,
            principal(secretary, true),
            "manage_recusal",
            {
              ...action,
              member_id: manager.memberId,
              operation: "lift",
              idempotency_key: "question-owner-recusal-lift-0001"
            }
          );
          const answer = await service.executeDirect(
            principal(manager, false, true),
            "answer_management_question",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              question_id: questionId,
              answer: "The eligible owner can resume answering after the conflict ends.",
              idempotency_key: "question-owner-restored-answer-0001"
            }
          );
          expect(answer.status).toBe("accepted");
        }
        if (!future) {
          const otherSecretary = await seedAdditionalAuthorizedActor(pool, secretary, {
            idBase: 314000,
            seatRole: "voting_member",
            isSecretary: true,
            scopes
          });
          const selfAction = {
            ...action,
            member_id: secretary.memberId,
            idempotency_key: `record-self-${kind}-add-0001`
          };
          await confirmSyntheticSurfaceAction(
            service,
            principal(secretary, true),
            "manage_recusal",
            selfAction
          );
          const selfLift = {
            ...selfAction,
            operation: "lift",
            idempotency_key: `record-self-${kind}-lift-0001`
          };
          await expect(
            service.prepareHumanAction(principal(secretary, true), "manage_recusal", selfLift)
          ).rejects.toThrow(/recusal is unavailable/);
          await confirmSyntheticSurfaceAction(
            service,
            principal(otherSecretary, true),
            "manage_recusal",
            selfLift
          );
        }
      });
    }
  );
});
