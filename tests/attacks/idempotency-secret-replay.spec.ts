import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { TOOL_INPUT_SCHEMA_VERSION, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  issueEnrollmentInTransaction,
  prepareEnrollmentIssuanceInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

describe("TH-33 idempotency secret replay", () => {
  it("replays only a safe reference and never stores or remints the one-time invitation secret", async () => {
    await withMigratedDatabase("idempotency_secret", async (pool) => {
      const actor = await seedAuthorizedActor(pool, {
        seatRole: "voting_member",
        scopes: ["governance:read", "secretariat:admin"],
        isSecretary: true
      });
      const targetMemberId = testId(33_100);
      await pool.query(
        `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
         values ($1,$2,'human','Invitee','Invitee','invited')`,
        [targetMemberId, actor.organizationId]
      );
      await pool.query(
        `insert into board_memberships(
           id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
         ) values ($1,$2,$3,$4,'voting_member',false,1,'active')`,
        [testId(33_101), actor.organizationId, actor.boardId, targetMemberId]
      );
      const originalArguments = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        member_id: targetMemberId,
        handoff_method: "operator_display" as const,
        expires_in_seconds: 900,
        idempotency_key: "secret-replay-enrollment-0001"
      };
      const prepared = await withRequestTransaction(
        pool,
        actor.context,
        (client) => prepareEnrollmentIssuanceInTransaction(client, originalArguments),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      const invitationId = testId(33_102);
      const firstSecret = Buffer.alloc(32, 0x31).toString("base64url");
      const replaySecret = Buffer.alloc(32, 0x32).toString("base64url");
      const safeResponseSha256 = canonicalSha256({
        schemaVersion: "boardagent.enrollment-safe-response.v1",
        invitationId,
        memberId: targetMemberId
      });
      await pool.query(
        `insert into enrollment_invitations(
           id,organization_id,member_id,token_sha256,issued_by,handoff_method,issued_at,expires_at
         ) values ($1,$2,$3,$4,$5,'operator_display',
           transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '1 hour')`,
        [
          invitationId,
          actor.organizationId,
          targetMemberId,
          Buffer.from(sha256(firstSecret), "hex"),
          actor.memberId
        ]
      );
      await pool.query(
        `insert into idempotency_records(
           id,organization_id,actor_member_id,client_id,operation,idempotency_key,
           request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256,
           expires_at,completed_at
         ) values ($1,$2,$3,$4,'issue_enrollment',$5,$6,'succeeded',
           'enrollment_invitation',$7,$8,transaction_timestamp()+interval '24 hours',
           transaction_timestamp())`,
        [
          testId(33_103),
          actor.organizationId,
          actor.memberId,
          actor.clientId,
          originalArguments.idempotency_key,
          Buffer.from(prepared.requestSha256, "hex"),
          invitationId,
          Buffer.from(safeResponseSha256, "hex")
        ]
      );

      const replay = await withRequestTransaction(
        pool,
        actor.context,
        (client) =>
          issueEnrollmentInTransaction(client, {
            originalArguments,
            expectedPayloadSha256: prepared.payloadSha256,
            invitationId: testId(33_104),
            invitationTokenSha256: sha256(replaySecret),
            idempotencyRecordId: testId(33_105),
            consentRecordId: testId(33_106),
            auditEventId: testId(33_107)
          }),
        { assumeRole: "boardagent_server", isolation: "serializable" }
      );
      expect(replay).toMatchObject({
        replayed: true,
        invitationId,
        memberId: targetMemberId,
        safeResponseSha256,
        auditEvent: null
      });
      expect(
        (
          await pool.query<{ first: string; invitations: string; replay: string }>(
            `select
               count(*)::text as invitations,
               count(*) filter (where token_sha256=$1)::text as first,
               count(*) filter (where token_sha256=$2)::text as replay
             from enrollment_invitations`,
            [Buffer.from(sha256(firstSecret), "hex"), Buffer.from(sha256(replaySecret), "hex")]
          )
        ).rows
      ).toEqual([{ invitations: "1", first: "1", replay: "0" }]);
      const columns = (
        await pool.query<{ column_name: string }>(
          `select column_name from information_schema.columns
            where table_schema='public' and table_name='idempotency_records'`
        )
      ).rows.map(({ column_name: column }) => column);
      expect(columns.some((column) => /secret|token|ciphertext/u.test(column))).toBe(false);
    });
  });
});
