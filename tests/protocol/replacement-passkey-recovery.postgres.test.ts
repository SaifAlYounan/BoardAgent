import { Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { administrativeOAuthFixture, testAuthenticator } from "../helpers/administrative-oauth.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("AC24 replacement passkey recovery", () => {
  it("MR-ENROLL-001 contains a registered pending member without a replacement grant or activation", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const admin = await f.connect(await f.login(f.issuer.memberId));
        const memberId = testId(109500);
        const invited = await admin.callTool({
          name: "manage_member",
          arguments: {
            schema_version: SCHEMA,
            change: {
              operation: "invite",
              member_id: memberId,
              board_id: f.issuer.boardId,
              member_kind: "human",
              seat_role: "voting_member",
              legal_name: "Pending Recovery Person",
              display_name: "Pending Recovery Person",
              voting_weight: 1,
              accountable_principal_id: null
            },
            idempotency_key: "pending-recovery-invite-person"
          }
        });
        expect(invited.isError).not.toBe(true);
        const issued = await admin.callTool({
          name: "issue_enrollment",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            handoff_method: "operator_display",
            expires_in_seconds: 900,
            idempotency_key: "pending-recovery-issue-enrollment"
          }
        });
        expect(issued.isError).not.toBe(true);
        const enrollment = (issued.structuredContent as { data: { enrollment_link: string } }).data;
        const person = f.browserSession();
        const page = await person.get("/enroll");
        expect(page.status).toBe(200);
        const csrf = /name="csrf_token" value="([A-Za-z0-9_.-]+)"/u.exec(await page.text())?.[1];
        if (!csrf) throw new Error("enrollment page lacks CSRF token");
        const common = {
          csrf_token: csrf,
          invitation_token: new URL(enrollment.enrollment_link).hash.slice(1)
        };
        const begun = await person.post("/enroll/passkey/begin", common);
        expect(begun.status).toBe(200);
        const options = (await begun.json()) as { publicKey: { challenge: string } };
        const original = testAuthenticator();
        const completed = await person.post("/enroll/passkey/complete", {
          ...common,
          proofing_method: "verified_number_call",
          credential: JSON.stringify(original.registration(options.publicKey.challenge, f.origin))
        });
        expect(completed.status).toBe(200);
        const pending = (await completed.json()) as {
          status: string;
          memberId: string;
          invitationId: string;
          activationChallengeId: string;
        };
        expect(pending).toMatchObject({ status: "pending_activation", memberId });
        const invitationBefore = (
          await pool.query("select * from enrollment_invitations where id=$1", [
            pending.invitationId
          ])
        ).rows;
        const challengeBefore = (
          await pool.query("select * from enrollment_activation_challenges where id=$1", [
            pending.activationChallengeId
          ])
        ).rows;
        const seatsBefore = (
          await pool.query("select * from board_memberships where member_id=$1 order by id", [
            memberId
          ])
        ).rows;
        expect(invitationBefore[0]?.consumed_at).not.toBeNull();
        expect(challengeBefore[0]?.state).toBe("issued");

        // The activation handoff was lost. Reach this state through public enrollment,
        // then exercise the existing administrator recovery ceremony without resetting it.
        const recovered = await admin.callTool({
          name: "initiate_identity_recovery",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            reason: "Recover the registered pending person after loss of the activation handoff",
            proofing_method: "verified_number_call",
            credential_disposition: "revoke_all",
            preserved_credential_ids: [],
            idempotency_key: "pending-recovery-confirmed-handoff"
          }
        });
        expect(recovered.isError).not.toBe(true);
        const data = (
          recovered.structuredContent as {
            data: {
              state: string;
              recoveryRequestId: string;
              replacement_enrollment?: { url: string };
            };
          }
        ).data;
        expect(data.state).toBe("initiated");
        expect(
          (await pool.query("select state from members where id=$1", [memberId])).rows[0]?.state
        ).toBe("pending_activation");
        expect(
          (
            await pool.query("select state from webauthn_credentials where member_id=$1", [
              memberId
            ])
          ).rows
        ).toEqual([{ state: "revoked" }]);
        expect(
          (
            await pool.query("select * from enrollment_invitations where id=$1", [
              pending.invitationId
            ])
          ).rows
        ).toEqual(invitationBefore);
        expect(
          (
            await pool.query("select * from enrollment_activation_challenges where id=$1", [
              pending.activationChallengeId
            ])
          ).rows
        ).toEqual(challengeBefore);
        expect(
          (
            await pool.query("select * from board_memberships where member_id=$1 order by id", [
              memberId
            ])
          ).rows
        ).toEqual(seatsBefore);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from pending_action_feed where member_id=$1",
              [memberId]
            )
          ).rows[0]?.n
        ).toBe(0);
        expect(f.errors).toEqual([]);
        // The current replacement policy covers active humans only. Pending-person
        // containment does not implement activation recovery or authorize a new grant.
        expect(data.replacement_enrollment).toBeUndefined();
        expect(
          (
            await pool.query(
              "select count(*)::int as n from recovery_registration_grants where recovery_request_id=$1",
              [data.recoveryRequestId]
            )
          ).rows[0]?.n
        ).toBe(0);
      } finally {
        await f.close();
      }
    });
  });

  it("recovers the same person after loss of all passkeys through a confirmed one-use handoff and verified registration", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const admin = await f.connect(await f.login(f.issuer.memberId));
        const oldToken = await f.login(f.target.memberId);
        const before = (await pool.query("select * from board_memberships order by id")).rows;
        const roles = (await pool.query("select * from organization_role_assignments order by id"))
          .rows;
        const result = await admin.callTool({
          name: "initiate_identity_recovery",
          arguments: {
            schema_version: SCHEMA,
            member_id: f.target.memberId,
            reason: "Replace the lost synthetic device after verified-person proof",
            proofing_method: "verified_number_call",
            credential_disposition: "revoke_all",
            preserved_credential_ids: [],
            idempotency_key: "replacement-recovery-lost-passkey"
          }
        });
        expect(result.isError).not.toBe(true);
        const data = result.structuredContent as {
          data: {
            recoveryRequestId: string;
            replacement_enrollment: { url: string; expires_at: string };
          };
        };
        expect(data.data.replacement_enrollment).toBeDefined();
        const link = new URL(data.data.replacement_enrollment.url);
        expect(link.origin).toBe(f.origin);
        expect(link.pathname).toBe("/recover");
        expect(link.search).toBe("");
        expect(link.hash.slice(1)).toMatch(/^[A-Za-z0-9_-]{43}$/u);
        const person = f.browserSession();
        const page = await person.get("/recover");
        expect(page.status).toBe(200);
        const html = await page.text();
        const script = await person.get("/recover/webauthn.js");
        expect(script.status).toBe(200);
        const scriptText = await script.text();
        expect(() => new Script(scriptText)).not.toThrow();
        const csrf = /name="csrf_token" value="([A-Za-z0-9_-]+)"/u.exec(html)?.[1];
        if (!csrf) throw new Error("recovery page lacks CSRF token");
        const common = { csrf_token: csrf, recovery_token: link.hash.slice(1) };
        const begin = await person.post("/recover/passkey/begin", common);
        expect(begin.status, f.errors.map((e) => e.message).join("; ")).toBe(200);
        const options = (await begin.json()) as {
          memberDisplayName: string;
          publicKey: { challenge: string };
        };
        expect(options.memberDisplayName).toEqual(expect.any(String));
        const auth = testAuthenticator();
        const completion = {
          ...common,
          credential: JSON.stringify(auth.registration(options.publicKey.challenge, f.origin))
        };
        const completed = await person.post("/recover/passkey/complete", completion);
        expect(completed.status, f.errors.map((e) => e.message).join("; ")).toBe(200);
        const pending = (await completed.json()) as {
          status: string;
          memberId: string;
          invitationId: string;
          activationChallengeId: string;
          activationCode: string;
          proofingMethod: string;
        };
        expect(pending).toMatchObject({
          status: "pending_activation",
          memberId: f.target.memberId
        });
        expect(
          (
            await pool.query(
              "select count(*)::int as count from webauthn_credentials where member_id=$1 and state='active'",
              [f.target.memberId]
            )
          ).rows[0].count
        ).toBe(0);
        const activation = await admin.callTool({
          name: "confirm_enrollment_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: pending.memberId,
            invitation_id: pending.invitationId,
            challenge_id: pending.activationChallengeId,
            confirmation_code: pending.activationCode,
            proofing_method: pending.proofingMethod,
            idempotency_key: "replacement-human-confirmation"
          }
        });
        expect(
          activation.isError,
          JSON.stringify(activation.content)
            .replaceAll(pending.activationCode, "[redacted]")
            .replaceAll(link.hash.slice(1), "[redacted]") +
            f.errors.map((e) => e.message).join("; ")
        ).not.toBe(true);
        expect(activation.structuredContent).toMatchObject({
          data: { activated: true, next_action: "fresh_sign_in", onboarding_tasks_created: 0 }
        });
        expect((await person.post("/recover/passkey/complete", completion)).status).toBe(400);
        expect((await person.post("/recover/passkey/begin", common)).status).toBe(400);
        const denied = await f.trustedFetch(f.resource, {
          method: "POST",
          headers: {
            authorization: `Bearer ${oldToken.access_token}`,
            "content-type": "application/json"
          },
          body: "{}"
        });
        expect(denied.status).toBe(401);
        await f.registerAgent(f.target.memberId, auth);
        const fresh = await f.connect(await f.login(f.target.memberId));
        expect(
          (await fresh.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .structuredContent
        ).toMatchObject({ data: { member_id: f.target.memberId } });
        expect((await pool.query("select * from board_memberships order by id")).rows).toEqual(
          before
        );
        expect(
          (await pool.query("select * from organization_role_assignments order by id")).rows
        ).toEqual(roles);
        expect(
          (
            await pool.query("select state from identity_recovery_requests where id=$1", [
              data.data.recoveryRequestId
            ])
          ).rows[0].state
        ).toBe("completed");
        const audit = (
          await pool.query(
            "select convert_from(canonical_payload,'UTF8') as payload from audit_events"
          )
        ).rows;
        expect(JSON.stringify(audit)).not.toContain(link.hash.slice(1));
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });
});
