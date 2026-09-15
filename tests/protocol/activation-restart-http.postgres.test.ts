import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture, testAuthenticator } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
type Fixture = Awaited<ReturnType<typeof administrativeOAuthFixture>>;

function csrfOf(html: string): string {
  const token = /name="csrf_token" value="([A-Za-z0-9_.-]+)"/u.exec(html)?.[1];
  if (!token) throw new Error("ceremony page has no CSRF token");
  return token;
}

/** Invite a person and complete their passkey registration; returns the pending handoff. */
async function registerPendingPerson(f: Fixture, memberId: string, name: string) {
  const admin = await f.connect(await f.login(f.issuer.memberId));
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
        legal_name: name,
        display_name: name,
        voting_weight: 1,
        accountable_principal_id: null
      },
      idempotency_key: `restart-invite-${memberId}`
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
      idempotency_key: `restart-issue-${memberId}`
    }
  });
  expect(issued.isError).not.toBe(true);
  const enrollment = (issued.structuredContent as { data: { enrollment_link: string } }).data;
  const person = f.browserSession();
  const page = await person.get("/enroll");
  expect(page.status).toBe(200);
  const common = {
    csrf_token: csrfOf(await page.text()),
    invitation_token: new URL(enrollment.enrollment_link).hash.slice(1)
  };
  const begun = await person.post("/enroll/passkey/begin", common);
  expect(begun.status).toBe(200);
  const options = (await begun.json()) as { publicKey: { challenge: string } };
  const auth = testAuthenticator();
  const completed = await person.post("/enroll/passkey/complete", {
    ...common,
    proofing_method: "verified_number_call",
    credential: JSON.stringify(auth.registration(options.publicKey.challenge, f.origin))
  });
  expect(completed.status).toBe(200);
  const pending = (await completed.json()) as {
    status: string;
    memberId: string;
    invitationId: string;
    activationChallengeId: string;
    activationCode: string;
  };
  expect(pending).toMatchObject({ status: "pending_activation", memberId });
  return { admin, person, auth, pending };
}

async function restartThroughBrowser(
  f: Fixture,
  person: ReturnType<Fixture["browserSession"]>,
  auth: ReturnType<typeof testAuthenticator>,
  restartLink: string
) {
  const link = new URL(restartLink);
  expect(link.origin).toBe(f.origin);
  expect(link.pathname).toBe("/enroll/restart");
  const page = await person.get("/enroll/restart");
  expect(page.status).toBe(200);
  expect(await page.text()).toContain("Restart your activation");
  const common = {
    csrf_token: csrfOf(await (await person.get("/enroll/restart")).text()),
    restart_token: link.hash.slice(1)
  };
  const begun = await person.post("/enroll/restart/passkey/begin", common);
  if (begun.status !== 200) {
    // A dead handoff refuses at the first step; the caller asserts on `begun`.
    return { common, begun, options: null, completed: null };
  }
  const options = (await begun.json()) as {
    memberDisplayName: string;
    publicKey: { challenge: string };
  };
  const completed = await person.post("/enroll/restart/passkey/complete", {
    ...common,
    credential: JSON.stringify(auth.assertion(options.publicKey.challenge, f.origin))
  });
  return { common, begun, options, completed };
}

describe("activation restart — one-use handoff, existing passkey, fresh code", () => {
  it("restarts an expired pending activation end to end and refuses replay, stale codes and live-code restarts", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const memberId = testId(119_500);
        const { admin, person, auth, pending } = await registerPendingPerson(
          f,
          memberId,
          "Pending Restart Person"
        );

        // A live code cannot be restarted.
        const premature = await admin.callTool({
          name: "reissue_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            challenge_id: pending.activationChallengeId,
            proofing_method: "verified_number_call",
            idempotency_key: "restart-premature-000001"
          }
        });
        expect(premature.isError).toBe(true);

        // The original ten-minute code lapses.
        await pool.query(
          "update enrollment_activation_challenges set expires_at=transaction_timestamp()-interval '1 minute' where id=$1",
          [pending.activationChallengeId]
        );
        const stale = await admin.callTool({
          name: "confirm_enrollment_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            invitation_id: pending.invitationId,
            challenge_id: pending.activationChallengeId,
            confirmation_code: pending.activationCode,
            proofing_method: "verified_number_call",
            idempotency_key: "restart-stale-confirm-000001"
          }
        });
        expect(stale.isError).toBe(true);

        const restarted = await admin.callTool({
          name: "reissue_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            challenge_id: pending.activationChallengeId,
            proofing_method: "verified_number_call",
            idempotency_key: "restart-issue-000000001"
          }
        });
        expect(
          restarted.isError,
          JSON.stringify(restarted) + f.errors.map((error) => error.stack).join("\n")
        ).not.toBe(true);
        const restart = (
          restarted.structuredContent as {
            data: {
              grant_id: string;
              stale_challenge_id: string;
              restart_link: string;
              secret_once: boolean;
            };
          }
        ).data;
        expect(restart.grant_id).toMatch(UUID);
        expect(restart.stale_challenge_id).toBe(pending.activationChallengeId);
        expect(restart.secret_once).toBe(true);
        expect(
          (
            await pool.query("select state from enrollment_activation_challenges where id=$1", [
              pending.activationChallengeId
            ])
          ).rows
        ).toEqual([{ state: "revoked" }]);

        const { begun, completed } = await restartThroughBrowser(
          f,
          person,
          auth,
          restart.restart_link
        );
        // The helper already consumed the begin body; the operator log carries the cause.
        expect(begun.status, f.errors.map((error) => error.stack).join("\n")).toBe(200);
        if (completed === null) throw new Error("restart assertion was never offered");
        expect(
          completed.status,
          (await completed.clone().text()) + f.errors.map((error) => error.stack).join("\n")
        ).toBe(200);
        const fresh = (await completed.json()) as {
          status: string;
          memberId: string;
          activationChallengeId: string;
          activationCode: string;
          proofingMethod: string;
          expiresInSeconds: number;
        };
        expect(fresh).toMatchObject({
          status: "pending_activation",
          memberId,
          proofingMethod: "verified_number_call",
          expiresInSeconds: 600
        });
        expect(fresh.activationChallengeId).toMatch(UUID);
        expect(fresh.activationChallengeId).not.toBe(pending.activationChallengeId);
        expect(fresh.activationCode).toMatch(/^[A-HJ-NP-Z2-9]{3}-[A-HJ-NP-Z2-9]{4}$/u);

        // The used handoff cannot be replayed: it refuses before any assertion is offered.
        const replay = await restartThroughBrowser(f, person, auth, restart.restart_link);
        expect(replay.begun.status).toBe(400);
        expect(replay.completed).toBeNull();

        // The old code is dead; the fresh one activates.
        const oldCode = await admin.callTool({
          name: "confirm_enrollment_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            invitation_id: pending.invitationId,
            challenge_id: fresh.activationChallengeId,
            confirmation_code: pending.activationCode,
            proofing_method: "verified_number_call",
            idempotency_key: "restart-old-code-000001"
          }
        });
        // The stale digits are a recorded mismatch against the fresh challenge, not an
        // activation (same shape as the replacement-recovery refusals).
        expect(oldCode.isError, JSON.stringify(oldCode)).not.toBe(true);
        expect(oldCode.structuredContent).toMatchObject({
          data: { activated: false, reason: "code_mismatch", attempt_count: 1 }
        });
        const activated = await admin.callTool({
          name: "confirm_enrollment_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            invitation_id: pending.invitationId,
            challenge_id: fresh.activationChallengeId,
            confirmation_code: fresh.activationCode,
            proofing_method: "verified_number_call",
            idempotency_key: "restart-fresh-code-000001"
          }
        });
        expect(activated.isError, JSON.stringify(activated)).not.toBe(true);
        expect(
          (await pool.query("select state from members where id=$1", [memberId])).rows
        ).toEqual([{ state: "active" }]);
        const events = await pool.query<{ event_type: string }>(
          "select event_type from audit_events where event_type in ('activation_restart_issued','activation_restart_completed','member_activated') order by sequence"
        );
        expect(events.rows.map((row) => row.event_type)).toEqual([
          "activation_restart_issued",
          "activation_restart_completed",
          "member_activated"
        ]);
      } finally {
        await f.close();
      }
    });
  }, 60_000);

  it("refuses a handoff older than ten minutes and an assertion from a different passkey", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const memberId = testId(119_600);
        const { admin, person, auth, pending } = await registerPendingPerson(
          f,
          memberId,
          "Pending Restart Refusals"
        );
        await pool.query(
          "update enrollment_activation_challenges set attempt_count=20 where id=$1",
          [pending.activationChallengeId]
        );
        const issue = async (key: string) =>
          admin.callTool({
            name: "reissue_activation",
            arguments: {
              schema_version: SCHEMA,
              member_id: memberId,
              challenge_id: pending.activationChallengeId,
              proofing_method: "verified_number_call",
              idempotency_key: key
            }
          });
        // The restart must name the proofing method the person chose at registration.
        const mismatched = await admin.callTool({
          name: "reissue_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            challenge_id: pending.activationChallengeId,
            proofing_method: "in_person",
            idempotency_key: "restart-refusal-method-01"
          }
        });
        expect(mismatched.isError).toBe(true);
        const first = await issue("restart-refusal-000001");
        expect(
          first.isError,
          JSON.stringify(first) + f.errors.map((error) => error.stack).join("\n")
        ).not.toBe(true);
        const link = (first.structuredContent as { data: { restart_link: string } }).data
          .restart_link;
        // A second live handoff for the same person is refused.
        expect((await issue("restart-refusal-000002")).isError).toBe(true);

        // Another passkey cannot answer the assertion.
        const impostor = testAuthenticator();
        const wrong = await restartThroughBrowser(f, person, impostor, link);
        expect(wrong.begun.status).toBe(200);
        expect(wrong.completed?.status).toBe(400);

        // After ten minutes the handoff is dead even for the right passkey. The grant's
        // authority columns are immutable, so the test ages the row with the guard paused
        // (the same pattern as the integration suite) rather than through the ceremony.
        await pool.query(
          "alter table activation_restart_grants disable trigger boardagent_activation_restart_grant_transition"
        );
        await pool.query(
          `update activation_restart_grants
              set created_at=transaction_timestamp()-interval '11 minutes',
                  expires_at=transaction_timestamp()-interval '1 minute'
            where member_id=$1 and consumed_at is null`,
          [memberId]
        );
        await pool.query(
          "alter table activation_restart_grants enable trigger boardagent_activation_restart_grant_transition"
        );
        const late = await person.post("/enroll/restart/passkey/begin", {
          csrf_token: csrfOf(await (await person.get("/enroll/restart")).text()),
          restart_token: new URL(link).hash.slice(1)
        });
        expect(late.status).toBe(400);
        expect(
          (await pool.query("select state from members where id=$1", [memberId])).rows
        ).toEqual([{ state: "pending_activation" }]);
        expect(auth).toBeDefined();
      } finally {
        await f.close();
      }
    });
  }, 60_000);
});
