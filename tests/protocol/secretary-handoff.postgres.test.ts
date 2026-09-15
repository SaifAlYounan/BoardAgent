import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import type { Client } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { bootstrapOAuthFixture, testAuthenticator } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
type Fixture = Awaited<ReturnType<typeof bootstrapOAuthFixture>>;
function csrf(html: string) {
  const token = /name="csrf_token" value="([A-Za-z0-9_.-]+)"/u.exec(html)?.[1];
  if (!token) throw new Error("ceremony page has no CSRF token");
  return token;
}
async function accepted(client: Client, name: string, argumentsValue: Record<string, unknown>) {
  const result = await client.callTool({
    name,
    arguments: { schema_version: SCHEMA, ...argumentsValue }
  });
  expect(result.isError, `tool ${name} must succeed`).not.toBe(true);
  return result.structuredContent as { reference: string; data: Record<string, unknown> };
}
async function beginCeremony(request: () => Promise<Response>) {
  const response = await request();
  if (response.status !== 429) return response;
  // Four scripted people share loopback and can exhaust the real one-minute cap.
  // Honour Retry-After; never disable rate enforcement or edit its database rows.
  const retry = Number(response.headers.get("retry-after"));
  expect(retry).toBeGreaterThan(0);
  expect(retry).toBeLessThanOrEqual(60);
  await delay(retry * 1000);
  return request();
}
async function enroll(f: Fixture, linkValue: string, memberId: string, invitationId: string) {
  const link = new URL(linkValue);
  expect(link.origin).toBe(f.origin);
  const person = f.browserSession();
  const auth = testAuthenticator();
  const page = await person.get("/enroll");
  expect(page.status).toBe(200);
  const csrfToken = csrf(await page.text());
  const common = { csrf_token: csrfToken, invitation_token: link.hash.slice(1) };
  const begin = await beginCeremony(() => person.post("/enroll/passkey/begin", common));
  expect(begin.status).toBe(200);
  const options = (await begin.json()) as { publicKey: { challenge: string } };
  // The completion shares the same real one-minute cap as the begin step; a 429 here
  // is refused before the challenge is consumed, so the same registration is re-sent
  // after Retry-After.
  const complete = await beginCeremony(() =>
    person.post("/enroll/passkey/complete", {
      ...common,
      proofing_method: "verified_number_call",
      credential: JSON.stringify(auth.registration(options.publicKey.challenge, f.origin))
    })
  );
  expect(complete.status).toBe(200);
  const handoff = (await complete.json()) as {
    status: string;
    activationCode: string;
    activationChallengeId: string;
    memberId: string;
    invitationId: string;
  };
  expect(handoff.status).toBe("pending_activation");
  // No database lookup fills in the activation reference missing from the old browser response.
  expect(handoff.activationChallengeId).toMatch(UUID);
  expect(handoff.memberId).toBe(memberId);
  expect(handoff.invitationId).toBe(invitationId);
  return { auth, person, handoff };
}
async function onboard(
  f: Fixture,
  memberId: string,
  enrolled: Awaited<ReturnType<typeof enroll>>,
  scopes?: readonly string[]
) {
  await f.registerAgent(memberId, enrolled.auth);
  // An agent may request its ordinary scopes at once. Until the new person attests the
  // exact terms the server issues only onboarding:read and says so in the token response;
  // a request that omits onboarding:read altogether still refuses.
  await expect(f.login(memberId, false, ["documents:read", "governance:read"])).rejects.toThrow(
    "invalid_grant"
  );
  const narrowed = await f.login(memberId, false, scopes);
  expect((narrowed as { scope?: string }).scope).toBe("onboarding:read");
  const agent = await f.connect(narrowed);
  const boardId = f.initialized.boardId;
  const before = await accepted(agent, "get_onboarding", { board_id: boardId });
  const onboarding = before.data.onboarding as {
    terms: { version_id: string };
    secretary_support: { version_id: string };
    attested: boolean;
  };
  expect(onboarding.attested).toBe(false);
  const prepared = await accepted(agent, "prepare_onboarding_attestation", {
    board_id: boardId,
    terms_version_id: onboarding.terms.version_id,
    support_version_id: onboarding.secretary_support.version_id,
    presentation_choice: "Structured summaries with source links",
    local_memory_choice: "No retained local board records",
    idempotency_key: "handoff-onboarding-" + memberId
  });
  const link = new URL(String(prepared.data.onboarding_url));
  expect(link.origin).toBe(f.origin);
  const page = await enrolled.person.get("/onboarding");
  expect(page.status).toBe(200);
  const common = { csrf_token: csrf(await page.text()), stage_token: link.hash.slice(1) };
  const begun = await beginCeremony(() =>
    enrolled.person.post("/onboarding/passkey/begin", common)
  );
  expect(begun.status).toBe(200);
  const options = (await begun.json()) as { publicKey: { challenge: string } };
  const attested = await enrolled.person.post("/onboarding/passkey/complete", {
    ...common,
    attest: "true",
    credential: JSON.stringify(enrolled.auth.assertion(options.publicKey.challenge, f.origin))
  });
  expect(attested.status).toBe(200);
  expect(await attested.json()).toMatchObject({ status: "current", memberId });
  // The narrowed family widens back to its granted set on the next refresh; no new
  // browser login is needed once onboarding is current.
  const refreshed = await f.trustedFetch(new URL("/token", f.origin), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: narrowed.protocolId,
      refresh_token: narrowed.refresh_token,
      resource: f.resource
    }).toString()
  });
  expect(refreshed.status).toBe(200);
  const widened = (await refreshed.json()) as { scope: string };
  const requested = scopes ?? f.scopes;
  expect(widened.scope).toBe([...requested].toSorted().join(" "));
  return f.connect(await f.login(memberId, false, scopes));
}
async function inviteAndActivate(
  f: Fixture,
  administrator: Client,
  memberId: string,
  name: string,
  authorityEvidence?: unknown,
  seatRole: "voting_member" | "management" | "observer" = "voting_member",
  scopes?: readonly string[]
) {
  await accepted(administrator, "manage_member", {
    idempotency_key: "handoff-invite-" + memberId,
    ...(authorityEvidence ? { authority_evidence: authorityEvidence } : {}),
    change: {
      operation: "invite",
      member_id: memberId,
      board_id: f.initialized.boardId,
      member_kind: "human",
      seat_role: seatRole,
      legal_name: name,
      display_name: name,
      voting_weight: seatRole === "voting_member" ? 1 : 0,
      accountable_principal_id: null,
      reason: "Register the appointed person"
    }
  });
  const issued = await accepted(administrator, "issue_enrollment", {
    member_id: memberId,
    handoff_method: "operator_display",
    expires_in_seconds: 900,
    idempotency_key: "handoff-enrollment-link-" + memberId
  });
  const enrolled = await enroll(f, String(issued.data.enrollment_link), memberId, issued.reference);
  const handoff = enrolled.handoff;
  await accepted(administrator, "confirm_enrollment_activation", {
    member_id: memberId,
    invitation_id: handoff.invitationId,
    challenge_id: handoff.activationChallengeId,
    confirmation_code: handoff.activationCode,
    proofing_method: "verified_number_call",
    idempotency_key: "handoff-activate-" + memberId
  });
  return onboard(f, memberId, enrolled, scopes);
}

describe("AC23 ordinary-secretary and separate-director handoff", () => {
  it.each(["voting_member", "management"] as const)(
    "bootstraps once, enrolls a %s secretary, separate directors and a human observer, then ends the setup seat while retaining administrator authority",
    async (secretarySeatRole) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await bootstrapOAuthFixture(pool);
        try {
          const setupId = f.initialized.firstMemberId;
          const boardId = f.initialized.boardId;
          let firstInvitation = f.initialized;
          if (secretarySeatRole === "management") {
            // The same real HTTP/passkey/OAuth journey must work after supported renewal.
            await pool.query(
              "update enrollment_invitations set issued_at=issued_at-interval '2 days',expires_at=expires_at-interval '2 days' where id=$1",
              [firstInvitation.invitationId]
            );
            const renewed = await f.operator.renewFirstInvitation({
              instanceId: firstInvitation.instanceId,
              organizationId: firstInvitation.organizationId,
              memberId: setupId,
              previousInvitationId: firstInvitation.invitationId,
              canonicalResourceUri: `${f.origin}/mcp`,
              handoffMethod: "in-person replacement QR",
              reason: "First invitation expired before this synthetic enrollment"
            });
            const stalePerson = f.browserSession();
            const stalePage = await stalePerson.get("/enroll");
            const staleBegin = await stalePerson.post("/enroll/passkey/begin", {
              csrf_token: csrf(await stalePage.text()),
              invitation_token: new URL(firstInvitation.enrollmentUrl).hash.slice(1)
            });
            expect(staleBegin.status).toBeGreaterThanOrEqual(400);
            firstInvitation = { ...firstInvitation, ...renewed, status: "created" };
          }
          const setup = await enroll(
            f,
            firstInvitation.enrollmentUrl,
            setupId,
            firstInvitation.invitationId
          );
          expect(
            await f.operator.activateFirstSecretary({
              activationCode: setup.handoff.activationCode,
              proofingMethod: "verified_number_call"
            })
          ).toMatchObject({ activated: true });
          await expect(
            f.operator.activateFirstSecretary({
              activationCode: setup.handoff.activationCode,
              proofingMethod: "verified_number_call"
            })
          ).rejects.toThrow();
          const admin = await onboard(f, setupId, setup);
          const secretaryId = testId(106_000);
          await inviteAndActivate(f, admin, secretaryId, "Rowan Ash", undefined, secretarySeatRole);
          await accepted(admin, "manage_member", {
            idempotency_key: "handoff-appoint-secretary",
            change: {
              operation: "change_seat",
              member_id: secretaryId,
              board_id: boardId,
              seat_role: secretarySeatRole,
              voting_weight: secretarySeatRole === "voting_member" ? 1 : 0,
              is_secretary: true,
              reason: "Appointed ordinary secretary for synthetic handoff"
            }
          });
          const secretary = await f.connect(await f.login(secretaryId));
          const noDelegation = await secretary.callTool({
            name: "manage_member",
            arguments: {
              schema_version: SCHEMA,
              idempotency_key: "handoff-no-delegation",
              change: {
                operation: "invite",
                member_id: testId(106_010),
                board_id: boardId,
                member_kind: "human",
                seat_role: "voting_member",
                legal_name: "Must Not Exist",
                display_name: "Must Not Exist",
                voting_weight: 1,
                accountable_principal_id: null,
                reason: "An ordinary secretary has no delegated account-management authority"
              }
            }
          });
          expect(noDelegation.isError).toBe(true);
          const documentId = testId(106_020);
          const body =
            "# Synthetic appointment authority\n\nClause 4: the secretary administers appointed ordinary director seats.\n";
          const created = await accepted(admin, "create_document_version", {
            board_id: boardId,
            document_id: documentId,
            title: "Synthetic appointment authority",
            media_type: "text/markdown; charset=utf-8",
            schema_name: null,
            canonical_body: body,
            expected_current_version_id: null,
            idempotency_key: "handoff-create-authority"
          });
          const authorityEvidence = [
            {
              document_version_id: created.reference,
              sha256: createHash("sha256").update(body).digest("hex"),
              clause: "4",
              locator: "Synthetic appointment authority"
            }
          ];
          await accepted(admin, "manage_document_access", {
            board_id: boardId,
            document_id: documentId,
            operation: "grant",
            member_id: secretaryId,
            permission: "read",
            reason: "Read the appointment authority",
            idempotency_key: "handoff-share-authority"
          });
          const member = await accepted(admin, "get_member", { member_id: secretaryId });
          const currentVersion = Number(
            (member.data.member as { row_version: string }).row_version
          );
          await accepted(admin, "manage_member_admin_delegation", {
            idempotency_key: "handoff-grant-director-administration",
            change: {
              operation: "grant",
              delegation_id: testId(106_021),
              member_id: secretaryId,
              board_id: boardId,
              expected_member_version: currentVersion,
              expires_at: new Date(Date.now() + 86400_000).toISOString(),
              reason: "Administer appointed ordinary directors only",
              authority_evidence: authorityEvidence
            }
          });
          const delegated = await f.connect(await f.login(secretaryId));
          for (const [id, name] of [
            [testId(106_001), "Mina Vale"],
            [testId(106_002), "Owen Birch"]
          ] as const) {
            const director = await inviteAndActivate(f, delegated, id, name, authorityEvidence);
            const who = await accepted(director, "whoami", {});
            expect(who.data.member_id).toBe(id);
            const denied = await director.callTool({
              name: "list_administrative_access",
              arguments: { schema_version: SCHEMA, mode: "organization" }
            });
            expect(denied.isError).toBe(true);
          }
          const observerId = testId(106_003);
          const observer = await inviteAndActivate(
            f,
            admin,
            observerId,
            "Nia Brook",
            undefined,
            "observer",
            ["documents:read", "governance:read", "onboarding:read"]
          );
          expect((await accepted(observer, "whoami", {})).data.member_id).toBe(observerId);
          const observerMutation = await observer.callTool({
            name: "manage_member",
            arguments: {
              schema_version: SCHEMA,
              idempotency_key: "observer-cannot-administer",
              change: {
                operation: "suspend",
                member_id: testId(106_001),
                board_id: boardId,
                reason: "Observers have no member administration"
              }
            }
          });
          expect(observerMutation.isError).toBe(true);
          await accepted(admin, "manage_member", {
            idempotency_key: "handoff-end-setup-seat",
            change: {
              operation: "remove",
              member_id: setupId,
              board_id: boardId,
              reason: "End setup voting seat; retain separate organization administrator"
            }
          });
          const retainedAdmin = await f.connect(await f.login(setupId));
          await accepted(retainedAdmin, "list_administrative_access", { mode: "organization" });
          const seats = (
            await pool.query(
              "select member_id,is_secretary,seat_role from board_memberships where board_id=$1 and state='active' and active_until is null order by member_id",
              [boardId]
            )
          ).rows;
          expect(seats).toEqual([
            { member_id: secretaryId, is_secretary: true, seat_role: secretarySeatRole },
            { member_id: testId(106_001), is_secretary: false, seat_role: "voting_member" },
            { member_id: testId(106_002), is_secretary: false, seat_role: "voting_member" },
            { member_id: observerId, is_secretary: false, seat_role: "observer" }
          ]);
          expect(
            (
              await pool.query(
                "select member_id from organization_role_assignments where role='admin' and active_until is null"
              )
            ).rows
          ).toEqual([{ member_id: setupId }]);
          expect(
            (
              await pool.query("select count(*)::int as n from members where id=$1", [
                testId(106_010)
              ])
            ).rows[0]?.n
          ).toBe(0);
          expect(
            (
              await pool.query(
                "select count(distinct member_id)::int as n from webauthn_credentials where state='active'"
              )
            ).rows[0]?.n
          ).toBe(5);
          if (secretarySeatRole === "management") {
            // Real released MCP transport exposes both additive H tools, including seatless setup.
            const additionalBoard = testId(107_001);
            await accepted(retainedAdmin, "create_board", {
              idempotency_key: "handoff-additional-board",
              board_id: additionalBoard,
              slug: "additional-committee",
              name: "Additional Committee",
              timezone: "UTC",
              initial_settings: { schema_version: "boardagent.board-settings.v1", values: {} },
              secretary_member_id: secretaryId
            });
            await accepted(retainedAdmin, "publish_secretary_support", {
              idempotency_key: "handoff-initialize-support",
              board_id: additionalBoard,
              version_id: testId(107_002),
              support_name: "Committee secretary office",
              contact_methods: [{ kind: "phone", value: "+971555010000" }],
              reason: "Initialize support before committee enrollment"
            });
            const hidden = await retainedAdmin.callTool({
              name: "get_board",
              arguments: { schema_version: SCHEMA, board_id: additionalBoard }
            });
            expect(hidden.isError).toBe(true);
            const cannotReplace = await retainedAdmin.callTool({
              name: "publish_secretary_support",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: "handoff-admin-no-support-updates",
                board_id: additionalBoard,
                version_id: testId(107_003),
                support_name: "Unappointed secretary",
                contact_methods: [{ kind: "phone", value: "+971555010001" }],
                reason: "Should be refused without secretary appointment"
              }
            });
            expect(cannotReplace.isError).toBe(true);
            await accepted(retainedAdmin, "publish_onboarding_terms", {
              idempotency_key: "handoff-publish-observer-terms",
              version_id: testId(107_004),
              seat_role: "observer",
              canonical_text:
                "Observers review entitled records and personally confirm the permitted actions.",
              reason: "Clarify observer responsibility"
            });
            const observerStatus = await accepted(observer, "get_onboarding_status", {
              board_id: boardId
            });
            expect(observerStatus.data.status).toBe("required");
            await accepted(delegated, "publish_secretary_support", {
              idempotency_key: "handoff-secretary-update-support",
              board_id: boardId,
              version_id: testId(107_005),
              support_name: "Updated secretary office",
              contact_methods: [{ kind: "phone", value: "+971555010002" }],
              reason: "Keep board support current"
            });
            const secretaryStatus = await accepted(delegated, "get_onboarding_status", {
              board_id: boardId
            });
            expect(secretaryStatus.data.status).toBe("required");
            expect(
              (
                await pool.query(
                  "select count(*)::int n from board_memberships where board_id=$1",
                  [additionalBoard]
                )
              ).rows[0]
            ).toEqual({ n: 0 });
          }
          expect(f.errors).toEqual([]);
        } finally {
          await f.close();
        }
      });
    },
    240_000
  );
});
