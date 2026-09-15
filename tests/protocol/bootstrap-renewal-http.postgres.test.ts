import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { bootstrapOAuthFixture, testAuthenticator } from "../helpers/administrative-oauth.js";

function csrf(html: string) {
  const token = /name="csrf_token" value="([A-Za-z0-9_.-]+)"/u.exec(html)?.[1];
  if (!token) throw new Error("enrollment page has no CSRF token");
  return token;
}

describe("SR002/SR005/SR102 abandoned first enrollment ceremony", () => {
  it("renews after an abandoned browser begin, rejects concurrent stale completion, and requires personal registration with the replacement", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await bootstrapOAuthFixture(pool);
      try {
        const first = f.initialized;
        const oldPerson = f.browserSession();
        const oldAuth = testAuthenticator();
        const oldCommon = {
          csrf_token: csrf(await (await oldPerson.get("/enroll")).text()),
          invitation_token: new URL(first.enrollmentUrl).hash.slice(1)
        };
        const begin = await oldPerson.post("/enroll/passkey/begin", oldCommon);
        expect(begin.status).toBe(200);
        const options = (await begin.json()) as { publicKey: { challenge: string } };
        expect((await pool.query("select state,row_version::text from members")).rows).toEqual([
          { state: "invited", row_version: "1" }
        ]);
        await pool.query(
          "update enrollment_invitations set issued_at=issued_at-interval '2 days',expires_at=expires_at-interval '2 days' where id=$1",
          [first.invitationId]
        );
        const request = {
          instanceId: first.instanceId,
          organizationId: first.organizationId,
          memberId: first.firstMemberId,
          previousInvitationId: first.invitationId,
          canonicalResourceUri: `${f.origin}/mcp`,
          handoffMethod: "in-person replacement QR",
          reason: "Original browser registration was abandoned before invitation expiry"
        };
        const [renewed, stale] = await Promise.all([
          f.operator.renewFirstInvitation(request),
          oldPerson.post("/enroll/passkey/complete", {
            ...oldCommon,
            proofing_method: "in_person",
            credential: JSON.stringify(oldAuth.registration(options.publicKey.challenge, f.origin))
          })
        ]);
        expect(stale.status).toBeGreaterThanOrEqual(400);
        expect(
          (await pool.query("select count(*)::int as n from webauthn_credentials")).rows
        ).toEqual([{ n: 0 }]);
        const person = f.browserSession();
        const auth = testAuthenticator();
        const common = {
          csrf_token: csrf(await (await person.get("/enroll")).text()),
          invitation_token: new URL(renewed.enrollmentUrl).hash.slice(1)
        };
        const newBegin = await person.post("/enroll/passkey/begin", common);
        expect(newBegin.status).toBe(200);
        const next = (await newBegin.json()) as { publicKey: { challenge: string } };
        const registered = await person.post("/enroll/passkey/complete", {
          ...common,
          proofing_method: "in_person",
          credential: JSON.stringify(auth.registration(next.publicKey.challenge, f.origin))
        });
        expect(registered.status).toBe(200);
        expect(await registered.json()).toMatchObject({
          status: "pending_activation",
          memberId: first.firstMemberId,
          invitationId: renewed.invitationId
        });
        await expect(
          f.operator.renewFirstInvitation({
            ...request,
            previousInvitationId: renewed.invitationId
          })
        ).rejects.toThrow();
        expect((await pool.query("select state from members")).rows).toEqual([
          { state: "pending_activation" }
        ]);
      } finally {
        await f.close();
      }
    });
  });
});
