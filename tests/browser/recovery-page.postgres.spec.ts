import { chromium } from "playwright";
import { describe, expect, it } from "vitest";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("replacement recovery browser", () => {
  it("removes the fragment, runs the real WebAuthn UI and presents the human-code handoff without activating the credential", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      const browser = await chromium.launch({ headless: true });
      try {
        const admin = await f.connect(await f.login(f.issuer.memberId));
        const result = await admin.callTool({
          name: "initiate_identity_recovery",
          arguments: {
            schema_version: SCHEMA,
            member_id: f.target.memberId,
            reason: "Browser recovery acceptance with a synthetic verified person",
            proofing_method: "verified_number_call",
            credential_disposition: "revoke_all",
            preserved_credential_ids: [],
            idempotency_key: "recovery-browser-acceptance-start"
          }
        });
        expect(result.isError).not.toBe(true);
        const url = (
          result.structuredContent as { data: { replacement_enrollment: { url: string } } }
        ).data.replacement_enrollment.url;
        // Only this disposable test context trusts the fixture's local self-signed TLS.
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await context.newPage();
        page.setDefaultTimeout(10_000);
        page.setDefaultNavigationTimeout(10_000);
        const errors: string[] = [];
        const requests: string[] = [];
        page.on("pageerror", (error) => errors.push(error.message));
        page.on("request", (request) => requests.push(request.url()));
        const cdp = await context.newCDPSession(page);
        await cdp.send("WebAuthn.enable");
        await cdp.send("WebAuthn.addVirtualAuthenticator", {
          options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true
          }
        });
        const response = await page.goto(url);
        expect(response?.status()).toBe(200);
        expect(new URL(page.url()).hash === "").toBe(true);
        expect(
          (await page.locator('input[name="recovery_token"]').inputValue()) ===
            new URL(url).hash.slice(1)
        ).toBe(true);
        await page.getByRole("button", { name: "Check recovery", exact: true }).click();
        await page.locator("[data-create]").waitFor({ state: "visible" });
        expect(await page.locator("[data-person]").textContent()).toContain("Additional actor");
        const completion = page.waitForResponse(
          (response) => new URL(response.url()).pathname === "/recover/passkey/complete"
        );
        await page.getByRole("button", { name: "Create replacement passkey", exact: true }).click();
        expect((await completion).status()).toBe(200);
        await page.locator("[data-handoff]").waitFor({ state: "visible" });
        const handoff = await page.locator("[data-handoff]").textContent();
        const memberId = /Member: ([a-f0-9-]{36})/u.exec(handoff ?? "")?.[1];
        const recoveryId = /Recovery reference: ([a-f0-9-]{36})/u.exec(handoff ?? "")?.[1];
        const challengeId = /Challenge: ([a-f0-9-]{36})/u.exec(handoff ?? "")?.[1];
        const code = /Human code: ([A-Z2-9]{3}-[A-Z2-9]{4})/u.exec(handoff ?? "")?.[1];
        expect(Boolean(memberId && recoveryId && challengeId && code)).toBe(true);
        expect(memberId).toBe(f.target.memberId);
        expect(await page.getByRole("status").textContent()).toContain(
          "waiting for identity confirmation"
        );
        expect(await page.locator('input[name="recovery_token"]').inputValue()).toBe("");
        expect(requests.some((request) => request.includes(new URL(url).hash.slice(1)))).toBe(
          false
        );
        expect(
          (
            await pool.query(
              "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
              [memberId]
            )
          ).rows[0].n
        ).toBe(0);
        const confirmed = await admin.callTool({
          name: "confirm_enrollment_activation",
          arguments: {
            schema_version: SCHEMA,
            member_id: memberId,
            invitation_id: recoveryId,
            challenge_id: challengeId,
            confirmation_code: code,
            proofing_method: "verified_number_call",
            idempotency_key: "recovery-browser-human-confirmation"
          }
        });
        expect(confirmed.structuredContent).toMatchObject({
          data: { activated: true, next_action: "fresh_sign_in" }
        });
        expect(errors).toEqual([]);
        expect(f.errors).toEqual([]);
      } finally {
        await browser.close();
        await f.close();
      }
    });
  });
});
