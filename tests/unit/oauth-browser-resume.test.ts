import { describe, expect, it } from "vitest";
import {
  authPageSecurityHeaders,
  renderOAuthResumePage
} from "../../artifacts/server/src/auth-page.js";
const issuer = "https://boardagent.test";
const uid = "a".repeat(24);
describe("OAuth browser form completion", () => {
  it("navigates only to the exact internal provider resume path with strict CSP", () => {
    const page = renderOAuthResumePage(issuer, `${issuer}/authorize/${uid}`);
    expect(page).toContain(`content="0;url=/authorize/${uid}"`);
    expect(page).toContain(`href="/authorize/${uid}"`);
    expect(page).not.toContain("<script");
    expect(authPageSecurityHeaders({ includeHsts: true })["content-security-policy"]).toContain(
      "form-action 'self';"
    );
  });
  it.each([
    `https://other.test/authorize/${uid}`,
    `${issuer}/authorize/${uid}?redirect=https://other.test`,
    `${issuer}/authorize/${uid}#fragment`,
    `${issuer}/authorize/${uid}/other`,
    `${issuer}/auth/interactions/${uid}`,
    `https://user@boardagent.test/authorize/${uid}`,
    `http://boardagent.test/authorize/${uid}`,
    `${issuer}/authorize/short`,
    `${issuer}/authorize/%22%3E%3Cscript%3E`,
    "javascript:alert(1)"
  ])("refuses an unrelated or ambiguous navigation target: %s", (target) => {
    expect(() => renderOAuthResumePage(issuer, target)).toThrow();
  });
});
