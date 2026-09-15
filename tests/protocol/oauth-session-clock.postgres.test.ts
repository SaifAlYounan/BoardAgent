import { describe, expect, it, vi } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";

describe("OAuth browser session database time authority", () => {
  it("completes real passkey OAuth when the provider clock crosses the database second without extending the session", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      const realNow = Date.now.bind(Date);
      try {
        for (const offset of [1_500, 3_500]) {
          let restoreClock: (() => void) | undefined;
          try {
            const token = await f.login(f.issuer.memberId, false, undefined, () => {
              const clock = vi.spyOn(Date, "now").mockImplementation(() => realNow() + offset);
              restoreClock = () => clock.mockRestore();
            });
            const agent = await f.connect(token);
            const who = await agent.callTool({
              name: "whoami",
              arguments: { schema_version: "boardagent.tool-input.v1" }
            });
            expect(who.isError).not.toBe(true);
          } finally {
            restoreClock?.();
          }
        }
        const sessions = await pool.query(
          `select expires_at<=created_at+interval '8 hours' as bounded,
                  last_authenticated_at<=transaction_timestamp() as authenticated_in_database_past
             from auth_sessions where member_id=$1 and state='authenticated'`,
          [f.issuer.memberId]
        );
        expect(sessions.rows.length).toBeGreaterThanOrEqual(2);
        expect(
          sessions.rows.every((row) => row.bounded && row.authenticated_in_database_past)
        ).toBe(true);
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });
});
