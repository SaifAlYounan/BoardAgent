import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  runWorkerMaintenanceInTransaction,
  withWorkerTransaction
} from "../../lib/db/src/index.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";

describe("approved OAuth request expiry", () => {
  it("revokes the expired code while retaining the approved request and a future usable code", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const expired = await f.authorizeCode(f.target.memberId);
        const future = await f.authorizeCode(f.target.memberId);
        const hash = createHash("sha256").update(expired.code).digest();
        const codeHashes = [hash, createHash("sha256").update(future.code).digest()];
        // Controlled clock-boundary fixture: no wall-clock minute is needed.
        await pool.query(
          "update oauth_authorization_codes set issued_at=transaction_timestamp()-interval '2 minutes',expires_at=transaction_timestamp()-interval '1 minute' where code_sha256=$1",
          [hash]
        );
        const requests = (
          await pool.query(
            "select * from oauth_authorization_requests where request_state='approved' and id in (select authorization_request_id from oauth_authorization_codes where code_sha256=any($1::bytea[])) order by id",
            [codeHashes]
          )
        ).rows;
        expect(requests).toHaveLength(2);
        const run = () =>
          withWorkerTransaction(
            pool,
            (c) =>
              runWorkerMaintenanceInTransaction(c, {
                jobType: "oauth_ephemera_expiry",
                organizationId: f.target.organizationId,
                limit: 100
              }),
            { assumeRole: "boardagent_worker" }
          );
        expect(await run()).toMatchObject({
          jobType: "oauth_ephemera_expiry",
          expiredAuthorizationRequests: 0,
          revokedAuthorizationCodes: 1
        });
        expect(
          (
            await pool.query(
              "select * from oauth_authorization_requests where request_state='approved' and id in (select authorization_request_id from oauth_authorization_codes where code_sha256=any($1::bytea[])) order by id",
              [codeHashes]
            )
          ).rows
        ).toEqual(requests);
        expect(await run()).toMatchObject({ revokedAuthorizationCodes: 0 });
        const denied = await f.exchangeAuthorization(expired);
        expect(denied.status).toBe(400);
        expect(await denied.json()).toEqual({ error: "invalid_grant" });
        expect((await f.exchangeAuthorization(future)).status).toBe(200);
      } finally {
        await f.close();
      }
    });
  });
});
