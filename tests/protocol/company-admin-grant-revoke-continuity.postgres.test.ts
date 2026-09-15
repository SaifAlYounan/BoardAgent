import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
const grant = (id: string, memberId: string, version: number) => ({
  schema_version: SCHEMA,
  idempotency_key: `continuity-grant-${id}`,
  change: {
    operation: "grant",
    proposal_id: id,
    member_id: memberId,
    expected_member_version: version,
    reason: "Synthetic confirmed administrator appointment"
  }
});
const accept = (id: string) => ({
  schema_version: SCHEMA,
  idempotency_key: `continuity-accept-${id}`,
  change: {
    operation: "accept",
    proposal_id: id,
    expected_proposal_version: 1,
    reason: "Accept this exact administrative responsibility"
  }
});

describe("AC09 real OAuth grant and revoke continuity", () => {
  it("invalidates old tokens, browsers, real unused codes and waiting forms on grant and revoke; reconnect uses only current authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool, true);
      const releases: Array<() => void> = [];
      const pending: Promise<unknown>[] = [];
      try {
        if (!f.third) throw new Error("unrelated member missing");
        const issuer = await f.connect(await f.login(f.issuer.memberId));
        const unrelated = await f.connect(await f.login(f.third.memberId));
        const targetToken = await f.login(f.target.memberId);
        const lowToken = await f.login(f.target.memberId, false, ["governance:read"]);
        const target = await f.connect(targetToken);
        const orgRead = {
          name: "list_administrative_access",
          arguments: { schema_version: SCHEMA, mode: "organization" }
        };
        expect((await (await f.connect(lowToken)).callTool(orgRead)).isError).toBe(true);
        const seatsBefore = (await pool.query("select * from board_memberships order by id")).rows;
        const versionsBefore = (await pool.query("select * from membership_versions order by id"))
          .rows;
        const hold = async (
          token: typeof targetToken,
          args: ReturnType<typeof grant> | ReturnType<typeof accept>
        ) => {
          const client = await f.connect(token);
          let present: () => void = () => {},
            release: () => void = () => {};
          const ready = new Promise<void>((r) => {
            present = r;
          });
          const wait = new Promise<void>((r) => {
            release = r;
          });
          releases.push(release);
          client.setRequestHandler("elicitation/create", async (request) => {
            const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(
              String(request.params.message)
            )?.[1];
            if (!code) throw new Error("waiting form has no confirmation code");
            present();
            await wait;
            return { action: "accept", content: { approve: true, confirmation_code: code } };
          });
          const settled = client.callTool({ name: "manage_company_admin", arguments: args }).then(
            (result) => ({ result }),
            (error: unknown) => ({ error })
          );
          pending.push(settled);
          await Promise.race([
            ready,
            settled.then(() => {
              throw new Error("action ended before presentation");
            })
          ]);
          const stage = (
            await pool.query(
              "select id from action_stages where actor_member_id=$1 and target_id=$2 and state='active'",
              [f.target.memberId, args.change.proposal_id]
            )
          ).rows;
          expect(stage).toHaveLength(1);
          return { settled, release, stageId: String(stage[0].id) };
        };
        const observeBefore = async () => {
          const authorization = await f.authorizeCode(f.target.memberId);
          const codeHash = createHash("sha256").update(authorization.code).digest();
          const code = (
            await pool.query(
              "select id,consumed_at,revoked_at,expires_at>clock_timestamp() as live from oauth_authorization_codes where code_sha256=$1",
              [codeHash]
            )
          ).rows;
          expect(code).toHaveLength(1);
          expect(code[0]).toMatchObject({ consumed_at: null, revoked_at: null, live: true });
          const sessions = (
            await pool.query(
              "select id from auth_sessions where member_id=$1 and state='authenticated'",
              [f.target.memberId]
            )
          ).rows.map((r: { id: string }) => r.id);
          expect(sessions.length).toBeGreaterThan(0);
          return { authorization, codeId: String(code[0].id), sessions };
        };
        const checkInvalidation = async (
          tokens: Array<typeof targetToken>,
          before: Awaited<ReturnType<typeof observeBefore>>,
          held: Awaited<ReturnType<typeof hold>>
        ) => {
          for (const token of tokens) {
            expect(
              (
                await f.trustedFetch(f.resource, {
                  method: "POST",
                  headers: {
                    authorization: `Bearer ${token.access_token}`,
                    "content-type": "application/json"
                  },
                  body: "{}"
                })
              ).status
            ).toBe(401);
            const refresh = await f.trustedFetch(new URL("/token", f.origin), {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: token.refresh_token,
                client_id: token.protocolId,
                resource: f.resource
              }).toString()
            });
            expect(refresh.status).toBe(400);
            expect(await refresh.json()).toEqual({ error: "invalid_grant" });
          }
          expect(
            (
              await pool.query(
                "select consumed_at,revoked_at is not null as revoked,expires_at>clock_timestamp() as unexpired from oauth_authorization_codes where id=$1",
                [before.codeId]
              )
            ).rows[0]
          ).toEqual({ consumed_at: null, revoked: true, unexpired: true });
          const exchange = await f.exchangeAuthorization(before.authorization);
          expect(exchange.status).toBe(400);
          expect(await exchange.json()).toEqual({ error: "invalid_grant" });
          expect(
            (
              await pool.query("select state from auth_sessions where id=any($1::uuid[])", [
                before.sessions
              ])
            ).rows
          ).toEqual(before.sessions.map(() => ({ state: "revoked" })));
          expect(
            (await pool.query("select state from action_stages where id=$1", [held.stageId]))
              .rows[0]
          ).toEqual({ state: "replaced" });
          held.release();
          const outcome = await held.settled;
          if ("result" in outcome) expect(outcome.result.isError).toBe(true);
          else expect(outcome.error).toMatchObject({ name: "SdkHttpError", status: 401 });
          expect(
            (await unrelated.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
              .isError
          ).not.toBe(true);
          expect((await issuer.callTool(orgRead)).isError).not.toBe(true);
        };
        const assignment = testId(112901),
          extraOffer = testId(112902),
          waitingGrant = testId(112903);
        for (const id of [assignment, extraOffer])
          expect(
            (
              await issuer.callTool({
                name: "manage_company_admin",
                arguments: grant(id, f.target.memberId, 1)
              })
            ).isError
          ).not.toBe(true);
        const waitingAccept = await hold(targetToken, accept(extraOffer));
        const beforeGrant = await observeBefore();
        expect(
          (await target.callTool({ name: "manage_company_admin", arguments: accept(assignment) }))
            .isError
        ).not.toBe(true);
        await checkInvalidation([targetToken, lowToken], beforeGrant, waitingAccept);
        expect(
          (await pool.query("select state from company_admin_proposals where id=$1", [extraOffer]))
            .rows[0]
        ).toEqual({ state: "pending" });
        const adminToken = await f.login(f.target.memberId);
        const current = await f.connect(adminToken);
        expect((await current.callTool(orgRead)).isError).not.toBe(true);
        const waitingProposal = await hold(adminToken, grant(waitingGrant, f.third.memberId, 1));
        const beforeRevoke = await observeBefore();
        expect(
          (
            await issuer.callTool({
              name: "manage_company_admin",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: "continuity-revoke-confirmed-admin",
                change: {
                  operation: "revoke",
                  assignment_id: assignment,
                  member_id: f.target.memberId,
                  expected_member_version: 2,
                  reason: "End this administrative appointment"
                }
              }
            })
          ).isError
        ).not.toBe(true);
        await checkInvalidation([adminToken], beforeRevoke, waitingProposal);
        const former = await f.connect(await f.login(f.target.memberId));
        expect((await former.callTool(orgRead)).isError).toBe(true);
        expect(
          (await former.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } })).isError
        ).not.toBe(true);
        expect((await pool.query("select * from board_memberships order by id")).rows).toEqual(
          seatsBefore
        );
        expect((await pool.query("select * from membership_versions order by id")).rows).toEqual(
          versionsBefore
        );
        expect(
          (
            await pool.query(
              "select member_id from organization_role_assignments where role='admin' and active_until is null"
            )
          ).rows
        ).toEqual([{ member_id: f.issuer.memberId }]);
        expect(
          (
            await pool.query("select count(*)::int as n from company_admin_proposals where id=$1", [
              waitingGrant
            ])
          ).rows[0]
        ).toEqual({ n: 0 });
        expect(
          (
            await pool.query(
              "select operation from administrative_authority_changes where record_id=$1 order by record_version",
              [assignment]
            )
          ).rows.map((r: { operation: string }) => r.operation)
        ).toEqual(["grant", "accept", "revoke"]);
        expect(f.errors).toEqual([]);
      } finally {
        for (const release of releases) release();
        await Promise.allSettled(pending);
        await f.close();
      }
    });
  }, 120_000);
});
