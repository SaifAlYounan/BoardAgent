import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("AC07/AC09/AC10 real OAuth administrator transfer continuity", () => {
  it("transfers atomically to a person without a board seat, revokes both connections and stale H stages, preserves votes and reconnects with current rights", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool, true);
      let unlock: (() => Promise<void>) | undefined;
      const releaseForms: Array<() => void> = [];
      const pendingForms: Promise<unknown>[] = [];
      try {
        if (!f.third) throw new Error("unrelated person fixture missing");
        const issuerToken = await f.login(f.issuer.memberId);
        const issuer = await f.connect(issuerToken);
        const unrelated = await f.connect(await f.login(f.third.memberId));
        // Supported removal of the setup board seat: admin status must never recreate a vote.
        expect(
          (
            await issuer.callTool({
              name: "manage_member",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: "transfer-end-recipient-board-seat",
                change: {
                  operation: "remove",
                  member_id: f.target.memberId,
                  board_id: f.target.boardId,
                  reason: "Recipient will administer the company without a voting board seat"
                }
              }
            })
          ).isError
        ).not.toBe(true);
        const targetToken = await f.login(f.target.memberId);
        const lowPrivilegeToken = await f.login(f.target.memberId, false, ["governance:read"]);
        const target = await f.connect(targetToken);
        const version = Number(
          (await pool.query("select row_version from members where id=$1", [f.target.memberId]))
            .rows[0].row_version
        );
        const proposal = (
          id: string,
          memberId: string,
          operation: "grant" | "transfer",
          targetVersion: number
        ) => ({
          schema_version: SCHEMA,
          idempotency_key: `transfer-continuity-offer-${id}`,
          change: {
            operation,
            proposal_id: id,
            member_id: memberId,
            expected_member_version: targetVersion,
            reason: "Confirm the exact administrative responsibility and recipient"
          }
        });
        const acceptance = (id: string) => ({
          schema_version: SCHEMA,
          idempotency_key: `transfer-continuity-accept-${id}`,
          change: {
            operation: "accept",
            proposal_id: id,
            expected_proposal_version: 1,
            reason: "Personally accept the proposed administrator responsibility"
          }
        });
        const transferId = testId(112401),
          extraOffer = testId(112402),
          waitingIssuerOffer = testId(112403);
        expect(
          (
            await issuer.callTool({
              name: "manage_company_admin",
              arguments: proposal(transferId, f.target.memberId, "transfer", version)
            })
          ).isError
        ).not.toBe(true);
        expect(
          (
            await issuer.callTool({
              name: "manage_company_admin",
              arguments: proposal(extraOffer, f.target.memberId, "grant", version)
            })
          ).isError
        ).not.toBe(true);
        const holdAction = async (
          client: typeof issuer,
          args: ReturnType<typeof proposal> | ReturnType<typeof acceptance>
        ) => {
          let release: () => void = () => {},
            presented: () => void = () => {};
          const ready = new Promise<void>((resolve) => {
            presented = resolve;
          });
          const held = new Promise<void>((resolve) => {
            release = resolve;
          });
          releaseForms.push(release);
          client.setRequestHandler("elicitation/create", async (request) => {
            const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(
              String(request.params.message)
            )?.[1];
            if (!code) throw new Error("held action lacks confirmation code");
            presented();
            await held;
            return { action: "accept", content: { approve: true, confirmation_code: code } };
          });
          const settled = client.callTool({ name: "manage_company_admin", arguments: args }).then(
            (result) => ({ result }),
            (error: unknown) => ({ error })
          );
          pendingForms.push(settled);
          await Promise.race([
            ready,
            settled.then(() => {
              throw new Error("held action completed before its form");
            })
          ]);
          return { settled };
        };
        const { settled: holdIssuer } = await holdAction(
          await f.connect(issuerToken),
          proposal(waitingIssuerOffer, f.third.memberId, "grant", 1)
        );
        const { settled: holdRecipient } = await holdAction(
          await f.connect(targetToken),
          acceptance(extraOffer)
        );
        // Observe persisted stages, rather than sleeping and hoping they were prepared.
        const waitUntil = async (probe: () => Promise<boolean>, label: string) => {
          const deadline = Date.now() + 5000;
          while (Date.now() < deadline) {
            if (await probe()) return;
            await delay(10);
          }
          throw new Error(`timed out observing ${label}`);
        };
        await waitUntil(
          async () =>
            (
              await pool.query(
                "select count(*)::int as n from action_stages where target_id=any($1::uuid[]) and state='active'",
                [[waitingIssuerOffer, extraOffer]]
              )
            ).rows[0].n === 2,
          "both waiting H stages"
        );
        const waitingStageIds = (
          await pool.query(
            "select id from action_stages where target_id=any($1::uuid[]) and state='active'",
            [[waitingIssuerOffer, extraOffer]]
          )
        ).rows.map((row: { id: string }) => row.id);
        const seatsBefore = (await pool.query("select * from board_memberships order by id")).rows;
        const versionsBefore = (await pool.query("select * from membership_versions order by id"))
          .rows;
        const otherRolesBefore = (
          await pool.query(
            "select * from organization_role_assignments where role<>'admin' order by id"
          )
        ).rows;
        const visibleAdmins = async () =>
          (
            await pool.query(
              "select a.member_id from organization_role_assignments a join members m on m.id=a.member_id and m.organization_id=a.organization_id where a.role='admin' and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp()) and m.state='active' and m.member_kind='human' order by a.member_id"
            )
          ).rows;
        expect(await visibleAdmins()).toEqual([{ member_id: f.issuer.memberId }]);
        // A disposable observation barrier pauses inside the real transfer transaction
        // after its new role INSERT. Concurrent readers must still see committed A.
        await pool.query(
          "create function test_hold_transfer_insert() returns trigger language plpgsql as $$ begin perform pg_advisory_xact_lock(11240001); return new; end $$"
        );
        await pool.query(
          "create trigger test_hold_transfer_insert after insert on organization_role_assignments for each row when (new.role='admin') execute function test_hold_transfer_insert()"
        );
        const gate = await pool.connect();
        await gate.query("select pg_advisory_lock(11240001)");
        unlock = async () => {
          await gate.query("select pg_advisory_unlock(11240001)");
          gate.release();
        };
        const transferring = target.callTool({
          name: "manage_company_admin",
          arguments: acceptance(transferId)
        });
        const transferOutcome = transferring.then(
          (result) => ({ result }),
          (error: unknown) => ({ error })
        );
        await waitUntil(
          async () =>
            (
              await pool.query(
                "select count(*)::int as n from pg_stat_activity where datname=current_database() and wait_event='advisory' and query like '%boardagent_finalize_company_admin%' and pid<>pg_backend_pid()"
              )
            ).rows[0].n === 1,
          "uncommitted transfer INSERT"
        );
        expect(await visibleAdmins()).toEqual([{ member_id: f.issuer.memberId }]);
        expect(
          (await unrelated.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .isError
        ).not.toBe(true);
        await unlock();
        unlock = undefined;
        const outcome = await transferOutcome;
        expect("result" in outcome && outcome.result.isError !== true).toBe(true);
        expect(await visibleAdmins()).toEqual([{ member_id: f.target.memberId }]);
        expect((await pool.query("select * from board_memberships order by id")).rows).toEqual(
          seatsBefore
        );
        expect((await pool.query("select * from membership_versions order by id")).rows).toEqual(
          versionsBefore
        );
        expect(
          (
            await pool.query(
              "select * from organization_role_assignments where role<>'admin' order by id"
            )
          ).rows
        ).toEqual(otherRolesBefore);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from board_memberships where member_id=$1 and state='active' and seat_role='voting_member'",
              [f.target.memberId]
            )
          ).rows[0]
        ).toEqual({ n: 0 });
        for (const token of [issuerToken, targetToken, lowPrivilegeToken]) {
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
          const response = await f.trustedFetch(new URL("/token", f.origin), {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "refresh_token",
              refresh_token: token.refresh_token,
              client_id: token.protocolId,
              resource: f.resource
            }).toString()
          });
          expect(response.status).toBe(400);
          expect(await response.json()).toEqual({ error: "invalid_grant" });
        }
        for (const id of [f.issuer.memberId, f.target.memberId]) {
          expect(
            (
              await pool.query(
                "select count(*)::int as n from auth_sessions where member_id=$1 and state='authenticated'",
                [id]
              )
            ).rows[0]
          ).toEqual({ n: 0 });
          expect(
            (
              await pool.query(
                "select count(*)::int as n from oauth_authorization_codes where member_id=$1 and consumed_at is null and revoked_at is null",
                [id]
              )
            ).rows[0]
          ).toEqual({ n: 0 });
        }
        expect(
          (
            await pool.query(
              "select state from action_stages where id=any($1::uuid[]) order by id",
              [waitingStageIds]
            )
          ).rows
        ).toEqual([{ state: "replaced" }, { state: "replaced" }]);
        for (const release of releaseForms) release();
        for (const held of [holdIssuer, holdRecipient]) {
          const result = await held;
          if ("result" in result) expect(result.result.isError).toBe(true);
          else expect(result.error).toMatchObject({ name: "SdkHttpError", status: 401 });
        }
        const outgoing = await f.connect(await f.login(f.issuer.memberId));
        const incoming = await f.connect(await f.login(f.target.memberId));
        expect(
          (
            await outgoing.callTool({
              name: "list_administrative_access",
              arguments: { schema_version: SCHEMA, mode: "organization" }
            })
          ).isError
        ).toBe(true);
        expect(
          (await outgoing.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .isError
        ).not.toBe(true);
        expect(
          (
            await incoming.callTool({
              name: "list_administrative_access",
              arguments: { schema_version: SCHEMA, mode: "organization" }
            })
          ).isError
        ).not.toBe(true);
        expect(
          (await unrelated.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
            .isError
        ).not.toBe(true);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from administrative_authority_changes where record_id=$1 and operation='accept'",
              [transferId]
            )
          ).rows[0]
        ).toEqual({ n: 1 });
        expect(
          (
            await pool.query("select count(*)::int as n from company_admin_proposals where id=$1", [
              waitingIssuerOffer
            ])
          ).rows[0]
        ).toEqual({ n: 0 });
        expect(f.errors).toEqual([]);
      } finally {
        if (unlock) await unlock();
        for (const release of releaseForms) release();
        await Promise.allSettled(pendingForms);
        await f.close();
      }
    });
  });
});
