import { describe, expect, it } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/index.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

const SCHEMA = "boardagent.tool-input.v1";
describe("AC06 production OAuth issuer authority loss", () => {
  it.each(["admin_revocation", "organization_suspension", "observer_change"] as const)(
    "%s refuses waiting acceptance and restoring the issuer does not revive the offer",
    async (variant) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await administrativeOAuthFixture(pool, true);
        try {
          const third = f.third;
          if (!third) throw new Error("third-person fixture missing");
          const issuerToken = await f.login(f.issuer.memberId);
          const issuer = await f.connect(issuerToken);
          const second = await f.connect(await f.login(f.target.memberId));
          const recipient = await f.connect(await f.login(third.memberId));
          const propose = (id: string, memberId: string, version: number) => ({
            schema_version: SCHEMA,
            idempotency_key: `lost-authority-propose-${id}`,
            change: {
              operation: "grant",
              proposal_id: id,
              member_id: memberId,
              expected_member_version: version,
              reason: "Appoint a separately accountable synthetic administrator"
            }
          });
          const accept = (id: string, suffix = "original") => ({
            schema_version: SCHEMA,
            idempotency_key: `lost-authority-accept-${suffix}-${id}`,
            change: {
              operation: "accept",
              proposal_id: id,
              expected_proposal_version: 1,
              reason: "Personally accept this exact pending appointment"
            }
          });
          const secondProposal = testId(112301),
            pendingProposal = testId(112302);
          expect(
            (
              await issuer.callTool({
                name: "manage_company_admin",
                arguments: propose(secondProposal, f.target.memberId, 1)
              })
            ).isError
          ).not.toBe(true);
          expect(
            (
              await second.callTool({
                name: "manage_company_admin",
                arguments: accept(secondProposal)
              })
            ).isError
          ).not.toBe(true);
          const currentSecond = await f.connect(await f.login(f.target.memberId));
          expect(
            (
              await issuer.callTool({
                name: "manage_company_admin",
                arguments: propose(pendingProposal, third.memberId, 1)
              })
            ).isError
          ).not.toBe(true);
          const ordinarySeats = (
            await pool.query("select * from board_memberships where member_id=$1 order by id", [
              third.memberId
            ])
          ).rows;
          let release: () => void = () => {},
            presented: () => void = () => {};
          const presentation = new Promise<void>((resolve) => {
            presented = resolve;
          });
          const held = new Promise<void>((resolve) => {
            release = resolve;
          });
          recipient.setRequestHandler("elicitation/create", async (request) => {
            const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(
              String(request.params.message)
            )?.[1];
            if (!code) throw new Error("waiting acceptance lacks a confirmation code");
            presented();
            await held;
            return { action: "accept", content: { approve: true, confirmation_code: code } };
          });
          const pending = recipient.callTool({
            name: "manage_company_admin",
            arguments: accept(pendingProposal)
          });
          const settled = pending.then(
            (result) => ({ result }),
            (error: unknown) => ({ error })
          );
          try {
            await Promise.race([
              presentation,
              settled.then(() => {
                throw new Error("acceptance ended before its form was held");
              })
            ]);
            const revokeChange: JsonValue = {
              operation: "revoke",
              assignment_id: testId(72000),
              member_id: f.issuer.memberId,
              expected_member_version: 1,
              reason: "End the original issuer's company-administrator assignment"
            };
            const memberChange: JsonValue =
              variant === "organization_suspension"
                ? {
                    operation: "suspend",
                    member_id: f.issuer.memberId,
                    board_id: null,
                    reason: "Suspend the original issuer throughout the organization"
                  }
                : {
                    operation: "change_seat",
                    member_id: f.issuer.memberId,
                    board_id: f.issuer.boardId,
                    seat_role: "observer",
                    voting_weight: 0,
                    is_secretary: false,
                    reason: "Record the original issuer's change to observer"
                  };
            const changed = await currentSecond.callTool({
              name: variant === "admin_revocation" ? "manage_company_admin" : "manage_member",
              arguments: {
                schema_version: SCHEMA,
                idempotency_key: `lost-authority-${variant}`,
                change: variant === "admin_revocation" ? revokeChange : memberChange
              }
            });
            expect(changed.isError).not.toBe(true);
          } finally {
            release();
          }
          const outcome = await settled;
          expect("result" in outcome && outcome.result.isError).toBe(true);
          expect(
            (
              await f.trustedFetch(f.resource, {
                method: "POST",
                headers: {
                  authorization: `Bearer ${issuerToken.access_token}`,
                  "content-type": "application/json"
                },
                body: "{}"
              })
            ).status
          ).toBe(401);
          const assertNoGrant = async () => {
            expect(
              (
                await pool.query(
                  "select state,row_version::text from company_admin_proposals where id=$1",
                  [pendingProposal]
                )
              ).rows
            ).toEqual([{ state: "pending", row_version: "1" }]);
            expect(
              (
                await pool.query(
                  "select count(*)::int as n from administrative_authority_changes where record_id=$1 and operation='accept'",
                  [pendingProposal]
                )
              ).rows[0]
            ).toEqual({ n: 0 });
            expect(
              (
                await pool.query(
                  "select count(*)::int as n from organization_role_assignments where member_id=$1 and role='admin'",
                  [third.memberId]
                )
              ).rows[0]
            ).toEqual({ n: 0 });
            expect(
              (
                await pool.query("select * from board_memberships where member_id=$1 order by id", [
                  third.memberId
                ])
              ).rows
            ).toEqual(ordinarySeats);
          };
          await assertNoGrant();
          if (variant === "admin_revocation") {
            const version = Number(
              (await pool.query("select row_version from members where id=$1", [f.issuer.memberId]))
                .rows[0].row_version
            );
            const restoration = testId(112303);
            expect(
              (
                await currentSecond.callTool({
                  name: "manage_company_admin",
                  arguments: propose(restoration, f.issuer.memberId, version)
                })
              ).isError
            ).not.toBe(true);
            const reconnectedIssuer = await f.connect(await f.login(f.issuer.memberId));
            expect(
              (
                await reconnectedIssuer.callTool({
                  name: "manage_company_admin",
                  arguments: accept(restoration)
                })
              ).isError
            ).not.toBe(true);
          } else {
            const change =
              variant === "organization_suspension"
                ? {
                    operation: "reactivate",
                    member_id: f.issuer.memberId,
                    board_id: null,
                    reason: "Restore the original issuer after the synthetic suspension"
                  }
                : {
                    operation: "change_seat",
                    member_id: f.issuer.memberId,
                    board_id: f.issuer.boardId,
                    seat_role: "voting_member",
                    voting_weight: 1,
                    is_secretary: true,
                    reason: "Restore the original issuer's prior board capacity"
                  };
            expect(
              (
                await currentSecond.callTool({
                  name: "manage_member",
                  arguments: {
                    schema_version: SCHEMA,
                    idempotency_key: `lost-authority-restore-${variant}`,
                    change
                  }
                })
              ).isError
            ).not.toBe(true);
          }
          const restored = await f.connect(await f.login(f.issuer.memberId));
          expect(
            (
              await restored.callTool({
                name: "list_administrative_access",
                arguments: { schema_version: SCHEMA, mode: "organization" }
              })
            ).isError
          ).not.toBe(true);
          // A fresh recipient call must still refuse the historical offer, even after
          // its issuer has current authority again. The old generation never revives.
          expect(
            (
              await recipient.callTool({
                name: "manage_company_admin",
                arguments: accept(pendingProposal, "after-restore")
              })
            ).isError
          ).toBe(true);
          await assertNoGrant();
          expect(
            (
              await currentSecond.callTool({
                name: "whoami",
                arguments: { schema_version: SCHEMA }
              })
            ).isError
          ).not.toBe(true);
          expect(
            (await recipient.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
              .isError
          ).not.toBe(true);
          expect(f.errors).toEqual([]);
        } finally {
          await f.close();
        }
      });
    }
  );
});
