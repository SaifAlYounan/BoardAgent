import { setTimeout as delay } from "node:timers/promises";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { delegationFixture } from "../helpers/administrative-delegation.js";
import {
  freshAdministrativeTestCredential,
  stageAdministrativeAction
} from "../helpers/administrative-service.js";
import { seedAdditionalAuthorizedActor, testId } from "../helpers/authorized-actor.js";

async function waitForQueuedRequests(pool: Pool, count: number) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const observed = await pool.query(
      "select count(*)::int as n from pg_stat_activity where datname=current_database() and wait_event='advisory'"
    );
    if (Number(observed.rows[0]?.n) >= count) return;
    await delay(10);
  }
  throw new Error(`expected ${count} blocked administrative request(s)`);
}
/** Force both service confirmations into the real org-lock queue in a known order. */
async function orderedConcurrent<T>(
  pool: Pool,
  org: string,
  first: () => Promise<T>,
  second: () => Promise<T>
) {
  const gate = await pool.connect();
  const pending: Promise<PromiseSettledResult<T>>[] = [];
  const settle = (run: () => Promise<T>) =>
    run().then(
      (value) => ({ status: "fulfilled", value }) as const,
      (reason) => ({ status: "rejected", reason }) as const
    );
  try {
    await gate.query("select pg_advisory_lock(hashtextextended($1,424286))", [org]);
    pending.push(settle(first));
    await waitForQueuedRequests(pool, 1);
    pending.push(settle(second));
    await waitForQueuedRequests(pool, 2);
  } finally {
    await gate.query("select pg_advisory_unlock(hashtextextended($1,424286))", [org]);
    gate.release();
  }
  return Promise.all(pending);
}
describe("AC17 concurrent administrative authority changes", () => {
  it.each(["issuer-first", "recipient-first"] as const)(
    "AC08 two administrators cannot concurrently revoke the last remaining authority (%s)",
    async (order) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool);
        const offerId = testId(93_001);
        const proposing = await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "last-admin-race-proposal-0001",
          change: {
            operation: "grant",
            proposal_id: offerId,
            member_id: target.memberId,
            expected_member_version: 1,
            reason: "Create the second administrator"
          }
        });
        expect((await proposing.confirm()).confirmed).toBe(true);
        const accepting = await stageAdministrativeAction(pool, target, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "last-admin-race-accept-0001",
          change: {
            operation: "accept",
            proposal_id: offerId,
            expected_proposal_version: 1,
            reason: "Personally accept second administrator authority"
          }
        });
        expect((await accepting.confirm()).confirmed).toBe(true);
        const second = await freshAdministrativeTestCredential(pool, target, 93_100);
        const seatsBefore = canonicalSha256(
          (
            await pool.query("select to_jsonb(s) as seat from board_memberships s order by s.id")
          ).rows.map((r) => r.seat)
        );
        const firstRevoke = await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "last-admin-race-self-revoke-a",
          change: {
            operation: "revoke",
            assignment_id: testId(72_000),
            member_id: issuer.memberId,
            expected_member_version: 1,
            reason: "Resign my own company-admin role"
          }
        });
        const secondRevoke = await stageAdministrativeAction(pool, second, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "last-admin-race-self-revoke-b",
          change: {
            operation: "revoke",
            assignment_id: offerId,
            member_id: second.memberId,
            expected_member_version: 2,
            reason: "Resign my own company-admin role"
          }
        });
        const results = await orderedConcurrent(
          pool,
          issuer.organizationId,
          order === "issuer-first" ? () => firstRevoke.confirm() : () => secondRevoke.confirm(),
          order === "issuer-first" ? () => secondRevoke.confirm() : () => firstRevoke.confirm()
        );
        expect(results.filter((r) => r.status === "fulfilled" && r.value.confirmed)).toHaveLength(
          1
        );
        expect(results[0]).toMatchObject({ status: "fulfilled", value: { confirmed: true } });
        const surviving = await pool.query(
          "select member_id from organization_role_assignments where role='admin' and active_until is null"
        );
        expect(surviving.rows).toEqual([
          { member_id: order === "issuer-first" ? second.memberId : issuer.memberId }
        ]);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from audit_events where event_type='company_admin_revoked'"
            )
          ).rows[0]?.n
        ).toBe(1);
        const seatsAfter = canonicalSha256(
          (
            await pool.query("select to_jsonb(s) as seat from board_memberships s order by s.id")
          ).rows.map((r) => r.seat)
        );
        expect(seatsAfter).toBe(seatsBefore);
        expect(
          (await pool.query("select count(*)::int as n from members where state='active'")).rows[0]
            ?.n
        ).toBe(2);
      });
    }
  );
  it.each([
    ["suspend", "resignation-first"],
    ["suspend", "member-first"],
    ["remove", "resignation-first"],
    ["remove", "member-first"]
  ] as const)(
    "AC08 last-admin self-resignation races organization-wide %s (%s)",
    async (operation, order) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool);
        const proposalId = testId(113101);
        const offer = await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "mixed-last-admin-offer",
          change: {
            operation: "grant",
            proposal_id: proposalId,
            member_id: target.memberId,
            expected_member_version: 1,
            reason: "Create the second administrator for the race"
          }
        });
        expect((await offer.confirm()).confirmed).toBe(true);
        const acceptance = await stageAdministrativeAction(pool, target, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "mixed-last-admin-accept",
          change: {
            operation: "accept",
            proposal_id: proposalId,
            expected_proposal_version: 1,
            reason: "Accept the second administrative responsibility"
          }
        });
        expect((await acceptance.confirm()).confirmed).toBe(true);
        const second = await freshAdministrativeTestCredential(pool, target, 113200);
        // B is an ordinary voter, not the board's secretary: this must test the
        // last-administrator rule rather than accidentally hit the last-secretary rule.
        expect(
          (
            await pool.query("select is_secretary from board_memberships where member_id=$1", [
              second.memberId
            ])
          ).rows[0]
        ).toEqual({ is_secretary: false });
        const issuerSeats = (
          await pool.query("select * from board_memberships where member_id=$1 order by id", [
            issuer.memberId
          ])
        ).rows;
        const resignation = await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "mixed-last-admin-resign",
          change: {
            operation: "revoke",
            assignment_id: testId(72000),
            member_id: issuer.memberId,
            expected_member_version: 1,
            reason: "Resign my administrative responsibility"
          }
        });
        const departure = await stageAdministrativeAction(pool, second, "manage_member", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "mixed-last-admin-depart",
          change: {
            operation,
            member_id: second.memberId,
            board_id: null,
            reason: "End my organization-wide access while another administrator remains"
          }
        });
        const results = await orderedConcurrent(
          pool,
          issuer.organizationId,
          order === "resignation-first" ? () => resignation.confirm() : () => departure.confirm(),
          order === "resignation-first" ? () => departure.confirm() : () => resignation.confirm()
        );
        expect(results[0]).toMatchObject({ status: "fulfilled", value: { confirmed: true } });
        expect(results.filter((r) => r.status === "fulfilled" && r.value.confirmed)).toHaveLength(
          1
        );
        const effective = await pool.query(`select a.member_id from organization_role_assignments a
          join members m on m.organization_id=a.organization_id and m.id=a.member_id
          where a.role='admin' and a.active_from<=transaction_timestamp()
            and (a.active_until is null or a.active_until>transaction_timestamp())
            and m.state='active' and m.member_kind='human' order by a.member_id`);
        expect(effective.rows).toEqual([
          { member_id: order === "resignation-first" ? second.memberId : issuer.memberId }
        ]);
        expect(
          (await pool.query("select state from members where id=$1", [second.memberId])).rows[0]
        ).toEqual({
          state:
            order === "resignation-first"
              ? "active"
              : operation === "suspend"
                ? "suspended"
                : "removed"
        });
        expect(
          (
            await pool.query("select * from board_memberships where member_id=$1 order by id", [
              issuer.memberId
            ])
          ).rows
        ).toEqual(issuerSeats);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from audit_events where event_type='company_admin_revoked'"
            )
          ).rows[0]
        ).toEqual({ n: order === "resignation-first" ? 1 : 0 });
        expect(
          (
            await pool.query(
              "select count(*)::int as n from audit_events where event_type='member_changed'"
            )
          ).rows[0]
        ).toEqual({ n: order === "member-first" ? 1 : 0 });
      });
    }
  );
  it.each([
    ["revocation", "authority-first"],
    ["revocation", "director-first"],
    ["secretary-departure", "authority-first"],
    ["secretary-departure", "director-first"],
    ["director-elevation", "authority-first"],
    ["director-elevation", "director-first"]
  ] as const)(
    "serializes %s and a director change (%s) without a deadlock or partial history",
    async (conflict, order) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await delegationFixture(pool);
        expect(
          (
            await (
              await stageAdministrativeAction(
                pool,
                f.issuer,
                "manage_member_admin_delegation",
                f.input
              )
            ).confirm()
          ).confirmed
        ).toBe(true);
        const secretary = await freshAdministrativeTestCredential(pool, f.target, 92_100);
        const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
          idBase: 92_200,
          seatRole: "voting_member",
          scopes: ["governance:read"]
        });
        const changing = await stageAdministrativeAction(pool, secretary, "manage_member", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "race-delegated-director-change",
          authority_evidence: f.input.change.authority_evidence,
          change: {
            operation: "suspend",
            member_id: director.memberId,
            board_id: director.boardId,
            reason: "Cited suspension of this director"
          }
        });
        const revocationInput = {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "race-delegation-revocation",
          change: {
            operation: "revoke",
            delegation_id: f.input.change.delegation_id,
            board_id: secretary.boardId,
            expected_delegation_version: 1,
            reason: "End secretary's delegated authority"
          }
        };
        let authority: Awaited<ReturnType<typeof stageAdministrativeAction>>;
        if (conflict === "revocation")
          authority = await stageAdministrativeAction(
            pool,
            f.issuer,
            "manage_member_admin_delegation",
            revocationInput
          );
        else if (conflict === "secretary-departure")
          authority = await stageAdministrativeAction(pool, f.issuer, "manage_member", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "race-secretary-role-departure",
            change: {
              operation: "change_seat",
              member_id: secretary.memberId,
              board_id: secretary.boardId,
              seat_role: "voting_member",
              voting_weight: 1,
              is_secretary: false,
              reason: "End the secretary role while retaining a director seat"
            }
          });
        else {
          const offerId = testId(92_400);
          const proposal = await stageAdministrativeAction(pool, f.issuer, "manage_company_admin", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "race-director-admin-proposal",
            change: {
              operation: "grant",
              proposal_id: offerId,
              member_id: director.memberId,
              expected_member_version: 1,
              reason: "Offer company administration to this director"
            }
          });
          expect((await proposal.confirm()).confirmed).toBe(true);
          const recipient = await freshAdministrativeTestCredential(pool, director, 92_500);
          authority = await stageAdministrativeAction(pool, recipient, "manage_company_admin", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "race-director-admin-acceptance",
            change: {
              operation: "accept",
              proposal_id: offerId,
              expected_proposal_version: 1,
              reason: "Accept the offered company administration"
            }
          });
        }
        const outcomes = await orderedConcurrent(
          pool,
          f.issuer.organizationId,
          order === "authority-first" ? () => authority.confirm() : () => changing.confirm(),
          order === "authority-first" ? () => changing.confirm() : () => authority.confirm()
        );
        const authorityResult = outcomes[order === "authority-first" ? 0 : 1];
        const authorityChanged =
          authorityResult?.status === "fulfilled" && authorityResult.value.confirmed;
        expect(authorityChanged).toBe(
          !(conflict === "director-elevation" && order === "director-first")
        );
        const directorResult = outcomes[order === "authority-first" ? 1 : 0];
        const changed = directorResult?.status === "fulfilled" && directorResult.value.confirmed;
        if (order === "authority-first") expect(changed).toBe(false);
        else expect(changed).toBe(true);
        expect(
          (
            await pool.query("select state from board_memberships where member_id=$1", [
              director.memberId
            ])
          ).rows[0]?.state
        ).toBe(changed ? "suspended" : "active");
        expect(
          (
            await pool.query(
              "select count(*)::int as n from membership_versions where member_id=$1",
              [director.memberId]
            )
          ).rows[0]?.n
        ).toBe(changed ? 1 : 0);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from audit_events where object_id=$1 and event_type='member_changed'",
              [director.memberId]
            )
          ).rows[0]?.n
        ).toBe(changed ? 1 : 0);
        expect(
          (
            await pool.query("select state from member_admin_delegations where id=$1", [
              f.input.change.delegation_id
            ])
          ).rows[0]?.state
        ).toBe(conflict === "revocation" ? "revoked" : "active");
        await pool.query("select pg_stat_clear_snapshot()");
        expect(
          (
            await pool.query(
              "select deadlocks::int as n from pg_stat_database where datname=current_database()"
            )
          ).rows[0]?.n
        ).toBe(0);
        if (conflict === "director-elevation") {
          expect(
            (
              await pool.query(
                "select count(*)::int as n from organization_role_assignments where member_id=$1 and role='admin' and active_until is null",
                [director.memberId]
              )
            ).rows[0]?.n
          ).toBe(authorityChanged ? 1 : 0);
        }
        const reconnected = await freshAdministrativeTestCredential(pool, secretary, 92_300);
        if (conflict !== "director-elevation" || authorityChanged)
          await expect(
            stageAdministrativeAction(pool, reconnected, "manage_member", {
              schema_version: "boardagent.tool-input.v1",
              idempotency_key: "race-revoked-delegate-retry",
              authority_evidence: f.input.change.authority_evidence,
              change: {
                operation: "suspend",
                member_id: director.memberId,
                board_id: director.boardId,
                reason: "The ended grant cannot be reused"
              }
            })
          ).rejects.toThrow();
      });
    }
  );
});
