import { describe, expect, it } from "vitest";
import type { Pool } from "pg";
import { z } from "zod";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { delegationFixture } from "../helpers/administrative-delegation.js";
import {
  administrativeService,
  stageAdministrativeAction,
  freshAdministrativeTestCredential
} from "../helpers/administrative-service.js";
import {
  testId,
  seedAdditionalAuthorizedActor,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const pageSchema = z
  .object({ items: z.array(z.record(z.string(), z.json())), next_cursor: z.string().nullable() })
  .strict();
async function read(
  pool: Pool,
  actor: AuthorizedActorFixture,
  extra: Record<string, unknown> = {}
) {
  const { principal, reads } = await administrativeService(pool, actor);
  return pageSchema.parse(
    (
      await reads.executeRead(
        principal,
        "list_administrative_access",
        z.json().parse({ schema_version: "boardagent.tool-input.v1", ...extra })
      )
    ).data
  );
}
async function propose(
  pool: Pool,
  issuer: AuthorizedActorFixture,
  target: AuthorizedActorFixture,
  ordinal: number
) {
  const proposalId = testId(88_000 + ordinal);
  const memberVersion = Number(
    (await pool.query("select row_version from members where id=$1", [target.memberId])).rows[0]
      ?.row_version
  );
  const staged = await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
    schema_version: "boardagent.tool-input.v1",
    idempotency_key: `administrative-read-proposal-${ordinal}`,
    change: {
      operation: "grant",
      proposal_id: proposalId,
      member_id: target.memberId,
      expected_member_version: memberVersion,
      reason: "Offer company administration"
    }
  });
  expect((await staged.confirm()).confirmed).toBe(true);
  return proposalId;
}
describe("SR099 private administrative access discovery", () => {
  it("lets the named recipient discover and accept an offer, then reports admin authority only after reconnect", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const offer = await propose(pool, issuer, target, 1);
      await propose(pool, issuer, target, 2);
      const before = await read(pool, target, { limit: 1 });
      expect(before.items[0]?.["record_type"]).toBe("company_admin_proposal");
      const acceptance = await stageAdministrativeAction(pool, target, "manage_company_admin", {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "discovered-offer-accept-0001",
        change: {
          operation: "accept",
          proposal_id: offer,
          expected_proposal_version: 1,
          reason: "Accept the disclosed company-admin offer"
        }
      });
      expect((await acceptance.confirm()).confirmed).toBe(true);
      await expect(read(pool, target)).rejects.toThrow("no live token");
      const reconnected = await freshAdministrativeTestCredential(pool, target, 90_400);
      const after = await read(pool, reconnected);
      expect(
        after.items.filter((x) => x["record_type"] === "company_admin_assignment")
      ).toMatchObject([
        { record_id: offer, state: "active", target: { member_id: target.memberId } }
      ]);
      expect(after.items.map((x) => x["record_id"])).not.toContain(testId(72_000));
      await expect(read(pool, reconnected, { cursor: before.next_cursor })).rejects.toThrow(
        "cursor"
      );
      expect(
        (await read(pool, reconnected, { mode: "organization" })).items.map((x) => x["record_id"])
      ).toContain(testId(72_000));
    });
  });
  it("removes expired delegation rights without any worker cleanup", async () => {
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
      const secretary = await freshAdministrativeTestCredential(pool, f.target, 90_500);
      expect((await read(pool, secretary)).items).toHaveLength(1);
      // Move the disposable fixture's entire immutable interval into the past.
      // Runtime roles cannot disable this trigger or edit the interval.
      await pool.query(
        "alter table member_admin_delegations disable trigger boardagent_member_admin_delegation_transition"
      );
      try {
        await pool.query(
          "update member_admin_delegations set created_at=transaction_timestamp()-interval '2 days',expires_at=transaction_timestamp()-interval '1 day' where id=$1",
          [f.input.change.delegation_id]
        );
      } finally {
        await pool.query(
          "alter table member_admin_delegations enable trigger boardagent_member_admin_delegation_transition"
        );
      }
      expect((await read(pool, secretary)).items).toEqual([]);
      expect(
        (
          await pool.query("select state from member_admin_delegations where id=$1", [
            f.input.change.delegation_id
          ])
        ).rows[0]?.state
      ).toBe("active");
    });
  });
  it("shows only the holder's board grant and filters citations with current document access", async () => {
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
      const secretary = await freshAdministrativeTestCredential(pool, f.target, 90_100);
      const offer = await propose(pool, f.issuer, { ...secretary }, 4);
      const grant = await read(pool, secretary, { board_id: secretary.boardId });
      expect(grant.items).toHaveLength(1);
      expect(grant.items[0]).toMatchObject({
        record_type: "member_admin_delegation",
        record_id: f.input.change.delegation_id,
        authority_evidence: f.input.change.authority_evidence
      });
      expect((await read(pool, f.issuer, { board_id: secretary.boardId })).items).toEqual([]);
      expect(
        (await read(pool, f.issuer, { mode: "organization", board_id: secretary.boardId })).items
      ).toHaveLength(1);
      const page = await read(pool, secretary, { limit: 1 });
      expect(page.next_cursor).toEqual(expect.any(String));
      await pool.query(
        "update document_access_grants set active_until=clock_timestamp() where id=$1",
        [testId(76_004)]
      );
      await expect(read(pool, secretary, { limit: 1, cursor: page.next_cursor })).rejects.toThrow(
        "cursor"
      );
      const filtered = await read(pool, secretary, { board_id: secretary.boardId });
      expect(filtered.items[0]?.["authority_evidence"]).toEqual([]);
      expect(JSON.stringify(filtered)).not.toContain(f.input.change.authority_evidence[0]!.sha256);
      expect(JSON.stringify(filtered)).not.toMatch(
        /token_jti|canonical_payload|session_id|consent_record_id/
      );
      expect((await read(pool, secretary)).items.map((x) => x["record_id"])).toContain(offer);
      const revoke = await stageAdministrativeAction(
        pool,
        f.issuer,
        "manage_member_admin_delegation",
        {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "read-test-delegation-revoke",
          change: {
            operation: "revoke",
            delegation_id: f.input.change.delegation_id,
            board_id: secretary.boardId,
            expected_delegation_version: 1,
            reason: "End the board capability"
          }
        }
      );
      expect((await revoke.confirm()).confirmed).toBe(true);
      await expect(read(pool, secretary)).rejects.toThrow();
      const reconnected = await freshAdministrativeTestCredential(pool, secretary, 90_200);
      expect((await read(pool, reconnected, { board_id: secretary.boardId })).items).toEqual([]);
    });
  });
  it.each(["identity_generation", "onboarding_generation", "entitlement_generation"] as const)(
    "invalidates a cursor after %s changes",
    async (generation) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool);
        await propose(pool, issuer, target, 1);
        await propose(pool, issuer, target, 2);
        const first = await read(pool, target, { limit: 1 });
        expect(first.next_cursor).toEqual(expect.any(String));
        // Controlled disposable database fixture, not an application role grant.
        if (generation === "entitlement_generation")
          await pool.query(
            "update board_memberships set entitlement_generation=entitlement_generation+1 where member_id=$1",
            [target.memberId]
          );
        else if (generation === "onboarding_generation")
          await pool.query(
            "update members set onboarding_generation=onboarding_generation+1,row_version=row_version+1 where id=$1",
            [target.memberId]
          );
        else
          await pool.query(
            "update members set identity_generation=identity_generation+1,row_version=row_version+1 where id=$1",
            [target.memberId]
          );
        await expect(read(pool, target, { cursor: first.next_cursor })).rejects.toThrow("cursor");
      });
    }
  );
  it("allows admin organization filters without a seat but refuses other organizations and nonhuman callers", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const extraBoard = testId(90_301);
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'other','Other board','UTC')",
        [extraBoard, issuer.organizationId]
      );
      expect(
        (await read(pool, issuer, { mode: "organization", board_id: extraBoard })).items
      ).toEqual([]);
      await expect(read(pool, issuer, { board_id: extraBoard })).rejects.toThrow();
      await expect(
        read(pool, issuer, { mode: "organization", board_id: testId(90_302) })
      ).rejects.toThrow("administrative access is unavailable");
      await expect(read(pool, target, { limit: 101 })).rejects.toThrow();
      await pool.query(
        "insert into accountable_principals(id,organization_id,legal_name,reference) values($1,$2,'Synthetic accountable principal','read-test')",
        [testId(90_303), issuer.organizationId]
      );
      await pool.query(
        "update members set member_kind='ai_system',accountable_principal_id=$1,row_version=row_version+1 where id=$2",
        [testId(90_303), target.memberId]
      );
      await expect(read(pool, target)).rejects.toThrow("administrative access is unavailable");
    });
  });
  it("defaults to only own rights and offers; organization mode requires an actual administrator", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const outsider = await freshAdministrativeTestCredential(
        pool,
        await seedAdditionalAuthorizedActor(pool, issuer, {
          idBase: 89_000,
          seatRole: "voting_member",
          scopes: ["secretariat:admin", "governance:read"]
        }),
        89_100
      );
      const ownOffer = await propose(pool, issuer, target, 1);
      const otherOffer = await propose(pool, issuer, outsider, 2);
      const own = await read(pool, target);
      expect(own.items.map((x) => x["record_id"])).toEqual([ownOffer]);
      expect(JSON.stringify(own)).not.toContain(otherOffer);
      expect(own.items[0]).toMatchObject({
        record_type: "company_admin_proposal",
        row_version: "1",
        state: "pending",
        board_id: null
      });
      await expect(read(pool, target, { mode: "organization" })).rejects.toThrow(
        "administrative access is unavailable"
      );
      const all = await read(pool, issuer, { mode: "organization" });
      expect(all.items.map((x) => x["record_id"])).toEqual(
        expect.arrayContaining([testId(72_000), ownOffer, otherOffer])
      );
      expect((await read(pool, target, { board_id: target.boardId })).items).toEqual([]);
      await expect(read(pool, target, { board_id: testId(89999) })).rejects.toThrow();
    });
  });
  it("paginates without duplicates and binds the cursor to actor, mode, board and current authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const ids = [];
      for (let i = 1; i <= 3; i++) ids.push(await propose(pool, issuer, target, i));
      const first = await read(pool, target, { limit: 1 });
      expect(first.next_cursor).toEqual(expect.any(String));
      const second = await read(pool, target, { limit: 1, cursor: first.next_cursor });
      const third = await read(pool, target, { limit: 1, cursor: second.next_cursor });
      expect(
        [...first.items, ...second.items, ...third.items].map((x) => x["record_id"]).toSorted()
      ).toEqual(ids.toSorted());
      expect(third.next_cursor).toBeNull();
      await expect(read(pool, issuer, { limit: 1, cursor: first.next_cursor })).rejects.toThrow(
        "cursor"
      );
      const adminPage = await read(pool, issuer, { limit: 1 });
      await expect(
        read(pool, issuer, { mode: "organization", limit: 1, cursor: adminPage.next_cursor })
      ).rejects.toThrow("cursor");
      await expect(
        read(pool, target, { board_id: target.boardId, cursor: first.next_cursor })
      ).rejects.toThrow("cursor");
      await expect(read(pool, target, { cursor: `${first.next_cursor}x` })).rejects.toThrow(
        "cursor"
      );
      const cancellation = await stageAdministrativeAction(pool, issuer, "manage_company_admin", {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "administrative-read-cancel-0001",
        change: {
          operation: "cancel",
          proposal_id: ids[1]!,
          expected_proposal_version: 1,
          reason: "Withdraw offer"
        }
      });
      expect((await cancellation.confirm()).confirmed).toBe(true);
      await expect(read(pool, target, { cursor: first.next_cursor })).rejects.toThrow("cursor");
    });
  });
  it("the SQL read boundary denies missing scope and forged organization context", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      await pool.query(
        "update access_token_records set scope_set=array['governance:read'] where id=$1",
        [target.accessTokenRecordId]
      );
      const direct = (actor: AuthorizedActorFixture, org = actor.organizationId) =>
        withRequestTransaction(
          pool,
          { ...actor.context, organizationId: org },
          (client) =>
            client.query("select boardagent_administrative_access_page($1,$2,$3,$4)", [
              "mine",
              null,
              10,
              null
            ]),
          { assumeRole: "boardagent_server" }
        );
      await expect(direct(target)).rejects.toMatchObject({ code: "42501" });
      await expect(direct(issuer, testId(89101))).rejects.toMatchObject({ code: "42501" });
    });
  });
});
