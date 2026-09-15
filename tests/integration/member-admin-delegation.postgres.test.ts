import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { delegationFixture as fixture } from "../helpers/administrative-delegation.js";
import { testId, seedAdditionalAuthorizedActor } from "../helpers/authorized-actor.js";
import {
  stageAdministrativeAction,
  administrativeService,
  freshAdministrativeTestCredential
} from "../helpers/administrative-service.js";

describe("SR097 exact-board secretary delegation preparation", () => {
  it.each(["revoked", "expired"] as const)(
    "a %s grant cannot complete a previously prepared director change",
    async (loss) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await fixture(pool);
        const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
          idBase: 80_000,
          seatRole: "voting_member",
          scopes: ["governance:read"]
        });
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
        const secretary = await freshAdministrativeTestCredential(pool, f.target, 80_100);
        const request = {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "stale-delegation-director-0001",
          authority_evidence: f.input.change.authority_evidence,
          change: {
            operation: "suspend",
            member_id: director.memberId,
            board_id: f.issuer.boardId,
            reason: "Cited director suspension"
          }
        };
        const pending = await stageAdministrativeAction(pool, secretary, "manage_member", request);
        if (loss === "revoked") {
          expect(
            (
              await (
                await stageAdministrativeAction(pool, f.issuer, "manage_member_admin_delegation", {
                  schema_version: "boardagent.tool-input.v1",
                  idempotency_key: "revoke-before-director-confirm-0001",
                  change: {
                    operation: "revoke",
                    delegation_id: f.input.change.delegation_id,
                    board_id: f.issuer.boardId,
                    expected_delegation_version: 1,
                    reason: "End the administrative grant"
                  }
                })
              ).confirm()
            ).confirmed
          ).toBe(true);
        } else {
          // Disposable superuser time fixture; runtime cannot rewrite this lineage.
          await pool.query(
            "alter table member_admin_delegations disable trigger boardagent_member_admin_delegation_transition"
          );
          await pool.query(
            "update member_admin_delegations set created_at=created_at-interval '2 days',expires_at=expires_at-interval '2 days'"
          );
          await pool.query(
            "alter table member_admin_delegations enable trigger boardagent_member_admin_delegation_transition"
          );
        }
        await expect(pending.confirm()).rejects.toMatchObject({ code: "42501" });
        const reconnected = await freshAdministrativeTestCredential(pool, f.target, 80_200);
        await expect(
          stageAdministrativeAction(pool, reconnected, "manage_member", request)
        ).rejects.toMatchObject({ code: "42501" });
        expect(
          (
            await pool.query("select state from board_memberships where member_id=$1", [
              director.memberId
            ])
          ).rows[0]
        ).toEqual({ state: "active" });
      });
    }
  );
  it("restoring secretary status does not revive a prior grant; a fresh confirmed grant is required", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
      const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
        idBase: 80_300,
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
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
      for (const is_secretary of [false, true]) {
        expect(
          (
            await (
              await stageAdministrativeAction(pool, f.issuer, "manage_member", {
                schema_version: "boardagent.tool-input.v1",
                idempotency_key: `secretary-role-change-${String(is_secretary)}-0001`,
                change: {
                  operation: "change_seat",
                  member_id: f.target.memberId,
                  board_id: f.issuer.boardId,
                  seat_role: "voting_member",
                  voting_weight: 1,
                  is_secretary,
                  reason: "Change the secretary appointment"
                }
              })
            ).confirm()
          ).confirmed
        ).toBe(true);
      }
      const request = {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "restored-secretary-director-0001",
        authority_evidence: f.input.change.authority_evidence,
        change: {
          operation: "suspend",
          member_id: director.memberId,
          board_id: f.issuer.boardId,
          reason: "Apply the cited appointment decision"
        }
      };
      const prior = await freshAdministrativeTestCredential(pool, f.target, 80_400);
      await expect(
        stageAdministrativeAction(pool, prior, "manage_member", request)
      ).rejects.toMatchObject({ code: "42501" });
      expect(
        (
          await pool.query("select state from member_admin_delegations where id=$1", [
            f.input.change.delegation_id
          ])
        ).rows[0]
      ).toEqual({ state: "active" });
      expect(
        (
          await (
            await stageAdministrativeAction(pool, f.issuer, "manage_member_admin_delegation", {
              ...f.input,
              idempotency_key: "fresh-secretary-delegation-0001",
              change: {
                ...f.input.change,
                delegation_id: testId(80_500),
                expected_member_version: 4
              }
            })
          ).confirm()
        ).confirmed
      ).toBe(true);
      const current = await freshAdministrativeTestCredential(pool, f.target, 80_600);
      expect(
        (await (await stageAdministrativeAction(pool, current, "manage_member", request)).confirm())
          .confirmed
      ).toBe(true);
      expect(
        (await pool.query("select count(*)::int as n from member_admin_delegations")).rows[0]
      ).toEqual({ n: 2 });
    });
  });
  it("rejects self, organization-wide, other-board, secretarial promotion and uncited director changes", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
      const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
        idBase: 79_000,
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
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
      const secretary = await freshAdministrativeTestCredential(pool, f.target, 79_100);
      const base = {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "forbidden-delegated-member-0001",
        authority_evidence: f.input.change.authority_evidence,
        change: {
          operation: "change_seat",
          member_id: director.memberId,
          board_id: f.issuer.boardId,
          seat_role: "voting_member",
          voting_weight: 2,
          is_secretary: false,
          reason: "Cited appointment decision"
        }
      };
      for (const change of [
        { ...base.change, member_id: secretary.memberId },
        { ...base.change, board_id: testId(79_200) },
        { ...base.change, seat_role: "management", voting_weight: 0 },
        { ...base.change, is_secretary: true },
        { ...base.change, reason: "x".repeat(2001) }
      ])
        await expect(
          stageAdministrativeAction(pool, secretary, "manage_member", { ...base, change })
        ).rejects.toMatchObject({ code: "42501" });
      await expect(
        stageAdministrativeAction(pool, secretary, "manage_member", {
          ...base,
          authority_evidence: [{ ...base.authority_evidence[0]!, sha256: "0".repeat(64) }]
        })
      ).rejects.toMatchObject({ code: "42501" });
      const { authority_evidence: _evidence, ...uncited } = base;
      await expect(
        stageAdministrativeAction(pool, secretary, "manage_member", uncited)
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        stageAdministrativeAction(pool, secretary, "manage_member", {
          ...base,
          change: {
            operation: "remove",
            member_id: director.memberId,
            board_id: null,
            reason: "Remove organization access"
          }
        })
      ).rejects.toMatchObject({ code: "42501" });
      expect(
        (
          await pool.query(
            "select voting_weight::text,is_secretary from board_memberships where member_id=$1",
            [director.memberId]
          )
        ).rows[0]
      ).toEqual({ voting_weight: "1", is_secretary: false });
    });
  });
  it.each(["organization_admin", "other_board_secretary", "management_seat"] as const)(
    "does not disclose or administer a protected %s target",
    async (protection) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await fixture(pool);
        const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
          idBase: 79_300,
          seatRole: "voting_member",
          scopes: ["governance:read"]
        });
        if (protection === "organization_admin")
          await pool.query(
            "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Synthetic protected target')",
            [testId(79_400), director.organizationId, director.memberId]
          );
        if (protection === "management_seat")
          await pool.query(
            "update board_memberships set seat_role='management',voting_weight=0 where member_id=$1",
            [director.memberId]
          );
        if (protection === "other_board_secretary") {
          await pool.query(
            "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'private-board','Private board','UTC')",
            [testId(79_401), director.organizationId]
          );
          await pool.query(
            "insert into board_memberships(id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state) values($1,$2,$3,$4,'voting_member',true,1,'active')",
            [testId(79_402), director.organizationId, testId(79_401), director.memberId]
          );
        }
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
        const secretary = await freshAdministrativeTestCredential(pool, f.target, 79_500);
        await expect(
          stageAdministrativeAction(pool, secretary, "manage_member", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "protected-director-remove-0001",
            authority_evidence: f.input.change.authority_evidence,
            change: {
              operation: "remove",
              member_id: director.memberId,
              board_id: f.issuer.boardId,
              reason: "Attempt a protected change"
            }
          })
        ).rejects.toMatchObject({ code: "42501", message: "member administration is unavailable" });
      });
    }
  );
  it("lets a reconnected delegate invite an ordinary director with cited appointment evidence", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
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
      const secretary = await freshAdministrativeTestCredential(pool, f.target, 77_100);
      const input = {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "delegated-director-invite-0001",
        authority_evidence: f.input.change.authority_evidence,
        change: {
          operation: "invite",
          member_id: testId(77_000),
          board_id: f.issuer.boardId,
          member_kind: "human",
          seat_role: "voting_member",
          legal_name: "Appointed Director",
          display_name: "Appointed Director",
          voting_weight: 1,
          accountable_principal_id: null,
          reason: "Register the appointed director"
        }
      };
      const invitation = await stageAdministrativeAction(pool, secretary, "manage_member", input);
      expect((await invitation.confirm()).confirmed).toBe(true);
      expect(
        (await pool.query("select state,member_kind from members where id=$1", [testId(77_000)]))
          .rows[0]
      ).toEqual({ state: "invited", member_kind: "human" });
      expect(
        (
          await pool.query(
            "select seat_role,is_secretary from board_memberships where member_id=$1",
            [testId(77_000)]
          )
        ).rows[0]
      ).toEqual({ seat_role: "voting_member", is_secretary: false });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from organization_role_assignments where member_id=$1 and role='admin'",
            [secretary.memberId]
          )
        ).rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it("lets a delegate suspend and restore only the director's seat with an unchanged membership history", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
      const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
        idBase: 77_200,
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
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
      const secretary = await freshAdministrativeTestCredential(pool, f.target, 77_300);
      for (const operation of ["suspend", "reactivate"] as const) {
        const action = await stageAdministrativeAction(pool, secretary, "manage_member", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: `delegated-director-${operation}-0001`,
          authority_evidence: f.input.change.authority_evidence,
          change: {
            operation,
            member_id: director.memberId,
            board_id: f.issuer.boardId,
            reason: "Apply the cited board appointment decision"
          }
        });
        expect((await action.confirm()).confirmed).toBe(true);
      }
      expect(
        (await pool.query("select state from members where id=$1", [director.memberId])).rows[0]
      ).toEqual({ state: "active" });
      expect(
        (
          await pool.query(
            "select state,entitlement_generation::text from board_memberships where member_id=$1",
            [director.memberId]
          )
        ).rows[0]
      ).toEqual({ state: "active", entitlement_generation: "3" });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from membership_versions where member_id=$1 and consent_record_id is not null",
            [director.memberId]
          )
        ).rows[0]
      ).toEqual({ n: 2 });
    });
  });
  it("confirms and revokes one board grant with retained evidence and credential invalidation", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
      const grant = await stageAdministrativeAction(
        pool,
        f.issuer,
        "manage_member_admin_delegation",
        f.input
      );
      expect(
        (await pool.query("select count(*)::int as n from member_admin_delegations")).rows[0]
      ).toEqual({ n: 0 });
      expect(grant.prepared.confirmation_lines.join("\n")).toContain(f.issuer.boardId);
      expect((await grant.confirm()).confirmed).toBe(true);
      expect(
        (
          await pool.query(
            "select state,row_version::text,authority_evidence from member_admin_delegations"
          )
        ).rows[0]
      ).toEqual({
        state: "active",
        row_version: "1",
        authority_evidence: f.input.change.authority_evidence
      });
      expect(
        (
          await pool.query(
            "select revoked_at is not null as revoked from access_token_records where id=$1",
            [f.target.accessTokenRecordId]
          )
        ).rows[0]
      ).toEqual({ revoked: true });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from organization_role_assignments where member_id=$1 and role='admin'",
            [f.target.memberId]
          )
        ).rows[0]
      ).toEqual({ n: 0 });
      const revoke = await stageAdministrativeAction(
        pool,
        f.issuer,
        "manage_member_admin_delegation",
        {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "secretary-delegation-revoke-0001",
          change: {
            operation: "revoke",
            delegation_id: f.input.change.delegation_id,
            board_id: f.issuer.boardId,
            expected_delegation_version: 1,
            reason: "End this limited grant"
          }
        }
      );
      expect((await revoke.confirm()).confirmed).toBe(true);
      expect(
        (
          await pool.query(
            "select state,row_version::text,authority_evidence from member_admin_delegations"
          )
        ).rows[0]
      ).toEqual({
        state: "revoked",
        row_version: "2",
        authority_evidence: f.input.change.authority_evidence
      });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from administrative_authority_changes where action_code='manage_member_admin_delegation'"
          )
        ).rows[0]
      ).toEqual({ n: 2 });
      expect(
        (
          await pool.query(
            "select identity_generation::text,row_version::text from members where id=$1",
            [f.target.memberId]
          )
        ).rows[0]
      ).toEqual({ identity_generation: "3", row_version: "3" });
    });
  });
  it("binds one current secretary, board, deadline and readable immutable citation without granting at prepare", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
      expect(await f.prepare()).toMatchObject({
        operation: "grant",
        recordType: "member_admin_delegation",
        boardId: f.issuer.boardId,
        targetMemberId: f.target.memberId,
        before: null,
        after: {
          state: "active",
          boardId: f.issuer.boardId,
          memberId: f.target.memberId,
          authorityEvidence: f.input.change.authority_evidence
        },
        affectedMemberIds: [f.target.memberId]
      });
      expect(
        (await pool.query("select count(*)::int as n from member_admin_delegations")).rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it("does not let an ordinary secretary create or redelegate administrative authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool, false);
      await expect(f.prepare()).rejects.toMatchObject({ code: "42501" });
    });
  });
  it("denies stale members, non-secretaries, wrong boards, unavailable citations and oversized deadlines", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
      const change = (patch: object) => ({ ...f.input, change: { ...f.input.change, ...patch } });
      await expect(f.prepare(change({ expected_member_version: 2 }))).rejects.toMatchObject({
        code: "42501"
      });
      await expect(f.prepare(change({ board_id: testId(76_100) }))).rejects.toMatchObject({
        code: "42501"
      });
      await expect(
        f.prepare(change({ expires_at: new Date(Date.now() + 91 * 86400_000).toISOString() }))
      ).rejects.toMatchObject({ code: "22023" });
      await expect(
        f.prepare(
          change({
            authority_evidence: [
              { ...f.input.change.authority_evidence[0], sha256: "0".repeat(64) }
            ]
          })
        )
      ).rejects.toMatchObject({ code: "42501" });
      await pool.query("update board_memberships set is_secretary=false where member_id=$1", [
        f.target.memberId
      ]);
      await expect(f.prepare()).rejects.toMatchObject({ code: "42501" });
    });
  });
});

describe("MR-MEC-001 chair appointment does not expand delegated authority", () => {
  it("an otherwise valid cited delegate cannot explicitly assign or clear a chair", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await fixture(pool);
      const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
        idBase: 81300,
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
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
      const secretary = await freshAdministrativeTestCredential(pool, f.target, 81400);
      for (const is_chair of [true, false]) {
        await expect(
          stageAdministrativeAction(pool, secretary, "manage_member", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: `delegated-chair-${String(is_chair)}-0001`,
            authority_evidence: f.input.change.authority_evidence,
            change: {
              operation: "change_seat",
              member_id: director.memberId,
              board_id: f.issuer.boardId,
              seat_role: "voting_member",
              voting_weight: 2,
              is_secretary: false,
              is_chair,
              reason: "Cited director weight change cannot also assign chair"
            }
          })
        ).rejects.toMatchObject({ code: "42501" });
      }
      expect(
        (
          await pool.query(
            "select is_chair,voting_weight::text from board_memberships where member_id=$1",
            [director.memberId]
          )
        ).rows
      ).toEqual([{ is_chair: false, voting_weight: "1" }]);
    });
  });
});

describe("MR-MEC-002 exact current delegated lifecycle replay", () => {
  it.each(["citation", "revoked", "renewed"] as const)(
    "returns original safe response while authority is live, then refuses after %s authority changes",
    async (loss) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await fixture(pool);
        const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
          idBase: 81500,
          seatRole: "voting_member",
          scopes: ["governance:read"]
        });
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
        let secretary = await freshAdministrativeTestCredential(pool, f.target, 81600);
        const input = {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "delegated-lifecycle-replay-0001",
          authority_evidence: f.input.change.authority_evidence,
          change: {
            operation: "change_seat",
            member_id: director.memberId,
            board_id: f.issuer.boardId,
            seat_role: "voting_member",
            voting_weight: 2,
            is_secretary: false,
            reason: "Cited director weight update"
          }
        };
        const original = await (
          await stageAdministrativeAction(pool, secretary, "manage_member", input)
        ).confirm();
        if (!original.confirmed) throw new Error("expected original delegated change");
        let current = await administrativeService(pool, secretary);
        expect(
          await current.service.replayHumanAction(current.principal, "manage_member", input)
        ).toEqual({ ...original.result, status: "already_applied" });
        if (loss === "citation") {
          await pool.query(
            "update document_access_grants set active_until=transaction_timestamp() where grantee_member_id=$1",
            [secretary.memberId]
          );
        } else {
          expect(
            (
              await (
                await stageAdministrativeAction(pool, f.issuer, "manage_member_admin_delegation", {
                  schema_version: "boardagent.tool-input.v1",
                  idempotency_key: "revoke-replay-delegation-0001",
                  change: {
                    operation: "revoke",
                    delegation_id: f.input.change.delegation_id,
                    board_id: f.issuer.boardId,
                    expected_delegation_version: 1,
                    reason: "End current delegation"
                  }
                })
              ).confirm()
            ).confirmed
          ).toBe(true);
          if (loss === "renewed") {
            const version = (
              await pool.query("select row_version::int as version from members where id=$1", [
                secretary.memberId
              ])
            ).rows[0].version;
            expect(
              (
                await (
                  await stageAdministrativeAction(
                    pool,
                    f.issuer,
                    "manage_member_admin_delegation",
                    {
                      ...f.input,
                      idempotency_key: "renew-replay-delegation-0001",
                      change: {
                        ...f.input.change,
                        delegation_id: testId(81700),
                        expected_member_version: version
                      }
                    }
                  )
                ).confirm()
              ).confirmed
            ).toBe(true);
          }
          secretary = await freshAdministrativeTestCredential(pool, f.target, 81800);
          current = await administrativeService(pool, secretary);
        }
        const count = async () =>
          (
            await pool.query(
              "select (select count(*)::int from audit_events) as audit,(select count(*)::int from membership_versions) as versions,(select count(*)::int from action_stages) as stages"
            )
          ).rows;
        const before = await count();
        await expect(
          current.service.replayHumanAction(current.principal, "manage_member", input)
        ).rejects.toMatchObject({ code: "42501" });
        expect(await count()).toEqual(before);
      });
    }
  );
});
