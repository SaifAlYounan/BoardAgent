import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../lib/contracts/src/index.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { delegationFixture } from "../helpers/administrative-delegation.js";
import {
  administrativeService,
  freshAdministrativeTestCredential,
  stageAdministrativeAction
} from "../helpers/administrative-service.js";
import { seedAdditionalAuthorizedActor, testId } from "../helpers/authorized-actor.js";

// Full rows stay in disposable test memory. Receipts never contain credentials or row dumps.
async function authorityState(pool: Pool, includeAudit = true) {
  const state: Record<string, unknown> = {};
  for (const table of [
    "members",
    "board_memberships",
    "membership_versions",
    "organization_role_assignments",
    "company_admin_proposals",
    "member_admin_delegations",
    "administrative_authority_changes",
    "consent_records",
    "audit_events"
  ]) {
    if (!includeAudit && table === "audit_events") continue;
    state[table] = (
      await pool.query(
        `select coalesce(jsonb_agg(to_jsonb(t) order by id),'[]') as rows from ${table} t`
      )
    ).rows[0].rows;
  }
  return sha256Hex(Buffer.from(JSON.stringify(state)));
}

async function grantedFixture(pool: Pool) {
  const f = await delegationFixture(pool);
  expect(
    (
      await (
        await stageAdministrativeAction(pool, f.issuer, "manage_member_admin_delegation", f.input)
      ).confirm()
    ).confirmed
  ).toBe(true);
  const secretary = await freshAdministrativeTestCredential(pool, f.target, 91_000);
  const director = await seedAdditionalAuthorizedActor(pool, f.issuer, {
    idBase: 91_100,
    seatRole: "voting_member",
    scopes: ["governance:read"]
  });
  const request = {
    schema_version: "boardagent.tool-input.v1",
    idempotency_key: "delegated-limit-change-0001",
    authority_evidence: f.input.change.authority_evidence,
    change: {
      operation: "change_seat",
      member_id: director.memberId,
      board_id: director.boardId,
      seat_role: "voting_member",
      voting_weight: 2,
      is_secretary: false,
      reason: "Cited appointment decision"
    }
  };
  return { ...f, secretary, director, request };
}

async function secondReadableBoard(pool: Pool, f: Awaited<ReturnType<typeof grantedFixture>>) {
  const boardId = testId(91_200);
  await pool.query(
    "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'second-board','Second board','UTC')",
    [boardId, f.issuer.organizationId]
  );
  // Synthetic onboarding arrangement, as in seedAdditionalEntitledBoard. This is
  // a permission test; it does not stand in for anyone's actual enrollment.
  await pool.query(
    "insert into secretary_support_versions(id,organization_id,board_id,version,support_name,contact_methods,canonical_sha256,effective_at,created_by) values($1,$2,$3,1,'Second board secretary','[]',$4,transaction_timestamp()-interval '1 minute',$5)",
    [testId(91_204), f.issuer.organizationId, boardId, Buffer.alloc(32, 122), f.issuer.memberId]
  );
  for (const [index, actor] of [f.issuer, f.secretary, f.director].entries()) {
    await pool.query(
      "insert into board_memberships(id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state) values($1,$2,$3,$4,'voting_member',$5,1,'active')",
      [testId(91_201 + index), actor.organizationId, boardId, actor.memberId, index < 2]
    );
    await pool.query(
      "insert into onboarding_attestations(id,organization_id,member_id,board_id,terms_version_id,support_version_id,presentation_choice,local_memory_choice,consent_record_id) select $1,$2,$3,$4,id,$5,'structured','local-only',$6 from onboarding_terms_versions where organization_id=$2 and seat_role='voting_member' order by version desc limit 1",
      [
        testId(91_205 + index),
        actor.organizationId,
        actor.memberId,
        boardId,
        testId(91_204),
        actor.consentRecordId
      ]
    );
  }
  const bytes = Buffer.from(
    "# Second board appointment\n\nClause 9 applies only to the second board.\n"
  );
  await pool.query(
    "insert into documents(id,organization_id,board_id,title,created_by) values($1,$2,$3,'Second board authority',$4)",
    [testId(91_210), f.issuer.organizationId, boardId, f.issuer.memberId]
  );
  await pool.query(
    "insert into document_access_grants(id,organization_id,board_id,document_id,grantee_member_id,permission,granted_by) values($1,$2,$3,$4,$5,'read',$6)",
    [
      testId(91_211),
      f.issuer.organizationId,
      boardId,
      testId(91_210),
      f.secretary.memberId,
      f.issuer.memberId
    ]
  );
  await pool.query(
    "insert into document_versions(id,organization_id,board_id,document_id,version,media_type,canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by) values($1,$2,$3,$4,1,'text/markdown; charset=utf-8','RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)",
    [
      testId(91_212),
      f.issuer.organizationId,
      boardId,
      testId(91_210),
      bytes,
      bytes.length,
      Buffer.from(sha256Hex(bytes), "hex"),
      f.issuer.memberId
    ]
  );
  const evidence = [
    {
      document_version_id: testId(91_212),
      sha256: sha256Hex(bytes),
      clause: "9",
      locator: "Second board authority"
    }
  ];
  const { principal, reads } = await administrativeService(pool, f.secretary);
  expect(principal.boardIds).toContain(boardId);
  const visible = await reads.executeRead(principal, "read_document", {
    schema_version: "boardagent.tool-input.v1",
    document_id: testId(91_210),
    version_id: testId(91_212)
  });
  expect(visible).toMatchObject({
    data: {
      version_id: testId(91_212),
      canonical_body: bytes.toString("utf8"),
      sha256: sha256Hex(bytes)
    }
  });
  return { boardId, evidence };
}

type DirectorOperation = "change_seat" | "suspend" | "remove" | "reactivate";
const protectedCases = (["secretariat", "management"] as const).flatMap((role) =>
  (["change_seat", "suspend", "remove", "reactivate"] as const).map((operation) => ({
    role,
    operation
  }))
);
async function directorRequest(
  pool: Pool,
  f: Awaited<ReturnType<typeof grantedFixture>>,
  operation: DirectorOperation
) {
  const change = {
    operation,
    member_id: f.director.memberId,
    board_id: f.director.boardId,
    reason: "Cited director lifecycle change"
  };
  if (operation === "reactivate") {
    const suspended = await stageAdministrativeAction(pool, f.issuer, "manage_member", {
      ...f.request,
      idempotency_key: "suspend-before-reactivation-0001",
      change: { ...change, operation: "suspend" }
    });
    expect((await suspended.confirm()).confirmed).toBe(true);
  }
  return operation === "change_seat" ? f.request : { ...f.request, change };
}

describe("SR097/AC11–15 delegated secretary limits", () => {
  it("retains organization secretary protection after confirmed admin transfer and loss of the board secretary seat", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await grantedFixture(pool);
      // Match the bootstrap organization-role arrangement in this synthetic identity fixture.
      // The transfer and subsequent seat change use the real confirmed service paths.
      await pool.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'secretariat','Synthetic initial organization secretary')",
        [testId(91_820), f.issuer.organizationId, f.issuer.memberId]
      );
      const recipient = await freshAdministrativeTestCredential(pool, f.director, 91_830);
      const proposalId = testId(91_840);
      const offer = await stageAdministrativeAction(pool, f.issuer, "manage_company_admin", {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "protected-target-transfer-0001",
        change: {
          operation: "transfer",
          proposal_id: proposalId,
          member_id: recipient.memberId,
          expected_member_version: 1,
          reason: "Transfer the administrative responsibility"
        }
      });
      expect((await offer.confirm()).confirmed).toBe(true);
      const acceptance = await stageAdministrativeAction(pool, recipient, "manage_company_admin", {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "protected-target-accept-0001",
        change: {
          operation: "accept",
          proposal_id: proposalId,
          expected_proposal_version: 1,
          reason: "Accept administrative responsibility"
        }
      });
      expect((await acceptance.confirm()).confirmed).toBe(true);
      const admin = await freshAdministrativeTestCredential(pool, recipient, 91_850);
      const targetRequest = {
        ...f.request,
        change: { ...f.request.change, member_id: f.issuer.memberId }
      };
      expect(
        (
          await (
            await stageAdministrativeAction(pool, admin, "manage_member", {
              schema_version: targetRequest.schema_version,
              idempotency_key: targetRequest.idempotency_key,
              change: targetRequest.change
            })
          ).confirm()
        ).confirmed
      ).toBe(true);
      expect(
        (
          await pool.query(
            "select seat_role,is_secretary,state from board_memberships where member_id=$1",
            [f.issuer.memberId]
          )
        ).rows
      ).toEqual([{ seat_role: "voting_member", is_secretary: false, state: "active" }]);
      expect(
        (
          await pool.query(
            "select role from organization_role_assignments where member_id=$1 and active_from<=transaction_timestamp() and (active_until is null or active_until>transaction_timestamp()) order by role",
            [f.issuer.memberId]
          )
        ).rows
      ).toEqual([{ role: "secretariat" }]);
      const ordinary = await seedAdditionalAuthorizedActor(pool, admin, {
        idBase: 91_900,
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      expect(
        (
          await (
            await stageAdministrativeAction(pool, f.secretary, "manage_member", {
              ...f.request,
              idempotency_key: "still-effective-delegation-0001",
              change: { ...f.request.change, member_id: ordinary.memberId }
            })
          ).confirm()
        ).confirmed
      ).toBe(true);
      const removal = {
        ...targetRequest,
        idempotency_key: "protected-former-admin-0001",
        change: {
          operation: "remove",
          member_id: f.issuer.memberId,
          board_id: f.issuer.boardId,
          reason: "Cited seat removal"
        }
      };
      const before = await authorityState(pool);
      await expect(
        stageAdministrativeAction(pool, f.secretary, "manage_member", removal)
      ).rejects.toMatchObject({ code: "42501", message: "member administration is unavailable" });
      expect(await authorityState(pool)).toBe(before);
      expect(
        (
          await (
            await stageAdministrativeAction(pool, admin, "manage_member", {
              schema_version: removal.schema_version,
              idempotency_key: removal.idempotency_key,
              change: removal.change
            })
          ).confirm()
        ).confirmed
      ).toBe(true);
    });
  });

  it.each(protectedCases)(
    "reserves $operation on a voting director with an organization $role role for the administrator",
    async ({ role, operation }) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await grantedFixture(pool);
        const request = await directorRequest(pool, f, operation);
        await pool.query(
          "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,$4,'Synthetic protected-role regression')",
          [testId(91_810), f.issuer.organizationId, f.director.memberId, role]
        );
        const before = await authorityState(pool);
        await expect(
          stageAdministrativeAction(pool, f.secretary, "manage_member", request)
        ).rejects.toMatchObject({ code: "42501", message: "member administration is unavailable" });
        expect(await authorityState(pool)).toBe(before);
        expect(
          (
            await (
              await stageAdministrativeAction(pool, f.issuer, "manage_member", request)
            ).confirm()
          ).confirmed
        ).toBe(true);
      });
    }
  );

  it.each(protectedCases)(
    "rechecks organization $role acquired after staging $operation",
    async ({ role, operation }) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await grantedFixture(pool);
        const request = await directorRequest(pool, f, operation);
        const staged = await stageAdministrativeAction(pool, f.secretary, "manage_member", request);
        await pool.query(
          "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,$4,'Synthetic authority change after staging')",
          [testId(91_811), f.issuer.organizationId, f.director.memberId, role]
        );
        // A refused stale stage may retain a denial audit event, but cannot change
        // memberships, privileged assignments or consent/governance authority.
        const before = await authorityState(pool, false);
        await staged.confirm().then(
          (result) => expect(result.confirmed).toBe(false),
          (error: unknown) =>
            expect(error).toMatchObject({
              code: "42501",
              message: "member administration is unavailable"
            })
        );
        expect(await authorityState(pool, false)).toBe(before);
      });
    }
  );

  it.each(
    (["secretariat", "management"] as const).flatMap((role) =>
      (["ended", "future"] as const).map((timing) => ({ role, timing }))
    )
  )(
    "does not treat a $timing organization $role assignment as current authority",
    async ({ role, timing }) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await grantedFixture(pool);
        await pool.query(
          "insert into organization_role_assignments(id,organization_id,member_id,role,active_from,active_until,change_reason) values($1,$2,$3,$4,transaction_timestamp()+$5::interval,transaction_timestamp()+$6::interval,'Synthetic authority timing fixture')",
          [
            testId(91_812),
            f.issuer.organizationId,
            f.director.memberId,
            role,
            timing === "ended" ? "-2 days" : "1 day",
            timing === "ended" ? "-1 day" : "2 days"
          ]
        );
        expect(
          (
            await (
              await stageAdministrativeAction(pool, f.secretary, "manage_member", f.request)
            ).confirm()
          ).confirmed
        ).toBe(true);
      });
    }
  );

  it.each(["delegate", "director"] as const)(
    "an active %s cannot grant, extend or revoke delegation",
    async (role) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await grantedFixture(pool);
        const recipient = await seedAdditionalAuthorizedActor(pool, f.issuer, {
          idBase: 91_700,
          seatRole: "voting_member",
          scopes: ["governance:read"]
        });
        expect(
          (
            await (
              await stageAdministrativeAction(pool, f.issuer, "manage_member", {
                schema_version: "boardagent.tool-input.v1",
                idempotency_key: "appoint-grant-recipient-0001",
                change: {
                  operation: "change_seat",
                  member_id: recipient.memberId,
                  board_id: f.issuer.boardId,
                  seat_role: "voting_member",
                  voting_weight: 1,
                  is_secretary: true,
                  reason: "Appoint an eligible grant recipient"
                }
              })
            ).confirm()
          ).confirmed
        ).toBe(true);
        const actor =
          role === "delegate"
            ? f.secretary
            : await freshAdministrativeTestCredential(pool, f.director, 91_300);
        const before = await authorityState(pool);
        const requests = [
          {
            ...f.input,
            idempotency_key: "onward-delegation-grant-0001",
            change: {
              ...f.input.change,
              member_id: recipient.memberId,
              delegation_id: testId(91_310),
              expected_member_version: 2
            }
          },
          {
            ...f.input,
            idempotency_key: "extend-own-delegation-0001",
            change: {
              ...f.input.change,
              expected_member_version: 2,
              expires_at: new Date(Date.now() + 2 * 86400_000).toISOString()
            }
          },
          {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "revoke-own-delegation-0001",
            change: {
              operation: "revoke",
              delegation_id: f.input.change.delegation_id,
              board_id: f.issuer.boardId,
              expected_delegation_version: 1,
              reason: "Attempt to revoke a delegation"
            }
          }
        ];
        for (const request of requests) {
          await expect(
            stageAdministrativeAction(pool, actor, "manage_member_admin_delegation", request)
          ).rejects.toMatchObject({ code: "42501" });
          expect(await authorityState(pool)).toBe(before);
        }
        // The exact onward grant is valid when the organization administrator confirms it.
        expect(
          (
            await (
              await stageAdministrativeAction(
                pool,
                f.issuer,
                "manage_member_admin_delegation",
                requests[0]!
              )
            ).confirm()
          ).confirmed
        ).toBe(true);
        expect(
          (
            await (
              await stageAdministrativeAction(pool, f.secretary, "manage_member", f.request)
            ).confirm()
          ).confirmed
        ).toBe(true);
      });
    }
  );

  it("membership and secretary status on a real readable board do not imply delegated authority there", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await grantedFixture(pool);
      const second = await secondReadableBoard(pool, f);
      const before = await authorityState(pool);
      await expect(
        stageAdministrativeAction(pool, f.secretary, "manage_member", {
          ...f.request,
          authority_evidence: second.evidence,
          change: { ...f.request.change, board_id: second.boardId }
        })
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        stageAdministrativeAction(pool, f.secretary, "manage_member", {
          ...f.request,
          authority_evidence: second.evidence,
          change: {
            operation: "invite",
            member_id: testId(91_320),
            board_id: second.boardId,
            member_kind: "human",
            seat_role: "voting_member",
            legal_name: "Second board director",
            display_name: "Second board director",
            voting_weight: 1,
            accountable_principal_id: null,
            reason: "Second board appointment"
          }
        })
      ).rejects.toMatchObject({ code: "member_invite_unavailable" });
      expect(await authorityState(pool)).toBe(before);
      expect(
        (
          await (
            await stageAdministrativeAction(pool, f.secretary, "manage_member", f.request)
          ).confirm()
        ).confirmed
      ).toBe(true);
      expect(
        (
          await pool.query(
            "select voting_weight::text from board_memberships where member_id=$1 and board_id=$2",
            [f.director.memberId, second.boardId]
          )
        ).rows[0]
      ).toEqual({ voting_weight: "1" });
    });
  });

  it.each(["observer", "ai", "delegate"] as const)(
    "cannot remove a protected %s account",
    async (kind) => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await grantedFixture(pool);
        let memberId: string;
        if (kind === "ai") {
          memberId = testId(91_400);
          await pool.query(
            "insert into accountable_principals(id,organization_id,legal_name,reference) values($1,$2,'Synthetic AI operator','synthetic-ai-operator')",
            [testId(91_401), f.issuer.organizationId]
          );
          const aiInvite = {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "protected-ai-admin-invite-0001",
            authority_evidence: f.request.authority_evidence,
            change: {
              operation: "invite",
              member_id: memberId,
              board_id: f.issuer.boardId,
              member_kind: "ai_observer",
              seat_role: "observer",
              legal_name: "Synthetic AI",
              display_name: "Synthetic AI",
              voting_weight: 0,
              accountable_principal_id: testId(91_401),
              reason: "Register a synthetic AI observer"
            }
          };
          const beforeInvite = await authorityState(pool);
          await expect(
            stageAdministrativeAction(pool, f.secretary, "manage_member", aiInvite)
          ).rejects.toMatchObject({ code: "member_invite_unavailable" });
          expect(await authorityState(pool)).toBe(beforeInvite);
          expect(
            (
              await (
                await stageAdministrativeAction(pool, f.issuer, "manage_member", aiInvite)
              ).confirm()
            ).confirmed
          ).toBe(true);
          expect(
            (await pool.query("select member_kind from members where id=$1", [memberId])).rows[0]
          ).toEqual({ member_kind: "ai_system" });
        } else {
          const actor = await seedAdditionalAuthorizedActor(pool, f.issuer, {
            idBase: 91_500,
            seatRole: kind === "observer" ? "observer" : "voting_member",
            isSecretary: false,
            scopes: ["governance:read"]
          });
          memberId = actor.memberId;
          if (kind === "delegate") {
            expect(
              (
                await (
                  await stageAdministrativeAction(pool, f.issuer, "manage_member", {
                    schema_version: "boardagent.tool-input.v1",
                    idempotency_key: "appoint-second-secretary-0001",
                    change: {
                      operation: "change_seat",
                      member_id: memberId,
                      board_id: f.issuer.boardId,
                      seat_role: "voting_member",
                      voting_weight: 1,
                      is_secretary: true,
                      reason: "Appoint a second secretary"
                    }
                  })
                ).confirm()
              ).confirmed
            ).toBe(true);
            expect(
              (
                await (
                  await stageAdministrativeAction(
                    pool,
                    f.issuer,
                    "manage_member_admin_delegation",
                    {
                      ...f.input,
                      idempotency_key: "second-secretary-grant-0001",
                      change: {
                        ...f.input.change,
                        expected_member_version: 2,
                        member_id: memberId,
                        delegation_id: testId(91_600)
                      }
                    }
                  )
                ).confirm()
              ).confirmed
            ).toBe(true);
            expect(
              (
                await pool.query("select state from member_admin_delegations where id=$1", [
                  testId(91_600)
                ])
              ).rows[0]
            ).toEqual({ state: "active" });
          }
        }
        const before = await authorityState(pool);
        await expect(
          stageAdministrativeAction(pool, f.secretary, "manage_member", {
            ...f.request,
            change: {
              operation: "remove",
              member_id: memberId,
              board_id: f.issuer.boardId,
              reason: "Attempt a protected target change"
            }
          })
        ).rejects.toMatchObject({ code: "42501", message: "member administration is unavailable" });
        expect(await authorityState(pool)).toBe(before);
      });
    }
  );

  it("refuses a readable citation from the other board without changing the director", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await grantedFixture(pool);
      const second = await secondReadableBoard(pool, f);
      const before = await authorityState(pool);
      await expect(
        stageAdministrativeAction(pool, f.secretary, "manage_member", {
          ...f.request,
          authority_evidence: second.evidence
        })
      ).rejects.toMatchObject({ code: "42501" });
      expect(await authorityState(pool)).toBe(before);
    });
  });

  it("rechecks citation access at confirmation and refuses a new preparation after access ends", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await grantedFixture(pool);
      const staged = await stageAdministrativeAction(pool, f.secretary, "manage_member", f.request);
      // Controlled ACL withdrawal; runtime authority tables remain untouched.
      await pool.query(
        "update document_access_grants set active_until=clock_timestamp() where id=$1",
        [testId(76_004)]
      );
      const before = await authorityState(pool);
      await expect(staged.confirm()).rejects.toMatchObject({ code: "42501" });
      await expect(
        stageAdministrativeAction(pool, f.secretary, "manage_member", f.request)
      ).rejects.toMatchObject({ code: "42501" });
      expect(await authorityState(pool)).toBe(before);
    });
  });

  it("rejects invalid evidence and reason lengths; binds both allowed reason boundaries and exact citations to audit and consent", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await grantedFixture(pool);
      const before = await authorityState(pool);
      for (const { authority_evidence, error } of [
        { authority_evidence: [], error: { name: "ZodError" } },
        {
          authority_evidence: [{ ...f.request.authority_evidence[0]!, clause: "" }],
          error: { name: "ZodError" }
        },
        {
          authority_evidence: [{ ...f.request.authority_evidence[0]!, sha256: "0".repeat(64) }],
          error: { code: "42501" }
        }
      ]) {
        await expect(
          stageAdministrativeAction(pool, f.secretary, "manage_member", {
            ...f.request,
            authority_evidence
          })
        ).rejects.toMatchObject(error);
        expect(await authorityState(pool)).toBe(before);
      }
      for (const reason of ["", "x".repeat(2001)]) {
        await expect(
          stageAdministrativeAction(pool, f.secretary, "manage_member", {
            ...f.request,
            change: { ...f.request.change, reason }
          })
        ).rejects.toMatchObject(reason.length === 0 ? { name: "ZodError" } : { code: "42501" });
        expect(await authorityState(pool)).toBe(before);
      }
      for (const [index, reason] of ["x", "x".repeat(2000)].entries()) {
        const request = {
          ...f.request,
          idempotency_key: `reason-boundary-confirm-${index}-0001`,
          change: { ...f.request.change, voting_weight: index + 2, reason }
        };
        const staged = await stageAdministrativeAction(pool, f.secretary, "manage_member", request);
        expect((await staged.confirm()).confirmed).toBe(true);
        const proof = (
          await pool.query(
            `select convert_from(s.canonical_payload,'UTF8')::jsonb as payload,
          convert_from(a.canonical_payload,'UTF8')::jsonb->'details'->'administrativeAuthority' as authority,
          a.consent_record_id=c.id and v.consent_record_id=c.id and v.audit_event_id=a.id as linked,
          v.change_reason as reason from action_stages s join consent_records c on c.stage_id=s.id
          join audit_events a on a.consent_record_id=c.id join membership_versions v on v.audit_event_id=a.id
          where s.id=$1`,
            [staged.prepared.stage_id]
          )
        ).rows;
        expect(proof).toHaveLength(1);
        expect(proof[0]).toMatchObject({
          linked: true,
          reason,
          authority: {
            mode: "delegated",
            delegationId: f.input.change.delegation_id,
            appointmentEvidence: request.authority_evidence
          },
          payload: { request }
        });
      }
    });
  });
});
