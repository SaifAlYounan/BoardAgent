import { describe, expect, it } from "vitest";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";

const setup = {
  organizationLegalName: "Synthetic Renewal Company",
  organizationDisplayName: "Synthetic Renewal Company",
  organizationSlug: "renewal-test",
  timezone: "UTC",
  canonicalResourceUri: "https://renewal.boardagent.test/mcp",
  boardSlug: "main",
  boardName: "Main Board",
  boardCanonicalPayload: { schemaVersion: "boardagent.board.v1", name: "Main Board" },
  firstSecretaryLegalName: "First Administrator",
  firstSecretaryDisplayName: "First Administrator",
  votingWeight: 1,
  supportName: "Secretary office",
  supportContactMethods: [{ kind: "phone", value: "synthetic-test-number" }],
  onboardingTermsText: "Read the canonical records and confirm personally.",
  invitationHandoffMethod: "in-person QR"
};

describe("SR002/SR005/SR102 untouched first invitation renewal", () => {
  it("renews an expired untouched first invitation without initializing or activating another identity", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const operator = new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator",
        expectedCanonicalResourceUri: setup.canonicalResourceUri
      });
      const first = await operator.initialize(setup);
      if (first.status !== "created") throw new Error("expected new bootstrap fixture");
      await pool.query(
        "update enrollment_invitations set issued_at=issued_at-interval '2 days',expires_at=expires_at-interval '2 days' where id=$1",
        [first.invitationId]
      );
      const request = {
        instanceId: first.instanceId,
        organizationId: first.organizationId,
        memberId: first.firstMemberId,
        previousInvitationId: first.invitationId,
        canonicalResourceUri: setup.canonicalResourceUri,
        handoffMethod: "in-person replacement QR",
        reason: "The first invitation expired before registration"
      };
      const renewable = operator;
      const renewed = await renewable.renewFirstInvitation(request);
      expect(renewed.status).toBe("renewed");
      expect(renewed.invitationId).not.toBe(first.invitationId);
      expect(new URL(renewed.enrollmentUrl).hash).toHaveLength(44);
      expect(
        (await pool.query("select state,count(*)::int as count from members group by state")).rows
      ).toEqual([{ state: "invited", count: 1 }]);
      expect(
        (await pool.query("select count(*)::int as count from webauthn_credentials")).rows[0]?.count
      ).toBe(0);
      expect(
        (
          await pool.query(
            "select revoked_at is not null as revoked from enrollment_invitations where id=$1",
            [first.invitationId]
          )
        ).rows[0]?.revoked
      ).toBe(true);
      await expect(renewable.renewFirstInvitation(request)).rejects.toThrow();
      expect(
        (await pool.query("select count(*)::int as count from enrollment_invitations")).rows[0]
          ?.count
      ).toBe(2);
    });
  });
});

async function fixture(pool: import("pg").Pool, expire = true) {
  const operator = new BoardAgentBootstrapOperator(pool, {
    assumeRole: "boardagent_migrator",
    expectedCanonicalResourceUri: setup.canonicalResourceUri
  });
  const first = await operator.initialize(setup);
  if (first.status !== "created") throw new Error("expected new bootstrap fixture");
  if (expire)
    await pool.query(
      "update enrollment_invitations set issued_at=issued_at-interval '2 days',expires_at=expires_at-interval '2 days' where id=$1",
      [first.invitationId]
    );
  return {
    operator,
    first,
    request: {
      instanceId: first.instanceId,
      organizationId: first.organizationId,
      memberId: first.firstMemberId,
      previousInvitationId: first.invitationId,
      canonicalResourceUri: setup.canonicalResourceUri,
      handoffMethod: "in-person replacement QR",
      reason: "First invitation expired before registration"
    }
  };
}

async function retained(pool: import("pg").Pool) {
  return (
    await pool.query(`select
    (select jsonb_agg(to_jsonb(i) order by i.id) from enrollment_invitations i) as invitations,
    (select jsonb_agg(to_jsonb(a) order by a.sequence) from audit_events a) as audit,
    (select jsonb_agg(to_jsonb(m) order by m.id) from members m) as members`)
  ).rows;
}

describe("first invitation renewal boundaries", () => {
  it("rejects mismatched instances, targets, resources and ambiguous input without changing retained data", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { operator, request } = await fixture(pool);
      const before = await retained(pool);
      const wrong = "00000000-0000-7000-8000-000000123456";
      for (const key of ["instanceId", "organizationId", "memberId", "previousInvitationId"])
        await expect(operator.renewFirstInvitation({ ...request, [key]: wrong })).rejects.toThrow();
      for (const change of [
        { canonicalResourceUri: "https://elsewhere.boardagent.test/mcp" },
        { canonicalResourceUri: "http://renewal.boardagent.test/mcp" },
        { reason: "" },
        { reason: "x".repeat(4097) },
        { handoffMethod: "" },
        { activate: true }
      ])
        await expect(operator.renewFirstInvitation({ ...request, ...change })).rejects.toThrow();
      // Even without an injected configuration guard, the database instance binding applies.
      const unbound = new BoardAgentBootstrapOperator(pool, { assumeRole: "boardagent_migrator" });
      await expect(
        unbound.renewFirstInvitation({
          ...request,
          canonicalResourceUri: "https://elsewhere.boardagent.test/mcp"
        })
      ).rejects.toThrow();
      expect(await retained(pool)).toEqual(before);
    });
  });

  it.each([
    "live",
    "consumed",
    "revoked",
    "credential",
    "activation",
    "changed_member",
    "another_member"
  ])("refuses the %s state and leaves all existing evidence intact", async (state) => {
    await withAdministrativeDatabase(async (pool) => {
      const { operator, first, request } = await fixture(pool, state !== "live");
      if (state === "consumed" || state === "revoked")
        await pool.query(
          `update enrollment_invitations set ${state === "consumed" ? "consumed_at" : "revoked_at"}=transaction_timestamp() where id=$1`,
          [first.invitationId]
        );
      if (state === "credential")
        await pool.query(
          `insert into webauthn_credentials(id,organization_id,member_id,credential_id,public_key,signature_counter,transports,backup_eligible,backup_state,state)
            values('00000000-0000-7000-8000-000000123457',$1,$2,$3,$4,0,array['internal'],false,false,'revoked')`,
          [first.organizationId, first.firstMemberId, Buffer.alloc(32, 49), Buffer.alloc(32, 50)]
        );
      if (state === "activation")
        await pool.query(
          `insert into enrollment_activation_challenges(id,organization_id,member_id,invitation_id,protected_code,proofing_method,state,expires_at)
            values('00000000-0000-7000-8000-000000123458',$1,$2,$3,$4,'in_person','expired',transaction_timestamp())`,
          [first.organizationId, first.firstMemberId, first.invitationId, Buffer.alloc(32, 51)]
        );
      if (state === "changed_member")
        await pool.query(
          "update members set state='enrollment_pending',row_version=row_version+1 where id=$1",
          [first.firstMemberId]
        );
      if (state === "another_member")
        await pool.query(
          `insert into members(id,organization_id,member_kind,legal_name,display_name)
            values('00000000-0000-7000-8000-000000123459',$1,'human','Second Person','Second Person')`,
          [first.organizationId]
        );
      const before = await retained(pool);
      await expect(operator.renewFirstInvitation(request)).rejects.toThrow("cannot be renewed");
      expect(await retained(pool)).toEqual(before);
    });
  });

  it("allows exactly one simultaneous renewal and retains the original audit chain and one live successor", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { operator, first, request } = await fixture(pool);
      const originalAudit = (await pool.query("select * from audit_events order by sequence")).rows;
      const outcomes = await Promise.allSettled([
        operator.renewFirstInvitation(request),
        operator.renewFirstInvitation(request)
      ]);
      expect(outcomes.filter((x) => x.status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter((x) => x.status === "rejected")).toHaveLength(1);
      const success = outcomes.find((x) => x.status === "fulfilled");
      if (success?.status !== "fulfilled") throw new Error("renewal did not succeed");
      const rows = (await pool.query("select * from audit_events order by sequence")).rows;
      expect(rows).toHaveLength(3);
      expect(rows[0]).toEqual(originalAudit[0]);
      expect(rows.slice(1).map((x) => x.event_type)).toEqual([
        "enrollment_revoked",
        "enrollment_issued"
      ]);
      const payloads = rows
        .slice(1)
        .map((x) => JSON.parse((x.canonical_payload as Buffer).toString("utf8")));
      for (const payload of payloads)
        expect(payload.details).toMatchObject({
          renewal: true,
          bootstrap: true,
          previousInvitationId: first.invitationId,
          newInvitationId: success.value.invitationId,
          reason: request.reason
        });
      expect(JSON.stringify(rows)).not.toContain(
        new URL(success.value.enrollmentUrl).hash.slice(1)
      );
      expect(
        (
          await pool.query(`select count(*)::int as n from enrollment_invitations
        where consumed_at is null and revoked_at is null and expires_at>transaction_timestamp()`)
        ).rows
      ).toEqual([{ n: 1 }]);
      expect(await operator.initialize(setup)).toEqual({
        status: "already_initialized",
        secretOnce: true
      });
      // If another day passes without registration, the exact latest successor can be renewed.
      await pool.query(
        "update enrollment_invitations set issued_at=issued_at-interval '2 days',expires_at=expires_at-interval '2 days' where id=$1",
        [success.value.invitationId]
      );
      const later = await operator.renewFirstInvitation({
        ...request,
        previousInvitationId: success.value.invitationId
      });
      expect(later.invitationId).not.toBe(success.value.invitationId);
      expect((await pool.query("select count(*)::int as n from members")).rows).toEqual([{ n: 1 }]);
    });
  });

  it("refuses server and worker roles even with a claimed bootstrap scope", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { request } = await fixture(pool);
      const { renewBootstrapInvitationInTransaction } =
        await import("../../lib/db/src/transactions/bootstrap.js");
      const before = await retained(pool);
      for (const role of ["boardagent_server", "boardagent_worker"] as const) {
        const client = await pool.connect();
        try {
          await client.query("begin isolation level serializable");
          await client.query(`set local role ${role}`);
          await client.query("select set_config('boardagent.transaction_scope','bootstrap',true)");
          await expect(
            renewBootstrapInvitationInTransaction(client, {
              ...request,
              invitationId: "00000000-0000-7000-8000-000000123460",
              invitationTokenSha256: "a".repeat(64),
              revokedAuditEventId: "00000000-0000-7000-8000-000000123461",
              issuedAuditEventId: "00000000-0000-7000-8000-000000123462"
            })
          ).rejects.toThrow("managed serializable migrator transaction");
        } finally {
          await client.query("rollback");
          client.release();
        }
      }
      expect(await retained(pool)).toEqual(before);
    });
  });
});
