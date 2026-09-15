import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import {
  TOOL_INPUT_SCHEMA_VERSION,
  canonicalJson,
  canonicalSha256,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { appendAuditEventsInTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeService,
  freshAdministrativeTestCredential
} from "../helpers/administrative-service.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

function principal(person: AuthorizedActorFixture): SurfacePrincipal {
  return {
    ...person.context,
    protocolClientId: "authorized-test-client",
    accessTokenRecordId: person.accessTokenRecordId,
    keyId: "test-oauth",
    serviceOrigin: "https://boardagent.test",
    roles: ["admin", "member", "secretariat"],
    scopes: ["secretariat:admin"]
  };
}
async function fixture(pool: Pool) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    isSecretary: true,
    scopes: ["secretariat:admin"]
  });
  await pool.query(
    "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Lifecycle security fixture')",
    [testId(192000), actor.organizationId, actor.memberId]
  );
  const target = await seedAdditionalAuthorizedActor(pool, actor, {
    idBase: 192100,
    seatRole: "voting_member",
    scopes: ["secretariat:admin"]
  });
  for (const [index, person] of [actor, target].entries()) {
    await pool.query(
      "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())",
      [
        testId(192300 + index),
        person.organizationId,
        Buffer.alloc(32, 120 + index),
        person.memberId,
        person.clientId
      ]
    );
    await pool.query("update access_token_records set session_id=$1 where id=$2", [
      testId(192300 + index),
      person.accessTokenRecordId
    ]);
  }
  const reads = new PgSurfaceReadRepository(pool, {
    cursorKey: Buffer.alloc(32, 7),
    transaction: { assumeRole: "boardagent_server" }
  });
  const service = new PgBoardAgentSurfaceService(pool, {
    reads,
    transaction: { assumeRole: "boardagent_server" }
  });
  return { actor, target, service, principal: principal(actor) };
}
let sequence = 0;
function request(
  target: AuthorizedActorFixture,
  operation: string,
  boardId: string | null = target.boardId,
  extra: Record<string, JsonValue> = {}
): JsonValue {
  sequence++;
  return {
    schema_version: TOOL_INPUT_SCHEMA_VERSION,
    change: {
      operation,
      member_id: target.memberId,
      board_id: boardId,
      reason: "Synthetic member authority security test",
      ...extra
    },
    idempotency_key: `lifecycle-security-${sequence.toString().padStart(8, "0")}`
  };
}
async function stage(
  service: PgBoardAgentSurfaceService,
  actor: SurfacePrincipal,
  input: JsonValue
) {
  const prepared = await service.prepareHumanAction(actor, "manage_member", input);
  const capabilities = { elicitation: { form: {} } };
  const state = `member-lifecycle-security-state-${prepared.stage_id}`;
  await service.persistHumanStage({
    principal: actor,
    tool: "manage_member",
    input,
    prepared,
    client_capabilities: capabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: "Confirm exact authority change" },
    request_state: state,
    prepared_request_id: Buffer.from(`prepare-${prepared.stage_id}`)
  });
  return {
    prepared,
    resolve: (code = prepared.confirmation_code, response: "accept" | "cancel" = "accept") =>
      service.resolveHumanAction({
        principal: actor,
        tool: "manage_member",
        input,
        stage_id: prepared.stage_id,
        client_capabilities: capabilities,
        request_state: state,
        retry_request_id: Buffer.from(`retry-${prepared.stage_id}`),
        response_action: response,
        input_response: response === "cancel" ? null : { approve: true, confirmation_code: code }
      })
  };
}
async function confirm(f: Awaited<ReturnType<typeof fixture>>, input: JsonValue) {
  const staged = await stage(f.service, f.principal, input);
  expect((await staged.resolve()).confirmed).toBe(true);
}
async function state(pool: Pool, member: string) {
  return (await pool.query("select state,row_version::text from members where id=$1", [member]))
    .rows[0];
}
async function resolvedToken(pool: Pool, person: AuthorizedActorFixture) {
  return withRequestTransaction(
    pool,
    person.context,
    async (client) =>
      (await client.query("select * from boardagent_resolve_access_token($1)", [person.tokenJti]))
        .rows,
    { assumeRole: "boardagent_server" }
  );
}

describe("member lifecycle security and historical authority", () => {
  it("atomically tombstones pending duties and retains removal snapshots through reactivation", async () => {
    await withMigratedDatabase("member_feed_removal", async (pool) => {
      const f = await fixture(pool);
      const auditId = testId(192700),
        feedId = testId(192701),
        taskId = testId(192702);
      await withRequestTransaction(
        pool,
        f.actor.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: f.actor.organizationId,
              objectVersion: 1n,
              event: {
                eventId: auditId,
                eventType: "notice_delivered",
                actorMemberId: f.actor.memberId,
                actorClientId: f.actor.clientId,
                tokenJti: f.actor.tokenJti,
                entityType: "task",
                entityId: taskId,
                boardId: f.actor.boardId,
                origin: "mcp",
                details: { meaning: "committed_recipient_feed_handoff" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      const payload = {
        schemaVersion: "boardagent.pending-action.v1",
        sequence: "1",
        deltaType: "task_due",
        objectType: "task",
        objectId: taskId,
        objectVersion: 1,
        entitlementGeneration: 1,
        actionState: "pending",
        safeRefs: { taskSha256: "91".repeat(32) },
        createdAt: "2026-09-04T12:00:00.000Z"
      };
      await pool.query(
        "insert into pending_action_feed(id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,action_type,object_type,object_id,object_version,visibility_sha256,canonical_payload,payload_sha256,audit_event_id) values($1,$2,$3,$4,1,1,'task_due','task',$5,1,$6,$7,$8,$9)",
        [
          feedId,
          f.target.organizationId,
          f.target.boardId,
          f.target.memberId,
          taskId,
          Buffer.alloc(32, 3),
          Buffer.from(canonicalJson(payload)),
          Buffer.from(canonicalSha256(payload), "hex"),
          auditId
        ]
      );
      await confirm(f, request(f.target, "remove", null));
      expect(
        (await pool.query("select state from pending_action_feed where id=$1", [feedId])).rows[0]
      ).toEqual({ state: "superseded" });
      const tomb = (
        await pool.query("select * from feed_tombstones where removed_feed_id=$1", [feedId])
      ).rows[0];
      expect(tomb.reason_class).toBe("revoked");
      expect(tomb.audit_event_id).toBe(auditId);
      expect(tomb.tombstone_sha256.toString("hex")).toBe(
        canonicalSha256({
          schemaVersion: "boardagent.feed-tombstone.v1",
          source: "member_lifecycle",
          boardId: f.target.boardId,
          memberId: f.target.memberId,
          removedFeedId: feedId,
          objectType: "task",
          objectId: taskId,
          priorEntitlementGeneration: "1",
          entitlementGeneration: "2",
          feedSequence: "1",
          reasonClass: "revoked"
        })
      );
      const retained = await pool.query(
        "select canonical_payload,canonical_sha256 from retention_snapshots where object_type='member' and object_id=$1",
        [f.target.memberId]
      );
      expect(retained.rows).toHaveLength(1);
      expect(retained.rows[0].canonical_sha256.toString("hex")).toBe(
        canonicalSha256(JSON.parse(retained.rows[0].canonical_payload.toString("utf8")))
      );
      const tombstone = (
        await pool.query(
          "select * from deletion_tombstones where object_type='member' and object_id=$1",
          [f.target.memberId]
        )
      ).rows[0];
      expect(tombstone).toBeDefined();
      await expect(
        pool.query("update members set state='active',row_version=row_version+1 where id=$1", [
          f.target.memberId
        ])
      ).rejects.toThrow(/illegal members state transition/u);
      await confirm(f, request(f.target, "reactivate", null));
      await confirm(f, request(f.target, "reactivate"));
      expect(
        (await pool.query("select * from deletion_tombstones where id=$1", [tombstone.id])).rows[0]
      ).toEqual(tombstone);
      expect(
        (
          await pool.query(
            "select count(*)::integer as n from pending_action_feed where member_id=$1 and state='pending'",
            [f.target.memberId]
          )
        ).rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it("changes only the selected board seat and rejects promotion of an AI observer", async () => {
    await withMigratedDatabase("member_board_separation", async (pool) => {
      const f = await fixture(pool);
      const otherBoard = testId(192800),
        otherSeat = testId(192801);
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'other','Other board','UTC')",
        [otherBoard, f.target.organizationId]
      );
      await pool.query(
        "insert into board_memberships(id,organization_id,board_id,member_id,seat_role,voting_weight,state) values($1,$2,$3,$4,'voting_member',4,'active')",
        [otherSeat, f.target.organizationId, otherBoard, f.target.memberId]
      );
      await confirm(f, request(f.target, "suspend"));
      expect(
        (
          await pool.query(
            "select state,entitlement_generation::text,voting_weight::text from board_memberships where id=$1",
            [otherSeat]
          )
        ).rows[0]
      ).toEqual({ state: "active", entitlement_generation: "1", voting_weight: "4" });
      await pool.query(
        "insert into accountable_principals(id,organization_id,legal_name) values($1,$2,'Synthetic accountable human')",
        [testId(192802), f.target.organizationId]
      );
      await pool.query(
        "update members set member_kind='ai_system',accountable_principal_id=$1,row_version=row_version+1 where id=$2",
        [testId(192802), f.target.memberId]
      );
      await pool.query(
        "update board_memberships set seat_role='observer',voting_weight=0 where member_id=$1",
        [f.target.memberId]
      );
      await expect(
        f.service.prepareHumanAction(
          f.principal,
          "manage_member",
          request(f.target, "change_seat", otherBoard, {
            seat_role: "voting_member",
            voting_weight: 1,
            is_secretary: false
          })
        )
      ).rejects.toThrow(/AI members must remain observers/u);
    });
  });

  it.each([
    "scope",
    "role",
    "revoked_token",
    "expired_session",
    "blocked_client",
    "onboarding"
  ] as const)("rejects unavailable administrator authority: %s", async (cause) => {
    await withMigratedDatabase("member_lifecycle_deny", async (pool) => {
      const f = await fixture(pool);
      if (cause === "scope")
        await pool.query(
          "update access_token_records set scope_set=array['governance:read'] where id=$1",
          [f.actor.accessTokenRecordId]
        );
      if (cause === "role")
        await pool.query(
          "update organization_role_assignments set active_until=transaction_timestamp() where member_id=$1",
          [f.actor.memberId]
        );
      if (cause === "revoked_token")
        await pool.query(
          "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
          [f.actor.accessTokenRecordId]
        );
      if (cause === "expired_session")
        await pool.query(
          "update auth_sessions set state='expired',expires_at=transaction_timestamp()-interval '1 second',created_at=transaction_timestamp()-interval '2 hours' where id=$1",
          [testId(192300)]
        );
      if (cause === "blocked_client")
        await pool.query("update oauth_clients set state='suspended' where id=$1", [
          f.actor.clientId
        ]);
      if (cause === "onboarding")
        await pool.query(
          "insert into onboarding_terms_versions(id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,material_change,effective_at,created_by) values($1,$2,'voting_member',2,'boardagent.onboarding-terms.v1','Changed terms',$3,true,transaction_timestamp(),$4)",
          [testId(192400), f.actor.organizationId, Buffer.alloc(32, 199), f.actor.memberId]
        );
      await expect(
        f.service.prepareHumanAction(f.principal, "manage_member", request(f.target, "suspend"))
      ).rejects.toThrow();
      expect(await state(pool, f.target.memberId)).toEqual({ state: "active", row_version: "1" });
    });
  });
  it.each(["wrong_code", "cancel"] as const)(
    "does not mutate membership after %s",
    async (cause) => {
      await withMigratedDatabase("member_lifecycle_code", async (pool) => {
        const f = await fixture(pool);
        const staged = await stage(f.service, f.principal, request(f.target, "suspend"));
        expect(
          (
            await staged.resolve(
              cause === "wrong_code"
                ? staged.prepared.confirmation_code === "AAAAAAAA"
                  ? "BBBBBBBB"
                  : "AAAAAAAA"
                : undefined,
              cause === "cancel" ? "cancel" : "accept"
            )
          ).confirmed
        ).toBe(false);
        expect(await state(pool, f.target.memberId)).toEqual({ state: "active", row_version: "1" });
        expect(
          (
            await pool.query(
              "select count(*)::integer as n from audit_events where event_type='member_changed'"
            )
          ).rows[0]
        ).toEqual({ n: 0 });
      });
    }
  );
  it("rejects a changed canonical seat between presentation and confirmation", async () => {
    await withMigratedDatabase("member_lifecycle_stale", async (pool) => {
      const f = await fixture(pool);
      const staged = await stage(f.service, f.principal, request(f.target, "suspend"));
      await pool.query(
        "update board_memberships set voting_weight=9,entitlement_generation=2 where member_id=$1",
        [f.target.memberId]
      );
      expect(await staged.resolve()).toMatchObject({ confirmed: false, reason: "canonical_stale" });
      expect(await state(pool, f.target.memberId)).toEqual({ state: "active", row_version: "1" });
    });
  });
  it("invalidates a staged administrator action when that administrator is revoked", async () => {
    await withMigratedDatabase("member_admin_stale", async (pool) => {
      const f = await fixture(pool);
      const staged = await stage(f.service, f.principal, request(f.target, "suspend"));
      await pool.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
        [f.actor.accessTokenRecordId]
      );
      await expect(staged.resolve()).rejects.toThrow();
      expect(await state(pool, f.target.memberId)).toEqual({ state: "active", row_version: "1" });
    });
  });
  it("keeps all old connections revoked after organization suspension and explicit reactivation", async () => {
    await withMigratedDatabase("member_reactivation", async (pool) => {
      const f = await fixture(pool);
      await pool.query(
        "insert into refresh_families(id,organization_id,member_id,client_id,resource_uri,generation,state,idle_expires_at,absolute_expires_at) values($1,$2,$3,$4,'https://boardagent.test/mcp',1,'active',transaction_timestamp()+interval '30 days',transaction_timestamp()+interval '90 days')",
        [testId(192410), f.target.organizationId, f.target.memberId, f.target.clientId]
      );
      await pool.query("update access_token_records set refresh_family_id=$1 where id=$2", [
        testId(192410),
        f.target.accessTokenRecordId
      ]);
      expect(await resolvedToken(pool, f.target)).toHaveLength(1);
      await confirm(f, request(f.target, "suspend", null));
      expect(await resolvedToken(pool, f.target)).toEqual([]);
      expect(await state(pool, f.target.memberId)).toEqual({
        state: "suspended",
        row_version: "2"
      });
      await confirm(f, request(f.target, "reactivate", null));
      expect(await state(pool, f.target.memberId)).toEqual({ state: "active", row_version: "3" });
      expect(await resolvedToken(pool, f.target)).toEqual([]);
      expect(
        (await pool.query("select state from refresh_families where id=$1", [testId(192410)]))
          .rows[0]
      ).toEqual({ state: "revoked" });
      const versions = await pool.query(
        "select version,authority_snapshot,snapshot_sha256 from membership_versions where member_id=$1 order by version",
        [f.target.memberId]
      );
      expect(versions.rows).toHaveLength(2);
      for (const row of versions.rows)
        expect(row.snapshot_sha256.toString("hex")).toBe(canonicalSha256(row.authority_snapshot));
    });
  });
  it("keeps removed board seats ended after reactivating the person until a separate board confirmation", async () => {
    await withMigratedDatabase("member_removed", async (pool) => {
      const f = await fixture(pool);
      await confirm(f, request(f.target, "remove", null));
      expect(
        (
          await pool.query("select hidden_at is not null as hidden from members where id=$1", [
            f.target.memberId
          ])
        ).rows[0]
      ).toEqual({ hidden: true });
      await confirm(f, request(f.target, "reactivate", null));
      expect(
        (
          await pool.query("select state from board_memberships where member_id=$1", [
            f.target.memberId
          ])
        ).rows[0]
      ).toEqual({ state: "ended" });
      await confirm(f, request(f.target, "reactivate"));
      expect(
        (
          await pool.query("select state from board_memberships where member_id=$1", [
            f.target.memberId
          ])
        ).rows[0]
      ).toEqual({ state: "active" });
      expect(await resolvedToken(pool, f.target)).toEqual([]);
    });
  });
  it.each(["suspend", "remove", "change_seat"] as const)(
    "protects the final board secretary from %s",
    async (operation) => {
      await withMigratedDatabase("member_final_secretary", async (pool) => {
        const f = await fixture(pool);
        const input = request(
          f.actor,
          operation,
          f.actor.boardId,
          operation === "change_seat"
            ? { seat_role: "voting_member", voting_weight: 1, is_secretary: false }
            : {}
        );
        await expect(
          f.service.prepareHumanAction(f.principal, "manage_member", input)
        ).rejects.toThrow(/final active board secretary/u);
      });
    }
  );
  it("protects the final administrator even when another board secretary exists", async () => {
    await withMigratedDatabase("member_final_admin", async (pool) => {
      const f = await fixture(pool);
      await pool.query("update board_memberships set is_secretary=true where member_id=$1", [
        f.target.memberId
      ]);
      await expect(
        f.service.prepareHumanAction(
          f.principal,
          "manage_member",
          request(f.actor, "suspend", null)
        )
      ).rejects.toThrow(/final active administrator/u);
    });
  });
  it("permits an exact self-demotion with another secretary and revokes the acting connection", async () => {
    await withMigratedDatabase("member_self_demote", async (pool) => {
      const f = await fixture(pool);
      await pool.query("update board_memberships set is_secretary=true where member_id=$1", [
        f.target.memberId
      ]);
      await confirm(
        f,
        request(f.actor, "change_seat", f.actor.boardId, {
          seat_role: "management",
          voting_weight: 0,
          is_secretary: false
        })
      );
      expect(await resolvedToken(pool, f.actor)).toEqual([]);
    });
  });
  it("does not allow forged caller role claims or a board identifier from another organization", async () => {
    await withMigratedDatabase("member_cross_org", async (pool) => {
      const f = await fixture(pool);
      await expect(
        f.service.prepareHumanAction(
          principal(f.target),
          "manage_member",
          request(f.actor, "suspend")
        )
      ).rejects.toThrow();
      const otherOrg = testId(192500),
        otherBoard = testId(192501);
      await pool.query(
        "insert into organizations(id,legal_name,display_name,slug,timezone) values($1,'Other','Other','other','UTC')",
        [otherOrg]
      );
      await pool.query(
        "insert into boards(id,organization_id,slug,name,timezone) values($1,$2,'other','Other','UTC')",
        [otherBoard, otherOrg]
      );
      await expect(
        f.service.prepareHumanAction(
          f.principal,
          "manage_member",
          request(f.target, "suspend", otherBoard)
        )
      ).rejects.toThrow();
      expect(await state(pool, f.target.memberId)).toEqual({ state: "active", row_version: "1" });
    });
  });
  it("prevents racing administrators from disabling both remaining administrators and secretaries", async () => {
    await withMigratedDatabase("member_last_race", async (pool) => {
      const f = await fixture(pool);
      await pool.query("update board_memberships set is_secretary=true where member_id=$1", [
        f.target.memberId
      ]);
      await pool.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Second synthetic administrator')",
        [testId(192510), f.target.organizationId, f.target.memberId]
      );
      const first = await stage(f.service, f.principal, request(f.target, "suspend", null));
      const second = await stage(f.service, principal(f.target), request(f.actor, "suspend", null));
      const results = await Promise.allSettled([first.resolve(), second.resolve()]);
      expect(
        results.filter((value) => value.status === "fulfilled" && value.value.confirmed)
      ).toHaveLength(1);
      expect(
        (await pool.query("select count(*)::integer as n from members where state='active'"))
          .rows[0]
      ).toEqual({ n: 1 });
      expect(
        (
          await pool.query(
            "select count(*)::integer as n from audit_events where event_type='member_changed'"
          )
        ).rows[0]
      ).toEqual({ n: 1 });
    });
  });
  it("does not expose raw lifecycle writes or accept a forged SQL finalization without consent", async () => {
    await withMigratedDatabase("member_raw_denied", async (pool) => {
      const f = await fixture(pool);
      await expect(
        withRequestTransaction(
          pool,
          f.actor.context,
          (client) =>
            client.query(
              "update members set state='suspended',row_version=row_version+1 where id=$1",
              [f.target.memberId]
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        withRequestTransaction(
          pool,
          f.actor.context,
          (client) =>
            client.query(
              "select boardagent_finalize_member_lifecycle($1::jsonb,$2,$3,$4,'[]'::jsonb,$5,$2)",
              [
                request(f.target, "suspend"),
                Buffer.alloc(32, 3),
                testId(192600),
                testId(192601),
                testId(192602)
              ]
            ),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toThrow(/consent/u);
      expect(await state(pool, f.target.memberId)).toEqual({ state: "active", row_version: "1" });
    });
  });
});

function chairChange(target: AuthorizedActorFixture, chair?: boolean, voting = true) {
  return request(target, "change_seat", target.boardId, {
    seat_role: voting ? "voting_member" : "management",
    voting_weight: voting ? 1 : 0,
    is_secretary: false,
    ...(chair === undefined ? {} : { is_chair: chair })
  });
}

async function currentChair(pool: Pool, target: AuthorizedActorFixture) {
  return (
    await pool.query(
      `select m.is_chair as live_chair,v.is_chair as version_chair,
         m.entitlement_generation::text,v.version,
         v.consent_record_id is not null as consent_bound,
         v.audit_event_id is not null as audit_bound
       from board_memberships m left join lateral (
         select * from membership_versions v where v.membership_id=m.id
         order by v.version desc limit 1
       ) v on true where m.board_id=$1 and m.member_id=$2`,
      [target.boardId, target.memberId]
    )
  ).rows[0];
}

describe("MR-MEC-001 supported chair authority", () => {
  it("a confirmed administrator appoints a chair and writes matching immutable authority exactly once", async () => {
    await withMigratedDatabase("chair_appointment", async (pool) => {
      const f = await fixture(pool);
      const input = chairChange(f.target, true);
      const staged = await stage(f.service, f.principal, input);
      expect((await currentChair(pool, f.target)).live_chair).toBe(false);
      expect((await staged.resolve()).confirmed).toBe(true);
      expect(await currentChair(pool, f.target)).toMatchObject({
        live_chair: true,
        version_chair: true,
        consent_bound: true,
        audit_bound: true,
        entitlement_generation: "2"
      });
      // A direct resolved-stage retry reaches the existing no-effect guard. Public
      // tool retries have a separate coordinator seam and are covered by Mining QA.
      await expect(staged.resolve()).rejects.toMatchObject({ code: "23514" });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='member_changed' and object_id=$1",
            [f.target.memberId]
          )
        ).rows
      ).toEqual([{ n: 1 }]);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from membership_versions where member_id=$1 and consent_record_id is not null",
            [f.target.memberId]
          )
        ).rows
      ).toEqual([{ n: 1 }]);
      expect(await resolvedToken(pool, f.target)).toEqual([]);
    });
  });

  it("an omitted chair field preserves a pre-existing chair in the new immutable membership version", async () => {
    await withMigratedDatabase("chair_omitted_version", async (pool) => {
      const f = await fixture(pool);
      // Persisted historical chair is fixture input, not a fabricated demo appointment.
      // This reproduces the distinct pre-existing chair/version loss on old schema152.
      await pool.query("update board_memberships set is_chair=true where member_id=$1", [
        f.target.memberId
      ]);
      await pool.query(
        `insert into membership_versions(id,organization_id,board_id,member_id,membership_id,
           version,seat_role,is_secretary,is_chair,voting_weight,authority_snapshot,snapshot_sha256,
           change_reason,actor_member_id)
         select $2,organization_id,board_id,member_id,id,1,seat_role,is_secretary,is_chair,
           voting_weight,'{"fixture":"pre-existing chair"}'::jsonb,$3,'Historical synthetic fixture',member_id
         from board_memberships where member_id=$1`,
        [
          f.target.memberId,
          testId(192950),
          Buffer.from(canonicalSha256({ fixture: "pre-existing chair" }), "hex")
        ]
      );
      const before = await currentChair(pool, f.target);
      expect(before).toMatchObject({ live_chair: true, version_chair: true });
      await confirm(
        f,
        request(f.target, "change_seat", f.target.boardId, {
          seat_role: "voting_member",
          voting_weight: 2,
          is_secretary: false
        })
      );
      expect(await currentChair(pool, f.target)).toMatchObject({
        live_chair: true,
        version_chair: true,
        version: before.version + 1,
        consent_bound: true,
        audit_bound: true
      });
    });
  });
  it("refuses a chair who is not a voting member and an overlapping time-limited second chair", async () => {
    await withMigratedDatabase("chair_invalid_seats", async (pool) => {
      const f = await fixture(pool);
      await expect(
        stage(f.service, f.principal, chairChange(f.target, true, false))
      ).rejects.toMatchObject({ code: "23514" });
      await pool.query(
        "update board_memberships set active_until=transaction_timestamp()+interval '7 days' where member_id=$1",
        [f.target.memberId]
      );
      await confirm(f, chairChange(f.target, true));
      const second = await seedAdditionalAuthorizedActor(pool, f.actor, {
        idBase: 193000,
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      await expect(stage(f.service, f.principal, chairChange(second, true))).rejects.toMatchObject({
        code: "23514"
      });
      expect(await currentChair(pool, f.target)).toMatchObject({
        live_chair: true,
        version_chair: true
      });
      expect((await currentChair(pool, second)).live_chair).toBe(false);
    });
  });

  it("a competing confirmed appointment invalidates an earlier second-chair stage", async () => {
    await withMigratedDatabase("chair_race", async (pool) => {
      const f = await fixture(pool);
      const second = await seedAdditionalAuthorizedActor(pool, f.actor, {
        idBase: 193000,
        seatRole: "voting_member",
        scopes: ["governance:read"]
      });
      const pending = await stage(f.service, f.principal, chairChange(second, true));
      await confirm(f, chairChange(f.target, true));
      await expect(pending.resolve()).rejects.toMatchObject({ code: "23514" });
      expect((await currentChair(pool, second)).live_chair).toBe(false);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='member_changed' and object_id=$1",
            [second.memberId]
          )
        ).rows
      ).toEqual([{ n: 0 }]);
    });
  });

  it.each(["changed_seat", "revoked_admin"] as const)(
    "rejects a chair confirmation after %s",
    async (loss) => {
      await withMigratedDatabase("chair_stale", async (pool) => {
        const f = await fixture(pool);
        const pending = await stage(f.service, f.principal, chairChange(f.target, true));
        if (loss === "changed_seat") {
          await confirm(
            f,
            request(f.target, "change_seat", f.target.boardId, {
              seat_role: "voting_member",
              voting_weight: 2,
              is_secretary: false
            })
          );
          expect(await pending.resolve()).toMatchObject({
            confirmed: false,
            reason: "stage_not_active"
          });
        } else {
          await pool.query(
            "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
            [f.actor.accessTokenRecordId]
          );
          await expect(pending.resolve()).rejects.toThrow();
        }
        expect((await currentChair(pool, f.target)).live_chair).toBe(false);
      });
    }
  );

  it("explicit removal and omitted-field voter demotion both preserve exact chair history", async () => {
    await withMigratedDatabase("chair_remove", async (pool) => {
      const f = await fixture(pool);
      await confirm(f, chairChange(f.target, true));
      await confirm(f, chairChange(f.target, false));
      await confirm(f, chairChange(f.target, true));
      await confirm(f, chairChange(f.target, undefined, false));
      expect(await currentChair(pool, f.target)).toMatchObject({
        live_chair: false,
        version_chair: false
      });
      expect(
        (
          await pool.query(
            "select is_chair from membership_versions where member_id=$1 order by version",
            [f.target.memberId]
          )
        ).rows
      ).toEqual([{ is_chair: true }, { is_chair: false }, { is_chair: true }, { is_chair: false }]);
    });
  });
});

async function lifecycleCounts(pool: Pool) {
  return (
    await pool.query(`select
    (select count(*)::int from action_stages) as stages,
    (select count(*)::int from consent_records) as consents,
    (select count(*)::int from audit_events) as audit,
    (select count(*)::int from membership_versions) as versions,
    (select count(*)::int from idempotency_records) as idempotency`)
  ).rows;
}

describe("MR-MEC-002 completed member lifecycle public replay seam", () => {
  it.each([
    ["suspend", "board"],
    ["remove", "board"],
    ["reactivate", "board"],
    ["suspend", "organization"],
    ["remove", "organization"],
    ["reactivate", "organization"]
  ] as const)(
    "replays the original %s result for %s scope without reviving or changing the target",
    async (operation, scope) => {
      await withMigratedDatabase("member_replay_operations", async (pool) => {
        const f = await fixture(pool);
        const boardId = scope === "board" ? f.target.boardId : null;
        if (operation === "reactivate") await confirm(f, request(f.target, "suspend", boardId));
        const input = request(f.target, operation, boardId);
        const original = await (await stage(f.service, f.principal, input)).resolve();
        if (!original.confirmed) throw new Error("expected supported lifecycle confirmation");
        const fresh = await freshAdministrativeTestCredential(pool, f.actor, 194000);
        const current = await administrativeService(pool, fresh);
        const before = await lifecycleCounts(pool);
        const targetBefore = await state(pool, f.target.memberId);
        const seatsBefore = (
          await pool.query(
            "select row_to_json(s) as seat from board_memberships s where member_id=$1 order by board_id",
            [f.target.memberId]
          )
        ).rows;
        expect(
          await current.service.replayHumanAction(current.principal, "manage_member", input)
        ).toEqual({ ...original.result, status: "already_applied" });
        expect(await lifecycleCounts(pool)).toEqual(before);
        expect(await state(pool, f.target.memberId)).toEqual(targetBefore);
        expect(
          (
            await pool.query(
              "select row_to_json(s) as seat from board_memberships s where member_id=$1 order by board_id",
              [f.target.memberId]
            )
          ).rows
        ).toEqual(seatsBefore);
      });
    }
  );

  it("returns the exact original result after token rotation and adds no stage, consent, event or version", async () => {
    await withMigratedDatabase("member_replay", async (pool) => {
      const f = await fixture(pool);
      const input = chairChange(f.target, true);
      const original = await (await stage(f.service, f.principal, input)).resolve();
      expect(original.confirmed).toBe(true);
      if (!original.confirmed) throw new Error("expected original supported appointment");
      const fresh = await freshAdministrativeTestCredential(pool, f.actor, 194000);
      const current = await administrativeService(pool, fresh);
      const before = await lifecycleCounts(pool);
      expect(
        await current.service.replayHumanAction(current.principal, "manage_member", input)
      ).toEqual({ ...original.result, status: "already_applied" });
      await expect(
        withRequestTransaction(
          pool,
          fresh.context,
          (client) =>
            client.query("select boardagent_replay_member_lifecycle($1::jsonb,$2,$3,$4)", [
              input,
              Buffer.alloc(32, 1),
              "https://boardagent.test",
              fresh.accessTokenRecordId
            ]),
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "23514" });
      expect(await lifecycleCounts(pool)).toEqual(before);
      for (const change of [
        { ...(input as { change: Record<string, JsonValue> }).change, is_chair: false },
        { ...(input as { change: Record<string, JsonValue> }).change, member_id: f.actor.memberId }
      ])
        await expect(
          current.service.replayHumanAction(current.principal, "manage_member", {
            ...(input as Record<string, JsonValue>),
            change
          })
        ).rejects.toThrow();
      expect(
        await current.service.replayHumanAction(current.principal, "manage_member", {
          ...(input as Record<string, JsonValue>),
          idempotency_key: "different-member-key-0001"
        })
      ).toBeNull();
      expect(await lifecycleCounts(pool)).toEqual(before);
    });
  });

  it("an administrator who retires their board seat can replay their exact uncited completed act after reconnecting", async () => {
    await withMigratedDatabase("member_replay_no_seat", async (pool) => {
      const f = await fixture(pool);
      const input = chairChange(f.target, true);
      const original = await (await stage(f.service, f.principal, input)).resolve();
      if (!original.confirmed) throw new Error("expected original supported appointment");
      await confirm(
        f,
        request(f.target, "change_seat", f.target.boardId, {
          seat_role: "voting_member",
          voting_weight: 1,
          is_secretary: true
        })
      );
      await confirm(f, request(f.actor, "remove", f.actor.boardId));
      const fresh = await freshAdministrativeTestCredential(pool, f.actor, 194000);
      const current = await administrativeService(pool, fresh);
      expect(current.principal.boardIds).toEqual([]);
      const before = await lifecycleCounts(pool);
      expect(
        await current.service.replayHumanAction(current.principal, "manage_member", input)
      ).toEqual({ ...original.result, status: "already_applied" });
      expect(await lifecycleCounts(pool)).toEqual(before);
    });
  });

  it.each([
    "scope",
    "role",
    "revoked_token",
    "expired_session",
    "blocked_client",
    "onboarding",
    "origin",
    "client",
    "token_record",
    "token"
  ] as const)(
    "refuses completed results after current %s authority is lost or mismatched",
    async (cause) => {
      await withMigratedDatabase("member_replay_denial", async (pool) => {
        const f = await fixture(pool);
        const input = chairChange(f.target, true);
        await confirm(f, input);
        let caller = f.principal;
        if (cause === "scope")
          await pool.query(
            "update access_token_records set scope_set=array['governance:read'] where id=$1",
            [f.actor.accessTokenRecordId]
          );
        if (cause === "role")
          await pool.query(
            "update organization_role_assignments set active_until=transaction_timestamp() where member_id=$1",
            [f.actor.memberId]
          );
        if (cause === "revoked_token")
          await pool.query(
            "update access_token_records set revoked_at=transaction_timestamp() where id=$1",
            [f.actor.accessTokenRecordId]
          );
        if (cause === "expired_session")
          await pool.query(
            "update auth_sessions set state='expired',expires_at=transaction_timestamp()-interval '1 second',created_at=transaction_timestamp()-interval '2 hours' where id=$1",
            [testId(192300)]
          );
        if (cause === "blocked_client")
          await pool.query("update oauth_clients set state='suspended' where id=$1", [
            f.actor.clientId
          ]);
        if (cause === "onboarding")
          await pool.query(
            "insert into onboarding_terms_versions(id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,material_change,effective_at,created_by) values($1,$2,'voting_member',2,'boardagent.onboarding-terms.v1','Changed terms',$3,true,transaction_timestamp(),$4)",
            [testId(192400), f.actor.organizationId, Buffer.alloc(32, 199), f.actor.memberId]
          );
        if (cause === "origin") caller = { ...caller, serviceOrigin: "https://wrong-origin.test" };
        if (cause === "client") caller = { ...caller, clientId: f.target.clientId };
        if (cause === "token_record")
          caller = { ...caller, accessTokenRecordId: f.target.accessTokenRecordId };
        if (cause === "token") caller = { ...caller, tokenJti: f.target.tokenJti };
        const before = await lifecycleCounts(pool);
        await expect(f.service.replayHumanAction(caller, "manage_member", input)).rejects.toThrow();
        expect(await lifecycleCounts(pool)).toEqual(before);
      });
    }
  );
});
