import { describe, expect, it } from "vitest";
import type { Pool } from "pg";
import {
  PgBoardAgentSurfaceService,
  PgSurfaceReadRepository,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { type JsonValue, sha256Hex } from "../../lib/contracts/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { appendAuditEventsInTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import { confirmSyntheticSurfaceAction } from "../helpers/confirmed-surface-action.js";

type Actor = Awaited<ReturnType<typeof administrativeActors>>["issuer"];
function components(pool: Pool, actor: Actor, admin: boolean) {
  const principal: SurfacePrincipal = {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    clientId: actor.clientId,
    protocolClientId: "authorized-test-client",
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    serviceOrigin: "https://boardagent.test",
    roles: admin ? ["admin", "member", "secretariat"] : ["member", "secretariat"],
    scopes: ["secretariat:admin", "governance:read"],
    boardIds: [actor.boardId]
  };
  const service = new PgBoardAgentSurfaceService(pool, {
    reads: new PgSurfaceReadRepository(pool, {
      cursorKey: Buffer.alloc(32, 9),
      transaction: { assumeRole: "boardagent_server" }
    }),
    transaction: { assumeRole: "boardagent_server" }
  });
  return { principal, service };
}
function support(actor: Actor): JsonValue {
  return {
    schema_version: "boardagent.tool-input.v1",
    board_id: actor.boardId,
    version_id: testId(95_001),
    expected_version_id: actor.supportVersionId,
    support_name: "Company secretary office",
    contact_methods: [{ kind: "phone", value: "+971555010000" }],
    reason: "Publish the new secretary contact number",
    idempotency_key: "publish-support-test-0001"
  };
}
function terms(_actor: Actor): JsonValue {
  return {
    schema_version: "boardagent.tool-input.v1",
    seat_role: "voting_member",
    version_id: testId(95_002),
    expected_version_id: testId(6),
    canonical_text:
      "Read original board records before personally confirming a decision. Contact the secretary for help.",
    reason: "Clarify directors' review responsibilities",
    idempotency_key: "publish-terms-test-0001"
  };
}

describe("SR033/SR034 supported onboarding publication", () => {
  it("lets the board secretary publish immutable support with actual confirmed authority", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer } = await administrativeActors(pool, false);
      const { service, principal } = components(pool, issuer, false);
      const before = (
        await pool.query("select to_jsonb(v) value from secretary_support_versions v order by id")
      ).rows;
      const attestations = (
        await pool.query("select to_jsonb(a) value from onboarding_attestations a order by id")
      ).rows;
      await confirmSyntheticSurfaceAction(
        service,
        principal,
        "publish_secretary_support",
        support(issuer)
      );
      expect(
        (
          await pool.query(
            "select version,support_name,created_by from secretary_support_versions where id=$1",
            [testId(95_001)]
          )
        ).rows
      ).toEqual([
        { version: 2, support_name: "Company secretary office", created_by: issuer.memberId }
      ]);
      expect(
        (
          await pool.query(
            "select to_jsonb(v) value from secretary_support_versions v where id<>$1 order by id",
            [testId(95_001)]
          )
        ).rows
      ).toEqual(before);
      expect(
        (await pool.query("select to_jsonb(a) value from onboarding_attestations a order by id"))
          .rows
      ).toEqual(attestations);
      expect(
        (
          await pool.query(
            "select event_type from audit_events where event_type='secretary_support_published'"
          )
        ).rowCount
      ).toBe(1);
    });
  });
  it("lets only the company administrator publish role terms without manufacturing acceptance", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const { service, principal } = components(pool, issuer, true);
      const other = components(pool, target, false);
      await expect(
        service.prepareHumanAction(other.principal, "publish_onboarding_terms", terms(issuer))
      ).rejects.toThrow();
      const before = (
        await pool.query("select to_jsonb(t) value from onboarding_terms_versions t order by id")
      ).rows;
      const attestations = (
        await pool.query("select to_jsonb(a) value from onboarding_attestations a order by id")
      ).rows;
      await confirmSyntheticSurfaceAction(
        service,
        principal,
        "publish_onboarding_terms",
        terms(issuer)
      );
      expect(
        (
          await pool.query(
            "select version,encode(canonical_sha256,'hex') hash,material_change from onboarding_terms_versions where id=$1",
            [testId(95_002)]
          )
        ).rows
      ).toEqual([
        {
          version: 2,
          hash: sha256Hex((terms(issuer) as { canonical_text: string }).canonical_text),
          material_change: true
        }
      ]);
      expect(
        (
          await pool.query(
            "select to_jsonb(t) value from onboarding_terms_versions t where id<>$1 order by id",
            [testId(95_002)]
          )
        ).rows
      ).toEqual(before);
      expect(
        (await pool.query("select to_jsonb(a) value from onboarding_attestations a order by id"))
          .rows
      ).toEqual(attestations);
      expect(
        (
          await pool.query(
            "select event_type from audit_events where event_type='onboarding_terms_published'"
          )
        ).rowCount
      ).toBe(1);
    });
  });
});

async function preparedPublication(pool: Pool, actor: Actor, tool: string, input: JsonValue) {
  const { service, principal } = components(pool, actor, true);
  const prepared = await service.prepareHumanAction(principal, tool, input);
  const capabilities = { elicitation: { form: {} } };
  const requestState = `publication-exact-protected-state-${prepared.stage_id}`;
  await service.persistHumanStage({
    principal,
    tool,
    input,
    prepared,
    client_capabilities: capabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: "Confirm exact version" },
    request_state: requestState,
    prepared_request_id: Buffer.from("publication-prepare")
  });
  return {
    prepared,
    confirm: () =>
      service.resolveHumanAction({
        principal,
        tool,
        input,
        stage_id: prepared.stage_id,
        client_capabilities: capabilities,
        request_state: requestState,
        retry_request_id: Buffer.from("publication-retry"),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: prepared.confirmation_code }
      })
  };
}
describe("publication authority cannot be replaced by runtime SQL or stale approval", () => {
  it("exposes no direct publication writes and refuses unrelated consent", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer } = await administrativeActors(pool);
      for (const table of ["secretary_support_versions", "onboarding_terms_versions"])
        expect(
          (
            await pool.query(
              "select has_table_privilege('boardagent_server',$1,'INSERT') ins,has_table_privilege('boardagent_server',$1,'UPDATE') upd,has_table_privilege('boardagent_worker',$1,'INSERT') worker",
              [table]
            )
          ).rows[0]
        ).toEqual({ ins: false, upd: false, worker: false });
      await expect(
        withRequestTransaction(
          pool,
          issuer.context,
          (c) =>
            c.query("select boardagent_apply_onboarding_publication($1,$2)", [
              issuer.consentRecordId,
              testId(99_009)
            ]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/confirmed authority/u);
    });
  });
  it.each(["scope", "nonsecretary", "recused", "inactive", "wrongboard", "nullboard", "observer"])(
    "refuses support publication for %s",
    async (denial) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer, target } = await administrativeActors(pool, false);
        let input = support(issuer) as Record<string, JsonValue>;
        if (denial === "recused") {
          // A different genuine current secretary records the exclusion before the tested request.
          await pool.query(
            "update board_memberships set is_secretary=true,entitlement_generation=entitlement_generation+1 where member_id=$1",
            [target.memberId]
          );
          const other = components(pool, target, false);
          await confirmSyntheticSurfaceAction(other.service, other.principal, "manage_recusal", {
            schema_version: "boardagent.tool-input.v1",
            board_id: issuer.boardId,
            object_type: "board",
            object_id: issuer.boardId,
            member_id: issuer.memberId,
            operation: "add",
            reason: "Declared conflict for this board",
            idempotency_key: "support-recusal-boundary-test"
          });
        }
        if (denial === "scope")
          await pool.query(
            "update access_token_records set scope_set=array['governance:read'] where id=$1",
            [issuer.accessTokenRecordId]
          );
        if (denial === "nonsecretary")
          await pool.query(
            "update board_memberships set is_secretary=false,entitlement_generation=entitlement_generation+1 where member_id=$1",
            [issuer.memberId]
          );
        if (denial === "inactive")
          await pool.query(
            "update members set state='suspended',row_version=row_version+1 where id=$1",
            [issuer.memberId]
          );
        if (denial === "observer")
          await pool.query(
            "update board_memberships set seat_role='observer',is_secretary=false,voting_weight=0,entitlement_generation=entitlement_generation+1 where member_id=$1",
            [issuer.memberId]
          );
        if (denial === "wrongboard") input = { ...input, board_id: testId(98_001) };
        if (denial === "nullboard") input = { ...input, board_id: null };
        const { service, principal } = components(pool, issuer, false);
        await expect(
          service.prepareHumanAction(principal, "publish_secretary_support", input)
        ).rejects.toThrow();
        expect(
          (
            await pool.query(
              "select count(*)::int n from secretary_support_versions where publication_consent_record_id is not null"
            )
          ).rows[0]
        ).toEqual({ n: 0 });
      });
    }
  );
  it("binds the server-discovered current terms version and refuses an obsolete prepared request", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer } = await administrativeActors(pool);
      // Seatless admin keeps company terms power, with no board read grant added.
      await pool.query(
        "update board_memberships set state='ended',active_until=transaction_timestamp(),entitlement_generation=entitlement_generation+1 where member_id=$1",
        [issuer.memberId]
      );
      const input = { ...(terms(issuer) as Record<string, JsonValue>) };
      delete input["expected_version_id"];
      const old = await preparedPublication(pool, issuer, "publish_onboarding_terms", input);
      const { service, principal } = components(pool, issuer, true);
      await confirmSyntheticSurfaceAction(
        service,
        { ...principal, boardIds: [] },
        "publish_onboarding_terms",
        { ...input, version_id: testId(95_003), idempotency_key: "newer-terms-publication-test" }
      );
      // Failure may be an explicit rejected resolution or an unavailable snapshot; neither commits the old text.
      let accepted = false;
      try {
        accepted = (await old.confirm()).confirmed;
      } catch {
        /* expected refusal */
      }
      expect(accepted).toBe(false);
      expect(
        (
          await pool.query(
            "select id from onboarding_terms_versions where publication_consent_record_id is not null"
          )
        ).rows
      ).toEqual([{ id: testId(95_003) }]);
      await expect(
        service.prepareHumanAction(
          { ...principal, boardIds: [] },
          "publish_secretary_support",
          support(issuer)
        )
      ).rejects.toThrow();
    });
  });
});

describe("new board can receive its initial support information before people enroll", () => {
  it("lets the company administrator initialize a new board without gaining secretary update powers", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer } = await administrativeActors(pool);
      const { service, principal } = components(pool, issuer, true);
      const boardId = testId(95_500);
      await confirmSyntheticSurfaceAction(service, principal, "create_board", {
        schema_version: "boardagent.tool-input.v1",
        idempotency_key: "publication-new-board-create",
        board_id: boardId,
        slug: "new-committee",
        name: "New Committee",
        timezone: "UTC",
        initial_settings: { schema_version: "boardagent.board-settings.v1", values: {} },
        secretary_member_id: issuer.memberId
      });
      expect(
        (await pool.query("select id from secretary_support_versions where board_id=$1", [boardId]))
          .rowCount
      ).toBe(0);
      expect(
        (await pool.query("select id from board_memberships where board_id=$1", [boardId])).rowCount
      ).toBe(0);
      const input = {
        ...(support(issuer) as Record<string, JsonValue>),
        board_id: boardId,
        expected_version_id: null
      };
      await confirmSyntheticSurfaceAction(service, principal, "publish_secretary_support", input);
      expect(
        (
          await pool.query("select version from secretary_support_versions where board_id=$1", [
            boardId
          ])
        ).rows
      ).toEqual([{ version: 1 }]);
      expect(
        (await pool.query("select id from board_memberships where board_id=$1", [boardId])).rowCount
      ).toBe(0);
      await expect(
        service.prepareHumanAction(principal, "publish_secretary_support", {
          ...input,
          version_id: testId(95_501),
          expected_version_id: testId(95_001)
        })
      ).rejects.toThrow();
    });
  });
});

describe("publication audit claims require a corresponding committed version", () => {
  it.each(["support", "terms"] as const)(
    "rejects a well-formed duplicate %s publication audit using runtime authority",
    async (kind) => {
      await withAdministrativeDatabase(async (pool) => {
        const { issuer } = await administrativeActors(pool);
        const { service, principal } = components(pool, issuer, true);
        await confirmSyntheticSurfaceAction(
          service,
          principal,
          kind === "support" ? "publish_secretary_support" : "publish_onboarding_terms",
          kind === "support" ? support(issuer) : terms(issuer)
        );
        const event = (
          await pool.query(
            "select consent_record_id,convert_from(canonical_payload,'UTF8')::jsonb body from audit_events where event_type=$1",
            [kind === "support" ? "secretary_support_published" : "onboarding_terms_published"]
          )
        ).rows[0];
        const forgedEventId = testId(99_501);
        await expect(
          withRequestTransaction(
            pool,
            issuer.context,
            (c) =>
              appendAuditEventsInTransaction(c, [
                {
                  organizationId: issuer.organizationId,
                  consentRecordId: event.consent_record_id,
                  objectVersion: 2n,
                  event: {
                    eventId: forgedEventId,
                    eventType:
                      kind === "support"
                        ? "secretary_support_published"
                        : "onboarding_terms_published",
                    actorMemberId: issuer.memberId,
                    actorClientId: issuer.clientId,
                    tokenJti: issuer.tokenJti,
                    boardId: kind === "support" ? issuer.boardId : null,
                    entityType:
                      kind === "support" ? "secretary_support_version" : "onboarding_terms_version",
                    entityId: testId(kind === "support" ? 95_001 : 95_002),
                    origin: "mcp",
                    schemaVersion: 1,
                    details: event.body.details
                  }
                }
              ]),
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toThrow(/publication audit.*matching/u);
        expect(
          (await pool.query("select id from audit_events where id=$1", [forgedEventId])).rowCount
        ).toBe(0);
      });
    }
  );
});
