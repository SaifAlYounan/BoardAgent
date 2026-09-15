import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { loadAdmittedGovernanceToolProjection } from "../../artifacts/server/src/governance-tool-projection.js";
import { ResponseAllocationManager } from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedGovernanceToolProjectionFixture } from "../helpers/governance-tool-projection-fixture.js";
import { ORIGINAL_RULESET_TOOL_SQL } from "../helpers/governance-tool-original-sql.js";

it("permits scoped governance rule SELECT while denying invalid actor contexts and all writes", async () => {
  await withMigratedDatabase("governance_rule_rls", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: ["governance:read", "secretariat:admin"]
    });
    const seed = await seedGovernanceToolProjectionFixture(pool, actor);
    type Context = typeof actor.context;
    function role<T>(work: (client: PoolClient) => Promise<T>, context: Context = actor.context) {
      return withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
    }
    async function visible(context: Context, request = true) {
      return role(async (client) => {
        expect((await client.query("select current_user")).rows[0].current_user).toBe(
          "boardagent_server"
        );
        if (!request)
          await client.query(
            "select set_config('boardagent.transaction_scope','not-request',true)"
          );
        const rules = await client.query<{ id: string }>(
          `select id from ruleset_rules where ruleset_id=$1
          order by priority desc,specificity desc,id`,
          [seed.rulesetId]
        );
        const matters = await client.query<{ id: string }>(
          "select id from matter_types where ruleset_id=$1",
          [seed.rulesetId]
        );
        return {
          rules: rules.rows.map((row) => row.id),
          matters: matters.rows.map((row) => row.id)
        };
      }, context);
    }
    // Clone only the ordinary supported token storage columns from the scoped
    // fixture. These are synthetic rows, not new public authorization ceremonies.
    async function token(index: number, scopes: readonly string[], expired = false) {
      const id = testId(311000 + index),
        jti = testId(311100 + index);
      const inserted = await pool.query(
        `insert into access_token_records(
        id,organization_id,jti,member_id,client_id,resource_uri,scope_set,signing_key_id,issued_at,expires_at)
        select $1,organization_id,$2,member_id,client_id,resource_uri,$3::text[],signing_key_id,
          transaction_timestamp()-interval '2 minutes',
          transaction_timestamp()+case when $4::boolean then interval '-1 minute' else interval '10 minutes' end
        from access_token_records where id=$5 returning id`,
        [id, jti, [...scopes], expired, actor.accessTokenRecordId]
      );
      expect(inserted.rows).toHaveLength(1);
      return { id, context: { ...actor.context, tokenJti: jti } };
    }
    const validClone = await token(4, ["governance:read"]);
    const missingScope = await token(1, ["meeting:act"]);
    const revoked = await token(2, ["governance:read"]);
    const expired = await token(3, ["governance:read"], true);
    const revokedRow = await pool.query(
      `update access_token_records set revoked_at=transaction_timestamp()
      where id=$1 and revoked_at is null returning id`,
      [revoked.id]
    );
    expect(revokedRow.rows).toHaveLength(1);
    const physical = await pool.query<{ id: string }>(
      "select id from ruleset_rules where ruleset_id=$1 order by priority desc,specificity desc,id",
      [seed.rulesetId]
    );
    expect(physical.rows.map((row) => row.id)).toEqual(seed.ruleIds);
    const positive = await visible(actor.context);
    // The existing sibling policy must already establish an entitled actor
    // before0167. Do not mistake a broken fixture for a missing rule policy.
    expect(positive.matters).toEqual([seed.matterTypeId]);
    const clonePositive = await visible(validClone.context);
    expect(clonePositive).toEqual(positive);

    const negativeContexts: ReadonlyArray<{ label: string; context: Context; request?: boolean }> =
      [
        {
          label: "wrong-organization",
          context: { ...actor.context, organizationId: testId(311200) }
        },
        { label: "wrong-board-scope", context: { ...actor.context, boardIds: [testId(311201)] } },
        { label: "missing-token", context: { ...actor.context, tokenJti: testId(311202) } },
        { label: "wrong-member", context: { ...actor.context, memberId: testId(311203) } },
        { label: "missing-governance-scope", context: missingScope.context },
        { label: "revoked-token", context: revoked.context },
        { label: "expired-token", context: expired.context },
        { label: "non-request", context: actor.context, request: false }
      ];
    const denials: unknown[] = [];
    for (const control of negativeContexts) {
      const found = await visible(control.context, control.request ?? true);
      expect(found).toEqual({ rules: [], matters: [] });
      denials.push({ label: control.label, ...found });
    }

    // Same normal end/restore storage effect used by the existing board read
    // fixture; this policy additionally requires current live membership.
    const ended = await pool.query(
      `update board_memberships set state='ended',active_until=transaction_timestamp()
      where board_id=$1 and member_id=$2 returning id`,
      [actor.boardId, actor.memberId]
    );
    expect(ended.rows).toHaveLength(1);
    let membershipFailure: unknown;
    try {
      const found = await visible(actor.context);
      expect(found).toEqual({ rules: [], matters: [] });
      denials.push({ label: "ended-membership", ...found });
    } catch (error) {
      membershipFailure = error;
    }
    try {
      const restored = await pool.query(
        `update board_memberships set state='active',active_until=null
        where board_id=$1 and member_id=$2 returning id`,
        [actor.boardId, actor.memberId]
      );
      expect(restored.rows).toHaveLength(1);
    } catch (error) {
      if (membershipFailure !== undefined)
        throw new AggregateError(
          [membershipFailure, error],
          "membership denial and restoration failed"
        );
      throw error;
    }
    if (membershipFailure !== undefined) throw membershipFailure;
    expect(await visible(actor.context)).toEqual(positive);

    // A visible parent alone must not expose its children. This is a direct
    // RLS/loader comparison; public executeRead would independently reject this
    // missing-scope actor before dispatch. No public token bypass is claimed.
    const hiddenOriginal = await role(
      (client) =>
        client.query<{ view: JsonValue }>(ORIGINAL_RULESET_TOOL_SQL, [
          actor.boardId,
          seed.rulesetId
        ]),
      missingScope.context
    );
    expect(hiddenOriginal.rows).toHaveLength(1);
    const hiddenView = hiddenOriginal.rows[0]!.view as Readonly<Record<string, JsonValue>>;
    expect(hiddenView["rules"]).toEqual([]);
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    let hiddenAdmitted: JsonValue | null = null;
    try {
      hiddenAdmitted = await owner.produce(() =>
        role(
          (client) =>
            loadAdmittedGovernanceToolProjection(client, {
              kind: "ruleset",
              boardId: actor.boardId,
              rulesetId: seed.rulesetId
            }),
          missingScope.context
        )
      );
    } finally {
      try {
        owner.nativeTerminal();
      } finally {
        owner.collectorSettled();
      }
    }
    expect(hiddenAdmitted).toEqual(hiddenView);
    expect(manager.accounting.usedUnits).toBe(0);

    const privileges = await role((client) =>
      client.query(`select
      has_table_privilege(current_user,'public.ruleset_rules','INSERT') as insert_allowed,
      has_table_privilege(current_user,'public.ruleset_rules','UPDATE') as update_allowed,
      has_table_privilege(current_user,'public.ruleset_rules','DELETE') as delete_allowed`)
    );
    expect(privileges.rows[0]).toEqual({
      insert_allowed: false,
      update_allowed: false,
      delete_allowed: false
    });
    // All three writes lack table ACLs in the installed schema. Their42501
    // failures prove retained ACL denial; the separate policy catalog check
    // establishes SELECT-only RLS without granting write access for this test.
    const writeErrors: unknown[] = [];
    for (const [kind, sql, values] of [
      [
        "insert",
        `insert into ruleset_rules(id,ruleset_id,matter_type_id,priority,specificity,
        condition_tree,approval_rule_id,canonical_sha256) values($1,$2,$3,1,1,'{}',$4,$5) returning id`,
        [
          testId(311300),
          seed.rulesetId,
          seed.matterTypeId,
          seed.approvalRuleId,
          Buffer.alloc(32, 8)
        ]
      ],
      [
        "update",
        "update ruleset_rules set priority=priority+1 where id=$1 returning id",
        [seed.ruleIds[0]]
      ],
      ["delete", "delete from ruleset_rules where id=$1 returning id", [seed.ruleIds[0]]]
    ] as const) {
      let failure: unknown;
      try {
        await role((client) => client.query(sql, [...values]));
      } catch (error) {
        failure = error;
      }
      expect(failure).toMatchObject({ code: "42501" });
      writeErrors.push({ kind, code: (failure as { code: string }).code });
    }
    const unchanged = await pool.query<{ id: string }>(
      "select id from ruleset_rules where ruleset_id=$1 order by priority desc,specificity desc,id",
      [seed.rulesetId]
    );
    expect(unchanged.rows.map((row) => row.id)).toEqual(seed.ruleIds);
    const policy =
      await pool.query(`select policy.polname,policy.polcmd,policy.polwithcheck is null as no_write_check,
      array(select role.rolname::text from pg_roles as role where role.oid=any(policy.polroles) order by role.rolname) as roles
      from pg_policy as policy where policy.polrelid='public.ruleset_rules'::regclass
        and policy.polname='boardagent_server_governance_rule_read'`);
    process.stdout.write(
      JSON.stringify({
        governanceRuleReadPolicy: {
          physicalRuleIds: seed.ruleIds,
          positive,
          clonePositive,
          denials,
          hiddenParentVisible: true,
          hiddenChildCount: 0,
          privileges: privileges.rows[0],
          writeErrors,
          policy: policy.rows,
          publicGovernanceActivationExecuted: false,
          finalUsedUnits: manager.accounting.usedUnits
        }
      }) + "\n"
    );
    // Last: before0167 this fails on a real4-versus0 server SELECT result after
    // the sibling, negative, hidden-child and write controls have all executed.
    expect(
      positive.rules,
      "entitled original rules are hidden without the server SELECT policy"
    ).toEqual(seed.ruleIds);
    expect(policy.rows).toEqual([
      {
        polname: "boardagent_server_governance_rule_read",
        polcmd: "r",
        no_write_check: true,
        roles: ["boardagent_server"]
      }
    ]);
  });
});
