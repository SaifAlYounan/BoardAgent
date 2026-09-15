import type { PoolClient } from "pg";
import { describe, expect, it } from "vitest";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  administrativeActors,
  withAdministrativeDatabase
} from "../helpers/administrative-authority.js";
import { stageAdministrativeAction } from "../helpers/administrative-service.js";
import { testId } from "../helpers/authorized-actor.js";

const HELPER = "boardagent_record_confirmed_consent(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea)";
const CALL = "select boardagent_record_confirmed_consent($1,$2,$3,$4,$5,$6,$7,$8)";
const inputFor = (memberId: string) => ({
  schema_version: "boardagent.tool-input.v1",
  idempotency_key: "verified-consent-database-offer",
  change: {
    operation: "grant",
    proposal_id: testId(112601),
    member_id: memberId,
    expected_member_version: 1,
    reason: "Synthetic protected confirmation boundary"
  }
});
async function helperArguments(
  client: PoolClient,
  stageId: string,
  code: string,
  input: ReturnType<typeof inputFor>
) {
  const row = (
    await client.query(
      `select s.*,a.id as attempt_id,
    to_char(s.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as staged_at,
    to_char(transaction_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as confirmed_at
    from action_stages s join input_required_attempts a on a.stage_id=s.id where s.id=$1`,
      [stageId]
    )
  ).rows[0];
  if (!row) throw new Error("disposable prepared stage missing");
  const response = { action: "accept", content: { approve: true, confirmation_code: code } };
  const record = {
    schemaVersion: "boardagent.consent-record.v1",
    id: testId(112602),
    stageId,
    inputRequiredAttemptId: row.attempt_id,
    actorMemberId: row.actor_member_id,
    actingForMemberId: row.acting_for_member_id,
    actionCode: row.action_code,
    targetType: row.target_type,
    targetId: row.target_id,
    payloadSha256: row.payload_sha256.toString("hex"),
    packageSha256: row.package_sha256?.toString("hex") ?? null,
    protectedCodeRecordSha256: canonicalSha256({
      schemaVersion: "boardagent.protected-code-record.v1",
      stageId,
      protectedCodeSha256: row.protected_code_sha256.toString("hex")
    }),
    accessTokenRecordId: row.access_token_record_id,
    tokenJti: row.token_jti,
    clientId: row.client_id,
    exactOrigin: row.exact_origin,
    stagedAt: row.staged_at,
    confirmedAt: row.confirmed_at,
    inputResponseSha256: canonicalSha256(response)
  };
  return [
    stageId,
    testId(112602),
    Buffer.from("retry-0001"),
    Buffer.from(canonicalJson(input)),
    Buffer.from(canonicalJson({ elicitation: { form: {} } })),
    Buffer.from(`administrative-test-state-${stageId}`),
    Buffer.from(canonicalJson(response)),
    Buffer.from(canonicalJson(record))
  ];
}

describe("SR021/AC19 protected database consent issuer", () => {
  it.each([
    "wrong_code",
    "cancel",
    "unapproved",
    "extra_response",
    "wrong_arguments",
    "wrong_capabilities",
    "wrong_state",
    "reused_request",
    "wrong_record",
    "wrong_actor",
    "missing_stage",
    "malformed_json"
  ] as const)("refuses %s before any consent or administrative effect", async (variant) => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const input = inputFor(target.memberId);
      const staged = await stageAdministrativeAction(pool, issuer, "manage_company_admin", input);
      const countBefore = (await pool.query("select count(*)::int as n from consent_records"))
        .rows[0];
      await expect(
        withRequestTransaction(
          pool,
          issuer.context,
          async (client) => {
            const args = await helperArguments(
              client,
              staged.prepared.stage_id,
              staged.prepared.confirmation_code,
              input
            );
            const code = staged.prepared.confirmation_code;
            if (variant === "wrong_code")
              args[6] = Buffer.from(
                canonicalJson({
                  action: "accept",
                  content: {
                    approve: true,
                    confirmation_code: `${code[0] === "Z" ? "Y" : "Z"}${code.slice(1)}`
                  }
                })
              );
            if (variant === "cancel")
              args[6] = Buffer.from(
                canonicalJson({
                  action: "cancel",
                  content: { approve: true, confirmation_code: code }
                })
              );
            if (variant === "unapproved")
              args[6] = Buffer.from(
                canonicalJson({
                  action: "accept",
                  content: { approve: false, confirmation_code: code }
                })
              );
            if (variant === "extra_response")
              args[6] = Buffer.from(
                canonicalJson({
                  action: "accept",
                  content: { approve: true, confirmation_code: code, bypass: true }
                })
              );
            if (variant === "wrong_arguments")
              args[3] = Buffer.from(
                canonicalJson({
                  ...input,
                  change: { ...input.change, reason: "Changed since presentation" }
                })
              );
            if (variant === "wrong_capabilities") args[4] = Buffer.from('{"elicitation":{}}');
            if (variant === "wrong_state") args[5] = Buffer.alloc(48, 144);
            if (variant === "reused_request") args[2] = Buffer.from("prepare-0001");
            if (variant === "wrong_record") args[7] = Buffer.from("{}");
            if (variant === "missing_stage") args[0] = testId(112603);
            if (variant === "malformed_json") args[6] = Buffer.from("{broken");
            if (variant === "wrong_actor")
              await client.query("select set_config('boardagent.member_id',$1,true)", [
                target.memberId
              ]);
            await client.query(CALL, args);
          },
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      expect((await pool.query("select count(*)::int as n from consent_records")).rows[0]).toEqual(
        countBefore
      );
      expect(
        (
          await pool.query("select state from action_stages where id=$1", [
            staged.prepared.stage_id
          ])
        ).rows[0]
      ).toEqual({ state: "active" });
      expect(
        (await pool.query("select count(*)::int as n from company_admin_proposals")).rows[0]
      ).toEqual({ n: 0 });
      expect(
        (await pool.query("select count(*)::int as n from administrative_authority_changes"))
          .rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it("enforces the exact database deadline at one microsecond before, at and after expiry", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const input = inputFor(target.memberId);
      const staged = await stageAdministrativeAction(pool, issuer, "manage_company_admin", input);
      for (const offset of [1, 0, -1]) {
        const attempt = withRequestTransaction(
          pool,
          issuer.context,
          async (client) => {
            // Rebase dates only in this owned disposable database, then restore the guard/runtime role.
            await client.query("reset role");
            await client.query(
              "alter table action_stages disable trigger boardagent_action_stage_binding_guard"
            );
            await client.query(
              "update action_stages set created_at=transaction_timestamp()-interval '10 minutes'+$2*interval '1 microsecond', expires_at=transaction_timestamp()+$2*interval '1 microsecond' where id=$1",
              [staged.prepared.stage_id, offset]
            );
            await client.query(
              "alter table action_stages enable trigger boardagent_action_stage_binding_guard"
            );
            await client.query("set local role boardagent_server");
            const args = await helperArguments(
              client,
              staged.prepared.stage_id,
              staged.prepared.confirmation_code,
              input
            );
            await client.query("savepoint before_verified_consent");
            await client.query(CALL, args);
            expect(
              (
                await client.query("select count(*)::int as n from consent_records where id=$1", [
                  testId(112602)
                ])
              ).rows[0]
            ).toEqual({ n: 1 });
            // Keep the positive boundary independent of the later refusal cases.
            await client.query("rollback to savepoint before_verified_consent");
          },
          { assumeRole: "boardagent_server", isolation: "serializable" }
        );
        if (offset > 0) await expect(attempt).resolves.toBeUndefined();
        else await expect(attempt).rejects.toMatchObject({ code: "42501" });
      }
      expect(
        (
          await pool.query("select count(*)::int as n from consent_records where id=$1", [
            testId(112602)
          ])
        ).rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it("issues only one consent per stage and refuses replay even before the caller finalizes the action", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const { issuer, target } = await administrativeActors(pool);
      const input = inputFor(target.memberId);
      const staged = await stageAdministrativeAction(pool, issuer, "manage_company_admin", input);
      await expect(
        withRequestTransaction(
          pool,
          issuer.context,
          async (client) => {
            const args = await helperArguments(
              client,
              staged.prepared.stage_id,
              staged.prepared.confirmation_code,
              input
            );
            await client.query(CALL, args);
            expect(
              (
                await client.query(
                  "select count(*)::int as n from consent_records where stage_id=$1",
                  [staged.prepared.stage_id]
                )
              ).rows[0]
            ).toEqual({ n: 1 });
            await client.query(CALL, args);
          },
          { assumeRole: "boardagent_server", isolation: "serializable" }
        )
      ).rejects.toMatchObject({ code: "42501" });
      expect(
        (
          await pool.query("select count(*)::int as n from consent_records where stage_id=$1", [
            staged.prepared.stage_id
          ])
        ).rows[0]
      ).toEqual({ n: 0 });
    });
  });
  it("keeps raw consent INSERT unavailable and the verifier fixed-owner, private and limited to the runtime caller", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const fn = (
        await pool.query(
          "select pg_get_userbyid(proowner) as owner,prosecdef,proconfig from pg_proc where oid=$1::regprocedure",
          [HELPER]
        )
      ).rows[0];
      expect(fn).toEqual({
        owner: "boardagent_migrator",
        prosecdef: true,
        proconfig: ["search_path=pg_catalog, public, pg_temp"]
      });
      for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
        expect(
          (
            await pool.query(
              "select has_table_privilege($1,'consent_records','INSERT') as allowed",
              [role]
            )
          ).rows[0]
        ).toEqual({ allowed: false });
        expect(
          (
            await pool.query("select has_function_privilege($1,$2,'EXECUTE') as allowed", [
              role,
              HELPER
            ])
          ).rows[0]
        ).toEqual({ allowed: role === "boardagent_server" });
      }
      expect(
        (
          await pool.query(
            "select count(*)::int as n from pg_proc p cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a where p.oid=$1::regprocedure and a.grantee=0 and a.privilege_type='EXECUTE'",
            [HELPER]
          )
        ).rows[0]
      ).toEqual({ n: 0 });
      // The helper cannot be used outside a managed request, even with valid UUIDs/bytes.
      await expect(
        pool.query(CALL, [
          testId(112601),
          testId(112602),
          Buffer.from("retry"),
          Buffer.from("{}"),
          Buffer.from("{}"),
          Buffer.alloc(32),
          Buffer.from("{}"),
          Buffer.from("{}")
        ])
      ).rejects.toMatchObject({ code: "42501" });
    });
  });
});
