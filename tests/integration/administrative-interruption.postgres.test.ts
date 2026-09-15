import { setTimeout as delay } from "node:timers/promises";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../lib/contracts/src/index.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { delegationFixture } from "../helpers/administrative-delegation.js";
import { stageAdministrativeAction } from "../helpers/administrative-service.js";
import { testId } from "../helpers/authorized-actor.js";

async function stateFingerprint(pool: Pool) {
  const state: Record<string, unknown> = {};
  for (const table of [
    "members",
    "organization_role_assignments",
    "company_admin_proposals",
    "member_admin_delegations",
    "administrative_authority_changes",
    "consent_records",
    "idempotency_records",
    "audit_events",
    "auth_sessions",
    "access_token_records",
    "refresh_families",
    "oauth_authorization_codes",
    "action_stages"
  ]) {
    state[table] = (
      await pool.query(
        `select coalesce(jsonb_agg(to_jsonb(t) order by id),'[]') as rows from ${table} t`
      )
    ).rows[0].rows;
  }
  return sha256Hex(Buffer.from(JSON.stringify(state)));
}

async function preparedChange(pool: Pool, kind: "admin" | "delegation") {
  const f = await delegationFixture(pool);
  if (kind === "admin") {
    expect(
      (
        await (
          await stageAdministrativeAction(pool, f.issuer, "manage_company_admin", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "interruption-admin-offer-0001",
            change: {
              operation: "grant",
              proposal_id: testId(197_000),
              member_id: f.target.memberId,
              expected_member_version: 1,
              reason: "Offer administrative responsibility"
            }
          })
        ).confirm()
      ).confirmed
    ).toBe(true);
  }
  const action =
    kind === "admin"
      ? await stageAdministrativeAction(pool, f.target, "manage_company_admin", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "interruption-admin-accept-0001",
          change: {
            operation: "accept",
            proposal_id: testId(197_000),
            expected_proposal_version: 1,
            reason: "Accept administrative responsibility"
          }
        })
      : await stageAdministrativeAction(pool, f.issuer, "manage_member_admin_delegation", f.input);
  const table = kind === "admin" ? "organization_role_assignments" : "member_admin_delegations";
  const event = kind === "admin" ? "company_admin_granted" : "member_admin_delegation_granted";
  const assertOnce = async () => {
    expect(
      (
        await pool.query(`select count(*)::int as n from ${table} where member_id=$1`, [
          f.target.memberId
        ])
      ).rows[0]
    ).toEqual({ n: 1 });
    expect(
      (await pool.query("select count(*)::int as n from audit_events where event_type=$1", [event]))
        .rows[0]
    ).toEqual({ n: 1 });
    expect(
      (
        await pool.query("select count(*)::int as n from consent_records where stage_id=$1", [
          action.prepared.stage_id
        ])
      ).rows[0]
    ).toEqual({ n: 1 });
    expect(
      (await pool.query("select state from action_stages where id=$1", [action.prepared.stage_id]))
        .rows[0]
    ).toEqual({ state: "confirmed" });
    expect(
      (
        await pool.query(
          "select revoked_at is not null as revoked from access_token_records where id=$1",
          [f.target.accessTokenRecordId]
        )
      ).rows[0]
    ).toEqual({ revoked: true });
  };
  return { ...f, action, table, event, assertOnce };
}

describe("SR095/SR097/SR100 AC20 administrative transaction faults", () => {
  for (const kind of ["admin", "delegation"] as const) {
    it(`${kind}: failed audit append rolls back authority and consent, then the original confirmation can succeed`, async () => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await preparedChange(pool, kind);
        const before = await stateFingerprint(pool);
        await pool.query(`create function test_interrupted_audit() returns trigger language plpgsql as $$ begin raise exception 'synthetic audit interruption'; end $$;
          create trigger test_interrupted_audit before insert on audit_events for each row when(new.event_type='${f.event}') execute function test_interrupted_audit()`);
        await expect(f.action.confirm()).rejects.toThrow("synthetic audit interruption");
        expect(await stateFingerprint(pool)).toBe(before);
        await pool.query("drop trigger test_interrupted_audit on audit_events");
        expect((await f.action.confirm()).confirmed).toBe(true);
        await f.assertOnce();
      });
    });

    it(`${kind}: losing the transaction connection after authority insertion leaves no partial appointment`, async () => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await preparedChange(pool, kind);
        const before = await stateFingerprint(pool);
        const lockKey = 1_970_000_001;
        await pool.query(`create function test_interrupt_after_authority() returns trigger language plpgsql as $$ begin perform pg_advisory_xact_lock(${lockKey}::bigint); return new; end $$;
          create trigger test_interrupt_after_authority after insert on ${f.table} for each row execute function test_interrupt_after_authority()`);
        const gate = await pool.connect();
        await gate.query("select pg_advisory_lock($1::bigint)", [lockKey]);
        const pending = f.action.confirm().then(
          (value) => ({ value }),
          (error: unknown) => ({ error })
        );
        try {
          const deadline = Date.now() + 5000;
          let pid: number | undefined;
          while (Date.now() < deadline) {
            const rows = (
              await pool.query<{ pid: number }>(
                `select a.pid from pg_stat_activity a join pg_locks l on l.pid=a.pid
              where a.datname=current_database() and a.wait_event='advisory' and l.locktype='advisory'
                and l.classid=0 and l.objid=$1 and not l.granted`,
                [lockKey]
              )
            ).rows;
            if (rows.length === 1) {
              pid = rows[0]!.pid;
              break;
            }
            await delay(10);
          }
          expect(pid).toBeDefined();
          // The only target is this disposable database's exact waiting transaction.
          expect(
            (
              await pool.query(
                "select pg_terminate_backend(pid) as terminated from pg_stat_activity where pid=$1 and datname=current_database()",
                [pid]
              )
            ).rows[0]
          ).toEqual({ terminated: true });
          expect(await pending).toMatchObject({ error: { code: "57P01" } });
        } finally {
          await gate.query("select pg_advisory_unlock($1::bigint)", [lockKey]);
          gate.release();
          await pending;
        }
        expect(await stateFingerprint(pool)).toBe(before);
        await pool.query(`drop trigger test_interrupt_after_authority on ${f.table}`);
        expect((await f.action.confirm()).confirmed).toBe(true);
        await f.assertOnce();
      });
    });

    it(`${kind}: a PostgreSQL serialization retry commits exactly one appointment and consent`, async () => {
      await withAdministrativeDatabase(async (pool) => {
        const f = await preparedChange(pool, kind);
        // A sequence intentionally survives rollback, allowing exactly one injected 40001.
        await pool.query(`create sequence test_serialization_attempt;
          grant usage on sequence test_serialization_attempt to boardagent_server;
          create function test_retry_admin_audit() returns trigger language plpgsql as $$ begin
            if nextval('public.test_serialization_attempt')=1 then raise exception 'synthetic serialization conflict' using errcode='40001'; end if;
            return new; end $$;
          create trigger test_retry_admin_audit before insert on audit_events for each row when(new.event_type='${f.event}') execute function test_retry_admin_audit()`);
        expect((await f.action.confirm()).confirmed).toBe(true);
        expect(
          (await pool.query("select last_value::int as attempts from test_serialization_attempt"))
            .rows[0]
        ).toEqual({ attempts: 2 });
        await f.assertOnce();
      });
    });
  }
});
