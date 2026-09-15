import type { Pool } from "pg";
import { expect } from "vitest";

const EXPOSED = [
  "boardagent_company_admin_snapshot",
  "boardagent_finalize_company_admin",
  "boardagent_member_admin_delegation_snapshot",
  "boardagent_finalize_member_admin_delegation",
  "boardagent_member_administration_authority",
  "boardagent_member_lifecycle_snapshot",
  "boardagent_finalize_member_lifecycle",
  "boardagent_prepare_member_invite",
  "boardagent_finalize_member_invite",
  "boardagent_administrative_access_page",
  "boardagent_member_recovery_credentials",
  "boardagent_issue_recovery_registration",
  "boardagent_lookup_recovery_registration",
  "boardagent_prepare_recovery_registration",
  "boardagent_complete_recovery_registration",
  "boardagent_prepare_recovery_activation",
  "boardagent_plan_recovery_activation",
  "boardagent_finalize_recovery_activation",
  "boardagent_record_confirmed_consent",
  "boardagent_communication_replay_authorized",
  "boardagent_owned_administrative_stage",
  "boardagent_owned_administrative_audit"
];
const PRIVATE = [
  "boardagent_administrative_member_eligible",
  "boardagent_administrative_citations",
  "boardagent_member_admin_delegation_effective",
  "boardagent_recovery_issuer_eligible"
];

/** Same explicit capability expectations on a fresh database and a schema86 upgrade. */
export async function assertAdministrativeCatalog(pool: Pool) {
  for (const role of ["boardagent_server", "boardagent_worker"])
    expect(
      (
        await pool.query(
          `select has_table_privilege($1,'public.schema_migrations','SELECT') as can_read,
              has_table_privilege($1,'public.schema_migrations','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') as can_write`,
          [role]
        )
      ).rows[0],
      `${role} migration metadata`
    ).toEqual({ can_read: true, can_write: false });
  expect(
    (
      await pool.query(`select p.proname from pg_proc p
        where p.pronamespace='public'::regnamespace and left(p.proname,11)='boardagent_'
        and not coalesce(p.proconfig @> array['search_path=pg_catalog, public, pg_temp'],false)
        order by p.proname`)
    ).rows
  ).toEqual([]);
  const functions = (
    await pool.query<{
      name: string;
      owner: string;
      prosecdef: boolean;
      proconfig: string[];
      server: boolean;
      worker: boolean;
      backup: boolean;
      public_execute: boolean;
    }>(
      `select p.proname as name,pg_get_userbyid(p.proowner) as owner,p.prosecdef,p.proconfig,
    has_function_privilege('boardagent_server',p.oid,'EXECUTE') as server,
    has_function_privilege('boardagent_worker',p.oid,'EXECUTE') as worker,
    has_function_privilege('boardagent_backup',p.oid,'EXECUTE') as backup,
    exists(select 1 from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
      where a.grantee=0 and a.privilege_type='EXECUTE') as public_execute
    from pg_proc p where p.pronamespace='public'::regnamespace and p.proname=any($1)
    order by p.proname`,
      [[...EXPOSED, ...PRIVATE]]
    )
  ).rows;
  expect(functions.map((f) => f.name)).toEqual([...EXPOSED, ...PRIVATE].sort());
  for (const fn of functions)
    expect(fn, fn.name).toEqual({
      name: fn.name,
      owner: "boardagent_migrator",
      prosecdef: true,
      proconfig: ["search_path=pg_catalog, public, pg_temp"],
      server: EXPOSED.includes(fn.name),
      worker: false,
      backup: false,
      public_execute: false
    });
  for (const table of [
    "organization_role_assignments",
    "company_admin_proposals",
    "member_admin_delegations",
    "administrative_authority_changes",
    "recovery_registration_grants",
    "consent_records"
  ]) {
    expect(
      (
        await pool.query(
          "select relrowsecurity,relforcerowsecurity from pg_class where oid=$1::regclass",
          [table]
        )
      ).rows[0]
    ).toEqual({ relrowsecurity: true, relforcerowsecurity: true });
    for (const role of ["boardagent_server", "boardagent_worker", "boardagent_backup"]) {
      expect(
        (
          await pool.query(
            "select has_table_privilege($1,$2,'INSERT,UPDATE,DELETE,TRUNCATE') as writable",
            [role, table]
          )
        ).rows[0],
        `${role} ${table}`
      ).toEqual({ writable: false });
      expect(
        (
          await pool.query("select has_any_column_privilege($1,$2,'INSERT,UPDATE') as writable", [
            role,
            table
          ])
        ).rows[0],
        `${role} column ${table}`
      ).toEqual({ writable: false });
    }
  }
  expect(
    (
      await pool.query(`select rolname from pg_roles where rolname in
    ('boardagent_server','boardagent_worker','boardagent_backup','boardagent_migrator')
    and (rolsuper or rolcreaterole or rolcreatedb or rolbypassrls) order by rolname`)
    ).rows
  ).toEqual([]);
  // No runtime path may assume the migration/backup role through role membership.
  for (const role of ["boardagent_server", "boardagent_worker"])
    for (const target of ["boardagent_migrator", "boardagent_backup"])
      expect(
        (await pool.query("select pg_has_role($1,$2,'MEMBER') as allowed", [role, target])).rows[0]
      ).toEqual({ allowed: false });
}
