import { copyFile, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { getTableColumns, getTableName } from "drizzle-orm";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { ACTIVE_SCHEMA_TABLES, FROZEN_SCHEMA_TABLES, migrate } from "../../lib/db/src/index.js";
import { enqueueRequestJobInTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

const FROZEN_TABLES = [
  "access_token_records",
  "accountable_principals",
  "action_stages",
  "agenda_items",
  "agenda_versions",
  "approval_rules",
  "audit_chain_head",
  "audit_checkpoints",
  "audit_events",
  "auth_sessions",
  "backup_receipts",
  "ballot_dispositions",
  "ballots",
  "board_memberships",
  "board_versions",
  "boards",
  "circulation_recipients",
  "clock_health_samples",
  "config_receipts",
  "consent_records",
  "crypto_key_registry",
  "decision_package_components",
  "decision_packages",
  "deletion_tombstones",
  "document_access_grants",
  "document_circulations",
  "document_exclusions",
  "document_search",
  "document_validation_attempts",
  "document_versions",
  "documents",
  "enrollment_activation_challenges",
  "enrollment_invitations",
  "export_artifacts",
  "export_chunks",
  "export_requests",
  "external_identity_links",
  "feed_tombstones",
  "governance_citations",
  "governance_profiles",
  "governance_rule_templates",
  "governance_seat_rules",
  "idempotency_records",
  "identity_recovery_requests",
  "input_required_attempts",
  "job_attempt_results",
  "jobs",
  "management_question_answers",
  "management_question_turns",
  "management_questions",
  "management_revision_replies",
  "management_revision_requests",
  "management_submission_dispositions",
  "management_submission_threads",
  "management_submission_versions",
  "matter_evaluations",
  "matter_types",
  "meeting_attendance",
  "meeting_rsvps",
  "meeting_transcript_versions",
  "meeting_transcripts",
  "meeting_versions",
  "meetings",
  "member_contact_points",
  "member_webhooks",
  "members",
  "membership_versions",
  "minutes",
  "minutes_action_declarations",
  "minutes_action_item_dispositions",
  "minutes_correction_cycles",
  "minutes_diffs",
  "minutes_resign_requirements",
  "minutes_review_dispositions",
  "minutes_review_items",
  "minutes_review_withdrawals",
  "minutes_signature_packages",
  "minutes_signature_requirements",
  "minutes_signature_supersessions",
  "minutes_signatures",
  "minutes_versions",
  "notices",
  "notification_attempts",
  "notification_jobs",
  "oauth_authorization_codes",
  "oauth_authorization_requests",
  "oauth_client_grants",
  "oauth_client_redirect_uris",
  "oauth_clients",
  "oauth_consents",
  "oidc_login_transactions",
  "onboarding_attestations",
  "onboarding_browser_stages",
  "onboarding_terms_versions",
  "organization_role_assignments",
  "organizations",
  "pending_action_feed",
  "proposal_dispositions",
  "proposals",
  "proxy_grants",
  "proxy_revocations",
  "question_decision_links",
  "question_visibility",
  "rate_limit_buckets",
  "refresh_families",
  "refresh_tokens",
  "resolution_versions",
  "retention_snapshots",
  "rule_citations",
  "rule_overrides",
  "ruleset_rules",
  "rulesets",
  "schema_migrations",
  "secretariat_request_turns",
  "secretariat_requests",
  "secretary_support_versions",
  "system_instance",
  "task_closures",
  "task_correction_cycles",
  "task_evidence",
  "task_evidence_reviews",
  "tasks",
  "totp_credentials",
  "transcript_challenge_dispositions",
  "transcript_challenges",
  "transcript_question_links",
  "transcript_turns",
  "transcript_verifications",
  "vote_certificates",
  "vote_close_stage_material",
  "vote_creation_stage_material",
  "vote_electorate",
  "vote_exclusions",
  "vote_outcomes",
  "vote_replacement_stage_material",
  "vote_source_update_causes",
  "vote_source_update_dispositions",
  "vote_supersessions",
  "votes",
  "webauthn_challenges",
  "webauthn_credentials",
  "wizard_drafts",
  "wizard_steps"
] as const;
const ACTIVE_TABLES = [
  ...FROZEN_TABLES,
  "member_feed_sync_counters",
  "member_feed_sync_positions",
  "board_exclusions",
  "meeting_exclusions",
  "minutes_exclusions",
  "audit_recoveries",
  "audit_recovery_completions",
  "key_lifecycle_operations",
  "key_lifecycle_completions",
  "key_lifecycle_browser_effects",
  "key_lifecycle_totp_effects",
  "key_lifecycle_contact_effects",
  "key_lifecycle_webhook_rewraps",
  "key_lifecycle_webhook_disables",
  "key_lifecycle_affected_families",
  "administrative_authority_changes",
  "company_admin_proposals",
  "recovery_registration_grants",
  "member_admin_delegations",
  "activation_restart_grants",
  "identity_admin_consent_uses"
].toSorted();

const SERVER_INSERT_TABLES = [
  "access_token_records",
  "action_stages",
  "agenda_items",
  "agenda_versions",
  "audit_events",
  "auth_sessions",
  "ballot_dispositions",
  "ballots",
  "circulation_recipients",
  "decision_package_components",
  "decision_packages",
  "deletion_tombstones",
  "document_access_grants",
  "document_circulations",
  "document_exclusions",
  "document_search",
  "document_validation_attempts",
  "document_versions",
  "documents",
  "export_requests",
  "feed_tombstones",
  "idempotency_records",
  "input_required_attempts",
  "management_question_answers",
  "management_question_turns",
  "management_questions",
  "management_submission_versions",
  "matter_evaluations",
  "meeting_attendance",
  "meeting_rsvps",
  "meeting_transcript_versions",
  "meeting_transcripts",
  "meeting_versions",
  "meetings",
  "member_webhooks",
  "minutes",
  "minutes_action_declarations",
  "minutes_action_item_dispositions",
  "minutes_correction_cycles",
  "minutes_diffs",
  "minutes_resign_requirements",
  "minutes_review_dispositions",
  "minutes_review_items",
  "minutes_review_withdrawals",
  "minutes_signature_packages",
  "minutes_signature_requirements",
  "minutes_signature_supersessions",
  "minutes_signatures",
  "minutes_versions",
  "notices",
  "notification_jobs",
  "oauth_authorization_codes",
  "oauth_authorization_requests",
  "oauth_consents",
  "onboarding_attestations",
  "onboarding_browser_stages",
  "pending_action_feed",
  "proxy_grants",
  "proxy_revocations",
  "question_decision_links",
  "question_visibility",
  "refresh_families",
  "refresh_tokens",
  "resolution_versions",
  "retention_snapshots",
  "rule_overrides",
  "task_closures",
  "task_correction_cycles",
  "task_evidence",
  "task_evidence_reviews",
  "tasks",
  "totp_credentials",
  "transcript_challenge_dispositions",
  "transcript_challenges",
  "transcript_question_links",
  "transcript_turns",
  "transcript_verifications",
  "vote_close_stage_material",
  "vote_creation_stage_material",
  "vote_electorate",
  "vote_exclusions",
  "vote_replacement_stage_material",
  "vote_source_update_causes",
  "vote_source_update_dispositions",
  "vote_supersessions",
  "votes",
  "webauthn_challenges",
  "wizard_drafts",
  "wizard_steps"
] as const;

const SERVER_UPDATE_COLUMNS = {
  access_token_records: ["revoked_at"],
  action_stages: ["state", "confirmed_at", "rejected_at", "cancelled_at"],
  auth_sessions: [
    "opaque_session_sha256",
    "member_id",
    "client_id",
    "state",
    "expires_at",
    "last_authenticated_at"
  ],
  document_exclusions: ["active_until"],
  document_search: ["current_version_id", "canonical_text_sha256", "search_text", "indexed_at"],
  documents: ["current_version_id", "row_version"],
  enrollment_invitations: ["revoked_at"],
  export_requests: ["state", "consent_record_id", "row_version", "completed_at"],
  idempotency_records: [
    "state",
    "safe_response_type",
    "safe_response_id",
    "safe_response_sha256",
    "completed_at"
  ],
  input_required_attempts: [
    "retry_request_id",
    "input_response_sha256",
    "response_action",
    "retry_received_at",
    "completed_at",
    "state"
  ],
  meeting_rsvps: ["is_current"],
  meeting_transcripts: ["state", "current_version_id", "row_version"],
  meetings: ["current_minutes_id", "row_version"],
  member_webhooks: [
    "secret_ciphertext",
    "secret_sha256",
    "key_id",
    "state",
    "generation",
    "verified_at",
    "updated_at",
    "disabled_at"
  ],
  minutes: [
    "state",
    "current_version_id",
    "current_signature_package_id",
    "row_version",
    "finalized_at",
    "cancelled_at"
  ],
  minutes_resign_requirements: ["state", "resolution", "resolved_signature_id", "resolved_at"],
  minutes_signature_packages: ["state"],
  oauth_authorization_codes: ["consumed_at", "revoked_at"],
  oauth_authorization_requests: ["member_id", "session_id", "request_state"],
  oauth_consents: ["revoked_at"],
  onboarding_browser_stages: ["state", "attested_audit_event_id", "completed_at"],
  pending_action_feed: ["state", "resolved_at"],
  refresh_families: ["generation", "state", "last_used_at", "idle_expires_at", "revoked_at"],
  refresh_tokens: ["used_at", "replaced_by_id", "revoked_at"],
  task_evidence: ["state", "row_version"],
  tasks: ["state", "row_version", "completed_at", "cancelled_at"],
  totp_credentials: [
    "state",
    "failed_attempts",
    "locked_until",
    "last_accepted_step",
    "activated_at",
    "terminal_at"
  ],
  transcript_challenges: ["state"],
  votes: [
    "state",
    "row_version",
    "current_resolution_version_id",
    "current_decision_package_id",
    "electorate_sha256",
    "close_mode",
    "deadline_at",
    "matter_evaluation_id",
    "selected_ruleset_rule_id",
    "rule_override_id",
    "rule_override_sha256",
    "opened_at"
  ],
  webauthn_challenges: ["consumed_at"],
  webauthn_credentials: ["signature_counter", "backup_state", "last_used_at"],
  wizard_drafts: ["state", "row_version", "posted_at"]
} as const;

const WORKER_UPDATE_COLUMNS = {
  export_artifacts: ["state", "deleted_at"],
  export_requests: [
    "state",
    "row_version",
    "snapshot_manifest",
    "snapshot_sha256",
    "started_at",
    "completed_at",
    "failure_class"
  ]
} as const;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_test_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 4 });
  try {
    return await run(pool);
  } finally {
    await pool.end();
    await dropClosedTestDatabase(admin, database);
    await admin.end();
  }
}

async function copyMigrations(): Promise<string> {
  const target = await mkdtemp(path.join(tmpdir(), "boardagent-db-migrations-"));
  for (const name of await readdir(MIGRATIONS)) {
    if (name.endsWith(".sql")) await copyFile(path.join(MIGRATIONS, name), path.join(target, name));
  }
  return target;
}

describe("PostgreSQL 18.6 migration ledger", () => {
  it("refuses an old in-flight enqueue after the upgrade installs the reserved identity guard", async () => {
    await withDatabase(async (pool) => {
      const copy = await copyMigrations();
      const entered = Promise.withResolvers<number>();
      const release = Promise.withResolvers<void>();
      let upgrading: Promise<unknown> | undefined;
      let requesting: Promise<unknown> | undefined;
      try {
        for (const name of await readdir(copy))
          if (Number.parseInt(name.slice(0, 4), 10) > 106) await rm(path.join(copy, name));
        expect(await migrate(pool, copy, "pre-inflight-worker-identity")).toBe(106);
        const actor = await seedAuthorizedActor(pool, {
          seatRole: "voting_member",
          scopes: ["audit:read"]
        });
        const name = "0107_worker_producer_identity_and_failure.sql";
        await copyFile(path.join(MIGRATIONS, name), path.join(copy, name));
        const sql = await readFile(path.join(copy, name), "utf8");
        const paused = new Proxy(pool, {
          get(target, key) {
            if (key === "connect")
              return async () => {
                const client = await target.connect();
                return new Proxy(client, {
                  get(connection, property) {
                    if (property === "query")
                      return async (...args: unknown[]) => {
                        if (args[0] === sql) {
                          // Pause inside the real migration transaction after its table
                          // lock, before installing107. The original SQL/checksum stays exact.
                          await connection.query(
                            "lock table public.jobs in share row exclusive mode"
                          );
                          const pid = (await connection.query("select pg_backend_pid() as pid"))
                            .rows[0]!.pid as number;
                          entered.resolve(pid);
                          await release.promise;
                        }
                        return Reflect.apply(connection.query, connection, args);
                      };
                    const value: unknown = Reflect.get(connection, property);
                    return typeof value === "function" ? value.bind(connection) : value;
                  }
                });
              };
            const value: unknown = Reflect.get(target, key);
            return typeof value === "function" ? value.bind(target) : value;
          }
        });
        upgrading = migrate(paused, copy, "inflight-worker-identity-upgrade").catch(
          (error: unknown) => {
            entered.reject(error);
            throw error;
          }
        );
        void upgrading.catch(() => undefined);
        const migratorPid = await entered.promise;
        const requestEntered = Promise.withResolvers<number>();
        requesting = withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            requestEntered.resolve(
              (await client.query("select pg_backend_pid() as pid")).rows[0]!.pid as number
            );
            return enqueueRequestJobInTransaction(client, {
              jobId: testId(97_002),
              idempotencyKey: "worker-v2:periodic:clock_health:inflight",
              envelope: {
                schemaVersion: "boardagent.job.clock_health.v1",
                organizationId: actor.organizationId,
                boardId: null,
                jobType: "clock_health",
                subjectType: "organization",
                subjectId: actor.organizationId,
                parameters: {}
              }
            });
          },
          { assumeRole: "boardagent_server" }
        ).catch((error: unknown) => {
          requestEntered.reject(error);
          throw error;
        });
        void requesting.catch(() => undefined);
        const requestPid = await requestEntered.promise;
        await expect
          .poll(
            async () =>
              (await pool.query("select pg_blocking_pids($1) as blockers", [requestPid])).rows[0]
                ?.blockers,
            { timeout: 2_000, interval: 20 }
          )
          .toContain(migratorPid);
        release.resolve();
        await expect(upgrading).resolves.toBe(1);
        await expect(requesting).rejects.toMatchObject({ code: "job_invalid" });
        expect(
          (await pool.query("select count(*)::int as count from public.jobs")).rows[0]?.count
        ).toBe(0);
        expect(
          (await pool.query("select max(version)::int as version from schema_migrations")).rows[0]
            ?.version
        ).toBe(107);
      } finally {
        release.resolve();
        await Promise.allSettled([upgrading, requesting]);
        await rm(copy, { recursive: true, force: true });
      }
    });
  }, 20_000);

  it.each([false, true])(
    "preserves legacy jobs and refuses adoption of a pre-existing reserved identity: %s",
    async (reserved) => {
      await withDatabase(async (pool) => {
        const copy = await copyMigrations();
        try {
          for (const name of await readdir(copy))
            if (Number.parseInt(name.slice(0, 4), 10) > 106) await rm(path.join(copy, name));
          expect(await migrate(pool, copy, "pre-worker-identity")).toBe(106);
          const actor = await seedAuthorizedActor(pool, {
            seatRole: "voting_member",
            scopes: ["audit:read"]
          });
          const created = await withRequestTransaction(
            pool,
            actor.context,
            (client) =>
              enqueueRequestJobInTransaction(client, {
                jobId: testId(97_001),
                idempotencyKey: reserved
                  ? "worker-v2:periodic:clock_health:preexisting"
                  : "worker-periodic:clock_health:legacy",
                availableAt: new Date(Date.now() + 86_400_000).toISOString(),
                envelope: {
                  schemaVersion: "boardagent.job.clock_health.v1",
                  organizationId: actor.organizationId,
                  boardId: null,
                  jobType: "clock_health",
                  subjectType: "organization",
                  subjectId: actor.organizationId,
                  parameters: {}
                }
              }),
            { assumeRole: "boardagent_server" }
          );
          const before = (
            await pool.query("select row_to_json(job) as value from jobs as job where id=$1", [
              created.jobId
            ])
          ).rows;
          const migration = "0107_worker_producer_identity_and_failure.sql";
          await copyFile(path.join(MIGRATIONS, migration), path.join(copy, migration));
          if (reserved)
            await expect(migrate(pool, copy, "worker-identity-collision")).rejects.toThrow(
              /worker producer identity already exists/u
            );
          else expect(await migrate(pool, copy, "worker-identity-upgrade")).toBe(1);
          expect(
            (
              await pool.query("select row_to_json(job) as value from jobs as job where id=$1", [
                created.jobId
              ])
            ).rows
          ).toEqual(before);
          expect(
            Number(
              (await pool.query("select max(version)::int as version from schema_migrations"))
                .rows[0]?.version
            )
          ).toBe(reserved ? 106 : 107);
        } finally {
          await rm(copy, { recursive: true, force: true });
        }
      });
    }
  );

  it("applies the complete product schema and is idempotent on the next boot", async () => {
    await withDatabase(async (pool) => {
      const version = await pool.query<{ server_version: string }>("show server_version");
      expect(version.rows[0]?.server_version).toMatch(/^18\.6\b/u);
      const applied = await migrate(pool, MIGRATIONS, "phase1-test");
      expect(applied).toBeGreaterThan(0);
      expect(await migrate(pool, MIGRATIONS, "phase1-test")).toBe(0);
      const ledger = await pool.query<{ count: string }>(
        "select count(*)::text as count from schema_migrations"
      );
      expect(Number(ledger.rows[0]?.count)).toBe(applied);
      const inventory = await pool.query<{ tablename: string }>(
        "select tablename from pg_tables where schemaname = 'public' order by tablename"
      );
      expect(inventory.rows.map(({ tablename }) => tablename)).toEqual(ACTIVE_TABLES);

      const mirrorTables = Object.values(FROZEN_SCHEMA_TABLES)
        .map((table) => getTableName(table))
        .toSorted();
      expect(mirrorTables).toEqual(FROZEN_TABLES);

      expect(Object.values(ACTIVE_SCHEMA_TABLES).map(getTableName).toSorted()).toEqual(
        ACTIVE_TABLES
      );
      const mirrorColumns = Object.values(ACTIVE_SCHEMA_TABLES)
        .flatMap((table) =>
          Object.values(getTableColumns(table)).map((column) => ({
            table_name: getTableName(table),
            column_name: column.name,
            not_null: column.notNull
          }))
        )
        .toSorted((left, right) => {
          const leftKey = `${left.table_name}\u0000${left.column_name}`;
          const rightKey = `${right.table_name}\u0000${right.column_name}`;
          return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        });
      const databaseColumns = await pool.query<{
        table_name: string;
        column_name: string;
        not_null: boolean;
      }>(
        `select table_name, column_name, is_nullable = 'NO' as not_null
           from information_schema.columns
          where table_schema = 'public'
          order by table_name, column_name`
      );
      const normalizedDatabaseColumns = databaseColumns.rows.toSorted((left, right) => {
        const leftKey = `${left.table_name}\u0000${left.column_name}`;
        const rightKey = `${right.table_name}\u0000${right.column_name}`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
      });
      expect(mirrorColumns).toEqual(normalizedDatabaseColumns);

      const mutationPrivileges = await pool.query<{
        grantee: string;
        privilege_type: "INSERT" | "UPDATE";
        table_name: string;
      }>(
        `select grantee,privilege_type,table_name
           from information_schema.role_table_grants
          where table_schema='public'
            and grantee in ('boardagent_server','boardagent_worker')
            and privilege_type in ('INSERT','UPDATE')
          order by grantee,privilege_type,table_name`
      );
      expect(mutationPrivileges.rows).toEqual([
        ...SERVER_INSERT_TABLES.map((table_name) => ({
          grantee: "boardagent_server",
          privilege_type: "INSERT" as const,
          table_name
        })),
        {
          grantee: "boardagent_worker",
          privilege_type: "INSERT",
          table_name: "audit_checkpoints"
        },
        {
          grantee: "boardagent_worker",
          privilege_type: "INSERT",
          table_name: "audit_events"
        },
        {
          grantee: "boardagent_worker",
          privilege_type: "INSERT",
          table_name: "backup_receipts"
        },
        {
          grantee: "boardagent_worker",
          privilege_type: "INSERT",
          table_name: "export_artifacts"
        },
        {
          grantee: "boardagent_worker",
          privilege_type: "INSERT",
          table_name: "export_chunks"
        }
      ]);

      const effectiveUpdatePrivileges = await pool.query<{
        column_name: string;
        grantee: "boardagent_server" | "boardagent_worker";
        table_name: string;
      }>(
        `with runtime_roles(grantee) as (
           values ('boardagent_server'::text),('boardagent_worker'::text)
         )
         select runtime_roles.grantee,columns.table_name,columns.column_name
           from runtime_roles
           cross join information_schema.columns as columns
          where columns.table_schema='public'
            and has_column_privilege(
              runtime_roles.grantee,
              format('%I.%I',columns.table_schema,columns.table_name),
              columns.column_name,
              'UPDATE'
            )
          order by runtime_roles.grantee,columns.table_name,columns.ordinal_position`
      );
      const expandColumns = (
        grantee: "boardagent_server" | "boardagent_worker",
        matrix: Readonly<Record<string, readonly string[]>>
      ): Array<{ column_name: string; grantee: string; table_name: string }> =>
        Object.entries(matrix).flatMap(([table_name, columns]) =>
          columns.map((column_name) => ({ column_name, grantee, table_name }))
        );
      const expectedEffectiveUpdates = [
        ...expandColumns("boardagent_server", SERVER_UPDATE_COLUMNS),
        ...expandColumns("boardagent_worker", WORKER_UPDATE_COLUMNS)
      ].toSorted((left, right) => {
        const leftKey = `${left.grantee}\u0000${left.table_name}\u0000${left.column_name}`;
        const rightKey = `${right.grantee}\u0000${right.table_name}\u0000${right.column_name}`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
      });
      expect(
        effectiveUpdatePrivileges.rows.toSorted((left, right) => {
          const leftKey = `${left.grantee}\u0000${left.table_name}\u0000${left.column_name}`;
          const rightKey = `${right.grantee}\u0000${right.table_name}\u0000${right.column_name}`;
          return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        })
      ).toEqual(expectedEffectiveUpdates);

      const unsafeSecurityDefiners = await pool.query<{
        execute_grantee: string | null;
        identity: string;
        owner: string;
      }>(
        `select routine.proname || '(' || pg_get_function_identity_arguments(routine.oid) || ')'
                  as identity,
                owner.rolname as owner,
                case when acl.grantee=0 then 'PUBLIC' else pg_get_userbyid(acl.grantee) end
                  as execute_grantee
           from pg_proc as routine
           join pg_namespace as namespace on namespace.oid=routine.pronamespace
           join pg_roles as owner on owner.oid=routine.proowner
           left join lateral aclexplode(
             coalesce(routine.proacl,acldefault('f',routine.proowner))
           ) as acl on acl.privilege_type='EXECUTE'
          where namespace.nspname='public'
            and routine.prosecdef
            and (
              owner.rolname<>'boardagent_migrator'
              or not coalesce(routine.proconfig @> array['search_path=pg_catalog, public, pg_temp'],false)
              or acl.grantee=0
              or (
                acl.grantee<>routine.proowner
                and pg_get_userbyid(acl.grantee)
                    not in ('boardagent_server','boardagent_worker')
                and not (
                  pg_get_userbyid(acl.grantee)='boardagent_backup'
                  and routine.oid='public.boardagent_context_board_allowed(uuid)'::regprocedure
                )
              )
            )
          order by identity,execute_grantee`
      );
      expect(unsafeSecurityDefiners.rows).toEqual([]);
      // SQL0148 revokes PUBLIC execution and names this exact read-only helper for
      // backup RLS evaluation. Backup receives no other definer entry point.
      const backupDefiners = await pool.query<{ identity: string }>(
        `select routine.oid::regprocedure::text as identity
           from pg_proc routine join pg_namespace namespace on namespace.oid=routine.pronamespace
          where namespace.nspname='public' and routine.prosecdef
            and has_function_privilege('boardagent_backup',routine.oid,'EXECUTE')
          order by identity`
      );
      expect(backupDefiners.rows).toEqual([{ identity: "boardagent_context_board_allowed(uuid)" }]);

      const minutesLineageTriggers = await pool.query<{
        table_name: string;
        tgdeferrable: boolean;
        tginitdeferred: boolean;
        tgname: string;
      }>(
        `select relation.relname as table_name,trigger.tgname,
                trigger.tgdeferrable,trigger.tginitdeferred
           from pg_trigger as trigger
           join pg_class as relation on relation.oid=trigger.tgrelid
          where trigger.tgname in (
            'boardagent_minutes_lineage_from_minutes',
            'boardagent_minutes_lineage_from_cycles',
            'boardagent_minutes_lineage_from_meeting'
          )
          order by trigger.tgname`
      );
      expect(minutesLineageTriggers.rows).toEqual([
        {
          table_name: "minutes_correction_cycles",
          tgdeferrable: true,
          tginitdeferred: true,
          tgname: "boardagent_minutes_lineage_from_cycles"
        },
        {
          table_name: "meetings",
          tgdeferrable: true,
          tginitdeferred: true,
          tgname: "boardagent_minutes_lineage_from_meeting"
        },
        {
          table_name: "minutes",
          tgdeferrable: true,
          tginitdeferred: true,
          tgname: "boardagent_minutes_lineage_from_minutes"
        }
      ]);
    });
  });

  it("serializes concurrent boots under the fixed advisory lock", async () => {
    await withDatabase(async (pool) => {
      const results = await Promise.all([
        migrate(pool, MIGRATIONS, "concurrent-a"),
        migrate(pool, MIGRATIONS, "concurrent-b")
      ]);
      expect(results.filter((result) => result === 0)).toHaveLength(1);
      expect(results.filter((result) => result > 0)).toHaveLength(1);
    });
  });

  it("refuses an application whose declared schema range excludes its migration target", async () => {
    await withDatabase(async (pool) => {
      const latest = (await readdir(MIGRATIONS)).filter((name) => name.endsWith(".sql")).length;
      await expect(
        migrate(pool, MIGRATIONS, "incompatible-app", {
          supportedSchemaRange: { minimum: 1, maximum: latest - 1 }
        })
      ).rejects.toThrow(`does not support bundled target schema ${String(latest)}`);
      const ledger = await pool.query<{ name: string | null }>(
        "select to_regclass('public.schema_migrations')::text as name"
      );
      expect(ledger.rows[0]?.name).toBeNull();
    });
  });

  it("refuses a noncontiguous migration ledger before applying another migration", async () => {
    await withDatabase(async (pool) => {
      const copy = await copyMigrations();
      for (const name of await readdir(copy)) {
        if (Number.parseInt(name.slice(0, 4), 10) > 3) await rm(path.join(copy, name));
      }
      expect(await migrate(pool, copy, "ledger-gap-a")).toBe(3);
      await pool.query("delete from schema_migrations where version=2");
      await expect(migrate(pool, copy, "ledger-gap-b")).rejects.toThrow(
        "migration ledger is noncontiguous"
      );
    });
  });

  it("runs later migrations as the migrator role and records bootstrapped evidence", async () => {
    await withDatabase(async (pool) => {
      const copy = await copyMigrations();
      const authorityMigrations = (await readdir(MIGRATIONS))
        .filter((name) => {
          const version = Number.parseInt(name.slice(0, 4), 10);
          return name.endsWith(".sql") && version >= 26 && version <= 34;
        })
        .toSorted();
      expect(authorityMigrations).toHaveLength(9);
      for (const name of await readdir(copy)) {
        const version = Number.parseInt(name.slice(0, 4), 10);
        if (Number.isInteger(version) && version >= 26) await rm(path.join(copy, name));
      }
      expect(await migrate(pool, copy, "pre-authority")).toBe(25);
      const organizationId = "018f0000-0000-7000-8000-000000000001";
      await pool.query(
        `insert into organizations(id,legal_name,display_name,slug,timezone)
         values ($1,'Migration Evidence Org','Migration Evidence Org','migration-evidence','UTC')`,
        [organizationId]
      );
      await pool.query(
        `insert into system_instance(instance_id,organization_id,canonical_resource_uri)
         values ('018f0000-0000-7000-8000-000000000002',$1,'https://boardagent.test/mcp')`,
        [organizationId]
      );
      for (const name of authorityMigrations) {
        await copyFile(path.join(MIGRATIONS, name), path.join(copy, name));
      }
      expect(await migrate(pool, copy, "authority-build")).toBe(authorityMigrations.length);
      const evidence = await pool.query<{
        event_type: string;
        payload: string;
        sequence: string;
      }>(
        `select event_type,sequence::text,
                convert_from(canonical_payload,'UTF8') as payload
           from audit_events order by sequence`
      );
      expect(evidence.rows).toHaveLength(authorityMigrations.length);
      expect(evidence.rows.map(({ event_type }) => event_type)).toEqual(
        authorityMigrations.map(() => "migration_applied")
      );
      expect(evidence.rows.map(({ sequence }) => sequence)).toEqual(
        authorityMigrations.map((_, index) => String(index + 1))
      );
      for (const [index, row] of evidence.rows.entries()) {
        const name = authorityMigrations[index]!;
        expect(JSON.parse(row.payload)).toMatchObject({
          eventType: "migration_applied",
          entityType: "schema_migration",
          entityId: name,
          origin: "migration",
          details: {
            version: Number.parseInt(name.slice(0, 4), 10),
            name,
            appBuild: "authority-build"
          }
        });
      }
      const wrongOwners = await pool.query<{ identity: string; owner: string }>(
        `select 'table:' || relation.tablename as identity,relation.tableowner as owner
           from pg_tables as relation
          where relation.schemaname='public' and relation.tableowner<>'boardagent_migrator'
         union all
         select 'function:' || routine.proname || '(' ||
                  pg_get_function_identity_arguments(routine.oid) || ')',owner.rolname
           from pg_proc as routine
           join pg_namespace as namespace on namespace.oid=routine.pronamespace
           join pg_roles as owner on owner.oid=routine.proowner
          where namespace.nspname='public' and owner.rolname<>'boardagent_migrator'
          order by identity`
      );
      expect(wrongOwners.rows).toEqual([]);

      await writeFile(
        path.join(copy, "0035_deliberate_authority_failure.sql"),
        "create table must_rollback_authority(id integer primary key);\nselect missing_authority_function();\n"
      );
      await expect(migrate(pool, copy, "authority-failure")).rejects.toThrow();
      const postFailure = await pool.query<{
        audit_count: string;
        maximum: number;
        rolled_back: string | null;
      }>(
        `select
           (select count(*)::text from audit_events) as audit_count,
           (select max(version)::integer from schema_migrations) as maximum,
           to_regclass('public.must_rollback_authority')::text as rolled_back`
      );
      expect(postFailure.rows[0]).toEqual({
        audit_count: String(authorityMigrations.length),
        maximum: 34,
        rolled_back: null
      });
    });
  });

  it(
    "rebuilds the exact schema after a disposable-database down and second up",
    { timeout: 30_000 },
    async () => {
      await withDatabase(async (pool) => {
        expect(await migrate(pool, MIGRATIONS, "up-down-up-a")).toBeGreaterThan(0);
        const firstInventory = await pool.query<{ tablename: string }>(
          "select tablename from pg_tables where schemaname='public' order by tablename"
        );
        expect(firstInventory.rows.map(({ tablename }) => tablename)).toEqual(ACTIVE_TABLES);

        await pool.query("drop schema public cascade");
        await pool.query("create schema public authorization current_user");
        await pool.query("grant usage on schema public to public");
        const empty = await pool.query<{ count: string }>(
          "select count(*)::text as count from pg_tables where schemaname='public'"
        );
        expect(empty.rows[0]?.count).toBe("0");

        const reapplied = await migrate(pool, MIGRATIONS, "up-down-up-b");
        expect(reapplied).toBeGreaterThan(0);
        const secondInventory = await pool.query<{ tablename: string }>(
          "select tablename from pg_tables where schemaname='public' order by tablename"
        );
        expect(secondInventory.rows.map(({ tablename }) => tablename)).toEqual(ACTIVE_TABLES);
        const ledger = await pool.query<{ count: string; distinct_hashes: string }>(
          `select count(*)::text as count,
                count(distinct sha256)::text as distinct_hashes
           from schema_migrations`
        );
        expect(ledger.rows[0]).toEqual({
          count: String(reapplied),
          distinct_hashes: String(reapplied)
        });
      });
    }
  );

  it("refuses edited and unknown migration history", async () => {
    await withDatabase(async (pool) => {
      const copy = await copyMigrations();
      await migrate(pool, copy, "history-a");
      const first = (await readdir(copy)).filter((name) => name.endsWith(".sql")).toSorted()[0]!;
      await writeFile(
        path.join(copy, first),
        `${await readFile(path.join(copy, first), "utf8")}\n-- edited\n`
      );
      await expect(migrate(pool, copy, "history-b")).rejects.toThrow("history mismatch");

      const ledger = await pool.query<{ maximum: number }>(
        "select max(version)::integer as maximum from schema_migrations"
      );
      const unknown = (ledger.rows[0]?.maximum ?? 0) + 1;
      await pool.query(
        "insert into schema_migrations(version,name,sha256,app_build) values ($1,$2,$3,$4)",
        [unknown, "unknown", "f".repeat(64), "future"]
      );
      await expect(migrate(pool, MIGRATIONS, "history-c")).rejects.toThrow(
        "unknown or downgraded migration"
      );
    });
  });

  it("rolls back a failed migration body and never records it", async () => {
    await withDatabase(async (pool) => {
      const directory = await mkdtemp(path.join(tmpdir(), "boardagent-db-failure-"));
      await writeFile(
        path.join(directory, "0001_ok.sql"),
        "create table survived(id integer primary key);\n"
      );
      await writeFile(
        path.join(directory, "0002_fails.sql"),
        "create table must_rollback(id integer primary key);\nselect missing_function();\n"
      );
      await expect(migrate(pool, directory, "failure-test")).rejects.toThrow();
      const ledger = await pool.query<{ versions: number[] }>(
        "select array_agg(version order by version) as versions from schema_migrations"
      );
      expect(ledger.rows[0]?.versions).toEqual([1]);
      const rolledBack = await pool.query<{ name: string | null }>(
        "select to_regclass('public.must_rollback')::text as name"
      );
      expect(rolledBack.rows[0]?.name).toBeNull();
    });
  });
});
