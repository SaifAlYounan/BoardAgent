/*
 * Adapted from LQGovernance-OpenBoard, commit
 * 1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb, lib/db/src/migrate.ts.
 * Copyright (c) 2026 Alexios Kirillov. Licensed under the Apache License 2.0.
 * Derived from LQGovernance-OpenBoard (MIT License); see docs/THIRD_PARTY_NOTICES.md.
 * Hostile changes: bounded advisory-lock acquisition, manifest checksums, monotonic
 * history validation, explicit transactionality and downgrade/unknown-version refusal.
 */
import { randomBytes } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

import type { Pool, PoolClient } from "pg";

import { sha256Hex } from "@boardagent/contracts";
import { uuidV7 } from "@boardagent/domain";

import { appendAuditEventsInTransaction } from "./transactions/audit.js";

export interface MigrationFile {
  readonly version: number;
  readonly name: string;
  readonly sha256: string;
  readonly sql: string;
}

export interface SupportedSchemaRange {
  readonly minimum: number;
  readonly maximum: number;
}

export interface MigrationOptions {
  readonly lockTimeoutMs?: number;
  readonly assumeRole?: "boardagent_migrator";
  /**
   * Application/schema compatibility declared by the booting binary. The bundle's
   * target schema must fall inside this closed interval or readiness is refused.
   */
  readonly supportedSchemaRange?: SupportedSchemaRange;
}

const MIGRATION_PATTERN = /^(\d{4})_([a-z0-9_]+)\.sql$/u;
const ADVISORY_LOCK_KEY = 4_242_486_065_882_889n;

export async function loadMigrations(directory: string): Promise<readonly MigrationFile[]> {
  const names = (await readdir(directory))
    .filter((name) => MIGRATION_PATTERN.test(name))
    .toSorted();
  const migrations = await Promise.all(
    names.map(async (name) => {
      const match = MIGRATION_PATTERN.exec(name);
      if (!match) throw new Error(`invalid migration filename: ${name}`);
      const sql = await readFile(path.join(directory, name), "utf8");
      return { version: Number(match[1]), name, sha256: sha256Hex(sql), sql };
    })
  );
  migrations.forEach((migration, index) => {
    if (migration.version !== index + 1)
      throw new Error("migration versions must be contiguous from 0001");
  });
  return migrations;
}

async function acquireLock(client: PoolClient, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await client.query<{ acquired: boolean }>(
      "select pg_try_advisory_lock($1) as acquired",
      [ADVISORY_LOCK_KEY.toString()]
    );
    if (result.rows[0]?.acquired) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("timed out acquiring migration advisory lock");
}

async function releaseMigrationClient(
  client: PoolClient,
  locked: boolean,
  assumedRole: boolean
): Promise<void> {
  try {
    if (locked) await client.query("select pg_advisory_unlock($1)", [ADVISORY_LOCK_KEY.toString()]);
    if (assumedRole) await client.query("reset role");
  } catch (error) {
    // A connection with an unproven lock/role reset must not return to the pool.
    client.release(true);
    throw error;
  }
  client.release();
}

async function ensureLedger(client: PoolClient): Promise<void> {
  await client.query(`
    create table if not exists schema_migrations (
      version integer primary key,
      name text not null unique,
      sha256 text not null,
      applied_at timestamptz not null default transaction_timestamp(),
      app_build text not null,
      constraint schema_migrations_hash_ck check (sha256 ~ '^[0-9a-f]{64}$')
    )
  `);
}

async function appendMigrationAuditIfBootstrapped(
  client: PoolClient,
  migration: MigrationFile,
  appBuild: string
): Promise<void> {
  const instance = await client.query<{ organization_id: string }>(
    "select organization_id from system_instance where singleton_key"
  );
  const organizationId = instance.rows[0]?.organization_id;
  if (!organizationId) return;
  await client.query("select set_config('boardagent.transaction_scope','migration',true)");
  await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      event: {
        eventId: uuidV7(Date.now(), randomBytes(10)),
        eventType: "migration_applied",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "schema_migration",
        entityId: migration.name,
        boardId: null,
        origin: "migration",
        details: {
          version: migration.version,
          name: migration.name,
          sha256: migration.sha256,
          appBuild
        },
        schemaVersion: 1
      }
    }
  ]);
}

export async function migrate(
  pool: Pool,
  directory: string,
  appBuild: string,
  options: MigrationOptions = {}
): Promise<number> {
  const migrations = await loadMigrations(directory);
  const targetVersion = migrations.at(-1)?.version ?? 0;
  const supported = options.supportedSchemaRange ?? {
    minimum: targetVersion,
    maximum: targetVersion
  };
  if (
    !Number.isSafeInteger(supported.minimum) ||
    !Number.isSafeInteger(supported.maximum) ||
    supported.minimum < 0 ||
    supported.maximum < supported.minimum
  ) {
    throw new Error("invalid supported application/schema range");
  }
  if (targetVersion < supported.minimum || targetVersion > supported.maximum) {
    throw new Error(
      `application does not support bundled target schema ${String(targetVersion)} ` +
        `(supported ${String(supported.minimum)}..${String(supported.maximum)})`
    );
  }
  const client = await pool.connect();
  let locked = false;
  let assumedRole = false;
  try {
    if (options.assumeRole) {
      await client.query(`set role ${options.assumeRole}`);
      assumedRole = true;
    }
    await acquireLock(client, options.lockTimeoutMs ?? 30_000);
    locked = true;
    await ensureLedger(client);
    const applied = await client.query<{ version: number; name: string; sha256: string }>(
      "select version, name, sha256 from schema_migrations order by version"
    );
    for (const [index, row] of applied.rows.entries()) {
      if (row.version !== index + 1) {
        throw new Error(`migration ledger is noncontiguous at ${String(index + 1)}`);
      }
      const expected = migrations[row.version - 1];
      if (!expected) throw new Error(`database has unknown or downgraded migration ${row.version}`);
      if (expected.name !== row.name || expected.sha256 !== row.sha256) {
        throw new Error(`migration history mismatch at ${row.version}`);
      }
    }
    const pending = migrations.slice(applied.rowCount ?? applied.rows.length);
    // Historical bundles retain per-file commits. Recovery-aware bundles install
    // their pending DDL before producing ledger/audit pairs in the same transaction;
    // otherwise an old full audit queue would prevent installing its own repair.
    // Initial role/bootstrap ownership through 0025 keeps its established ordering.
    const recoveryAware = migrations.some(
      ({ name }) => name === "0126_migration_audit_admission.sql"
    );
    const groups: MigrationFile[][] = [];
    for (const migration of pending) {
      if (!recoveryAware || migration.version <= 25) groups.push([migration]);
      else {
        const batch = pending.filter(({ version }) => version >= migration.version);
        groups.push(batch);
        break;
      }
    }
    let count = 0;
    for (const group of groups) {
      await client.query("begin");
      try {
        await client.query("set local lock_timeout = '10s'");
        await client.query("set local statement_timeout = '60s'");
        if (group[0]!.version > 25) await client.query("set local role boardagent_migrator");
        for (const migration of group) {
          await client.query(migration.sql);
          if (migration.version === 25) await client.query("set local role boardagent_migrator");
        }
        if (group[0]!.version >= 25)
          await client.query("select set_config('boardagent.transaction_scope','migration',true)");
        for (const migration of group) {
          await client.query(
            "insert into schema_migrations(version, name, sha256, app_build) values ($1,$2,$3,$4)",
            [migration.version, migration.name, migration.sha256, appBuild]
          );
          if (migration.version >= 25)
            await appendMigrationAuditIfBootstrapped(client, migration, appBuild);
        }
        await client.query("commit");
        count += group.length;
      } catch (error) {
        await client.query("rollback");
        throw error;
      }
    }
    return count;
  } finally {
    await releaseMigrationClient(client, locked, assumedRole);
  }
}
