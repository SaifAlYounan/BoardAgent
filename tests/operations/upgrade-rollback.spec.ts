import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { migrate } from "../../lib/db/src/index.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";

function databaseUrl(database: string): string {
  const url = new URL(BASE_URL);
  url.pathname = `/${database}`;
  return url.toString();
}

describe("T9 first-release synthetic upgrade and restore rollback", () => {
  it.each([
    {
      label: "upgrades 85→86, refuses the old bundle, and preserves a pre-upgrade database clone",
      previous: 85,
      target: 86
    },
    {
      label:
        "AC22 upgrades original86 to the current authority schema, refuses the old binary and preserves clone rollback",
      previous: 86,
      target: null
    }
  ])(
    "$label",
    async ({ previous, target }) => {
      const suffix = `${String(process.pid)}_${Date.now().toString(36)}`;
      const sourceDatabase = `boardagent_upgrade_${suffix}`;
      const rollbackDatabase = `boardagent_rollback_${suffix}`;
      const previousBundle = await mkdtemp(path.join(tmpdir(), "boardagent-previous-migrations-"));
      const currentBundle = await mkdtemp(path.join(tmpdir(), "boardagent-current-migrations-"));
      const adminUrl = new URL(BASE_URL);
      adminUrl.pathname = "/postgres";
      const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });

      try {
        const migrations = (await readdir(MIGRATIONS))
          .filter((name) => name.endsWith(".sql"))
          .toSorted();
        const currentVersion = target ?? migrations.length;
        expect(migrations[85]).toMatch(/^0086_/u);
        expect(currentVersion).toBeGreaterThan(previous);
        for (const name of migrations.slice(0, currentVersion))
          await copyFile(path.join(MIGRATIONS, name), path.join(currentBundle, name));
        for (const name of migrations.slice(0, previous)) {
          await copyFile(path.join(MIGRATIONS, name), path.join(previousBundle, name));
        }

        await admin.query(`create database "${sourceDatabase}"`);
        let source = new Pool({ connectionString: databaseUrl(sourceDatabase), max: 2 });
        try {
          expect(
            await migrate(source, previousBundle, "synthetic-previous-release", {
              supportedSchemaRange: { minimum: previous, maximum: previous }
            })
          ).toBe(previous);
          await source.query(
            `insert into organizations(id,legal_name,display_name,slug,timezone)
           values ('018f0000-0000-7000-8000-000000000001',
                   'Upgrade Evidence Ltd','Upgrade Evidence','upgrade-evidence','UTC')`
          );
        } finally {
          await source.end();
        }

        await admin.query(`create database "${rollbackDatabase}" template "${sourceDatabase}"`);
        source = new Pool({ connectionString: databaseUrl(sourceDatabase), max: 2 });
        try {
          expect(await migrate(source, currentBundle, "current-release")).toBe(
            currentVersion - previous
          );
          expect(
            (
              await source.query<{ version: number }>(
                "select max(version)::integer as version from schema_migrations"
              )
            ).rows[0]
          ).toEqual({ version: currentVersion });
          expect(
            (
              await source.query<{ function_name: string | null }>(
                "select to_regprocedure('boardagent_member_lifecycle_snapshot(jsonb)')::text as function_name"
              )
            ).rows[0]?.function_name
          ).toBe("boardagent_member_lifecycle_snapshot(jsonb)");
          if (previous === 86) {
            for (const table of [
              "company_admin_proposals",
              "member_admin_delegations",
              "administrative_authority_changes"
            ])
              expect(
                (await source.query(`select count(*)::int as n from ${table}`)).rows[0]?.n
              ).toBe(0);
          }
          await expect(
            migrate(source, previousBundle, "old-release-downgrade", {
              supportedSchemaRange: { minimum: previous, maximum: previous }
            })
          ).rejects.toThrow("unknown or downgraded migration");
        } finally {
          await source.end();
        }

        const rollback = new Pool({ connectionString: databaseUrl(rollbackDatabase), max: 2 });
        try {
          expect(
            await migrate(rollback, previousBundle, "restored-previous-release", {
              supportedSchemaRange: { minimum: previous, maximum: previous }
            })
          ).toBe(0);
          expect(
            (
              await rollback.query<{ display_name: string }>(
                "select display_name from organizations where slug='upgrade-evidence'"
              )
            ).rows
          ).toEqual([{ display_name: "Upgrade Evidence" }]);
          expect(
            (
              await rollback.query<{ function_name: string | null }>(
                "select to_regprocedure('boardagent_member_lifecycle_snapshot(jsonb)')::text as function_name"
              )
            ).rows[0]?.function_name
          ).toBe(previous < 86 ? null : "boardagent_member_lifecycle_snapshot(jsonb)");

          if (previous === 86)
            expect(
              (
                await rollback.query(
                  "select to_regclass('public.member_admin_delegations')::text as name"
                )
              ).rows[0]?.name
            ).toBeNull();
          expect(await migrate(rollback, currentBundle, "current-release-after-rollback")).toBe(
            currentVersion - previous
          );
          expect(
            (
              await rollback.query<{ display_name: string }>(
                "select display_name from organizations where slug='upgrade-evidence'"
              )
            ).rows
          ).toEqual([{ display_name: "Upgrade Evidence" }]);
        } finally {
          await rollback.end();
        }
      } finally {
        await admin.query(`drop database if exists "${sourceDatabase}" with (force)`);
        await admin.query(`drop database if exists "${rollbackDatabase}" with (force)`);
        await admin.end();
        await rm(previousBundle, { recursive: true, force: true });
        await rm(currentBundle, { recursive: true, force: true });
      }
    },
    180_000
  );
});
