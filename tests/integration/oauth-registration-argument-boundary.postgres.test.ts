import { randomBytes } from "node:crypto";
import { copyFile, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { canonicalSha256, sha256Hex } from "../../lib/contracts/src/index.js";
import { loadMigrations, migrate, withIdentityTransaction } from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";

const organizationId = testId(880_001);
const redirect = "https://synthetic-client.example/oauth/callback";
const scope = "documents:read";
const registrationSql = `select result_internal_id,result_inserted
  from public.boardagent_register_oauth_client($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`;

function candidate(method: "cimd" | "dcr", ordinal: number, maximum = 10): unknown[] {
  const name = "Synthetic registration boundary client";
  const protocolId =
    method === "cimd"
      ? `https://synthetic-client.example/metadata/${ordinal}`
      : `ba_dcr_${String(ordinal).padStart(43, "a")}`;
  const metadata = {
    client_name: name,
    redirect_uris: [redirect],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope,
    ...(method === "cimd" ? { client_id: protocolId } : {})
  };
  return [
    organizationId,
    testId(880_100 + ordinal),
    method === "cimd" ? "verified_cimd_url" : "dcr_opaque",
    protocolId,
    { schemaVersion: 1, registrationMethod: method, name },
    Buffer.from(canonicalSha256(metadata), "hex"),
    [redirect],
    [Buffer.from(sha256Hex(redirect), "hex")],
    [scope],
    maximum
  ];
}

async function register(pool: Pool, args: readonly unknown[]) {
  return withIdentityTransaction(
    pool,
    { organizationId },
    async (client) => {
      return (
        await client.query<{ result_internal_id: string; result_inserted: boolean }>(
          registrationSql,
          [...args]
        )
      ).rows;
    },
    { assumeRole: "boardagent_server" }
  );
}

async function snapshot(pool: Pool) {
  const clients = await pool.query(
    `select id,organization_id,protocol_id_kind,protocol_id_value,safe_metadata,
       encode(metadata_sha256,'hex') as metadata_sha256,state,registered_by,registered_at::text
     from oauth_clients where organization_id=$1 order by id`,
    [organizationId]
  );
  const redirects = await pool.query(
    `select child.client_id,child.redirect_uri,encode(child.redirect_uri_sha256,'hex') as redirect_uri_sha256,child.created_at::text
     from oauth_client_redirect_uris child join oauth_clients parent on parent.id=child.client_id
     where parent.organization_id=$1 order by child.client_id,child.redirect_uri`,
    [organizationId]
  );
  const grants = await pool.query(
    `select child.client_id,child.grant_type,child.scope,child.created_at::text
     from oauth_client_grants child join oauth_clients parent on parent.id=child.client_id
     where parent.organization_id=$1 order by child.client_id,child.grant_type,child.scope`,
    [organizationId]
  );
  return { clients: clients.rows, redirects: redirects.rows, grants: grants.rows };
}

async function attempted(pool: Pool, args: readonly unknown[]) {
  try {
    return { result: await register(pool, args), error: null };
  } catch (error) {
    return {
      result: null,
      error: {
        code: error && typeof error === "object" && "code" in error ? error.code : null,
        message: error instanceof Error ? error.message : String(error)
      }
    };
  }
}

type RecordEvidence = (filename: string, value: unknown) => Promise<void>;

async function withRegistrationDatabase(
  label: string,
  run: (pool: Pool, record: RecordEvidence) => Promise<void>,
  initialVersion?: number
) {
  const base = new URL(
    process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
      "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent"
  );
  if (!["127.0.0.1", "localhost"].includes(base.hostname))
    throw new Error("OAuth boundary test requires local disposable PostgreSQL");
  const directoryRoot =
    process.env["BOARDAGENT_OAUTH_BOUNDARY_EVIDENCE_DIRECTORY"] ??
    path.resolve("artifacts/verification/execution-runs/oauth-registration-argument-boundary");
  if (!path.isAbsolute(directoryRoot))
    throw new Error("OAuth boundary evidence directory must be absolute");
  await mkdir(directoryRoot, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(path.join(directoryRoot, `${label}-`));
  const record: RecordEvidence = (filename, value) =>
    writeFile(path.join(directory, filename), JSON.stringify(value, null, 2) + "\n", {
      mode: 0o600
    });
  const database = `boardagent_oauth_arg_${process.pid}_${randomBytes(4).toString("hex")}`;
  const ownerUrl = new URL(base);
  ownerUrl.pathname = "/postgres";
  const owner = new Pool({ connectionString: ownerUrl.toString(), max: 1 });
  base.pathname = `/${database}`;
  const pool = new Pool({ connectionString: base.toString(), max: 4 });
  let created = false;
  let passed = false;
  let dropped = false;
  try {
    await owner.query(`create database "${database}"`);
    created = true;
    await record("fixture.json", {
      database,
      host: base.hostname,
      port: base.port,
      label,
      synthetic: true
    });
    const currentMigrations = path.resolve("lib/db/migrations");
    let initialMigrations = currentMigrations;
    if (initialVersion !== undefined) {
      initialMigrations = path.join(directory, "initial-migrations");
      await mkdir(initialMigrations, { mode: 0o700 });
      const prefix = (await loadMigrations(currentMigrations)).filter(
        ({ version }) => version <= initialVersion
      );
      expect(prefix).toHaveLength(initialVersion);
      for (const migration of prefix)
        await copyFile(
          path.join(currentMigrations, migration.name),
          path.join(initialMigrations, migration.name)
        );
    }
    await migrate(pool, initialMigrations, "oauth-required-argument-boundary");
    await record(
      "schema.json",
      (await pool.query("select version,name,sha256 from schema_migrations order by version")).rows
    );
    await pool.query(
      "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Synthetic boundary organization','Synthetic boundary','oauth-boundary','UTC')",
      [organizationId]
    );
    await run(pool, record);
    passed = true;
  } catch (error) {
    await record("failure.json", {
      message: error instanceof Error ? error.message : String(error)
    });
    if (created)
      await record("normalized-at-failure.json", await snapshot(pool)).catch(() => undefined);
    throw error;
  } finally {
    await pool.end();
    try {
      if (passed && created) {
        await dropClosedTestDatabase(owner, database);
        dropped = true;
      }
    } finally {
      await owner.end();
      await record("lifecycle.json", { database, passed, preserved: created && !dropped });
      console.info(
        JSON.stringify({
          probe: "oauth-required-argument-boundary",
          label,
          database,
          passed,
          preserved: created && !dropped,
          directory
        })
      );
    }
  }
}

const malformed = [
  {
    label: "null-cap",
    change: (args: unknown[]) => {
      args[9] = null;
    }
  },
  {
    label: "null-redirect-arrays",
    change: (args: unknown[]) => {
      args[6] = null;
      args[7] = null;
    }
  },
  {
    label: "null-scopes",
    change: (args: unknown[]) => {
      args[8] = null;
    }
  },
  {
    label: "missing-name",
    change: (args: unknown[]) => {
      delete (args[4] as Record<string, unknown>)["name"];
    }
  },
  {
    label: "missing-schema-version",
    change: (args: unknown[]) => {
      delete (args[4] as Record<string, unknown>)["schemaVersion"];
    }
  },
  {
    label: "json-null-name",
    change: (args: unknown[]) => {
      (args[4] as Record<string, unknown>)["name"] = null;
    }
  },
  {
    label: "json-null-schema-version",
    change: (args: unknown[]) => {
      (args[4] as Record<string, unknown>)["schemaVersion"] = null;
    }
  },
  {
    label: "only-null-redirect-uris",
    change: (args: unknown[]) => {
      args[6] = null;
    }
  },
  {
    label: "only-null-redirect-hashes",
    change: (args: unknown[]) => {
      args[7] = null;
    }
  },
  {
    label: "null-internal-id",
    change: (args: unknown[]) => {
      args[1] = null;
    }
  },
  {
    label: "null-protocol-kind",
    change: (args: unknown[]) => {
      args[2] = null;
    }
  },
  {
    label: "null-safe-metadata",
    change: (args: unknown[]) => {
      args[4] = null;
    }
  },
  {
    label: "null-protocol-value",
    change: (args: unknown[]) => {
      args[3] = null;
    }
  },
  {
    label: "null-metadata-digest",
    change: (args: unknown[]) => {
      args[5] = null;
    }
  }
] as const;

describe("OAuth managed SQL registration required arguments", () => {
  it.each(malformed)(
    "refuses $label before creating any normalized authority",
    async ({ label, change }) => {
      await withRegistrationDatabase(label, async (pool, record) => {
        // Establish real complete authority first. Keep capacity available for shape cases,
        // so an unrelated capacity refusal cannot mask malformed rows being accepted.
        await register(pool, candidate("dcr", 1, 1));
        const args = candidate("dcr", 2, label === "null-cap" ? 1 : 10);
        change(args);
        const before = await snapshot(pool);
        await record("normalized-before.json", before);
        const outcome = await attempted(pool, args);
        const after = await snapshot(pool);
        await record("attempt.json", { label, outcome });
        await record("normalized-after.json", after);
        // Capture the committed result before assertions: unexpected success must not
        // be hidden by a test rollback or followed by destructive fixture cleanup.
        expect(after).toEqual(before);
        expect(outcome).toMatchObject({ result: null, error: { code: "22023" } });
      });
    },
    30_000
  );

  it.each(
    malformed.filter(({ label }) =>
      ["null-cap", "null-redirect-arrays", "null-scopes", "null-internal-id"].includes(label)
    )
  )(
    "refuses $label on an existing CIMD replay",
    async ({ label, change }) => {
      await withRegistrationDatabase(`replay-${label}`, async (pool, record) => {
        const original = candidate("cimd", 1, 1);
        await register(pool, original);
        const args = candidate("cimd", 1, 1);
        args[1] = testId(880_999);
        change(args);
        const before = await snapshot(pool);
        await record("normalized-before.json", before);
        const outcome = await attempted(pool, args);
        const after = await snapshot(pool);
        await record("attempt.json", { label, outcome });
        await record("normalized-after.json", after);
        expect(after).toEqual(before);
        expect(outcome).toMatchObject({ result: null, error: { code: "22023" } });
      });
    },
    30_000
  );

  it("registers complete DCR authority with exactly the normalized redirects and grants", async () => {
    await withRegistrationDatabase("valid-dcr", async (pool, record) => {
      const args = candidate("dcr", 1, 1);
      expect(await register(pool, args)).toEqual([
        { result_internal_id: args[1], result_inserted: true }
      ]);
      const stored = await snapshot(pool);
      await record("normalized-after.json", stored);
      expect(stored.clients).toHaveLength(1);
      expect(stored.clients[0]).toMatchObject({
        id: args[1],
        safe_metadata: args[4],
        state: "active"
      });
      expect(stored.redirects).toHaveLength(1);
      expect(stored.redirects[0]).toMatchObject({
        client_id: args[1],
        redirect_uri: redirect,
        redirect_uri_sha256: sha256Hex(redirect)
      });
      expect(
        stored.grants.map(({ client_id, grant_type, scope: value }) => ({
          client_id,
          grant_type,
          scope: value
        }))
      ).toEqual([
        { client_id: args[1], grant_type: "authorization_code", scope },
        { client_id: args[1], grant_type: "refresh_token", scope }
      ]);
    });
  }, 30_000);

  it("permits exact CIMD replay at capacity and refuses a new client without changing authority", async () => {
    await withRegistrationDatabase("valid-replay-cap", async (pool, record) => {
      const original = candidate("cimd", 1, 1);
      expect(await register(pool, original)).toEqual([
        { result_internal_id: original[1], result_inserted: true }
      ]);
      const before = await snapshot(pool);
      await record("normalized-before.json", before);
      const replay = candidate("cimd", 1, 1);
      replay[1] = testId(880_999);
      expect(await register(pool, replay)).toEqual([
        { result_internal_id: original[1], result_inserted: false }
      ]);
      expect(await snapshot(pool)).toEqual(before);
      const refused = await attempted(pool, candidate("dcr", 2, 1));
      await record("attempt.json", { refused });
      expect(refused).toMatchObject({ result: null, error: { code: "54000" } });
      const after = await snapshot(pool);
      await record("normalized-after.json", after);
      expect(after).toEqual(before);
    });
  }, 30_000);

  it("upgrades existing schema 163 registration authority without changing client rows or function permissions", async () => {
    await withRegistrationDatabase(
      "upgrade-163",
      async (pool, record) => {
        const schemaRows = async () =>
          (
            await pool.query(
              "select version,name,sha256,app_build,applied_at::text from schema_migrations order by version"
            )
          ).rows;
        const functionAuthority = async () =>
          (
            await pool.query(
              `select procedure_row.oid::text as oid,pg_get_userbyid(procedure_row.proowner) as owner,
           procedure_row.prosecdef,procedure_row.proconfig,procedure_row.provolatile,procedure_row.proisstrict,
           procedure_row.proacl::text as acl,
           has_function_privilege('boardagent_server',procedure_row.oid,'EXECUTE') as server_execute,
           has_function_privilege('boardagent_worker',procedure_row.oid,'EXECUTE') as worker_execute,
           exists (select 1 from aclexplode(coalesce(procedure_row.proacl,acldefault('f',procedure_row.proowner))) as privilege
             where privilege.grantee=0 and privilege.privilege_type='EXECUTE') as public_execute
         from pg_proc as procedure_row join pg_namespace as namespace on namespace.oid=procedure_row.pronamespace
         where namespace.nspname='public' and procedure_row.proname='boardagent_register_oauth_client'`
            )
          ).rows;
        const beforeSchema = await schemaRows();
        expect(beforeSchema).toHaveLength(163);
        expect(beforeSchema.at(-1)).toMatchObject({ version: 163 });
        const dcr = candidate("dcr", 1);
        const cimd = candidate("cimd", 2);
        expect(await register(pool, dcr)).toEqual([
          { result_internal_id: dcr[1], result_inserted: true }
        ]);
        expect(await register(pool, cimd)).toEqual([
          { result_internal_id: cimd[1], result_inserted: true }
        ]);
        const before = await snapshot(pool);
        expect(before.clients).toHaveLength(2);
        expect(before.redirects).toHaveLength(2);
        expect(before.grants).toHaveLength(4);
        const authorityBefore = await functionAuthority();
        await record("upgrade-before.json", {
          schema: beforeSchema,
          normalized: before,
          authority: authorityBefore
        });
        expect(authorityBefore).toHaveLength(1);
        expect(authorityBefore[0]).toMatchObject({
          owner: "boardagent_migrator",
          prosecdef: true,
          proconfig: ["search_path=pg_catalog, public, pg_temp"],
          provolatile: "v",
          proisstrict: false,
          server_execute: true,
          worker_execute: false,
          public_execute: false
        });

        // Apply the real append-only current bundle to this existing database. The
        // recorded run is 163 -> 164; later bundles must preserve the same authority.
        const currentMigrations = path.resolve("lib/db/migrations");
        const current = await loadMigrations(currentMigrations);
        expect(current.length).toBeGreaterThanOrEqual(164);
        expect(await migrate(pool, currentMigrations, "oauth-required-argument-upgrade")).toBe(
          current.length - 163
        );
        const afterSchema = await schemaRows();
        const after = await snapshot(pool);
        const authorityAfter = await functionAuthority();
        await record("upgrade-after.json", {
          schema: afterSchema,
          normalized: after,
          authority: authorityAfter
        });
        expect(afterSchema.slice(0, 163)).toEqual(beforeSchema);
        expect(afterSchema).toHaveLength(current.length);
        expect(afterSchema[163]).toMatchObject({
          version: 164,
          name: "0164_oauth_registration_required_arguments.sql"
        });
        expect(after).toEqual(before);
        expect(authorityAfter).toEqual(authorityBefore);

        const invalid = candidate("dcr", 3);
        invalid[9] = null;
        const refused = await attempted(pool, invalid);
        await record("upgrade-refusal.json", refused);
        expect(refused).toMatchObject({ result: null, error: { code: "22023" } });
        const replay = candidate("cimd", 2);
        replay[1] = testId(880_999);
        expect(await register(pool, replay)).toEqual([
          { result_internal_id: cimd[1], result_inserted: false }
        ]);
        const final = await snapshot(pool);
        await record("normalized-after-replay.json", final);
        expect(final).toEqual(before);
      },
      163
    );
  }, 30_000);
});
