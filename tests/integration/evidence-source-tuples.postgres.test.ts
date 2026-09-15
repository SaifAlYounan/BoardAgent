import { randomBytes } from "node:crypto";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";

import { canonicalJson, canonicalSha256, sha256Hex } from "../../lib/contracts/src/index.js";
import {
  createMeetingTranscriptVersionInTransaction,
  createMinutesVersionInTransaction,
  migrate,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const TUPLE_MIGRATION = "0159_complete_optional_evidence_tuples.sql";

async function withLegacyDatabase(
  run: (pool: Pool, upgrade: () => Promise<number>) => Promise<void>
) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "boardagent-evidence-tuples-"));
  const database = `boardagent_tuple_legacy_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
  const databaseUrl = new URL(
    process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
      "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent"
  );
  databaseUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: databaseUrl.toString(), max: 1 });
  let pool: Pool | undefined;
  let created = false;
  try {
    // Copy the real historical files byte for byte. No constraint, trigger, grant,
    // RLS policy or evidence row is altered to make a legacy fixture possible.
    for (const name of await readdir(MIGRATIONS)) {
      if (/^\d{4}_[a-z0-9_]+\.sql$/u.test(name) && Number(name.slice(0, 4)) <= 158) {
        await copyFile(path.join(MIGRATIONS, name), path.join(directory, name));
      }
    }
    await admin.query(`create database "${database}"`);
    created = true;
    databaseUrl.pathname = `/${database}`;
    const legacyPool = new Pool({ connectionString: databaseUrl.toString(), max: 2 });
    pool = legacyPool;
    expect(await migrate(legacyPool, directory, "tuple-legacy-test")).toBe(158);
    await run(legacyPool, async () => {
      await copyFile(path.join(MIGRATIONS, TUPLE_MIGRATION), path.join(directory, TUPLE_MIGRATION));
      return migrate(legacyPool, directory, "tuple-upgrade-test");
    });
  } finally {
    await pool?.end();
    if (created) await dropClosedTestDatabase(admin, database);
    await admin.end();
    await rm(directory, { recursive: true, force: true });
  }
}

async function evidenceRows(pool: Pool) {
  // Database-rendered text retains all stored fields, including bytea values and
  // microsecond timestamps, rather than a selectively reconstructed payload.
  return {
    minutes: (
      await pool.query("select row_to_json(r)::text as row from minutes_versions r order by id")
    ).rows,
    tasks: (await pool.query("select row_to_json(r)::text as row from tasks r order by id")).rows
  };
}

async function ledgerRows(pool: Pool) {
  return (
    await pool.query("select row_to_json(r)::text as row from schema_migrations r order by version")
  ).rows;
}

async function auditRows(pool: Pool) {
  return (await pool.query("select row_to_json(r)::text as row from audit_events r order by id"))
    .rows;
}

async function tupleConstraints(pool: Pool) {
  return (
    await pool.query(`select conname, convalidated from pg_constraint
      where (conrelid='public.minutes_versions'::regclass and conname='minutes_versions_transcript_tuple_ck')
         or (conrelid='public.tasks'::regclass and conname='tasks_minutes_source_tuple_ck')
      order by conname`)
  ).rows;
}

async function fixture(pool: Pool) {
  const actor = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["secretariat:admin", "meeting:act", "minutes:act"],
    isSecretary: true
  });
  const meetingId = testId(788001);
  const minutesId = testId(788002);
  const minutesVersionId = testId(788003);
  const transcriptVersionId = testId(788004);
  const minutesText = "# Synthetic minutes\nThe committee reviewed the exploration programme.\n";
  const minutesSha256 = sha256Hex(minutesText);
  await pool.query(
    `insert into meetings(id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by)
     values($1,$2,$3,'Synthetic evidence tuple meeting','called',
       transaction_timestamp()+interval '1 hour',transaction_timestamp()+interval '2 hours',$4)`,
    [meetingId, actor.organizationId, actor.boardId, actor.memberId]
  );
  const request = <T>(run: (client: PoolClient) => Promise<T>) =>
    withRequestTransaction(pool, actor.context, run, { assumeRole: "boardagent_server" });
  await request(async (client) => {
    expect(
      (
        await client.query(`select current_user as role,
          row_security_active('public.minutes_versions'::regclass) as minutes_rls,
          row_security_active('public.tasks'::regclass) as tasks_rls`)
      ).rows[0]
    ).toEqual({ role: "boardagent_server", minutes_rls: true, tasks_rls: true });
  });

  // Referenced annex/minutes evidence is created by the real request-role producers.
  // The tested INSERTs below isolate SQL tuple shape, not a public MCP attack path.
  const transcript = await request((client) =>
    createMeetingTranscriptVersionInTransaction(client, {
      meetingId,
      transcriptId: testId(788005),
      transcriptVersionId,
      mediaType: "application/json",
      canonicalBody: canonicalJson({
        schema_version: "boardagent.transcript-turns.v1",
        values: {
          turns: [
            {
              canonical_text: "The synthetic exploration programme was reviewed.",
              starts_at_ms: 1000,
              ends_at_ms: 2000,
              speaker_label: "Secretary",
              speaker_member_id: actor.memberId,
              turn_id: testId(788006)
            }
          ]
        }
      }),
      coverageStatement: "Synthetic fixture only; no real meeting or recording.",
      supersedesVersionId: null,
      idempotencyRecordId: testId(788007),
      idempotencyKey: "evidence-tuple-transcript-0001",
      auditEventId: testId(788008)
    })
  );
  await request((client) =>
    createMinutesVersionInTransaction(client, {
      meetingId,
      minutesId,
      minutesVersionId,
      canonicalText: minutesText,
      transcriptVersionId: null,
      expectedCurrentVersionId: null,
      idempotencyRecordId: testId(788009),
      idempotencyKey: "evidence-tuple-minutes-0001",
      auditEventId: testId(788010)
    })
  );

  const insertMinutes = (annex: "none" | "complete" | "missing_hash") => {
    const versionId = annex === "none" ? null : transcriptVersionId;
    const hash = annex === "complete" ? transcript.canonicalSha256 : null;
    const packageHash = canonicalSha256({
      schemaVersion: "boardagent.minutes-package-base.v1",
      minutesId,
      version: 2,
      canonicalSha256: minutesSha256,
      transcriptVersionId: versionId,
      transcriptSha256: hash
    });
    return request((client) =>
      client.query(
        `insert into minutes_versions(id,organization_id,board_id,minutes_id,version,
          canonical_schema,canonical_text,canonical_sha256,package_base_sha256,
          transcript_version_id,transcript_sha256,created_by,supersedes_id)
         values($1,$2,$3,$4,2,'boardagent.minutes.v1',$5,$6,$7,$8,$9,$10,$11)`,
        [
          testId(788011),
          actor.organizationId,
          actor.boardId,
          minutesId,
          minutesText,
          Buffer.from(minutesSha256, "hex"),
          Buffer.from(packageHash, "hex"),
          versionId,
          hash === null ? null : Buffer.from(hash, "hex"),
          actor.memberId,
          minutesVersionId
        ]
      )
    );
  };
  const insertTask = (
    source: "none" | "complete" | "missing_hash" | "missing_locator" | "missing_both"
  ) => {
    const sourced = source !== "none";
    const hash = source === "complete" || source === "missing_locator" ? minutesSha256 : null;
    const locator =
      source === "complete" || source === "missing_hash"
        ? { sourceType: "minutes_version", minutesId, minutesVersionId }
        : null;
    return request((client) =>
      client.query(
        `insert into tasks(id,organization_id,board_id,owner_member_id,due_at,description_schema,
          canonical_description,required_evidence,task_sha256,state,created_by,
          source_meeting_id,source_minutes_id,source_minutes_version_id,source_minutes_sha256,source_locator)
         values($1,$2,$3,$4,transaction_timestamp()+interval '1 day','boardagent.task.v1',
          'Prepare the synthetic programme summary.','{"items":["Canonical summary"]}'::jsonb,$5,$6,$4,
          $7,$8,$9,$10,$11::jsonb)`,
        [
          testId(788012),
          actor.organizationId,
          actor.boardId,
          actor.memberId,
          Buffer.from(
            canonicalSha256({ source, minutesId, minutesVersionId, hash, locator }),
            "hex"
          ),
          sourced ? "draft" : "open",
          sourced ? meetingId : null,
          sourced ? minutesId : null,
          sourced ? minutesVersionId : null,
          hash === null ? null : Buffer.from(hash, "hex"),
          locator === null ? null : JSON.stringify(locator)
        ]
      )
    );
  };
  return { insertMinutes, insertTask };
}

async function expectRejectedWithoutEvidence(
  pool: Pool,
  insert: () => Promise<unknown>
): Promise<void> {
  const counts = async () =>
    (
      await pool.query(`select
        (select count(*)::int from minutes_versions) as minutes_versions,
        (select count(*)::int from tasks) as tasks,
        (select count(*)::int from audit_events) as audit_events`)
    ).rows;
  const before = await counts();
  const outcome = await insert().then(
    () => ({ accepted: true, code: null }),
    (error: unknown) => ({
      accepted: false,
      code: typeof error === "object" && error !== null && "code" in error ? error.code : null
    })
  );
  expect({ outcome, after: await counts() }).toEqual({
    outcome: { accepted: false, code: "23514" },
    after: before
  });
}

describe("optional evidence source tuples at the SQL request boundary", () => {
  it.each(["none", "complete"] as const)("accepts a %s minutes annex tuple", async (annex) => {
    await withMigratedDatabase("minutes-tuple-control", async (pool) => {
      const f = await fixture(pool);
      await expect(f.insertMinutes(annex)).resolves.toMatchObject({ rowCount: 1 });
    });
  });

  it("rejects an annex version with a SQL NULL transcript hash", async () => {
    await withMigratedDatabase("minutes-tuple-null", async (pool) => {
      const f = await fixture(pool);
      await expectRejectedWithoutEvidence(pool, () => f.insertMinutes("missing_hash"));
    });
  });

  it.each(["none", "complete"] as const)("accepts a %s task source tuple", async (source) => {
    await withMigratedDatabase("task-tuple-control", async (pool) => {
      const f = await fixture(pool);
      await expect(f.insertTask(source)).resolves.toMatchObject({ rowCount: 1 });
    });
  });

  it.each(["missing_hash", "missing_locator", "missing_both"] as const)(
    "rejects a sourced draft task with %s as SQL NULL",
    async (source) => {
      await withMigratedDatabase("task-tuple-null", async (pool) => {
        const f = await fixture(pool);
        await expectRejectedWithoutEvidence(pool, () => f.insertTask(source));
      });
    }
  );
});

describe("validated optional evidence tuple upgrade from schema 158", () => {
  it.each(["none", "complete"] as const)(
    "preserves %s historical tuples and records migration 159",
    async (source) => {
      await withLegacyDatabase(async (pool, upgrade) => {
        const f = await fixture(pool);
        await f.insertMinutes(source);
        await f.insertTask(source);
        const beforeEvidence = await evidenceRows(pool);
        const beforeLedger = await ledgerRows(pool);
        const beforeAudit = await auditRows(pool);
        expect(beforeLedger).toHaveLength(158);
        expect(await tupleConstraints(pool)).toEqual([]);

        expect(await upgrade()).toBe(1);

        expect(await evidenceRows(pool)).toEqual(beforeEvidence);
        const afterLedger = await ledgerRows(pool);
        expect(afterLedger.slice(0, 158)).toEqual(beforeLedger);
        expect(afterLedger).toHaveLength(159);
        expect(
          (await pool.query("select version,name from schema_migrations where version=159")).rows
        ).toEqual([{ version: 159, name: TUPLE_MIGRATION }]);
        const afterAudit = await auditRows(pool);
        expect(afterAudit).toEqual(expect.arrayContaining(beforeAudit));
        expect(afterAudit).toHaveLength(beforeAudit.length + 1);
        expect(
          (
            await pool.query(
              `select count(*)::int as count from audit_events
        where event_type='migration_applied'
          and convert_from(canonical_payload,'UTF8')::jsonb->'details'->>'name'=$1`,
              [TUPLE_MIGRATION]
            )
          ).rows[0]?.count
        ).toBe(1);
        expect(await tupleConstraints(pool)).toEqual([
          { conname: "minutes_versions_transcript_tuple_ck", convalidated: true },
          { conname: "tasks_minutes_source_tuple_ck", convalidated: true }
        ]);
      });
    }
  );

  it.each(["minutes_missing_hash", "missing_hash", "missing_locator", "missing_both"] as const)(
    "refuses malformed historical %s atomically without rewriting evidence or recording success",
    async (source) => {
      await withLegacyDatabase(async (pool, upgrade) => {
        const f = await fixture(pool);
        if (source === "minutes_missing_hash") await f.insertMinutes("missing_hash");
        else await f.insertTask(source);
        const beforeEvidence = await evidenceRows(pool);
        const beforeLedger = await ledgerRows(pool);
        const beforeAudit = await auditRows(pool);
        expect(beforeLedger).toHaveLength(158);
        expect(await tupleConstraints(pool)).toEqual([]);

        await expect(upgrade()).rejects.toMatchObject({
          code: "23514",
          constraint:
            source === "minutes_missing_hash"
              ? "minutes_versions_transcript_tuple_ck"
              : "tasks_minutes_source_tuple_ck"
        });

        expect(await evidenceRows(pool)).toEqual(beforeEvidence);
        expect(await ledgerRows(pool)).toEqual(beforeLedger);
        expect(await auditRows(pool)).toEqual(beforeAudit);
        // A task validation failure must also roll back the preceding minutes DDL.
        expect(await tupleConstraints(pool)).toEqual([]);
      });
    }
  );
});
