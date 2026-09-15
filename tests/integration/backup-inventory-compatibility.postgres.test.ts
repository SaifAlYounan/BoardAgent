import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { canonicalJson } from "../../lib/contracts/src/index.js";
import {
  captureBackupBoundaryInTransaction,
  withBackupTransaction
} from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import { withUnseededWorker } from "../helpers/unseeded-worker.js";
import { seedValidAuditEnvelope } from "../helpers/valid-audit-envelope.js";

it("keeps every legacy inventory digest across scalar, nested, quoted and zero-column rows", async () => {
  await withUnseededWorker("inventory-compat", async ({ pool, config, backupKeyId }) => {
    await seedValidAuditEnvelope(pool, config, 1000);
    await pool.query(
      `create table inventory_types (
      id bigint, amount numeric, flags boolean[], happened timestamptz,
      bytes bytea, payload jsonb, original json, note text, nullable text,
      "quoted""column" text, dropped text
    );
    alter table inventory_types drop column dropped;
    insert into inventory_types values
      (9007199254740993,1.2300,array[true,false,null], '2026-09-09T00:00:00.123456Z',
       decode('00ff','hex'),'{"nested":[1,null,{"x":"Ω"}]}','{"number":1.00}',E'line\\nnext',null,'quote'),
      (null,'NaN',null,null,null,'null',null,'😀',null,null);`
    );
    await pool.query(
      "create table inventory_zero (); insert into inventory_zero default values; insert into inventory_zero default values; grant select on inventory_types,inventory_zero to boardagent_backup"
    );
    // Exercise every normalization type in the catalog-proven UUID ordering path
    // as well as the full JSON sort above. Special names must remain own data.
    await pool.query(`
      create table inventory_uuid_types as
        select ('00000000-0000-0000-0000-'||lpad(row_number() over ()::text,12,'0'))::uuid as id,
               source.id as exact_bigint, amount, flags, happened, bytes, payload,
               original, note, nullable, "quoted""column", 'data'::text as "__proto__",
               'ordinary text'::text as "toJSON"
          from inventory_types as source;
      alter table inventory_uuid_types add primary key (id);
      grant select on inventory_uuid_types to boardagent_backup;
    `);
    await pool.query(`
      create table inventory_uuid (id uuid primary key,note text);
      insert into inventory_uuid values
        ('ffffffff-ffff-ffff-ffff-ffffffffffff','first inserted'),
        ('00000000-0000-0000-0000-000000000001','last inserted');
      create table inventory_earlier_property (id uuid primary key,a text);
      insert into inventory_earlier_property values
        ('ffffffff-ffff-ffff-ffff-ffffffffffff','a'),
        ('00000000-0000-0000-0000-000000000001','z');
      create table inventory_numeric_primary (id integer primary key,note text);
      insert into inventory_numeric_primary values (2,'two'),(10,'ten');
      create table inventory_inherited (id uuid primary key,note text);
      create table inventory_child () inherits (inventory_inherited);
      insert into inventory_inherited values ('00000000-0000-0000-0000-000000000001','z');
      insert into inventory_child values ('00000000-0000-0000-0000-000000000001','a');
      grant select on inventory_uuid,inventory_earlier_property,inventory_numeric_primary,
        inventory_inherited,inventory_child to boardagent_backup;
    `);
    await withBackupTransaction(
      pool,
      async (client) => {
        const actual = await captureBackupBoundaryInTransaction(client, {
          receiptId: testId(30_000_003),
          encryptionKeyId: backupKeyId,
          encryptionKeyFingerprintSha256: "a".repeat(64)
        });
        expect(actual.tableInventory.find((row) => row.table === "inventory_types")?.rowCount).toBe(
          "2"
        );
        expect(actual.tableInventory.find((row) => row.table === "inventory_zero")?.rowCount).toBe(
          "2"
        );
        for (const entry of actual.tableInventory) {
          const quoted = '"' + entry.table.replaceAll('"', '""') + '"';
          // Legacy projection and ordering are the compatibility oracle. Include every
          // current table, both fixture-only shapes and real signed audit history.
          const rows = await client.query(`select normalized from (
          select (select jsonb_object_agg(field.key,field.value order by field.key)
                    from jsonb_each_text(to_jsonb(source_row)) as field) as normalized
          from public.${quoted} as source_row
        ) as original order by normalized::text collate "C"`);
          const hash = createHash("sha256");
          for (const row of rows.rows) {
            const bytes = Buffer.from(canonicalJson(row.normalized));
            const length = Buffer.alloc(8);
            length.writeBigUInt64BE(BigInt(bytes.length));
            hash.update(length);
            hash.update(bytes);
          }
          expect(entry, entry.table).toMatchObject({
            rowCount: String(rows.rows.length),
            rowsSha256: hash.digest("hex")
          });
        }
      },
      { assumeRole: "boardagent_backup" }
    );
  });
}, 20000);

it("refuses a noncanonical row after a full page, closes the cursor and permits a clean retry", async () => {
  await withUnseededWorker("inventory-failure", async ({ pool, config, backupKeyId }) => {
    await seedValidAuditEnvelope(pool, config, 1000);
    await pool.query(`
      create table inventory_stream_failure (id uuid primary key,note text);
      insert into inventory_stream_failure
        select ('00000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'valid'
          from generate_series(1,3000) i;
      grant select on inventory_stream_failure to boardagent_backup;
    `);
    await pool.query("update inventory_stream_failure set note=$1 where id=$2", [
      "e\u0301",
      "00000000-0000-0000-0000-000000001500"
    ]);
    const input = {
      receiptId: testId(30_000_050),
      encryptionKeyId: backupKeyId,
      encryptionKeyFingerprintSha256: "a".repeat(64)
    };
    await withBackupTransaction(
      pool,
      async (client) => {
        await expect(captureBackupBoundaryInTransaction(client, input)).rejects.toThrow("NFC");
        const cursors = await client.query(
          "select name from pg_cursors where name='boardagent_backup_inventory_rows'"
        );
        expect(cursors.rows).toEqual([]);
        expect((await client.query("select 1 as ok")).rows).toEqual([{ ok: 1 }]);
      },
      { assumeRole: "boardagent_backup" }
    );
    // Only the disposable fixture owner repairs the synthetic invalid input.
    await pool.query("update inventory_stream_failure set note='valid'");
    const retried = await withBackupTransaction(
      pool,
      (client) => captureBackupBoundaryInTransaction(client, input),
      { assumeRole: "boardagent_backup" }
    );
    expect(
      retried.tableInventory.find((row) => row.table === "inventory_stream_failure")
    ).toMatchObject({
      rowCount: "3000"
    });
  });
}, 20000);
