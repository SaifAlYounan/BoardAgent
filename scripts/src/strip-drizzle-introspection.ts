import { readFile, writeFile } from "node:fs/promises";

const [, , input, output] = process.argv;
if (!input || !output) throw new Error("usage: strip-drizzle-introspection INPUT OUTPUT");

let source = await readFile(input, "utf8");
source = source.replace(
  /^import \{[^\n]+\} from "drizzle-orm\/pg-core"\nimport \{ sql \} from "drizzle-orm"\n+/u,
  `/*
 * Generated typed query mirror of the migrated PostgreSQL schema.
 * Hand-reviewed SQL migrations remain authoritative for constraints, indexes, RLS and FKs.
 */
import {
  bigint,
  boolean,
  customType,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

const bytea = customType<{ data: Uint8Array }>({ dataType: () => "bytea" });
const pgLsn = customType<{ data: string }>({ dataType: () => "pg_lsn" });
const tsvector = customType<{ data: string }>({ dataType: () => "tsvector" });

`
);
source = source
  .replace(
    /\s*\/\/ TODO: failed to parse database type 'bytea'\n(\s*[A-Za-z][A-Za-z0-9]*:) unknown\(/gu,
    "$1 bytea("
  )
  .replace(
    /\s*\/\/ TODO: failed to parse database type 'pg_lsn'\n(\s*[A-Za-z][A-Za-z0-9]*:) unknown\(/gu,
    "$1 pgLsn("
  )
  .replace(
    /\s*\/\/ TODO: failed to parse database type 'tsvector'\n(\s*[A-Za-z][A-Za-z0-9]*:) unknown\(/gu,
    "$1 tsvector("
  )
  .replace(/\}, \(table\) => \[\n[\s\S]*?\n\]\);/gu, "});");

const tableNames = [...source.matchAll(/export const ([A-Za-z][A-Za-z0-9]*) = pgTable\(/gu)].map(
  (match) => match[1]
);
if (tableNames.length !== 131) {
  throw new Error(`expected 131 tables, produced ${String(tableNames.length)}`);
}
if (new Set(tableNames).size !== tableNames.length) {
  throw new Error("duplicate table export in introspected schema");
}
if (source.includes("TODO: failed") || source.includes("unknown(")) {
  throw new Error("unresolved introspection type remains");
}
source += `\nexport const FROZEN_SCHEMA_TABLES = Object.freeze({\n${tableNames
  .map((name) => `  ${name},`)
  .join("\n")}\n});\n`;
await writeFile(output, source);
