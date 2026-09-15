import type { PoolClient } from "pg";
import { expect } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import { ORIGINAL_GOVERNANCE_LIST_SQL } from "./governance-lists-original-sql.js";
import {
  governanceListOriginalMetadataSQL,
  governanceListOriginalKeys,
  governanceListOriginalGraph
} from "./governance-lists-postgres-oracle.js";

export type OracleGovernanceListKind = "rulesets" | "templates" | "matter_types";
export interface OracleGovernanceListInput {
  readonly kind: OracleGovernanceListKind;
  readonly selectorId: string;
  readonly limit: number;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
}
export interface OriginalGovernancePageRow {
  readonly item: Record<string, JsonValue>;
  readonly cursor_at: string | null;
  readonly cursor_id: string;
}
interface Metadata {
  readonly id: string;
  readonly scalar_utf8: string;
  readonly normalized_json_utf8: string;
  readonly json_property_count: string;
  readonly json_container_count: string;
}
interface Measurement {
  readonly rows: readonly OriginalGovernancePageRow[];
  readonly metadata: readonly Metadata[];
}
const parameters = (input: OracleGovernanceListInput) => [
  input.selectorId,
  input.cursorAt,
  input.cursorId,
  input.limit + 1
];
export async function readOriginalGovernanceList(
  client: PoolClient,
  input: OracleGovernanceListInput
) {
  return (
    await client.query<OriginalGovernancePageRow>(
      ORIGINAL_GOVERNANCE_LIST_SQL[input.kind],
      parameters(input)
    )
  ).rows;
}
export async function readOriginalGovernanceListMeasurement(
  client: PoolClient,
  input: OracleGovernanceListInput
): Promise<Measurement> {
  // Both reads derive from the complete captured old SQL, never from the new
  // loader. The synthetic fixture is unchanged throughout the twelve calls.
  const rows = await readOriginalGovernanceList(client, input);
  const metadata = (
    await client.query<Metadata>(governanceListOriginalMetadataSQL(input.kind), parameters(input))
  ).rows;
  expect(metadata.map((row) => row.id)).toEqual(rows.map((row) => row.cursor_id));
  return { rows, metadata };
}
export function originalGovernanceRows(measurement: Measurement) {
  return measurement.rows;
}
export function assertOriginalGovernanceScalars(
  kind: OracleGovernanceListKind,
  measurement: Measurement
) {
  const jsonKey =
    kind === "templates" ? "exact_rule" : kind === "matter_types" ? "strict_fact_schema" : null;
  for (const [index, row] of measurement.rows.entries()) {
    expect(Object.keys(row.item).sort()).toEqual([...governanceListOriginalKeys[kind]].sort());
    const metadata = measurement.metadata[index]!;
    const flat = governanceListOriginalKeys[kind]
      .filter((key) => key !== jsonKey)
      .map((key) => row.item[key]);
    const scalar = [...flat, row.cursor_at, row.cursor_id].reduce<bigint>((sum, value) => {
      if (value === null) return sum;
      if (typeof value !== "string" && typeof value !== "number")
        throw new Error("unexpected governance scalar");
      return sum + BigInt(Buffer.byteLength(String(value)));
    }, 0n);
    expect(metadata.scalar_utf8).toBe(String(scalar));
    if (jsonKey) {
      const graph = governanceListOriginalGraph(row.item[jsonKey]!);
      expect(metadata.json_property_count).toBe(String(graph.properties));
      expect(metadata.json_container_count).toBe(String(graph.containers));
      expect(BigInt(Buffer.byteLength(JSON.stringify(row.item[jsonKey])))).toBeLessThanOrEqual(
        BigInt(metadata.normalized_json_utf8) + 1n
      );
    } else
      expect([
        metadata.normalized_json_utf8,
        metadata.json_property_count,
        metadata.json_container_count
      ]).toEqual(["0", "0", "0"]);
  }
}
export function originalGovernanceAllocationBound(
  kind: OracleGovernanceListKind,
  measurement: Measurement
) {
  const r = BigInt(measurement.rows.length),
    sum = (key: keyof Metadata) =>
      measurement.metadata.reduce((n, row) => n + BigInt(row[key]), 0n);
  const s = sum("scalar_utf8"),
    n = sum("normalized_json_utf8"),
    p = sum("json_property_count"),
    o = sum("json_container_count");
  // Independent reviewed original-key formulas, including four-field retained
  // PostgreSQL rows. These are analytic bounds, not an RSS measurement.
  const jsonUpperBytes =
    2n + { rulesets: 197n, templates: 147n, matter_types: 146n }[kind] * r + 6n * s + n;
  const propertyCount = 25n + (kind === "rulesets" ? 12n : 9n) * r + p,
    objectOrArrayCount = 7n + 2n * r + o;
  const allocationBytes =
    65536n + 8n * (jsonUpperBytes + 4096n) + 256n * propertyCount + 512n * objectOrArrayCount;
  const wireBytes = 65536n + 3n * (jsonUpperBytes + 4096n);
  return {
    jsonUpperBytes,
    propertyCount,
    objectOrArrayCount,
    allocationBytes,
    wireBytes,
    units: Number((allocationBytes + 1048575n) / 1048576n)
  };
}
