import type { PoolClient } from "pg";
import { expect } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  originalManagementSubmission,
  originalManagementSubmissionList,
  originalManagementQuestionList,
  managementObject,
  managementArray,
  SUBMISSION_ROOT_FLAT,
  SUBMISSION_VERSION_FLAT,
  SUBMISSION_REQUEST_FLAT,
  SUBMISSION_REPLY_FLAT,
  SUBMISSION_DISPOSITION_FLAT,
  SUBMISSION_LIST_KEYS,
  QUESTION_LIST_FLAT
} from "./management-postgres-oracle.js";
import {
  originalManagementListEnvelope,
  type OriginalManagementPageRow
} from "./management-page-oracle.js";

export type ManagementNativeKind = "point" | "submissions" | "questions";
export interface ManagementNativeInput {
  readonly kind: ManagementNativeKind;
  readonly selectorId: string;
  readonly limit: number;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
}
function bound(j: bigint, p: bigint, o: bigint) {
  const allocationBytes = 65536n + 8n * (j + 4096n) + 256n * p + 512n * o;
  return {
    jsonUpperBytes: j,
    propertyCount: p,
    objectOrArrayCount: o,
    allocationBytes,
    wireBytes: 65536n + 3n * (j + 4096n),
    units: Number((allocationBytes + 1048575n) / 1048576n)
  };
}
function keys(value: JsonValue, expected: readonly string[]) {
  expect(Object.keys(managementObject(value)).sort()).toEqual([...expected].sort());
}
export async function originalManagementNative(
  client: PoolClient,
  input: ManagementNativeInput,
  memberId: string
) {
  if (input.kind === "point") {
    const original = await originalManagementSubmission(client, input.selectorId, memberId);
    if (original.value === null || original.metadata.length !== 1)
      throw new Error("native complete submission requires actual visible root");
    const value = managementObject(original.value),
      m = original.metadata[0]!;
    keys(value, [
      ...SUBMISSION_ROOT_FLAT,
      "management_owner_ids",
      "versions",
      "revision_requests",
      "dispositions"
    ]);
    for (const entry of managementArray(value.versions))
      keys(entry, [...SUBMISSION_VERSION_FLAT, "document_references"]);
    for (const entry of managementArray(value.revision_requests)) {
      keys(entry, [...SUBMISSION_REQUEST_FLAT, "replies"]);
      for (const reply of managementArray(managementObject(entry).replies))
        keys(reply, SUBMISSION_REPLY_FLAT);
    }
    for (const entry of managementArray(value.dispositions))
      keys(entry, SUBMISSION_DISPOSITION_FLAT);
    const v = BigInt(m.version_count),
      q = BigInt(m.request_count),
      l = BigInt(m.reply_count),
      d = BigInt(m.disposition_count);
    // Independent complete-field formula, including retained PG rows/header O11.
    const measured = bound(
      303n +
        212n * v +
        167n * q +
        150n * l +
        173n * d +
        6n * BigInt(m.scalar_utf8) +
        BigInt(m.json_utf8),
      36n + 9n * v + 7n * q + 6n * l + 7n * d + BigInt(m.json_properties),
      11n + v + 2n * q + l + d + BigInt(m.json_containers)
    );
    return {
      point: original.value,
      rows: [] as OriginalManagementPageRow[],
      totalVisible: undefined as string | undefined,
      retained: [{ fits: true, view: original.value }],
      metadata: original.metadata,
      bound: measured
    };
  }
  const parameters = [
    input.selectorId,
    input.kind === "submissions" ? memberId : null,
    input.cursorAt,
    input.cursorId,
    input.limit + 1
  ];
  if (input.kind === "submissions") {
    const original = await originalManagementSubmissionList(client, parameters);
    for (const row of original.value) keys(row.item, SUBMISSION_LIST_KEYS);
    const sum = (
      field: "scalar_utf8" | "normalized_json_utf8" | "json_property_count" | "json_container_count"
    ) => original.metadata.reduce((n, m) => n + BigInt(m[field]), 0n);
    const r = BigInt(original.value.length);
    return {
      point: null,
      rows: original.value,
      totalVisible: undefined as string | undefined,
      retained: original.value.map((row) => ({ fits: true, ...row })),
      metadata: original.metadata,
      bound: bound(
        2n + 289n * r + 6n * sum("scalar_utf8") + sum("normalized_json_utf8"),
        25n + 14n * r + sum("json_property_count"),
        7n + 2n * r + sum("json_container_count")
      )
    };
  }
  const original = await originalManagementQuestionList(client, parameters),
    m = original.observation;
  const rows: OriginalManagementPageRow[] = original.value.items.map((item) => {
    keys(item, [...QUESTION_LIST_FLAT, "assignedOwnerIds"]);
    const value = managementObject(item);
    if (
      typeof value.questionId !== "string" ||
      (value.createdAt !== null && typeof value.createdAt !== "string")
    )
      throw new Error("invalid original question cursor tuple");
    return { item, cursor_at: value.createdAt, cursor_id: value.questionId };
  });
  const r = BigInt(m.row_count);
  return {
    point: null,
    rows,
    totalVisible: original.value.total_visible,
    retained: [{ fits: true, ...original.value }],
    metadata: original.preflight,
    bound: bound(
      166n + 224n * r + 6n * BigInt(m.scalar_utf8) + BigInt(m.json_utf8),
      33n + 22n * r + 2n * BigInt(m.json_properties),
      12n + 2n * r + 2n * BigInt(m.json_containers)
    )
  };
}
export type ManagementNativeOriginal = Awaited<ReturnType<typeof originalManagementNative>>;
export function originalManagementNativeEnvelope(
  input: ManagementNativeInput,
  original: ManagementNativeOriginal,
  principal: { organizationId: string; memberId: string },
  actualNext: unknown,
  before: number,
  after: number
) {
  if (input.kind === "point")
    return {
      schema_version: "boardagent.tool-result.v1",
      tool: "get_management_submission",
      status: "ok",
      reference: input.selectorId,
      resource_uri: null,
      data: { submission: original.point }
    };
  const envelope = originalManagementListEnvelope(
    input.kind,
    input.selectorId,
    original.rows,
    input.limit,
    principal,
    actualNext,
    before,
    after,
    original.totalVisible
  );
  // Model the existing JsonValueSchema parse as a distinct complete public page
  // graph; the PG aggregate and its DB sliced items remain separately retained.
  return input.kind === "questions"
    ? {
        ...envelope,
        data: {
          ...envelope.data,
          items: JSON.parse(JSON.stringify(envelope.data.items)) as JsonValue[]
        }
      }
    : envelope;
}
export function originalManagementRetainedRoots(
  input: ManagementNativeInput,
  original: ManagementNativeOriginal
): readonly unknown[] {
  if (input.kind !== "questions") return [original.retained];
  const selected = original.rows.slice(0, input.limit),
    last = selected.at(-1);
  const dbResult = {
    items: selected.map((row) => row.item),
    totalVisible: Number(original.totalVisible),
    nextCursor:
      original.rows.length > input.limit && last
        ? { createdAt: last.cursor_at, questionId: last.cursor_id }
        : null
  };
  return [original.retained, dbResult];
}
