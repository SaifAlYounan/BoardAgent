import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import {
  SUBMISSION_PROJECTION_PREFLIGHT_SQL,
  SUBMISSION_PROJECTION_CONTENT_SQL,
  loadAdmittedSubmission,
  submissionProjectionCost,
  submissionProjectionPlan,
  type SubmissionProjectionMetadata
} from "../../artifacts/server/src/management-submission-projection.js";
import {
  SUBMISSION_LIST_PREFLIGHT_SQL,
  SUBMISSION_LIST_CONTENT_SQL,
  loadAdmittedSubmissionList,
  submissionListProjectionCost,
  submissionListProjectionPlan,
  type SubmissionListMetadata
} from "../../artifacts/server/src/management-submission-list-projection.js";
import {
  loadAdmittedQuestionList,
  questionListProjectionCost,
  questionListProjectionPlan
} from "../../artifacts/server/src/management-question-list-projection.js";
import {
  QUESTION_LIST_PROJECTION_PREFLIGHT_SQL,
  QUESTION_LIST_PROJECTION_CONTENT_SQL,
  type ManagementQuestionListProjectionMetadata,
  type ManagementQuestionListProjectionObservation
} from "../../lib/db/src/question-queries.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_SUBMISSION_POINT_SQL,
  ORIGINAL_SUBMISSION_LIST_SQL,
  ORIGINAL_QUESTION_LIST_SQL,
  ORIGINAL_REQUEST_CONTEXT_SQL
} from "../helpers/management-read-original-sql.js";

// Only transaction/actor/authority seams are modeled. Real public input/registry,
// original question-list context/parser, cursor, page and admission code execute.
// These unit doubles make no PostgreSQL planner, RLS or writer-reachability claim.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, callback: (client: PoolClient) => Promise<unknown>) => {
        const client = (pool as unknown as { fixtureClient: PoolClient }).fixtureClient;
        if (!client) throw new Error("unexpected management pool");
        return callback(client);
      }
    )
  };
});
const kinds = ["point", "submissions", "questions"] as const;
type Kind = (typeof kinds)[number];
type Item = Record<string, JsonValue>;
type Metadata = Record<string, string | null>;
const id = (n: number) => `01993c00-0000-7000-8000-${String(n).padStart(12, "0")}`;
const digest = (s: string) => createHash("sha256").update(s).digest("hex");
const bytes = (name: string) =>
  readFileSync(path.resolve(import.meta.dirname, `../fixtures/management-read-${name}.txt`));
const literal = <T>(name: string) => JSON.parse(bytes(name).toString("utf8")) as T;
const clone = <T>(value: T) => JSON.parse(JSON.stringify(value)) as T;
const tools = {
  point: "get_management_submission",
  submissions: "list_management_submissions",
  questions: "list_management_questions"
} as const;
const originals = {
  point: ORIGINAL_SUBMISSION_POINT_SQL,
  submissions: ORIGINAL_SUBMISSION_LIST_SQL,
  questions: ORIGINAL_QUESTION_LIST_SQL
};
const preflights = {
  point: SUBMISSION_PROJECTION_PREFLIGHT_SQL,
  submissions: SUBMISSION_LIST_PREFLIGHT_SQL,
  questions: QUESTION_LIST_PROJECTION_PREFLIGHT_SQL
};
const contents = {
  point: SUBMISSION_PROJECTION_CONTENT_SQL,
  submissions: SUBMISSION_LIST_CONTENT_SQL,
  questions: QUESTION_LIST_PROJECTION_CONTENT_SQL
};
const flat = {
  point: [
    "submission_id",
    "board_id",
    "assigned_secretary_id",
    "state",
    "current_version_id",
    "row_version",
    "queue_entered_at",
    "created_by",
    "created_at"
  ],
  version: [
    "version_id",
    "version",
    "schema_version",
    "payload_sha256",
    "author_member_id",
    "change_reason",
    "supersedes_id",
    "created_at"
  ],
  request: [
    "request_id",
    "submission_version_id",
    "secretary_member_id",
    "request_text",
    "request_sha256",
    "created_at"
  ],
  reply: [
    "reply_id",
    "submission_version_id",
    "management_author_id",
    "canonical_reply",
    "reply_sha256",
    "created_at"
  ],
  disposition: [
    "disposition_id",
    "submission_version_id",
    "disposition",
    "secretary_member_id",
    "reason",
    "resulting_draft_id",
    "created_at"
  ],
  submissions: [
    "submission_id",
    "board_id",
    "assigned_secretary_id",
    "state",
    "current_version_id",
    "row_version",
    "queue_entered_at",
    "current_version",
    "current_payload_sha256"
  ],
  questions: [
    "questionId",
    "boardId",
    "askerMemberId",
    "dueAt",
    "state",
    "currentTurnId",
    "rowVersion",
    "turnCount",
    "answerCount",
    "createdAt"
  ]
} as const;
const records = (v: JsonValue | undefined) => v as Item[];
const text = (v: JsonValue | undefined) => v as string;
function graph(roots: readonly unknown[]) {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (!Array.isArray(value)) properties += Object.keys(value).length;
    pending.push(...Object.values(value));
  }
  return { properties, containers };
}
// This independent normalized-JSON model inserts PostgreSQL-style separators.
// Actual numeric carry and PG text equivalence belong to a later SQL fixture.
function normalized(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(normalized).join(", ")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.entries(value)
      .map(([k, v]) => `${JSON.stringify(k)}: ${normalized(v)}`)
      .join(", ")}}`;
  return JSON.stringify(value);
}
function scalar(item: Item, keys: readonly string[]): bigint {
  return keys.reduce((n, key) => {
    const value = item[key];
    if (value === null) return n;
    if (typeof value !== "string" && typeof value !== "number")
      throw new Error(`unexpected flat ${key}`);
    return n + BigInt(Buffer.byteLength(String(value)));
  }, 0n);
}
const itemId = (kind: Kind, item: Item) =>
  text(item[kind === "questions" ? "questionId" : "submission_id"]);
const itemAt = (kind: Kind, item: Item) =>
  item[kind === "questions" ? "createdAt" : "queue_entered_at"] as string | null;
function measure(kind: Kind, item: Item, rawTime: string): Metadata {
  let s = scalar(item, flat[kind]);
  let roots: JsonValue[] = [
    item[kind === "questions" ? "assignedOwnerIds" : "management_owner_ids"]!
  ];
  const base: Metadata = { observation_sha256: digest(JSON.stringify([item, rawTime])) };
  if (kind === "point") {
    const versions = records(item.versions),
      requests = records(item.revision_requests),
      dispositions = records(item.dispositions),
      replies = requests.flatMap((r) => records(r.replies));
    for (const [rows, keys] of [
      [versions, flat.version],
      [requests, flat.request],
      [replies, flat.reply],
      [dispositions, flat.disposition]
    ] as const)
      for (const row of rows) s += scalar(row, keys);
    roots = roots.concat(versions.map((v) => v.document_references!));
    Object.assign(base, {
      submission_id: item.submission_id,
      board_id: item.board_id,
      row_version: item.row_version,
      current_version_id: item.current_version_id,
      version_count: String(versions.length),
      request_count: String(requests.length),
      reply_count: String(replies.length),
      disposition_count: String(dispositions.length)
    });
  } else if (kind === "submissions") {
    s +=
      BigInt(Buffer.byteLength(itemId(kind, item))) +
      BigInt(itemAt(kind, item) === null ? 0 : Buffer.byteLength(itemAt(kind, item)!));
    Object.assign(base, {
      id: itemId(kind, item),
      cursor_at: itemAt(kind, item),
      raw_order_key: rawTime
    });
  } else
    Object.assign(base, {
      question_id: itemId(kind, item),
      created_at: itemAt(kind, item),
      raw_created_at: rawTime
    });
  const j = roots.reduce((n, v) => n + BigInt(Buffer.byteLength(normalized(v))), 0n),
    g = graph(roots);
  return Object.assign(
    base,
    kind === "submissions"
      ? {
          scalar_utf8: String(s),
          normalized_json_utf8: String(j),
          json_property_count: String(g.properties),
          json_container_count: String(g.containers)
        }
      : {
          scalar_utf8: String(s),
          json_utf8: String(j),
          json_properties: String(g.properties),
          json_containers: String(g.containers)
        }
  );
}
const metricKeys = (kind: Kind) =>
  kind === "submissions"
    ? ["scalar_utf8", "normalized_json_utf8", "json_property_count", "json_container_count"]
    : ["scalar_utf8", "json_utf8", "json_properties", "json_containers"];
function totals(kind: Kind, rows: readonly Metadata[]) {
  return Object.fromEntries([
    ["row_count", String(rows.length)],
    ...metricKeys(kind).map((key) => [key, String(rows.reduce((n, r) => n + BigInt(r[key]!), 0n))])
  ]) as Record<string, string>;
}
function fixture(
  kind: Kind,
  options: {
    rows?: Item[];
    limit?: number;
    cursorAt?: string;
    cursorId?: string;
    cursorWire?: string;
  } = {}
) {
  const source =
    kind === "point"
      ? [literal<Item>("point-source")]
      : kind === "submissions"
        ? literal<{ item: Item }[]>("submissions-source").map((r) => r.item)
        : literal<Item[]>("questions-source");
  const state = {
    sourceRows: options.rows ?? source,
    hiddenIds: new Set<string>(),
    rawTimes: new Map<string, string>(),
    constructions: 0,
    contentStarted: false,
    preflightRows: undefined as unknown[] | undefined,
    contentRows: undefined as unknown[] | undefined,
    retainedRows: [] as unknown[],
    totalOverride: undefined as string | undefined,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined
  };
  const limit = options.limit ?? 100;
  const input = {
    boardId: id(2),
    memberId: id(98),
    limit,
    cursorAt: options.cursorAt ?? null,
    cursorId: options.cursorId ?? null
  };
  const visible = () => state.sourceRows.filter((row) => !state.hiddenIds.has(itemId(kind, row)));
  const selected = () =>
    visible()
      .filter(
        (row) =>
          kind === "point" ||
          input.cursorAt === null ||
          itemAt(kind, row)! < input.cursorAt ||
          (itemAt(kind, row) === input.cursorAt && itemId(kind, row) < input.cursorId!)
      )
      .slice(0, kind === "point" ? 2 : limit + 1);
  const current = () =>
    selected().map((item) =>
      measure(
        kind,
        item,
        state.rawTimes.get(itemId(kind, item)) ??
          itemAt(kind, item)?.replace("T", " ").replace("Z", "+00") ??
          "infinity"
      )
    );
  const metadata = current();
  const total = () => state.totalOverride ?? String(visible().length);
  const observedTotal = total();
  const parameters =
    kind === "point"
      ? [id(1), id(98)]
      : kind === "submissions"
        ? [id(2), id(98), input.cursorAt, input.cursorId, limit + 1]
        : [id(2), null, input.cursorAt, input.cursorId, limit + 1];
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql === ORIGINAL_REQUEST_CONTEXT_SQL) {
      expect(kind).toBe("questions");
      return {
        rows: [{ organization_id: id(99), member_id: id(98), client_id: id(97), token_jti: id(95) }]
      };
    }
    if (sql === contents[kind] || sql === originals[kind]) {
      state.contentStarted = true;
      await state.beforeContent?.();
    }
    if (sql === preflights[kind]) {
      expect(values).toEqual(parameters);
      const footer = {
        total_visible: observedTotal,
        question_id: null,
        created_at: null,
        raw_created_at: null,
        observation_sha256: null,
        scalar_utf8: "0",
        json_utf8: "0",
        json_properties: "0",
        json_containers: "0"
      };
      const rows =
        state.preflightRows ??
        (kind === "questions"
          ? metadata.length
            ? metadata.map((r) => ({ ...r, total_visible: observedTotal }))
            : [footer]
          : clone(metadata));
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === contents[kind]) {
      expect(values?.slice(0, parameters.length)).toEqual(parameters);
      if (state.contentRows) return { rows: state.contentRows };
      const fresh = current();
      let expected: Metadata[];
      if (kind === "point") {
        const row = metadata[0]!;
        expect(values?.slice(2)).toEqual([
          row.submission_id,
          row.board_id,
          row.row_version,
          row.current_version_id,
          row.observation_sha256,
          ...[
            "version_count",
            "request_count",
            "reply_count",
            "disposition_count",
            ...metricKeys(kind)
          ].map((k) => row[k])
        ]);
        expected = metadata;
      } else expected = JSON.parse(String(values?.[parameters.length])) as Metadata[];
      const key = kind === "point" ? "submission_id" : kind === "questions" ? "question_id" : "id";
      const fits = fresh.every((row) => {
        const bound = expected.find((r) => r[key] === row[key]);
        return (
          bound !== undefined &&
          Object.entries(row).every(([k, v]) =>
            metricKeys(kind).includes(k)
              ? (kind !== "point" && k.includes("propert")) ||
                (kind !== "point" && k.includes("container"))
                ? BigInt(v!) === BigInt(bound[k]!)
                : BigInt(v!) <= BigInt(bound[k]!)
              : v === bound[k]
          )
        );
      });
      if (!fits)
        return {
          rows:
            kind === "questions"
              ? [{ fits: false, total_visible: total(), items: null }]
              : [{ fits: false, view: null, item: null, cursor_at: null, cursor_id: null }]
        };
      const rows = selected();
      state.constructions += rows.length;
      state.retainedRows =
        kind === "point"
          ? rows.map((view) => ({ fits: true, view }))
          : kind === "questions"
            ? [{ fits: true, total_visible: total(), items: rows }]
            : rows.map((item) => ({
                fits: true,
                item,
                cursor_at: itemAt(kind, item),
                cursor_id: itemId(kind, item)
              }));
      return { rows: state.retainedRows };
    }
    if (sql === originals[kind]) {
      expect(values).toEqual(parameters);
      const rows = selected();
      state.constructions += rows.length;
      state.retainedRows =
        kind === "point"
          ? rows.map((view) => ({ view }))
          : kind === "questions"
            ? [{ total_visible: total(), items: rows }]
            : rows.map((item) => ({
                item,
                cursor_at: itemAt(kind, item),
                cursor_id: itemId(kind, item)
              }));
      return { rows: state.retainedRows };
    }
    throw new Error("unexpected management query");
  });
  const client = { query } as unknown as PoolClient;
  const repository = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
    cursorKey: Buffer.alloc(32, 1)
  });
  const principal: SurfacePrincipal = {
    organizationId: id(99),
    memberId: id(98),
    serviceOrigin: "https://boardagent.test",
    clientId: id(97),
    protocolClientId: "management-fixture",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture-key",
    scopes: ["governance:read"],
    roles: ["member"],
    boardIds: [id(2)]
  };
  const seam = repository as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    dispatch(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readSubmission(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readQuestion(
      client: PoolClient,
      actor: SurfacePrincipal,
      tool: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({}),
    authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((c, p, name, args) => {
    if (name !== tools[kind]) throw new Error("out-of-scope management dispatch");
    return kind === "questions"
      ? seam.readQuestion(c, p, name, args)
      : seam.readSubmission(c, p, name, args);
  });
  const questionObservation = (): ManagementQuestionListProjectionObservation => {
    const measured = totals(kind, metadata);
    return {
      rows: metadata as unknown as ManagementQuestionListProjectionMetadata[],
      total_visible: observedTotal,
      row_count: measured["row_count"]!,
      scalar_utf8: measured["scalar_utf8"]!,
      json_utf8: measured["json_utf8"]!,
      json_properties: measured["json_properties"]!,
      json_containers: measured["json_containers"]!
    };
  };
  const cost = () =>
    kind === "point"
      ? submissionProjectionCost(metadata[0] as unknown as SubmissionProjectionMetadata)
      : kind === "submissions"
        ? submissionListProjectionCost(
            totals(kind, metadata) as unknown as Parameters<typeof submissionListProjectionCost>[0]
          )
        : questionListProjectionCost(questionObservation());
  const plan = () =>
    kind === "point"
      ? submissionProjectionPlan(metadata[0] as unknown as SubmissionProjectionMetadata)
      : kind === "submissions"
        ? submissionListProjectionPlan(input, metadata as unknown as SubmissionListMetadata[])
        : questionListProjectionPlan({ boardId: input.boardId, limit }, questionObservation());
  return {
    kind,
    state,
    input,
    metadata,
    current,
    query,
    client,
    liveActor,
    authorize,
    plan,
    cost,
    read: (overrides: Record<string, unknown> = {}) =>
      repository.executeRead(principal, tools[kind], {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        ...(kind === "point" ? { submission_id: id(1) } : { board_id: input.boardId, limit }),
        ...(options.cursorWire ? { cursor: options.cursorWire } : {}),
        ...overrides
      }),
    helper: (): Promise<unknown> =>
      kind === "point"
        ? loadAdmittedSubmission(client, id(1), id(98))
        : kind === "submissions"
          ? loadAdmittedSubmissionList(client, input)
          : loadAdmittedQuestionList(client, {
              boardId: input.boardId,
              limit,
              ...(input.cursorAt
                ? { after: { createdAt: input.cursorAt, questionId: input.cursorId! } }
                : {})
            })
  };
}
const small = () =>
  responseAllocationPlan({
    kind: "document",
    representation: "tool",
    canonicalBytes: 1,
    sourceId: "synthetic-small",
    sourceVersion: "1",
    sha256: "a".repeat(64)
  });
const close = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
async function owned<T>(manager: ResponseAllocationManager, work: () => Promise<T>) {
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(work);
  } finally {
    close(owner);
  }
}
async function fixedClock<T>(work: () => Promise<T>) {
  const now = vi.spyOn(Date, "now").mockReturnValue(1800000000000);
  try {
    return await work();
  } finally {
    now.mockRestore();
  }
}

describe.each(kinds)("%s management read", (kind) => {
  it("refuses saturated public calls before full response construction", async () => {
    const manager = new ResponseAllocationManager(),
      occupied = manager.openRequest(new AbortController().signal),
      f = fixture(kind);
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 2048; i++) occupied.reserve(small());
      });
      await expect(owned(manager, () => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.liveActor).toHaveBeenCalledOnce();
      expect(f.authorize).toHaveBeenCalledOnce();
      expect(f.state.contentStarted).toBe(false);
      expect(f.state.constructions).toBe(0);
    } finally {
      close(occupied);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("preserves the complete independently authored original response", async () => {
    const f = fixture(kind);
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes(kind + "-full"));
    expect(f.state.constructions).toBe(kind === "point" ? 1 : 3);
  });
  it("preserves the original absent or empty response", async () => {
    const f = fixture(kind, { rows: [] });
    expect(
      Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => f.read())))
    ).toEqual(bytes(kind + "-empty"));
    expect(f.state.constructions).toBe(0);
  });
  it("keeps actor and authority denials before all content and metadata", async () => {
    for (const gate of ["actor", "authority"]) {
      const f = fixture(kind),
        error = new Error("synthetic authority denial");
      if (gate === "actor") f.liveActor.mockRejectedValue(error);
      else
        f.authorize.mockImplementation(() => {
          throw error;
        });
      await expect(f.read()).rejects.toBe(error);
      expect(f.query).not.toHaveBeenCalled();
    }
  });
  it("requires the native owner at the public entry", async () => {
    const f = fixture(kind);
    await expect(f.read()).rejects.toBeInstanceOf(TypeError);
    expect(f.query).not.toHaveBeenCalled();
    expect(f.state.contentStarted).toBe(false);
    expect(f.state.constructions).toBe(0);
  });
  it("refuses a metadata-phase public disconnect before content", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    f.state.afterMetadata = () => abort.abort();
    try {
      await expect(owner.produce(() => f.read())).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
    } finally {
      close(owner);
    }
    expect(f.state.constructions).toBe(0);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains a disconnected producer while the original or admitted query is held", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      abort = new AbortController(),
      owner = manager.openRequest(abort.signal);
    let resume!: () => void,
      settled = false;
    const gate = new Promise<void>((resolve) => {
      resume = resolve;
    });
    f.state.beforeContent = () => gate;
    const outcome = owner
      .produce(() => f.read())
      .then(
        (value) => ({ value, error: undefined }),
        (error: unknown) => ({ value: undefined, error })
      )
      .finally(() => {
        settled = true;
      });
    const failures: unknown[] = [];
    try {
      await vi.waitFor(() => expect(f.state.contentStarted).toBe(true), { timeout: 1000 });
      abort.abort();
      close(owner);
      expect(manager.accounting.usedUnits).toBe(f.plan().units);
    } catch (error) {
      failures.push(error);
    } finally {
      resume();
      close(owner);
      try {
        await vi.waitFor(() => expect(settled).toBe(true), { timeout: 1000 });
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length)
      throw new AggregateError(failures, "management assertion or bounded producer drain failed");
    expect((await outcome).error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("retains successful public output until both terminal signals", async () => {
    const f = fixture(kind),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      await owner.produce(() => f.read());
      expect(manager.accounting.usedUnits).toBe(f.plan().units);
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      close(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses oversized scalar metadata before the full query", async () => {
    const f = fixture(kind);
    f.metadata[0]!.scalar_utf8 = "999999999";
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.contentStarted).toBe(false);
  });
  it("rejects malformed scalar metadata before content", async () => {
    for (const value of ["-1", "01", "1.0", "1e3"]) {
      const f = fixture(kind);
      f.metadata[0]!.scalar_utf8 = value;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
      expect(f.state.contentStarted).toBe(false);
    }
  });
  it("preserves a full-query error and retains its admission until closure", async () => {
    const f = fixture(kind),
      error = new Error("synthetic content SQL error"),
      manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    f.state.beforeContent = async () => {
      throw error;
    };
    try {
      await expect(owner.produce(() => f.helper())).rejects.toBe(error);
      expect(manager.accounting.usedUnits).toBe(f.plan().units);
    } finally {
      close(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses the bounded false sentinel without accepting its content", async () => {
    const f = fixture(kind);
    f.state.contentRows =
      kind === "questions"
        ? [{ fits: false, total_visible: "3", items: null }]
        : [{ fits: false, view: null, item: null, cursor_at: null, cursor_id: null }];
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("bounds ordinary native JSON text and retained complete object graphs", async () => {
    const f = fixture(kind),
      reply = await owned(new ResponseAllocationManager(), () => f.read()),
      wire = { content: [{ type: "text", text: JSON.stringify(reply) }], structuredContent: reply };
    const extra: unknown[] = [];
    if (kind === "questions") {
      const rows = (f.state.retainedRows[0] as { items: Item[] }).items;
      extra.push({ items: rows.slice(0, f.input.limit), totalVisible: 3, nextCursor: null });
    }
    const actual = graph([wire, f.state.retainedRows, ...extra]),
      cost = f.cost();
    expect(BigInt(actual.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(actual.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    expect(Buffer.byteLength(JSON.stringify(f.state.retainedRows))).toBeLessThanOrEqual(
      Number(cost.jsonUpperBytes)
    );
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(f.plan().wireUpperBytes);
    expect(Buffer.byteLength(canonicalJson(reply))).toBeLessThanOrEqual(
      Number(cost.jsonUpperBytes) + 4096
    );
  });
});

describe.each(["submissions", "questions"] as const)("%s management pages", (kind) => {
  it("preserves independently signed lookahead and next-page bytes", async () =>
    fixedClock(async () => {
      const f = fixture(kind, { limit: 1 }),
        first = await owned(new ResponseAllocationManager(), () => f.read());
      expect(Buffer.from(canonicalJson(first))).toEqual(bytes(kind + "-page"));
      expect(f.state.constructions).toBe(2);
      const row = f.state.sourceRows[0]!,
        next = fixture(kind, {
          cursorAt: itemAt(kind, row)!,
          cursorId: itemId(kind, row),
          cursorWire: text((first.data as Item).next_cursor)
        });
      expect(
        Buffer.from(canonicalJson(await owned(new ResponseAllocationManager(), () => next.read())))
      ).toEqual(bytes(kind + "-next"));
      expect(next.state.constructions).toBe(2);
    }));
  it("allows only known visible subsets in the original relative order", async () => {
    const f = fixture(kind);
    f.state.afterMetadata = () => f.state.hiddenIds.add(itemId(kind, f.state.sourceRows[1]!));
    await owned(new ResponseAllocationManager(), () => f.helper());
    expect(f.state.constructions).toBe(2);
    const items =
      kind === "questions"
        ? (f.state.retainedRows[0] as { items: Item[] }).items
        : (f.state.retainedRows as { item: Item }[]).map((r) => r.item);
    expect(items.map((r) => itemId(kind, r))).toEqual(
      [f.state.sourceRows[0], f.state.sourceRows[2]].map((r) => itemId(kind, r!))
    );
  });
  it("refuses an unseen backfill row at the original limit-plus-one frontier", async () => {
    const f = fixture(kind, { limit: 1 });
    f.state.afterMetadata = () => f.state.hiddenIds.add(itemId(kind, f.state.sourceRows[0]!));
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("refuses empty-frontier growth without full item construction", async () => {
    const source = fixture(kind).state.sourceRows,
      f = fixture(kind, { rows: [] });
    f.state.afterMetadata = () => {
      f.state.sourceRows = source;
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(f.state.constructions).toBe(0);
  });
  it("charges all 501 selected rows while exposing only 500 public items", async () => {
    const item = fixture(kind).state.sourceRows[0]!,
      rows = Array.from({ length: 501 }, (_, i) => ({
        ...clone(item),
        [kind === "questions" ? "questionId" : "submission_id"]: id(2000 - i)
      })),
      f = fixture(kind, { rows, limit: 500 });
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      const result = await owner.produce(() => f.read());
      expect(records((result.data as Item).items)).toHaveLength(500);
      expect(f.state.constructions).toBe(501);
      expect(manager.accounting.usedUnits).toBe(f.plan().units);
    } finally {
      close(owner);
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("rejects duplicate preflight IDs and malformed returned tuples", async () => {
    const duplicate = fixture(kind);
    duplicate.state.preflightRows = [duplicate.metadata[0], duplicate.metadata[0]].map((r) =>
      kind === "questions" ? { ...r, total_visible: "3" } : r
    );
    await expect(
      owned(new ResponseAllocationManager(), () => duplicate.helper())
    ).rejects.toBeInstanceOf(TypeError);
    for (const change of ["unknown", "time", "reverse", "extra"]) {
      const f = fixture(kind),
        items = clone(f.state.sourceRows);
      if (change === "unknown")
        items[0]![kind === "questions" ? "questionId" : "submission_id"] = id(77);
      if (change === "time")
        items[0]![kind === "questions" ? "createdAt" : "queue_entered_at"] = "different";
      if (change === "reverse") items.reverse();
      if (change === "extra") items.push(clone(items[0]!));
      f.state.contentRows =
        kind === "questions"
          ? [{ fits: true, total_visible: "3", items }]
          : items.map((item) => ({
              fits: true,
              item,
              cursor_at: itemAt(kind, item),
              cursor_id: itemId(kind, item)
            }));
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
        TypeError
      );
    }
  });
});

describe("management submission complete history", () => {
  it("contains every original field at all five independent levels", () => {
    const root = literal<Item>("point-source");
    expect(Object.keys(root).sort()).toEqual(
      [
        ...flat.point,
        "management_owner_ids",
        "versions",
        "revision_requests",
        "dispositions"
      ].sort()
    );
    for (const v of records(root.versions))
      expect(Object.keys(v).sort()).toEqual([...flat.version, "document_references"].sort());
    for (const q of records(root.revision_requests)) {
      expect(Object.keys(q).sort()).toEqual([...flat.request, "replies"].sort());
      for (const l of records(q.replies))
        expect(Object.keys(l).sort()).toEqual([...flat.reply].sort());
    }
    for (const d of records(root.dispositions))
      expect(Object.keys(d).sort()).toEqual([...flat.disposition].sort());
  });
  it("preserves visible requests, replies and dispositions when a version is hidden", async () => {
    const root = literal<Item>("point-source");
    root.versions = [];
    const f = fixture("point", { rows: [root] });
    const result = await owned(new ResponseAllocationManager(), () => f.read());
    expect((result.data as Item).submission).toEqual(root);
    expect(records(root.revision_requests)).toHaveLength(2);
    expect(records(records(root.revision_requests)[0]!.replies)).toHaveLength(2);
    expect(records(root.dispositions)).toHaveLength(2);
  });
  it("preserves null root references and independently empty child arrays", async () => {
    const root = literal<Item>("point-source");
    Object.assign(root, {
      assigned_secretary_id: null,
      current_version_id: null,
      state: "submitted",
      versions: [],
      revision_requests: [],
      dispositions: []
    });
    const f = fixture("point", { rows: [root] });
    expect((await owned(new ResponseAllocationManager(), () => f.read())).data).toEqual({
      submission: root
    });
  });
  it("returns a newly invisible root without exposing its prior content", async () => {
    const f = fixture("point");
    f.state.afterMetadata = () => f.state.hiddenIds.add(id(1));
    expect(await owned(new ResponseAllocationManager(), () => f.helper())).toBeNull();
    expect(f.state.constructions).toBe(0);
  });
  it("does not reselect an initially absent point after metadata", async () => {
    const root = literal<Item>("point-source"),
      f = fixture("point", { rows: [] });
    f.state.afterMetadata = () => {
      f.state.sourceRows = [root];
    };
    expect(await owned(new ResponseAllocationManager(), () => f.helper())).toBeNull();
    expect(f.state.contentStarted).toBe(false);
  });
  it("rejects duplicate roots and a mismatched final root reference", async () => {
    const duplicate = fixture("point");
    duplicate.state.preflightRows = [duplicate.metadata[0], duplicate.metadata[0]];
    await expect(
      owned(new ResponseAllocationManager(), () => duplicate.helper())
    ).rejects.toBeInstanceOf(TypeError);
    const f = fixture("point"),
      view = clone(f.state.sourceRows[0]!);
    view.current_version_id = id(77);
    f.state.contentRows = [{ fits: true, view }];
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      TypeError
    );
  });
  it("retains two rows/header containers beyond the shared native graph", async () => {
    const root = literal<Item>("point-source");
    Object.assign(root, {
      versions: [],
      revision_requests: [],
      dispositions: [],
      management_owner_ids: [id(98)]
    });
    const f = fixture("point", { rows: [root] }),
      reply = await owned(new ResponseAllocationManager(), () => f.read()),
      wire = { content: [{ type: "text", text: JSON.stringify(reply) }], structuredContent: reply };
    expect(graph([wire, f.state.retainedRows]).containers).toBe(12);
    expect(f.cost().objectOrArrayCount).toBe("12");
  });
  it("bounds escaped multi-byte history and arbitrary nested reference JSON", async () => {
    const root = literal<Item>("point-source");
    records(root.revision_requests)[0]!.request_text = '"\\\n\u0001Δ🙂'.repeat(4096);
    records(records(root.revision_requests)[0]!.replies)[0]!.canonical_reply =
      '"\\\n\u0001Ω🙂'.repeat(4096);
    records(root.versions)[0]!.document_references = [
      { nested: [[], {}, null, true, false, { text: '"\\\nΔ🙂'.repeat(2048), number: 0.5 }] }
    ];
    const f = fixture("point", { rows: [root] }),
      reply = await owned(new ResponseAllocationManager(), () => f.read()),
      wire = { content: [{ type: "text", text: JSON.stringify(reply) }], structuredContent: reply },
      cost = f.cost(),
      g = graph([wire, f.state.retainedRows]);
    expect(Buffer.byteLength(JSON.stringify(f.state.retainedRows))).toBeLessThanOrEqual(
      Number(cost.jsonUpperBytes)
    );
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(f.plan().wireUpperBytes);
    expect(BigInt(g.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(g.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
  });
  it("absorbs a modeled PostgreSQL numeric carry in the fixed JSON allowance", async () => {
    const raw = "[9999999999999999]",
      root = literal<Item>("point-source");
    records(root.versions)[0]!.document_references = JSON.parse(raw) as JsonValue;
    expect(JSON.stringify(records(root.versions)[0]!.document_references)).toBe(
      "[10000000000000000]"
    );
    const f = fixture("point", { rows: [root] });
    f.metadata[0]!.json_utf8 = String(BigInt(f.metadata[0]!.json_utf8!) - 1n);
    // Evaluate the byte bound only: the unit's fresh-JSON model deliberately uses
    // JavaScript text, so this is not an assertion of actual PG hash/SQL behavior.
    expect(Buffer.byteLength(JSON.stringify([{ fits: true, view: root }]))).toBeLessThanOrEqual(
      Number(f.cost().jsonUpperBytes)
    );
  });
});

const changes: [string, (root: Item) => void][] = [
  [
    "root owner identity",
    (root) => {
      root.management_owner_ids = [id(97), id(90)];
    }
  ],
  [
    "actual version reason with stored hash unchanged",
    (root) => {
      records(root.versions)[0]!.change_reason = "Initial Δ";
    }
  ],
  [
    "actual same-size reference JSON with stored hash unchanged",
    (root) => {
      const refs = records(records(root.versions)[0]!.document_references);
      const nested = refs[0]!.nested as JsonValue[];
      (nested[2] as Item).ratio = 0.6;
    }
  ],
  [
    "actual request text with stored hash unchanged",
    (root) => {
      const q = records(root.revision_requests)[0]!;
      q.request_text = text(q.request_text).replace("Please", "Kindly");
    }
  ],
  [
    "actual reply text with stored hash unchanged",
    (root) => {
      const l = records(records(root.revision_requests)[0]!.replies)[0]!;
      l.canonical_reply = text(l.canonical_reply).replace("Answer", "Return");
    }
  ],
  [
    "actual disposition reason",
    (root) => {
      const d = records(root.dispositions)[0]!;
      d.reason = text(d.reason).replace("Decision", "Response");
    }
  ],
  [
    "ordered reply membership",
    (root) => {
      records(records(root.revision_requests)[0]!.replies).reverse();
    }
  ]
];
describe("management private observation model", () => {
  it.each(changes)("refuses same-cost %s", async (_name, change) => {
    const f = fixture("point"),
      before = clone(f.metadata[0]!);
    f.state.afterMetadata = () => change(f.state.sourceRows[0]!);
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    const after = f.current()[0]!;
    for (const key of [
      "version_count",
      "request_count",
      "reply_count",
      "disposition_count",
      ...metricKeys("point")
    ])
      expect(after[key]).toBe(before[key]);
    expect(after.observation_sha256).not.toBe(before.observation_sha256);
    expect(f.state.constructions).toBe(0);
  });
  it.each(["submissions", "questions"] as const)(
    "binds same-cost owner and private raw-time changes in %s",
    async (kind) => {
      for (const mode of ["owner", "raw-time"]) {
        const f = fixture(kind),
          before = clone(f.metadata[0]!);
        f.state.afterMetadata = () => {
          if (mode === "owner")
            f.state.sourceRows[0]![
              kind === "questions" ? "assignedOwnerIds" : "management_owner_ids"
            ] = [id(97), id(90)];
          else
            f.state.rawTimes.set(
              itemId(kind, f.state.sourceRows[0]!),
              "2026-09-15 01:02:03.456788+00"
            );
        };
        await expect(
          owned(new ResponseAllocationManager(), () => f.helper())
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        for (const key of metricKeys(kind)) expect(f.current()[0]![key]).toBe(before[key]);
        expect(f.state.constructions).toBe(0);
      }
    }
  );
  it("refuses child growth without depending on a root row-version change", async () => {
    const f = fixture("point"),
      root = f.state.sourceRows[0]!,
      before = text(root.row_version);
    f.state.afterMetadata = () => {
      const q = clone(records(root.revision_requests)[0]!);
      q.request_id = id(303);
      q.replies = [];
      records(root.revision_requests).push(q);
    };
    await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(root.row_version).toBe(before);
    expect(f.state.constructions).toBe(0);
  });
});

describe("management question independent count and parsed-page behavior", () => {
  it("retains a nonzero visible total on an empty cursor tail", async () => {
    const f = fixture("questions", { cursorAt: "2026-09-12T00:00:00.000000Z", cursorId: id(1) });
    expect(await owned(new ResponseAllocationManager(), () => f.helper())).toEqual({
      items: [],
      totalVisible: 3,
      nextCursor: null
    });
    expect(f.metadata).toHaveLength(0);
    expect(f.state.constructions).toBe(0);
  });
  it("permits the fresh full-board total to change independently of known page rows", async () => {
    const f = fixture("questions", { limit: 1 });
    f.state.afterMetadata = () => {
      f.state.totalOverride = "9007199254740991";
    };
    const page = await owned(new ResponseAllocationManager(), () => f.helper());
    expect(page).toMatchObject({ totalVisible: Number.MAX_SAFE_INTEGER });
    expect(f.state.constructions).toBe(2);
  });
  it("preserves invalid total errors in either phase", async () => {
    for (const value of ["invalid", "-1", "9007199254740992"]) {
      for (const phase of ["metadata", "content"]) {
        const f = fixture("questions");
        if (phase === "metadata")
          f.state.preflightRows = f.metadata.map((row) => ({ ...row, total_visible: value }));
        else
          f.state.afterMetadata = () => {
            f.state.totalOverride = value;
          };
        await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toThrow(
          "management question list returned an invalid count"
        );
        if (phase === "metadata") expect(f.state.contentStarted).toBe(false);
      }
    }
  });
  it("rejects missing or malformed empty metadata footers", async () => {
    for (const rows of [
      [],
      [
        {
          total_visible: "3",
          question_id: null,
          created_at: null,
          raw_created_at: null,
          observation_sha256: null,
          scalar_utf8: "1",
          json_utf8: "0",
          json_properties: "0",
          json_containers: "0"
        }
      ]
    ]) {
      const f = fixture("questions", { rows: [] });
      f.state.preflightRows = rows;
      await expect(owned(new ResponseAllocationManager(), () => f.helper())).rejects.toThrow();
      expect(f.state.contentStarted).toBe(false);
    }
  });
  it("measures and bounds nested nullable UUID-array storage shapes without flattening", async () => {
    // The initial SQL cardinality check does not require one-dimensional/non-null
    // arrays. This is a read-row shape model, not a public writer acceptance claim.
    const item = fixture("questions").state.sourceRows[0]!;
    item.assignedOwnerIds = [
      [id(98), null],
      [id(90), id(91)]
    ];
    const f = fixture("questions", { rows: [item] }),
      reply = await owned(new ResponseAllocationManager(), () => f.read());
    expect(records((reply.data as Item).items)[0]!.assignedOwnerIds).toEqual(item.assignedOwnerIds);
    const wire = {
        content: [{ type: "text", text: JSON.stringify(reply) }],
        structuredContent: reply
      },
      rows = (f.state.retainedRows[0] as { items: Item[] }).items;
    const actual = graph([
      wire,
      f.state.retainedRows,
      { items: rows.slice(), totalVisible: 1, nextCursor: null }
    ]);
    expect(BigInt(actual.containers)).toBeLessThanOrEqual(BigInt(f.cost().objectOrArrayCount));
    expect(BigInt(actual.properties)).toBeLessThanOrEqual(BigInt(f.cost().propertyCount));
  });
});

describe("management arithmetic and fixed pool lanes", () => {
  it("matches independent zero and complete-child coefficient vectors", () => {
    const p = fixture("point").metadata[0]!;
    for (const key of [
      "version_count",
      "request_count",
      "reply_count",
      "disposition_count",
      ...metricKeys("point")
    ])
      p[key] = "0";
    expect(submissionProjectionCost(p as unknown as SubmissionProjectionMetadata)).toEqual({
      jsonUpperBytes: "303",
      propertyCount: "36",
      objectOrArrayCount: "11"
    });
    for (const key of ["version_count", "request_count", "reply_count", "disposition_count"])
      p[key] = "1";
    expect(submissionProjectionCost(p as unknown as SubmissionProjectionMetadata)).toEqual({
      jsonUpperBytes: "1005",
      propertyCount: "65",
      objectOrArrayCount: "16"
    });
    expect(
      submissionListProjectionCost({
        row_count: "0",
        scalar_utf8: "0",
        normalized_json_utf8: "0",
        json_property_count: "0",
        json_container_count: "0"
      })
    ).toEqual({ jsonUpperBytes: "2", propertyCount: "25", objectOrArrayCount: "7" });
    expect(
      questionListProjectionCost({
        row_count: "0",
        scalar_utf8: "0",
        json_utf8: "0",
        json_properties: "0",
        json_containers: "0"
      })
    ).toEqual({ jsonUpperBytes: "166", propertyCount: "33", objectOrArrayCount: "12" });
  });
  it.each(kinds)(
    "reserves the exact 1920-unit %s scalar boundary and refuses 1921",
    async (kind) => {
      const source = fixture(kind).state.sourceRows[0]!,
        f = fixture(kind, { rows: [source] }),
        row = f.metadata[0]!;
      for (const key of metricKeys(kind)) row[key] = "0";
      if (kind === "point")
        for (const key of ["version_count", "request_count", "reply_count", "disposition_count"])
          row[key] = "0";
      // Independent fixed A=65536+8(J+4096)+256P+512O at S=0.
      const base = { point: 115576n, submissions: 115224n, questions: 122672n }[kind],
        threshold = (1920n * 1048576n - base) / 48n;
      row.scalar_utf8 = String(threshold);
      const accepted = f.plan();
      expect(accepted.units).toBe(1920);
      row.scalar_utf8 = String(threshold + 1n);
      const refused = f.plan();
      expect(refused.units).toBe(1921);
      const manager = new ResponseAllocationManager(),
        owner = manager.openRequest(new AbortController().signal);
      try {
        await owner.produce(async () => {
          expect(() => owner.reserve(refused)).toThrow(ResponseAllocationUnavailable);
          expect(manager.accounting.usedUnits).toBe(0);
          owner.reserve(accepted);
        });
        expect(manager.accounting.usedUnits).toBe(1920);
      } finally {
        close(owner);
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
  );
  it("requires the private kind to use tool representation and zero raw-byte charge", () => {
    const input = {
      kind: "management_read_projection" as const,
      representation: "tool" as const,
      canonicalBytes: 0,
      sourceId: id(1),
      sourceVersion: "1",
      sha256: "a".repeat(64),
      listProjection: { jsonUpperBytes: "303", propertyCount: "36", objectOrArrayCount: "11" }
    };
    expect(responseAllocationPlan(input).units).toBe(1);
    expect(() => responseAllocationPlan({ ...input, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...input, canonicalBytes: 1 })).toThrow(TypeError);
  });
});
