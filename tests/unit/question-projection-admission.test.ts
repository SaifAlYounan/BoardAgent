import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  QUESTION_PROJECTION_PREFLIGHT_SQL,
  QUESTION_PROJECTION_CONTENT_SQL,
  type ManagementQuestionProjectionMetadata,
  type ManagementQuestionView
} from "../../lib/db/src/question-queries.js";
import { prepareManagementQuestionTurn } from "../../lib/domain/src/question.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  loadAdmittedManagementQuestion,
  questionProjectionCost,
  questionProjectionPlan
} from "../../artifacts/server/src/question-projection-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

const id = (n: number) => `01993400-0000-7000-8000-${String(n).padStart(12, "0")}`;
const at = "2026-09-12T18:00:00.000000Z";
const principal = { organizationId: id(99), memberId: id(3) } as SurfacePrincipal;
function graph(text = "Synthetic question Δ\n"): ManagementQuestionView {
  return {
    questionId: id(1),
    boardId: id(2),
    askerMemberId: id(3),
    assignedOwnerIds: [id(4)],
    dueAt: at,
    state: "pending",
    currentTurnId: id(5),
    rowVersion: "1",
    turnCount: 1,
    answerCount: 0,
    createdAt: at,
    aclPolicy: { schemaVersion: "boardagent.question-acl.v1", grants: [] },
    turns: [
      {
        turnId: id(5),
        ordinal: 1,
        turnKind: "question",
        authorMemberId: id(3),
        authorRole: "voting_member",
        canonicalText: text,
        textSha256: "a".repeat(64),
        citations: [],
        answerRecordId: null,
        createdAt: at
      }
    ],
    deliveries: [
      {
        noticeId: id(6),
        noticeType: "question_assigned",
        objectVersion: "1",
        recipientMemberId: id(4),
        feedSequence: "1",
        state: "committed",
        auditEventId: id(7),
        createdAt: at
      }
    ],
    decisionLinks: [
      {
        linkId: id(8),
        inclusiveTurnOrdinal: 1,
        inclusiveTurnSha256: "b".repeat(64),
        decisionPackageId: id(9),
        decisionPackageVersion: 1,
        decisionPackageSha256: "c".repeat(64),
        createdAt: at
      }
    ]
  };
}
function jsonShape(value: unknown) {
  let properties = 0,
    containers = 0;
  const stack: unknown[] = [value];
  while (stack.length) {
    const next = stack.pop();
    if (next && typeof next === "object") {
      containers += 1;
      if (!Array.isArray(next)) properties += Object.keys(next).length;
      for (const child of Object.values(next)) stack.push(child);
    }
  }
  return { properties, containers };
}
// Independent enumeration of the actual returned shape, not the SQL field map
// or the formula constants. PostgreSQL scalar extraction has its separate case.
type MutableMetadata = {
  -readonly [
    K in keyof ManagementQuestionProjectionMetadata
  ]: ManagementQuestionProjectionMetadata[K];
};
function measure(q: ManagementQuestionView): MutableMetadata {
  const flat: unknown[] = [
    q.questionId,
    q.boardId,
    q.askerMemberId,
    q.dueAt,
    q.state,
    q.currentTurnId,
    q.rowVersion,
    q.turnCount,
    q.answerCount,
    q.createdAt
  ];
  for (const t of q.turns)
    flat.push(
      t.turnId,
      t.ordinal,
      t.turnKind,
      t.authorMemberId,
      t.authorRole,
      t.canonicalText,
      t.textSha256,
      t.answerRecordId,
      t.createdAt
    );
  for (const n of q.deliveries)
    flat.push(
      n.noticeId,
      n.noticeType,
      n.objectVersion,
      n.recipientMemberId,
      n.feedSequence,
      n.state,
      n.auditEventId,
      n.createdAt
    );
  for (const l of q.decisionLinks)
    flat.push(
      l.linkId,
      l.inclusiveTurnOrdinal,
      l.inclusiveTurnSha256,
      l.decisionPackageId,
      l.decisionPackageVersion,
      l.decisionPackageSha256,
      l.createdAt
    );
  const roots: unknown[] = [q.aclPolicy, q.assignedOwnerIds, ...q.turns.map((t) => t.citations)];
  return {
    question_id: q.questionId,
    board_id: q.boardId,
    row_version: q.rowVersion,
    current_turn_id: q.currentTurnId,
    turn_count: String(q.turnCount),
    answer_count: String(q.answerCount),
    projected_turn_count: String(q.turns.length),
    delivery_count: String(q.deliveries.length),
    link_count: String(q.decisionLinks.length),
    scalar_utf8: String(
      flat.reduce<number>((n, v) => n + (v === null ? 0 : Buffer.byteLength(String(v))), 0)
    ),
    json_utf8: String(roots.reduce<number>((n, v) => n + Buffer.byteLength(JSON.stringify(v)), 0)),
    json_properties: String(roots.reduce<number>((n, v) => n + jsonShape(v).properties, 0)),
    json_containers: String(roots.reduce<number>((n, v) => n + jsonShape(v).containers, 0))
  };
}
function fixture(q = graph()) {
  const metadata = measure(q);
  const state = {
    missing: false,
    hidden: false,
    fits: true,
    content: q,
    constructions: 0,
    beforeContent: undefined as undefined | (() => Promise<void>),
    afterPreflight: undefined as undefined | (() => void)
  };
  const query = vi.fn(async (sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> => {
    if (sql.includes("as organization_id") && sql.includes("boardagent_context_uuid"))
      return {
        rows: [{ organization_id: id(99), member_id: id(3), client_id: id(10), token_jti: id(11) }]
      };
    if (sql === QUESTION_PROJECTION_PREFLIGHT_SQL) {
      state.afterPreflight?.();
      return {
        rows:
          state.missing || (values?.[1] !== null && values?.[1] !== metadata.board_id)
            ? []
            : [{ ...metadata }]
      };
    }
    if (sql === QUESTION_PROJECTION_CONTENT_SQL) {
      await state.beforeContent?.();
      if (state.hidden) return { rows: [] };
      if (state.fits) state.constructions += 1;
      return { rows: [{ fits: state.fits, question: state.fits ? state.content : null }] };
    }
    // Original SQL is supported fully enough for an exact positive result. The
    // baseline saturation failure is real old construction, not an unknown SQL
    // string or missing required callback after a prerequisite patch.
    if (sql.startsWith("with visible_question as materialized (") && sql.includes("jsonb_agg(")) {
      state.constructions += 1;
      return {
        rows: state.missing
          ? []
          : [
              {
                question_id: q.questionId,
                board_id: q.boardId,
                asker_member_id: q.askerMemberId,
                assigned_owner_ids: q.assignedOwnerIds,
                due_at: q.dueAt,
                state: q.state,
                current_turn_id: q.currentTurnId,
                row_version: q.rowVersion,
                turn_count: String(q.turnCount),
                answer_count: String(q.answerCount),
                created_at: q.createdAt,
                acl_policy: q.aclPolicy,
                turns: q.turns,
                deliveries: q.deliveries,
                decision_links: q.decisionLinks
              }
            ]
      };
    }
    throw new Error("unexpected question fixture query");
  });
  const client = { query } as unknown as PoolClient;
  const repo = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    readQuestion(
      client: PoolClient,
      principal: SurfacePrincipal,
      tool: string,
      input: Record<string, JsonValue>
    ): Promise<{ data: JsonValue }>;
    loadBoardResource(
      client: PoolClient,
      principal: SurfacePrincipal,
      uri: URL
    ): Promise<{ bytes: Buffer } | null>;
  };
  vi.spyOn(seam, "liveActor").mockResolvedValue({});
  vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  return {
    q,
    metadata,
    state,
    query,
    client,
    tool: () =>
      seam.readQuestion(client, principal, "get_management_question", {
        question_id: q.questionId
      }),
    resource: () =>
      seam.loadBoardResource(
        client,
        principal,
        new URL(`board://${q.boardId}/questions/${q.questionId}`)
      ),
    helper: (representation: "tool" | "resource" = "tool", boardId?: string) =>
      loadAdmittedManagementQuestion(client, q.questionId, representation, boardId)
  };
}
const small = () =>
  responseAllocationPlan({
    kind: "document",
    representation: "tool",
    sourceId: "small",
    sourceVersion: "1",
    sha256: "a".repeat(64),
    canonicalBytes: 1
  });
async function owned<T>(manager: ResponseAllocationManager, work: () => Promise<T>) {
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(work);
  } finally {
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}
function emptyMetrics(): MutableMetadata {
  return {
    question_id: id(1),
    board_id: id(2),
    row_version: "1",
    current_turn_id: id(5),
    turn_count: "0",
    answer_count: "0",
    projected_turn_count: "0",
    delivery_count: "0",
    link_count: "0",
    scalar_utf8: "0",
    json_utf8: "0",
    json_properties: "0",
    json_containers: "0"
  };
}

describe("question projection preconstruction admission", () => {
  for (const lane of ["tool", "resource"] as const) {
    it(`refuses the saturated ${lane} caller before constructing question JSON`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager();
      const held = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
      try {
        await expect(owned<unknown>(manager, () => f[lane]())).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(f.state.constructions).toBe(0);
        expect(
          f.query.mock.calls.filter(([sql]) => sql === QUESTION_PROJECTION_PREFLIGHT_SQL)
        ).toHaveLength(1);
        expect(f.query.mock.calls.some(([sql]) => sql === QUESTION_PROJECTION_CONTENT_SQL)).toBe(
          false
        );
      } finally {
        for (const lease of held) lease.release();
      }
    });
    it(`preserves all fields through the admitted ${lane} caller`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager();
      if (lane === "tool") expect((await owned(manager, f.tool)).data).toEqual({ question: f.q });
      else
        expect(JSON.parse((await owned(manager, f.resource))!.bytes.toString("utf8"))).toEqual(f.q);
      expect(Object.keys(f.q)).toHaveLength(15);
      expect(Object.keys(f.q.turns[0]!)).toHaveLength(10);
      expect(Object.keys(f.q.deliveries[0]!)).toHaveLength(8);
      expect(Object.keys(f.q.decisionLinks[0]!)).toHaveLength(7);
      expect(f.state.constructions).toBe(1);
      expect(manager.accounting.usedUnits).toBe(0);
    });
  }
  it("admits ordinary reads from both representations in the same accounting pool", async () => {
    const manager = new ResponseAllocationManager();
    const leases = Array.from({ length: 100 }, (_, i) =>
      manager.tryReserve(questionProjectionPlan(measure(graph()), i % 2 ? "tool" : "resource"))
    );
    expect(manager.accounting.usedUnits).toBe(100);
    for (const lease of leases) lease.release();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses known oversized JSON scalars before the content statement", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.metadata.json_utf8 = "251643858";
    await expect(owned(manager, f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(f.state.constructions).toBe(0);
    expect(f.query.mock.calls.some(([sql]) => sql === QUESTION_PROJECTION_CONTENT_SQL)).toBe(false);
  });
  it("distinguishes a changed authorized root from an absent root", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.fits = false;
    await expect(owned(manager, f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(f.state.constructions).toBe(0);
    f.state.hidden = true;
    expect(await owned(manager, f.helper)).toBeNull();
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("returns null for a preflight-hidden root without reservation or content", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.missing = true;
    expect(await owned(manager, f.helper)).toBeNull();
    expect(f.query.mock.calls.some(([sql]) => sql === QUESTION_PROJECTION_CONTENT_SQL)).toBe(false);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("passes the resource board selector to both statements and refuses no other board", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    expect(await owned(manager, () => f.helper("resource", id(90)))).toBeNull();
    expect(await owned(manager, () => f.helper("resource", f.q.boardId))).toEqual(f.q);
    const call = f.query.mock.calls.find(([sql]) => sql === QUESTION_PROJECTION_CONTENT_SQL)!;
    expect(call[1]?.slice(0, 5)).toEqual([
      f.q.questionId,
      f.q.boardId,
      f.q.boardId,
      "1",
      f.q.currentTurnId
    ]);
  });
  it("binds every fresh scalar count and cost to the preflight observation", async () => {
    const f = fixture();
    await owned(new ResponseAllocationManager(), f.helper);
    const call = f.query.mock.calls.find(([sql]) => sql === QUESTION_PROJECTION_CONTENT_SQL)!;
    expect(call[1]?.slice(5)).toEqual([
      f.metadata.turn_count,
      f.metadata.answer_count,
      f.metadata.projected_turn_count,
      f.metadata.delivery_count,
      f.metadata.link_count,
      f.metadata.scalar_utf8,
      f.metadata.json_utf8,
      f.metadata.json_properties,
      f.metadata.json_containers
    ]);
  });
  it("rejects a mismatched returned root tuple after the SQL guard", async () => {
    const f = fixture();
    f.state.content = { ...f.q, rowVersion: "2" };
    await expect(owned(new ResponseAllocationManager(), f.helper)).rejects.toThrow(
      "question projection identity is invalid"
    );
  });
  it("does not start content after disconnect during preflight", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    const owner = manager.openRequest(abort.signal);
    f.state.afterPreflight = () => abort.abort();
    try {
      await expect(owner.produce(f.helper)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query.mock.calls.some(([sql]) => sql === QUESTION_PROJECTION_CONTENT_SQL)).toBe(
        false
      );
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
  it("retains an early-disconnect lease until the pending producer really ends", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      abort = new AbortController();
    let enter!: () => void, release!: () => void;
    const entered = new Promise<void>((r) => {
        enter = r;
      }),
      gate = new Promise<void>((r) => {
        release = r;
      });
    f.state.beforeContent = async () => {
      enter();
      await gate;
    };
    const owner = manager.openRequest(abort.signal),
      pending = owner.produce(f.helper);
    await entered;
    abort.abort();
    owner.nativeTerminal();
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(questionProjectionPlan(f.metadata, "tool").units);
    release();
    await expect(pending).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("requires the native owner even when a synthetic connection is provided", async () => {
    await expect(fixture().helper()).rejects.toThrow(
      "question projection requires a native request owner"
    );
  });
  it("has an exact 1920-unit arithmetic boundary and rejects one further JSON byte", () => {
    const manager = new ResponseAllocationManager(),
      metadata = emptyMetrics();
    metadata.json_utf8 = "251643857";
    const plan = questionProjectionPlan(metadata, "tool");
    expect(plan.units).toBe(1920);
    const lease = manager.tryReserve(plan);
    lease.release();
    metadata.json_utf8 = "251643858";
    expect(questionProjectionPlan(metadata, "tool").units).toBe(1921);
    expect(() => manager.tryReserve(questionProjectionPlan(metadata, "tool"))).toThrow(
      ResponseAllocationUnavailable
    );
  });
  it("recomputes forged plan weights and forbids raw bytes on this projection", () => {
    const metadata = emptyMetrics();
    metadata.json_utf8 = "251643858";
    const plan = questionProjectionPlan(metadata, "tool"),
      manager = new ResponseAllocationManager();
    expect(() => manager.tryReserve({ ...plan, units: 1 })).toThrow(ResponseAllocationUnavailable);
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(
      "does not load canonical bytes"
    );
  });
  it("distinguishes malformed metadata from bounded aggregate overflow", () => {
    const metadata = emptyMetrics();
    for (const value of ["-1", "01", "1.0", "1e3"]) {
      metadata.scalar_utf8 = value;
      expect(() => questionProjectionPlan(metadata, "tool")).toThrow(TypeError);
    }
    metadata.scalar_utf8 = "9".repeat(25);
    expect(() => questionProjectionPlan(metadata, "tool")).toThrow(ResponseAllocationUnavailable);
    metadata.scalar_utf8 = "0";
    metadata.answer_count = "9007199254740992";
    expect(() => questionProjectionPlan(metadata, "tool")).toThrow(ResponseAllocationUnavailable);
  });
  it("does not charge flat JSON citation text as hundreds of thousands of object properties", () => {
    const metadata = {
      ...emptyMetrics(),
      projected_turn_count: "11",
      turn_count: "11",
      scalar_utf8: "4096",
      json_utf8: "5632196",
      json_properties: "11",
      json_containers: "24"
    };
    expect(questionProjectionPlan(metadata, "tool").units).toBe(44);
    const maximumTurn = {
      ...emptyMetrics(),
      turn_count: "1",
      projected_turn_count: "1",
      scalar_utf8: "3145728"
    };
    expect(questionProjectionPlan(maximumTurn, "tool").units).toBeLessThan(1920);
    // This is a scalar policy vector, not maximum-history/DB/native capacity evidence.
  });
  it("admits a maximum supported BMP turn alongside 100 small leases using the actual graph oracle", async () => {
    const prepared = prepareManagementQuestionTurn({
      questionId: id(1),
      turnKind: "answer",
      text: "界".repeat(1_048_576),
      citations: []
    });
    expect(prepared.text.length).toBe(1_048_576);
    expect(Buffer.byteLength(prepared.text)).toBe(3_145_728);
    const initial = graph(prepared.text);
    const q = {
      ...initial,
      turns: initial.turns.map((t) => ({ ...t, textSha256: prepared.textSha256 }))
    };
    const f = fixture(q),
      cost = questionProjectionCost(f.metadata),
      shape = jsonShape(q);
    expect(BigInt(Buffer.byteLength(JSON.stringify(q)))).toBeLessThanOrEqual(
      BigInt(cost.jsonUpperBytes)
    );
    expect(BigInt(shape.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(shape.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    const manager = new ResponseAllocationManager(),
      held = Array.from({ length: 100 }, () => manager.tryReserve(small()));
    const owner = manager.openRequest(new AbortController().signal);
    try {
      expect(await owner.produce(f.helper)).toEqual(q);
      expect(manager.accounting.usedUnits).toBe(
        100 + questionProjectionPlan(f.metadata, "tool").units
      );
      expect(manager.accounting.largeUsedUnits).toBeLessThanOrEqual(1920);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      for (const lease of held) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("charges small-byte JSON with many containers by its independently counted graph", () => {
    const initial = graph();
    const q = { ...initial, aclPolicy: { nested: Array.from({ length: 3000 }, () => []) } };
    const measured = measure(q),
      shape = jsonShape(q),
      cost = questionProjectionCost(measured);
    expect(Number(measured.json_utf8)).toBeLessThan(20_000);
    expect(Number(measured.json_containers)).toBeGreaterThan(3000);
    expect(BigInt(shape.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    const charged = questionProjectionPlan(measured, "tool");
    const noGraph = questionProjectionPlan(
      { ...measured, json_containers: "0", json_properties: "0" },
      "tool"
    );
    expect(charged.units).toBeGreaterThan(noGraph.units);
    expect(BigInt(Buffer.byteLength(JSON.stringify(q)))).toBeLessThanOrEqual(
      BigInt(cost.jsonUpperBytes)
    );
  });
  it("bounds independent serialization and graph oracles for adversarial flat strings and nested JSON", () => {
    const atoms = [
      "\u0001",
      "\b",
      "\t",
      "\n",
      "\f",
      "\r",
      '"',
      "\\",
      "Δ",
      "🙂",
      "\u2028",
      "123e+45"
    ];
    for (let n = 0; n < 32; n += 1) {
      const text = Array.from({ length: 32 }, (_, i) => atoms[(i * 7 + n) % atoms.length]).join("");
      const q = graph(text);
      const citations = [
        {
          [text]: [
            {},
            [],
            { payload: text, number: 1e100, small: 1e-100, flag: false, empty: null }
          ]
        }
      ];
      const withJson = {
        ...q,
        aclPolicy: { [text]: [{}, [], { text }] },
        turns: q.turns.map((t) => ({ ...t, citations }))
      } as unknown as ManagementQuestionView;
      const measured = measure(withJson),
        cost = questionProjectionCost(measured),
        shape = jsonShape(withJson);
      const encoded = JSON.stringify(withJson),
        j = BigInt(cost.jsonUpperBytes);
      expect(BigInt(Buffer.byteLength(encoded))).toBeLessThanOrEqual(j);
      expect(BigInt(shape.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
      expect(BigInt(shape.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
      const wire = JSON.stringify({
        structuredContent: { question: withJson },
        content: [{ type: "text", text: JSON.stringify({ question: withJson }) }]
      });
      expect(Buffer.byteLength(wire)).toBeLessThanOrEqual(
        questionProjectionPlan(measured, "tool").wireUpperBytes
      );
      expect(
        Buffer.byteLength(
          JSON.stringify({
            contents: [
              { uri: "board://synthetic/questions/1", mimeType: "application/json", text: encoded }
            ]
          })
        )
      ).toBeLessThanOrEqual(questionProjectionPlan(measured, "resource").wireUpperBytes);
    }
  });
});
