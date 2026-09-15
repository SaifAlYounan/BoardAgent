import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  BOARD_VOTE_PAGE_PREFLIGHT_SQL,
  BOARD_VOTE_PAGE_CONTENT_SQL,
  PROXY_STATUS_PREFLIGHT_SQL,
  PROXY_STATUS_CONTENT_SQL,
  VOTE_LINEAGE_PREFLIGHT_SQL,
  VOTE_LINEAGE_CONTENT_SQL,
  boardVotePageCost,
  boardVotePagePlan,
  proxyStatusCost,
  proxyStatusPlan,
  voteLineageCost,
  voteLineagePlan,
  loadAdmittedBoardVotePage,
  loadAdmittedProxyStatus,
  loadAdmittedVoteLineage,
  type BoardVotePageKind,
  type BoardVotePageInput,
  type BoardVotePageMetadata,
  type ProxyStatusMetadata,
  type VoteLineageMetadata
} from "../../artifacts/server/src/board-vote-read-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_BOARDS_SQL,
  ORIGINAL_VOTES_SQL,
  ORIGINAL_PROXY_SQL,
  ORIGINAL_VOTE_LINEAGE_SQL
} from "../helpers/board-vote-read-original-sql.js";

// Public parser/registry/callers are real; authority, transaction, and SQL port are modeled.
// Literal fields and original SQL are independent of runtime field descriptors. No SQL/RLS/storage proof.
vi.mock("@boardagent/db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/db/src/index.js")>();
  return {
    ...actual,
    withRequestTransaction: vi.fn(
      async (pool: Pool, _context: unknown, work: (client: PoolClient) => Promise<unknown>) =>
        work((pool as unknown as { fixtureClient: PoolClient }).fixtureClient)
    )
  };
});
type Tool = "list_my_boards" | "list_votes" | "get_proxy_status" | "get_vote_lineage";
const tools: readonly Tool[] = [
  "list_my_boards",
  "list_votes",
  "get_proxy_status",
  "get_vote_lineage"
];
type Item = Record<string, JsonValue>;
const id = (n: number) => `01993700-0000-7000-8000-${String(n).padStart(12, "0")}`;
const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const bytes = (value: unknown) => (value === null ? 0 : Buffer.byteLength(String(value)));
const total = (values: unknown[]) => values.reduce<number>((sum, value) => sum + bytes(value), 0);
function shape(value: unknown) {
  let properties = 0,
    containers = 0;
  const seen = new Set<object>(),
    pending = [value];
  while (pending.length) {
    const node = pending.pop();
    if (node !== null && typeof node === "object" && !seen.has(node)) {
      seen.add(node);
      containers++;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      for (const child of Object.values(node)) pending.push(child);
    }
  }
  return { properties, containers };
}
interface PageSource {
  row: { item: Item; cursor_at: string | null; cursor_id: string };
  join: string | null;
  outcome: string | null;
  raw: string;
}
function boards(): PageSource[] {
  const item = {
    board_id: id(3),
    slug: "synthetic",
    name: 'Board "Δ" 🙂',
    timezone: "UTC",
    state: "active",
    row_version: "2",
    seat_role: "voting_member",
    is_chair: false,
    is_secretary: true,
    voting_weight: "1",
    entitlement_generation: "1"
  };
  // Two joined occurrences have exactly the same original board-only ordering key.
  return [
    {
      row: { item: { ...item }, cursor_at: "2026-09-13T00:00:00.000002Z", cursor_id: id(3) },
      join: id(10),
      outcome: null,
      raw: "2026-09-13 00:00:00.000002+00"
    },
    {
      row: {
        item: { ...item, is_secretary: false },
        cursor_at: "2026-09-13T00:00:00.000002Z",
        cursor_id: id(3)
      },
      join: id(11),
      outcome: null,
      raw: "2026-09-13 00:00:00.000002+00"
    },
    {
      row: {
        item: { ...item, board_id: id(4), slug: "older", name: "Older" },
        cursor_at: "2026-09-13T00:00:00.000001Z",
        cursor_id: id(4)
      },
      join: id(12),
      outcome: null,
      raw: "2026-09-13 00:00:00.000001+00"
    }
  ];
}
function votes(): PageSource[] {
  return [1, 2].map((n) => ({
    row: {
      item: {
        vote_id: id(40 + n),
        board_id: id(3),
        title: `Synthetic vote ${n}`,
        state: n === 1 ? "draft" : "closed",
        resolution_version_id: id(50 + n),
        decision_package_id: id(60 + n),
        package_sha256: n === 1 ? null : "a".repeat(64),
        close_mode: "manual",
        deadline_at: "2026-09-14T00:00:00.000000Z",
        row_version: String(n),
        opened_at: n === 1 ? null : "2026-09-13T00:00:00.000000Z",
        closed_outcome: n === 1 ? null : "passed"
      },
      cursor_at: `2026-09-13T00:00:00.00000${3 - n}Z`,
      cursor_id: id(40 + n)
    },
    join: n === 1 ? null : id(60 + n),
    outcome: n === 1 ? null : id(70 + n),
    raw: `2026-09-13 00:00:00.00000${3 - n}+00`
  }));
}
interface AggregateSource {
  item: Item;
  raw: string;
}
function grants(): AggregateSource[] {
  return [
    {
      item: {
        grant_id: id(20),
        vote_id: id(1),
        principal_member_id: id(2),
        holder_member_id: id(21),
        policy: "discretionary",
        active: true,
        granted_at: "2026-09-13T00:00:00.000001Z",
        expires_at: null,
        revocation: null
      },
      raw: "2026-09-13 00:00:00.000001+00"
    },
    {
      item: {
        grant_id: id(22),
        vote_id: id(1),
        principal_member_id: id(23),
        holder_member_id: id(2),
        policy: "discretionary",
        active: false,
        granted_at: "2026-09-13T00:00:00.000002Z",
        expires_at: "2026-09-14T00:00:00.000000Z",
        revocation: {
          revocation_id: id(24),
          reason: 'Reason "Δ"',
          effect: "prospective",
          revoked_at: "2026-09-13T00:01:00.000001Z"
        }
      },
      raw: "2026-09-13 00:00:00.000002+00"
    }
  ];
}
function edges(): AggregateSource[] {
  return [1, 2].map((n) => ({
    item: {
      supersession_id: id(30 + n),
      old_vote_id: n === 1 ? id(0) : id(1),
      new_vote_id: n === 1 ? id(1) : id(5),
      changed_component_classes:
        n === 1
          ? ["text", null]
          : [
              ["numeric-looking 9999999999999999", null],
              ['quote "', "Δ🙂"]
            ],
      old_package_sha256: "b".repeat(64),
      new_package_sha256: "c".repeat(64),
      secretary_member_id: id(2),
      reason: `Correction ${n}`,
      created_at: `2026-09-13T00:00:00.00000${n}Z`
    },
    raw: `2026-09-13 00:00:00.00000${n}+00`
  }));
}
function pageMeasure(kind: BoardVotePageKind, source: PageSource): BoardVotePageMetadata {
  const v = source.row.item;
  const flat =
    kind === "boards"
      ? [
          v.board_id,
          v.slug,
          v.name,
          v.timezone,
          v.state,
          v.row_version,
          v.seat_role,
          v.is_chair,
          v.is_secretary,
          v.voting_weight,
          v.entitlement_generation
        ]
      : [
          v.vote_id,
          v.board_id,
          v.title,
          v.state,
          v.resolution_version_id,
          v.decision_package_id,
          v.package_sha256,
          v.close_mode,
          v.deadline_at,
          v.row_version,
          v.opened_at,
          v.closed_outcome
        ];
  return {
    id: source.row.cursor_id,
    join_id: source.join,
    outcome_id: source.outcome,
    raw_at: source.raw,
    cursor_at: source.row.cursor_at,
    cursor_id: source.row.cursor_id,
    scalar_utf8: String(total([...flat, source.row.cursor_at, source.row.cursor_id])),
    observation_sha256: sha(
      JSON.stringify([
        flat,
        source.row.cursor_at,
        source.row.cursor_id,
        source.raw,
        source.join,
        source.outcome
      ])
    )
  };
}
function proxyMeasure(rows: AggregateSource[], member = id(2)): ProxyStatusMetadata {
  let s = bytes(id(1)) + bytes(member),
    revocations = 0;
  const tuples: unknown[] = [];
  for (const { item: v, raw } of rows) {
    const flat = [
      v.grant_id,
      v.vote_id,
      v.principal_member_id,
      v.holder_member_id,
      v.policy,
      v.active,
      v.granted_at,
      v.expires_at
    ];
    s += total(flat);
    const r = v.revocation as Item | null;
    if (r !== null) {
      revocations++;
      s += total([r.revocation_id, r.reason, r.effect, r.revoked_at]);
    }
    tuples.push([flat, r, raw]);
  }
  return {
    vote_id: id(1),
    member_id: member,
    principal_id: id(2),
    grant_count: String(rows.length),
    revocation_count: String(revocations),
    scalar_utf8: String(s),
    observation_sha256: sha(rows.length ? JSON.stringify(tuples) : "")
  };
}
function edgeMeasure({ item: v, raw }: AggregateSource): VoteLineageMetadata {
  const flat = [
    v.supersession_id,
    v.old_vote_id,
    v.new_vote_id,
    v.old_package_sha256,
    v.new_package_sha256,
    v.secretary_member_id,
    v.reason,
    v.created_at
  ];
  return {
    supersession_id: v.supersession_id as string,
    old_vote_id: v.old_vote_id as string,
    new_vote_id: v.new_vote_id as string,
    raw_at: raw,
    scalar_utf8: String(total(flat)),
    json_utf8: String(Buffer.byteLength(JSON.stringify(v.changed_component_classes))),
    json_containers: String(shape(v.changed_component_classes).containers),
    observation_sha256: sha(JSON.stringify([flat, v.changed_component_classes, raw]))
  };
}
const pageInput = (kind: BoardVotePageKind, take = 501): BoardVotePageInput => ({
  kind,
  selectorId: kind === "boards" ? id(2) : id(3),
  at: null,
  cursorId: null,
  take
});
function envelope(tool: Tool, data: JsonValue): JsonValue {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: tool.startsWith("list_") ? null : id(1),
    resource_uri: null,
    data
  };
}
function fixture() {
  const state = {
    boards: boards(),
    votes: votes(),
    grants: grants(),
    edges: edges(),
    constructions: 0,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined,
    metadataOverride: undefined as unknown[] | undefined,
    contentOverride: undefined as unknown[] | undefined
  };
  const selectedPage = (kind: BoardVotePageKind, params: unknown[]) =>
    [...state[kind]]
      .sort((a, b) => b.raw.localeCompare(a.raw) || b.row.cursor_id.localeCompare(a.row.cursor_id))
      .filter(
        (row) =>
          params[1] === null ||
          row.row.cursor_at! < String(params[1]) ||
          (row.row.cursor_at === params[1] && row.row.cursor_id < String(params[2]))
      )
      .slice(0, Number(params[3]));
  const selectedProxy = (member: string) =>
    state.grants.filter(
      ({ item: v }) => v.principal_member_id === member || v.holder_member_id === member
    );
  const selectedEdges = () =>
    [...state.edges].sort(
      (a, b) =>
        a.raw.localeCompare(b.raw) ||
        String(a.item.supersession_id).localeCompare(String(b.item.supersession_id))
    );
  const query = vi.fn(async (sql: string, params: unknown[] = []) => {
    for (const kind of ["boards", "votes"] as const) {
      if (sql === BOARD_VOTE_PAGE_PREFLIGHT_SQL[kind]) {
        const rows =
          state.metadataOverride ?? selectedPage(kind, params).map((row) => pageMeasure(kind, row));
        state.afterMetadata?.();
        return { rows };
      }
      if (
        sql === BOARD_VOTE_PAGE_CONTENT_SQL[kind] ||
        sql === (kind === "boards" ? ORIGINAL_BOARDS_SQL : ORIGINAL_VOTES_SQL)
      ) {
        await state.beforeContent?.();
        if (state.contentOverride) return { rows: state.contentOverride };
        const selected = selectedPage(kind, params);
        if (sql === BOARD_VOTE_PAGE_CONTENT_SQL[kind]) {
          const admitted = JSON.parse(String(params[4])) as BoardVotePageMetadata[];
          if (
            !selected.every((row) => {
              const fresh = pageMeasure(kind, row);
              return admitted.some((bound) => JSON.stringify(bound) === JSON.stringify(fresh));
            }) ||
            selected.length > admitted.length
          )
            return { rows: [{ fits: false, item: null, cursor_at: null, cursor_id: null }] };
        }
        state.constructions++;
        return {
          rows: selected.map((source) => ({
            ...source.row,
            ...(sql === BOARD_VOTE_PAGE_CONTENT_SQL[kind] ? { fits: true } : {})
          }))
        };
      }
    }
    if (sql === PROXY_STATUS_PREFLIGHT_SQL) {
      const rows = state.metadataOverride ?? [
        proxyMeasure(selectedProxy(String(params[1])), String(params[1]))
      ];
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === VOTE_LINEAGE_PREFLIGHT_SQL) {
      const rows = state.metadataOverride ?? selectedEdges().map(edgeMeasure).slice(0, 3);
      state.afterMetadata?.();
      return { rows };
    }
    if (
      [
        PROXY_STATUS_CONTENT_SQL,
        VOTE_LINEAGE_CONTENT_SQL,
        ORIGINAL_PROXY_SQL,
        ORIGINAL_VOTE_LINEAGE_SQL
      ].includes(sql)
    )
      await state.beforeContent?.();
    if (state.contentOverride) return { rows: state.contentOverride };
    if (sql === ORIGINAL_PROXY_SQL) {
      state.constructions++;
      return { rows: [{ items: selectedProxy(String(params[1])).map((x) => x.item) }] };
    }
    if (sql === ORIGINAL_VOTE_LINEAGE_SQL) {
      state.constructions++;
      return { rows: [{ items: selectedEdges().map((x) => x.item) }] };
    }
    if (sql === PROXY_STATUS_CONTENT_SQL) {
      const selected = selectedProxy(String(params[1])),
        m = proxyMeasure(selected, String(params[1]));
      const fits =
        m.grant_count === "0" ||
        (m.grant_count === params[3] &&
          m.revocation_count === params[4] &&
          BigInt(m.scalar_utf8) <= BigInt(String(params[5])) &&
          m.observation_sha256 === params[6]);
      if (fits) state.constructions++;
      return { rows: [{ ...m, fits, items: fits ? selected.map((x) => x.item) : null }] };
    }
    if (sql === VOTE_LINEAGE_CONTENT_SQL) {
      const selected = selectedEdges(),
        admitted = JSON.parse(String(params[1])) as VoteLineageMetadata[];
      const fits =
        selected.length <= admitted.length &&
        selected.every((row) =>
          admitted.some((bound) => JSON.stringify(edgeMeasure(row)) === JSON.stringify(bound))
        );
      if (fits) state.constructions++;
      return {
        rows: [
          {
            fits,
            row_count: String(selected.length),
            items: fits ? selected.map((x) => x.item) : null
          }
        ]
      };
    }
    throw new Error("unexpected four-route SQL");
  });
  const client = { query } as unknown as PoolClient,
    repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
      cursorKey: Buffer.alloc(32, 1)
    });
  const principal: SurfacePrincipal = {
    organizationId: id(99),
    memberId: id(2),
    serviceOrigin: "https://boardagent.test",
    clientId: id(97),
    protocolClientId: "four-read-unit",
    accessTokenRecordId: id(96),
    tokenJti: id(95),
    keyId: "fixture",
    scopes: ["governance:read"],
    roles: ["member"],
    boardIds: [id(3), id(4)]
  };
  const seam = repo as unknown as {
    liveActor(...args: unknown[]): Promise<unknown>;
    authorizeRead(...args: unknown[]): void;
    dispatch(
      client: PoolClient,
      principal: SurfacePrincipal,
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    listBoards(
      client: PoolClient,
      principal: SurfacePrincipal,
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
    readVote(
      client: PoolClient,
      principal: SurfacePrincipal,
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({}),
    authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, name, input) => {
    if (!tools.includes(name as Tool)) throw new Error("out-of-scope dispatch");
    return name === "list_my_boards"
      ? seam.listBoards(connection, actor, name, input)
      : seam.readVote(connection, actor, name, input);
  });
  const helper = (tool: Tool): Promise<unknown> =>
    tool === "list_my_boards"
      ? loadAdmittedBoardVotePage(client, pageInput("boards"))
      : tool === "list_votes"
        ? loadAdmittedBoardVotePage(client, pageInput("votes"))
        : tool === "get_proxy_status"
          ? loadAdmittedProxyStatus(client, id(1), id(2), id(2))
          : loadAdmittedVoteLineage(client, id(1));
  const read = (
    tool: Tool,
    limit = 500,
    cursor: string | null = null,
    member: string | null = null
  ) =>
    repo.executeRead(principal, tool, {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      ...(tool === "list_my_boards"
        ? { limit, cursor }
        : tool === "list_votes"
          ? { board_id: id(3), limit, cursor }
          : tool === "get_proxy_status"
            ? { vote_id: id(1), member_id: member }
            : { vote_id: id(1) })
    });
  return { state, client, query, liveActor, authorize, helper, read };
}
const small = () =>
  responseAllocationPlan({
    kind: "document",
    representation: "resource",
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
    try {
      owner.nativeTerminal();
    } finally {
      owner.collectorSettled();
    }
  }
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
async function deadline<T>(promise: Promise<T>) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("bounded producer wait expired")), 2000);
      })
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

describe("board and vote read projection admission", () => {
  for (const tool of tools)
    it(`refuses public ${tool} before full construction under complete occupancy`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager(),
        leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
      let failure: unknown;
      try {
        try {
          await owned(manager, () => f.read(tool));
        } catch (error) {
          failure = error;
        }
        expect(f.state.constructions, "old caller attempted full projection before admission").toBe(
          0
        );
        expect(failure).toBeInstanceOf(ResponseAllocationUnavailable);
        expect(f.liveActor).toHaveBeenCalledOnce();
        expect(f.authorize).toHaveBeenCalledOnce();
        expect(f.query).toHaveBeenCalledOnce();
      } finally {
        for (const lease of leases) lease.release();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    });
  for (const tool of tools)
    for (const empty of [false, true])
      it(`preserves complete original ${tool} ${empty ? "empty" : "populated"} envelope`, async () => {
        const f = fixture();
        if (empty) {
          f.state.boards = [];
          f.state.votes = [];
          f.state.grants = [];
          f.state.edges = [];
        }
        const data: JsonValue =
          tool === "list_my_boards"
            ? { items: f.state.boards.map((x) => x.row.item), next_cursor: null }
            : tool === "list_votes"
              ? { items: f.state.votes.map((x) => x.row.item), next_cursor: null }
              : tool === "get_proxy_status"
                ? { vote_id: id(1), member_id: id(2), grants: f.state.grants.map((x) => x.item) }
                : { vote_id: id(1), lineage: f.state.edges.map((x) => x.item) };
        const expected = envelope(tool, data),
          actual = await owned(new ResponseAllocationManager(), () => f.read(tool));
        expect(actual).toEqual(expected);
        expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
        expect(canonicalJson(actual)).toBe(canonicalJson(expected));
      });
  it("preserves explicit proxy member selection separately from the requesting principal", async () => {
    const f = fixture(),
      actual = await owned(new ResponseAllocationManager(), () =>
        f.read("get_proxy_status", 500, null, id(21))
      );
    expect(actual).toEqual(
      envelope("get_proxy_status", {
        vote_id: id(1),
        member_id: id(21),
        grants: [grants()[0]!.item]
      })
    );
  });
  for (const collaborator of ["liveActor", "authorize"] as const)
    it(`preserves ${collaborator} denial before any of the four projections`, async () => {
      for (const tool of tools) {
        const f = fixture(),
          error = new Error("synthetic initial denial");
        if (collaborator === "liveActor") f.liveActor.mockRejectedValueOnce(error);
        else
          f.authorize.mockImplementationOnce(() => {
            throw error;
          });
        await expect(owned(new ResponseAllocationManager(), () => f.read(tool))).rejects.toBe(
          error
        );
        expect(f.query).not.toHaveBeenCalled();
      }
    });
  it("keeps duplicate board occurrences and the existing board-only cursor behavior", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    const first = await owned(manager, () => f.read("list_my_boards", 1));
    expect((first.data as Item).items).toEqual([boards()[0]!.row.item]);
    const cursor = (first.data as Item).next_cursor;
    expect(typeof cursor).toBe("string");
    const next = await owned(manager, () => f.read("list_my_boards", 1, cursor as string));
    expect((next.data as Item).items).toEqual([boards()[2]!.row.item]);
    // The second tied membership remains skipped by the original board-only cursor; no new ordering contract.
  });
  it("charges all 501 joined lookahead rows while preserving the 500-item public page", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager();
    f.state.boards = Array.from({ length: 501 }, (_, n) => ({
      ...boards()[0]!,
      join: id(1000 + n)
    }));
    const owner = manager.openRequest(new AbortController().signal);
    try {
      const actual = await owner.produce(() => f.read("list_my_boards"));
      expect((actual.data as Item).items as JsonValue[]).toHaveLength(500);
      expect(typeof (actual.data as Item).next_cursor).toBe("string");
      expect(f.query.mock.calls[0]?.[1]?.[3]).toBe(501);
      expect(manager.accounting.usedUnits).toBe(
        boardVotePagePlan(
          pageInput("boards"),
          f.state.boards.map((x) => pageMeasure("boards", x))
        ).units
      );
    } finally {
      try {
        owner.nativeTerminal();
      } finally {
        owner.collectorSettled();
      }
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("accepts exact surviving page subsets and tie permutations, but refuses unseen boundary occurrences", async () => {
    for (const change of ["subset", "tie", "new"]) {
      const f = fixture();
      f.state.afterMetadata = () => {
        if (change === "subset") f.state.boards = f.state.boards.slice(1);
        else if (change === "tie")
          f.state.boards = [f.state.boards[1]!, f.state.boards[0]!, f.state.boards[2]!];
        else f.state.boards[0]!.join = id(999);
      };
      if (change === "new") {
        await expect(
          owned(new ResponseAllocationManager(), () => f.helper("list_my_boards"))
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(f.state.constructions).toBe(0);
      } else
        expect(
          await owned(new ResponseAllocationManager(), () => f.helper("list_my_boards"))
        ).toEqual(f.state.boards.map((x) => ({ ...x.row, fits: true })));
    }
  });
  it("refuses fresh page scalar, joined outcome and raw timestamp changes despite retained root identity", async () => {
    for (const change of ["scalar", "outcome", "time", "new"]) {
      const f = fixture();
      f.state.afterMetadata = () => {
        if (change === "scalar") f.state.votes[0]!.row.item.title = "Synthetic vote X";
        else if (change === "outcome") f.state.votes[1]!.outcome = id(999);
        else if (change === "time") f.state.votes[0]!.raw = "2026-09-13 00:00:00.000003+00";
        else
          f.state.votes.unshift({
            ...f.state.votes[0]!,
            row: {
              ...f.state.votes[0]!.row,
              cursor_id: id(999),
              item: { ...f.state.votes[0]!.row.item, vote_id: id(999) }
            }
          });
      };
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper("list_votes"))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
    }
  });
  it("uses strict nonempty proxy observations and permits only complete fresh loss without a new request", async () => {
    for (const change of ["reason", "partial", "growth", "empty"]) {
      const f = fixture();
      f.state.afterMetadata = () => {
        if (change === "reason") (f.state.grants[1]!.item.revocation as Item).reason = 'Reason "Γ"';
        else if (change === "partial") f.state.grants.pop();
        else if (change === "growth")
          f.state.grants.push({
            ...f.state.grants[0]!,
            item: { ...f.state.grants[0]!.item, grant_id: id(999) }
          });
        else f.state.grants = [];
      };
      if (change === "empty")
        expect(
          await owned(new ResponseAllocationManager(), () => f.helper("get_proxy_status"))
        ).toEqual([]);
      else {
        await expect(
          owned(new ResponseAllocationManager(), () => f.helper("get_proxy_status"))
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(f.state.constructions).toBe(0);
      }
    }
  });
  it("allows lineage endpoint subsets but binds same-byte array contents and lossless raw timestamp text", async () => {
    for (const change of ["subset", "empty", "array", "time"]) {
      const f = fixture();
      f.state.afterMetadata = () => {
        if (change === "subset") f.state.edges.pop();
        else if (change === "empty") f.state.edges = [];
        else if (change === "array")
          f.state.edges[0]!.item.changed_component_classes = ["next", null];
        else f.state.edges[0]!.raw = "2026-09-13 00:00:00.000003+00";
      };
      if (change === "subset" || change === "empty")
        expect(
          await owned(new ResponseAllocationManager(), () => f.helper("get_vote_lineage"))
        ).toEqual(f.state.edges.map((x) => x.item));
      else {
        await expect(
          owned(new ResponseAllocationManager(), () => f.helper("get_vote_lineage"))
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(f.state.constructions).toBe(0);
      }
    }
  });
  it("refuses new nonempty aggregates selected after an empty preflight", async () => {
    for (const tool of ["get_proxy_status", "get_vote_lineage"] as const) {
      const f = fixture();
      f.state.grants = [];
      f.state.edges = [];
      f.state.afterMetadata = () => {
        f.state.grants = grants();
        f.state.edges = edges();
      };
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper(tool))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
    }
  });
  it("bounds adversarial literal outputs, full SDK graphs and nested wire independently", () => {
    const escape = '\u0001\n\\\"Δ🙂'.repeat(1000),
      b = boards(),
      v = votes(),
      g = grants(),
      e = edges();
    b[0]!.row.item.name = escape;
    v[0]!.row.item.title = escape;
    (g[1]!.item.revocation as Item).reason = escape;
    e[0]!.item.reason = escape;
    e[1]!.item.changed_component_classes = [
      [escape, null],
      ["9999999999999999", ""]
    ];
    const examples = [
      {
        tool: "list_my_boards" as Tool,
        data: { items: b.map((x) => x.row.item), next_cursor: null },
        retained: b.map((x) => ({ ...x.row, fits: true })),
        cost: boardVotePageCost(
          "boards",
          b.map((x) => pageMeasure("boards", x))
        ),
        plan: boardVotePagePlan(
          pageInput("boards"),
          b.map((x) => pageMeasure("boards", x))
        )
      },
      {
        tool: "list_votes" as Tool,
        data: { items: v.map((x) => x.row.item), next_cursor: null },
        retained: v.map((x) => ({ ...x.row, fits: true })),
        cost: boardVotePageCost(
          "votes",
          v.map((x) => pageMeasure("votes", x))
        ),
        plan: boardVotePagePlan(
          pageInput("votes"),
          v.map((x) => pageMeasure("votes", x))
        )
      },
      {
        tool: "get_proxy_status" as Tool,
        data: { vote_id: id(1), member_id: id(2), grants: g.map((x) => x.item) },
        retained: { vote_id: id(1), member_id: id(2), grants: g.map((x) => x.item) },
        cost: proxyStatusCost(proxyMeasure(g)),
        plan: proxyStatusPlan(proxyMeasure(g))
      },
      {
        tool: "get_vote_lineage" as Tool,
        data: { vote_id: id(1), lineage: e.map((x) => x.item) },
        retained: { vote_id: id(1), lineage: e.map((x) => x.item) },
        cost: voteLineageCost(e.map(edgeMeasure)),
        plan: voteLineagePlan(id(1), e.map(edgeMeasure))
      }
    ];
    for (const example of examples) {
      const body = envelope(example.tool, example.data as JsonValue),
        wire = { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body };
      expect(Buffer.byteLength(JSON.stringify(example.retained))).toBeLessThanOrEqual(
        Number(example.cost.jsonUpperBytes)
      );
      expect(shape(wire).properties).toBeLessThanOrEqual(Number(example.cost.propertyCount));
      expect(shape(wire).containers).toBeLessThanOrEqual(Number(example.cost.objectOrArrayCount));
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(
        example.plan.wireUpperBytes
      );
    }
    for (const kind of ["proxy", "lineage"] as const) {
      const items = (kind === "proxy" ? g : e).map((x) => x.item);
      const data =
        kind === "proxy"
          ? { vote_id: id(1), member_id: id(2), grants: items }
          : { vote_id: id(1), lineage: items };
      const body = envelope(kind === "proxy" ? "get_proxy_status" : "get_vote_lineage", data),
        wire = { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body };
      const pgRows =
        kind === "proxy"
          ? [{ ...proxyMeasure(g), fits: true, items }]
          : [{ fits: true, row_count: String(items.length), items }];
      // The synthetic root only enumerates two retained roots, and is not itself counted.
      const combined = shape([pgRows, wire]);
      const cost =
        kind === "proxy" ? proxyStatusCost(proxyMeasure(g)) : voteLineageCost(e.map(edgeMeasure));
      expect(combined.containers - 1).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
      expect(combined.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
    }
    expect(shape(e[1]!.item.changed_component_classes)).toEqual({ properties: 0, containers: 3 });
  });
  it("matches twelve independently derived integer vectors including both 1920/1921 boundaries", () => {
    const vectors = [
      ["boards", 0, 0, 0, 0, 0, 2, 25, 7, 108304, 77830, 1],
      ["votes", 0, 0, 0, 0, 0, 2, 25, 7, 108304, 77830, 1],
      ["proxy", 0, 72, 0, 0, 0, 486, 26, 8, 112944, 79282, 1],
      ["lineage", 0, 36, 0, 0, 0, 252, 25, 8, 110816, 78580, 1],
      ["boards", 501, 128256, 0, 0, 0, 912824, 7540, 1009, 9847744, 2816296, 10],
      ["votes", 501, 256512, 0, 0, 0, 1702400, 8041, 1009, 16292608, 5185024, 16],
      ["proxy", 1, 262500, 1, 0, 0, 1575317, 39, 10, 12715944, 4803775, 13],
      ["lineage", 2, 524800, 0, 128, 2, 3149418, 43, 12, 25310800, 9526078, 25],
      ["proxy", 161, 41919104, 161, 0, 0, 251557021, 2119, 330, 2013265896, 754748887, 1920],
      ["proxy", 161, 41919105, 161, 0, 0, 251557027, 2119, 330, 2013265944, 754748905, 1921],
      ["lineage", 2, 524800, 0, 248494518, 2, 251643808, 43, 12, 2013265920, 755009248, 1920],
      ["lineage", 2, 524800, 0, 248494519, 2, 251643809, 43, 12, 2013265928, 755009251, 1921]
    ] as const;
    for (const [kind, r, s, v, n, o, j, p, containers, a, wire, units] of vectors) {
      let cost, plan;
      if (kind === "boards" || kind === "votes") {
        const metadata = Array.from({ length: r }, (_, index) => ({
          ...pageMeasure(kind, (kind === "boards" ? boards() : votes())[0]!),
          scalar_utf8: String(index === 0 ? s : 0)
        }));
        cost = boardVotePageCost(kind, metadata);
        plan = boardVotePagePlan(pageInput(kind), metadata);
      } else if (kind === "proxy") {
        const metadata = {
          ...proxyMeasure([]),
          grant_count: String(r),
          revocation_count: String(v),
          scalar_utf8: String(s)
        };
        cost = proxyStatusCost(metadata);
        plan = proxyStatusPlan(metadata);
      } else {
        const metadata = Array.from({ length: r }, (_, index) => ({
          ...edgeMeasure(edges()[0]!),
          scalar_utf8: String(index === 0 ? s - 36 : 0),
          json_utf8: String(index === 0 ? n - (r - 1) : 1),
          json_containers: String(index === 0 ? o - (r - 1) : 1)
        }));
        cost = voteLineageCost(metadata);
        plan = voteLineagePlan(id(1), metadata);
      }
      expect(cost).toEqual({
        jsonUpperBytes: String(j),
        propertyCount: String(p),
        objectOrArrayCount: String(containers)
      });
      expect(65536 + 8 * (j + 4096) + 256 * p + 512 * containers).toBe(a);
      expect(plan.units).toBe(units);
      expect(plan.wireUpperBytes).toBe(wire);
    }
  });
  it("crosses an exact one-unit lineage boundary at one added JSON byte", () => {
    const metadata = [
      { ...edgeMeasure(edges()[0]!), scalar_utf8: "0", json_utf8: "116577", json_containers: "1" }
    ];
    const cost = voteLineageCost(metadata);
    expect(cost).toEqual({
      jsonUpperBytes: "117056",
      propertyCount: "34",
      objectOrArrayCount: "10"
    });
    expect(65536 + 8 * (117056 + 4096) + 256 * 34 + 512 * 10).toBe(1048576);
    expect(voteLineagePlan(id(1), metadata).units).toBe(1);
    expect(voteLineagePlan(id(1), [{ ...metadata[0]!, json_utf8: "116578" }]).units).toBe(2);
  });
  it("admits the 1920-unit lineage plan alongside 100 small leases and rejects one extra JSON byte", () => {
    const metadata = edges().map(edgeMeasure);
    Object.assign(metadata[0]!, {
      scalar_utf8: "524764",
      json_utf8: "248494517",
      json_containers: "1"
    });
    Object.assign(metadata[1]!, { scalar_utf8: "0", json_utf8: "1", json_containers: "1" });
    const manager = new ResponseAllocationManager(),
      smallLeases = Array.from({ length: 100 }, () => manager.tryReserve(small()));
    let lease: ReturnType<typeof manager.tryReserve> | undefined;
    try {
      lease = manager.tryReserve(voteLineagePlan(id(1), metadata));
      expect(manager.accounting.usedUnits).toBe(2020);
      lease.release();
      lease = undefined;
      const over = voteLineagePlan(id(1), [
        { ...metadata[0]!, json_utf8: "248494518" },
        metadata[1]!
      ]);
      expect(over.units).toBe(1921);
      expect(() => manager.tryReserve(over)).toThrow(ResponseAllocationUnavailable);
    } finally {
      lease?.release();
      for (const smallLease of smallLeases) smallLease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("refuses oversized scalar metadata before any full content query", async () => {
    for (const tool of tools) {
      const f = fixture();
      f.state.metadataOverride =
        tool === "list_my_boards"
          ? [{ ...pageMeasure("boards", boards()[0]!), scalar_utf8: "999999999" }]
          : tool === "list_votes"
            ? [{ ...pageMeasure("votes", votes()[0]!), scalar_utf8: "999999999" }]
            : tool === "get_proxy_status"
              ? [{ ...proxyMeasure(grants()), scalar_utf8: "999999999" }]
              : [{ ...edgeMeasure(edges()[0]!), json_utf8: "999999999" }];
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper(tool))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledOnce();
      expect(f.state.constructions).toBe(0);
    }
  });
  it("rejects duplicate or foreign metadata and the bounded third-edge inconsistency detector", async () => {
    for (const change of ["duplicate-board", "foreign-edge", "third-edge", "proxy-selector"]) {
      const f = fixture();
      let tool: Tool;
      if (change === "duplicate-board") {
        tool = "list_my_boards";
        const m = pageMeasure("boards", boards()[0]!);
        f.state.metadataOverride = [m, m];
      } else if (change === "proxy-selector") {
        tool = "get_proxy_status";
        f.state.metadataOverride = [{ ...proxyMeasure(grants()), member_id: id(999) }];
      } else {
        tool = "get_vote_lineage";
        f.state.metadataOverride =
          change === "third-edge"
            ? [...edges().map(edgeMeasure), edgeMeasure(edges()[0]!)]
            : [{ ...edgeMeasure(edges()[0]!), old_vote_id: id(998), new_vote_id: id(999) }];
      }
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper(tool))
      ).rejects.toBeInstanceOf(change === "third-edge" ? ResponseAllocationUnavailable : TypeError);
      expect(f.query).toHaveBeenCalledOnce();
    }
    expect(() => proxyStatusCost({ ...proxyMeasure([]), grant_count: "00" })).toThrow(TypeError);
    expect(() => proxyStatusCost({ ...proxyMeasure([]), scalar_utf8: "9".repeat(25) })).toThrow(
      ResponseAllocationUnavailable
    );
  });
  it("rejects forged loaded page IDs, aggregate headers and lineage endpoints", async () => {
    for (const tool of tools) {
      const f = fixture();
      if (tool === "list_my_boards" || tool === "list_votes") {
        const source = (tool === "list_my_boards" ? boards() : votes())[0]!;
        f.state.contentOverride = [{ ...source.row, fits: true, cursor_id: id(999) }];
      } else if (tool === "get_proxy_status")
        f.state.contentOverride = [
          {
            ...proxyMeasure(grants()),
            fits: true,
            observation_sha256: sha("forged"),
            items: grants().map((x) => x.item)
          }
        ];
      else
        f.state.contentOverride = [
          { fits: true, row_count: "1", items: [{ ...edges()[0]!.item, new_vote_id: id(999) }] }
        ];
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper(tool))
      ).rejects.toBeInstanceOf(TypeError);
    }
  });
  it("keeps the new kind private, tool-only and zero-raw, with factory-recomputed weights", () => {
    const plan = proxyStatusPlan(proxyMeasure(grants()));
    expect(plan.canonicalBytes).toBe(0);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    const manager = new ResponseAllocationManager();
    const lease = manager.tryReserve({ ...plan, units: 0 });
    try {
      expect(manager.accounting.usedUnits).toBe(plan.units);
    } finally {
      lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("prevents all four content queries when disconnect follows preflight", async () => {
    for (const tool of tools) {
      const f = fixture(),
        manager = new ResponseAllocationManager(),
        controller = new AbortController(),
        owner = manager.openRequest(controller.signal);
      f.state.afterMetadata = () => controller.abort();
      try {
        await expect(owner.produce(() => f.helper(tool))).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(f.query).toHaveBeenCalledOnce();
      } finally {
        try {
          owner.nativeTerminal();
        } finally {
          owner.collectorSettled();
        }
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
  });
  it("retains a pending producer through disconnect and both markers until actual settlement", async () => {
    const f = fixture(),
      manager = new ResponseAllocationManager(),
      controller = new AbortController(),
      owner = manager.openRequest(controller.signal),
      entered = gate(),
      release = gate();
    f.state.beforeContent = async () => {
      entered.release();
      await release.promise;
    };
    const produced = owner.produce(() => f.helper("get_proxy_status"));
    const settled = produced.then(
      (value) => ({ ok: true as const, value }),
      (error) => ({ ok: false as const, error })
    );
    let failure: unknown;
    try {
      await deadline(
        Promise.race([
          entered.promise,
          settled.then((result) => {
            throw new Error("producer ended before content gate", {
              cause: result.ok ? undefined : result.error
            });
          })
        ])
      );
      expect(manager.accounting.usedUnits).toBe(1);
      controller.abort();
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(1);
      release.release();
      const outcome = await deadline(settled);
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) expect(outcome.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(manager.accounting.usedUnits).toBe(0);
    } catch (error) {
      failure = error;
    } finally {
      release.release();
      controller.abort();
      try {
        owner.nativeTerminal();
      } finally {
        owner.collectorSettled();
      }
      try {
        await deadline(settled);
      } catch (error) {
        failure =
          failure === undefined
            ? error
            : new AggregateError([failure, error], "test and producer cleanup failed");
      }
    }
    if (failure !== undefined) throw failure;
  });
  it("retains all empty responses until actual terminal and collector settlement", async () => {
    for (const tool of tools) {
      const f = fixture();
      f.state.boards = [];
      f.state.votes = [];
      f.state.grants = [];
      f.state.edges = [];
      const manager = new ResponseAllocationManager(),
        owner = manager.openRequest(new AbortController().signal);
      try {
        expect(await owner.produce(() => f.helper(tool))).toEqual([]);
        expect(manager.accounting.usedUnits).toBe(1);
        owner.collectorSettled();
        expect(manager.accounting.usedUnits).toBe(1);
        owner.nativeTerminal();
        expect(manager.accounting.usedUnits).toBe(0);
      } finally {
        try {
          owner.nativeTerminal();
        } finally {
          owner.collectorSettled();
        }
      }
    }
  });
});
