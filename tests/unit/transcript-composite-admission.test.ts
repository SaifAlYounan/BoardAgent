import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  transcriptProjectionCost,
  type TranscriptProjectionScalars
} from "../../artifacts/server/src/response-allocation.js";
import {
  loadAdmittedTranscriptProjection,
  TRANSCRIPT_CONTENT_SQL,
  TRANSCRIPT_PREFLIGHT_SQL
} from "../../artifacts/server/src/transcript-projection-read.js";

const id = (tail: number) => `018f47a1-1f5d-7c3a-8b22-${String(tail).padStart(12, "0")}`;
const empty: TranscriptProjectionScalars = {
  rootUtf8Bytes: "512",
  turnCount: "0",
  turnUtf8Bytes: "0",
  challengeCount: "0",
  challengeUtf8Bytes: "0",
  verificationCount: "0",
  verificationUtf8Bytes: "0"
};
function plan(canonicalBytes: number, transcriptProjection: TranscriptProjectionScalars = empty) {
  return responseAllocationPlan({
    kind: "transcript_tool",
    representation: "tool",
    sourceId: id(1),
    sourceVersion: `${id(2)}:1`,
    sha256: "a".repeat(64),
    canonicalBytes,
    transcriptProjection
  });
}

describe("complete transcript projection accounting", () => {
  it("admits the supported maximum annex and a conservative maximum parser-turn envelope", () => {
    const markdown = plan(10_485_760);
    const turns = plan(10_485_760, {
      ...empty,
      turnCount: "10000",
      turnUtf8Bytes: "11225760",
      verificationCount: "1",
      verificationUtf8Bytes: "256"
    });
    expect(markdown.units).toBe(1_281);
    expect(turns.units).toBe(1_832);
    for (const candidate of [markdown, turns]) {
      const manager = new ResponseAllocationManager();
      const lease = manager.tryReserve(candidate);
      expect(manager.accounting.usedUnits).toBe(candidate.units);
      lease.release();
    }
  });

  it("admits the exact large-work boundary and refuses one further UTF-8 byte", () => {
    // Fixed independently recorded boundary vector; this test does not calculate
    // the implementation's formula to obtain its expected admission decision.
    const scalars = {
      ...empty,
      turnCount: "1",
      turnUtf8Bytes: "256",
      challengeCount: "16",
      challengeUtf8Bytes: "39142525"
    };
    const exact = plan(1_048_576, scalars);
    const over = plan(1_048_576, { ...scalars, challengeUtf8Bytes: "39142526" });
    expect(exact.units).toBe(1_920);
    expect(over.units).toBe(1_921);
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(exact);
    const small = responseAllocationPlan({
      kind: "document",
      representation: "tool",
      sourceId: id(4),
      sourceVersion: "1",
      sha256: "b".repeat(64),
      canonicalBytes: 4096
    });
    const smallLeases = Array.from({ length: 100 }, () => manager.tryReserve(small));
    expect(manager.accounting.usedUnits).toBe(2_020);
    for (const lease of smallLeases) lease.release();
    held.release();
    expect(() => manager.tryReserve(over)).toThrow(ResponseAllocationUnavailable);
    expect(() => manager.tryReserve({ ...over, units: 1, wireUpperBytes: 1 })).toThrow(
      ResponseAllocationUnavailable
    );
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it.each(["999999999999999999999999", "1000000000000000000000000"])(
    "refuses overflow-sized scalar %s without unsafe Number arithmetic",
    (challengeUtf8Bytes) => {
      expect(() => plan(1, { ...empty, challengeCount: "1", challengeUtf8Bytes })).toThrow(
        ResponseAllocationUnavailable
      );
    }
  );

  it.each(["-1", "1.5", "1e20", "NaN"])("fails closed on malformed scalar %s", (turnCount) => {
    expect(() => plan(1, { ...empty, turnCount })).toThrow(
      "transcript projection scalar is invalid"
    );
  });

  it("freezes the exact input scalars and rejects an incomplete or resource-shaped composite plan", () => {
    const mutable = { ...empty };
    const selected = plan(10_485_760, mutable);
    mutable.challengeUtf8Bytes = "100000000";
    expect(selected.transcriptProjection?.challengeUtf8Bytes).toBe("0");
    expect(Object.isFrozen(selected.transcriptProjection)).toBe(true);
    expect(() => responseAllocationPlan({ ...selected, representation: "resource" })).toThrow(
      "transcript tool allocation requires the complete projection"
    );
    const { transcriptProjection: _unused, ...incomplete } = selected;
    expect(() => responseAllocationPlan(incomplete)).toThrow(
      "transcript tool allocation requires the complete projection"
    );
  });

  it("bounds actual JSON and nested tool encoding for generated adversarial flat strings", () => {
    const alphabet = ['"', "\\", "\n", "\t", "\u0001", "é", "Δ", "😀", "z"];
    const scalarBytes = (object: Record<string, unknown>, skip: ReadonlySet<string> = new Set()) =>
      Object.entries(object).reduce(
        (total, [key, value]) =>
          total +
          (skip.has(key) || value === null || typeof value === "object"
            ? 0
            : Buffer.byteLength(String(value), "utf8")),
        0
      );
    for (let seed = 0; seed < 64; seed += 1) {
      const text =
        seed === 0
          ? "\u0001".repeat(4096)
          : Array.from(
              { length: 4096 },
              (_, i) => alphabet[(i * (seed + 1) + seed) % alphabet.length]
            ).join("");
      const turns = Array.from({ length: seed % 4 }, (_, i) => ({
        turn_id: id(i + 10),
        ordinal: 2_147_483_647 - i,
        speaker_member_id: i % 2 ? null : id(20),
        speaker_label: text.slice(0, 31),
        starts_at_ms: i % 2 ? null : "9223372036854775806",
        ends_at_ms: i % 2 ? null : "9223372036854775807",
        canonical_text: text,
        sha256: "f".repeat(64)
      }));
      const challenges = Array.from({ length: seed % 3 }, (_, i) => ({
        challenge_id: id(i + 30),
        turn_id: id(10),
        challenger_member_id: id(40),
        canonical_comment: text,
        comment_sha256: "e".repeat(64),
        state: "pending",
        created_at: "2026-09-12T14:00:00.123456Z"
      }));
      const verification =
        seed % 2
          ? null
          : {
              verification_id: id(50),
              sha256: "d".repeat(64),
              secretary_member_id: id(60),
              status: "secretary_verified",
              verified_at: "2026-09-12T14:00:00.123456Z"
            };
      const view = {
        transcript_id: id(2),
        meeting_id: id(3),
        state: "active",
        version_id: id(1),
        version: 2_147_483_647,
        canonical_schema: "boardagent.transcript-turns.v1",
        media_type: "application/json",
        canonical_body: text,
        sha256: "a".repeat(64),
        source_type: "agent_prepared",
        verification_state: "agent_prepared_unverified",
        supersedes_id: seed % 2 ? null : id(70),
        turns,
        challenges,
        verification
      };
      const n = Buffer.byteLength(text);
      const scalars = {
        rootUtf8Bytes: String(scalarBytes(view, new Set(["canonical_body"]))),
        turnCount: String(turns.length),
        turnUtf8Bytes: String(turns.reduce((sum, row) => sum + scalarBytes(row), 0)),
        challengeCount: String(challenges.length),
        challengeUtf8Bytes: String(challenges.reduce((sum, row) => sum + scalarBytes(row), 0)),
        verificationCount: verification ? "1" : "0",
        verificationUtf8Bytes: String(verification ? scalarBytes(verification) : 0)
      };
      const bound = transcriptProjectionCost(n, scalars);
      const result = {
        schema_version: "boardagent.tool-result.v1",
        tool: "get_meeting_transcript",
        status: "ok",
        reference: id(1),
        resource_uri: null,
        data: { transcript: view }
      };
      const encoded = JSON.stringify({
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: result
      });
      // JSON.stringify is the independent encoding oracle, not a second copy of
      // the bound formula. Some strings exceed application canonical-text rules.
      expect(Buffer.byteLength(JSON.stringify(view))).toBeLessThanOrEqual(bound.viewJsonUpperBytes);
      expect(Buffer.byteLength(encoded)).toBeLessThanOrEqual(bound.wireUpperBytes);
    }
    const control = "\u0001".repeat(4096);
    expect(Buffer.byteLength(JSON.stringify(control))).toBe(6 * Buffer.byteLength(control) + 2);
  });
});

// Query/authority fixtures below exercise the selected loader seam only. The
// separate PostgreSQL proposal proves the CASE gate under actual application RLS.
function fixture() {
  const bytes = Buffer.from('{"exact":"transcript Δ"}');
  const metadata = {
    board_id: id(3),
    meeting_id: id(4),
    version_id: id(1),
    version: 7,
    media_type: "application/json",
    canonical_length: bytes.length,
    canonical_sha256: createHash("sha256").update(bytes).digest("hex"),
    root_utf8: "512",
    turn_count: "0",
    turn_utf8: "0",
    challenge_count: "0",
    challenge_utf8: "0",
    verification_count: "0",
    verification_utf8: "0"
  };
  const view = { transcript_id: id(2), version_id: id(1), canonical_body: bytes.toString("utf8") };
  const query = vi.fn(
    async (sql: string, _values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }> => {
      if (sql === TRANSCRIPT_PREFLIGHT_SQL) return { rows: [metadata] };
      if (sql === TRANSCRIPT_CONTENT_SQL)
        return { rows: [{ ...metadata, fits: true, view, canonical_bytes: bytes }] };
      throw new Error("legacy full transcript construction ran before admission");
    }
  );
  return { bytes, metadata, view, query, client: { query } as unknown as PoolClient };
}

describe("transcript composite pre-load seam", () => {
  it("refuses the actual tool branch before constructing view/bytea or preparing an audit", async () => {
    const f = fixture();
    f.metadata.canonical_length = 10_485_760;
    const repository = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
    const seam = repository as unknown as {
      readMeeting(
        client: PoolClient,
        principal: SurfacePrincipal,
        tool: string,
        input: Record<string, string | null>
      ): Promise<unknown>;
      prepareResourceAudit(...args: unknown[]): Promise<string>;
    };
    const audit = vi.spyOn(seam, "prepareResourceAudit").mockResolvedValue(id(90));
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(
      responseAllocationPlan({
        kind: "document",
        representation: "tool",
        sourceId: id(5),
        sourceVersion: "1",
        sha256: "c".repeat(64),
        canonicalBytes: 10_485_760
      })
    );
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() =>
          seam.readMeeting(f.client, {} as SurfacePrincipal, "get_meeting_transcript", {
            transcript_id: id(2),
            version_id: null
          })
        )
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.query.mock.calls[0]?.[0]).toBe(TRANSCRIPT_PREFLIGHT_SQL);
      expect(audit).not.toHaveBeenCalled();
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      held.release();
    }
  });

  it("pins the selected current/explicit version and supplies scalar budgets to the guarded statement", async () => {
    const f = fixture();
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedTranscriptProjection(f.client, id(2), null))
      ).resolves.toMatchObject({
        version_id: id(1),
        version: 7,
        view: f.view,
        canonical_bytes: f.bytes
      });
      expect(f.query).toHaveBeenCalledTimes(2);
      expect(f.query.mock.calls[0]?.[1]).toEqual([id(2), null]);
      const values = f.query.mock.calls[1]?.[1];
      expect(values?.slice(0, 8)).toEqual([
        id(2),
        id(1),
        7,
        f.bytes.length,
        Buffer.from(f.metadata.canonical_sha256, "hex"),
        "application/json",
        id(3),
        id(4)
      ]);
      expect(values?.[8]).toEqual(expect.any(Number));
      expect(values?.[9]).toEqual(expect.any(Number));
      expect(manager.accounting.usedUnits).toBe(1);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("maps a fresh growth refusal to the existing capacity error and retains the lease", async () => {
    const f = fixture();
    f.query.mockImplementation(async (sql) =>
      sql === TRANSCRIPT_PREFLIGHT_SQL
        ? { rows: [f.metadata] }
        : { rows: [{ ...f.metadata, fits: false, view: null, canonical_bytes: null }] }
    );
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedTranscriptProjection(f.client, id(2), id(1)))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(2);
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("keeps missing metadata unavailable with no owner and no content query", async () => {
    const query = vi.fn(async () => ({ rows: [] }));
    await expect(
      loadAdmittedTranscriptProjection({ query } as unknown as PoolClient, id(2), null)
    ).resolves.toBeNull();
    expect(query).toHaveBeenCalledTimes(1);
  });

  it.each(["digest", "length"] as const)(
    "rejects a loaded bytea %s mismatch while retaining its lease",
    async (kind) => {
      const f = fixture();
      const corrupt = kind === "length" ? f.bytes.subarray(0, -1) : Buffer.from(f.bytes);
      if (kind === "digest") {
        corrupt[0] = (corrupt[0] ?? 0) ^ 1;
        expect(corrupt.length).toBe(f.bytes.length);
      }
      f.query.mockImplementation(async (sql) =>
        sql === TRANSCRIPT_PREFLIGHT_SQL
          ? { rows: [f.metadata] }
          : { rows: [{ ...f.metadata, fits: true, view: f.view, canonical_bytes: corrupt }] }
      );
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(
          owner.produce(() => loadAdmittedTranscriptProjection(f.client, id(2), id(1)))
        ).rejects.toThrow("transcript projection failed integrity verification");
        expect(manager.accounting.usedUnits).toBe(1);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
  );

  it("prevents content loading after cancellation during preflight", async () => {
    const f = fixture();
    const controller = new AbortController();
    f.query.mockImplementationOnce(async () => {
      controller.abort();
      return { rows: [f.metadata] };
    });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(controller.signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedTranscriptProjection(f.client, id(2), null))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });
});
