import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

// Selected private alias seam only. Stubbed authority and query results below do
// not establish PostgreSQL RLS, audit delivery, SDK validation, or native lifetime.
interface TranscriptSeam {
  liveActor(...args: unknown[]): Promise<unknown>;
  authorizeRead(...args: unknown[]): void;
  loadBoardResource(client: PoolClient, principal: SurfacePrincipal, uri: URL): Promise<unknown>;
}
const boardId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const meetingId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e02";
const versionId = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e03";
const uri = new URL(`board://${boardId}/meetings/${meetingId}/transcripts/7`);
const caller = { organizationId: boardId, memberId: meetingId } as SurfacePrincipal;
const maximum = responseAllocationPlan({
  kind: "document",
  representation: "resource",
  sourceId: versionId,
  sourceVersion: "7",
  sha256: "b".repeat(64),
  canonicalBytes: 10_485_760
});
const combinedContent = (sql: string) =>
  /version_row\.media_type,\s*version_row\.canonical_bytes/u.test(sql);
const fullContent = (sql: string) =>
  /^\s*select version_row\.canonical_bytes\s/u.test(sql) || combinedContent(sql);
function fixture(
  options: {
    bytes?: Buffer;
    mediaType?: "application/json" | "text/markdown; charset=utf-8";
    metadataLength?: number;
    missingMetadata?: boolean;
    missingContent?: boolean;
    content?: Buffer;
  } = {}
) {
  const bytes = options.bytes ?? Buffer.from('{"exact":"record Δ"}');
  const metadata = {
    id: versionId,
    version: 7,
    media_type: options.mediaType ?? "application/json",
    byte_length: options.metadataLength ?? bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
  const query = vi.fn(async (sql: string, _values?: unknown[]) => {
    // Preserve the original combined query's real row shape for failing-first
    // runs; only the metadata-first query omits the canonical bytes.
    if (combinedContent(sql))
      return {
        rows: options.missingMetadata
          ? []
          : [{ ...metadata, canonical_bytes: options.content ?? bytes }]
      };
    if (fullContent(sql))
      return {
        rows: options.missingContent ? [] : [{ canonical_bytes: options.content ?? bytes }]
      };
    return { rows: options.missingMetadata ? [] : [metadata] };
  });
  const repository = new PgSurfaceReadRepository({} as Pool, {
    cursorKey: Buffer.alloc(32, 1)
  });
  const seam = repository as unknown as TranscriptSeam;
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  const read = () => seam.loadBoardResource({ query } as unknown as PoolClient, caller, uri);
  return { bytes, metadata, query, liveActor, authorize, read };
}

describe("transcript resource admission", () => {
  it("uses document-body allocation for the supported maximum raw resource", () => {
    const transcript = responseAllocationPlan({ ...maximum, kind: "transcript" });
    expect(transcript.units).toBe(1_281);
    expect(transcript.units).toBe(maximum.units);
    expect(transcript.wireUpperBytes).toBe(65_536 + 6 * 10_485_760);
  });

  it("rejects a transcript composite tool plan rather than claiming it is covered", () => {
    expect(() =>
      responseAllocationPlan({ ...maximum, kind: "transcript", representation: "tool" })
    ).toThrow("transcript allocation requires the resource representation");
  });

  it.each([0, -1, 10_485_761, 1.5, Number.NaN])(
    "rejects invalid canonical transcript length %s before full-content selection",
    async (metadataLength) => {
      const f = fixture({ metadataLength });
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(owner.produce(f.read)).rejects.toThrow(
          "authorized response byte length is invalid"
        );
        expect(f.query).toHaveBeenCalledTimes(1);
        expect(f.query.mock.calls.some(([sql]) => fullContent(sql))).toBe(false);
        expect(manager.accounting.usedUnits).toBe(0);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
  );

  it("refuses after authorized scalar metadata and before selecting canonical bytes", async () => {
    const f = fixture({ metadataLength: 10_485_760 });
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(maximum);
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.authorize).toHaveBeenCalledWith(caller, {}, "get_meeting_transcript", {});
      expect(f.query).toHaveBeenCalledTimes(1);
      const sql = f.query.mock.calls[0]?.[0] ?? "";
      expect(sql).toContain("octet_length(version_row.canonical_bytes) as byte_length");
      expect(sql).toContain("encode(version_row.canonical_sha256,'hex') as sha256");
      expect(fullContent(sql)).toBe(false);
      expect(manager.accounting.usedUnits).toBe(1_281);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      held.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("leaves missing or hidden metadata unavailable without consulting capacity", async () => {
    const f = fixture({ missingMetadata: true });
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(maximum);
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toBeNull();
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(manager.accounting.usedUnits).toBe(1_281);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      held.release();
    }
  });

  it("requires an explicit owner before an existing alias can load canonical bytes", async () => {
    const f = fixture();
    await expect(f.read()).rejects.toThrow("native response allocation owner is required");
    expect(f.query).toHaveBeenCalledTimes(1);
    expect(f.query.mock.calls.some(([sql]) => fullContent(sql))).toBe(false);
  });

  it("does not load if the request disconnects while scalar metadata is selected", async () => {
    const f = fixture();
    const manager = new ResponseAllocationManager();
    const controller = new AbortController();
    const owner = manager.openRequest(controller.signal);
    f.query.mockImplementationOnce(async (sql) => {
      controller.abort();
      return {
        rows: [combinedContent(sql) ? { ...f.metadata, canonical_bytes: f.bytes } : f.metadata]
      };
    });
    try {
      await expect(owner.produce(f.read)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.query.mock.calls.some(([sql]) => fullContent(sql))).toBe(false);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it.each(["liveActor", "authorize"] as const)(
    "keeps %s rejection before metadata or capacity disclosure",
    async (gate) => {
      const f = fixture();
      const denied = new Error("synthetic authority refused");
      if (gate === "liveActor") f.liveActor.mockRejectedValue(denied);
      else
        f.authorize.mockImplementation(() => {
          throw denied;
        });
      const manager = new ResponseAllocationManager();
      const held = manager.tryReserve(maximum);
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(owner.produce(f.read)).rejects.toBe(denied);
        expect(f.query).not.toHaveBeenCalled();
        expect(manager.accounting.usedUnits).toBe(1_281);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        held.release();
      }
    }
  );

  it.each(["application/json", "text/markdown; charset=utf-8"] as const)(
    "loads the exact authorized immutable alias as %s with unchanged identity and bytes",
    async (mediaType) => {
      const f = fixture({ mediaType });
      const manager = new ResponseAllocationManager();
      const owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(owner.produce(f.read)).resolves.toEqual({
          entityType: "meeting_transcript_version",
          entityId: versionId,
          boardId,
          objectVersion: 7n,
          mediaType,
          bytes: f.bytes
        });
        expect(f.query).toHaveBeenCalledTimes(2);
        for (const [sql] of f.query.mock.calls) {
          expect(sql).toContain("from meetings as meeting");
          expect(sql).toContain(
            "join meeting_transcripts as transcript on transcript.meeting_id=meeting.id"
          );
          expect(sql).toContain(
            "join meeting_transcript_versions as version_row on version_row.transcript_id=transcript.id"
          );
          expect(sql).toContain("meeting.board_id=$1 and meeting.id=$2");
        }
        expect(f.query.mock.calls[0]?.[1]).toEqual([boardId, meetingId, 7]);
        const [sql, values] = f.query.mock.calls[1]!;
        expect(sql).toContain("version_row.id=$3 and version_row.version=$4");
        expect(sql).toContain("octet_length(version_row.canonical_bytes)=$5");
        expect(sql).toContain("version_row.canonical_sha256=$6 and version_row.media_type=$7");
        expect(values).toEqual([
          boardId,
          meetingId,
          versionId,
          7,
          f.bytes.length,
          Buffer.from(f.metadata.sha256, "hex"),
          mediaType
        ]);
        expect(manager.accounting.usedUnits).toBe(1);
        owner.nativeTerminal();
        expect(manager.accounting.usedUnits).toBe(1);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
  );

  it("returns unavailable if the exact tuple disappears after metadata, retaining the reservation until settlement", async () => {
    const f = fixture({ missingContent: true });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).resolves.toBeNull();
      expect(f.query).toHaveBeenCalledTimes(2);
      expect(manager.accounting.usedUnits).toBe(1);
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it.each([
    { label: "digest", content: Buffer.from("ORIGINAL EXACT BODY") },
    { label: "length", content: Buffer.from("short") }
  ])("rejects loaded bytes that fail the selected $label", async ({ content, label }) => {
    const f = fixture({ bytes: Buffer.from("original exact body"), content });
    if (label === "digest") expect(content.length).toBe(f.bytes.length);
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(owner.produce(f.read)).rejects.toThrow(
        "transcript version failed integrity verification"
      );
      expect(f.query).toHaveBeenCalledTimes(2);
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
