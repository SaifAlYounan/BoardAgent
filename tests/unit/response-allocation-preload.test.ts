import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

const canonicalLoad = vi.hoisted(() =>
  vi.fn(async () => {
    throw new Error("canonical document loader ran before refusal");
  })
);
vi.mock("@boardagent/db", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/db/src/index.js")>()),
  fetchDocumentVersionInTransaction: canonicalLoad
}));

// White-box pre-load seam tests. Authorization/RLS are deliberately stubbed here;
// these do not replace the existing PostgreSQL authority tests or claim auth coverage.
interface SelectedSeams {
  liveActor(...args: unknown[]): Promise<unknown>;
  authorizeRead(...args: unknown[]): void;
  readDocument(
    client: PoolClient,
    principal: SurfacePrincipal,
    input: Record<string, unknown>
  ): Promise<unknown>;
  readOperations(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    input: Record<string, unknown>
  ): Promise<unknown>;
  loadBoardResource(client: PoolClient, principal: SurfacePrincipal, uri: URL): Promise<unknown>;
  loadExportResource(client: PoolClient, principal: SurfacePrincipal, uri: URL): Promise<unknown>;
}
const ids = Array.from(
  { length: 8 },
  (_, index) => `018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e0${index + 1}`
);
const principal = {
  organizationId: ids[0],
  memberId: ids[1],
  serviceOrigin: "https://synthetic.test",
  clientId: ids[2]
} as SurfacePrincipal;
const exportId = Buffer.alloc(32, 0).toString("base64url");
const maximum = responseAllocationPlan({
  kind: "document",
  representation: "tool",
  sourceId: ids[3]!,
  sourceVersion: "7",
  sha256: "b".repeat(64),
  canonicalBytes: 10_485_760
});
function fixture(missing = false) {
  canonicalLoad.mockClear();
  const storage = vi.fn(async () => new Uint8Array());
  const repository = new PgSurfaceReadRepository({} as Pool, {
    cursorKey: new Uint8Array(32).fill(1),
    exportChunks: { readExactChunk: storage }
  });
  const seams = repository as unknown as SelectedSeams;
  vi.spyOn(seams, "liveActor").mockResolvedValue({});
  vi.spyOn(seams, "authorizeRead").mockReturnValue(undefined);
  const metadata = {
    board_id: ids[4],
    id: ids[3],
    version: 7,
    media_type: "text/plain; charset=utf-8",
    byte_length: 10_485_760,
    sha256: "b".repeat(64),
    request_id: ids[5],
    artifact_id: ids[6],
    storage_locator: "synthetic-only"
  };
  const query = vi.fn(async (sql: string) => {
    if (missing) return { rows: [] };
    if (sql.includes("canonical_bytes")) throw new Error("full-content query must not run");
    return { rows: [metadata] };
  });
  const client = { query } as unknown as PoolClient;
  const calls = {
    documentTool: () =>
      seams.readDocument(client, principal, { document_id: ids[7], version_id: null }),
    documentResource: () =>
      seams.loadBoardResource(
        client,
        principal,
        new URL(`board://${ids[4]}/documents/${ids[7]}/versions/7`)
      ),
    exportTool: () =>
      seams.readOperations(client, principal, "read_export_chunk", {
        export_id: exportId,
        chunk_no: 0
      }),
    exportResource: () =>
      seams.loadExportResource(client, principal, new URL(`export://${exportId}/chunks/0`))
  };
  return { calls, query, storage, seams };
}

describe("selected document/export pre-load reservations", () => {
  it.each(["documentTool", "documentResource", "exportTool", "exportResource"] as const)(
    "refuses %s after metadata and before canonical bytes/storage",
    async (lane) => {
      const f = fixture();
      const manager = new ResponseAllocationManager();
      const held = manager.tryReserve(maximum);
      const owner = manager.openRequest(new AbortController().signal);
      await expect(owner.produce(f.calls[lane])).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.storage).not.toHaveBeenCalled();
      expect(canonicalLoad).not.toHaveBeenCalled();
      owner.nativeTerminal();
      owner.collectorSettled();
      held.release();
    }
  );

  it.each(["documentTool", "documentResource", "exportTool", "exportResource"] as const)(
    "keeps missing %s unavailable without admission/size disclosure",
    async (lane) => {
      const f = fixture(true);
      const manager = new ResponseAllocationManager();
      const held = manager.tryReserve(maximum);
      const owner = manager.openRequest(new AbortController().signal);
      await expect(owner.produce(f.calls[lane])).resolves.not.toBeInstanceOf(Error);
      expect(manager.accounting.usedUnits).toBe(1_281);
      expect(f.storage).not.toHaveBeenCalled();
      owner.nativeTerminal();
      owner.collectorSettled();
      held.release();
    }
  );

  it("loads the exact selected resource version/hash/length after metadata, without resolving a newer current version", async () => {
    const f = fixture();
    const bytes = Buffer.from("selected immutable bytes");
    const hash = createHash("sha256").update(bytes).digest("hex");
    const query = vi.fn(async (sql: string, values: unknown[]) => {
      if (!sql.includes("canonical_bytes"))
        return {
          rows: [
            {
              id: ids[3],
              version: 7,
              media_type: "text/plain; charset=utf-8",
              byte_length: bytes.length,
              sha256: hash
            }
          ]
        };
      expect(sql).toContain("version_row.id=$3");
      expect(sql).toContain("version_row.version=$4");
      expect(sql).toContain("version_row.byte_length=$5");
      expect(sql).toContain("version_row.sha256=$6");
      expect(values).toEqual([
        ids[4],
        ids[7],
        ids[3],
        7,
        bytes.length,
        Buffer.from(hash, "hex"),
        "text/plain; charset=utf-8"
      ]);
      return { rows: [{ canonical_bytes: bytes }] };
    });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    const result = await owner.produce(() =>
      f.seams.loadBoardResource(
        { query } as unknown as PoolClient,
        principal,
        new URL(`board://${ids[4]}/documents/${ids[7]}/versions/7`)
      )
    );
    expect(result).toMatchObject({ entityId: ids[3], objectVersion: 7n, bytes });
    expect(query).toHaveBeenCalledTimes(2);
    owner.nativeTerminal();
    owner.collectorSettled();
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
