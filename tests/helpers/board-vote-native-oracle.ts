import type { PoolClient } from "pg";
import { expect } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  originalBoardVotePage,
  originalProxyStatus,
  originalVoteLineage,
  boardVoteObject,
  BOARD_KEYS,
  VOTE_KEYS,
  GRANT_FLAT_KEYS,
  REVOCATION_KEYS,
  LINEAGE_FLAT_KEYS
} from "./board-vote-postgres-oracle.js";

export type BoardVoteNativeKind = "boards" | "votes" | "proxy" | "lineage";
export interface BoardVoteNativeInput {
  readonly kind: BoardVoteNativeKind;
  readonly selectorId: string;
  readonly memberId: string | null;
  readonly principalId: string;
  readonly limit: number;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
}
export interface BoardVoteNativePageRow {
  readonly item: JsonValue;
  readonly cursor_at: string | null;
  readonly cursor_id: string;
}
export async function readBoardVoteNativeOriginal(client: PoolClient, input: BoardVoteNativeInput) {
  let rows: readonly BoardVoteNativePageRow[] = [],
    items: readonly JsonValue[] = [],
    retained: readonly unknown[] = [];
  let j: bigint, p: bigint, o: bigint;
  if (input.kind === "boards" || input.kind === "votes") {
    const original = await originalBoardVotePage(client, input.kind, [
      input.selectorId,
      input.cursorAt,
      input.cursorId,
      input.limit + 1
    ]);
    rows = original.rows;
    items = rows.map((row) => row.item);
    retained = rows.map((row) => ({ fits: true, ...row }));
    const keys = input.kind === "boards" ? BOARD_KEYS : VOTE_KEYS;
    for (const row of rows)
      expect(Object.keys(boardVoteObject(row.item)).sort()).toEqual([...keys].sort());
    const r = BigInt(rows.length),
      s = original.metadata.reduce((sum, row) => sum + BigInt(row.scalar_utf8), 0n);
    j = 2n + (input.kind === "boards" ? 286n : 326n) * r + 6n * s;
    p = 25n + (input.kind === "boards" ? 15n : 16n) * r;
    o = 7n + 2n * r;
  } else if (input.kind === "proxy") {
    if (input.memberId === null)
      throw new Error("original proxy requires resolved selected member");
    const original = await originalProxyStatus(
      client,
      input.selectorId,
      input.memberId,
      input.principalId
    );
    items = original.items;
    retained = [{ ...original.metadata, fits: true, items }];
    for (const value of items) {
      const row = boardVoteObject(value);
      expect(Object.keys(row).sort()).toEqual([...GRANT_FLAT_KEYS, "revocation"].sort());
      if (row.revocation !== null)
        expect(Object.keys(boardVoteObject(row.revocation)).sort()).toEqual(
          [...REVOCATION_KEYS].sort()
        );
    }
    const r = BigInt(original.metadata.grant_count),
      v = BigInt(original.metadata.revocation_count),
      s = BigInt(original.metadata.scalar_utf8);
    j = 54n + 186n * r + 77n * v + 6n * s;
    p = 26n + 9n * r + 4n * v;
    o = 8n + r + v;
  } else {
    const original = await originalVoteLineage(client, input.selectorId);
    items = original.items;
    retained = [{ row_count: String(items.length), fits: true, items }];
    for (const value of items)
      expect(Object.keys(boardVoteObject(value)).sort()).toEqual(
        [...LINEAGE_FLAT_KEYS, "changed_component_classes"].sort()
      );
    const r = BigInt(items.length),
      s =
        BigInt(Buffer.byteLength(input.selectorId)) +
        original.metadata.reduce((sum, row) => sum + BigInt(row.scalar_utf8), 0n);
    const n = original.metadata.reduce((sum, row) => sum + BigInt(row.json_utf8), 0n),
      oj = original.metadata.reduce((sum, row) => sum + BigInt(row.json_containers), 0n);
    // The original PostgreSQL text[] conversion is measured in its actual JSONB
    // spelling. The adapter does not replace it with a flat enum or JS byte estimate.
    j = 36n + 227n * r + 6n * s + n;
    p = 25n + 9n * r;
    o = 8n + r + oj;
  }
  const allocationBytes = 65536n + 8n * (j + 4096n) + 256n * p + 512n * o;
  return {
    rows,
    items,
    retained,
    bound: {
      jsonUpperBytes: j,
      propertyCount: p,
      objectOrArrayCount: o,
      allocationBytes,
      wireBytes: 65536n + 3n * (j + 4096n)
    },
    units: Number((allocationBytes + 1048575n) / 1048576n)
  };
}
