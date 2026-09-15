import { createHash } from "node:crypto";
import {
  currentResponseAllocationOwner,
  responseAllocationPlan,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export type FixedReadKind =
  | "list_my_drafts"
  | "list_my_webhooks"
  | "get_retention_policy"
  | "list_members"
  | "list_enrollments";

// Each row has a fixed object shape and bounded scalar leaves. The two
// identity lists allow one512-character text leaf per row; its worst JSON
// UTF8 width and fixed nested member fields fit the same8192-byte bound.
// Keep the original SQL unchanged and reserve its maximum before loading rows.
export function fixedReadPlan(
  kind: FixedReadKind,
  sourceId: string,
  limit?: number
): ResponseAllocationPlan {
  if (
    ![
      "list_my_drafts",
      "list_my_webhooks",
      "get_retention_policy",
      "list_members",
      "list_enrollments"
    ].includes(kind)
  )
    throw new TypeError("unknown fixed read kind");
  if (typeof sourceId !== "string" || sourceId.length === 0 || sourceId.length > 512)
    throw new TypeError("fixed read source is invalid");
  const paged = kind !== "get_retention_policy";
  if (paged ? !Number.isSafeInteger(limit) || limit! < 1 || limit! > 500 : limit !== undefined)
    throw new TypeError("fixed read limit is invalid");
  const rows = paged ? BigInt(limit! + 1) : 1n;
  return responseAllocationPlan({
    kind: "fixed_read_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: createHash("sha256").update(sourceId).digest("hex"),
    sourceVersion: kind + ":" + String(rows),
    sha256: createHash("sha256")
      .update(JSON.stringify([kind, sourceId, String(rows)]))
      .digest("hex"),
    listProjection: {
      jsonUpperBytes: (4096n + 8192n * rows).toString(),
      propertyCount: (64n + 32n * rows).toString(),
      objectOrArrayCount: (16n + 4n * rows).toString()
    }
  });
}

export function reserveFixedRead(kind: FixedReadKind, sourceId: string, limit?: number): void {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new Error("native response allocation owner is required");
  owner.reserve(fixedReadPlan(kind, sourceId, limit));
  owner.assertLive();
}
