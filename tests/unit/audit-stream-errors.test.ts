import type { PoolClient, Query } from "pg";
import { expect, it } from "vitest";
import { streamAuditEvidence } from "../../lib/db/src/transactions/audit-evidence-stream.js";

it("retains the first stream error and absorbs a later error notification", async () => {
  let query: Query | undefined;
  const client = {
    query: (submitted: Query | string) => {
      if (typeof submitted === "string") return Promise.resolve({ rows: [] });
      query = submitted;
      return submitted;
    }
  } as unknown as PoolClient;
  const result = streamAuditEvidence(client, () => undefined);
  const observed = result.catch((error: unknown) => error);
  await Promise.resolve(); // DECLARE completes before the first streamed FETCH.
  const first = new Error("first synthetic stream error");
  query!.emit("error", first);
  expect(() => query!.emit("error", new Error("second synthetic stream error"))).not.toThrow();
  expect(await observed).toBe(first);
});
