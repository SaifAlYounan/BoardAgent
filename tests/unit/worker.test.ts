import { describe, expect, it } from "vitest";

import { CORE_WORKER_JOB_TYPES } from "../../artifacts/server/src/core-worker-handlers.js";
import { NOTIFICATION_WORKER_JOB_TYPES } from "../../artifacts/server/src/notification-worker.js";
import {
  composeTypedJobHandlers,
  type TypedJobHandler,
  type TypedJobType
} from "../../artifacts/server/src/worker.js";
import { TYPED_JOB_TYPES } from "../../lib/db/src/jobs.js";

const handler: TypedJobHandler = async () => ({ handled: true });

describe("typed worker handler registry", () => {
  it("assigns every frozen typed job to exactly one production handler group", () => {
    const owned = [...CORE_WORKER_JOB_TYPES, ...NOTIFICATION_WORKER_JOB_TYPES];
    expect(new Set(owned).size).toBe(owned.length);
    expect(owned.toSorted()).toEqual([...TYPED_JOB_TYPES].toSorted());
  });

  it("merges independently owned handler groups in closed-registry order", () => {
    const handlers = composeTypedJobHandlers(
      new Map<TypedJobType, TypedJobHandler>([["wizard_expiry", handler]]),
      new Map<TypedJobType, TypedJobHandler>([
        ["notice_fanout", handler],
        ["clock_health", handler]
      ])
    );
    expect([...handlers.keys()]).toEqual(["clock_health", "notice_fanout", "wizard_expiry"]);
  });

  it("refuses duplicate ownership instead of silently replacing a handler", () => {
    expect(() =>
      composeTypedJobHandlers(
        new Map<TypedJobType, TypedJobHandler>([["clock_health", handler]]),
        new Map<TypedJobType, TypedJobHandler>([["clock_health", handler]])
      )
    ).toThrow("duplicate worker handler: clock_health");
  });
});
