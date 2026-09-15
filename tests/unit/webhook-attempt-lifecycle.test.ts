import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({ claim: vi.fn(), complete: vi.fn() }));
// Every database export is inert. Delivery and validation below are injected functions.
vi.mock("@boardagent/db", () => ({
  TYPED_JOB_TYPES: [],
  withWorkerTransaction: async (_pool: unknown, run: (client: unknown) => Promise<unknown>) =>
    run({}),
  claimNotificationDeliveryInTransaction: mocked.claim,
  completeNotificationDeliveryInTransaction: mocked.complete,
  ...Object.fromEntries(
    [
      "createNotificationDeliveryInTransaction",
      "enqueueNotificationDeadLetterAlertInTransaction",
      "listNoticeWebhookTargetsInTransaction",
      "readNotificationDeadLetterTargetInTransaction",
      "readNotificationDeliveryStateInTransaction",
      "reapExpiredNotificationLeasesInTransaction",
      "claimTypedJobInTransaction",
      "completeTypedJobInTransaction",
      "heartbeatJobLeaseInTransaction",
      "withRuntimeDatabaseLease"
    ].map((name) => [
      name,
      vi.fn(() => {
        throw new Error("unexpected repository call");
      })
    ])
  )
}));

import {
  BoardAgentNotificationWorker,
  type WebhookDeliveryTransportInput
} from "../../artifacts/server/src/notification-worker.js";
import { WebhookPreconnectError } from "../../artifacts/server/src/webhook-attempt.js";
import type { TypedJobExecutionContext } from "../../artifacts/server/src/worker.js";
import {
  Aes256GcmWebhookSecurity,
  WebhookResolutionTimeoutError,
  type WebhookSecurityPort
} from "../../artifacts/server/src/webhook-security.js";
import { canonicalJson, sha256Hex } from "../../lib/contracts/src/index.js";

const ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const ADDRESSES = ["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"];
const SUCCESS = { statusCode: 204, responseSha256: sha256Hex("accepted") };
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function fixture() {
  const endpoint = "https://synthetic-webhook.example/wake";
  const secret = Buffer.alloc(32, 7).toString("base64url");
  const canonicalPayload = Buffer.from(
    canonicalJson({ eventClass: "security", wakeId: "synthetic" })
  );
  const claim = {
    notificationJobId: ID,
    organizationId: ID,
    boardId: null,
    memberId: ID,
    webhookId: ID,
    endpointCiphertext: Buffer.from("synthetic"),
    secretCiphertext: Buffer.from("synthetic"),
    endpointSha256: sha256Hex(endpoint),
    secretSha256: sha256Hex(Buffer.from(secret, "base64url")),
    keyId: ID,
    webhookGeneration: 1n,
    sourceKind: "test",
    wakeClass: "security",
    randomWakeId: Buffer.alloc(32, 8),
    canonicalPayload,
    payloadSha256: sha256Hex(canonicalPayload),
    attempt: 1,
    leaseExpiresAt: "2026-09-11T20:00:00Z"
  };
  mocked.claim.mockResolvedValue(claim);
  mocked.complete.mockImplementation(async (_client, input) => ({
    completed: true,
    state:
      input.resultClass === "delivered"
        ? "delivered"
        : input.resultClass === "permanent_failure"
          ? "dead"
          : "retry"
  }));
  const validated = {
    endpoint,
    endpointSha256: claim.endpointSha256,
    validationReceiptSha256: "0".repeat(64),
    resolvedAddresses: [...ADDRESSES]
  };
  const validation = deferred<typeof validated>();
  const transport = deferred<typeof SUCCESS>();
  const validate = vi.fn(async () => validated);
  const deliver = vi.fn(async (_input: WebhookDeliveryTransportInput) => SUCCESS);
  const security: WebhookSecurityPort = {
    activeKeyId: ID,
    validateEndpoint: validate,
    openEndpoint: () => endpoint,
    openSecret: () => secret,
    protectEndpoint: async () => {
      throw new Error("unexpected protection");
    },
    createSecret: () => {
      throw new Error("unexpected secret creation");
    }
  };
  const controller = new AbortController();
  const worker = new BoardAgentNotificationWorker(
    {} as ConstructorParameters<typeof BoardAgentNotificationWorker>[0],
    { webhookSecurity: security, transport: { deliver }, newId: () => ID }
  );
  const start = () =>
    worker.deliveryHandler({
      signal: controller.signal,
      job: {
        envelope: {
          jobType: "webhook_delivery",
          organizationId: ID,
          boardId: null,
          parameters: { notificationJobId: ID }
        }
      }
    } as TypedJobExecutionContext);
  return { validate, deliver, validated, validation, transport, controller, start };
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(async () => {
  await vi.runAllTimersAsync();
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("pure complete webhook attempt orchestration", () => {
  it.each([
    ["EAI_AGAIN", "retryable_failure"],
    ["ENOTFOUND", "permanent_failure"]
  ] as const)("classifies the actual resolver's %s failure as %s", async (code, resultClass) => {
    const f = fixture();
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: ID,
      keys: new Map([[ID, Buffer.alloc(32, 30)]]),
      resolve: async () => {
        throw Object.assign(new Error("synthetic resolver failure"), { code });
      }
    });
    f.validate.mockImplementation(async () => {
      await security.validateEndpoint(f.validated.endpoint);
      throw new Error("failed DNS must not return validation");
    });
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.deliver).not.toHaveBeenCalled();
    expect(mocked.complete).toHaveBeenCalledTimes(1);
    expect(mocked.complete.mock.calls[0]?.[1]).toMatchObject({ resultClass });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps a bounded DNS timeout retryable without starting delivery", async () => {
    const f = fixture();
    f.validate.mockRejectedValue(new WebhookResolutionTimeoutError());
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.deliver).not.toHaveBeenCalled();
    expect(mocked.complete).toHaveBeenCalledTimes(1);
    expect(mocked.complete.mock.calls[0]?.[1]).toMatchObject({
      resultClass: "retryable_failure",
      errorClass: "webhook_transport_failure"
    });
    expect(vi.getTimerCount()).toBe(0);
  });
  it("refuses a pre-aborted attempt before calling validation or delivery", async () => {
    const f = fixture();
    f.controller.abort();
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.validate).not.toHaveBeenCalled();
    expect(f.deliver).not.toHaveBeenCalled();
    expect(mocked.complete.mock.calls[0]?.[1]).toMatchObject({ resultClass: "retryable_failure" });
  });

  it("copies the validated address set before the first delivery attempt", async () => {
    const f = fixture();
    f.deliver.mockImplementationOnce(async () => {
      f.validated.resolvedAddresses[1] = "93.184.216.35";
      throw new WebhookPreconnectError(ADDRESSES[0]!);
    });
    const outcome = f.start();
    await vi.runAllTimersAsync();
    expect(await outcome).toMatchObject({ state: "delivered" });
    expect(f.deliver.mock.calls[1]?.[0].address).toBe(ADDRESSES[1]);
  });

  it("does not advance after cancellation between two address attempts", async () => {
    const f = fixture();
    f.deliver.mockImplementationOnce(async () => {
      f.controller.abort();
      throw new WebhookPreconnectError(ADDRESSES[0]!);
    });
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.deliver).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cannot use a preconnection marker belonging to another address", async () => {
    const f = fixture();
    f.deliver.mockRejectedValueOnce(new WebhookPreconnectError(ADDRESSES[1]!));
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.deliver).toHaveBeenCalledTimes(1);
  });

  it("stops at the end of the validated set and completes the attempt once", async () => {
    const f = fixture();
    f.deliver.mockImplementation(async ({ address }) => {
      throw new WebhookPreconnectError(address);
    });
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.validate).toHaveBeenCalledTimes(1);
    expect(f.deliver).toHaveBeenCalledTimes(2);
    expect(mocked.complete).toHaveBeenCalledTimes(1);
  });

  it("refuses a malformed validated set larger than sixteen before delivery", async () => {
    const f = fixture();
    f.validated.resolvedAddresses = Array.from(
      { length: 17 },
      (_, index) => `93.184.216.${index + 1}`
    );
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.deliver).not.toHaveBeenCalled();
    expect(mocked.complete.mock.calls[0]?.[1]).toMatchObject({ resultClass: "permanent_failure" });
  });

  it("clears the network timer and lease listener before completion even if bookkeeping fails", async () => {
    const f = fixture();
    const removed = vi.spyOn(f.controller.signal, "removeEventListener");
    mocked.complete.mockImplementation(async () => {
      expect(vi.getTimerCount()).toBe(0);
      expect(removed).toHaveBeenCalledWith("abort", expect.any(Function));
      throw new Error("synthetic completion failure");
    });
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toMatchObject({ message: "synthetic completion failure" });
    f.controller.abort();
    expect(f.deliver.mock.calls[0]?.[0].signal.aborted).toBe(false);
    expect(f.deliver).toHaveBeenCalledTimes(1);
  });
  it.each(["resolve", "reject"] as const)(
    "bounds stalled validation and ignores late %s without delivery",
    async (late) => {
      const f = fixture();
      f.validate.mockImplementation(() => f.validation.promise);
      let settled: unknown;
      const outcome = f.start().then(
        (value) => {
          settled = value;
        },
        (error: unknown) => {
          settled = error;
        }
      );
      try {
        await vi.advanceTimersByTimeAsync(10_000);
        expect(settled).toBeInstanceOf(Error);
        expect(f.deliver).not.toHaveBeenCalled();
        expect(mocked.complete).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ resultClass: "retryable_failure" })
        );
        if (late === "resolve") f.validation.resolve(f.validated);
        else f.validation.reject(new Error("late validation error"));
        await vi.advanceTimersByTimeAsync(0);
        expect(f.deliver).not.toHaveBeenCalled();
        expect(mocked.complete).toHaveBeenCalledTimes(1);
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        f.validation.resolve(f.validated);
        await vi.runAllTimersAsync();
        await outcome;
      }
    }
  );

  it("cancels while validation is pending and ignores its later result", async () => {
    const f = fixture();
    f.validate.mockImplementation(() => f.validation.promise);
    let settled: unknown;
    const outcome = f.start().catch((error: unknown) => {
      settled = error;
    });
    try {
      await vi.advanceTimersByTimeAsync(0);
      f.controller.abort();
      await vi.advanceTimersByTimeAsync(0);
      expect(settled).toBeInstanceOf(Error);
      expect(mocked.complete).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ resultClass: "retryable_failure" })
      );
      f.validation.resolve(f.validated);
      await vi.advanceTimersByTimeAsync(0);
      expect(f.deliver).not.toHaveBeenCalled();
    } finally {
      f.validation.resolve(f.validated);
      await vi.runAllTimersAsync();
      await outcome;
    }
  });

  it("tries the next validated address only after a matching typed preconnection failure", async () => {
    const f = fixture();
    f.deliver.mockRejectedValueOnce(new WebhookPreconnectError(ADDRESSES[0]!));
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toMatchObject({ state: "delivered" });
    expect(f.validate).toHaveBeenCalledTimes(1);
    expect(f.deliver).toHaveBeenCalledTimes(2);
    const first = f.deliver.mock.calls[0]![0],
      second = f.deliver.mock.calls[1]![0];
    expect(first.address).toBe(ADDRESSES[0]);
    expect(second.address).toBe(ADDRESSES[1]);
    expect({ ...second, address: first.address }).toEqual(first);
    expect(mocked.complete).toHaveBeenCalledTimes(1);
  });

  it.each(["ECONNREFUSED", "ECONNRESET", "ERR_TLS_CERT_ALTNAME_INVALID", "response_error"])(
    "does not infer fallback permission from a generic %s error",
    async (code) => {
      const f = fixture();
      f.deliver.mockRejectedValueOnce(Object.assign(new Error("synthetic failure"), { code }));
      const outcome = f.start().catch((error: unknown) => error);
      await vi.runAllTimersAsync();
      expect(await outcome).toBeInstanceOf(Error);
      expect(f.deliver).toHaveBeenCalledTimes(1);
    }
  );

  it.each([302, 500])("does not try another address after HTTP %s", async (statusCode) => {
    const f = fixture();
    f.deliver.mockResolvedValueOnce({ ...SUCCESS, statusCode });
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.deliver).toHaveBeenCalledTimes(1);
    expect(mocked.complete.mock.calls[0]?.[1]).toMatchObject({
      resultClass: statusCode === 302 ? "permanent_failure" : "retryable_failure"
    });
  });

  it("counts validation and all address attempts against one deadline", async () => {
    const f = fixture();
    f.validate.mockImplementation(() => f.validation.promise);
    f.deliver
      .mockImplementationOnce(() => f.transport.promise)
      .mockImplementationOnce(() => new Promise(() => {}));
    let settled: unknown;
    const outcome = f.start().catch((error: unknown) => {
      settled = error;
    });
    try {
      await vi.advanceTimersByTimeAsync(6_000);
      f.validation.resolve(f.validated);
      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(3_000);
      f.transport.reject(new WebhookPreconnectError(ADDRESSES[0]!));
      await vi.advanceTimersByTimeAsync(0);
      expect(f.deliver).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(settled).toBeInstanceOf(Error);
      expect(f.deliver.mock.calls[1]?.[0].signal.aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      f.validation.resolve(f.validated);
      f.transport.resolve(SUCCESS);
      await vi.runAllTimersAsync();
      await outcome;
    }
  });

  it("keeps unsafe endpoint refusal permanent and never calls delivery", async () => {
    const f = fixture();
    f.validate.mockRejectedValue(new Error("unsafe endpoint"));
    const outcome = f.start().catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    expect(await outcome).toBeInstanceOf(Error);
    expect(f.deliver).not.toHaveBeenCalled();
    expect(mocked.complete).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        resultClass: "permanent_failure",
        errorClass: "webhook_security_validation_failed"
      })
    );
  });
});
