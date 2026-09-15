import { afterEach, describe, expect, it, vi } from "vitest";

import {
  Aes256GcmWebhookSecurity,
  WebhookEndpointRejectedError
} from "../../artifacts/server/src/webhook-security.js";
import { testId } from "../helpers/authorized-actor.js";

afterEach(() => vi.useRealTimers());

describe("canonical webhook endpoint byte limit", () => {
  it.each(["validate", "protect"] as const)(
    "refuses URL-encoding growth before %s resolves or encrypts the endpoint",
    async (operation) => {
      const resolve = vi.fn(async () => [{ address: "93.184.216.34", family: 4 as const }]);
      const security = new Aes256GcmWebhookSecurity({
        activeKeyId: testId(300_080),
        keys: new Map([[testId(300_080), Buffer.alloc(32, 31)]]),
        resolve
      });
      const endpoint = `https://synthetic-hook.example/${"界".repeat(500)}`;
      expect(Buffer.byteLength(endpoint)).toBeLessThan(4000);
      expect(Buffer.byteLength(new URL(endpoint).href)).toBeGreaterThan(4096);
      const binding = {
        organizationId: testId(300_081),
        memberId: testId(300_082),
        webhookId: testId(300_083)
      };
      const outcome = await (
        operation === "validate"
          ? security.validateEndpoint(endpoint)
          : security.protectEndpoint({ ...binding, endpoint }).then((protectedEndpoint) => {
              // Preserve the concrete before-state: accepted ciphertext cannot be opened.
              expect(() => security.openEndpoint({ ...binding, ...protectedEndpoint })).toThrow(
                "envelope is invalid"
              );
              return protectedEndpoint;
            })
      ).then(
        (result) => ({ result, error: null }),
        (error: unknown) => ({ result: null, error })
      );
      expect(outcome.error).toBeInstanceOf(WebhookEndpointRejectedError);
      expect(resolve).not.toHaveBeenCalled();
    }
  );

  it("round-trips an encoded endpoint at exactly 4000 canonical bytes", async () => {
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: testId(300_090),
      keys: new Map([[testId(300_090), Buffer.alloc(32, 31)]]),
      resolve: async () => [{ address: "93.184.216.34", family: 4 }]
    });
    const base = "https://synthetic-hook.example/界";
    const endpoint = base + "a".repeat(4000 - Buffer.byteLength(new URL(base).href));
    const binding = {
      organizationId: testId(300_091),
      memberId: testId(300_092),
      webhookId: testId(300_093)
    };
    const protectedEndpoint = await security.protectEndpoint({ ...binding, endpoint });
    expect(Buffer.byteLength(protectedEndpoint.endpoint)).toBe(4000);
    expect(security.openEndpoint({ ...binding, ...protectedEndpoint })).toBe(
      new URL(endpoint).href
    );
  });
});

describe("inert webhook DNS port duration", () => {
  it.each(["validate", "protect"] as const)(
    "bounds a stalled %s call and ignores its late DNS answer",
    async (operation) => {
      vi.useFakeTimers();
      const answers = [{ address: "93.184.216.34", family: 4 as const }];
      let finish: ((value: typeof answers) => void) | undefined;
      const entropy = vi.fn((length: number) => Buffer.alloc(length, 32));
      const security = new Aes256GcmWebhookSecurity({
        activeKeyId: testId(300_050),
        keys: new Map([[testId(300_050), Buffer.alloc(32, 31)]]),
        randomBytes: entropy,
        resolve: () =>
          new Promise<typeof answers>((resolve) => {
            finish = resolve;
          })
      });
      const promise =
        operation === "validate"
          ? security.validateEndpoint("https://synthetic-hook.example/wake")
          : security.protectEndpoint({
              organizationId: testId(300_051),
              memberId: testId(300_052),
              webhookId: testId(300_053),
              endpoint: "https://synthetic-hook.example/wake"
            });
      let outcome: unknown;
      const observed = promise.then(
        (result) => {
          outcome = result;
        },
        (error: unknown) => {
          outcome = error;
        }
      );
      try {
        await vi.advanceTimersByTimeAsync(5_001);
        expect(outcome).toMatchObject({ name: "WebhookResolutionTimeoutError" });
        finish?.(answers);
        await vi.advanceTimersByTimeAsync(0);
        await observed;
        expect(outcome).toMatchObject({ name: "WebhookResolutionTimeoutError" });
        expect(entropy).not.toHaveBeenCalled();
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        finish?.(answers);
        await observed;
      }
    }
  );

  it("clears the deadline for a timely DNS result and preserves the exact receipt", async () => {
    vi.useFakeTimers();
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: testId(300_060),
      keys: new Map([[testId(300_060), Buffer.alloc(32, 31)]]),
      resolve: () =>
        new Promise((resolve) =>
          setTimeout(() => resolve([{ address: "93.184.216.34", family: 4 }]), 20)
        )
    });
    const pending = security.validateEndpoint("https://synthetic-hook.example/wake");
    await vi.advanceTimersByTimeAsync(21);
    await expect(pending).resolves.toMatchObject({
      endpoint: "https://synthetic-hook.example/wake",
      resolvedAddresses: ["93.184.216.34"]
    });
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("webhook SSRF and secret boundary", () => {
  it("accepts only freshly resolved public HTTPS endpoints and emits a deterministic receipt", async () => {
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: testId(300_001),
      keys: new Map([[testId(300_001), Buffer.alloc(32, 31)]]),
      randomBytes: (length) => Buffer.alloc(length, 32),
      resolve: async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }
      ]
    });
    const first = await security.protectEndpoint({
      organizationId: testId(300_002),
      memberId: testId(300_003),
      webhookId: testId(300_004),
      endpoint: "https://hooks.example.com/boardagent"
    });
    expect(first.endpoint).toBe("https://hooks.example.com/boardagent");
    expect(first.resolvedAddresses).toEqual([
      "2606:2800:220:1:248:1893:25c8:1946",
      "93.184.216.34"
    ]);
    expect(first.endpointSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(first.validationReceiptSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(first.endpointCiphertext.toString("utf8")).not.toContain("hooks.example.com");
    expect(
      security.openEndpoint({
        organizationId: testId(300_002),
        memberId: testId(300_003),
        webhookId: testId(300_004),
        keyId: security.activeKeyId,
        endpointCiphertext: first.endpointCiphertext
      })
    ).toBe(first.endpoint);
  });

  it.each([
    "http://hooks.example.com/wake",
    "https://user:password@hooks.example.com/wake",
    "https://hooks.example.com/wake#fragment",
    "https://localhost/wake",
    "https://127.0.0.1/wake",
    "https://10.0.0.1/wake",
    "https://169.254.169.254/latest/meta-data",
    "https://[::1]/wake",
    "https://[fd00::1]/wake",
    "https://[fe80::1]/wake"
  ])("rejects a non-public endpoint before persistence: %s", async (endpoint) => {
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: testId(300_010),
      keys: new Map([[testId(300_010), Buffer.alloc(32, 33)]]),
      resolve: async () => [{ address: "93.184.216.34", family: 4 }]
    });
    await expect(security.validateEndpoint(endpoint)).rejects.toBeInstanceOf(
      WebhookEndpointRejectedError
    );
  });

  it("rejects mixed/private DNS answers and catches rebinding on the next attempt", async () => {
    let attempt = 0;
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: testId(300_020),
      keys: new Map([[testId(300_020), Buffer.alloc(32, 34)]]),
      resolve: async () => {
        attempt += 1;
        return attempt === 1
          ? [{ address: "93.184.216.34", family: 4 }]
          : [
              { address: "93.184.216.34", family: 4 },
              { address: "192.168.1.20", family: 4 }
            ];
      }
    });
    await expect(security.validateEndpoint("https://rebind.example/wake")).resolves.toMatchObject({
      endpoint: "https://rebind.example/wake"
    });
    await expect(security.validateEndpoint("https://rebind.example/wake")).rejects.toBeInstanceOf(
      WebhookEndpointRejectedError
    );
  });

  it("encrypts each per-member HMAC secret and binds decryption to member/webhook AAD", () => {
    let byte = 41;
    const security = new Aes256GcmWebhookSecurity({
      activeKeyId: testId(300_030),
      keys: new Map([[testId(300_030), Buffer.alloc(32, 35)]]),
      randomBytes: (length) => Buffer.alloc(length, byte++)
    });
    const material = security.createSecret({
      organizationId: testId(300_031),
      memberId: testId(300_032),
      webhookId: testId(300_033)
    });
    expect(material.secret).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(material.secretCiphertext.toString("base64url")).not.toContain(material.secret);
    expect(
      security.openSecret({
        organizationId: testId(300_031),
        memberId: testId(300_032),
        webhookId: testId(300_033),
        keyId: security.activeKeyId,
        secretCiphertext: material.secretCiphertext
      })
    ).toBe(material.secret);
    expect(() =>
      security.openSecret({
        organizationId: testId(300_031),
        memberId: testId(300_032),
        webhookId: testId(300_034),
        keyId: security.activeKeyId,
        secretCiphertext: material.secretCiphertext
      })
    ).toThrow("authentication failed");
  });
});
