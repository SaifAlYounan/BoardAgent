import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ClientRegistrationError,
  isPublicCimdAddress,
  parseDcrClientMetadata,
  resolveCimdClientMetadata,
  validateCimdClientId,
  validateOAuthRedirectUri
} from "../../artifacts/server/src/client-registration.js";

afterEach(() => vi.useRealTimers());

describe("CIMD total attempt budget with inert resolver and document ports", () => {
  const clientId = "https://synthetic-client.example/metadata";
  const addresses = [{ address: "8.8.8.8", family: 4 as const }];
  const response = {
    statusCode: 200,
    contentType: "application/json",
    body: Buffer.from(
      JSON.stringify({
        client_id: clientId,
        client_name: "Synthetic client",
        redirect_uris: ["https://synthetic-client.example/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none"
      })
    )
  };

  it.each(["resolution", "document"] as const)(
    "bounds stalled %s and suppresses late results",
    async (phase) => {
      vi.useFakeTimers();
      let finishResolution: ((value: typeof addresses) => void) | undefined;
      let finishDocument: ((value: typeof response) => void) | undefined;
      const resolver = vi.fn(() =>
        phase === "resolution"
          ? new Promise<typeof addresses>((resolve) => {
              finishResolution = resolve;
            })
          : Promise.resolve(addresses)
      );
      const fetcher = vi.fn(
        () =>
          new Promise<typeof response>((resolve) => {
            finishDocument = resolve;
          })
      );
      let settled: unknown;
      const attempt = resolveCimdClientMetadata(clientId, ["governance:read"], {
        resolver,
        fetcher,
        timeoutMs: 100
      }).then(
        (value) => {
          settled = value;
        },
        (error: unknown) => {
          settled = error;
        }
      );
      try {
        await vi.advanceTimersByTimeAsync(101);
        expect(settled).toBeInstanceOf(ClientRegistrationError);
        expect(settled).toMatchObject({ code: "cimd_timeout" });
        if (phase === "resolution") expect(fetcher).not.toHaveBeenCalled();
        finishResolution?.(addresses);
        finishDocument?.(response);
        await vi.advanceTimersByTimeAsync(0);
        if (phase === "resolution") expect(fetcher).not.toHaveBeenCalled();
        expect(settled).toMatchObject({ code: "cimd_timeout" });
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        finishResolution?.(addresses);
        await vi.advanceTimersByTimeAsync(0);
        finishDocument?.(response);
        await attempt;
      }
    }
  );

  it("shares one deadline across resolution and metadata, but accepts a timely exact document", async () => {
    vi.useFakeTimers();
    const run = (documentDelay: number) =>
      resolveCimdClientMetadata(clientId, ["governance:read"], {
        resolver: () => new Promise((resolve) => setTimeout(() => resolve(addresses), 60)),
        fetcher: () => new Promise((resolve) => setTimeout(() => resolve(response), documentDelay)),
        timeoutMs: 100
      });
    let settled: unknown;
    const late = run(60).then(
      (value) => {
        settled = value;
      },
      (error: unknown) => {
        settled = error;
      }
    );
    await vi.advanceTimersByTimeAsync(101);
    expect(settled).toMatchObject({ code: "cimd_timeout" });
    await vi.advanceTimersByTimeAsync(30);
    await late;
    const timely = run(20);
    await vi.advanceTimersByTimeAsync(81);
    await expect(timely).resolves.toMatchObject({ clientId, clientName: "Synthetic client" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(["resolution", "document"] as const)(
    "observes a late %s rejection after the total deadline",
    async (phase) => {
      vi.useFakeTimers();
      let rejectLate: ((error: Error) => void) | undefined;
      const stalled = new Promise<never>((_resolve, reject) => {
        rejectLate = reject;
      });
      const fetcher = vi.fn(() => (phase === "document" ? stalled : Promise.resolve(response)));
      const pending = resolveCimdClientMetadata(clientId, ["governance:read"], {
        resolver: () => (phase === "resolution" ? stalled : Promise.resolve(addresses)),
        fetcher,
        timeoutMs: 100
      }).catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(101);
      const error = await pending;
      expect(error).toMatchObject({ code: "cimd_timeout" });
      rejectLate?.(new Error("synthetic late dependency rejection"));
      await vi.advanceTimersByTimeAsync(0);
      expect(await pending).toBe(error);
      if (phase === "resolution") expect(fetcher).not.toHaveBeenCalled();
      expect(vi.getTimerCount()).toBe(0);
    }
  );

  it("forwards only the remaining time and cancels the document port on expiry", async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn(
      (_request: { timeoutMs: number; signal?: AbortSignal }) => new Promise<never>(() => {})
    );
    const pending = resolveCimdClientMetadata(clientId, ["governance:read"], {
      resolver: () => new Promise((resolve) => setTimeout(() => resolve(addresses), 60)),
      fetcher,
      timeoutMs: 100
    }).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(61);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0]?.[0].timeoutMs).toBe(40);
    const signal = fetcher.mock.calls[0]?.[0].signal;
    expect(signal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(40);
    await expect(pending).resolves.toMatchObject({ code: "cimd_timeout" });
    expect(signal?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([0, 99, 30001, Number.NaN])(
    "refuses invalid timeout %s before calling either dependency",
    async (timeoutMs) => {
      const resolver = vi.fn(() => Promise.resolve(addresses));
      const fetcher = vi.fn(() => Promise.resolve(response));
      await expect(
        resolveCimdClientMetadata(clientId, ["governance:read"], {
          resolver,
          fetcher,
          timeoutMs
        })
      ).rejects.toBeInstanceOf(RangeError);
      expect(resolver).not.toHaveBeenCalled();
      expect(fetcher).not.toHaveBeenCalled();
    }
  );

  it.each(["resolution", "document"] as const)(
    "normalizes a prompt %s failure and clears the deadline",
    async (phase) => {
      vi.useFakeTimers();
      const marker = new Error("synthetic dependency rejection");
      const pending = resolveCimdClientMetadata(clientId, ["governance:read"], {
        resolver: () =>
          phase === "resolution" ? Promise.reject(marker) : Promise.resolve(addresses),
        fetcher: () => Promise.reject(marker),
        timeoutMs: 100
      });
      await expect(pending).rejects.toMatchObject({
        code: phase === "resolution" ? "cimd_resolution_failed" : "cimd_fetch_failed"
      });
      expect(vi.getTimerCount()).toBe(0);
    }
  );
});

describe("TH-06 client-registration abuse", () => {
  it("rejects SSRF addresses, redirect confusion, and asserted registration authority", () => {
    for (const address of [
      "0.0.0.0",
      "10.0.0.1",
      "127.0.0.1",
      "169.254.169.254",
      "192.168.1.1",
      "::1",
      "::ffff:127.0.0.1",
      "fc00::1"
    ]) {
      expect(isPublicCimdAddress(address), address).toBe(false);
    }
    for (const clientId of [
      "http://client.example/metadata",
      "https://127.0.0.1/metadata",
      "https://client.example:444/metadata",
      "https://client.example/metadata?target=internal"
    ]) {
      expect(() => validateCimdClientId(clientId)).toThrow(ClientRegistrationError);
    }
    for (const redirect of [
      "http://client.example/callback",
      "http://localhost/callback",
      "http://app.localhost:49152/callback",
      "https://user@client.example/callback",
      "https://client.example/callback#fragment"
    ]) {
      expect(() => validateOAuthRedirectUri(redirect)).toThrow(ClientRegistrationError);
    }

    const metadata = {
      client_name: "Attacker-controlled label",
      redirect_uris: ["https://client.example/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: "documents:read governance:read",
      software_id: "claims-to-be-trusted"
    };
    expect(() =>
      parseDcrClientMetadata(JSON.stringify({ ...metadata, client_id: "admin" }), [
        "documents:read",
        "governance:read"
      ])
    ).toThrow(ClientRegistrationError);
    expect(() =>
      parseDcrClientMetadata(JSON.stringify({ ...metadata, scope: "secretariat:admin" }), [
        "documents:read",
        "governance:read"
      ])
    ).toThrow(ClientRegistrationError);
  });
});
