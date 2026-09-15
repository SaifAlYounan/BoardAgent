import { describe, expect, it } from "vitest";

import { WebAuthnCeremony } from "../../artifacts/server/src/index.js";
import {
  MEMBER_ID,
  MemoryWebAuthnStore,
  ORGANIZATION_ID,
  ORIGIN,
  RP_ID,
  SESSION_ID,
  idSequence
} from "./webauthn-harness.js";

describe("BoardAgent WebAuthn attempt throttling", () => {
  it("returns one generic rate-limit verdict before issuing challenge material", async () => {
    const store = new MemoryWebAuthnStore(() => new Date("2026-09-02T04:00:00Z"));
    const attempts: unknown[] = [];
    const options = {
      rpName: "BoardAgent",
      rpId: RP_ID,
      origin: ORIGIN,
      store,
      newId: idSequence(64_000),
      attemptLimiter: {
        async consume(context: unknown) {
          attempts.push(context);
          return { allowed: false, retryAfterSeconds: 60 };
        }
      }
    };
    const ceremony = new WebAuthnCeremony(options);
    await expect(
      ceremony.beginAuthentication({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "authentication"
      })
    ).rejects.toMatchObject({ code: "rate_limited", retryAfterSeconds: 60 });
    expect(attempts).toHaveLength(1);
    expect(store.challenges.size).toBe(0);
  });
});
