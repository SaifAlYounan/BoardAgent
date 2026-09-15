import { createServer } from "node:http";

import type {
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON
} from "@simplewebauthn/server";
import { chromium, type Page } from "playwright";
import { describe, expect, it } from "vitest";

import {
  WebAuthnCeremony,
  type WebAuthnCredentialRecord
} from "../../artifacts/server/src/index.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  MEMBER_ID,
  MemoryWebAuthnStore,
  ORGANIZATION_ID,
  ORIGIN,
  RP_ID,
  SESSION_ID,
  allowAllWebAuthnAttempts,
  authenticationResponse,
  fakeWebAuthnCrypto,
  idSequence,
  registrationResponse,
  type FakeCryptoControls
} from "./webauthn-harness.js";

function fixture(controls: Partial<FakeCryptoControls> = {}) {
  let current = new Date("2026-09-02T01:00:00Z");
  const store = new MemoryWebAuthnStore(() => current);
  const fake = fakeWebAuthnCrypto(controls);
  const ceremony = new WebAuthnCeremony({
    rpName: "BoardAgent",
    rpId: RP_ID,
    origin: ORIGIN,
    store,
    attemptLimiter: allowAllWebAuthnAttempts,
    crypto: fake.crypto,
    now: () => current,
    newId: idSequence(61_000)
  });
  return {
    ceremony,
    store,
    fake,
    advance(milliseconds: number) {
      current = new Date(current.getTime() + milliseconds);
    }
  };
}

async function register(setup: ReturnType<typeof fixture>): Promise<WebAuthnCredentialRecord> {
  await setup.ceremony.beginRegistration({
    organizationId: ORGANIZATION_ID,
    memberId: MEMBER_ID,
    sessionId: SESSION_ID,
    purpose: "enrollment",
    userName: "board-member-001",
    displayName: "Board Member"
  });
  return setup.ceremony.completeRegistration({
    organizationId: ORGANIZATION_ID,
    memberId: MEMBER_ID,
    sessionId: SESSION_ID,
    purpose: "enrollment",
    response: registrationResponse
  });
}

describe("BoardAgent WebAuthn negative ceremonies", () => {
  it("refuses real Chromium wrong-RP, missing-UV, origin tamper and replay attempts", async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><title>BoardAgent WebAuthn negative test</title>");
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("browser server has no port");
    const origin = `http://localhost:${String(address.port)}`;
    const store = new MemoryWebAuthnStore(() => new Date());
    const ceremony = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: "localhost",
      origin,
      store,
      attemptLimiter: allowAllWebAuthnAttempts,
      allowInsecureLoopbackDevelopment: true,
      newId: idSequence(61_100)
    });
    const options = await ceremony.beginRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      userName: "board-member-001",
      displayName: "Board Member"
    });
    const browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true
        }
      });
      await page.goto(origin);

      const wrongRp = await browserRegistration(page, options, "other.test");
      expect(wrongRp).toMatchObject({ ok: false });

      await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: false });
      const missingUv = await browserRegistration(page, { ...options, timeout: 1_000 });
      expect(missingUv).toMatchObject({ ok: false });

      await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: true });
      const created = await browserRegistration(page, options);
      if (!created.ok) throw new Error(`valid virtual ceremony failed: ${created.error}`);

      const clientData = JSON.parse(
        Buffer.from(created.response.response.clientDataJSON, "base64url").toString("utf8")
      ) as Record<string, unknown>;
      const wrongChallenge: RegistrationResponseJSON = {
        ...created.response,
        response: {
          ...created.response.response,
          clientDataJSON: Buffer.from(
            JSON.stringify({
              ...clientData,
              challenge: Buffer.alloc(32, 0xee).toString("base64url")
            })
          ).toString("base64url")
        }
      };
      await expect(
        ceremony.completeRegistration({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: SESSION_ID,
          purpose: "enrollment",
          response: wrongChallenge
        })
      ).rejects.toMatchObject({ code: "challenge_unavailable" });

      const wrongOrigin: RegistrationResponseJSON = {
        ...created.response,
        response: {
          ...created.response.response,
          clientDataJSON: Buffer.from(
            JSON.stringify({ ...clientData, origin: "https://attacker.test" })
          ).toString("base64url")
        }
      };
      await expect(
        ceremony.completeRegistration({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: SESSION_ID,
          purpose: "enrollment",
          response: wrongOrigin
        })
      ).rejects.toMatchObject({ code: "verification_failed" });

      await ceremony.completeRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "enrollment",
        response: created.response
      });
      await expect(
        ceremony.completeRegistration({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: SESSION_ID,
          purpose: "enrollment",
          response: created.response
        })
      ).rejects.toMatchObject({ code: "challenge_unavailable" });
      expect(store.credentials.size).toBe(1);
    } finally {
      await browser.close();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
    }
  }, 30_000);

  it("refuses insecure, non-origin and RP-confused configuration", () => {
    const store = new MemoryWebAuthnStore(() => new Date());
    expect(
      () =>
        new WebAuthnCeremony({
          rpName: "BoardAgent",
          rpId: RP_ID,
          origin: "http://boardagent.test",
          store,
          attemptLimiter: allowAllWebAuthnAttempts
        })
    ).toThrow(/exact HTTPS origin/u);
    expect(
      () =>
        new WebAuthnCeremony({
          rpName: "BoardAgent",
          rpId: "other.test",
          origin: ORIGIN,
          store,
          attemptLimiter: allowAllWebAuthnAttempts
        })
    ).toThrow(/exactly match/u);
    expect(
      () =>
        new WebAuthnCeremony({
          rpName: "BoardAgent",
          rpId: "BOARDAGENT.test",
          origin: ORIGIN,
          store,
          attemptLimiter: allowAllWebAuthnAttempts
        })
    ).toThrow(/canonical hostname/u);
  });

  it("binds registration to the exact member, session and unexpired one-use challenge", async () => {
    const setup = fixture();
    await setup.ceremony.beginRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      userName: "board-member-001",
      displayName: "Board Member"
    });
    await expect(
      setup.ceremony.completeRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: testId(61_500),
        purpose: "enrollment",
        response: registrationResponse
      })
    ).rejects.toMatchObject({ code: "challenge_unavailable" });
    expect(setup.fake.registrationCalls).toHaveLength(0);

    setup.advance(5 * 60_000 + 1);
    await expect(
      setup.ceremony.completeRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "enrollment",
        response: registrationResponse
      })
    ).rejects.toMatchObject({ code: "challenge_unavailable" });
    expect([...setup.store.challenges.values()][0]?.consumedAt).toBeNull();
  });

  it("rejects cross-origin client data before invoking the cryptographic verifier", async () => {
    const setup = fixture({ crossOrigin: true });
    await setup.ceremony.beginRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      userName: "board-member-001",
      displayName: "Board Member"
    });
    await expect(
      setup.ceremony.completeRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "enrollment",
        response: registrationResponse
      })
    ).rejects.toMatchObject({ code: "verification_failed" });
    expect(setup.fake.registrationCalls).toHaveLength(0);
  });

  it.each([
    ["cryptographic failure", { throwRegistration: true }],
    ["unverified response", { registrationVerified: false }],
    ["missing user verification", { registrationUserVerified: false }]
  ] satisfies Array<[string, Partial<FakeCryptoControls>]>)(
    "rejects registration %s without consuming the challenge",
    async (_label, controls) => {
      const setup = fixture(controls);
      await setup.ceremony.beginRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "enrollment",
        userName: "board-member-001",
        displayName: "Board Member"
      });
      await expect(
        setup.ceremony.completeRegistration({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: SESSION_ID,
          purpose: "enrollment",
          response: registrationResponse
        })
      ).rejects.toMatchObject({ code: "verification_failed" });
      expect([...setup.store.challenges.values()][0]?.consumedAt).toBeNull();
      expect(setup.store.credentials).toHaveLength(0);
    }
  );

  it("rejects impossible single-device backup state and duplicate ceremony replay", async () => {
    const impossible = fixture({ registrationBackedUp: true });
    await impossible.ceremony.beginRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      userName: "board-member-001",
      displayName: "Board Member"
    });
    await expect(
      impossible.ceremony.completeRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "enrollment",
        response: registrationResponse
      })
    ).rejects.toMatchObject({ code: "credential_policy_violation" });

    const replay = fixture();
    await register(replay);
    await expect(
      replay.ceremony.completeRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "enrollment",
        response: registrationResponse
      })
    ).rejects.toMatchObject({ code: "challenge_unavailable" });
    expect(replay.store.credentials.size).toBe(1);
  });

  it("rejects credential substitution, raw-ID ambiguity and backup-eligibility drift", async () => {
    const setup = fixture({ authenticationDeviceType: "multiDevice" });
    await register(setup);
    await setup.ceremony.beginAuthentication({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "authentication"
    });

    await expect(
      setup.ceremony.completeAuthentication({
        organizationId: ORGANIZATION_ID,
        sessionId: SESSION_ID,
        purpose: "authentication",
        response: { ...authenticationResponse, id: Buffer.alloc(32, 9).toString("base64url") }
      })
    ).rejects.toMatchObject({ code: "verification_failed" });

    await expect(
      setup.ceremony.completeAuthentication({
        organizationId: ORGANIZATION_ID,
        sessionId: SESSION_ID,
        purpose: "authentication",
        response: {
          ...authenticationResponse,
          id: Buffer.alloc(32, 9).toString("base64url"),
          rawId: Buffer.alloc(32, 9).toString("base64url")
        }
      })
    ).rejects.toMatchObject({ code: "credential_unavailable" });

    await expect(
      setup.ceremony.completeAuthentication({
        organizationId: ORGANIZATION_ID,
        sessionId: SESSION_ID,
        purpose: "authentication",
        response: authenticationResponse
      })
    ).rejects.toMatchObject({ code: "credential_policy_violation" });
    expect([...setup.store.challenges.values()].at(-1)?.consumedAt).toBeNull();
  });

  it("fails closed when an atomic counter race or challenge replay reaches commit", async () => {
    const raced = fixture({ authenticationCounter: 3 });
    const credential = await register(raced);
    await raced.ceremony.beginAuthentication({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "authentication"
    });
    const originalCommit = raced.store.completeAuthentication.bind(raced.store);
    raced.store.completeAuthentication = async (input) => {
      const current = raced.store.credentials.get(credential.id);
      if (!current) throw new Error("credential disappeared");
      raced.store.credentials.set(credential.id, { ...current, counter: 2 });
      return originalCommit(input);
    };
    await expect(
      raced.ceremony.completeAuthentication({
        organizationId: ORGANIZATION_ID,
        sessionId: SESSION_ID,
        purpose: "authentication",
        response: authenticationResponse
      })
    ).rejects.toMatchObject({ code: "ceremony_replayed" });

    const replay = fixture({ authenticationCounter: 1 });
    await register(replay);
    await replay.ceremony.beginAuthentication({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "authentication"
    });
    await replay.ceremony.completeAuthentication({
      organizationId: ORGANIZATION_ID,
      sessionId: SESSION_ID,
      purpose: "authentication",
      response: authenticationResponse
    });
    await expect(
      replay.ceremony.completeAuthentication({
        organizationId: ORGANIZATION_ID,
        sessionId: SESSION_ID,
        purpose: "authentication",
        response: authenticationResponse
      })
    ).rejects.toMatchObject({ code: "challenge_unavailable" });
  });
});

type BrowserRegistrationResult =
  | { readonly ok: true; readonly response: RegistrationResponseJSON }
  | { readonly ok: false; readonly error: string };

async function browserRegistration(
  page: Page,
  options: PublicKeyCredentialCreationOptionsJSON,
  overrideRpId?: string
): Promise<BrowserRegistrationResult> {
  return page.evaluate(
    async ({ supplied, rpId }): Promise<BrowserRegistrationResult> => {
      const decode = (value: string): Uint8Array<ArrayBuffer> => {
        const padded = value
          .replaceAll("-", "+")
          .replaceAll("_", "/")
          .padEnd(Math.ceil(value.length / 4) * 4, "=");
        const binary = atob(padded);
        return Uint8Array.from(binary, (character) => character.charCodeAt(0));
      };
      const encode = (value: ArrayBuffer): string => {
        const binary = Array.from(new Uint8Array(value), (byte) => String.fromCharCode(byte)).join(
          ""
        );
        return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
      };
      const { excludeCredentials, ...base } = supplied;
      try {
        const credential = (await navigator.credentials.create({
          publicKey: {
            ...base,
            rp: { ...base.rp, ...(rpId === undefined ? {} : { id: rpId }) },
            challenge: decode(base.challenge),
            user: { ...base.user, id: decode(base.user.id) },
            ...(excludeCredentials === undefined
              ? {}
              : {
                  excludeCredentials: excludeCredentials.map(
                    ({ transports: _transports, ...excluded }) => ({
                      ...excluded,
                      id: decode(excluded.id)
                    })
                  )
                })
          }
        })) as PublicKeyCredential | null;
        if (!credential) return { ok: false, error: "credential was null" };
        const attestation = credential.response as AuthenticatorAttestationResponse;
        return {
          ok: true,
          response: {
            id: credential.id,
            rawId: encode(credential.rawId),
            type: "public-key",
            ...(credential.authenticatorAttachment === "platform" ||
            credential.authenticatorAttachment === "cross-platform"
              ? { authenticatorAttachment: credential.authenticatorAttachment }
              : {}),
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
              clientDataJSON: encode(attestation.clientDataJSON),
              attestationObject: encode(attestation.attestationObject),
              transports: attestation.getTransports() as NonNullable<
                RegistrationResponseJSON["response"]["transports"]
              >
            }
          }
        };
      } catch (error) {
        return { ok: false, error: error instanceof Error ? error.name : "browser failure" };
      }
    },
    { supplied: options, rpId: overrideRpId }
  );
}
