import {
  createServer,
  type IncomingMessage,
  type RequestListener,
  type ServerResponse
} from "node:http";

import { chromium } from "playwright";
import { describe, expect, it } from "vitest";

import {
  AuthRequestBoundary,
  BuiltinEnrollmentCsrf,
  createBoardAgentOAuthInteractionHandler,
  createBuiltinEnrollmentHandler,
  WebAuthnCeremony,
  type BoardAgentOAuthProvider,
  type BuiltinEnrollmentService,
  type OidcInteractionBinding,
  type OidcInteractionBindingStore
} from "../../artifacts/server/src/index.js";
import { UuidV7Schema } from "../../lib/contracts/src/index.js";
import {
  AUTHENTICATION_CHALLENGE,
  CREDENTIAL_ID,
  MEMBER_ID,
  MemoryWebAuthnStore,
  ORGANIZATION_ID,
  ORIGIN,
  REGISTRATION_CHALLENGE,
  RP_ID,
  SESSION_ID,
  allowAllWebAuthnAttempts,
  authenticationResponse,
  fakeWebAuthnCrypto,
  idSequence,
  registrationResponse
} from "./webauthn-harness.js";

describe("BoardAgent WebAuthn positive ceremonies", () => {
  it("drives the hosted enrollment page through seat review and a real virtual passkey", async () => {
    const invitationToken = Buffer.alloc(32, 0xd1).toString("base64url");
    const activationCode = "ABC-2345";
    const store = new MemoryWebAuthnStore(() => new Date());
    let ceremony: WebAuthnCeremony | undefined;
    let enrollmentHandler: RequestListener | undefined;
    let completedProofingMethod: string | undefined;
    const server = createServer((request, response) => {
      if (!enrollmentHandler) {
        response.writeHead(503).end();
        return;
      }
      enrollmentHandler(request, response);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("browser server has no port");
    const origin = `http://localhost:${String(address.port)}`;
    ceremony = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: "localhost",
      origin,
      store,
      attemptLimiter: allowAllWebAuthnAttempts,
      allowInsecureLoopbackDevelopment: true,
      newId: idSequence(60_350)
    });
    const enrollment: Pick<BuiltinEnrollmentService, "begin" | "complete"> = {
      begin: async () => ({
        organizationDisplayName: "Example Mining Exploration Ltd",
        memberDisplayName: "Jane Director",
        seats: [
          {
            boardId: UuidV7Schema.parse(ORGANIZATION_ID),
            boardName: "Exploration Board",
            seatRole: "voting_member"
          }
        ],
        publicKey: await ceremony!.beginRegistration({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: null,
          purpose: "enrollment",
          userName: MEMBER_ID,
          displayName: "Jane Director"
        })
      }),
      complete: async (input) => {
        completedProofingMethod = input.proofingMethod;
        await ceremony!.completeRegistration({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: null,
          purpose: "enrollment",
          response: input.response
        });
        return {
          status: "pending_activation",
          memberId: MEMBER_ID,
          invitationId: SESSION_ID,
          activationChallengeId: ORGANIZATION_ID,
          activationCode,
          proofingMethod: input.proofingMethod,
          expiresInSeconds: 600
        };
      }
    };
    enrollmentHandler = createBuiltinEnrollmentHandler({
      boundary: new AuthRequestBoundary({
        origin,
        allowInsecureLoopbackDevelopment: true
      }),
      enrollment,
      csrf: new BuiltinEnrollmentCsrf({ key: Buffer.alloc(32, 0xd2) }),
      includeHsts: false
    });

    const browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      page.setDefaultTimeout(10_000);
      page.setDefaultNavigationTimeout(10_000);
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true
        }
      });

      const pageResponse = await page.goto(`${origin}/enroll#${invitationToken}`);
      expect(pageResponse?.status()).toBe(200);
      expect(page.url()).toBe(`${origin}/enroll`);
      expect(await page.locator('input[name="invitation_token"]').inputValue()).toBe(
        invitationToken
      );
      await page.locator("[data-inspect-invitation]").click();
      await page.locator("[data-candidate]").waitFor({ state: "visible" });
      expect(await page.locator("[data-organization]").textContent()).toBe(
        "Example Mining Exploration Ltd"
      );
      expect(await page.locator("[data-member]").textContent()).toBe("Jane Director");
      expect(await page.locator("[data-seats]").textContent()).toContain("Exploration Board");

      await page.locator("[data-create-passkey]").click();
      await page.locator("[data-activation-code]").waitFor({ state: "visible" });
      expect(await page.locator("[data-activation-code]").textContent()).toContain(activationCode);
      expect(await page.locator("[data-activation-code]").textContent()).toContain(
        "Activation reference: " + ORGANIZATION_ID
      );
      expect(await page.locator("[data-enrollment-status]").textContent()).toContain(
        "access remains disabled"
      );
      expect(await page.locator('input[name="invitation_token"]').inputValue()).toBe("");
      expect(completedProofingMethod).toBe("verified_number_call");
      expect(store.credentials.size).toBe(1);
      expect([...store.challenges.values()].every(({ consumedAt }) => consumedAt !== null)).toBe(
        true
      );
    } finally {
      await browser.close();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
    }
  }, 30_000);

  it("completes real registration and authentication in Chromium's virtual authenticator", async () => {
    const store = new MemoryWebAuthnStore(() => new Date());
    let ceremony: WebAuthnCeremony | undefined;
    const server = createServer((request, response) => {
      void handleVirtualAuthenticatorRequest(request, response, () => ceremony);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("browser server has no port");
    const origin = `http://localhost:${String(address.port)}`;
    ceremony = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: "localhost",
      origin,
      store,
      attemptLimiter: allowAllWebAuthnAttempts,
      allowInsecureLoopbackDevelopment: true,
      newId: idSequence(60_400)
    });
    const browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      page.setDefaultTimeout(5_000);
      page.setDefaultNavigationTimeout(5_000);
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
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
      const result = await page.evaluate(async () => {
        const decode = (value: string): Uint8Array<ArrayBuffer> => {
          const padded = value
            .replaceAll("-", "+")
            .replaceAll("_", "/")
            .padEnd(Math.ceil(value.length / 4) * 4, "=");
          const binary = atob(padded);
          return Uint8Array.from(binary, (character) => character.charCodeAt(0));
        };
        const encode = (value: ArrayBuffer): string => {
          const binary = Array.from(new Uint8Array(value), (byte) =>
            String.fromCharCode(byte)
          ).join("");
          return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
        };

        const registrationOptions = (await (
          await fetch("/webauthn/register/options")
        ).json()) as PublicKeyCredentialCreationOptionsJSON;
        const { excludeCredentials, ...registrationBase } = registrationOptions;
        const created = (await navigator.credentials.create({
          publicKey: {
            ...registrationBase,
            challenge: decode(registrationOptions.challenge),
            user: { ...registrationOptions.user, id: decode(registrationOptions.user.id) },
            ...(excludeCredentials === undefined
              ? {}
              : {
                  excludeCredentials: excludeCredentials.map((credential) => ({
                    ...credential,
                    id: decode(credential.id)
                  }))
                })
          }
        })) as PublicKeyCredential | null;
        if (!created) throw new Error("virtual authenticator did not create a credential");
        const attestation = created.response as AuthenticatorAttestationResponse;
        const registration = await fetch("/webauthn/register/complete", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            id: created.id,
            rawId: encode(created.rawId),
            type: created.type,
            authenticatorAttachment: created.authenticatorAttachment,
            clientExtensionResults: created.getClientExtensionResults(),
            response: {
              clientDataJSON: encode(attestation.clientDataJSON),
              attestationObject: encode(attestation.attestationObject),
              transports: attestation.getTransports()
            }
          })
        });
        if (!registration.ok) throw new Error(await registration.text());

        const authenticationOptions = (await (
          await fetch("/webauthn/authenticate/options")
        ).json()) as PublicKeyCredentialRequestOptionsJSON;
        const { allowCredentials, ...authenticationBase } = authenticationOptions;
        const asserted = (await navigator.credentials.get({
          publicKey: {
            ...authenticationBase,
            challenge: decode(authenticationOptions.challenge),
            ...(allowCredentials === undefined
              ? {}
              : {
                  allowCredentials: allowCredentials.map((credential) => ({
                    ...credential,
                    id: decode(credential.id)
                  }))
                })
          }
        })) as PublicKeyCredential | null;
        if (!asserted) throw new Error("virtual authenticator did not assert a credential");
        const assertion = asserted.response as AuthenticatorAssertionResponse;
        const authentication = await fetch("/webauthn/authenticate/complete", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            id: asserted.id,
            rawId: encode(asserted.rawId),
            type: asserted.type,
            authenticatorAttachment: asserted.authenticatorAttachment,
            clientExtensionResults: asserted.getClientExtensionResults(),
            response: {
              clientDataJSON: encode(assertion.clientDataJSON),
              authenticatorData: encode(assertion.authenticatorData),
              signature: encode(assertion.signature),
              ...(assertion.userHandle === null ? {} : { userHandle: encode(assertion.userHandle) })
            }
          })
        });
        if (!authentication.ok) throw new Error(await authentication.text());
        return authentication.json() as Promise<{ newCounter: number; memberId: string }>;
      });
      expect(result.memberId).toBe(MEMBER_ID);
      expect(result.newCounter).toBeGreaterThanOrEqual(1);
      expect(store.credentials.size).toBe(1);
      expect([...store.challenges.values()].every(({ consumedAt }) => consumedAt !== null)).toBe(
        true
      );
    } finally {
      await browser.close();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
    }
  }, 30_000);

  it("drives the hardened OAuth page script through a real virtual passkey", async () => {
    const interactionUid = Buffer.alloc(24, 0xb1).toString("base64url");
    const csrfToken = Buffer.alloc(32, 0xb2).toString("base64url");
    const store = new MemoryWebAuthnStore(() => new Date());
    let ceremony: WebAuthnCeremony | undefined;
    let interactionHandler: RequestListener | undefined;
    let approvedMember: string | undefined;
    let completionStarted = false;
    let completionHeaders: unknown;
    const server = createServer((request, response) => {
      if (request.url?.endsWith("/passkey/complete")) {
        completionHeaders = {
          host: request.headers.host,
          origin: request.headers.origin,
          secFetchSite: request.headers["sec-fetch-site"],
          contentType: request.headers["content-type"],
          contentLength: request.headers["content-length"]
        };
      }
      if (request.url === "/approved") {
        response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        response.end("approved");
        return;
      }
      if (request.url?.startsWith("/auth/") && interactionHandler) {
        interactionHandler(request, response);
        return;
      }
      void handleVirtualAuthenticatorRequest(request, response, () => ceremony);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("browser server has no port");
    const origin = `http://localhost:${String(address.port)}`;
    ceremony = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: "localhost",
      origin,
      store,
      attemptLimiter: allowAllWebAuthnAttempts,
      allowInsecureLoopbackDevelopment: true,
      newId: idSequence(60_500)
    });
    const binding: OidcInteractionBinding = {
      interactionUid,
      authorizationRequestId: SESSION_ID,
      sessionId: SESSION_ID,
      clientId: ORGANIZATION_ID,
      protocolClientId: "https://portable-client.test/client.json",
      clientDisplayName: "Portable client",
      resourceUri: "https://boardagent.test/mcp",
      scopes: ["documents:read"],
      csrfToken,
      expiresAt: new Date(Date.now() + 300_000)
    };
    const bindingStore: OidcInteractionBindingStore = {
      load: async () => binding,
      verifyCsrf: (candidate, submitted) => {
        if (candidate !== binding || submitted !== csrfToken) throw new Error("CSRF rejected");
      }
    };
    const provider: BoardAgentOAuthProvider = {
      issuer: "https://boardagent.test",
      resourceUri: "https://boardagent.test/mcp",
      callback: () => {
        throw new Error("provider callback is outside this browser fixture");
      },
      interactionDetails: async () =>
        ({
          uid: interactionUid,
          prompt: { name: "login", reasons: [], details: {} },
          params: {
            client_id: binding.protocolClientId,
            resource: binding.resourceUri,
            scope: "documents:read"
          }
        }) as never,
      approveInteraction: async (_request, responseValue, input) => {
        approvedMember = input.memberId;
        const response = responseValue as ServerResponse;
        response.writeHead(303, { location: "/approved" });
        response.end();
      },
      denyInteraction: async (_request, responseValue) => {
        const response = responseValue as ServerResponse;
        response.writeHead(303, { location: "/denied" });
        response.end();
      }
    };
    interactionHandler = createBoardAgentOAuthInteractionHandler({
      organizationId: ORGANIZATION_ID,
      boundary: new AuthRequestBoundary({
        origin,
        allowInsecureLoopbackDevelopment: true
      }),
      provider,
      bindingStore,
      webauthn: {
        beginAuthentication: (input) => ceremony!.beginAuthentication(input),
        completeAuthentication: async (input) => {
          completionStarted = true;
          return ceremony!.completeAuthentication(input);
        }
      },
      includeHsts: false
    });

    const browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      page.setDefaultTimeout(5_000);
      page.setDefaultNavigationTimeout(5_000);
      let completionShape: unknown;
      page.on("request", (outbound) => {
        if (!outbound.url().endsWith("/passkey/complete")) return;
        try {
          const form = new URLSearchParams(outbound.postData() ?? "");
          const submitted = JSON.parse(form.get("credential") ?? "null") as {
            readonly response?: Readonly<Record<string, unknown>>;
            readonly clientExtensionResults?: Readonly<Record<string, unknown>>;
            readonly [key: string]: unknown;
          };
          completionShape = {
            formKeys: [...form.keys()].toSorted(),
            credentialKeys: Object.keys(submitted).toSorted(),
            responseKeys: Object.keys(submitted.response ?? {}).toSorted(),
            extensionKeys: Object.keys(submitted.clientExtensionResults ?? {}).toSorted(),
            authenticatorAttachment: submitted["authenticatorAttachment"] ?? null,
            fieldShapes: Object.fromEntries(
              [
                submitted["id"],
                submitted["rawId"],
                submitted.response?.["clientDataJSON"],
                submitted.response?.["authenticatorData"],
                submitted.response?.["signature"],
                submitted.response?.["userHandle"]
              ].map((value, index) => [
                index,
                typeof value === "string"
                  ? { length: value.length, canonical: /^[A-Za-z0-9_-]+$/u.test(value) }
                  : typeof value
              ])
            ),
            credentialType: submitted["type"],
            userHandle:
              submitted.response?.["userHandle"] === null
                ? null
                : typeof submitted.response?.["userHandle"]
          };
        } catch {
          completionShape = "unparseable";
        }
      });
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
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
      const enrolled = await page.evaluate(async () => {
        const decode = (value: string): Uint8Array<ArrayBuffer> => {
          const padded = value
            .replaceAll("-", "+")
            .replaceAll("_", "/")
            .padEnd(Math.ceil(value.length / 4) * 4, "=");
          const binary = atob(padded);
          return Uint8Array.from(binary, (character) => character.charCodeAt(0));
        };
        const encode = (value: ArrayBuffer): string => {
          const binary = Array.from(new Uint8Array(value), (byte) =>
            String.fromCharCode(byte)
          ).join("");
          return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
        };
        const options = (await (
          await fetch("/webauthn/register/options")
        ).json()) as PublicKeyCredentialCreationOptionsJSON;
        const { excludeCredentials, ...base } = options;
        const created = (await navigator.credentials.create({
          publicKey: {
            ...base,
            challenge: decode(options.challenge),
            user: { ...options.user, id: decode(options.user.id) },
            ...(excludeCredentials === undefined
              ? {}
              : {
                  excludeCredentials: excludeCredentials.map((entry) => ({
                    ...entry,
                    id: decode(entry.id)
                  }))
                })
          }
        })) as PublicKeyCredential | null;
        if (!created) throw new Error("virtual authenticator did not enroll a passkey");
        const attestation = created.response as AuthenticatorAttestationResponse;
        const completed = await fetch("/webauthn/register/complete", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            id: created.id,
            rawId: encode(created.rawId),
            type: created.type,
            authenticatorAttachment: created.authenticatorAttachment,
            clientExtensionResults: created.getClientExtensionResults(),
            response: {
              clientDataJSON: encode(attestation.clientDataJSON),
              attestationObject: encode(attestation.attestationObject),
              transports: attestation.getTransports()
            }
          })
        });
        return completed.ok;
      });
      expect(enrolled).toBe(true);

      const interactionPage = await page.goto(`${origin}/auth/interactions/${interactionUid}`);
      if (interactionPage?.status() !== 200) {
        throw new Error(
          `OAuth passkey page failed: ${String(interactionPage?.status())} ${await page.textContent("body")}`
        );
      }
      await page.locator("[data-passkey-button]").evaluate((button: HTMLButtonElement) => {
        button.click();
      });
      try {
        await page.waitForURL(`${origin}/approved`, { timeout: 10_000 });
      } catch {
        throw new Error(
          `OAuth passkey browser did not continue: ${JSON.stringify({
            url: page.url(),
            body: await page.textContent("body").catch(() => null),
            status: await page
              .locator("[data-passkey-status]")
              .textContent()
              .catch(() => null),
            approvedMember,
            completionStarted,
            completionHeaders,
            completionShape,
            challengeCount: store.challenges.size,
            credentialCounter: [...store.credentials.values()][0]?.counter
          })}`
        );
      }
      expect(await page.textContent("body")).toBe("approved");
      expect(approvedMember).toBe(MEMBER_ID);
      expect(store.credentials.size).toBe(1);
      expect([...store.credentials.values()][0]?.counter).toBeGreaterThanOrEqual(1);
      expect([...store.challenges.values()].every(({ consumedAt }) => consumedAt !== null)).toBe(
        true
      );
    } finally {
      await browser.close();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
    }
  }, 30_000);

  it("registers a UV passkey with an exact, hashed, one-use ceremony", async () => {
    const current = new Date("2026-09-02T00:00:00Z");
    const store = new MemoryWebAuthnStore(() => current);
    const fake = fakeWebAuthnCrypto();
    const ceremony = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: RP_ID,
      origin: ORIGIN,
      store,
      attemptLimiter: allowAllWebAuthnAttempts,
      crypto: fake.crypto,
      now: () => current,
      newId: idSequence()
    });

    const options = await ceremony.beginRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      userName: "board-member-001",
      displayName: "Board Member"
    });

    expect(options).toMatchObject({
      challenge: REGISTRATION_CHALLENGE,
      rp: { id: RP_ID, name: "BoardAgent" },
      timeout: 60_000,
      attestation: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required"
      }
    });
    expect(options.user.id).toBe(
      Buffer.from(MEMBER_ID.replaceAll("-", ""), "hex").toString("base64url")
    );
    expect(options.excludeCredentials).toEqual([]);
    const [storedChallenge] = [...store.challenges.values()];
    expect(storedChallenge).toMatchObject({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      rpId: RP_ID,
      exactOrigin: ORIGIN,
      consumedAt: null
    });
    expect(storedChallenge?.challengeSha256).not.toContain(REGISTRATION_CHALLENGE);
    expect(storedChallenge?.expiresAt.toISOString()).toBe("2026-09-02T00:05:00.000Z");

    const credential = await ceremony.completeRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      response: registrationResponse
    });

    expect(credential).toMatchObject({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      counter: 0,
      transports: ["internal"],
      backupEligible: false,
      backupState: false,
      state: "active"
    });
    expect(Buffer.from(credential.credentialId).toString("base64url")).toBe(CREDENTIAL_ID);
    expect([...store.challenges.values()][0]?.consumedAt).toEqual(current);
    expect(fake.registrationCalls[0]).toMatchObject({
      expectedChallenge: REGISTRATION_CHALLENGE,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      expectedType: "webauthn.create",
      requireUserPresence: true,
      requireUserVerification: true
    });
  });

  it("authenticates the credential with required UV and atomically advances its counter", async () => {
    const current = new Date("2026-09-02T00:10:00Z");
    const store = new MemoryWebAuthnStore(() => current);
    const fake = fakeWebAuthnCrypto({ authenticationCounter: 7 });
    const ceremony = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: RP_ID,
      origin: ORIGIN,
      store,
      attemptLimiter: allowAllWebAuthnAttempts,
      crypto: fake.crypto,
      now: () => current,
      newId: idSequence(60_200)
    });
    await ceremony.beginRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      userName: "board-member-001",
      displayName: "Board Member"
    });
    const registered = await ceremony.completeRegistration({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "enrollment",
      response: registrationResponse
    });

    const options = await ceremony.beginAuthentication({
      organizationId: ORGANIZATION_ID,
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      purpose: "authentication"
    });
    expect(options).toMatchObject({
      challenge: AUTHENTICATION_CHALLENGE,
      rpId: RP_ID,
      timeout: 60_000,
      userVerification: "required",
      allowCredentials: [{ id: CREDENTIAL_ID, transports: ["internal"] }]
    });

    const result = await ceremony.completeAuthentication({
      organizationId: ORGANIZATION_ID,
      sessionId: SESSION_ID,
      purpose: "authentication",
      response: authenticationResponse
    });
    expect(result).toEqual({
      memberId: MEMBER_ID,
      sessionId: SESSION_ID,
      credentialId: registered.id,
      newCounter: 7,
      backupState: false
    });
    expect(store.credentials.get(registered.id)?.counter).toBe(7);
    expect(fake.authenticationCalls[0]).toMatchObject({
      expectedChallenge: AUTHENTICATION_CHALLENGE,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      expectedType: "webauthn.get",
      requireUserVerification: true,
      credential: { id: CREDENTIAL_ID, counter: 0, transports: ["internal"] }
    });
  });

  it("supports discoverable authentication without leaking a credential allow-list", async () => {
    const current = new Date("2026-09-02T00:20:00Z");
    const store = new MemoryWebAuthnStore(() => current);
    const fake = fakeWebAuthnCrypto();
    const ceremony = new WebAuthnCeremony({
      rpName: "BoardAgent",
      rpId: RP_ID,
      origin: ORIGIN,
      store,
      attemptLimiter: allowAllWebAuthnAttempts,
      crypto: fake.crypto,
      now: () => current,
      newId: idSequence(60_300)
    });
    const options = await ceremony.beginAuthentication({
      organizationId: ORGANIZATION_ID,
      memberId: null,
      sessionId: SESSION_ID,
      purpose: "authentication"
    });
    expect(options.allowCredentials).toBeUndefined();
    expect([...store.challenges.values()][0]?.memberId).toBeNull();
  });
});

interface PublicKeyCredentialCreationOptionsJSON {
  readonly challenge: string;
  readonly rp: PublicKeyCredentialRpEntity;
  readonly user: Omit<PublicKeyCredentialUserEntity, "id"> & { readonly id: string };
  readonly pubKeyCredParams: PublicKeyCredentialParameters[];
  readonly timeout?: number;
  readonly attestation?: AttestationConveyancePreference;
  readonly authenticatorSelection?: AuthenticatorSelectionCriteria;
  readonly excludeCredentials?: Array<
    Omit<PublicKeyCredentialDescriptor, "id"> & { readonly id: string }
  >;
}

interface PublicKeyCredentialRequestOptionsJSON {
  readonly challenge: string;
  readonly rpId?: string;
  readonly timeout?: number;
  readonly userVerification?: UserVerificationRequirement;
  readonly allowCredentials?: Array<
    Omit<PublicKeyCredentialDescriptor, "id"> & { readonly id: string }
  >;
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 256 * 1024) throw new Error("browser test request is too large");
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const encoded = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(encoded.length),
    "cache-control": "no-store"
  });
  response.end(encoded);
}

async function handleVirtualAuthenticatorRequest(
  request: IncomingMessage,
  response: ServerResponse,
  getCeremony: () => WebAuthnCeremony | undefined
): Promise<void> {
  try {
    const ceremony = getCeremony();
    if (!ceremony) throw new Error("WebAuthn ceremony is not initialized");
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    if (path === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><title>BoardAgent WebAuthn test</title>");
      return;
    }
    if (request.method === "GET" && path === "/webauthn/register/options") {
      sendJson(
        response,
        200,
        await ceremony.beginRegistration({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: SESSION_ID,
          purpose: "enrollment",
          userName: "board-member-001",
          displayName: "Board Member"
        })
      );
      return;
    }
    if (request.method === "POST" && path === "/webauthn/register/complete") {
      const credential = await ceremony.completeRegistration({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        sessionId: SESSION_ID,
        purpose: "enrollment",
        response: (await readJson(request)) as Parameters<
          WebAuthnCeremony["completeRegistration"]
        >[0]["response"]
      });
      sendJson(response, 200, { credentialId: credential.id });
      return;
    }
    if (request.method === "GET" && path === "/webauthn/authenticate/options") {
      sendJson(
        response,
        200,
        await ceremony.beginAuthentication({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          sessionId: SESSION_ID,
          purpose: "authentication"
        })
      );
      return;
    }
    if (request.method === "POST" && path === "/webauthn/authenticate/complete") {
      const result = await ceremony.completeAuthentication({
        organizationId: ORGANIZATION_ID,
        sessionId: SESSION_ID,
        purpose: "authentication",
        response: (await readJson(request)) as Parameters<
          WebAuthnCeremony["completeAuthentication"]
        >[0]["response"]
      });
      sendJson(response, 200, result);
      return;
    }
    sendJson(response, 404, { error: "not_found" });
  } catch (error) {
    sendJson(response, 400, {
      error: error instanceof Error ? error.message : "WebAuthn request failed"
    });
  }
}
