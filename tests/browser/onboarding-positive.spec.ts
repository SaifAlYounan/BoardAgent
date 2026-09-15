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
  BuiltinOnboardingCsrf,
  WebAuthnCeremony,
  createBuiltinOnboardingHandler,
  type BuiltinOnboardingService
} from "../../artifacts/server/src/index.js";
import {
  MEMBER_ID,
  MemoryWebAuthnStore,
  ORGANIZATION_ID,
  SESSION_ID,
  allowAllWebAuthnAttempts,
  idSequence
} from "./webauthn-harness.js";

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

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunkValue of request) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    size += chunk.length;
    if (size > 256 * 1024) throw new Error("browser test request is too large");
    chunks.push(chunk);
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

describe("BoardAgent browser onboarding", () => {
  it("strips the one-use fragment, shows exact responsibilities, and requires a real passkey", async () => {
    const stageToken = Buffer.alloc(32, 0xe7).toString("base64url");
    const store = new MemoryWebAuthnStore(() => new Date());
    let ceremony: WebAuthnCeremony | undefined;
    let onboardingHandler: RequestListener | undefined;
    let completed = false;
    let completedStageToken: string | undefined;
    const server = createServer((request, response) => {
      const handle = async (): Promise<void> => {
        const path = new URL(request.url ?? "/", "http://localhost").pathname;
        if (path === "/") {
          response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
          response.end("<!doctype html><title>BoardAgent passkey setup</title>");
          return;
        }
        if (!ceremony || !onboardingHandler) {
          response.writeHead(503).end();
          return;
        }
        if (request.method === "GET" && path === "/register/options") {
          sendJson(
            response,
            200,
            await ceremony.beginRegistration({
              organizationId: ORGANIZATION_ID,
              memberId: MEMBER_ID,
              sessionId: SESSION_ID,
              purpose: "recovery",
              userName: "board-member-001",
              displayName: "Jane Director"
            })
          );
          return;
        }
        if (request.method === "POST" && path === "/register/complete") {
          await ceremony.completeRegistration({
            organizationId: ORGANIZATION_ID,
            memberId: MEMBER_ID,
            sessionId: SESSION_ID,
            purpose: "recovery",
            response: (await readJson(request)) as Parameters<
              WebAuthnCeremony["completeRegistration"]
            >[0]["response"]
          });
          sendJson(response, 200, { registered: true });
          return;
        }
        onboardingHandler(request, response);
      };
      void handle().catch((error: unknown) => {
        if (response.headersSent) {
          response.destroy();
          return;
        }
        sendJson(response, 500, {
          error: error instanceof Error ? error.message : "browser test failed"
        });
      });
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
      newId: idSequence(60_900)
    });
    const onboarding: Pick<BuiltinOnboardingService, "begin" | "complete"> = {
      begin: async (input) => {
        if (input.stageToken !== stageToken) throw new Error("unknown onboarding stage");
        return {
          organizationDisplayName: "Example Mining Exploration Ltd",
          boardName: "Exploration Board",
          memberDisplayName: "Jane Director",
          memberKind: "human",
          accountablePrincipalId: null,
          seatRole: "voting_member",
          terms: {
            versionId: ORGANIZATION_ID,
            version: 2,
            schemaVersion: "boardagent.onboarding-terms.v1",
            canonicalText:
              "Review board materials personally, keep the agent secure, and refetch before binding acts.",
            sha256: "12".repeat(32)
          },
          secretarySupport: {
            versionId: SESSION_ID,
            version: 1,
            name: "Amina — Board Secretary",
            contactMethods: [{ kind: "email", value: "secretary@example.test" }],
            sha256: "34".repeat(32)
          },
          presentationChoice: "structured summaries with source links",
          localMemoryChoice: "encrypted local cache with tombstone processing",
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
          publicKey: await ceremony!.beginAuthentication({
            organizationId: ORGANIZATION_ID,
            memberId: MEMBER_ID,
            sessionId: SESSION_ID,
            purpose: "recent_auth"
          })
        };
      },
      complete: async (input) => {
        if (input.stageToken !== stageToken) throw new Error("unknown onboarding stage");
        completedStageToken = input.stageToken;
        await ceremony!.completeAuthentication({
          organizationId: ORGANIZATION_ID,
          sessionId: SESSION_ID,
          purpose: "recent_auth",
          response: input.response
        });
        completed = true;
        return {
          status: "current",
          memberId: MEMBER_ID,
          boardId: ORGANIZATION_ID,
          termsVersionId: ORGANIZATION_ID,
          supportVersionId: SESSION_ID
        };
      }
    };
    onboardingHandler = createBuiltinOnboardingHandler({
      boundary: new AuthRequestBoundary({
        origin,
        allowInsecureLoopbackDevelopment: true
      }),
      onboarding,
      csrf: new BuiltinOnboardingCsrf({ key: Buffer.alloc(32, 0xe8) }),
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

      await page.goto(origin);
      await page.evaluate(async () => {
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
          await fetch("/register/options")
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
        if (!created) throw new Error("virtual authenticator did not create a passkey");
        const attestation = created.response as AuthenticatorAttestationResponse;
        const saved = await fetch("/register/complete", {
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
        if (!saved.ok) throw new Error(await saved.text());
      });

      const pageResponse = await page.goto(`${origin}/onboarding#${stageToken}`);
      expect(pageResponse?.status()).toBe(200);
      await expect.poll(() => page.url()).toBe(`${origin}/onboarding`);
      expect(await page.locator('input[name="stage_token"]').inputValue()).toBe(stageToken);
      expect(pageResponse?.headers()["referrer-policy"]).toBe("no-referrer");
      expect(pageResponse?.headers()["cache-control"]).toContain("no-store");
      expect(pageResponse?.headers()["content-security-policy"]).toContain(
        "frame-ancestors 'none'"
      );

      await page.locator("[data-load-onboarding]").click();
      await page.locator("[data-onboarding-review]").waitFor({ state: "visible" });
      expect(await page.locator("[data-organization]").textContent()).toBe(
        "Example Mining Exploration Ltd"
      );
      expect(await page.locator("[data-board]").textContent()).toBe("Exploration Board");
      expect(await page.locator("[data-member]").textContent()).toBe("Jane Director");
      expect(await page.locator("[data-member-kind]").textContent()).toBe("Human");
      expect(await page.locator("[data-accountable-principal]").textContent()).toBe(
        "Self — human member"
      );
      expect(await page.locator("[data-terms]").textContent()).toContain(
        "refetch before binding acts"
      );
      expect(await page.locator("[data-support]").textContent()).toBe("Amina — Board Secretary");
      expect(await page.locator("main").textContent()).toContain(
        "BoardAgent records this attestation; it does not claim that I understood"
      );
      expect(await page.locator("main").textContent()).toContain(
        "BoardAgent supplies canonical information to my agent"
      );

      await page.locator("[data-attest-passkey]").click();
      expect(await page.locator("[data-onboarding-status]").textContent()).toContain(
        "check the attestation box first"
      );
      expect(completed).toBe(false);
      await page.locator('input[name="attest"]').check();
      await page.locator("[data-attest-passkey]").click();
      await expect
        .poll(() => page.locator("[data-onboarding-status]").textContent())
        .toContain("Onboarding complete");
      expect(completed).toBe(true);
      expect(completedStageToken).toBe(stageToken);
      expect(await page.locator('input[name="stage_token"]').inputValue()).toBe("");
      expect([...store.challenges.values()].every(({ consumedAt }) => consumedAt !== null)).toBe(
        true
      );
      expect(store.credentials.size).toBe(1);
    } finally {
      await browser.close();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
    }
  }, 30_000);
});
