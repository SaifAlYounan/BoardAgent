import { afterEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({ confirm: vi.fn() }));
// Inert repository and security ports; this test opens no sockets or database connection.
vi.mock("@boardagent/db", () => ({
  isOnboardingPublicationTool: () => false,
  withRequestTransaction: async (
    _pool: unknown,
    _context: unknown,
    run: (client: unknown) => Promise<unknown>
  ) => run({}),
  confirmWebhookAdministrationActionInTransaction: mocked.confirm
}));

import { ControlPlaneSurface } from "../../artifacts/server/src/control-plane-surface.js";
import type {
  ResolveHumanActionInput,
  SurfacePrincipal
} from "../../artifacts/server/src/ports.js";
import type { WebhookSecurityPort } from "../../artifacts/server/src/webhook-security.js";

const ID = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e01";
const principal: SurfacePrincipal = {
  organizationId: ID,
  memberId: ID,
  serviceOrigin: "https://synthetic-board.example",
  clientId: ID,
  protocolClientId: "synthetic-client",
  accessTokenRecordId: ID,
  tokenJti: ID,
  keyId: "synthetic",
  scopes: ["notifications:manage"],
  roles: ["observer"],
  boardIds: []
};

function fixture() {
  const validate = vi.fn(async () => {
    throw new Error("synthetic DNS unavailable");
  });
  const createSecret = vi.fn(() => {
    throw new Error("unexpected secret creation");
  });
  const security: WebhookSecurityPort = {
    activeKeyId: ID,
    validateEndpoint: validate,
    createSecret,
    openEndpoint: () => {
      throw new Error("unexpected endpoint decryption");
    },
    openSecret: () => {
      throw new Error("unexpected secret decryption");
    },
    protectEndpoint: async () => {
      throw new Error("unexpected endpoint protection");
    }
  };
  const surface = new ControlPlaneSurface(
    {} as ConstructorParameters<typeof ControlPlaneSurface>[0],
    {
      webhookSecurity: security,
      newId: () => ID
    }
  );
  const resolve = (action: ResolveHumanActionInput["response_action"]) =>
    surface.resolveHumanAction({
      principal,
      tool: "configure_webhook",
      input: {
        webhook_id: ID,
        endpoint: "https://synthetic-hook.example/wake",
        event_classes: ["security"],
        recent_auth_proof: "synthetic-proof",
        idempotency_key: "synthetic-webhook-cancellation"
      },
      stage_id: ID,
      client_capabilities: { elicitation: { form: {} } },
      request_state: "synthetic-request-state",
      retry_request_id: Buffer.from("synthetic-retry"),
      response_action: action,
      input_response: null
    });
  return { validate, createSecret, resolve };
}

afterEach(() => vi.clearAllMocks());

describe("webhook confirmation cancellation with inert ports", () => {
  it.each(["decline", "cancel"] as const)(
    "records %s without requiring the endpoint to resolve",
    async (action) => {
      const f = fixture();
      mocked.confirm.mockResolvedValue({ confirmed: false, reason: action });
      await expect(f.resolve(action)).resolves.toEqual({ confirmed: false, reason: action });
      expect(f.validate).not.toHaveBeenCalled();
      expect(f.createSecret).not.toHaveBeenCalled();
      expect(mocked.confirm).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          secretMaterial: null,
          confirmation: expect.objectContaining({
            responseAction: action,
            stageId: ID,
            originalArguments: expect.objectContaining({ webhook_id: ID })
          })
        })
      );
    }
  );

  it("still refuses acceptance when fresh endpoint validation fails", async () => {
    const f = fixture();
    await expect(f.resolve("accept")).rejects.toThrow("synthetic DNS unavailable");
    expect(f.validate).toHaveBeenCalledTimes(1);
    expect(f.createSecret).not.toHaveBeenCalled();
    expect(mocked.confirm).not.toHaveBeenCalled();
  });
});
