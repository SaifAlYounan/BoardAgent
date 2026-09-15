import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Aes256GcmWebhookSecurity } from "../../artifacts/server/src/webhook-security.js";
import { testId } from "../helpers/authorized-actor.js";

async function fixture() {
  const oldId = testId(199_001),
    newId = testId(199_002);
  const oldKey = randomBytes(32),
    newKey = randomBytes(32);
  const context = {
    organizationId: testId(199_003),
    memberId: testId(199_004),
    webhookId: testId(199_005)
  };
  const old = new Aes256GcmWebhookSecurity({
    activeKeyId: oldId,
    keys: new Map([[oldId, oldKey]]),
    resolve: async () => [{ address: "8.8.8.8", family: 4 }]
  });
  const endpoint = await old.protectEndpoint({
    ...context,
    endpoint: "https://notification.example/board"
  });
  const secret = old.createSecret(context);
  const current = new Aes256GcmWebhookSecurity({
    activeKeyId: newId,
    keys: new Map([
      [oldId, oldKey],
      [newId, newKey]
    ]),
    resolve: async () => {
      throw new Error("rewrap must not perform network lookup");
    }
  });
  const input = {
    ...context,
    keyId: oldId,
    endpointCiphertext: endpoint.endpointCiphertext,
    endpointSha256: endpoint.endpointSha256,
    secretCiphertext: secret.secretCiphertext,
    secretSha256: secret.secretSha256
  };
  return { old, current, input, context, oldId, newId, oldKey, newKey, endpoint, secret };
}

describe("webhook encryption-key replacement", () => {
  it("reencrypts the same endpoint and secret under a distinct key without contacting the endpoint", async () => {
    const f = await fixture();
    const beforeEndpoint = Buffer.from(f.input.endpointCiphertext),
      beforeSecret = Buffer.from(f.input.secretCiphertext);
    const changed = f.current.rewrapStoredMaterial(f.input);
    expect(Object.keys(changed).sort()).toEqual([
      "endpointCiphertext",
      "keyId",
      "secretCiphertext"
    ]);
    expect(changed.keyId).toBe(f.newId);
    expect(f.current.openEndpoint({ ...f.context, ...changed })).toBe(f.endpoint.endpoint);
    expect(f.current.openSecret({ ...f.context, ...changed })).toBe(f.secret.secret);
    expect(changed.endpointCiphertext).not.toEqual(beforeEndpoint);
    expect(changed.secretCiphertext).not.toEqual(beforeSecret);
    expect(f.input.endpointCiphertext).toEqual(beforeEndpoint);
    expect(f.input.secretCiphertext).toEqual(beforeSecret);
    expect(() => f.old.openSecret({ ...f.context, ...changed })).toThrow();
  });

  it.each([
    "organization",
    "member",
    "webhook",
    "endpoint-hash",
    "secret-hash",
    "endpoint-ciphertext",
    "secret-ciphertext"
  ] as const)("refuses changed %s binding or content", async (kind) => {
    const f = await fixture();
    const input = {
      ...f.input,
      endpointCiphertext: Buffer.from(f.input.endpointCiphertext),
      secretCiphertext: Buffer.from(f.input.secretCiphertext)
    };
    if (kind === "organization") input.organizationId = testId(199_010);
    if (kind === "member") input.memberId = testId(199_011);
    if (kind === "webhook") input.webhookId = testId(199_012);
    if (kind === "endpoint-hash") input.endpointSha256 = "f".repeat(64);
    if (kind === "secret-hash") input.secretSha256 = "f".repeat(64);
    if (kind === "endpoint-ciphertext")
      input.endpointCiphertext[input.endpointCiphertext.length - 1]! ^= 1;
    if (kind === "secret-ciphertext")
      input.secretCiphertext[input.secretCiphertext.length - 1]! ^= 1;
    expect(() => f.current.rewrapStoredMaterial(input)).toThrow();
  });

  it("refuses unchanged or renamed key bytes and missing old material", async () => {
    const f = await fixture();
    expect(() => f.old.rewrapStoredMaterial(f.input)).toThrow("distinct key material");
    const renamed = new Aes256GcmWebhookSecurity({
      activeKeyId: f.newId,
      keys: new Map([
        [f.oldId, f.oldKey],
        [f.newId, f.oldKey]
      ])
    });
    expect(() => renamed.rewrapStoredMaterial(f.input)).toThrow("distinct key material");
    const missing = new Aes256GcmWebhookSecurity({
      activeKeyId: f.newId,
      keys: new Map([[f.newId, f.newKey]])
    });
    expect(() => missing.rewrapStoredMaterial(f.input)).toThrow("key is unavailable");
  });
});
