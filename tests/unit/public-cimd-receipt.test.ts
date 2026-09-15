import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  PUBLIC_CIMD_RECEIPT_PATH,
  PUBLIC_CIMD_RECEIPT_SCHEMA_VERSION,
  verifyPublicCimdReceipt
} from "../../scripts/src/public-cimd-check.js";

const ROOT = path.resolve(import.meta.dirname, "../..");

const synthetic = {
  schemaVersion: PUBLIC_CIMD_RECEIPT_SCHEMA_VERSION,
  checkedAt: "2026-09-13T20:00:00.000000Z",
  clientIdUrl: "https://example.org/boardagent/cimd.json",
  resolverMode: "production-default",
  fetcherMode: "production-default",
  timeoutMs: 5000,
  resolvedAddresses: [{ address: "93.184.215.14", family: 4 }],
  tlsPeer: {
    servername: "example.org",
    protocol: "TLSv1.3",
    subject: "CN=example.org",
    issuer: "C=US, O=Synthetic CA, CN=Synthetic Root",
    validFrom: "Jan  1 00:00:00 2026 GMT",
    validTo: "Jan  1 00:00:00 2027 GMT",
    fingerprint256: Array.from({ length: 32 }, () => "AB").join(":"),
    authorized: true
  },
  metadata: {
    clientId: "https://example.org/boardagent/cimd.json",
    clientName: "Synthetic transport check",
    redirectUris: ["https://agent-callback.example/callback"],
    scopes: ["onboarding:read", "governance:read"],
    canonicalSha256: "c".repeat(64),
    canonicalBytes: 240
  },
  candidate: { gitCommit: "a".repeat(40), sourceTreeSha256: "b".repeat(64), worktreeClean: true },
  node: "v24.20.0"
} as const;

describe("SR-013 public CIMD transport receipt", () => {
  it("accepts a receipt that binds a public HTTPS client id, public addresses and a verified peer", () => {
    expect(verifyPublicCimdReceipt(synthetic)).toMatchObject({
      clientIdUrl: synthetic.clientIdUrl
    });
  });

  it.each([
    ["loopback address", { resolvedAddresses: [{ address: "127.0.0.1", family: 4 }] }],
    ["private address", { resolvedAddresses: [{ address: "10.1.2.3", family: 4 }] }],
    ["plain http client id", { clientIdUrl: "http://example.org/boardagent/cimd.json" }],
    ["localhost client id", { clientIdUrl: "https://localhost/cimd.json" }],
    [
      "client id drift",
      { metadata: { ...synthetic.metadata, clientId: "https://example.org/other" } }
    ],
    ["unadvertised scope", { metadata: { ...synthetic.metadata, scopes: ["admin:everything"] } }],
    ["servername drift", { tlsPeer: { ...synthetic.tlsPeer, servername: "other.example" } }],
    ["unauthorized peer", { tlsPeer: { ...synthetic.tlsPeer, authorized: false } }],
    ["injected resolver", { resolverMode: "injected" }],
    ["unknown field", { extra: true }]
  ] as const)("refuses a receipt with %s", (_label, patch) => {
    expect(() => verifyPublicCimdReceipt({ ...synthetic, ...patch })).toThrow();
  });

  it("verifies the checked-in receipt of the last real public-provider run", async () => {
    // Deliberately unconditional: an absent or invalid receipt fails this tier. The receipt
    // is produced by `tsx scripts/src/check-public-cimd.ts <url>` against a provider the
    // operator controls and copied here; no network access happens in this test.
    const bytes = await readFile(path.join(ROOT, PUBLIC_CIMD_RECEIPT_PATH), "utf8");
    const receipt = verifyPublicCimdReceipt(JSON.parse(bytes));
    expect(receipt.resolverMode).toBe("production-default");
    expect(receipt.fetcherMode).toBe("production-default");
    expect(receipt.tlsPeer.authorized).toBe(true);
  });
});
