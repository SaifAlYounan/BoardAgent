import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { connect as tlsConnect, type PeerCertificate } from "node:tls";

import { z } from "zod";

import {
  BOARDAGENT_OAUTH_SCOPES,
  defaultCimdHostResolver,
  isPublicCimdAddress,
  resolveCimdClientMetadata,
  validateCimdClientId
} from "@boardagent/server";

/**
 * SR-013 public-provider transport evidence.
 *
 * The controlled unit and integration tests prove the CIMD fetch's deadline, size,
 * DNS-pinning and TLS-verification behaviour against local fixtures. They cannot prove the
 * ordinary public path: real DNS, real TLS trust and port 443 to a provider the operator
 * controls. This module runs that one bounded request with the PRODUCTION resolver and
 * fetcher (no injected seams, system trust store) and writes a receipt that binds the
 * request, the resolved addresses, the observed TLS peer and the accepted metadata to the
 * candidate. A separate deterministic test verifies the checked-in receipt without any
 * network access, so the tiers stay offline and nothing is skipped.
 *
 * A provider outage, refusal or timeout is a failed run, never a pass.
 */

export const PUBLIC_CIMD_RECEIPT_SCHEMA_VERSION = "boardagent.public-cimd-transport-receipt.v1";
export const PUBLIC_CIMD_RECEIPT_PATH = "docs/evidence/public-cimd-transport-receipt.json";

const Sha256Hex = z.string().regex(/^[0-9a-f]{64}$/u);
const Rfc3339 = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/u)
  .refine((value) => !Number.isNaN(Date.parse(value)), "timestamp must parse");

export const PublicCimdReceiptSchema = z
  .object({
    schemaVersion: z.literal(PUBLIC_CIMD_RECEIPT_SCHEMA_VERSION),
    checkedAt: Rfc3339,
    clientIdUrl: z.string().min(1).max(2048),
    resolverMode: z.literal("production-default"),
    fetcherMode: z.literal("production-default"),
    timeoutMs: z.number().int().min(100).max(30_000),
    resolvedAddresses: z
      .array(
        z
          .object({
            address: z.string().min(1).max(64),
            family: z.union([z.literal(4), z.literal(6)])
          })
          .strict()
      )
      .min(1)
      .max(16),
    tlsPeer: z
      .object({
        servername: z.string().min(1).max(253),
        protocol: z.string().min(1).max(32),
        subject: z.string().min(1).max(2048),
        issuer: z.string().min(1).max(2048),
        validFrom: z.string().min(1).max(64),
        validTo: z.string().min(1).max(64),
        fingerprint256: z.string().regex(/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/u),
        authorized: z.literal(true)
      })
      .strict(),
    metadata: z
      .object({
        clientId: z.string().min(1).max(2048),
        clientName: z.string().min(1).max(120),
        redirectUris: z.array(z.string().min(1).max(2048)).min(1).max(10),
        scopes: z.array(z.string().min(1).max(128)).min(1).max(128),
        canonicalSha256: Sha256Hex,
        canonicalBytes: z
          .number()
          .int()
          .min(1)
          .max(32 * 1024)
      })
      .strict(),
    candidate: z
      .object({
        gitCommit: z.string().regex(/^[0-9a-f]{40}$/u),
        sourceTreeSha256: Sha256Hex,
        worktreeClean: z.boolean()
      })
      .strict(),
    node: z.string().min(1).max(32)
  })
  .strict();

export type PublicCimdReceipt = z.infer<typeof PublicCimdReceiptSchema>;

/**
 * Deterministic verification of a receipt: schema, a canonical public HTTPS client id,
 * only public resolved addresses, the metadata's client id equal to the requested URL,
 * scopes inside the server's advertised set, and a verified TLS peer.
 */
export function verifyPublicCimdReceipt(value: unknown): PublicCimdReceipt {
  const receipt = PublicCimdReceiptSchema.parse(value);
  validateCimdClientId(receipt.clientIdUrl);
  if (receipt.metadata.clientId !== receipt.clientIdUrl) {
    throw new Error("public CIMD receipt metadata client id differs from the requested URL");
  }
  for (const entry of receipt.resolvedAddresses) {
    if (!isPublicCimdAddress(entry.address)) {
      throw new Error(`public CIMD receipt resolved a non-public address: ${entry.address}`);
    }
  }
  const allowed = new Set<string>(BOARDAGENT_OAUTH_SCOPES);
  for (const scope of receipt.metadata.scopes) {
    if (!allowed.has(scope))
      throw new Error(`public CIMD receipt scope is not advertised: ${scope}`);
  }
  if (receipt.tlsPeer.servername !== new URL(receipt.clientIdUrl).hostname) {
    throw new Error("public CIMD receipt TLS servername differs from the client id host");
  }
  return receipt;
}

function certificateName(name: PeerCertificate["subject"]): string {
  return Object.entries(name)
    .map(([key, entry]) => `${key}=${Array.isArray(entry) ? entry.join("+") : String(entry)}`)
    .join(", ");
}

/** One bounded TLS handshake to record the peer the system trust store accepted. */
async function observeTlsPeer(
  hostname: string,
  timeoutMs: number
): Promise<PublicCimdReceipt["tlsPeer"]> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: true
    });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("TLS observation timed out"));
    }, timeoutMs);
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      const certificate = socket.getPeerCertificate(false);
      const authorized = socket.authorized;
      const protocol = socket.getProtocol() ?? "unknown";
      socket.end();
      if (!authorized || !certificate.fingerprint256) {
        reject(new Error("TLS peer was not authorized by the system trust store"));
        return;
      }
      resolve({
        servername: hostname,
        protocol,
        subject: certificateName(certificate.subject),
        issuer: certificateName(certificate.issuer),
        validFrom: certificate.valid_from,
        validTo: certificate.valid_to,
        fingerprint256: certificate.fingerprint256,
        authorized: true
      });
    });
  });
}

export interface PublicCimdCheckCandidate {
  readonly gitCommit: string;
  readonly sourceTreeSha256: string;
  readonly worktreeClean: boolean;
}

/**
 * Run the live check with the production resolver and fetcher, then write the receipt
 * under `artifacts/verification/public-cimd/<timestamp>/receipt.json` (ignored evidence).
 * The caller copies the receipt to `docs/evidence/` for the deterministic tier test.
 */
export async function runPublicCimdCheck(
  root: string,
  clientIdUrl: string,
  candidate: PublicCimdCheckCandidate,
  options: { readonly timeoutMs?: number; readonly now?: () => Date } = {}
): Promise<{ readonly receipt: PublicCimdReceipt; readonly receiptPath: string }> {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const hostname = new URL(validateCimdClientId(clientIdUrl)).hostname;
  const resolvedAddresses = await defaultCimdHostResolver(hostname);
  // Production seams only: no injected resolver, no injected fetcher, system trust store.
  const metadata = await resolveCimdClientMetadata(clientIdUrl, BOARDAGENT_OAUTH_SCOPES, {
    timeoutMs
  });
  const tlsPeer = await observeTlsPeer(hostname, timeoutMs);
  const checkedAt = (options.now ?? (() => new Date()))().toISOString();
  const receipt = verifyPublicCimdReceipt({
    schemaVersion: PUBLIC_CIMD_RECEIPT_SCHEMA_VERSION,
    checkedAt,
    clientIdUrl,
    resolverMode: "production-default",
    fetcherMode: "production-default",
    timeoutMs,
    resolvedAddresses: resolvedAddresses.map((entry) => ({
      address: entry.address,
      family: entry.family
    })),
    tlsPeer,
    metadata: {
      clientId: metadata.clientId,
      clientName: metadata.clientName,
      redirectUris: [...metadata.redirectUris],
      scopes: [...metadata.scopes],
      canonicalSha256: createHash("sha256")
        .update(metadata.canonicalMetadata, "utf8")
        .digest("hex"),
      canonicalBytes: Buffer.byteLength(metadata.canonicalMetadata, "utf8")
    },
    candidate,
    node: process.version
  });
  const stamp = checkedAt.replace(/[-:]/gu, "").replace(/\.\d+Z$/u, "Z");
  const directory = path.join(root, "artifacts", "verification", "public-cimd", stamp);
  await mkdir(directory, { recursive: true });
  const receiptPath = path.join(directory, "receipt.json");
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx" });
  return { receipt, receiptPath };
}
