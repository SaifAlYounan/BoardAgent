import {
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  type JsonWebKey,
  type KeyObject
} from "node:crypto";
import { lstat, readFile } from "node:fs/promises";

import { importJWK, type JWK } from "jose";
import { z } from "zod";

import { assertSecretDirectoryReady, type BoardAgentConfig } from "@boardagent/config";
import { canonicalJson } from "@boardagent/contracts";
import { symmetricKeyId as symmetricKid } from "./symmetric-key-id.js";
import { loadRetainedDataKeys, type RetainedDataKeyMaterial } from "./retained-data-keys.js";

const P256CoordinateSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/u)
  .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value);

const Es256PrivateJwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: P256CoordinateSchema,
    y: P256CoordinateSchema,
    d: P256CoordinateSchema,
    kid: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u),
    use: z.literal("sig"),
    alg: z.literal("ES256")
  })
  .passthrough();

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface BoardAgentKeyMaterial {
  readonly oauthPrivateJwk: Readonly<Record<string, unknown>>;
  readonly oauthPublicJwk: Readonly<Record<string, unknown>>;
  readonly oauthPublicKey: CryptoKey;
  readonly oauthKid: string;
  readonly evidencePrivateKey: KeyObject;
  readonly evidencePublicJwk: Readonly<Record<string, unknown>>;
  readonly evidenceKid: string;
  readonly browserSessionKid: string;
  readonly dataEncryptionKid: string;
  readonly browserSessionKey: Uint8Array;
  readonly dataEncryptionKey: Uint8Array;
  readonly retainedDataKeys?: RetainedDataKeyMaterial;
}

/** Background work cannot possess OAuth or browser-session signing authority. */
export type BoardAgentWorkerKeyMaterial = Pick<
  BoardAgentKeyMaterial,
  | "evidencePrivateKey"
  | "evidencePublicJwk"
  | "evidenceKid"
  | "dataEncryptionKid"
  | "dataEncryptionKey"
  | "retainedDataKeys"
>;

function bytes(value: Uint8Array | string, label: string): Buffer {
  if (typeof value === "string") throw new Error(`${label} must be loaded from its secret file`);
  const result = Buffer.from(value);
  if (result.length !== 32) throw new Error(`${label} must contain exactly 32 bytes`);
  return result;
}

function kid(prefix: "oauth" | "evidence", publicJwk: Readonly<Record<string, unknown>>): string {
  return `${prefix}-${createHash("sha256")
    .update(canonicalJson(publicJwk as never), "utf8")
    .digest("hex")
    .slice(0, 24)}`;
}

function deterministicP256(seed: Uint8Array): Readonly<Record<string, unknown>> {
  const ecdh = createECDH("prime256v1");
  let scalar: Buffer | undefined;
  for (let counter = 0; counter <= 255; counter += 1) {
    const candidate = createHash("sha256")
      .update("boardagent/dev/es256/v1\0", "utf8")
      .update(seed)
      .update(Buffer.from([counter]))
      .digest();
    try {
      ecdh.setPrivateKey(candidate);
      scalar = candidate;
      break;
    } catch {
      candidate.fill(0);
    }
  }
  if (!scalar) throw new Error("could not derive a valid local ES256 scalar");
  try {
    const publicPoint = ecdh.getPublicKey(undefined, "uncompressed");
    if (publicPoint.length !== 65 || publicPoint[0] !== 4) {
      throw new Error("local ES256 public key derivation failed");
    }
    const publicJwk = {
      kty: "EC",
      crv: "P-256",
      x: publicPoint.subarray(1, 33).toString("base64url"),
      y: publicPoint.subarray(33, 65).toString("base64url"),
      use: "sig",
      alg: "ES256"
    } as const;
    return { ...publicJwk, d: scalar.toString("base64url"), kid: kid("oauth", publicJwk) };
  } finally {
    scalar.fill(0);
  }
}

function deterministicEd25519(seedValue: Uint8Array): {
  readonly privateKey: KeyObject;
  readonly publicJwk: Readonly<Record<string, unknown>>;
  readonly kid: string;
} {
  const seed = createHash("sha256")
    .update("boardagent/dev/ed25519/v1\0", "utf8")
    .update(seedValue)
    .digest();
  try {
    const privateKey = createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
      format: "der",
      type: "pkcs8"
    });
    const exported = createPublicKey(privateKey).export({ format: "jwk" }) as JsonWebKey;
    const publicJwk = { kty: exported.kty, crv: exported.crv, x: exported.x };
    return { privateKey, publicJwk, kid: kid("evidence", publicJwk) };
  } finally {
    seed.fill(0);
  }
}

async function secretFile(path: string, label: string): Promise<Buffer> {
  assertSecretDirectoryReady(path);
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} is not a regular file`);
  if ((stat.mode & 0o007) !== 0) throw new Error(`${label} must not be accessible to other users`);
  const value = await readFile(path);
  if (value.length === 0 || value.length > 65_536) throw new Error(`${label} has invalid length`);
  return value;
}

async function symmetricSecretFile(path: string, label: string): Promise<Buffer> {
  const raw = await secretFile(path, label);
  if (raw.length === 32) return raw;
  const text = raw.toString("utf8").trimEnd();
  const decoded = Buffer.from(text, "base64url");
  if (
    !/^[A-Za-z0-9_-]{43}$/u.test(text) ||
    decoded.length !== 32 ||
    decoded.toString("base64url") !== text
  ) {
    raw.fill(0);
    throw new Error(`${label} must be 32 raw bytes or canonical base64url`);
  }
  raw.fill(0);
  return decoded;
}

function publicEs256(
  privateJwk: Readonly<Record<string, unknown>>
): Readonly<Record<string, unknown>> {
  return {
    kty: privateJwk["kty"],
    crv: privateJwk["crv"],
    x: privateJwk["x"],
    y: privateJwk["y"],
    kid: privateJwk["kid"],
    use: privateJwk["use"],
    alg: privateJwk["alg"]
  };
}

function assertPrivateEs256Binding(jwk: z.infer<typeof Es256PrivateJwkSchema>): void {
  const scalar = Buffer.from(jwk.d, "base64url");
  try {
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(scalar);
    const point = ecdh.getPublicKey(undefined, "uncompressed");
    if (
      point.length !== 65 ||
      point[0] !== 4 ||
      point.subarray(1, 33).toString("base64url") !== jwk.x ||
      point.subarray(33, 65).toString("base64url") !== jwk.y
    ) {
      throw new Error("OAuth public coordinates do not match its private scalar");
    }
  } finally {
    scalar.fill(0);
  }
}

async function productionKeys(config: BoardAgentConfig): Promise<BoardAgentKeyMaterial> {
  if (
    typeof config.keySources.oauth !== "string" ||
    typeof config.keySources.evidence !== "string" ||
    typeof config.keySources.browserSession !== "string" ||
    typeof config.keySources.dataEncryption !== "string"
  ) {
    throw new Error("production key sources must be file paths");
  }
  const oauthBytes = await secretFile(config.keySources.oauth, "OAuth signing key");
  let oauthPrivateJwk: z.infer<typeof Es256PrivateJwkSchema>;
  try {
    oauthPrivateJwk = Es256PrivateJwkSchema.parse(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(oauthBytes)) as unknown
    );
    assertPrivateEs256Binding(oauthPrivateJwk);
  } finally {
    oauthBytes.fill(0);
  }
  const oauthPublicJwk = publicEs256(oauthPrivateJwk);
  const imported = await importJWK(oauthPublicJwk as JWK, "ES256");
  if (!(imported instanceof CryptoKey))
    throw new Error("OAuth public key did not import as WebCrypto");

  const workerKeys = await productionWorkerKeys(config);
  const browserSessionKey = await symmetricSecretFile(
    config.keySources.browserSession,
    "browser session key"
  );
  return {
    ...workerKeys,
    oauthPrivateJwk,
    oauthPublicJwk,
    oauthPublicKey: imported,
    oauthKid: oauthPrivateJwk.kid,
    browserSessionKid: symmetricKid("browser", browserSessionKey),
    browserSessionKey
  };
}

async function productionWorkerKeys(
  config: BoardAgentConfig
): Promise<BoardAgentWorkerKeyMaterial> {
  if (
    typeof config.keySources.evidence !== "string" ||
    typeof config.keySources.dataEncryption !== "string"
  ) {
    throw new Error("production worker key sources must be file paths");
  }
  const evidenceBytes = await secretFile(config.keySources.evidence, "evidence signing key");
  let evidencePrivateKey: KeyObject;
  try {
    evidencePrivateKey = createPrivateKey(evidenceBytes);
  } finally {
    evidenceBytes.fill(0);
  }
  if (evidencePrivateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("evidence signing key must be Ed25519 PKCS8 PEM");
  }
  const exported = createPublicKey(evidencePrivateKey).export({ format: "jwk" }) as JsonWebKey;
  const evidencePublicJwk = { kty: exported.kty, crv: exported.crv, x: exported.x };
  const dataEncryptionKey = await symmetricSecretFile(config.keySources.dataEncryption, "data KEK");
  const retainedDataKeys = await loadRetainedDataKeys(config, dataEncryptionKey).catch(
    (error: unknown) => {
      dataEncryptionKey.fill(0);
      throw error;
    }
  );
  return {
    evidencePrivateKey,
    evidencePublicJwk,
    evidenceKid: kid("evidence", evidencePublicJwk),
    dataEncryptionKid: symmetricKid("data", dataEncryptionKey),
    dataEncryptionKey,
    ...(retainedDataKeys === undefined ? {} : { retainedDataKeys })
  };
}

async function developmentKeys(config: BoardAgentConfig): Promise<BoardAgentKeyMaterial> {
  const oauthSeed = bytes(config.keySources.oauth, "development OAuth seed");
  const evidenceSeed = bytes(config.keySources.evidence, "development evidence seed");
  const oauthPrivateJwk = Es256PrivateJwkSchema.parse(deterministicP256(oauthSeed));
  const oauthPublicJwk = publicEs256(oauthPrivateJwk);
  const imported = await importJWK(oauthPublicJwk as JWK, "ES256");
  if (!(imported instanceof CryptoKey))
    throw new Error("OAuth public key did not import as WebCrypto");
  const evidence = deterministicEd25519(evidenceSeed);
  const browserSessionKey = bytes(
    config.keySources.browserSession,
    "development browser-session key"
  );
  const dataEncryptionKey = bytes(config.keySources.dataEncryption, "development data KEK");
  oauthSeed.fill(0);
  evidenceSeed.fill(0);
  return {
    oauthPrivateJwk,
    oauthPublicJwk,
    oauthPublicKey: imported,
    oauthKid: oauthPrivateJwk.kid,
    evidencePrivateKey: evidence.privateKey,
    evidencePublicJwk: evidence.publicJwk,
    evidenceKid: evidence.kid,
    browserSessionKid: symmetricKid("browser", browserSessionKey),
    dataEncryptionKid: symmetricKid("data", dataEncryptionKey),
    browserSessionKey,
    dataEncryptionKey
  };
}

export async function loadBoardAgentKeyMaterial(
  config: BoardAgentConfig
): Promise<BoardAgentKeyMaterial> {
  return config.environment === "production" ? productionKeys(config) : developmentKeys(config);
}

export async function loadBoardAgentWorkerKeyMaterial(
  config: BoardAgentConfig
): Promise<BoardAgentWorkerKeyMaterial> {
  if (config.environment === "production") return productionWorkerKeys(config);
  const keys = await developmentKeys(config);
  return {
    evidencePrivateKey: keys.evidencePrivateKey,
    evidencePublicJwk: keys.evidencePublicJwk,
    evidenceKid: keys.evidenceKid,
    dataEncryptionKid: keys.dataEncryptionKid,
    dataEncryptionKey: keys.dataEncryptionKey
  };
}
