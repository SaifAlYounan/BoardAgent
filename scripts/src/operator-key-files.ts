import {
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes
} from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, open, unlink } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { assertSecretDirectoryReady } from "@boardagent/config";
import { canonicalJson, canonicalJsonFromText, canonicalSha256 } from "@boardagent/contracts";
import {
  keyLifecyclePublicMaterialSha256,
  type KeyLifecyclePurposeSchema
} from "@boardagent/audit";

type Purpose = z.infer<typeof KeyLifecyclePurposeSchema>;
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
export const OperatorFilePathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine(
    (file) =>
      path.isAbsolute(file) &&
      path.normalize(file) === file &&
      file !== "/" &&
      Array.from(file).every((c) => c.codePointAt(0)! >= 32 && c.codePointAt(0) !== 127)
  );

/** Physical paths only. Root-owned sticky temporary directories are safe ancestors of an owned child. */
export async function assertOperatorFileParents(file: string): Promise<void> {
  OperatorFilePathSchema.parse(file);
  let current = path.dirname(file);
  for (;;) {
    const stat = await lstat(current);
    const trustedOwner = stat.uid === 0 || stat.uid === process.getuid?.();
    const stickyRoot = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      !trustedOwner ||
      ((stat.mode & 0o022) !== 0 && !stickyRoot)
    )
      throw new Error("unsafe operator file directory");
    if (current === path.dirname(current)) break;
    current = path.dirname(current);
  }
}

/** Single opened inode, bounded read, no links or writable/untrusted path components. */
export async function readOperatorProtectedFile(
  file: string,
  maximumBytes: number
): Promise<Buffer> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 16_777_216)
    throw new Error("invalid private read bound");
  await assertOperatorFileParents(file);
  assertSecretDirectoryReady(file);
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const bytes = Buffer.alloc(maximumBytes + 1);
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      (before.mode & 0o137) !== 0 ||
      (before.uid !== 0 && before.uid !== process.getuid?.()) ||
      before.size < 1 ||
      before.size > maximumBytes
    )
      throw new Error("unsafe operator private file");
    let length = 0;
    while (length < bytes.length) {
      const read = await handle.read(bytes, length, bytes.length - length, length);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    const after = await handle.stat();
    if (
      length !== before.size ||
      length > maximumBytes ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      throw new Error("operator private file changed while reading");
    await assertOperatorFileParents(file);
    return Buffer.from(bytes.subarray(0, length));
  } finally {
    bytes.fill(0);
    await handle.close();
  }
}

/** Publish new versioned material exclusively; failure never replaces an earlier file. */
export async function publishOperatorKeyFile(file: string, bytes: Uint8Array): Promise<void> {
  if (bytes.byteLength < 1 || bytes.byteLength > 65_536) throw new Error("invalid key file size");
  await assertOperatorFileParents(file);
  assertSecretDirectoryReady(file);
  const parent = await open(
    path.dirname(file),
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
  );
  const temporary = `${file}.partial-${process.pid}-${randomBytes(8).toString("hex")}`;
  let created = false;
  try {
    const handle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600
    );
    created = true;
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await assertOperatorFileParents(file);
    await link(temporary, file);
    await parent.sync();
  } finally {
    try {
      if (created) {
        await unlink(temporary);
        await parent.sync();
      }
    } finally {
      await parent.close();
    }
  }
}

const Coordinate = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/u)
  .refine((v) => Buffer.from(v, "base64url").toString("base64url") === v);
const OAuthPrivate = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: Coordinate,
    y: Coordinate,
    d: Coordinate,
    kid: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u),
    use: z.literal("sig"),
    alg: z.literal("ES256")
  })
  .strict();
export interface OperatorKeyProjection {
  readonly purpose: Purpose;
  readonly algorithm: "ES256" | "EdDSA" | "HMAC-SHA256" | "A256GCM";
  readonly kid: string | null;
  readonly materialSha256: string;
  readonly fileSha256: string;
  readonly publicJwk:
    | { kty: "EC"; crv: "P-256"; x: string; y: string; kid: string; use: "sig"; alg: "ES256" }
    | { kty: "OKP"; crv: "Ed25519"; x: string }
    | null;
}
export interface OperatorKeyMaterial extends OperatorKeyProjection {
  /** Fresh copy for the bounded crypto operation. Caller must erase its copy. */
  symmetricBytes(): Buffer;
  destroy(): void;
}

export async function loadOperatorKeyMaterial(
  purpose: Purpose,
  file: string
): Promise<OperatorKeyMaterial> {
  const raw = await readOperatorProtectedFile(file, 65_536);
  let symmetric: Buffer | undefined;
  let projection: OperatorKeyProjection;
  try {
    const fileSha256 = sha(raw);
    if (purpose === "oauth_signing") {
      const jwk = OAuthPrivate.parse(JSON.parse(canonicalJsonFromText(raw)));
      const scalar = Buffer.from(jwk.d, "base64url");
      try {
        const ecdh = createECDH("prime256v1");
        ecdh.setPrivateKey(scalar);
        const point = ecdh.getPublicKey(undefined, "uncompressed");
        if (
          point.subarray(1, 33).toString("base64url") !== jwk.x ||
          point.subarray(33).toString("base64url") !== jwk.y
        )
          throw new Error("OAuth private and public material differ");
      } finally {
        scalar.fill(0);
      }
      const { d: _d, ...publicJwk } = jwk;
      projection = {
        purpose,
        algorithm: "ES256",
        kid: jwk.kid,
        publicJwk,
        materialSha256: keyLifecyclePublicMaterialSha256(publicJwk),
        fileSha256
      };
    } else if (purpose === "evidence_signing") {
      const privateKey = createPrivateKey(raw);
      if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519")
        throw new Error("invalid evidence private key");
      const exported = createPublicKey(privateKey).export({ format: "jwk" });
      const publicJwk = {
        kty: "OKP" as const,
        crv: "Ed25519" as const,
        x: Coordinate.parse(exported.x)
      };
      const materialSha256 = keyLifecyclePublicMaterialSha256(publicJwk);
      projection = {
        purpose,
        algorithm: "EdDSA",
        kid: `evidence-${materialSha256.slice(0, 24)}`,
        publicJwk,
        materialSha256,
        fileSha256
      };
    } else {
      if (raw.length === 32) symmetric = Buffer.from(raw);
      else {
        const text = new TextDecoder("utf8", { fatal: true }).decode(raw).replace(/\n$/u, "");
        Coordinate.parse(text);
        symmetric = Buffer.from(text, "base64url");
      }
      const prefix = purpose === "browser_session" ? "browser" : "data";
      projection = {
        purpose,
        algorithm: purpose === "browser_session" ? "HMAC-SHA256" : "A256GCM",
        kid:
          purpose === "backup_kek"
            ? null
            : `${prefix}-${createHash("sha256").update(`boardagent/${prefix}/key-id/v1\0`).update(symmetric).digest("hex").slice(0, 24)}`,
        publicJwk: null,
        materialSha256: sha(symmetric),
        fileSha256
      };
    }
    return {
      ...projection,
      symmetricBytes: () => {
        if (!symmetric) throw new Error("symmetric material unavailable");
        return Buffer.from(symmetric);
      },
      destroy: () => {
        symmetric?.fill(0);
        symmetric = undefined;
      }
    };
  } catch (error) {
    symmetric?.fill(0);
    throw error;
  } finally {
    raw.fill(0);
  }
}

export async function assertDistinctOperatorKeyMaterial(
  materials: readonly OperatorKeyProjection[]
): Promise<void> {
  if (new Set(materials.map((m) => m.materialSha256)).size !== materials.length)
    throw new Error("private material reused across key identities");
}

export async function generateOperatorKeyFile(
  purpose: Purpose,
  file: string
): Promise<OperatorKeyProjection> {
  let bytes: Buffer;
  if (purpose === "oauth_signing") {
    const jwk = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
      format: "jwk"
    });
    const publicJwk = { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y!, use: "sig", alg: "ES256" };
    bytes = Buffer.from(
      `${canonicalJson({ ...publicJwk, d: jwk.d!, kid: `oauth-${canonicalSha256(publicJwk).slice(0, 24)}` })}\n`
    );
  } else if (purpose === "evidence_signing")
    bytes = Buffer.from(
      generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" })
    );
  else bytes = randomBytes(32);
  try {
    await publishOperatorKeyFile(file, bytes);
  } finally {
    bytes.fill(0);
  }
  const material = await loadOperatorKeyMaterial(purpose, file);
  try {
    const { destroy: _destroy, symmetricBytes: _symmetricBytes, ...projection } = material;
    return projection;
  } finally {
    material.destroy();
  }
}
