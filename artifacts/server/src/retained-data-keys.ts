import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import type { PoolClient } from "pg";
import { z } from "zod";
import { assertSecretDirectoryReady, type BoardAgentConfig } from "@boardagent/config";
import { canonicalJsonFromText, UuidV7Schema } from "@boardagent/contracts";
import { symmetricKeyId } from "./symmetric-key-id.js";

const FilePath = z
  .string()
  .min(1)
  .max(4096)
  .refine(
    (value) => path.isAbsolute(value) && path.normalize(value) === value && !value.includes("\0")
  );
const Entry = z
  .object({
    keyId: UuidV7Schema,
    kid: z.string().regex(/^data-[0-9a-f]{24}$/u),
    fingerprintSha256: z.string().regex(/^[0-9a-f]{64}$/u),
    keyFile: FilePath
  })
  .strict();
const Manifest = z
  .object({
    schemaVersion: z.literal("boardagent.retained-data-keys.v1"),
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    keys: z.array(Entry).max(4096)
  })
  .strict()
  .superRefine((value, context) => {
    for (const field of ["keyId", "kid", "fingerprintSha256", "keyFile"] as const) {
      if (new Set(value.keys.map((entry) => entry[field])).size !== value.keys.length)
        context.addIssue({ code: "custom", message: "duplicate retained key identity or file" });
    }
  });

export interface RetainedDataKeyMaterial {
  readonly instanceId: string;
  readonly organizationId: string;
  readonly entries: readonly (z.infer<typeof Entry> & { readonly key: Buffer })[];
}

/** Open once, refuse links/FIFOs, check the opened object and bound reads before parsing. */
async function protectedBytes(file: string, maximumBytes: number): Promise<Buffer> {
  FilePath.parse(file);
  assertSecretDirectoryReady(file);
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const buffer = Buffer.alloc(maximumBytes + 1);
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
      throw new Error("unsafe retained key file");
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    const after = await handle.stat();
    if (
      total !== before.size ||
      total > maximumBytes ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      throw new Error("retained key file changed while reading");
    return Buffer.from(buffer.subarray(0, total));
  } finally {
    buffer.fill(0);
    await handle.close();
  }
}

export async function loadRetainedDataKeys(
  config: BoardAgentConfig,
  activeKey: Uint8Array
): Promise<RetainedDataKeyMaterial | undefined> {
  if (config.retainedDataKeysFile === undefined) return undefined;
  if (config.environment !== "production")
    throw new Error("retained data-key files are production-only");
  const entries: RetainedDataKeyMaterial["entries"][number][] = [];
  try {
    const rawManifest = await protectedBytes(config.retainedDataKeysFile, 1_048_576);
    let manifest: z.infer<typeof Manifest>;
    try {
      manifest = Manifest.parse(JSON.parse(canonicalJsonFromText(rawManifest)));
    } finally {
      rawManifest.fill(0);
    }
    if (manifest.organizationId !== config.organizationId)
      throw new Error("retained keys organization mismatch");
    const reserved = new Set(
      [
        config.retainedDataKeysFile,
        ...Object.values(config.keySources).filter(
          (value): value is string => typeof value === "string"
        )
      ].map((file) => path.resolve(file))
    );
    for (const entry of manifest.keys) {
      if (reserved.has(entry.keyFile)) throw new Error("retained key aliases active material");
      const raw = await protectedBytes(entry.keyFile, 44);
      let key: Buffer | undefined;
      try {
        if (raw.length === 32) key = Buffer.from(raw);
        else {
          const text = new TextDecoder("utf8", { fatal: true }).decode(raw).replace(/\n$/u, "");
          if (!/^[A-Za-z0-9_-]{43}$/u.test(text)) throw new Error("invalid retained symmetric key");
          key = Buffer.from(text, "base64url");
          if (key.length !== 32 || key.toString("base64url") !== text)
            throw new Error("noncanonical retained key");
        }
        if (
          key.equals(Buffer.from(activeKey)) ||
          entry.kid !== symmetricKeyId("data", key) ||
          entry.fingerprintSha256 !== createHash("sha256").update(key).digest("hex")
        )
          throw new Error("retained key identity mismatch");
        entries.push({ ...entry, key });
        key = undefined;
      } finally {
        key?.fill(0);
        raw.fill(0);
      }
    }
    return { instanceId: manifest.instanceId, organizationId: manifest.organizationId, entries };
  } catch {
    for (const entry of entries) entry.key.fill(0);
    // Never include parser excerpts, private bytes or secret-file errors in diagnostics.
    throw new Error("retained data-key manifest or protected key file is invalid");
  }
}

/** Historical retirement permits decryption; compromise never grants ordinary runtime use. */
export async function assertRetainedDataKeyBinding(
  client: PoolClient,
  input: {
    readonly instanceId: string;
    readonly organizationId: string;
    readonly activeKeyId: string;
  },
  retained: RetainedDataKeyMaterial | undefined
): Promise<void> {
  if (retained === undefined) return;
  if (
    retained.instanceId !== input.instanceId ||
    retained.organizationId !== input.organizationId ||
    retained.entries.some((entry) => entry.keyId === input.activeKeyId)
  )
    throw new Error("retained data keys do not match this runtime installation");
  const result = await client.query<{ id: string; kid: string }>(
    `select id,kid from crypto_key_registry
      where organization_id=$1 and id=any($2::uuid[]) and purpose='data_kek'
        and algorithm='A256GCM' and public_jwk is null
        and activated_at<=transaction_timestamp() and retired_at<=transaction_timestamp()
        and compromised_at is null`,
    [input.organizationId, retained.entries.map((entry) => entry.keyId)]
  );
  const actual = new Map(result.rows.map((row) => [row.id, row.kid]));
  if (
    actual.size !== retained.entries.length ||
    retained.entries.some((entry) => actual.get(entry.keyId) !== entry.kid)
  )
    throw new Error(
      "retained data key is missing, invalid, active or compromised in this registry"
    );
}

export function dataDecryptionKeyring(
  activeKeyId: string,
  activeKey: Uint8Array,
  retained: RetainedDataKeyMaterial | undefined
): ReadonlyMap<string, Uint8Array> {
  const result = new Map<string, Uint8Array>([[activeKeyId, activeKey]]);
  for (const entry of retained?.entries ?? []) {
    if (result.has(entry.keyId)) throw new Error("duplicate runtime data key");
    result.set(entry.keyId, entry.key);
  }
  return result;
}
