import { createCipheriv, createDecipheriv, randomBytes as nodeRandomBytes } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  open as openFile,
  readFile,
  readdir,
  realpath,
  rmdir,
  unlink
} from "node:fs/promises";
import path from "node:path";
import {
  SignedAuditExportAttestationSchema,
  type SignedAuditExportAttestation
} from "@boardagent/audit";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  sha256Hex
} from "@boardagent/contracts";
import {
  ExportArtifactManifestSchema,
  ExportScopeSchema,
  ExportSnapshotManifestSchema,
  type ExportArtifactManifest,
  type ExportScope,
  type FrozenExportSnapshot
} from "@boardagent/db";
import { z } from "zod";

import type { ExportChunkReader } from "./surface-read.js";

const MAGIC = Buffer.from("BOARDAGENT-EXPORT-AES256GCM-V1\n", "ascii");
const TAG_BYTES = 16;
const NONCE_BYTES = 12;
const MAX_HEADER_BYTES = 16_384;
const MANIFEST_FILE = "manifest.json";
const ARTIFACT_FILE_PATTERN = /^(?:\d+\.bin|\d+\.bin\.tmp-[0-9a-f]{32})$/u;

const ExportEncryptionHeaderSchema = z
  .object({
    schemaVersion: z.literal("boardagent.export-encryption.v1"),
    algorithm: z.literal("A256GCM"),
    artifactId: UuidV7Schema,
    exportRequestId: UuidV7Schema,
    organizationId: UuidV7Schema,
    snapshotSha256: Sha256HexSchema,
    encryptionKeyId: UuidV7Schema,
    nonce: z.string().regex(/^[A-Za-z0-9_-]{16}$/u)
  })
  .strict();

const LegacyExportPackageSchema = z
  .object({
    schemaVersion: z.literal("boardagent.export-package.v1"),
    scope: ExportScopeSchema,
    snapshot: ExportSnapshotManifestSchema,
    components: z
      .array(
        z
          .object({
            name: z.string().regex(/^[a-z][a-z0-9_:-]{1,127}$/u),
            rowCount: z.string().regex(/^(?:0|[1-9]\d*)$/u),
            sha256: Sha256HexSchema,
            encoding: z.literal("base64url"),
            bytes: z.string().regex(/^[A-Za-z0-9_-]+$/u)
          })
          .strict()
      )
      .min(1)
      .max(256)
  })
  .strict();

// A distinct version makes older verifiers refuse, rather than ignore, the proof.
const ExportPackageSchema = z.discriminatedUnion("schemaVersion", [
  LegacyExportPackageSchema,
  LegacyExportPackageSchema.extend({
    schemaVersion: z.literal("boardagent.export-package.v2"),
    auditAttestation: SignedAuditExportAttestationSchema
  }).refine((value) => value.scope.exportType === "audit_chain")
]);

export interface LocalExportArtifactStoreOptions {
  readonly maximumArtifactBytes: number;
  readonly chunkBytes: number;
}

export interface PublishEncryptedExportInput {
  readonly frozen: FrozenExportSnapshot;
  readonly artifactId: string;
  readonly encryptionKeyId: string;
  readonly encryptionKey: Uint8Array;
  readonly newChunkId: () => string;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly signal?: AbortSignal;
  readonly auditAttestation?: SignedAuditExportAttestation;
}

export interface DecryptedExportPackage {
  readonly header: z.infer<typeof ExportEncryptionHeaderSchema>;
  readonly scope: ExportScope;
  readonly snapshot: z.infer<typeof ExportSnapshotManifestSchema>;
  readonly auditAttestation?: SignedAuditExportAttestation;
  readonly components: readonly {
    readonly name: string;
    readonly rowCount: string;
    readonly sha256: string;
    readonly bytes: Buffer;
  }[];
}

export interface CommittedExportArtifactInventoryEntry {
  readonly state: "committed";
  readonly exportRequestId: string;
  readonly artifactId: string;
  readonly manifest: ExportArtifactManifest;
  readonly manifestSha256: string;
  readonly modifiedAt: string;
}

export interface PartialExportArtifactInventoryEntry {
  readonly state: "partial";
  readonly exportRequestId: string;
  readonly artifactId: string;
  readonly fingerprint: string;
  readonly modifiedAt: string;
}

export type ExportArtifactInventoryEntry =
  CommittedExportArtifactInventoryEntry | PartialExportArtifactInventoryEntry;

function boundedInteger(value: number, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(
      `${label} must be an integer from ${String(minimum)} through ${String(maximum)}`
    );
  }
  return value;
}

function exactKey(value: Uint8Array): Buffer {
  const key = Buffer.from(value);
  if (key.length !== 32) throw new RangeError("export encryption key must contain 32 bytes");
  return key;
}

function assertNotAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new Error("export artifact publication was interrupted");
}

function locator(exportRequestId: string, artifactId: string, ordinal?: number): string {
  const root = `boardagent-export:v1/${exportRequestId}/${artifactId}`;
  return ordinal === undefined ? root : `${root}/${String(ordinal)}`;
}

function encodeEnvelope(input: PublishEncryptedExportInput): Buffer {
  if (input.frozen.scope.exportType === "audit_chain" && input.auditAttestation === undefined) {
    throw new Error("audit export attestation is required");
  }
  const artifactId = UuidV7Schema.parse(input.artifactId);
  const encryptionKeyId = UuidV7Schema.parse(input.encryptionKeyId);
  const exportRequestId = UuidV7Schema.parse(input.frozen.exportRequestId);
  const key = exactKey(input.encryptionKey);
  const randomBytes = input.randomBytes ?? nodeRandomBytes;
  const nonce = Buffer.from(randomBytes(NONCE_BYTES));
  if (nonce.length !== NONCE_BYTES) {
    key.fill(0);
    throw new Error("export nonce source returned the wrong length");
  }
  const header = ExportEncryptionHeaderSchema.parse({
    schemaVersion: "boardagent.export-encryption.v1",
    algorithm: "A256GCM",
    artifactId,
    exportRequestId,
    organizationId: input.frozen.snapshot.organizationId,
    snapshotSha256: input.frozen.snapshotSha256,
    encryptionKeyId,
    nonce: nonce.toString("base64url")
  });
  const headerBytes = Buffer.from(canonicalJson(header), "utf8");
  const packageBytes = Buffer.from(
    canonicalJson({
      schemaVersion:
        input.auditAttestation === undefined
          ? "boardagent.export-package.v1"
          : "boardagent.export-package.v2",
      ...(input.auditAttestation === undefined
        ? {}
        : { auditAttestation: SignedAuditExportAttestationSchema.parse(input.auditAttestation) }),
      scope: input.frozen.scope,
      snapshot: input.frozen.snapshot,
      components: input.frozen.components.map((component) => {
        if (sha256Hex(component.bytes) !== component.sha256) {
          throw new Error(`export component ${component.name} failed its frozen hash`);
        }
        return {
          name: component.name,
          rowCount: component.rowCount,
          sha256: component.sha256,
          encoding: "base64url",
          bytes: component.bytes.toString("base64url")
        };
      })
    }),
    "utf8"
  );
  try {
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(headerBytes, { plaintextLength: packageBytes.length });
    const ciphertext = Buffer.concat([cipher.update(packageBytes), cipher.final()]);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(headerBytes.length);
    return Buffer.concat([MAGIC, length, headerBytes, ciphertext, cipher.getAuthTag()]);
  } finally {
    key.fill(0);
    nonce.fill(0);
    packageBytes.fill(0);
  }
}

/** Authenticates, decrypts and re-verifies every frozen component descriptor. */
export function decryptExportEnvelope(
  encrypted: Uint8Array,
  encryptionKey: Uint8Array
): DecryptedExportPackage {
  const bytes = Buffer.from(encrypted);
  if (
    bytes.length < MAGIC.length + 4 + 2 + TAG_BYTES ||
    !bytes.subarray(0, MAGIC.length).equals(MAGIC)
  ) {
    throw new Error("encrypted export envelope header is invalid");
  }
  const headerLength = bytes.readUInt32BE(MAGIC.length);
  const headerStart = MAGIC.length + 4;
  const ciphertextStart = headerStart + headerLength;
  if (
    headerLength < 2 ||
    headerLength > MAX_HEADER_BYTES ||
    ciphertextStart + TAG_BYTES >= bytes.length
  ) {
    throw new Error("encrypted export envelope bounds are invalid");
  }
  const headerBytes = bytes.subarray(headerStart, ciphertextStart);
  let rawHeader: unknown;
  try {
    rawHeader = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(headerBytes));
  } catch {
    throw new Error("encrypted export envelope metadata is invalid");
  }
  const header = ExportEncryptionHeaderSchema.parse(rawHeader);
  if (!headerBytes.equals(Buffer.from(canonicalJson(header), "utf8"))) {
    throw new Error("encrypted export envelope metadata is not canonical");
  }
  const nonce = Buffer.from(header.nonce, "base64url");
  const key = exactKey(encryptionKey);
  const ciphertext = bytes.subarray(ciphertextStart, -TAG_BYTES);
  const authTag = bytes.subarray(-TAG_BYTES);
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(headerBytes, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    key.fill(0);
    nonce.fill(0);
  }
  try {
    const parsed = ExportPackageSchema.parse(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext))
    );
    if (
      !plaintext.equals(Buffer.from(canonicalJson(parsed), "utf8")) ||
      parsed.snapshot.exportRequestId !== header.exportRequestId ||
      parsed.snapshot.organizationId !== header.organizationId ||
      parsed.scope.organizationId !== parsed.snapshot.organizationId ||
      parsed.scope.boardId !== parsed.snapshot.boardId ||
      parsed.scope.exportType !== parsed.snapshot.exportType ||
      canonicalSha256(parsed.scope) !== parsed.snapshot.scopeSha256 ||
      canonicalSha256(parsed.snapshot) !== header.snapshotSha256 ||
      parsed.components.length !== parsed.snapshot.components.length
    ) {
      throw new Error("decrypted export package binding is invalid");
    }
    const components = parsed.components.map((component, index) => {
      const descriptor = parsed.snapshot.components[index];
      const componentBytes = Buffer.from(component.bytes, "base64url");
      if (
        componentBytes.toString("base64url") !== component.bytes ||
        !descriptor ||
        descriptor.name !== component.name ||
        descriptor.rowCount !== component.rowCount ||
        descriptor.sha256 !== component.sha256 ||
        descriptor.byteLength !== componentBytes.length.toString(10) ||
        sha256Hex(componentBytes) !== component.sha256
      ) {
        throw new Error("decrypted export component binding is invalid");
      }
      return {
        name: component.name,
        rowCount: component.rowCount,
        sha256: component.sha256,
        bytes: componentBytes
      };
    });
    return {
      header,
      scope: parsed.scope,
      snapshot: parsed.snapshot,
      components,
      ...(parsed.schemaVersion === "boardagent.export-package.v2"
        ? { auditAttestation: parsed.auditAttestation }
        : {})
    };
  } finally {
    plaintext.fill(0);
  }
}

/** Local encrypted artifact storage shared by the worker and authenticated read surface. */
export class LocalExportArtifactStore implements ExportChunkReader {
  private readonly configuredRoot: string;
  private readonly maximumArtifactBytes: number;
  private readonly chunkBytes: number;
  private resolvedRoot: Promise<string> | undefined;

  public constructor(root: string, options: LocalExportArtifactStoreOptions) {
    if (!path.isAbsolute(root) || path.resolve(root) === path.parse(path.resolve(root)).root) {
      throw new Error("export artifact root must be a non-root absolute path");
    }
    this.configuredRoot = path.resolve(root);
    this.maximumArtifactBytes = boundedInteger(
      options.maximumArtifactBytes,
      "maximum export artifact bytes",
      1_048_576,
      1_073_741_824
    );
    this.chunkBytes = boundedInteger(options.chunkBytes, "export chunk bytes", 65_536, 10_485_760);
  }

  private root(): Promise<string> {
    this.resolvedRoot ??= (async () => {
      await mkdir(this.configuredRoot, { recursive: true, mode: 0o700 });
      const info = await lstat(this.configuredRoot);
      if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022) !== 0) {
        throw new Error("export artifact root must be a private non-symlink directory");
      }
      return realpath(this.configuredRoot);
    })();
    return this.resolvedRoot;
  }

  public async initialize(): Promise<void> {
    await this.root();
  }

  private async directory(...parts: readonly string[]): Promise<string> {
    let current = await this.root();
    for (const part of ["exports", ...parts]) {
      current = path.join(current, part);
      await mkdir(current, { recursive: true, mode: 0o700 });
      const info = await lstat(current);
      if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022) !== 0) {
        throw new Error("export artifact path crossed an unsafe directory");
      }
    }
    return current;
  }

  private async existingDirectory(...parts: readonly string[]): Promise<string | null> {
    let current = await this.root();
    for (const part of ["exports", ...parts]) {
      current = path.join(current, part);
      let info;
      try {
        info = await lstat(current);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
      if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022) !== 0) {
        throw new Error("export artifact path crossed an unsafe directory");
      }
    }
    return current;
  }

  private async chunkPath(
    exportRequestId: string,
    artifactId: string,
    ordinal: number
  ): Promise<string> {
    const request = UuidV7Schema.parse(exportRequestId);
    const artifact = UuidV7Schema.parse(artifactId);
    const safeOrdinal = boundedInteger(ordinal, "export chunk ordinal", 0, 1_000_000);
    const directory = await this.directory(request, artifact);
    return path.join(directory, `${String(safeOrdinal)}.bin`);
  }

  private async writeExact(target: string, bytes: Buffer): Promise<void> {
    const temporary = `${target}.tmp-${nodeRandomBytes(16).toString("hex")}`;
    let handle: Awaited<ReturnType<typeof openFile>> | undefined;
    try {
      handle = await openFile(temporary, "wx", 0o600);
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      handle = undefined;
      try {
        await link(temporary, target);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existing = await readFile(target);
        if (!existing.equals(bytes)) throw new Error("export chunk path already binds other bytes");
      }
      await unlink(temporary);
    } catch (error) {
      await handle?.close().catch(() => undefined);
      await unlink(temporary).catch(() => undefined);
      throw error;
    }
  }

  public async publish(input: PublishEncryptedExportInput): Promise<ExportArtifactManifest> {
    assertNotAborted(input.signal);
    const envelope = encodeEnvelope(input);
    if (envelope.length > this.maximumArtifactBytes) {
      envelope.fill(0);
      throw new RangeError("encrypted export exceeds the configured artifact ceiling");
    }
    const chunks: ExportArtifactManifest["chunks"][number][] = [];
    try {
      for (let offset = 0, ordinal = 0; offset < envelope.length; ordinal += 1) {
        assertNotAborted(input.signal);
        const end = Math.min(envelope.length, offset + this.chunkBytes);
        const bytes = envelope.subarray(offset, end);
        const chunkId = UuidV7Schema.parse(input.newChunkId());
        const target = await this.chunkPath(
          input.frozen.exportRequestId,
          input.artifactId,
          ordinal
        );
        await this.writeExact(target, bytes);
        chunks.push({
          chunkId,
          ordinal,
          byteOffset: offset.toString(10),
          byteLength: bytes.length,
          chunkSha256: Sha256HexSchema.parse(sha256Hex(bytes)),
          storageLocator: locator(input.frozen.exportRequestId, input.artifactId, ordinal)
        });
        offset = end;
      }
      const encryptedContentSetSha256 = canonicalSha256({
        schemaVersion: "boardagent.export-encrypted-content-set.v1",
        chunks: chunks.map(({ ordinal, byteOffset, byteLength, chunkSha256 }) => ({
          ordinal,
          byteOffset,
          byteLength,
          chunkSha256
        }))
      });
      const manifest = ExportArtifactManifestSchema.parse({
        schemaVersion: "boardagent.export-artifact.v1",
        artifactId: input.artifactId,
        exportRequestId: input.frozen.exportRequestId,
        organizationId: input.frozen.snapshot.organizationId,
        scopeSha256: input.frozen.snapshot.scopeSha256,
        snapshotSha256: input.frozen.snapshotSha256,
        plaintextContentSetSha256: input.frozen.snapshot.plaintextContentSetSha256,
        encryptedContentSetSha256,
        encryptionKeyId: input.encryptionKeyId,
        encryptedStorageLocator: locator(input.frozen.exportRequestId, input.artifactId),
        byteLength: envelope.length.toString(10),
        complete: true,
        chunks
      });
      assertNotAborted(input.signal);
      const artifactDirectory = await this.directory(manifest.exportRequestId, manifest.artifactId);
      await this.writeExact(
        path.join(artifactDirectory, MANIFEST_FILE),
        Buffer.from(canonicalJson(manifest), "utf8")
      );
      return manifest;
    } finally {
      envelope.fill(0);
    }
  }

  private async inspectArtifactDirectory(
    exportRequestId: string,
    artifactId: string,
    artifactDirectory: string
  ): Promise<ExportArtifactInventoryEntry> {
    const names = (await readdir(artifactDirectory)).toSorted();
    const directoryInfo = await lstat(artifactDirectory);
    let latestModified = directoryInfo.mtimeMs;
    const manifestPath = path.join(artifactDirectory, MANIFEST_FILE);
    if (names.includes(MANIFEST_FILE)) {
      const manifestInfo = await lstat(manifestPath);
      if (!manifestInfo.isFile() || manifestInfo.isSymbolicLink()) {
        throw new Error("export artifact manifest marker is not a regular file");
      }
      latestModified = Math.max(latestModified, manifestInfo.mtimeMs);
      const manifestBytes = await readFile(manifestPath);
      let rawManifest: unknown;
      try {
        rawManifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes));
      } catch {
        throw new Error("export artifact manifest marker is not valid UTF-8 JSON");
      }
      const manifest = ExportArtifactManifestSchema.parse(rawManifest);
      if (
        !manifest.complete ||
        manifest.exportRequestId !== exportRequestId ||
        manifest.artifactId !== artifactId ||
        !manifestBytes.equals(Buffer.from(canonicalJson(manifest), "utf8"))
      ) {
        throw new Error("export artifact manifest marker binding is invalid");
      }
      const expectedNames = new Set([
        MANIFEST_FILE,
        ...manifest.chunks.map(({ ordinal }) => `${String(ordinal)}.bin`)
      ]);
      for (const name of names) {
        if (!expectedNames.has(name) && !/^\d+\.bin\.tmp-[0-9a-f]{32}$/u.test(name)) {
          throw new Error("export artifact directory contains an unexpected storage object");
        }
      }
      for (const chunk of manifest.chunks) {
        const target = path.join(artifactDirectory, `${String(chunk.ordinal)}.bin`);
        const info = await lstat(target);
        if (!info.isFile() || info.isSymbolicLink() || info.size !== chunk.byteLength) {
          throw new Error("committed export artifact chunk has an invalid shape");
        }
        latestModified = Math.max(latestModified, info.mtimeMs);
        const bytes = await readFile(target);
        if (sha256Hex(bytes) !== chunk.chunkSha256) {
          throw new Error("committed export artifact chunk failed its manifest hash");
        }
      }
      return {
        state: "committed",
        exportRequestId,
        artifactId,
        manifest,
        manifestSha256: canonicalSha256(manifest),
        modifiedAt: new Date(latestModified).toISOString()
      };
    }

    const files: Array<{
      readonly name: string;
      readonly byteLength: number;
      readonly sha256: string;
    }> = [];
    let totalBytes = 0;
    for (const name of names) {
      if (!ARTIFACT_FILE_PATTERN.test(name)) {
        throw new Error("partial export artifact contains an unexpected storage object");
      }
      const target = path.join(artifactDirectory, name);
      const info = await lstat(target);
      if (!info.isFile() || info.isSymbolicLink()) {
        throw new Error("partial export artifact contains a non-regular object");
      }
      totalBytes += info.size;
      if (totalBytes > this.maximumArtifactBytes) {
        throw new Error("partial export artifact exceeds the configured artifact ceiling");
      }
      latestModified = Math.max(latestModified, info.mtimeMs);
      const bytes = await readFile(target);
      files.push({ name, byteLength: bytes.length, sha256: sha256Hex(bytes) });
    }
    return {
      state: "partial",
      exportRequestId,
      artifactId,
      fingerprint: canonicalSha256({
        schemaVersion: "boardagent.export-partial-fingerprint.v1",
        exportRequestId,
        artifactId,
        files
      }),
      modifiedAt: new Date(latestModified).toISOString()
    };
  }

  /** Returns a bounded, exact inventory. Unexpected paths fail closed instead of being ignored. */
  public async scanArtifacts(limit = 100): Promise<readonly ExportArtifactInventoryEntry[]> {
    const boundedLimit = boundedInteger(limit, "export artifact scan limit", 1, 10_000);
    const exportsDirectory = await this.existingDirectory();
    if (exportsDirectory === null) return [];
    const inventory: ExportArtifactInventoryEntry[] = [];
    for (const requestName of (await readdir(exportsDirectory)).toSorted()) {
      const exportRequestId = UuidV7Schema.parse(requestName);
      const requestDirectory = await this.existingDirectory(exportRequestId);
      if (requestDirectory === null) continue;
      for (const artifactName of (await readdir(requestDirectory)).toSorted()) {
        const artifactId = UuidV7Schema.parse(artifactName);
        const artifactDirectory = await this.existingDirectory(exportRequestId, artifactId);
        if (artifactDirectory === null) continue;
        inventory.push(
          await this.inspectArtifactDirectory(exportRequestId, artifactId, artifactDirectory)
        );
        if (inventory.length >= boundedLimit) return inventory;
      }
    }
    return inventory;
  }

  public async readExactChunk(input: {
    readonly exportRequestId: string;
    readonly artifactId: string;
    readonly ordinal: number;
    readonly storageLocator: string;
    readonly byteLength: number;
    readonly expectedSha256: string;
  }): Promise<Uint8Array> {
    const expectedSha256 = Sha256HexSchema.parse(input.expectedSha256);
    const byteLength = boundedInteger(input.byteLength, "export chunk byte length", 1, 10_485_760);
    if (input.storageLocator !== locator(input.exportRequestId, input.artifactId, input.ordinal)) {
      throw new Error("export chunk locator does not bind its database row");
    }
    const request = UuidV7Schema.parse(input.exportRequestId);
    const artifact = UuidV7Schema.parse(input.artifactId);
    const safeOrdinal = boundedInteger(input.ordinal, "export chunk ordinal", 0, 1_000_000);
    const artifactDirectory = await this.existingDirectory(request, artifact);
    if (artifactDirectory === null) throw new Error("export chunk storage object is unavailable");
    const target = path.join(artifactDirectory, `${String(safeOrdinal)}.bin`);
    const info = await lstat(target);
    if (!info.isFile() || info.isSymbolicLink() || info.size !== byteLength) {
      throw new Error("export chunk storage object has an invalid shape");
    }
    const bytes = await readFile(target);
    if (sha256Hex(bytes) !== expectedSha256) throw new Error("export chunk storage hash mismatch");
    return bytes;
  }

  public async deleteArtifact(manifestValue: unknown): Promise<void> {
    const manifest = ExportArtifactManifestSchema.parse(manifestValue);
    const artifactDirectory = await this.existingDirectory(
      manifest.exportRequestId,
      manifest.artifactId
    );
    if (artifactDirectory === null) return;
    const manifestPath = path.join(artifactDirectory, MANIFEST_FILE);
    try {
      const manifestInfo = await lstat(manifestPath);
      const manifestBytes = await readFile(manifestPath);
      if (
        !manifestInfo.isFile() ||
        manifestInfo.isSymbolicLink() ||
        !manifestBytes.equals(Buffer.from(canonicalJson(manifest), "utf8"))
      ) {
        throw new Error("export deletion manifest marker does not match database evidence");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    for (const chunk of manifest.chunks) {
      if (
        chunk.storageLocator !==
        locator(manifest.exportRequestId, manifest.artifactId, chunk.ordinal)
      ) {
        throw new Error("export deletion manifest contains an invalid locator");
      }
      const target = path.join(artifactDirectory, `${String(chunk.ordinal)}.bin`);
      try {
        const info = await lstat(target);
        if (!info.isFile() || info.isSymbolicLink()) {
          throw new Error("export deletion target is not a regular file");
        }
        const bytes = await readFile(target);
        if (bytes.length !== chunk.byteLength || sha256Hex(bytes) !== chunk.chunkSha256) {
          throw new Error("export deletion target does not match its immutable manifest");
        }
        await unlink(target);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    const unexpected = (await readdir(artifactDirectory)).filter(
      (name) => name !== MANIFEST_FILE && !/^\d+\.bin\.tmp-[0-9a-f]{32}$/u.test(name)
    );
    if (unexpected.length > 0) {
      throw new Error("export artifact directory contains unmanifested storage objects");
    }
    for (const temporary of await readdir(artifactDirectory)) {
      await unlink(path.join(artifactDirectory, temporary));
    }
    await rmdir(artifactDirectory);
    const requestDirectory = path.dirname(artifactDirectory);
    if ((await readdir(requestDirectory)).length === 0) await rmdir(requestDirectory);
  }

  /** Restores only the derived commit marker after every database-manifest chunk re-verifies. */
  public async restoreManifestMarker(manifestValue: unknown): Promise<void> {
    const manifest = ExportArtifactManifestSchema.parse(manifestValue);
    const artifactDirectory = await this.existingDirectory(
      manifest.exportRequestId,
      manifest.artifactId
    );
    if (artifactDirectory === null) throw new Error("export artifact directory is unavailable");
    const allowedNames = new Set(manifest.chunks.map(({ ordinal }) => `${String(ordinal)}.bin`));
    for (const name of await readdir(artifactDirectory)) {
      if (name === MANIFEST_FILE || /^\d+\.bin\.tmp-[0-9a-f]{32}$/u.test(name)) continue;
      if (!allowedNames.has(name)) {
        throw new Error("export artifact directory contains an unexpected storage object");
      }
    }
    for (const chunk of manifest.chunks) {
      const target = path.join(artifactDirectory, `${String(chunk.ordinal)}.bin`);
      const info = await lstat(target);
      if (!info.isFile() || info.isSymbolicLink() || info.size !== chunk.byteLength) {
        throw new Error("export artifact chunk cannot restore its manifest marker");
      }
      if (sha256Hex(await readFile(target)) !== chunk.chunkSha256) {
        throw new Error("export artifact chunk hash blocks manifest marker restoration");
      }
    }
    await this.writeExact(
      path.join(artifactDirectory, MANIFEST_FILE),
      Buffer.from(canonicalJson(manifest), "utf8")
    );
  }

  /** Deletes only the byte-for-byte partial inventory previously inspected by this store. */
  public async deletePartialArtifact(entry: PartialExportArtifactInventoryEntry): Promise<void> {
    const exportRequestId = UuidV7Schema.parse(entry.exportRequestId);
    const artifactId = UuidV7Schema.parse(entry.artifactId);
    const fingerprint = Sha256HexSchema.parse(entry.fingerprint);
    const artifactDirectory = await this.existingDirectory(exportRequestId, artifactId);
    if (artifactDirectory === null) return;
    const current = await this.inspectArtifactDirectory(
      exportRequestId,
      artifactId,
      artifactDirectory
    );
    if (current.state !== "partial" || current.fingerprint !== fingerprint) {
      throw new Error("partial export artifact changed after inventory");
    }
    for (const name of await readdir(artifactDirectory)) {
      if (!ARTIFACT_FILE_PATTERN.test(name)) {
        throw new Error("partial export artifact changed before deletion");
      }
      await unlink(path.join(artifactDirectory, name));
    }
    await rmdir(artifactDirectory);
    const requestDirectory = path.dirname(artifactDirectory);
    if ((await readdir(requestDirectory)).length === 0) await rmdir(requestDirectory);
  }
}
