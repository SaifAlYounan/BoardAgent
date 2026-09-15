import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual
} from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, open, rm, unlink } from "node:fs/promises";
import path from "node:path";
import type { Readable } from "node:stream";
import { syncRecoveryDirectory } from "./recovery-publication.js";

const MAGIC = Buffer.from("BOARDAGENT-BACKUP-AES256GCM-V1\0", "ascii");
const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const IO_CHUNK_BYTES = 64 * 1024;

export interface EncryptedBackupArtifact {
  readonly sha256: string;
  readonly byteLength: number;
  readonly plaintextSha256: string;
  readonly plaintextByteLength: number;
}

function assertKey(key: Uint8Array): Buffer {
  const value = Buffer.from(key);
  if (value.length !== 32) throw new Error("backup encryption key must contain exactly 32 bytes");
  return value;
}

async function writeAll(
  handle: Awaited<ReturnType<typeof open>>,
  value: Uint8Array,
  hash?: ReturnType<typeof createHash>
): Promise<number> {
  const buffer = Buffer.from(value);
  let offset = 0;
  while (offset < buffer.length) {
    const result = await handle.write(buffer, offset, buffer.length - offset, null);
    if (result.bytesWritten < 1) throw new Error("backup artifact write made no progress");
    offset += result.bytesWritten;
  }
  hash?.update(buffer);
  return buffer.length;
}

async function assertWritableParent(filePath: string): Promise<void> {
  const parent = await lstat(path.dirname(filePath));
  if (!parent.isDirectory() || parent.isSymbolicLink()) {
    throw new Error("backup artifact parent must be a real directory");
  }
}

export async function encryptBackupArtifact(
  source: Readable,
  artifactPath: string,
  rawKey: Uint8Array
): Promise<EncryptedBackupArtifact> {
  const key = assertKey(rawKey);
  const target = path.resolve(artifactPath);
  await assertWritableParent(target);
  const temporary = `${target}.partial-${String(process.pid)}-${randomBytes(8).toString("hex")}`;
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: AUTH_TAG_BYTES });
  cipher.setAAD(MAGIC);
  const hash = createHash("sha256");
  const plaintextHash = createHash("sha256");
  const handle = await open(temporary, "wx", 0o600);
  let byteLength = 0;
  let plaintextByteLength = 0;
  let closed = false;
  try {
    byteLength += await writeAll(handle, MAGIC, hash);
    byteLength += await writeAll(handle, nonce, hash);
    for await (const chunk of source) {
      const plaintext = Buffer.from(chunk as Uint8Array);
      plaintextHash.update(plaintext);
      plaintextByteLength += plaintext.length;
      const encrypted = cipher.update(plaintext);
      if (encrypted.length > 0) byteLength += await writeAll(handle, encrypted, hash);
    }
    const final = cipher.final();
    if (final.length > 0) byteLength += await writeAll(handle, final, hash);
    byteLength += await writeAll(handle, cipher.getAuthTag(), hash);
    await handle.sync();
    await handle.close();
    closed = true;
    await link(temporary, target);
    await syncRecoveryDirectory(path.dirname(target));
    await unlink(temporary);
    await syncRecoveryDirectory(path.dirname(target));
    return {
      sha256: hash.digest("hex"),
      byteLength,
      plaintextSha256: plaintextHash.digest("hex"),
      plaintextByteLength
    };
  } catch (error) {
    if (!closed) await handle.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  } finally {
    key.fill(0);
    nonce.fill(0);
  }
}

async function readExactly(
  handle: Awaited<ReturnType<typeof open>>,
  position: number,
  byteLength: number
): Promise<Buffer> {
  const value = Buffer.alloc(byteLength);
  let offset = 0;
  while (offset < byteLength) {
    const result = await handle.read(value, offset, byteLength - offset, position + offset);
    if (result.bytesRead < 1) throw new Error("backup artifact ended unexpectedly");
    offset += result.bytesRead;
  }
  return value;
}

async function regularArtifact(filePath: string): Promise<{ readonly size: number }> {
  const stat = await lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error("backup artifact must be a regular file");
  }
  if (
    !Number.isSafeInteger(stat.size) ||
    stat.size <= MAGIC.length + NONCE_BYTES + AUTH_TAG_BYTES
  ) {
    throw new Error("backup artifact has an invalid length");
  }
  return { size: stat.size };
}

export async function verifyBackupArtifact(
  artifactPath: string,
  expectedSha256: string,
  expectedByteLength: number
): Promise<void> {
  if (!/^[0-9a-f]{64}$/u.test(expectedSha256)) {
    throw new Error("backup artifact expected hash is invalid");
  }
  const { size } = await regularArtifact(artifactPath);
  if (size !== expectedByteLength) throw new Error("backup artifact length mismatch");
  const handle = await open(artifactPath, "r");
  const hash = createHash("sha256");
  try {
    let position = 0;
    while (position < size) {
      const length = Math.min(IO_CHUNK_BYTES, size - position);
      hash.update(await readExactly(handle, position, length));
      position += length;
    }
  } finally {
    await handle.close();
  }
  const expected = Buffer.from(expectedSha256, "hex");
  const actual = hash.digest();
  if (!timingSafeEqual(expected, actual)) throw new Error("backup artifact hash mismatch");
}

export async function* decryptBackupArtifact(
  artifactPath: string,
  rawKey: Uint8Array,
  // Use mounted storage, not the deployment's small /tmp tmpfs. Callers reading
  // a read-only archive supply their writable receipt or recovery target directory.
  scratchDirectory = path.dirname(path.resolve(artifactPath)),
  signal?: AbortSignal
): AsyncGenerator<Buffer> {
  const key = assertKey(rawKey);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let snapshot: Awaited<ReturnType<typeof open>> | undefined;
  let nonce: Buffer | undefined;
  let tag: Buffer | undefined;
  try {
    signal?.throwIfAborted();
    await regularArtifact(artifactPath);
    handle = await open(
      artifactPath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
    );
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error("backup artifact must be a regular file");
    const { size } = stat;
    if (!Number.isSafeInteger(size) || size <= MAGIC.length + NONCE_BYTES + AUTH_TAG_BYTES) {
      throw new Error("backup artifact has an invalid length");
    }
    const magic = await readExactly(handle, 0, MAGIC.length);
    if (!timingSafeEqual(magic, MAGIC)) throw new Error("backup artifact format is unsupported");
    nonce = await readExactly(handle, MAGIC.length, NONCE_BYTES);
    tag = await readExactly(handle, size - AUTH_TAG_BYTES, AUTH_TAG_BYTES);
    const authenticator = createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: AUTH_TAG_BYTES
    });
    authenticator.setAAD(MAGIC);
    authenticator.setAuthTag(tag);
    snapshot = await openPrivateEncryptedSnapshot(scratchDirectory);
    let position = MAGIC.length + NONCE_BYTES;
    const ciphertextEnd = size - AUTH_TAG_BYTES;
    while (position < ciphertextEnd) {
      signal?.throwIfAborted();
      const length = Math.min(IO_CHUNK_BYTES, ciphertextEnd - position);
      const encrypted = await readExactly(handle, position, length);
      await writeAll(snapshot, encrypted);
      // Never release or persist first-pass plaintext before final tag validation.
      authenticator.update(encrypted).fill(0);
      position += length;
    }
    signal?.throwIfAborted();
    try {
      authenticator.final().fill(0);
    } catch {
      throw new Error("backup artifact authentication failed");
    }
    await handle.close();
    handle = undefined;

    // The snapshot was unlinked before it received any ciphertext. Only this
    // private descriptor can write it; reopening/mutating the source cannot
    // substitute bytes between authentication and consumption.
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: AUTH_TAG_BYTES
    });
    decipher.setAAD(MAGIC);
    decipher.setAuthTag(tag);
    const ciphertextBytes = ciphertextEnd - MAGIC.length - NONCE_BYTES;
    position = 0;
    while (position < ciphertextBytes) {
      signal?.throwIfAborted();
      const length = Math.min(IO_CHUNK_BYTES, ciphertextBytes - position);
      const decrypted = decipher.update(await readExactly(snapshot, position, length));
      if (decrypted.length > 0) yield decrypted;
      position += length;
    }
    const final = decipher.final();
    if (final.length > 0) yield final;
  } finally {
    key.fill(0);
    nonce?.fill(0);
    tag?.fill(0);
    try {
      await snapshot?.close();
    } finally {
      await handle?.close();
    }
  }
}

async function openPrivateEncryptedSnapshot(
  rawDirectory: string
): Promise<Awaited<ReturnType<typeof open>>> {
  const directory = path.resolve(rawDirectory);
  const parent = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
  );
  try {
    if (((await parent.stat()).mode & 0o022) !== 0) {
      throw new Error(
        "backup authentication scratch directory must not be writable by other users"
      );
    }
    const temporary = path.join(
      directory,
      `.boardagent-auth-${process.pid}-${randomBytes(16).toString("hex")}`
    );
    const handle = await open(
      temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600
    );
    try {
      // Remove the name while still empty, so no unauthenticated or authenticated
      // snapshot can be reopened through the filesystem during either pass.
      await unlink(temporary);
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 0 || (stat.mode & 0o077) !== 0) {
        throw new Error("backup authentication snapshot must be private and unlinked");
      }
      return handle;
    } catch (error) {
      await handle.close();
      await rm(temporary, { force: true });
      throw error;
    }
  } finally {
    await parent.close();
  }
}

export async function loadBackupEncryptionKey(keyPath: string): Promise<Buffer> {
  const stat = await lstat(keyPath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error("backup encryption key must be a regular file");
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error("backup encryption key must not be accessible to other users");
  }
  if (stat.size < 32 || stat.size > 256) {
    throw new Error("backup encryption key has an invalid length");
  }
  const handle = await open(keyPath, "r");
  let raw: Buffer;
  try {
    raw = await readExactly(handle, 0, stat.size);
  } finally {
    await handle.close();
  }
  if (raw.length === 32) return raw;
  const text = raw.toString("utf8").trimEnd();
  const decoded = Buffer.from(text, "base64url");
  raw.fill(0);
  if (
    !/^[A-Za-z0-9_-]{43}$/u.test(text) ||
    decoded.length !== 32 ||
    decoded.toString("base64url") !== text
  ) {
    decoded.fill(0);
    throw new Error("backup encryption key must be 32 raw bytes or canonical base64url");
  }
  return decoded;
}
