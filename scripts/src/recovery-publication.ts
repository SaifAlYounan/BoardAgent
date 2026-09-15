import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, open, unlink } from "node:fs/promises";
import path from "node:path";

import { canonicalJson, UuidV7Schema, type JsonValue } from "@boardagent/contracts";

/** Durable recovery evidence exists, but its database recording was not confirmed. */
export class PublishedRecoveryRecordError extends Error {
  constructor(
    readonly command: "backup" | "restore-check",
    readonly receiptId: string,
    readonly manifestFile: string,
    cause: unknown
  ) {
    super("recovery evidence published but database recording is unconfirmed", { cause });
  }
}

/** Persist directory entries before acknowledging removal of a PostgreSQL source. */
export async function syncRecoveryDirectory(directory: string): Promise<void> {
  const handle = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Publish a complete, private manifest exclusively; never overwrite existing evidence. */
export async function publishRecoveryJson(filePath: string, value: JsonValue): Promise<void> {
  const target = path.resolve(filePath);
  const temporary = `${target}.partial-${process.pid}-${randomBytes(8).toString("hex")}`;
  const directory = await open(
    path.dirname(target),
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
  );
  try {
    const handle = await open(temporary, "wx", 0o600);
    try {
      try {
        await handle.writeFile(`${canonicalJson(value)}\n`);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await link(temporary, target);
      await directory.sync();
    } finally {
      await unlink(temporary);
    }
    await directory.sync();
  } finally {
    await directory.close();
  }
}

/** Recognition is not proof that the writer stopped. Callers preserve these files. */
export function isRecoveryTemporaryFile(name: string, kind: "base" | "wal"): boolean {
  const match = /^(.*)\.partial-[1-9][0-9]{0,9}-[0-9a-f]{16}$/u.exec(name);
  if (!match) return false;
  if (kind === "wal")
    return /^(?:[0-9A-F]{24}|[0-9A-F]{8}\.history|[0-9A-F]{24}\.[0-9A-F]{8}\.backup)\.(?:aes256gcm|manifest\.json)$/u.test(
      match[1]!
    );
  const base = /^boardagent-([0-9a-f-]{36})\.base\.(?:tar\.aes256gcm|manifest\.json)$/u.exec(
    match[1]!
  );
  return base !== null && UuidV7Schema.safeParse(base[1]).success;
}

export interface RecoveryTemporaryReport {
  readonly ignoredTemporaryFileCount?: number;
  /** At most twenty safe basenames; the count reports the complete observed set. */
  readonly ignoredTemporaryFiles?: readonly string[];
}

export function recoveryTemporaryReport(names: readonly string[]): RecoveryTemporaryReport {
  return names.length === 0
    ? {}
    : {
        ignoredTemporaryFileCount: names.length,
        ignoredTemporaryFiles: names.toSorted().slice(0, 20)
      };
}
