import { createHash } from "node:crypto";

function missingSourceFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function lengthFrame(length: number): Buffer {
  const frame = Buffer.alloc(8);
  frame.writeBigUInt64BE(BigInt(length));
  return frame;
}

export async function sourceTreeSha256ForFiles(
  names: readonly string[],
  readSource: (name: string) => Promise<Uint8Array>
): Promise<string> {
  const digest = createHash("sha256");
  // Versioned framing distinguishes missing files from every possible file body,
  // and binary content cannot impersonate a boundary between source files.
  digest.update("boardagent.source-tree-sha256.v2\0");
  digest.update(lengthFrame(names.length));
  for (const name of names) {
    const nameBytes = Buffer.from(name, "utf8");
    digest.update(lengthFrame(nameBytes.byteLength));
    digest.update(nameBytes);
    let content: Uint8Array | null;
    try {
      content = await readSource(name);
    } catch (error) {
      if (!missingSourceFile(error)) throw error;
      content = null;
    }
    digest.update(Buffer.from([content === null ? 0 : 1]));
    digest.update(lengthFrame(content?.byteLength ?? 0));
    if (content !== null) digest.update(content);
  }
  return digest.digest("hex");
}
