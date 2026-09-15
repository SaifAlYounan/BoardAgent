import { createHash } from "node:crypto";

/** Existing version1 identity; changing it would disconnect retained ciphertext from its key. */
export function symmetricKeyId(prefix: "browser" | "data", value: Uint8Array): string {
  return `${prefix}-${createHash("sha256")
    .update(`boardagent/${prefix}/key-id/v1\0`, "utf8")
    .update(value)
    .digest("hex")
    .slice(0, 24)}`;
}
