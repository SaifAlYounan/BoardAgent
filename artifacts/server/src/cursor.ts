import { createHmac, timingSafeEqual } from "node:crypto";

import { z } from "zod";

import { UuidV7Schema, canonicalJson } from "@boardagent/contracts";

const CURSOR_SCHEMA_VERSION = "boardagent.cursor.v1" as const;

const CursorPayloadSchema = z
  .object({
    schema_version: z.literal(CURSOR_SCHEMA_VERSION),
    organization_id: UuidV7Schema,
    member_id: UuidV7Schema,
    tool: z.string().regex(/^[a-z][a-z0-9_]{1,127}$/u),
    board_id: UuidV7Schema.nullable(),
    after: z.string().min(1).max(1024),
    expires_at: z.number().int().positive().safe()
  })
  .strict();

interface CursorBinding {
  readonly organizationId: string;
  readonly memberId: string;
  readonly tool: string;
  readonly boardId: string | null;
}

export interface CursorCodec {
  mint(binding: CursorBinding, after: string, nowSeconds?: number): string;
  verify(wire: string, binding: CursorBinding, nowSeconds?: number): string;
}

export function createCursorCodec(key: Uint8Array | string, ttlSeconds = 86_400): CursorCodec {
  const secret = Buffer.from(key);
  if (secret.length < 32) throw new Error("cursor HMAC key must contain at least 32 bytes");
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 604_800) {
    throw new RangeError("cursor TTL must be 60 through 604800 seconds");
  }
  const mac = (payload: string): Buffer =>
    createHmac("sha256", secret).update("boardagent.cursor.v1\0").update(payload).digest();
  return {
    mint(binding, after, nowSeconds = Math.floor(Date.now() / 1000)) {
      const payload = canonicalJson(
        CursorPayloadSchema.parse({
          schema_version: CURSOR_SCHEMA_VERSION,
          organization_id: binding.organizationId,
          member_id: binding.memberId,
          tool: binding.tool,
          board_id: binding.boardId,
          after,
          expires_at: nowSeconds + ttlSeconds
        })
      );
      return `${Buffer.from(payload).toString("base64url")}.${mac(payload).toString("base64url")}`;
    },
    verify(wire, binding, nowSeconds = Math.floor(Date.now() / 1000)) {
      if (wire.length > 4096) throw new Error("cursor is invalid");
      const [encoded, signature, extra] = wire.split(".");
      if (!encoded || !signature || extra !== undefined) throw new Error("cursor is invalid");
      let payload: string;
      let payloadBytes: Buffer;
      let received: Buffer;
      try {
        payloadBytes = Buffer.from(encoded, "base64url");
        received = Buffer.from(signature, "base64url");
      } catch {
        throw new Error("cursor is invalid");
      }
      if (
        payloadBytes.toString("base64url") !== encoded ||
        received.toString("base64url") !== signature
      ) {
        throw new Error("cursor is invalid");
      }
      payload = payloadBytes.toString("utf8");
      const expected = mac(payload);
      if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
        throw new Error("cursor is invalid");
      }
      let parsed: z.infer<typeof CursorPayloadSchema>;
      try {
        parsed = CursorPayloadSchema.parse(JSON.parse(payload));
      } catch {
        throw new Error("cursor is invalid");
      }
      if (
        canonicalJson(parsed) !== payload ||
        parsed.organization_id !== binding.organizationId ||
        parsed.member_id !== binding.memberId ||
        parsed.tool !== binding.tool ||
        parsed.board_id !== binding.boardId ||
        parsed.expires_at <= nowSeconds
      ) {
        throw new Error("cursor is invalid");
      }
      return parsed.after;
    }
  };
}
