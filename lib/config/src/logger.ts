import { createHmac } from "node:crypto";

import { z } from "zod";

const SafeCode = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/u);

export const SafeLogInputSchema = z
  .object({
    level: z.enum(["error", "warn", "info"]),
    event: SafeCode,
    requestId: SafeCode.optional(),
    principalId: z.string().min(1).max(256).optional(),
    clientId: z.string().min(1).max(512).optional(),
    result: z.enum(["success", "denied", "error"]),
    reasonCode: SafeCode.optional(),
    surface: SafeCode.optional(),
    protocol: SafeCode.optional(),
    durationMs: z.number().int().min(0).max(86_400_000).optional(),
    bytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
    count: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional()
  })
  .strict();

export type SafeLogInput = z.infer<typeof SafeLogInputSchema>;

export interface StructuredLoggerOptions {
  readonly pseudonymKey: Uint8Array | string;
  readonly service: string;
  readonly clock: () => Date;
  readonly sink: (line: string) => void;
}

export interface StructuredLogger {
  write(input: SafeLogInput): void;
}

function pseudonym(key: Uint8Array | string, kind: string, value: string): string {
  return `${kind}_${createHmac("sha256", key).update(kind).update("\0").update(value).digest("hex").slice(0, 24)}`;
}

export function createStructuredLogger(options: StructuredLoggerOptions): StructuredLogger {
  const keyLength =
    typeof options.pseudonymKey === "string"
      ? Buffer.byteLength(options.pseudonymKey)
      : options.pseudonymKey.byteLength;
  if (keyLength < 32) throw new Error("structured logger pseudonym key must be at least 32 bytes");
  const service = SafeCode.parse(options.service);

  return {
    write(input) {
      const parsed = SafeLogInputSchema.parse(input);
      const record = {
        schemaVersion: 1,
        timestamp: options.clock().toISOString(),
        service,
        level: parsed.level,
        event: parsed.event,
        ...(parsed.requestId === undefined ? {} : { requestId: parsed.requestId }),
        ...(parsed.principalId === undefined
          ? {}
          : { principalRef: pseudonym(options.pseudonymKey, "member", parsed.principalId) }),
        ...(parsed.clientId === undefined
          ? {}
          : { clientRef: pseudonym(options.pseudonymKey, "client", parsed.clientId) }),
        result: parsed.result,
        ...(parsed.reasonCode === undefined ? {} : { reasonCode: parsed.reasonCode }),
        ...(parsed.surface === undefined ? {} : { surface: parsed.surface }),
        ...(parsed.protocol === undefined ? {} : { protocol: parsed.protocol }),
        ...(parsed.durationMs === undefined ? {} : { durationMs: parsed.durationMs }),
        ...(parsed.bytes === undefined ? {} : { bytes: parsed.bytes }),
        ...(parsed.count === undefined ? {} : { count: parsed.count })
      };
      options.sink(`${JSON.stringify(record)}\n`);
    }
  };
}
