import { z } from "zod";

const UUID_V7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RFC3339_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/u;

export const UuidV7Schema = z.string().regex(UUID_V7_PATTERN).brand<"Uuid">();
export const UuidSchema = UuidV7Schema;
export type Uuid = z.infer<typeof UuidSchema>;

export const Sha256HexSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/u)
  .brand<"Sha256Hex">();
export type Sha256Hex = z.infer<typeof Sha256HexSchema>;

export const Rfc3339UtcSchema = z
  .string()
  .regex(RFC3339_UTC_PATTERN)
  .refine((value) => {
    const instant = new Date(value);
    // Date accepts normalized inputs such as February 30 and 24:00. Compare
    // calendar components without truncating the original microsecond precision.
    return (
      Number.isFinite(instant.valueOf()) &&
      instant.toISOString().slice(0, 19) === value.slice(0, 19)
    );
  }, "invalid UTC timestamp")
  .brand<"Rfc3339Utc">();
export type Rfc3339Utc = z.infer<typeof Rfc3339UtcSchema>;

export const SafePositiveIntegerSchema = z.number().int().positive().safe();
export const VotingWeightSchema = z
  .number()
  .int()
  .min(1)
  .max(1_000_000_000)
  .safe()
  .brand<"VotingWeight">();
export type VotingWeight = z.infer<typeof VotingWeightSchema>;

export const NonEmptyTextSchema = z.string().min(1).max(262_144);
export const CanonicalResolutionTextSchema = z.string().min(1).max(1_048_576);

export const StructuredErrorSchema = z
  .object({
    code: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),
    message: z.string().min(1).max(512),
    requestId: UuidSchema.optional(),
    retryable: z.boolean(),
    details: z
      .record(z.string(), z.union([z.boolean(), z.number().safe(), z.string(), z.null()]))
      .optional()
  })
  .strict();
export type StructuredError = z.infer<typeof StructuredErrorSchema>;

export function strictObject<T extends z.ZodRawShape>(shape: T): z.ZodObject<T> {
  return z.object(shape).strict();
}
