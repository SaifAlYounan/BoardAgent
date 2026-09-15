import { z } from "zod";

import { Sha256HexSchema, UuidSchema } from "./schemas.js";

export const CanonicalMediaTypeSchema = z.enum([
  "text/markdown; charset=utf-8",
  "text/plain; charset=utf-8",
  "application/json"
]);

export const RejectedMediaTypeSchema = z.enum([
  "application/pdf",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-powerpoint",
  "application/msword",
  "application/zip",
  "image/jpeg",
  "image/png",
  "image/tiff"
]);

export const CanonicalDocumentSchema = z
  .object({
    schemaVersion: z.literal("boardagent.document.v1"),
    documentId: UuidSchema,
    title: z.string().min(1).max(512),
    mediaType: CanonicalMediaTypeSchema,
    byteLength: z.number().int().nonnegative().max(10_485_760),
    sha256: Sha256HexSchema,
    body: z.string().max(10_485_760)
  })
  .strict();

export const MaterialRejectionSchema = z
  .object({
    accepted: z.literal(false),
    code: z.literal("machine_readable_material_required"),
    message: z.literal(
      "BoardAgent accepts only UTF-8 Markdown, plain text, or versioned strict JSON. Submit a machine-readable source; rejected bytes were not retained."
    ),
    receivedMediaType: z.string().min(1).max(255)
  })
  .strict();

export function isCanonicalMediaType(
  value: string
): value is z.infer<typeof CanonicalMediaTypeSchema> {
  return CanonicalMediaTypeSchema.safeParse(value).success;
}
