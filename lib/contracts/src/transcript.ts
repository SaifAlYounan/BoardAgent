import { z } from "zod";

import { canonicalJsonFromText, canonicalText } from "./canonical.js";
import { UuidV7Schema } from "./schemas.js";

export const TRANSCRIPT_TURNS_SCHEMA_VERSION = "boardagent.transcript-turns.v1" as const;
export const TRANSCRIPT_MARKDOWN_SCHEMA_VERSION = "boardagent.transcript-markdown.v1" as const;
export const MAX_TRANSCRIPT_BYTES = 10 * 1024 * 1024;

function canonicalTranscriptString(maximum: number): z.ZodType<string> {
  return z
    .string()
    .min(1)
    .max(maximum)
    .superRefine((value, context) => {
      try {
        canonicalText(value);
      } catch (error) {
        context.addIssue({
          code: "custom",
          message: error instanceof Error ? error.message : "transcript text is not canonical"
        });
      }
    });
}

export const TranscriptTurnSchema = z
  .object({
    turn_id: UuidV7Schema,
    speaker_member_id: UuidV7Schema.nullable().default(null),
    speaker_label: canonicalTranscriptString(512),
    starts_at_ms: z.number().int().nonnegative().safe().nullable().default(null),
    ends_at_ms: z.number().int().nonnegative().safe().nullable().default(null),
    canonical_text: canonicalTranscriptString(1_048_576)
  })
  .strict()
  .superRefine((turn, context) => {
    if ((turn.starts_at_ms === null) !== (turn.ends_at_ms === null)) {
      context.addIssue({
        code: "custom",
        message: "transcript turn start and end must both be present or both be null"
      });
    } else if (
      turn.starts_at_ms !== null &&
      turn.ends_at_ms !== null &&
      turn.ends_at_ms <= turn.starts_at_ms
    ) {
      context.addIssue({
        code: "custom",
        message: "transcript turn end must be after its start"
      });
    }
  });

export const TranscriptTurnsDocumentSchema = z
  .object({
    schema_version: z.literal(TRANSCRIPT_TURNS_SCHEMA_VERSION),
    values: z.object({ turns: z.array(TranscriptTurnSchema).min(1).max(10_000) }).strict()
  })
  .strict()
  .superRefine((document, context) => {
    const ids = document.values.turns.map(({ turn_id: turnId }) => turnId);
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: "custom", message: "transcript turn identifiers must be unique" });
    }
  });

export type TranscriptTurn = z.infer<typeof TranscriptTurnSchema>;
export type TranscriptTurnsDocument = z.infer<typeof TranscriptTurnsDocumentSchema>;
export type TranscriptMediaType = "application/json" | "text/markdown; charset=utf-8";

export type ParsedTranscriptAnnex =
  | {
      readonly canonicalSchema: typeof TRANSCRIPT_TURNS_SCHEMA_VERSION;
      readonly canonicalBody: string;
      readonly turns: readonly TranscriptTurn[];
    }
  | {
      readonly canonicalSchema: typeof TRANSCRIPT_MARKDOWN_SCHEMA_VERSION;
      readonly canonicalBody: string;
      readonly turns: readonly [];
    };

/**
 * Validate the public transcript annex byte representation. JSON annexes must already
 * be exact RFC 8785-style canonical JSON; parsing must never silently rewrite the bytes
 * whose hash is persisted and later bound into minutes.
 */
export function parseTranscriptAnnex(
  mediaType: TranscriptMediaType,
  value: string
): ParsedTranscriptAnnex {
  const body = canonicalText(value);
  const byteLength = Buffer.byteLength(body, "utf8");
  if (byteLength < 1 || byteLength > MAX_TRANSCRIPT_BYTES) {
    throw new RangeError("transcript annex must contain 1 through 10485760 UTF-8 bytes");
  }
  if (mediaType === "text/markdown; charset=utf-8") {
    return {
      canonicalSchema: TRANSCRIPT_MARKDOWN_SCHEMA_VERSION,
      canonicalBody: body,
      turns: []
    };
  }
  const canonicalBody = canonicalJsonFromText(body);
  if (canonicalBody !== body) {
    throw new TypeError("JSON transcript annex must already use the exact canonical encoding");
  }
  const document = TranscriptTurnsDocumentSchema.parse(JSON.parse(canonicalBody) as unknown);
  return {
    canonicalSchema: TRANSCRIPT_TURNS_SCHEMA_VERSION,
    canonicalBody,
    turns: document.values.turns
  };
}
