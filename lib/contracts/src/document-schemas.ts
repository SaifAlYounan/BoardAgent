import { z } from "zod";
import { MinutesCommentSchema, MinutesRedlineSchema } from "./governance.js";

/** Versioned, compiled document formats. A label never grants runtime schema authority. */
export const BoardPackDocumentSchema = z
  .object({
    schemaVersion: z.literal("boardagent.board-pack.v1"),
    title: z.string().min(1).max(512),
    sections: z
      .array(
        z
          .object({
            heading: z.string().min(1).max(512),
            body: z.string().min(1).max(10_485_760)
          })
          .strict()
      )
      .min(1)
      .max(1000)
  })
  .strict();

export const SUPPORTED_JSON_DOCUMENT_SCHEMAS = [
  "boardagent.board-pack.v1",
  "boardagent.minutes-comment.v1",
  "boardagent.minutes-redline.v1"
] as const;

export function documentBodySchema(name: string): z.ZodType | undefined {
  switch (name) {
    case "boardagent.board-pack.v1":
      return BoardPackDocumentSchema;
    case "boardagent.minutes-comment.v1":
      return MinutesCommentSchema;
    case "boardagent.minutes-redline.v1":
      return MinutesRedlineSchema;
    default:
      return undefined;
  }
}
