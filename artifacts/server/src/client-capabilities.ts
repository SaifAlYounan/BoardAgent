import { assertJsonStructure, CanonicalizationError, type JsonValue } from "@boardagent/contracts";
import { z } from "zod";

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);

const ClientCapabilitiesSchema = z.preprocess((value, ctx) => {
  try {
    assertJsonStructure(value);
  } catch (error) {
    if (!(error instanceof CanonicalizationError)) throw error;
    ctx.addIssue({ code: "custom", message: error.message });
    return z.NEVER;
  }
  return value;
}, JsonValueSchema);

// Capability metadata lives outside registered tool arguments. Admit its structure
// independently before the recursive JSON schema runs, including direct JS callers.
export function parseClientCapabilities(value: unknown) {
  return ClientCapabilitiesSchema.safeParse(value);
}

/**
 * Form-mode elicitation support per the MCP client capability rules: a declared
 * `elicitation` object supports form mode when it names `form`, or when it names
 * neither `form` nor `url` (the spec's backwards-compatible empty object). A client that
 * declares only `url`, or no `elicitation` at all, cannot receive the confirmation form.
 * This mirrors the reference SDK's `getSupportedElicitationModes`.
 */
export function supportsFormElicitation(value: JsonValue): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const elicitation = (value as Readonly<Record<string, JsonValue>>)["elicitation"];
  if (typeof elicitation !== "object" || elicitation === null || Array.isArray(elicitation)) {
    return false;
  }
  const hasForm = Object.hasOwn(elicitation, "form");
  const hasUrl = Object.hasOwn(elicitation, "url");
  return hasForm || !hasUrl;
}
