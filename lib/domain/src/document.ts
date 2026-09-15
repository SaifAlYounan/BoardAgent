import {
  CanonicalDocumentSchema,
  documentBodySchema,
  SUPPORTED_JSON_DOCUMENT_SCHEMAS,
  CanonicalMediaTypeSchema,
  canonicalJsonFromText,
  canonicalSha256,
  canonicalText,
  CanonicalizationError,
  sha256Hex,
  UuidV7Schema,
  type JsonValue
} from "@boardagent/contracts";

const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;

export type DocumentValidationCode =
  | "machine_readable_material_required"
  | "document_empty"
  | "document_too_large"
  | "document_schema_required"
  | "document_schema_forbidden"
  | "document_schema_invalid"
  | "invalid_canonical_content";

export class DocumentValidationError extends Error {
  public readonly code: DocumentValidationCode;
  public readonly remediation: string;

  public constructor(code: DocumentValidationCode, message: string, remediation: string) {
    super(message);
    this.name = "DocumentValidationError";
    this.code = code;
    this.remediation = remediation;
  }
}

export interface DocumentContributionInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly documentId: string;
  readonly title: string;
  readonly mediaType: string;
  readonly documentSchema: string | null;
  readonly body: Uint8Array;
}

export interface DocumentCanonicalMetadata {
  readonly schemaVersion: "boardagent.document-metadata.v1";
  readonly organizationId: string;
  readonly boardId: string;
  readonly documentId: string;
  readonly title: string;
  readonly mediaType:
    "text/markdown; charset=utf-8" | "text/plain; charset=utf-8" | "application/json";
  readonly documentSchema: string | null;
  readonly canonicalizationVersion: "RFC8785+NFC-LF-v1";
  readonly byteLength: number;
  readonly sha256: string;
}

export interface PreparedDocumentContribution {
  readonly organizationId: string;
  readonly boardId: string;
  readonly documentId: string;
  readonly title: string;
  readonly mediaType: DocumentCanonicalMetadata["mediaType"];
  readonly documentSchema: string | null;
  readonly canonicalizationVersion: "RFC8785+NFC-LF-v1";
  readonly canonicalBytes: Uint8Array;
  readonly canonicalText: string;
  readonly offeredByteLength: number;
  readonly offeredSha256: string;
  readonly byteLength: number;
  readonly sha256: string;
  readonly canonicalMetadata: DocumentCanonicalMetadata;
  readonly requestSha256: string;
}

function validateSchema(mediaType: string, documentSchema: string | null): string | null {
  if (mediaType === "application/json") {
    if (documentSchema === null) {
      throw new DocumentValidationError(
        "document_schema_required",
        "a versioned document schema is required for application/json",
        "Supply a schema identifier such as boardagent.board-pack.v1."
      );
    }
    if (!/^boardagent\.[a-z0-9_.-]+\.v[0-9]+$/u.test(documentSchema)) {
      throw new DocumentValidationError(
        "document_schema_invalid",
        "document schema must be a versioned boardagent identifier",
        "Use boardagent.<name>.v<number>."
      );
    }
    if (!documentBodySchema(documentSchema)) {
      throw new DocumentValidationError(
        "document_schema_invalid",
        "document schema is not in the supported versioned catalog",
        `Use a supported JSON document schema: ${SUPPORTED_JSON_DOCUMENT_SCHEMAS.join(", ")}; or submit canonical Markdown/plain text.`
      );
    }
    return documentSchema;
  }
  if (documentSchema !== null) {
    throw new DocumentValidationError(
      "document_schema_forbidden",
      "document schema is allowed only for application/json",
      "Remove documentSchema for Markdown or plain text."
    );
  }
  return null;
}

export function prepareDocumentContribution(
  input: DocumentContributionInput
): PreparedDocumentContribution {
  const media = CanonicalMediaTypeSchema.safeParse(input.mediaType);
  if (!media.success) {
    throw new DocumentValidationError(
      "machine_readable_material_required",
      "BoardAgent accepts only UTF-8 Markdown, plain text, or versioned strict JSON; rejected bytes were not retained.",
      "Submit a machine-readable Markdown, plain-text, or strict JSON source."
    );
  }
  if (input.body.byteLength === 0) {
    throw new DocumentValidationError(
      "document_empty",
      "canonical document content cannot be empty",
      "Submit at least one UTF-8 content byte."
    );
  }
  if (input.body.byteLength > MAX_DOCUMENT_BYTES) {
    throw new DocumentValidationError(
      "document_too_large",
      "document content exceeds the exact 10 MiB limit",
      "Split the machine-readable source into separately governed documents."
    );
  }

  const organizationId = UuidV7Schema.parse(input.organizationId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const documentId = UuidV7Schema.parse(input.documentId);
  const title = canonicalText(input.title);
  const documentSchema = validateSchema(media.data, input.documentSchema);
  let body: string;
  try {
    body =
      media.data === "application/json"
        ? canonicalJsonFromText(input.body)
        : canonicalText(input.body);
  } catch (error) {
    if (error instanceof CanonicalizationError) {
      throw new DocumentValidationError(
        "invalid_canonical_content",
        error.message,
        "Submit strict UTF-8 NFC/LF content; JSON must have unique decoded keys and finite numbers."
      );
    }
    throw error;
  }
  if (documentSchema !== null) {
    const validator = documentBodySchema(documentSchema);
    if (!validator || !validator.safeParse(JSON.parse(body)).success) {
      throw new DocumentValidationError(
        "document_schema_invalid",
        "document body does not match its declared versioned schema",
        `Follow the documented ${documentSchema} format, including its exact schemaVersion and required fields; rejected bytes were not retained.`
      );
    }
  }
  const canonicalBytes = new TextEncoder().encode(body);
  if (canonicalBytes.byteLength === 0 || canonicalBytes.byteLength > MAX_DOCUMENT_BYTES) {
    throw new DocumentValidationError(
      canonicalBytes.byteLength === 0 ? "document_empty" : "document_too_large",
      canonicalBytes.byteLength === 0
        ? "canonical document content cannot be empty"
        : "canonical document content exceeds the exact 10 MiB limit",
      "Submit bounded, nonempty machine-readable content."
    );
  }
  const sha256 = sha256Hex(canonicalBytes);
  CanonicalDocumentSchema.parse({
    schemaVersion: "boardagent.document.v1",
    documentId,
    title,
    mediaType: media.data,
    byteLength: canonicalBytes.byteLength,
    sha256,
    body
  });
  const canonicalMetadata: DocumentCanonicalMetadata = {
    schemaVersion: "boardagent.document-metadata.v1",
    organizationId,
    boardId,
    documentId,
    title,
    mediaType: media.data,
    documentSchema,
    canonicalizationVersion: "RFC8785+NFC-LF-v1",
    byteLength: canonicalBytes.byteLength,
    sha256
  };
  const requestSha256 = canonicalSha256(canonicalMetadata as unknown as JsonValue);
  return {
    organizationId,
    boardId,
    documentId,
    title,
    mediaType: media.data,
    documentSchema,
    canonicalizationVersion: "RFC8785+NFC-LF-v1",
    canonicalBytes,
    canonicalText: body,
    offeredByteLength: input.body.byteLength,
    offeredSha256: sha256Hex(input.body),
    byteLength: canonicalBytes.byteLength,
    sha256,
    canonicalMetadata,
    requestSha256
  };
}
