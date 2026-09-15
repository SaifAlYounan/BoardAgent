import type { JsonValue } from "@boardagent/contracts";

export interface SurfacePrincipal {
  readonly organizationId: string;
  readonly memberId: string;
  /** Canonical HTTPS origin of the protected MCP resource. */
  readonly serviceOrigin: string;
  /** Internal UUID, distinct from the protocol client identifier. */
  readonly clientId: string;
  readonly protocolClientId: string;
  readonly accessTokenRecordId: string;
  readonly tokenJti: string;
  readonly keyId: string;
  readonly scopes: readonly string[];
  readonly roles: readonly string[];
  readonly boardIds: readonly string[];
}

export interface SurfaceToolResult {
  readonly schema_version: "boardagent.tool-result.v1";
  readonly tool: string;
  readonly status: "ok" | "accepted" | "already_applied";
  readonly reference: string | null;
  readonly resource_uri: string | null;
  readonly data: JsonValue;
}

export interface PreparedHumanAction {
  readonly schema_version: "boardagent.prepared-human-action.v1";
  readonly stage_id: string;
  readonly action_code: string;
  readonly board_id: string | null;
  readonly target_type: string;
  readonly target_id: string | null;
  readonly package_sha256: string | null;
  readonly confirmation_code: string;
  readonly expires_at: string;
  readonly confirmation_lines: readonly string[];
  /** Strict, canonical payload that the final act will consume. */
  readonly canonical_payload: JsonValue;
}

export interface PersistHumanStageInput {
  readonly principal: SurfacePrincipal;
  readonly tool: string;
  readonly input: JsonValue;
  readonly prepared: PreparedHumanAction;
  readonly client_capabilities: JsonValue;
  readonly embedded_form: JsonValue;
  readonly embedded_result: JsonValue;
  readonly request_state: string;
  readonly prepared_request_id: Uint8Array;
}

export interface ResolveHumanActionInput {
  readonly principal: SurfacePrincipal;
  readonly tool: string;
  readonly input: JsonValue;
  readonly stage_id: string;
  readonly client_capabilities: JsonValue;
  readonly request_state: string;
  readonly retry_request_id: Uint8Array;
  readonly response_action: "accept" | "decline" | "cancel";
  readonly input_response: JsonValue | null;
}

export type HumanActionResolution =
  | { readonly confirmed: true; readonly result: SurfaceToolResult }
  | { readonly confirmed: false; readonly reason: string };

export interface SurfaceResourceResult {
  readonly uri: string;
  readonly media_type:
    | "application/json"
    | "application/octet-stream"
    | "text/markdown; charset=utf-8"
    | "text/plain; charset=utf-8";
  readonly text?: string;
  readonly blob_base64?: string;
}

/**
 * Secret-free application port for the recoverable vote-certificate signing step.
 * Implementations resolve the persisted non-secret locator to a file/KMS/HSM key;
 * private key material never crosses this boundary or enters PostgreSQL.
 */
export interface VoteCertificateSigningPort {
  signVoteCertificate(input: {
    readonly signingKeyId: string;
    readonly signingKeyLocator: string;
    readonly canonicalPayload: string;
    readonly payloadSha256: string;
  }): Promise<{ readonly signatureBase64Url: string }>;
}

/**
 * The executable application boundary. Routes and MCP handlers only validate and
 * translate protocol data; all authorization, locking, persistence and evidence live
 * behind this interface.
 */
export interface BoardAgentSurfaceService {
  executeRead(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<SurfaceToolResult>;
  executeDirect(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<SurfaceToolResult>;
  /** Read an exactly completed act after live authorization, without fresh consent or effects. */
  replayHumanAction?(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<SurfaceToolResult | null>;
  /** Pure/read-only preparation. It must not create a durable stage. */
  prepareHumanAction(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<PreparedHumanAction>;
  /** Rechecks authority and persists the exact state/form bytes before they are returned. */
  persistHumanStage(input: PersistHumanStageInput): Promise<void>;
  resolveHumanAction(input: ResolveHumanActionInput): Promise<HumanActionResolution>;
  readResource(principal: SurfacePrincipal, uri: URL): Promise<SurfaceResourceResult>;
}

export interface PrincipalView {
  readonly memberId: string;
  readonly displayName: string;
  readonly roles: readonly string[];
  readonly scopes: readonly string[];
  readonly boardIds: readonly string[];
  readonly onboardingCurrent: boolean;
  readonly secretaryContact: {
    readonly name: string;
    readonly contactText: string;
  };
}

export interface PendingActionView {
  readonly sequence: string;
  readonly kind: string;
  readonly objectId: string;
  readonly title: string;
  readonly occurredAt: string;
  readonly dueAt: string | null;
  readonly resourceUri: string;
}

export interface DocumentView {
  readonly documentId: string;
  readonly versionId: string;
  readonly boardId: string;
  readonly title: string;
  readonly mediaType:
    "application/json" | "text/markdown; charset=utf-8" | "text/plain; charset=utf-8";
  readonly sha256: string;
  readonly byteLength: number;
  readonly resourceUri: string;
}

export interface BallotStageView {
  readonly stageId: string;
  readonly voteId: string;
  readonly voteTitle: string;
  readonly memberName: string;
  readonly choice: "yes" | "no" | "abstain";
  readonly statement: string | null;
  readonly canonicalResolutionText: string;
  readonly canonicalResolutionSha256: string;
  readonly confirmationCode: string;
  readonly requestHash: string;
  readonly expiresAt: string;
}

export interface BallotConfirmationView {
  readonly ballotId: string;
  readonly voteId: string;
  readonly principalMemberId: string;
  readonly casterMemberId: string;
  readonly certificateResourceUri: string;
  readonly auditSequence: string;
}

export interface BoardAgentService {
  whoami(memberId: string): Promise<PrincipalView>;
  listPendingActions(
    memberId: string,
    afterSequence: string | null,
    limit: number
  ): Promise<readonly PendingActionView[]>;
  listDocuments(
    memberId: string,
    boardId: string,
    afterSequence: string | null,
    limit: number
  ): Promise<readonly DocumentView[]>;
  stageBallot(input: {
    memberId: string;
    clientId: string;
    tokenJti: string;
    voteId: string;
    choice: "yes" | "no" | "abstain";
    statement: string | null;
    requestHash: string;
  }): Promise<BallotStageView>;
  confirmBallot(input: {
    memberId: string;
    clientId: string;
    tokenJti: string;
    stageId: string;
    confirmationCode: string;
    requestHash: string;
    canonicalResolutionSha256: string;
  }): Promise<BallotConfirmationView>;
  rejectBallotStage(input: {
    memberId: string;
    clientId: string;
    tokenJti: string;
    stageId: string;
    reason: "declined" | "cancelled" | "invalid_response";
  }): Promise<void>;
}
