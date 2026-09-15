import { randomBytes } from "node:crypto";

import {
  Rfc3339UtcSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";
import {
  confirmOnboardingPublicationInTransaction,
  prepareOnboardingPublicationInTransaction,
  stageOnboardingPublicationInTransaction,
  isOnboardingPublicationTool,
  confirmIdentityAdministrationActionInTransaction,
  confirmExportDispositionInTransaction,
  confirmExportRequestInTransaction,
  confirmGovernanceAdministrationActionInTransaction,
  confirmWebhookAdministrationActionInTransaction,
  ExportScopeSchema,
  buildBoardArchiveRequest,
  buildBoardCreationRequest,
  buildBoardUpdateRequest,
  buildGovernanceProfileRequest,
  buildRulesetRequest,
  hashOpaqueIdentityProof,
  normalizeIdentityAdministrationAction,
  prepareIdentityAdministrationActionInTransaction,
  prepareExportDispositionInTransaction,
  prepareExportRequestInTransaction,
  prepareGovernanceAdministrationActionInTransaction,
  prepareWebhookAdministrationActionInTransaction,
  readOwnedWebhookMaterialInTransaction,
  resolveAuditExportRangeInTransaction,
  stageIdentityAdministrationActionInTransaction,
  stageExportDispositionInTransaction,
  stageExportRequestInTransaction,
  stageGovernanceAdministrationActionInTransaction,
  stageWebhookAdministrationActionInTransaction,
  testWebhookInTransaction,
  withRequestTransaction,
  type IdentityAdministrationAction,
  type ExportDispositionAction,
  type ExportScope,
  type GovernanceAdministrationRequest,
  type PreparedGovernanceAdministrationAction,
  type PreparedWebhookAdministrationAction,
  type SurfaceGovernanceCitation,
  type TransactionOptions,
  type WebhookAdministrationRequest
} from "@boardagent/db";
import { confirmationCode, uuidV7 } from "@boardagent/domain";
import { GovernanceProfileSchema, RulesetVersionSchema } from "@boardagent/ruleset";
import type { Pool, PoolClient } from "pg";

import type {
  HumanActionResolution,
  PersistHumanStageInput,
  PreparedHumanAction,
  ResolveHumanActionInput,
  SurfacePrincipal,
  SurfaceToolResult
} from "./ports.js";
import type { WebhookSecurityPort } from "./webhook-security.js";

const IDENTITY_HUMAN_TOOLS = new Set([
  "revoke_enrollment",
  "initiate_identity_recovery",
  "revoke_my_session",
  "block_oauth_client",
  "unblock_oauth_client",
  "link_external_identity",
  "unlink_external_identity"
]);
const EXPORT_REQUEST_TOOLS = new Set(["export_audit_chain", "export_system_data"]);
const EXPORT_DISPOSITION_TOOLS = new Set(["cancel_export", "delete_export_artifact"]);
const GOVERNANCE_ADMINISTRATION_TOOLS = new Set([
  "create_board",
  "update_board",
  "archive_board",
  "configure_board_governance",
  "manage_ruleset"
]);
const WEBHOOK_ADMINISTRATION_TOOLS = new Set([
  "configure_webhook",
  "rotate_webhook_secret",
  "disable_webhook"
]);
const TEST_WEBHOOK = "test_webhook" as const;
const SYSTEM_DATA_CLASSES = [
  "audit",
  "decisions",
  "documents",
  "governance",
  "identity_authority",
  "management",
  "meetings",
  "minutes_tasks",
  "operations"
] as const;

function secureBytes(entropy: (length: number) => Buffer, length: number): Buffer {
  const bytes = entropy(length);
  if (bytes.length !== length) throw new Error("secure entropy source returned the wrong length");
  return bytes;
}

function record(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("control-plane input must be an object");
  }
  return value as Readonly<Record<string, JsonValue>>;
}

function stringField(input: Readonly<Record<string, JsonValue>>, name: string): string {
  const value = input[name];
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  return value;
}

function numberField(input: Readonly<Record<string, JsonValue>>, name: string): number {
  const value = input[name];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  return value;
}

function nullableStringField(
  input: Readonly<Record<string, JsonValue>>,
  name: string
): string | null {
  const value = input[name];
  if (value === null) return null;
  if (typeof value !== "string") throw new TypeError(`${name} must be a string or null`);
  return value;
}

function governanceCitations(
  input: Readonly<Record<string, JsonValue>>
): readonly SurfaceGovernanceCitation[] {
  const value = input["citations"];
  if (!Array.isArray(value)) throw new TypeError("citations must be an array");
  return value.map((item) => {
    const citation = record(item);
    return {
      documentVersionId: UuidV7Schema.parse(stringField(citation, "document_version_id")),
      sourceDocumentSha256: Sha256HexSchema.parse(stringField(citation, "sha256")),
      clause: stringField(citation, "clause"),
      locator: stringField(citation, "locator")
    };
  });
}

function stringArrayField(
  input: Readonly<Record<string, JsonValue>>,
  name: string
): readonly string[] {
  const value = input[name];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new TypeError(`${name} must be a string array`);
  }
  return value as string[];
}

function exactServiceOrigin(value: string): string {
  const origin = new URL(value);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== value ||
    origin.username !== "" ||
    origin.password !== ""
  ) {
    throw new TypeError("surface principal requires one canonical HTTPS service origin");
  }
  return value;
}

function requestContext(principal: SurfacePrincipal) {
  return {
    organizationId: UuidV7Schema.parse(principal.organizationId),
    memberId: UuidV7Schema.parse(principal.memberId),
    clientId: UuidV7Schema.parse(principal.clientId),
    tokenJti: UuidV7Schema.parse(principal.tokenJti),
    boardIds: principal.boardIds.map((boardId) => UuidV7Schema.parse(boardId))
  } as const;
}

function toolResult(tool: string, reference: string, data: JsonValue): SurfaceToolResult {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "accepted",
    reference,
    resource_uri: null,
    data
  };
}

export interface ControlPlaneSurfaceOptions {
  readonly transaction?: TransactionOptions;
  readonly now?: () => Date;
  readonly entropy?: (length: number) => Buffer;
  readonly newId?: () => string;
  readonly webhookSecurity?: WebhookSecurityPort;
}

/**
 * Confirmed deployment/identity/operations actions kept out of the governance-domain
 * surface service. Every H action still uses the shared durable MRTR coordinator.
 */
export class ControlPlaneSurface {
  private readonly transaction: TransactionOptions;
  private readonly now: () => Date;
  private readonly entropy: (length: number) => Buffer;
  private readonly newId: () => string;
  private readonly webhookSecurity: WebhookSecurityPort | undefined;

  public constructor(
    private readonly pool: Pool,
    options: ControlPlaneSurfaceOptions = {}
  ) {
    this.transaction = { ...options.transaction, isolation: "serializable" };
    this.now = options.now ?? (() => new Date());
    this.entropy = options.entropy ?? randomBytes;
    this.newId =
      options.newId ?? (() => uuidV7(this.now().getTime(), secureBytes(this.entropy, 10)));
    this.webhookSecurity = options.webhookSecurity;
  }

  public handlesHumanTool(tool: string): boolean {
    return (
      isOnboardingPublicationTool(tool) ||
      IDENTITY_HUMAN_TOOLS.has(tool) ||
      EXPORT_REQUEST_TOOLS.has(tool) ||
      EXPORT_DISPOSITION_TOOLS.has(tool) ||
      GOVERNANCE_ADMINISTRATION_TOOLS.has(tool) ||
      WEBHOOK_ADMINISTRATION_TOOLS.has(tool)
    );
  }

  public handlesDirectTool(tool: string): boolean {
    return tool === TEST_WEBHOOK;
  }

  public async executeDirect(
    principal: SurfacePrincipal,
    tool: string,
    rawInput: JsonValue
  ): Promise<SurfaceToolResult> {
    if (!this.handlesDirectTool(tool)) {
      throw new Error(`control-plane direct tool is unavailable: ${tool}`);
    }
    const input = record(rawInput);
    const webhookId = UuidV7Schema.parse(stringField(input, "webhook_id"));
    const exactOrigin = exactServiceOrigin(principal.serviceOrigin);
    const security = this.webhookSecurityPort();
    const material = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) => readOwnedWebhookMaterialInTransaction(client, { webhookId, exactOrigin }),
      this.transaction
    );
    const endpoint = security.openEndpoint({
      organizationId: material.organizationId,
      memberId: material.memberId,
      webhookId,
      keyId: material.keyId,
      endpointCiphertext: material.endpointCiphertext
    });
    const validation = await security.validateEndpoint(endpoint);
    if (!safeHashEqual(validation.endpointSha256, material.endpointSha256)) {
      throw new Error("webhook endpoint fingerprint changed after authenticated decryption");
    }
    const tested = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) =>
        testWebhookInTransaction(client, {
          webhookId,
          exactOrigin,
          idempotencyRecordId: UuidV7Schema.parse(this.newId()),
          idempotencyKey: stringField(input, "idempotency_key"),
          notificationJobId: UuidV7Schema.parse(this.newId()),
          randomWakeId: secureBytes(this.entropy, 32),
          auditEventId: UuidV7Schema.parse(this.newId())
        }),
      this.transaction
    );
    return {
      schema_version: "boardagent.tool-result.v1",
      tool,
      status: tested.replayed ? "already_applied" : "accepted",
      reference: tested.notificationJobId,
      resource_uri: null,
      data: {
        schema_version: "boardagent.webhook-test-result.v1",
        webhook_id: webhookId,
        notification_job_id: tested.notificationJobId,
        state: "queued",
        contentless: true,
        replayed: tested.replayed,
        response_sha256: tested.responseSha256,
        ...(!tested.replayed ? { payload_sha256: tested.payloadSha256 } : {})
      }
    };
  }

  private identityAction(tool: string, rawInput: JsonValue): IdentityAdministrationAction {
    const input = record(rawInput);
    switch (tool) {
      case "revoke_enrollment":
        return normalizeIdentityAdministrationAction({
          kind: tool,
          invitationId: stringField(input, "invitation_id"),
          reason: stringField(input, "reason")
        });
      case "initiate_identity_recovery": {
        const disposition = stringField(input, "credential_disposition");
        if (disposition !== "revoke_all" && disposition !== "preserve_named") {
          throw new TypeError("credential_disposition is invalid");
        }
        return normalizeIdentityAdministrationAction({
          kind: tool,
          memberId: stringField(input, "member_id"),
          reason: stringField(input, "reason"),
          proofingMethod: stringField(input, "proofing_method"),
          credentialDisposition: disposition,
          preservedCredentialIds: stringArrayField(input, "preserved_credential_ids")
        });
      }
      case "revoke_my_session":
        return normalizeIdentityAdministrationAction({
          kind: tool,
          sessionId: stringField(input, "session_id"),
          recentAuthProofSha256: hashOpaqueIdentityProof(stringField(input, "recent_auth_proof"))
        });
      case "block_oauth_client":
      case "unblock_oauth_client":
        return normalizeIdentityAdministrationAction({
          kind: tool,
          clientId: stringField(input, "client_id"),
          reason: stringField(input, "reason")
        });
      case "link_external_identity":
        return normalizeIdentityAdministrationAction({
          kind: tool,
          memberId: stringField(input, "member_id"),
          issuer: stringField(input, "issuer"),
          subject: stringField(input, "subject"),
          browserProofSha256: hashOpaqueIdentityProof(stringField(input, "browser_proof"))
        });
      case "unlink_external_identity":
        return normalizeIdentityAdministrationAction({
          kind: tool,
          identityLinkId: stringField(input, "identity_link_id"),
          reason: stringField(input, "reason")
        });
      default:
        throw new Error(`identity administration tool is unavailable: ${tool}`);
    }
  }

  private exportDispositionAction(tool: string, rawInput: JsonValue): ExportDispositionAction {
    const input = record(rawInput);
    const publicId = stringField(input, "export_id");
    if (tool === "cancel_export") return { kind: tool, publicId };
    if (tool === "delete_export_artifact") return { kind: tool, publicId };
    throw new Error(`export disposition tool is unavailable: ${tool}`);
  }

  private governanceAction(tool: string, rawInput: JsonValue): GovernanceAdministrationRequest {
    const input = record(rawInput);
    switch (tool) {
      case "create_board":
        return buildBoardCreationRequest({
          boardId: stringField(input, "board_id"),
          slug: stringField(input, "slug"),
          name: stringField(input, "name"),
          timezone: stringField(input, "timezone"),
          initialSettings: input["initial_settings"] ?? null,
          secretaryMemberId: stringField(input, "secretary_member_id"),
          boardVersionId: this.newId()
        });
      case "update_board":
        return buildBoardUpdateRequest({
          boardId: stringField(input, "board_id"),
          expectedRowVersion: numberField(input, "expected_row_version"),
          name: stringField(input, "name"),
          timezone: stringField(input, "timezone"),
          settings: input["settings"] ?? null,
          reason: stringField(input, "reason"),
          boardVersionId: this.newId()
        });
      case "archive_board":
        return buildBoardArchiveRequest({
          boardId: stringField(input, "board_id"),
          reason: stringField(input, "reason")
        });
      case "configure_board_governance": {
        const wrapper = record(input["profile"] ?? null);
        if (stringField(wrapper, "schema_version") !== "boardagent.governance-profile.v1") {
          throw new TypeError("profile schema_version is unsupported");
        }
        const profile = GovernanceProfileSchema.parse(wrapper["values"]);
        const roleCount = new Set(profile.seats.map(({ role }) => role)).size;
        const citationCount =
          profile.sourceAgreements.length +
          profile.templates.reduce((count, template) => count + template.citations.length, 0);
        return buildGovernanceProfileRequest({
          boardId: stringField(input, "board_id"),
          expectedProfileId: nullableStringField(input, "expected_profile_id"),
          profile,
          citations: governanceCitations(input),
          generatedIds: Array.from(
            { length: roleCount + profile.templates.length + citationCount },
            () => this.newId()
          ),
          reason: stringField(input, "reason")
        });
      }
      case "manage_ruleset": {
        const wrapper = record(input["ruleset"] ?? null);
        if (stringField(wrapper, "schema_version") !== "boardagent.ruleset.v1") {
          throw new TypeError("ruleset schema_version is unsupported");
        }
        const ruleset = RulesetVersionSchema.parse(wrapper["values"]);
        const citationCount = ruleset.rules.reduce(
          (count, rule) => count + rule.citations.length,
          0
        );
        return buildRulesetRequest({
          boardId: stringField(input, "board_id"),
          expectedRulesetId: nullableStringField(input, "expected_ruleset_id"),
          ruleset,
          citations: governanceCitations(input),
          generatedMatterTypeIds: Array.from({ length: ruleset.matterTypes.length }, () =>
            this.newId()
          ),
          generatedCitationIds: Array.from({ length: citationCount }, () => this.newId()),
          reason: stringField(input, "reason")
        });
      }
      default:
        throw new Error(`governance administration tool is unavailable: ${tool}`);
    }
  }

  private webhookSecurityPort(): WebhookSecurityPort {
    if (!this.webhookSecurity) {
      throw new Error("webhook support is disabled or has no active encryption key");
    }
    return this.webhookSecurity;
  }

  private async webhookAction(
    principal: SurfacePrincipal,
    tool: string,
    rawInput: JsonValue
  ): Promise<WebhookAdministrationRequest> {
    const input = record(rawInput);
    const webhookId = UuidV7Schema.parse(stringField(input, "webhook_id"));
    const exactOrigin = exactServiceOrigin(principal.serviceOrigin);
    const security = this.webhookSecurityPort();
    if (tool === "configure_webhook") {
      const protectedEndpoint = await security.protectEndpoint({
        organizationId: principal.organizationId,
        memberId: principal.memberId,
        webhookId,
        endpoint: stringField(input, "endpoint")
      });
      const classes = stringArrayField(input, "event_classes");
      if (
        classes.some(
          (value) => value !== "pending_action" && value !== "notice" && value !== "security"
        )
      ) {
        throw new TypeError("webhook event class is invalid");
      }
      return {
        kind: tool,
        webhookId,
        endpointCiphertext: protectedEndpoint.endpointCiphertext.toString("base64"),
        endpointSha256: Sha256HexSchema.parse(protectedEndpoint.endpointSha256),
        validationReceiptSha256: Sha256HexSchema.parse(protectedEndpoint.validationReceiptSha256),
        eventClasses: [...classes] as Array<"pending_action" | "notice" | "security">,
        keyId: UuidV7Schema.parse(protectedEndpoint.keyId),
        recentAuthProofSha256: Sha256HexSchema.parse(
          hashOpaqueIdentityProof(stringField(input, "recent_auth_proof"))
        ),
        exactOrigin
      };
    }
    if (tool === "rotate_webhook_secret") {
      return {
        kind: tool,
        webhookId,
        keyId: UuidV7Schema.parse(security.activeKeyId),
        recentAuthProofSha256: Sha256HexSchema.parse(
          hashOpaqueIdentityProof(stringField(input, "recent_auth_proof"))
        ),
        exactOrigin
      };
    }
    if (tool === "disable_webhook") {
      return {
        kind: tool,
        webhookId,
        keyId: null,
        reason: stringField(input, "reason"),
        exactOrigin
      };
    }
    throw new Error(`webhook administration tool is unavailable: ${tool}`);
  }

  private async exportScope(
    client: PoolClient,
    principal: SurfacePrincipal,
    tool: string,
    rawInput: JsonValue
  ): Promise<ExportScope> {
    const input = record(rawInput);
    hashOpaqueIdentityProof(stringField(input, "recent_auth_proof"));
    const boardValue = input["board_id"];
    const boardId = boardValue === null ? null : UuidV7Schema.parse(boardValue);
    if (tool === "export_audit_chain") {
      const requestedTo = input["to_sequence"];
      if (requestedTo !== null && typeof requestedTo !== "string") {
        throw new TypeError("to_sequence must be a string or null");
      }
      const range = await resolveAuditExportRangeInTransaction(client, {
        boardId,
        firstSequence: stringField(input, "from_sequence"),
        lastSequence: requestedTo,
        exactOrigin: exactServiceOrigin(principal.serviceOrigin)
      });
      return ExportScopeSchema.parse({
        schemaVersion: "boardagent.export-scope.v1",
        exportType: "audit_chain",
        organizationId: principal.organizationId,
        boardId,
        firstSequence: range.firstSequence,
        lastSequence: range.lastSequence,
        includeCheckpoints: true,
        includePublicKeys: true
      });
    }
    if (tool !== "export_system_data") {
      throw new Error(`export request tool is unavailable: ${tool}`);
    }
    const scope = stringField(input, "scope");
    if (scope !== "organization" && scope !== "board" && scope !== "member_portability") {
      throw new TypeError("system export scope is invalid");
    }
    const purpose = canonicalText(stringField(input, "purpose"));
    return ExportScopeSchema.parse({
      schemaVersion: "boardagent.export-scope.v1",
      exportType: "system_data",
      organizationId: principal.organizationId,
      boardId: scope === "board" ? boardId : null,
      scope,
      memberId: scope === "member_portability" ? principal.memberId : null,
      purpose,
      dataClasses: SYSTEM_DATA_CLASSES,
      includeCanonicalContent: true,
      excludeSecretMaterial: true
    });
  }

  private exportConfirmationLines(
    actionCode: string,
    targetId: string,
    scopeSha256: string,
    code: string
  ): readonly string[] {
    return [
      "BOARDAGENT EXPORT CONFIRMATION",
      `Action: ${actionCode}`,
      `Export request: ${targetId}`,
      `Frozen scope SHA-256: ${scopeSha256}`,
      "The export is asynchronous, encrypted, secret-free, and expires after 24 hours.",
      `Confirmation code: ${code}`
    ];
  }

  private governanceConfirmationLines(
    prepared: PreparedGovernanceAdministrationAction,
    code: string
  ): readonly string[] {
    return [
      "BOARDAGENT GOVERNANCE ADMINISTRATION CONFIRMATION",
      `Action: ${prepared.actionCode}`,
      `Board: ${prepared.boardId}`,
      `Target: ${prepared.targetType}/${prepared.targetId}`,
      `Exact payload SHA-256: ${prepared.payloadSha256}`,
      ...(prepared.packageSha256 === null
        ? []
        : [`Frozen governance package SHA-256: ${prepared.packageSha256}`]),
      "This creates or changes durable board authority and never edits prior versions.",
      `Confirmation code: ${code}`
    ];
  }

  private webhookConfirmationLines(
    prepared: PreparedWebhookAdministrationAction,
    rawInput: JsonValue,
    code: string
  ): readonly string[] {
    const input = record(rawInput);
    const endpoint =
      prepared.actionCode === "configure_webhook"
        ? stringField(input, "endpoint")
        : "existing encrypted endpoint";
    return [
      "BOARDAGENT WEBHOOK SECURITY CONFIRMATION",
      `Action: ${prepared.actionCode}`,
      `Webhook: ${prepared.targetId}`,
      `Endpoint: ${endpoint}`,
      `Exact payload SHA-256: ${prepared.payloadSha256}`,
      prepared.actionCode === "disable_webhook"
        ? "Result: the endpoint is disabled and receives no more wake-ups."
        : "Result: a new per-member HMAC secret is displayed once and cannot be replayed.",
      "Wake-ups contain no governance content, only class, random ID, and time.",
      `Confirmation code: ${code}`
    ];
  }

  private confirmationLines(
    prepared: Awaited<ReturnType<typeof prepareIdentityAdministrationActionInTransaction>>,
    code: string
  ): readonly string[] {
    return [
      "BOARDAGENT IDENTITY ADMINISTRATION CONFIRMATION",
      `Action: ${prepared.actionCode}`,
      `Target: ${prepared.targetType}/${prepared.targetId}`,
      `Exact payload SHA-256: ${prepared.payloadSha256}`,
      "This may revoke enrollment, credentials, sessions, client access, or an identity link.",
      ...(prepared.actionCode === "initiate_identity_recovery"
        ? [
            "For another active human verified in person or by verified-number call, this issues a one-use, ten-minute replacement-passkey handoff.",
            "The replacement stays inactive until you obtain the registered person's ten-minute human code and freshly confirm their identity and exact credential.",
            "Deliver the handoff through a separately trusted channel. A lost response requires a new confirmed recovery."
          ]
        : []),
      `Confirmation code: ${code}`
    ];
  }

  public async prepareHumanAction(
    principal: SurfacePrincipal,
    tool: string,
    input: JsonValue
  ): Promise<PreparedHumanAction> {
    if (!this.handlesHumanTool(tool)) throw new Error(`control-plane tool is unavailable: ${tool}`);
    const code = confirmationCode();
    if (isOnboardingPublicationTool(tool)) {
      const p = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (c) => prepareOnboardingPublicationInTransaction(c, tool, input),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: tool,
        board_id: p.boardId,
        target_type: p.targetType,
        target_id: p.targetId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(new Date(this.now().getTime() + 600_000).toISOString()),
        confirmation_lines: [
          "BOARDAGENT ONBOARDING PUBLICATION CONFIRMATION",
          tool === "publish_secretary_support"
            ? `Support contacts for board: ${p.boardId}`
            : `Organization-wide terms for role: ${String(p.request["seat_role"])}`,
          ...(p.canonicalPayload.initialAdministrativeSetup
            ? [
                "First support version: company administrator setup. This grants no board seat or continuing secretary powers."
              ]
            : []),
          `New version: ${p.version}; version ID: ${p.targetId}`,
          `Replaces: ${String(p.canonicalPayload.previousVersionId ?? "no previous version")}`,
          `Content SHA-256: ${p.contentSha256}`,
          "Exact content:",
          p.canonicalPayload.canonicalContent,
          `Reason: ${String(p.request["reason"])}`,
          "Effective immediately. Affected people must personally accept this version before ordinary board work. Previous versions and attestations remain unchanged.",
          `Confirmation code: ${code}`
        ],
        canonical_payload: p.canonicalPayload
      };
    }
    if (WEBHOOK_ADMINISTRATION_TOOLS.has(tool)) {
      const action = await this.webhookAction(principal, tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) => prepareWebhookAdministrationActionInTransaction(client, action),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: null,
        target_type: "webhook",
        target_id: prepared.targetId,
        package_sha256: null,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(new Date(this.now().getTime() + 600_000).toISOString()),
        confirmation_lines: this.webhookConfirmationLines(prepared, input, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (GOVERNANCE_ADMINISTRATION_TOOLS.has(tool)) {
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          prepareGovernanceAdministrationActionInTransaction(
            client,
            this.governanceAction(tool, input)
          ),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(new Date(this.now().getTime() + 600_000).toISOString()),
        confirmation_lines: this.governanceConfirmationLines(prepared, code),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (EXPORT_REQUEST_TOOLS.has(tool)) {
      const exportRequestId = UuidV7Schema.parse(this.newId());
      const publicId = secureBytes(this.entropy, 32);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        async (client) =>
          prepareExportRequestInTransaction(client, {
            exportRequestId,
            publicId,
            scope: await this.exportScope(client, principal, tool, input),
            exactOrigin: exactServiceOrigin(principal.serviceOrigin)
          }),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.exportRequestId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(new Date(this.now().getTime() + 600_000).toISOString()),
        confirmation_lines: this.exportConfirmationLines(
          prepared.actionCode,
          prepared.exportRequestId,
          prepared.packageSha256,
          code
        ),
        canonical_payload: prepared.canonicalPayload
      };
    }
    if (EXPORT_DISPOSITION_TOOLS.has(tool)) {
      const action = this.exportDispositionAction(tool, input);
      const prepared = await withRequestTransaction(
        this.pool,
        requestContext(principal),
        (client) =>
          prepareExportDispositionInTransaction(
            client,
            action,
            exactServiceOrigin(principal.serviceOrigin)
          ),
        this.transaction
      );
      return {
        schema_version: "boardagent.prepared-human-action.v1",
        stage_id: UuidV7Schema.parse(this.newId()),
        action_code: prepared.actionCode,
        board_id: prepared.boardId,
        target_type: prepared.targetType,
        target_id: prepared.targetId,
        package_sha256: prepared.packageSha256,
        confirmation_code: code,
        expires_at: Rfc3339UtcSchema.parse(new Date(this.now().getTime() + 600_000).toISOString()),
        confirmation_lines: this.exportConfirmationLines(
          prepared.actionCode,
          prepared.targetId,
          prepared.packageSha256,
          code
        ),
        canonical_payload: prepared.canonicalPayload
      };
    }
    const action = this.identityAction(tool, input);
    const prepared = await withRequestTransaction(
      this.pool,
      requestContext(principal),
      (client) => prepareIdentityAdministrationActionInTransaction(client, action),
      this.transaction
    );
    return {
      schema_version: "boardagent.prepared-human-action.v1",
      stage_id: UuidV7Schema.parse(this.newId()),
      action_code: prepared.actionCode,
      board_id: null,
      target_type: prepared.targetType,
      target_id: prepared.targetId,
      package_sha256: null,
      confirmation_code: code,
      expires_at: Rfc3339UtcSchema.parse(new Date(this.now().getTime() + 600_000).toISOString()),
      confirmation_lines: this.confirmationLines(prepared, code),
      canonical_payload: prepared.canonicalPayload
    };
  }

  public async persistHumanStage(input: PersistHumanStageInput): Promise<void> {
    if (!this.handlesHumanTool(input.tool)) {
      throw new Error(`control-plane tool is unavailable: ${input.tool}`);
    }
    if (isOnboardingPublicationTool(input.tool)) {
      const tool = input.tool;
      if (
        input.prepared.action_code !== tool ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      )
        throw new Error("invalid publication confirmation");
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (c) => {
          const staged = await stageOnboardingPublicationInTransaction(c, {
            tool,
            request: input.input,
            expectedPayloadSha256: canonicalSha256(input.prepared.canonical_payload),
            stage: {
              stageId: UuidV7Schema.parse(input.prepared.stage_id),
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: this.newId(),
                stageCreated: this.newId(),
                elicitationSent: this.newId()
              }
            }
          });
          if (
            staged.boardId !== input.prepared.board_id ||
            staged.targetType !== input.prepared.target_type ||
            staged.targetId !== input.prepared.target_id
          )
            throw new Error("publication target changed before persistence");
        },
        this.transaction
      );
      return;
    }
    if (WEBHOOK_ADMINISTRATION_TOOLS.has(input.tool)) {
      if (
        input.prepared.action_code !== input.tool ||
        input.prepared.board_id !== null ||
        input.prepared.target_type !== "webhook" ||
        input.prepared.target_id === null ||
        input.prepared.package_sha256 !== null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared webhook action has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      const prepared: PreparedWebhookAdministrationAction = {
        actionCode: input.tool as PreparedWebhookAdministrationAction["actionCode"],
        boardId: null,
        targetType: "webhook",
        targetId: UuidV7Schema.parse(input.prepared.target_id),
        canonicalSchema: "boardagent.webhook-administration.v1",
        canonicalPayload: input.prepared.canonical_payload,
        payloadSha256: canonicalSha256(input.prepared.canonical_payload),
        packageSha256: null
      };
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageWebhookAdministrationActionInTransaction(client, {
            prepared,
            stage: {
              stageId: UuidV7Schema.parse(input.prepared.stage_id),
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.stageId !== input.prepared.stage_id ||
            staged.actionCode !== input.tool ||
            staged.targetId !== input.prepared.target_id ||
            !safeHashEqual(staged.payloadSha256, prepared.payloadSha256) ||
            staged.packageSha256 !== null
          ) {
            throw new Error("persisted webhook action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (GOVERNANCE_ADMINISTRATION_TOOLS.has(input.tool)) {
      const targetType = input.prepared.target_type;
      if (
        input.prepared.action_code !== input.tool ||
        input.prepared.board_id === null ||
        input.prepared.target_id === null ||
        (targetType !== "board" &&
          targetType !== "governance_profile" &&
          targetType !== "ruleset") ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared governance action has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      const prepared: PreparedGovernanceAdministrationAction = {
        actionCode: input.tool as GovernanceAdministrationRequest["actionCode"],
        boardId: UuidV7Schema.parse(input.prepared.board_id),
        targetType,
        targetId: UuidV7Schema.parse(input.prepared.target_id),
        canonicalSchema: "boardagent.governance-administration.v1",
        canonicalPayload: input.prepared.canonical_payload,
        payloadSha256: canonicalSha256(input.prepared.canonical_payload),
        packageSha256: input.prepared.package_sha256
      };
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageGovernanceAdministrationActionInTransaction(client, {
            prepared,
            stage: {
              stageId: UuidV7Schema.parse(input.prepared.stage_id),
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.stageId !== input.prepared.stage_id ||
            staged.actionCode !== input.tool ||
            staged.boardId !== input.prepared.board_id ||
            staged.targetId !== input.prepared.target_id ||
            staged.payloadSha256 !== prepared.payloadSha256 ||
            staged.packageSha256 !== prepared.packageSha256
          ) {
            throw new Error("persisted governance action changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (EXPORT_REQUEST_TOOLS.has(input.tool)) {
      const payload = record(input.prepared.canonical_payload);
      const exportRequestId = UuidV7Schema.parse(input.prepared.target_id);
      const publicIdText = stringField(payload, "publicId");
      const publicId = Buffer.from(publicIdText, "base64url");
      if (
        input.prepared.action_code !== input.tool ||
        input.prepared.target_type !== "export_request" ||
        publicId.length !== 32 ||
        publicId.toString("base64url") !== publicIdText ||
        payload["exportRequestId"] !== exportRequestId ||
        input.prepared.package_sha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared export request has an invalid protected shape");
      }
      const scope = ExportScopeSchema.parse(payload["scope"]);
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageExportRequestInTransaction(client, {
            exportRequestId,
            publicId,
            scope,
            expiresAt: stringField(payload, "expiresAt"),
            stage: {
              stageId: UuidV7Schema.parse(input.prepared.stage_id),
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.stageId !== input.prepared.stage_id ||
            staged.exportRequestId !== exportRequestId ||
            !safeHashEqual(staged.scopeSha256, input.prepared.package_sha256!) ||
            !safeHashEqual(staged.payloadSha256, canonicalSha256(input.prepared.canonical_payload))
          ) {
            throw new Error("persisted export request changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (EXPORT_DISPOSITION_TOOLS.has(input.tool)) {
      const action = this.exportDispositionAction(input.tool, input.input);
      const targetId = UuidV7Schema.parse(input.prepared.target_id);
      if (
        input.prepared.action_code !== input.tool ||
        input.prepared.target_type !== "export_request" ||
        input.prepared.package_sha256 === null ||
        !/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)
      ) {
        throw new Error("prepared export disposition has an invalid protected shape");
      }
      Rfc3339UtcSchema.parse(input.prepared.expires_at);
      await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const staged = await stageExportDispositionInTransaction(client, {
            action,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            stage: {
              stageId: UuidV7Schema.parse(input.prepared.stage_id),
              inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
              nonce: secureBytes(this.entropy, 32),
              confirmationCode: input.prepared.confirmation_code,
              accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              embeddedForm: input.embedded_form,
              embeddedResult: input.embedded_result,
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              preparedRequestId: input.prepared_request_id,
              auditEventIds: {
                stageReplaced: UuidV7Schema.parse(this.newId()),
                stageCreated: UuidV7Schema.parse(this.newId()),
                elicitationSent: UuidV7Schema.parse(this.newId())
              }
            }
          });
          if (
            staged.stageId !== input.prepared.stage_id ||
            staged.targetId !== targetId ||
            !safeHashEqual(staged.packageSha256, input.prepared.package_sha256!) ||
            !safeHashEqual(staged.payloadSha256, canonicalSha256(input.prepared.canonical_payload))
          ) {
            throw new Error("persisted export disposition changed after presentation");
          }
        },
        this.transaction
      );
      return;
    }
    if (input.prepared.action_code !== input.tool || input.prepared.board_id !== null) {
      throw new Error("prepared identity administration action changed before persistence");
    }
    const targetId = UuidV7Schema.parse(input.prepared.target_id);
    const action = this.identityAction(input.tool, input.input);
    Rfc3339UtcSchema.parse(input.prepared.expires_at);
    if (!/^[A-Z2-9]{8}$/u.test(input.prepared.confirmation_code)) {
      throw new Error("prepared identity administration confirmation code is invalid");
    }
    await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      async (client) => {
        const staged = await stageIdentityAdministrationActionInTransaction(client, {
          action,
          stage: {
            stageId: UuidV7Schema.parse(input.prepared.stage_id),
            inputRequiredAttemptId: UuidV7Schema.parse(this.newId()),
            nonce: secureBytes(this.entropy, 32),
            confirmationCode: input.prepared.confirmation_code,
            accessTokenRecordId: UuidV7Schema.parse(input.principal.accessTokenRecordId),
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            embeddedForm: input.embedded_form,
            embeddedResult: input.embedded_result,
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            preparedRequestId: input.prepared_request_id,
            auditEventIds: {
              stageReplaced: UuidV7Schema.parse(this.newId()),
              stageCreated: UuidV7Schema.parse(this.newId()),
              elicitationSent: UuidV7Schema.parse(this.newId())
            }
          }
        });
        if (
          staged.actionCode !== input.tool ||
          staged.targetId !== targetId ||
          staged.targetType !== input.prepared.target_type ||
          !safeHashEqual(staged.payloadSha256, canonicalSha256(input.prepared.canonical_payload)) ||
          staged.packageSha256 !== null
        ) {
          throw new Error("persisted identity administration action changed after presentation");
        }
      },
      this.transaction
    );
  }

  public async resolveHumanAction(input: ResolveHumanActionInput): Promise<HumanActionResolution> {
    if (!this.handlesHumanTool(input.tool)) {
      throw new Error(`control-plane tool is unavailable: ${input.tool}`);
    }
    if (isOnboardingPublicationTool(input.tool)) {
      const tool = input.tool;
      const resolution = await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (c) =>
          confirmOnboardingPublicationInTransaction(c, {
            tool,
            request: input.input,
            auditEventId: this.newId(),
            confirmation: {
              stageId: UuidV7Schema.parse(input.stage_id),
              consentRecordId: this.newId(),
              retryRequestId: input.retry_request_id,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              responseAction: input.response_action,
              inputResponse: input.input_response,
              auditEventIds: { consentRecorded: this.newId(), consentRejected: this.newId() }
            }
          }),
        this.transaction
      );
      return resolution.confirmed
        ? {
            confirmed: true,
            result: toolResult(tool, resolution.value.versionId, {
              schema_version: "boardagent.onboarding-publication-result.v1",
              version_id: resolution.value.versionId,
              version: resolution.value.version,
              content_sha256: resolution.value.contentSha256,
              board_id: resolution.value.boardId,
              reattestation_required: true
            })
          }
        : { confirmed: false, reason: resolution.reason };
    }
    if (WEBHOOK_ADMINISTRATION_TOOLS.has(input.tool)) {
      const security = this.webhookSecurityPort();
      if (input.tool === "configure_webhook" && input.response_action === "accept") {
        await security.validateEndpoint(stringField(record(input.input), "endpoint"));
      }
      const secret =
        input.tool === "disable_webhook" || input.response_action !== "accept"
          ? null
          : security.createSecret({
              organizationId: input.principal.organizationId,
              memberId: input.principal.memberId,
              webhookId: stringField(record(input.input), "webhook_id")
            });
      const resolution = await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (client) =>
          confirmWebhookAdministrationActionInTransaction(client, {
            auditEventId: UuidV7Schema.parse(this.newId()),
            secretMaterial:
              secret === null
                ? null
                : {
                    keyId: secret.keyId,
                    secretCiphertext: secret.secretCiphertext,
                    secretSha256: secret.secretSha256
                  },
            confirmation: {
              stageId: UuidV7Schema.parse(input.stage_id),
              consentRecordId: UuidV7Schema.parse(this.newId()),
              retryRequestId: input.retry_request_id,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              responseAction: input.response_action,
              inputResponse: input.input_response,
              auditEventIds: {
                consentRecorded: UuidV7Schema.parse(this.newId()),
                consentRejected: UuidV7Schema.parse(this.newId())
              }
            }
          }),
        this.transaction
      );
      if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
      return {
        confirmed: true,
        result: toolResult(input.tool, resolution.value.webhookId, {
          schema_version: "boardagent.webhook-administration-result.v1",
          ...record(resolution.value.data),
          secret: secret?.secret ?? null,
          secret_once: secret !== null,
          signature_header: secret === null ? null : "X-BoardAgent-Signature"
        })
      };
    }
    if (GOVERNANCE_ADMINISTRATION_TOOLS.has(input.tool)) {
      const resolution = await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (client) =>
          confirmGovernanceAdministrationActionInTransaction(client, {
            auditEventId: UuidV7Schema.parse(this.newId()),
            confirmation: {
              stageId: UuidV7Schema.parse(input.stage_id),
              consentRecordId: UuidV7Schema.parse(this.newId()),
              retryRequestId: input.retry_request_id,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              responseAction: input.response_action,
              inputResponse: input.input_response,
              auditEventIds: {
                consentRecorded: UuidV7Schema.parse(this.newId()),
                consentRejected: UuidV7Schema.parse(this.newId())
              }
            }
          }),
        this.transaction
      );
      if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
      return {
        confirmed: true,
        result: toolResult(input.tool, resolution.value.targetId, {
          schema_version: "boardagent.governance-administration-result.v1",
          ...record(resolution.value.data)
        })
      };
    }
    if (EXPORT_REQUEST_TOOLS.has(input.tool)) {
      const resolution = await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        async (client) => {
          const stage = await client.query<{ target_id: string }>(
            `select target_id from action_stages
              where id=$1 and action_code=$2 and target_type='export_request'`,
            [UuidV7Schema.parse(input.stage_id), input.tool]
          );
          const exportRequestId = UuidV7Schema.parse(stage.rows[0]?.target_id);
          return confirmExportRequestInTransaction(client, {
            exportRequestId,
            jobId: UuidV7Schema.parse(this.newId()),
            jobIdempotencyKey: `export-build-${canonicalSha256(input.input)}`,
            exportRequestedAuditEventId: UuidV7Schema.parse(this.newId()),
            confirmation: {
              stageId: UuidV7Schema.parse(input.stage_id),
              consentRecordId: UuidV7Schema.parse(this.newId()),
              retryRequestId: input.retry_request_id,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              responseAction: input.response_action,
              inputResponse: input.input_response,
              auditEventIds: {
                consentRecorded: UuidV7Schema.parse(this.newId()),
                consentRejected: UuidV7Schema.parse(this.newId())
              }
            }
          });
        },
        this.transaction
      );
      if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
      return {
        confirmed: true,
        result: toolResult(input.tool, resolution.value.publicId, {
          schema_version: "boardagent.export-request-result.v1",
          export_id: resolution.value.publicId,
          request_id: resolution.value.exportRequestId,
          scope_sha256: resolution.value.scopeSha256,
          state: resolution.value.state,
          job_id: resolution.value.jobId
        })
      };
    }
    if (EXPORT_DISPOSITION_TOOLS.has(input.tool)) {
      const action = this.exportDispositionAction(input.tool, input.input);
      const resolution = await withRequestTransaction(
        this.pool,
        requestContext(input.principal),
        (client) =>
          confirmExportDispositionInTransaction(client, {
            action,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            cleanupJobId: UuidV7Schema.parse(this.newId()),
            cleanupJobIdempotencyKey: `export-cleanup-${canonicalSha256(input.input)}`,
            exportCancelledAuditEventId: UuidV7Schema.parse(this.newId()),
            confirmation: {
              stageId: UuidV7Schema.parse(input.stage_id),
              consentRecordId: UuidV7Schema.parse(this.newId()),
              retryRequestId: input.retry_request_id,
              originalArguments: input.input,
              clientCapabilities: input.client_capabilities,
              exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
              requestStateBytes: Buffer.from(input.request_state, "utf8"),
              responseAction: input.response_action,
              inputResponse: input.input_response,
              auditEventIds: {
                consentRecorded: UuidV7Schema.parse(this.newId()),
                consentRejected: UuidV7Schema.parse(this.newId())
              }
            }
          }),
        this.transaction
      );
      if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
      return {
        confirmed: true,
        result: toolResult(input.tool, resolution.value.publicId, {
          schema_version: "boardagent.export-disposition-result.v1",
          export_id: resolution.value.publicId,
          request_id: resolution.value.exportRequestId,
          state: resolution.value.state,
          cleanup_job_id: resolution.value.cleanupJobId
        })
      };
    }
    const action = this.identityAction(input.tool, input.input);
    const recoveryToken =
      action.kind === "initiate_identity_recovery"
        ? secureBytes(this.entropy, 32).toString("base64url")
        : undefined;
    let replacement: { expires_at: string } | null = null;
    const resolution = await withRequestTransaction(
      this.pool,
      requestContext(input.principal),
      async (client) => {
        replacement = null;
        const outcome = await confirmIdentityAdministrationActionInTransaction(client, {
          action,
          recoveryRequestId: UuidV7Schema.parse(this.newId()),
          auditEventId: UuidV7Schema.parse(this.newId()),
          confirmation: {
            stageId: UuidV7Schema.parse(input.stage_id),
            consentRecordId: UuidV7Schema.parse(this.newId()),
            retryRequestId: input.retry_request_id,
            originalArguments: input.input,
            clientCapabilities: input.client_capabilities,
            exactOrigin: exactServiceOrigin(input.principal.serviceOrigin),
            requestStateBytes: Buffer.from(input.request_state, "utf8"),
            responseAction: input.response_action,
            inputResponse: input.input_response,
            auditEventIds: {
              consentRecorded: UuidV7Schema.parse(this.newId()),
              consentRejected: UuidV7Schema.parse(this.newId())
            }
          }
        });
        if (outcome.confirmed && recoveryToken !== undefined) {
          const recoveryId = record(outcome.value.data)["recoveryRequestId"];
          replacement = (
            await client.query("select boardagent_issue_recovery_registration($1,$2) as grant", [
              recoveryId,
              Buffer.from(sha256Hex(recoveryToken), "hex")
            ])
          ).rows[0]?.grant as { expires_at: string } | null;
        }
        return outcome;
      },
      this.transaction
    );
    if (!resolution.confirmed) return { confirmed: false, reason: resolution.reason };
    return {
      confirmed: true,
      result: toolResult(input.tool, resolution.value.targetId, {
        schema_version: "boardagent.identity-administration-result.v1",
        ...record(resolution.value.data),
        ...(replacement === null || recoveryToken === undefined
          ? {}
          : {
              replacement_enrollment: {
                ...(replacement as { expires_at: string }),
                url: `${exactServiceOrigin(input.principal.serviceOrigin)}/recover#${recoveryToken}`
              }
            })
      })
    };
  }
}
