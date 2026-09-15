/*
 * Generated typed query mirror of the migrated PostgreSQL schema.
 * Hand-reviewed SQL migrations remain authoritative for constraints, indexes, RLS and FKs.
 */
import {
  bigint,
  boolean,
  customType,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

const bytea = customType<{ data: Uint8Array }>({ dataType: () => "bytea" });
const pgLsn = customType<{ data: string }>({ dataType: () => "pg_lsn" });
const xid8 = customType<{ data: string }>({ dataType: () => "xid8" });
const tsvector = customType<{ data: string }>({ dataType: () => "tsvector" });

export const keyLifecycleContactEffects = pgTable("key_lifecycle_contact_effects", {
  operationId: uuid("operation_id").notNull(),
  contactId: uuid("contact_id").notNull(),
  beforeSha256: bytea("before_sha256").notNull(),
  afterSha256: bytea("after_sha256").notNull()
});

export const keyLifecycleWebhookRewraps = pgTable("key_lifecycle_webhook_rewraps", {
  operationId: uuid("operation_id").notNull(),
  webhookId: uuid("webhook_id").notNull(),
  sourceKeyId: uuid("source_key_id").notNull(),
  destinationKeyId: uuid("destination_key_id").notNull(),
  previousGeneration: bigint("previous_generation", { mode: "bigint" }).notNull(),
  secretSha256: bytea("secret_sha256").notNull(),
  endpointSha256: bytea("endpoint_sha256").notNull(),
  previousEndpointCipherSha256: bytea("previous_endpoint_cipher_sha256").notNull(),
  previousSecretCipherSha256: bytea("previous_secret_cipher_sha256").notNull(),
  endpointCiphertext: bytea("endpoint_ciphertext").notNull(),
  secretCiphertext: bytea("secret_ciphertext").notNull(),
  beforeSha256: bytea("before_sha256").notNull(),
  afterSha256: bytea("after_sha256").notNull()
});
export const keyLifecycleWebhookDisables = pgTable("key_lifecycle_webhook_disables", {
  operationId: uuid("operation_id").notNull(),
  webhookId: uuid("webhook_id").notNull(),
  beforeSha256: bytea("before_sha256").notNull(),
  afterSha256: bytea("after_sha256").notNull()
});

export const keyLifecycleTotpEffects = pgTable("key_lifecycle_totp_effects", {
  operationId: uuid("operation_id").notNull(),
  credentialId: uuid("credential_id").notNull(),
  beforeSha256: bytea("before_sha256").notNull(),
  afterSha256: bytea("after_sha256").notNull()
});

export const keyLifecycleBrowserEffects = pgTable("key_lifecycle_browser_effects", {
  operationId: uuid("operation_id").notNull(),
  targetType: text("target_type").notNull(),
  targetId: uuid("target_id").notNull(),
  onboardingStageId: uuid("onboarding_stage_id"),
  sessionId: uuid("session_id"),
  authorizationRequestId: uuid("authorization_request_id"),
  actionStageId: uuid("action_stage_id"),
  beforeSha256: bytea("before_sha256").notNull(),
  afterSha256: bytea("after_sha256").notNull()
});

export const keyLifecycleAffectedFamilies = pgTable("key_lifecycle_affected_families", {
  operationId: uuid("operation_id").notNull(),
  familyId: uuid("family_id").notNull(),
  beforeSha256: bytea("before_sha256").notNull(),
  afterSha256: bytea("after_sha256").notNull()
});

export const keyLifecycleOperations = pgTable("key_lifecycle_operations", {
  id: uuid().primaryKey().notNull(),
  instanceId: uuid("instance_id").notNull(),
  organizationId: uuid("organization_id").notNull(),
  keyId: uuid("key_id").notNull(),
  replacementKeyId: uuid("replacement_key_id"),
  canonicalRequest: bytea("canonical_request").notNull(),
  requestSha256: bytea("request_sha256").notNull(),
  canonicalInventory: bytea("canonical_inventory").notNull(),
  details: jsonb().notNull(),
  recordedAt: timestamp("recorded_at", { withTimezone: true, mode: "string" }).notNull(),
  authorizingPrincipal: text("authorizing_principal").notNull(),
  authorizationTransactionId: xid8("authorization_transaction_id").notNull(),
  authorizationServerStart: timestamp("authorization_server_start", {
    withTimezone: true,
    mode: "string"
  }).notNull()
});
export const keyLifecycleCompletions = pgTable("key_lifecycle_completions", {
  operationId: uuid("operation_id").primaryKey().notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true, mode: "string" }).notNull()
});

export const auditRecoveries = pgTable("audit_recoveries", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  instanceId: uuid("instance_id").notNull(),
  canonicalRequest: bytea("canonical_request").notNull(),
  requestSha256: bytea("request_sha256").notNull(),
  signingKeyId: uuid("signing_key_id").notNull(),
  firstSequence: bigint("first_sequence", { mode: "bigint" }).notNull(),
  lastSequence: bigint("last_sequence", { mode: "bigint" }).notNull(),
  firstEventSha256: bytea("first_event_sha256").notNull(),
  headSha256: bytea("head_sha256").notNull(),
  authorizedAt: timestamp("authorized_at", { withTimezone: true, mode: "string" }).notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true, mode: "string" }).notNull(),
  authorizingPrincipal: text("authorizing_principal").notNull(),
  authorizationTransactionId: xid8("authorization_transaction_id").notNull(),
  authorizationServerStart: timestamp("authorization_server_start", {
    withTimezone: true,
    mode: "string"
  }).notNull()
});

export const auditRecoveryCompletions = pgTable("audit_recovery_completions", {
  recoveryId: uuid("recovery_id").primaryKey().notNull(),
  finalCheckpointId: uuid("final_checkpoint_id").notNull(),
  finalHeadSequence: bigint("final_head_sequence", { mode: "bigint" }).notNull(),
  finalHeadSha256: bytea("final_head_sha256").notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true, mode: "string" }).notNull()
});

export const schemaMigrations = pgTable("schema_migrations", {
  version: integer().primaryKey().notNull(),
  name: text().notNull(),
  sha256: text().notNull(),
  appliedAt: timestamp("applied_at", { withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  appBuild: text("app_build").notNull(),
  auditTransactionId: xid8("audit_transaction_id"),
  auditServerStart: timestamp("audit_server_start", { withTimezone: true, mode: "string" }),
  auditSequence: bigint("audit_sequence", { mode: "bigint" })
});

export const accessTokenRecords = pgTable("access_token_records", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  jti: uuid().notNull(),
  memberId: uuid("member_id").notNull(),
  clientId: uuid("client_id").notNull(),
  resourceUri: text("resource_uri").notNull(),
  scopeSet: text("scope_set").array().notNull(),
  sessionId: uuid("session_id"),
  refreshFamilyId: uuid("refresh_family_id"),
  signingKeyId: uuid("signing_key_id").notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  revokedAt: timestamp("revoked_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const accountablePrincipals = pgTable("accountable_principals", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  legalName: text("legal_name").notNull(),
  reference: text(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const actionStages = pgTable("action_stages", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  actorMemberId: uuid("actor_member_id").notNull(),
  actingForMemberId: uuid("acting_for_member_id"),
  actionCode: text("action_code").notNull(),
  targetType: text("target_type").notNull(),
  targetId: uuid("target_id"),
  canonicalSchema: text("canonical_schema").notNull(),
  canonicalizationVersion: text("canonicalization_version").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  packageSha256: bytea("package_sha256"),
  nonceSha256: bytea("nonce_sha256").notNull(),
  protectedCodeSha256: bytea("protected_code_sha256").notNull(),
  clientId: uuid("client_id").notNull(),
  accessTokenRecordId: uuid("access_token_record_id").notNull(),
  tokenJti: uuid("token_jti").notNull(),
  exactOrigin: text("exact_origin").notNull(),
  contextSha256: bytea("context_sha256").notNull(),
  state: text().default("active").notNull(),
  replacesStageId: uuid("replaces_stage_id"),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  confirmedAt: timestamp("confirmed_at", { precision: 6, withTimezone: true, mode: "string" }),
  rejectedAt: timestamp("rejected_at", { precision: 6, withTimezone: true, mode: "string" }),
  cancelledAt: timestamp("cancelled_at", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const agendaItems = pgTable("agenda_items", {
  id: uuid().primaryKey().notNull(),
  agendaVersionId: uuid("agenda_version_id").notNull(),
  ordinal: integer().notNull(),
  title: text().notNull(),
  sourceDocumentVersionId: uuid("source_document_version_id"),
  sourceDocumentSha256: bytea("source_document_sha256"),
  itemSha256: bytea("item_sha256").notNull()
});

export const agendaVersions = pgTable("agenda_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  meetingId: uuid("meeting_id").notNull(),
  meetingVersionId: uuid("meeting_version_id").notNull(),
  version: integer().notNull(),
  schemaVersion: text("schema_version").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const auditChainHead = pgTable("audit_chain_head", {
  singletonKey: boolean("singleton_key").default(true).primaryKey().notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  lastSequence: bigint("last_sequence", { mode: "number" }).default(0).notNull(),
  lastEventSha256: bytea("last_event_sha256").notNull(),
  admissionTransactionId: xid8("admission_transaction_id"),
  admissionServerStart: timestamp("admission_server_start", { withTimezone: true, mode: "string" }),
  admissionStartSequence: bigint("admission_start_sequence", { mode: "bigint" })
    .default(0n)
    .notNull(),
  admissionPayloadBytes: bigint("admission_payload_bytes", { mode: "bigint" })
    .default(0n)
    .notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull()
});

export const authSessions = pgTable("auth_sessions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  opaqueSessionSha256: bytea("opaque_session_sha256").notNull(),
  memberId: uuid("member_id"),
  clientId: uuid("client_id"),
  state: text().notNull(),
  exactOrigin: text("exact_origin").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  lastAuthenticatedAt: timestamp("last_authenticated_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  })
});

export const backupReceipts = pgTable("backup_receipts", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  receiptKind: text("receipt_kind").default("backup").notNull(),
  sourceBackupReceiptId: uuid("source_backup_receipt_id"),
  schemaVersion: text("schema_version").notNull(),
  canonicalManifest: bytea("canonical_manifest").notNull(),
  manifestSha256: bytea("manifest_sha256").notNull(),
  snapshotLsn: pgLsn("snapshot_lsn").notNull(),
  snapshotAt: timestamp("snapshot_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  contentSetSha256: bytea("content_set_sha256").notNull(),
  encryptionKeyId: uuid("encryption_key_id").notNull(),
  state: text().notNull(),
  verifiedRestoreAt: timestamp("verified_restore_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const boardMemberships = pgTable("board_memberships", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  seatRole: text("seat_role").notNull(),
  isChair: boolean("is_chair").default(false).notNull(),
  isSecretary: boolean("is_secretary").default(false).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  votingWeight: bigint("voting_weight", { mode: "number" }).default(0).notNull(),
  state: text().default("active").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  entitlementGeneration: bigint("entitlement_generation", { mode: "number" }).default(1).notNull(),
  activeFrom: timestamp("active_from", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  activeUntil: timestamp("active_until", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const boards = pgTable("boards", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  slug: text().notNull(),
  name: text().notNull(),
  timezone: text().notNull(),
  state: text().default("active").notNull(),
  currentVersionId: uuid("current_version_id"),
  currentGovernanceProfileId: uuid("current_governance_profile_id"),
  currentRulesetId: uuid("current_ruleset_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const cryptoKeyRegistry = pgTable("crypto_key_registry", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  kid: text().notNull(),
  purpose: text().notNull(),
  algorithm: text().notNull(),
  publicJwk: jsonb("public_jwk"),
  nonsecretLocator: text("nonsecret_locator").notNull(),
  activatedAt: timestamp("activated_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  retiredAt: timestamp("retired_at", { precision: 6, withTimezone: true, mode: "string" }),
  compromisedAt: timestamp("compromised_at", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const documentAccessGrants = pgTable("document_access_grants", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  documentId: uuid("document_id").notNull(),
  granteeMemberId: uuid("grantee_member_id"),
  granteeSeatRole: text("grantee_seat_role"),
  permission: text().notNull(),
  activeFrom: timestamp("active_from", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  activeUntil: timestamp("active_until", { precision: 6, withTimezone: true, mode: "string" }),
  grantedBy: uuid("granted_by").notNull()
});

export const documentExclusions = pgTable("document_exclusions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  documentId: uuid("document_id").notNull(),
  memberId: uuid("member_id").notNull(),
  version: integer().notNull(),
  reason: text().notNull(),
  activeFrom: timestamp("active_from", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  activeUntil: timestamp("active_until", { precision: 6, withTimezone: true, mode: "string" }),
  createdBy: uuid("created_by").notNull()
});

export const documentSearch = pgTable("document_search", {
  documentId: uuid("document_id").primaryKey().notNull(),
  boardId: uuid("board_id").notNull(),
  currentVersionId: uuid("current_version_id").notNull(),
  canonicalTextSha256: bytea("canonical_text_sha256").notNull(),
  searchText: text("search_text").notNull(),
  searchVector: tsvector("search_vector").generatedAlwaysAs(
    sql`to_tsvector('simple'::regconfig, search_text)`
  ),
  indexedAt: timestamp("indexed_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const documents = pgTable("documents", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  title: text().notNull(),
  state: text().default("active").notNull(),
  currentVersionId: uuid("current_version_id"),
  createdBy: uuid("created_by").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  hiddenAt: timestamp("hidden_at", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const enrollmentActivationChallenges = pgTable("enrollment_activation_challenges", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  invitationId: uuid("invitation_id").notNull(),
  protectedCode: bytea("protected_code").notNull(),
  proofingMethod: text("proofing_method").notNull(),
  attemptCount: integer("attempt_count").default(0).notNull(),
  state: text().notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  consumedAt: timestamp("consumed_at", { precision: 6, withTimezone: true, mode: "string" }),
  confirmedBy: uuid("confirmed_by")
});

export const enrollmentInvitations = pgTable("enrollment_invitations", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  tokenSha256: bytea("token_sha256").notNull(),
  issuedBy: uuid("issued_by").notNull(),
  handoffMethod: text("handoff_method").notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  consumedAt: timestamp("consumed_at", { precision: 6, withTimezone: true, mode: "string" }),
  revokedAt: timestamp("revoked_at", { precision: 6, withTimezone: true, mode: "string" }),
  pendingActivationMemberId: uuid("pending_activation_member_id")
});

export const exportArtifacts = pgTable("export_artifacts", {
  id: uuid().primaryKey().notNull(),
  exportRequestId: uuid("export_request_id").notNull(),
  manifest: bytea("manifest").notNull(),
  manifestSha256: bytea("manifest_sha256").notNull(),
  contentSetSha256: bytea("content_set_sha256").notNull(),
  encryptedStorageLocator: text("encrypted_storage_locator").notNull(),
  encryptionKeyId: uuid("encryption_key_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  byteLength: bigint("byte_length", { mode: "number" }).notNull(),
  state: text().default("ready").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  deletedAt: timestamp("deleted_at", { precision: 6, withTimezone: true, mode: "string" }),
  expiresAt: timestamp("expires_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()+interval '24 hours'`)
    .notNull(),
  cleanupLeaseToken: uuid("cleanup_lease_token"),
  cleanupLeaseExpiresAt: timestamp("cleanup_lease_expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  })
});

export const exportChunks = pgTable("export_chunks", {
  id: uuid().primaryKey().notNull(),
  artifactId: uuid("artifact_id").notNull(),
  ordinal: integer().notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  byteOffset: bigint("byte_offset", { mode: "number" }).notNull(),
  byteLength: integer("byte_length").notNull(),
  chunkSha256: bytea("chunk_sha256").notNull(),
  storageLocator: text("storage_locator").notNull()
});

export const exportRequests = pgTable("export_requests", {
  id: uuid().primaryKey().notNull(),
  publicId: bytea("public_id").notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  requesterMemberId: uuid("requester_member_id").notNull(),
  exportType: text("export_type").notNull(),
  scopeManifest: bytea("scope_manifest").notNull(),
  scopeSha256: bytea("scope_sha256").notNull(),
  state: text().default("staged").notNull(),
  consentRecordId: uuid("consent_record_id"),
  recentAuthAt: timestamp("recent_auth_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  snapshotManifest: bytea("snapshot_manifest"),
  snapshotSha256: bytea("snapshot_sha256"),
  startedAt: timestamp("started_at", { precision: 6, withTimezone: true, mode: "string" }),
  failureClass: text("failure_class"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const externalIdentityLinks = pgTable("external_identity_links", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  issuer: text().notNull(),
  subject: text().notNull(),
  state: text().notNull(),
  invitationId: uuid("invitation_id"),
  confirmedBy: uuid("confirmed_by"),
  confirmedAt: timestamp("confirmed_at", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const identityRecoveryRequests = pgTable("identity_recovery_requests", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  requestedBy: uuid("requested_by").notNull(),
  reason: text().notNull(),
  proofingMethod: text("proofing_method").notNull(),
  credentialDisposition: text("credential_disposition").notNull(),
  preservedCredentialIds: uuid("preserved_credential_ids").array().default([]).notNull(),
  priorIdentityGeneration: bigint("prior_identity_generation", { mode: "number" }).notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  state: text().default("initiated").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const governanceProfiles = pgTable("governance_profiles", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  version: integer().notNull(),
  state: text().notNull(),
  schemaVersion: text("schema_version").notNull(),
  canonicalPayload: jsonb("canonical_payload").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  sourceAgreementReferences: jsonb("source_agreement_references").notNull(),
  activationConsentRecordId: uuid("activation_consent_record_id"),
  supersedesId: uuid("supersedes_id"),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  activatedAt: timestamp("activated_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const idempotencyRecords = pgTable("idempotency_records", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  clientId: uuid("client_id").notNull(),
  operation: text().notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  requestSha256: bytea("request_sha256").notNull(),
  state: text().notNull(),
  safeResponseType: text("safe_response_type"),
  safeResponseId: uuid("safe_response_id"),
  safeResponseSha256: bytea("safe_response_sha256"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const inputRequiredAttempts = pgTable("input_required_attempts", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  stageId: uuid("stage_id").notNull(),
  wizardDraftId: uuid("wizard_draft_id"),
  protocolVersion: text("protocol_version").notNull(),
  protocolHeaderVersion: text("protocol_header_version").notNull(),
  resultMetaVersion: text("result_meta_version").notNull(),
  originalMethod: text("original_method").notNull(),
  originalName: text("original_name").notNull(),
  originalArgumentsSha256: bytea("original_arguments_sha256").notNull(),
  capabilitiesSha256: bytea("capabilities_sha256").notNull(),
  embeddedFormSha256: bytea("embedded_form_sha256").notNull(),
  embeddedResultSha256: bytea("embedded_result_sha256").notNull(),
  requestStateBytes: bytea("request_state_bytes").notNull(),
  requestStateSha256: bytea("request_state_sha256").notNull(),
  preparedRequestId: bytea("prepared_request_id").notNull(),
  retryRequestId: bytea("retry_request_id"),
  inputResponseSha256: bytea("input_response_sha256"),
  responseAction: text("response_action"),
  state: text().default("prepared").notNull(),
  preparedAt: timestamp("prepared_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  retryReceivedAt: timestamp("retry_received_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const jobs = pgTable("jobs", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  jobType: text("job_type").notNull(),
  schemaVersion: text("schema_version").notNull(),
  subjectType: text("subject_type").notNull(),
  subjectId: uuid("subject_id"),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  state: text().default("queued").notNull(),
  attempts: integer().default(0).notNull(),
  availableAt: timestamp("available_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  leaseOwner: text("lease_owner"),
  leaseToken: uuid("lease_token"),
  leaseStartedAt: timestamp("lease_started_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  leaseExpiresAt: timestamp("lease_expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  lastErrorClass: text("last_error_class"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const jobAttemptResults = pgTable("job_attempt_results", {
  jobId: uuid("job_id").notNull(),
  attempt: integer().notNull(),
  leaseToken: uuid("lease_token").notNull(),
  leaseOwner: text("lease_owner").notNull(),
  resultClass: text("result_class").notNull(),
  resultSha256: bytea("result_sha256").notNull(),
  errorClass: text("error_class"),
  resultingState: text("resulting_state").notNull(),
  startedAt: timestamp("started_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  completedAt: timestamp("completed_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull()
});

export const managementQuestions = pgTable("management_questions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  askerMemberId: uuid("asker_member_id").notNull(),
  assignedOwnerIds: uuid("assigned_owner_ids").array().notNull(),
  dueAt: timestamp("due_at", { precision: 6, withTimezone: true, mode: "string" }).notNull(),
  aclPolicy: jsonb("acl_policy").notNull(),
  state: text().default("pending").notNull(),
  currentTurnId: uuid("current_turn_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const managementSubmissionThreads = pgTable("management_submission_threads", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  managementOwnerIds: uuid("management_owner_ids").array().notNull(),
  assignedSecretaryId: uuid("assigned_secretary_id"),
  state: text().default("submitted").notNull(),
  currentVersionId: uuid("current_version_id"),
  queueEnteredAt: timestamp("queue_entered_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdBy: uuid("created_by").notNull(),
  lastAuditEventId: uuid("last_audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const matterTypes = pgTable("matter_types", {
  id: uuid().primaryKey().notNull(),
  rulesetId: uuid("ruleset_id").notNull(),
  code: text().notNull(),
  name: text().notNull(),
  strictFactSchema: jsonb("strict_fact_schema").notNull(),
  schemaSha256: bytea("schema_sha256").notNull()
});

export const meetingRsvps = pgTable("meeting_rsvps", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  meetingId: uuid("meeting_id").notNull(),
  memberId: uuid("member_id").notNull(),
  version: integer().notNull(),
  response: text().notNull(),
  note: text(),
  isCurrent: boolean("is_current").default(true).notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  recordedAt: timestamp("recorded_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const meetingTranscripts = pgTable("meeting_transcripts", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  meetingId: uuid("meeting_id").notNull(),
  state: text().default("unverified").notNull(),
  currentVersionId: uuid("current_version_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const meetings = pgTable("meetings", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  title: text().notNull(),
  state: text().default("draft").notNull(),
  scheduledStart: timestamp("scheduled_start", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  scheduledEnd: timestamp("scheduled_end", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  currentVersionId: uuid("current_version_id"),
  currentAgendaVersionId: uuid("current_agenda_version_id"),
  currentMinutesId: uuid("current_minutes_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" }),
  cancelledAt: timestamp("cancelled_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const memberContactPoints = pgTable("member_contact_points", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  kind: text().notNull(),
  protectedValue: bytea("protected_value").notNull(),
  keyId: uuid("key_id").notNull(),
  verifiedAt: timestamp("verified_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  state: text().notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const memberWebhooks = pgTable("member_webhooks", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  endpointCiphertext: bytea("endpoint_ciphertext").notNull(),
  endpointSha256: bytea("endpoint_sha256").notNull(),
  secretCiphertext: bytea("secret_ciphertext").notNull(),
  secretSha256: bytea("secret_sha256").notNull(),
  keyId: uuid("key_id").notNull(),
  ssrfValidationReceiptSha256: bytea("ssrf_validation_receipt_sha256").notNull(),
  eventClasses: text("event_classes").array().notNull(),
  state: text().default("active").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  generation: bigint({ mode: "number" }).default(1).notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  verifiedAt: timestamp("verified_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  updatedAt: timestamp("updated_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  disabledAt: timestamp("disabled_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const members = pgTable("members", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberKind: text("member_kind").notNull(),
  legalName: text("legal_name").notNull(),
  displayName: text("display_name").notNull(),
  state: text().default("invited").notNull(),
  accountablePrincipalId: uuid("accountable_principal_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  identityGeneration: bigint("identity_generation", { mode: "number" }).default(1).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  onboardingGeneration: bigint("onboarding_generation", { mode: "number" }).default(1).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  hiddenAt: timestamp("hidden_at", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutes = pgTable("minutes", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  meetingId: uuid("meeting_id").notNull(),
  state: text().default("unpublished_draft").notNull(),
  currentVersionId: uuid("current_version_id"),
  currentSignaturePackageId: uuid("current_signature_package_id"),
  correctionOfMinutesId: uuid("correction_of_minutes_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  finalizedAt: timestamp("finalized_at", { precision: 6, withTimezone: true, mode: "string" }),
  cancelledAt: timestamp("cancelled_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const minutesSignaturePackages = pgTable("minutes_signature_packages", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  minutesId: uuid("minutes_id").notNull(),
  minutesVersionId: uuid("minutes_version_id").notNull(),
  version: integer().notNull(),
  minutesSha256: bytea("minutes_sha256").notNull(),
  transcriptManifestSha256: bytea("transcript_manifest_sha256").notNull(),
  actionManifestSha256: bytea("action_manifest_sha256").notNull(),
  reviewManifestSha256: bytea("review_manifest_sha256").notNull(),
  signerManifestSha256: bytea("signer_manifest_sha256").notNull(),
  packageSha256: bytea("package_sha256").notNull(),
  state: text().default("current").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const notices = pgTable("notices", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  noticeType: text("notice_type").notNull(),
  objectType: text("object_type").notNull(),
  objectId: uuid("object_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  objectVersion: bigint("object_version", { mode: "number" }).notNull(),
  recipientMemberId: uuid("recipient_member_id").notNull(),
  contentSha256: bytea("content_sha256").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  feedSequence: bigint("feed_sequence", { mode: "number" }).notNull(),
  state: text().default("committed").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  deliveredAt: timestamp("delivered_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const notificationJobs = pgTable("notification_jobs", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  noticeId: uuid("notice_id"),
  recipientMemberId: uuid("recipient_member_id").notNull(),
  webhookId: uuid("webhook_id"),
  sourceKind: text("source_kind").default("notice").notNull(),
  wakeClass: text("wake_class").notNull(),
  randomWakeId: bytea("random_wake_id").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  state: text().default("queued").notNull(),
  attempts: integer().default(0).notNull(),
  availableAt: timestamp("available_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  leaseOwner: text("lease_owner"),
  leaseStartedAt: timestamp("lease_started_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  leaseExpiresAt: timestamp("lease_expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  deliveredAt: timestamp("delivered_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const oauthAuthorizationCodes = pgTable("oauth_authorization_codes", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  codeSha256: bytea("code_sha256").notNull(),
  authorizationRequestId: uuid("authorization_request_id").notNull(),
  clientId: uuid("client_id").notNull(),
  memberId: uuid("member_id").notNull(),
  redirectUri: text("redirect_uri").notNull(),
  resourceUri: text("resource_uri").notNull(),
  scopeSet: text("scope_set").array().notNull(),
  pkceS256Challenge: text("pkce_s256_challenge").notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  consumedAt: timestamp("consumed_at", { precision: 6, withTimezone: true, mode: "string" }),
  revokedAt: timestamp("revoked_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const oauthAuthorizationRequests = pgTable("oauth_authorization_requests", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  clientId: uuid("client_id").notNull(),
  resourceUri: text("resource_uri").notNull(),
  redirectUri: text("redirect_uri").notNull(),
  scopeSet: text("scope_set").array().notNull(),
  memberId: uuid("member_id"),
  sessionId: uuid("session_id").notNull(),
  stateHash: bytea("state_hash").notNull(),
  requestState: text("request_state").notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const oauthClients = pgTable("oauth_clients", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  protocolIdKind: text("protocol_id_kind").notNull(),
  protocolIdValue: text("protocol_id_value").notNull(),
  safeMetadata: jsonb("safe_metadata").notNull(),
  metadataSha256: bytea("metadata_sha256").notNull(),
  state: text().notNull(),
  registeredBy: uuid("registered_by"),
  registeredAt: timestamp("registered_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const oauthConsents = pgTable("oauth_consents", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  clientId: uuid("client_id").notNull(),
  resourceUri: text("resource_uri").notNull(),
  scopeSet: text("scope_set").array().notNull(),
  grantedAt: timestamp("granted_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  revokedAt: timestamp("revoked_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const oidcLoginTransactions = pgTable("oidc_login_transactions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  providerId: text("provider_id").notNull(),
  providerKind: text("provider_kind").notNull(),
  exactIssuer: text("exact_issuer").notNull(),
  interactionUid: text("interaction_uid").notNull(),
  authorizationRequestId: uuid("authorization_request_id").notNull(),
  stateSha256: bytea("state_sha256").notNull(),
  nonceSha256: bytea("nonce_sha256").notNull(),
  sessionId: uuid("session_id").notNull(),
  clientId: uuid("client_id").notNull(),
  resourceUri: text("resource_uri").notNull(),
  callbackUri: text("callback_uri").notNull(),
  pkceS256Challenge: text("pkce_s256_challenge").notNull(),
  invitationTokenSha256: bytea("invitation_token_sha256"),
  linkedIdentityLinkId: uuid("linked_identity_link_id"),
  linkedMemberId: uuid("linked_member_id"),
  completionSha256: bytea("completion_sha256"),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  consumedAt: timestamp("consumed_at", { precision: 6, withTimezone: true, mode: "string" }),
  completionConsumedAt: timestamp("completion_consumed_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  failureCode: text("failure_code")
});

export const organizationRoleAssignments = pgTable("organization_role_assignments", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  role: text().notNull(),
  activeFrom: timestamp("active_from", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  activeUntil: timestamp("active_until", { precision: 6, withTimezone: true, mode: "string" }),
  changeReason: text("change_reason").notNull(),
  consentRecordId: uuid("consent_record_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const organizations = pgTable("organizations", {
  id: uuid().primaryKey().notNull(),
  legalName: text("legal_name").notNull(),
  displayName: text("display_name").notNull(),
  slug: text().notNull(),
  timezone: text().notNull(),
  state: text().default("active").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const pendingActionFeed = pgTable("pending_action_feed", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  entitlementGeneration: bigint("entitlement_generation", { mode: "number" }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  feedSequence: bigint("feed_sequence", { mode: "number" }).notNull(),
  actionType: text("action_type").notNull(),
  objectType: text("object_type").notNull(),
  objectId: uuid("object_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  objectVersion: bigint("object_version", { mode: "number" }).notNull(),
  visibilitySha256: bytea("visibility_sha256").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  state: text().default("pending").notNull(),
  noticeId: uuid("notice_id"),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  resolvedAt: timestamp("resolved_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const questionVisibility = pgTable("question_visibility", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  questionId: uuid("question_id").notNull(),
  inheritedDocumentId: uuid("inherited_document_id"),
  inheritedObjectType: text("inherited_object_type"),
  inheritedObjectId: uuid("inherited_object_id"),
  granteeMemberId: uuid("grantee_member_id"),
  granteeSeatRole: text("grantee_seat_role"),
  effect: text().notNull(),
  reason: text().notNull(),
  activeFrom: timestamp("active_from", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  activeUntil: timestamp("active_until", { precision: 6, withTimezone: true, mode: "string" }),
  createdBy: uuid("created_by").notNull(),
  recusalConsentRecordId: uuid("recusal_consent_record_id"),
  recusalAuditEventId: uuid("recusal_audit_event_id"),
  liftConsentRecordId: uuid("lift_consent_record_id"),
  liftAuditEventId: uuid("lift_audit_event_id")
});

export const refreshFamilies = pgTable("refresh_families", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  clientId: uuid("client_id").notNull(),
  resourceUri: text("resource_uri").notNull(),
  grantedScopeSet: text("granted_scope_set").array(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  generation: bigint({ mode: "number" }).default(0).notNull(),
  state: text().notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  lastUsedAt: timestamp("last_used_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  idleExpiresAt: timestamp("idle_expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  absoluteExpiresAt: timestamp("absolute_expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  revokedAt: timestamp("revoked_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const refreshTokens = pgTable("refresh_tokens", {
  id: uuid().primaryKey().notNull(),
  familyId: uuid("family_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  generation: bigint({ mode: "number" }).notNull(),
  tokenSha256: bytea("token_sha256").notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  usedAt: timestamp("used_at", { precision: 6, withTimezone: true, mode: "string" }),
  replacedById: uuid("replaced_by_id"),
  revokedAt: timestamp("revoked_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const ruleOverrides = pgTable("rule_overrides", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  evaluationId: uuid("evaluation_id").notNull(),
  wizardDraftId: uuid("wizard_draft_id").notNull(),
  finalObjectType: text("final_object_type").notNull(),
  finalObjectId: uuid("final_object_id").notNull(),
  recommendedRuleId: uuid("recommended_rule_id"),
  selectedRuleId: uuid("selected_rule_id").notNull(),
  reason: text().notNull(),
  citationSnapshot: jsonb("citation_snapshot").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const rulesets = pgTable("rulesets", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  profileId: uuid("profile_id").notNull(),
  version: integer().notNull(),
  state: text().notNull(),
  schemaVersion: text("schema_version").notNull(),
  canonicalPayload: jsonb("canonical_payload").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  activationConsentRecordId: uuid("activation_consent_record_id"),
  supersedesId: uuid("supersedes_id"),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  activatedAt: timestamp("activated_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const systemInstance = pgTable("system_instance", {
  singletonKey: boolean("singleton_key").default(true).primaryKey().notNull(),
  instanceId: uuid("instance_id").notNull(),
  organizationId: uuid("organization_id").notNull(),
  canonicalResourceUri: text("canonical_resource_uri").notNull(),
  bootstrappedAt: timestamp("bootstrapped_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const taskEvidence = pgTable("task_evidence", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  taskId: uuid("task_id").notNull(),
  ownerMemberId: uuid("owner_member_id").notNull(),
  canonicalText: text("canonical_text"),
  documentReferences: jsonb("document_references").notNull(),
  resourceReferences: jsonb("resource_references").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  state: text().default("submitted").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  submittedAt: timestamp("submitted_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const tasks = pgTable("tasks", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  sourceMeetingId: uuid("source_meeting_id"),
  sourceMinutesId: uuid("source_minutes_id"),
  sourceMinutesVersionId: uuid("source_minutes_version_id"),
  sourceMinutesSha256: bytea("source_minutes_sha256"),
  sourceLocator: jsonb("source_locator"),
  ownerMemberId: uuid("owner_member_id").notNull(),
  dueAt: timestamp("due_at", { precision: 6, withTimezone: true, mode: "string" }).notNull(),
  descriptionSchema: text("description_schema").notNull(),
  canonicalDescription: text("canonical_description").notNull(),
  requiredEvidence: jsonb("required_evidence").notNull(),
  taskSha256: bytea("task_sha256").notNull(),
  state: text().default("open").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" }),
  cancelledAt: timestamp("cancelled_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const totpCredentials = pgTable("totp_credentials", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  encryptedSecret: bytea("encrypted_secret").notNull(),
  keyId: uuid("key_id").notNull(),
  fallbackHandleSha256: bytea("fallback_handle_sha256").notNull(),
  authorizedBy: uuid("authorized_by").notNull(),
  state: text().notNull(),
  maxFailedAttempts: integer("max_failed_attempts").notNull(),
  lockoutSeconds: integer("lockout_seconds").notNull(),
  failedAttempts: integer("failed_attempts").default(0).notNull(),
  lockedUntil: timestamp("locked_until", { precision: 6, withTimezone: true, mode: "string" }),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  lastAcceptedStep: bigint("last_accepted_step", { mode: "number" }),
  activatedAt: timestamp("activated_at", { precision: 6, withTimezone: true, mode: "string" }),
  terminalAt: timestamp("terminal_at", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const transcriptChallenges = pgTable("transcript_challenges", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  transcriptVersionId: uuid("transcript_version_id").notNull(),
  turnId: uuid("turn_id").notNull(),
  challengerMemberId: uuid("challenger_member_id").notNull(),
  canonicalComment: text("canonical_comment").notNull(),
  commentSha256: bytea("comment_sha256").notNull(),
  state: text().default("pending").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteExclusions = pgTable("vote_exclusions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  memberId: uuid("member_id").notNull(),
  version: integer().notNull(),
  state: text().notNull(),
  reason: text().notNull(),
  causeRequestedState: text("cause_requested_state"),
  sourceBoardExclusionId: uuid("source_board_exclusion_id"),
  actorMemberId: uuid("actor_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  effectiveAt: timestamp("effective_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const votes = pgTable("votes", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  title: text().notNull(),
  state: text().default("draft").notNull(),
  currentResolutionVersionId: uuid("current_resolution_version_id"),
  currentDecisionPackageId: uuid("current_decision_package_id"),
  approvalRuleId: uuid("approval_rule_id").notNull(),
  governanceProfileId: uuid("governance_profile_id").notNull(),
  rulesetId: uuid("ruleset_id").notNull(),
  matterEvaluationId: uuid("matter_evaluation_id"),
  selectedRulesetRuleId: uuid("selected_ruleset_rule_id"),
  ruleOverrideId: uuid("rule_override_id"),
  ruleOverrideSha256: bytea("rule_override_sha256"),
  electorateSha256: bytea("electorate_sha256"),
  closeMode: text("close_mode").notNull(),
  deadlineAt: timestamp("deadline_at", { precision: 6, withTimezone: true, mode: "string" }),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  openedAt: timestamp("opened_at", { precision: 6, withTimezone: true, mode: "string" }),
  closedAt: timestamp("closed_at", { precision: 6, withTimezone: true, mode: "string" }),
  cancelledAt: timestamp("cancelled_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const webauthnChallenges = pgTable("webauthn_challenges", {
  recoveryRequestId: uuid("recovery_request_id"),
  activationRestartGrantId: uuid("activation_restart_grant_id"),
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  challengeSha256: bytea("challenge_sha256").notNull(),
  sessionId: uuid("session_id"),
  memberId: uuid("member_id"),
  purpose: text().notNull(),
  rpId: text("rp_id").notNull(),
  exactOrigin: text("exact_origin").notNull(),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  consumedAt: timestamp("consumed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const webauthnCredentials = pgTable("webauthn_credentials", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  credentialId: bytea("credential_id").notNull(),
  publicKey: bytea("public_key").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  signatureCounter: bigint("signature_counter", { mode: "number" }).default(0).notNull(),
  transports: text().array().default([""]).notNull(),
  backupEligible: boolean("backup_eligible").notNull(),
  backupState: boolean("backup_state").notNull(),
  state: text().notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  lastUsedAt: timestamp("last_used_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const wizardDrafts = pgTable("wizard_drafts", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  draftType: text("draft_type").notNull(),
  creatorMemberId: uuid("creator_member_id").notNull(),
  currentStep: integer("current_step").default(0).notNull(),
  signedContext: bytea("signed_context").notNull(),
  contextSha256: bytea("context_sha256").notNull(),
  state: text().default("active").notNull(),
  rulesetId: uuid("ruleset_id"),
  packageSha256: bytea("package_sha256"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  postedAt: timestamp("posted_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const approvalRules = pgTable("approval_rules", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  schemaVersion: text("schema_version").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  thresholdNumerator: bigint("threshold_numerator", { mode: "number" }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  thresholdDenominator: bigint("threshold_denominator", { mode: "number" }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  quorumNumerator: bigint("quorum_numerator", { mode: "number" }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  quorumDenominator: bigint("quorum_denominator", { mode: "number" }).notNull(),
  approvalDenominator: text("approval_denominator").notNull(),
  abstentionsCountForQuorum: boolean("abstentions_count_for_quorum").notNull(),
  tieBehavior: text("tie_behavior").notNull(),
  proxyPolicy: text("proxy_policy").notNull(),
  closeMode: text("close_mode").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const auditCheckpoints = pgTable("audit_checkpoints", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  firstSequence: bigint("first_sequence", { mode: "number" }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  lastSequence: bigint("last_sequence", { mode: "number" }).notNull(),
  firstEventSha256: bytea("first_event_sha256").notNull(),
  lastEventSha256: bytea("last_event_sha256").notNull(),
  canonicalManifest: bytea("canonical_manifest").notNull(),
  manifestSha256: bytea("manifest_sha256").notNull(),
  signature: bytea("signature").notNull(),
  signingKeyId: uuid("signing_key_id").notNull(),
  // Internal insert-guard authority; never caller-supplied or part of signed payloads.
  attestationTransactionId: xid8("attestation_transaction_id"),
  attestationSequence: bigint("attestation_sequence", { mode: "bigint" }),
  recoveryId: uuid("recovery_id"),
  attestationOrigin: text("attestation_origin"),
  attestationServerStart: timestamp("attestation_server_start", {
    withTimezone: true,
    mode: "string"
  }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const auditEvents = pgTable("audit_events", {
  id: uuid().primaryKey().notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  sequence: bigint({ mode: "number" }).notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  eventType: text("event_type").notNull(),
  schemaVersion: text("schema_version").notNull(),
  actorMemberId: uuid("actor_member_id"),
  actingForMemberId: uuid("acting_for_member_id"),
  clientId: uuid("client_id"),
  tokenJti: uuid("token_jti"),
  consentRecordId: uuid("consent_record_id"),
  objectType: text("object_type").notNull(),
  objectId: uuid("object_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  objectVersion: bigint("object_version", { mode: "number" }),
  canonicalPayload: bytea("canonical_payload").notNull(),
  previousEventSha256: bytea("previous_event_sha256").notNull(),
  eventSha256: bytea("event_sha256").notNull(),
  occurredAt: timestamp("occurred_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const ballotDispositions = pgTable("ballot_dispositions", {
  id: uuid().primaryKey().notNull(),
  priorBallotId: uuid("prior_ballot_id").notNull(),
  supersedingBallotId: uuid("superseding_ballot_id"),
  replacementVoteId: uuid("replacement_vote_id"),
  reason: text().notNull(),
  effect: text().notNull(),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const ballots = pgTable("ballots", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  decisionPackageId: uuid("decision_package_id").notNull(),
  principalMemberId: uuid("principal_member_id").notNull(),
  casterMemberId: uuid("caster_member_id").notNull(),
  choice: text().notNull(),
  statementText: text("statement_text"),
  statementSha256: bytea("statement_sha256"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  votingWeight: bigint("voting_weight", { mode: "number" }).notNull(),
  ballotSource: text("ballot_source").notNull(),
  proxyGrantId: uuid("proxy_grant_id"),
  consentRecordId: uuid("consent_record_id").notNull(),
  castAt: timestamp("cast_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const boardVersions = pgTable("board_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  version: integer().notNull(),
  canonicalSchema: text("canonical_schema").notNull(),
  canonicalPayload: jsonb("canonical_payload").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  changeReason: text("change_reason").notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const configReceipts = pgTable("config_receipts", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  effectiveConfigSha256: bytea("effective_config_sha256").notNull(),
  appBuild: text("app_build").notNull(),
  schemaVersion: integer("schema_version").notNull(),
  protocolVersion: text("protocol_version").notNull(),
  startedAt: timestamp("started_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const consentRecords = pgTable("consent_records", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  stageId: uuid("stage_id").notNull(),
  inputRequiredAttemptId: uuid("input_required_attempt_id").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  actingForMemberId: uuid("acting_for_member_id"),
  actionCode: text("action_code").notNull(),
  targetType: text("target_type").notNull(),
  targetId: uuid("target_id"),
  canonicalSchema: text("canonical_schema").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  packageSha256: bytea("package_sha256"),
  protectedCodeRecordSha256: bytea("protected_code_record_sha256").notNull(),
  accessTokenRecordId: uuid("access_token_record_id").notNull(),
  tokenJti: uuid("token_jti").notNull(),
  clientId: uuid("client_id").notNull(),
  exactOrigin: text("exact_origin").notNull(),
  stagedAt: timestamp("staged_at", { precision: 6, withTimezone: true, mode: "string" }).notNull(),
  confirmedAt: timestamp("confirmed_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  recordSha256: bytea("record_sha256").notNull()
});

export const decisionPackageComponents = pgTable("decision_package_components", {
  id: uuid().primaryKey().notNull(),
  decisionPackageId: uuid("decision_package_id").notNull(),
  componentClass: text("component_class").notNull(),
  ordinal: integer().notNull(),
  objectType: text("object_type").notNull(),
  objectId: uuid("object_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  objectVersion: bigint("object_version", { mode: "number" }),
  objectSha256: bytea("object_sha256").notNull()
});

export const decisionPackages = pgTable("decision_packages", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  version: integer().notNull(),
  schemaVersion: text("schema_version").notNull(),
  resolutionVersionId: uuid("resolution_version_id").notNull(),
  resolutionSha256: bytea("resolution_sha256").notNull(),
  submissionManifest: jsonb("submission_manifest").notNull(),
  submissionManifestSha256: bytea("submission_manifest_sha256").notNull(),
  documentManifest: jsonb("document_manifest").notNull(),
  documentManifestSha256: bytea("document_manifest_sha256").notNull(),
  questionCutoffManifest: jsonb("question_cutoff_manifest").notNull(),
  questionCutoffSha256: bytea("question_cutoff_sha256").notNull(),
  approvalRuleId: uuid("approval_rule_id").notNull(),
  approvalRuleSha256: bytea("approval_rule_sha256").notNull(),
  governanceProfileId: uuid("governance_profile_id").notNull(),
  governanceProfileSha256: bytea("governance_profile_sha256").notNull(),
  rulesetId: uuid("ruleset_id").notNull(),
  rulesetSha256: bytea("ruleset_sha256").notNull(),
  matterEvaluationId: uuid("matter_evaluation_id").notNull(),
  matterEvaluationResultSha256: bytea("matter_evaluation_result_sha256").notNull(),
  selectedRulesetRuleId: uuid("selected_ruleset_rule_id").notNull(),
  selectedRulesetRuleSha256: bytea("selected_ruleset_rule_sha256").notNull(),
  ruleOverrideId: uuid("rule_override_id"),
  ruleOverrideSha256: bytea("rule_override_sha256"),
  electorateSha256: bytea("electorate_sha256").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  packageSha256: bytea("package_sha256").notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const deletionTombstones = pgTable("deletion_tombstones", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  objectType: text("object_type").notNull(),
  objectId: uuid("object_id").notNull(),
  snapshotId: uuid("snapshot_id").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  reason: text().notNull(),
  hiddenAt: timestamp("hidden_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const documentCirculations = pgTable("document_circulations", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  documentId: uuid("document_id").notNull(),
  documentVersionId: uuid("document_version_id").notNull(),
  documentSha256: bytea("document_sha256").notNull(),
  recipientPolicy: jsonb("recipient_policy").notNull(),
  packageSha256: bytea("package_sha256").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  circulatedBy: uuid("circulated_by").notNull(),
  circulatedAt: timestamp("circulated_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  state: text().notNull()
});

export const documentValidationAttempts = pgTable("document_validation_attempts", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  actorMemberId: uuid("actor_member_id").notNull(),
  offeredMediaType: text("offered_media_type").notNull(),
  offeredName: text("offered_name"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  offeredLength: bigint("offered_length", { mode: "number" }),
  offeredSha256: bytea("offered_sha256"),
  result: text().notNull(),
  resultCode: text("result_code").notNull(),
  remediation: text().notNull(),
  acceptedDocumentVersionId: uuid("accepted_document_version_id"),
  attemptedAt: timestamp("attempted_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const documentVersions = pgTable("document_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  documentId: uuid("document_id").notNull(),
  version: integer().notNull(),
  mediaType: text("media_type").notNull(),
  documentSchema: text("document_schema"),
  canonicalizationVersion: text("canonicalization_version").notNull(),
  canonicalBytes: bytea("canonical_bytes").notNull(),
  byteLength: integer("byte_length").notNull(),
  sha256: bytea("sha256").notNull(),
  canonicalMetadata: jsonb("canonical_metadata").notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const feedTombstones = pgTable("feed_tombstones", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  entitlementGeneration: bigint("entitlement_generation", { mode: "number" }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  feedSequence: bigint("feed_sequence", { mode: "number" }).notNull(),
  removedFeedId: uuid("removed_feed_id"),
  objectType: text("object_type").notNull(),
  objectId: uuid("object_id").notNull(),
  reasonClass: text("reason_class").notNull(),
  tombstoneSha256: bytea("tombstone_sha256").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const governanceCitations = pgTable("governance_citations", {
  id: uuid().primaryKey().notNull(),
  profileId: uuid("profile_id").notNull(),
  ruleTemplateId: uuid("rule_template_id"),
  sourceDocumentVersionId: uuid("source_document_version_id").notNull(),
  sourceDocumentSha256: bytea("source_document_sha256").notNull(),
  clause: text().notNull(),
  locator: text().notNull()
});

export const governanceRuleTemplates = pgTable("governance_rule_templates", {
  id: uuid().primaryKey().notNull(),
  profileId: uuid("profile_id").notNull(),
  code: text().notNull(),
  approvalRuleId: uuid("approval_rule_id").notNull(),
  exactRulePayload: jsonb("exact_rule_payload").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull()
});

export const governanceSeatRules = pgTable("governance_seat_rules", {
  id: uuid().primaryKey().notNull(),
  profileId: uuid("profile_id").notNull(),
  seatClass: text("seat_class").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  minimumWeight: bigint("minimum_weight", { mode: "number" }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  maximumWeight: bigint("maximum_weight", { mode: "number" }).notNull(),
  eligibilityConstraints: jsonb("eligibility_constraints").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull()
});

export const managementQuestionAnswers = pgTable("management_question_answers", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  questionId: uuid("question_id").notNull(),
  answerTurnId: uuid("answer_turn_id").notNull(),
  managementAuthorId: uuid("management_author_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const managementQuestionTurns = pgTable("management_question_turns", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  questionId: uuid("question_id").notNull(),
  ordinal: integer().notNull(),
  turnKind: text("turn_kind").notNull(),
  authorMemberId: uuid("author_member_id").notNull(),
  authorRole: text("author_role").notNull(),
  canonicalText: text("canonical_text").notNull(),
  textSha256: bytea("text_sha256").notNull(),
  citationSnapshot: jsonb("citation_snapshot").notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const managementRevisionReplies = pgTable("management_revision_replies", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  requestId: uuid("request_id").notNull(),
  submissionVersionId: uuid("submission_version_id").notNull(),
  managementAuthorId: uuid("management_author_id").notNull(),
  canonicalReply: text("canonical_reply").notNull(),
  replySha256: bytea("reply_sha256").notNull(),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const managementRevisionRequests = pgTable("management_revision_requests", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  threadId: uuid("thread_id").notNull(),
  submissionVersionId: uuid("submission_version_id").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  requestText: text("request_text").notNull(),
  requestSha256: bytea("request_sha256").notNull(),
  consentRecordId: uuid("consent_record_id"),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const managementSubmissionDispositions = pgTable("management_submission_dispositions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  threadId: uuid("thread_id").notNull(),
  submissionVersionId: uuid("submission_version_id").notNull(),
  disposition: text().notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  reason: text().notNull(),
  resultingDraftId: uuid("resulting_draft_id"),
  consentRecordId: uuid("consent_record_id"),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const managementSubmissionVersions = pgTable("management_submission_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  threadId: uuid("thread_id").notNull(),
  version: integer().notNull(),
  schemaVersion: text("schema_version").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  documentReferences: jsonb("document_references").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  authorMemberId: uuid("author_member_id").notNull(),
  changeReason: text("change_reason").notNull(),
  supersedesId: uuid("supersedes_id"),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const matterEvaluations = pgTable("matter_evaluations", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  requesterMemberId: uuid("requester_member_id").notNull(),
  profileId: uuid("profile_id").notNull(),
  rulesetId: uuid("ruleset_id").notNull(),
  matterTypeId: uuid("matter_type_id").notNull(),
  engineVersion: text("engine_version").notNull(),
  canonicalFacts: jsonb("canonical_facts").notNull(),
  factsSha256: bytea("facts_sha256").notNull(),
  result: text().notNull(),
  matchedRuleId: uuid("matched_rule_id"),
  candidateRuleIds: uuid("candidate_rule_ids").array().default([""]).notNull(),
  citationSnapshot: jsonb("citation_snapshot").notNull(),
  resultDetails: jsonb("result_details").default({}).notNull(),
  resultSha256: bytea("result_sha256").notNull(),
  evaluatedAt: timestamp("evaluated_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const meetingAttendance = pgTable("meeting_attendance", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  meetingId: uuid("meeting_id").notNull(),
  memberId: uuid("member_id").notNull(),
  attendanceStatus: text("attendance_status").notNull(),
  source: text().notNull(),
  recorderMemberId: uuid("recorder_member_id").notNull(),
  correctsId: uuid("corrects_id"),
  correctionReason: text("correction_reason"),
  consentRecordId: uuid("consent_record_id"),
  recordedAt: timestamp("recorded_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const meetingTranscriptVersions = pgTable("meeting_transcript_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  transcriptId: uuid("transcript_id").notNull(),
  version: integer().notNull(),
  canonicalSchema: text("canonical_schema").notNull(),
  mediaType: text("media_type").notNull(),
  canonicalBytes: bytea("canonical_bytes").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  sourceType: text("source_type").notNull(),
  coverageStart: timestamp("coverage_start", { precision: 6, withTimezone: true, mode: "string" }),
  coverageEnd: timestamp("coverage_end", { precision: 6, withTimezone: true, mode: "string" }),
  coverageStatement: text("coverage_statement").notNull(),
  verificationState: text("verification_state").default("agent_prepared_unverified").notNull(),
  createdBy: uuid("created_by").notNull(),
  supersedesId: uuid("supersedes_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const meetingVersions = pgTable("meeting_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  meetingId: uuid("meeting_id").notNull(),
  version: integer().notNull(),
  canonicalSchema: text("canonical_schema").notNull(),
  canonicalTitle: text("canonical_title").notNull(),
  scheduledStart: timestamp("scheduled_start", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  scheduledEnd: timestamp("scheduled_end", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  noticePackage: bytea("notice_package").notNull(),
  noticePackageSha256: bytea("notice_package_sha256").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  changeReason: text("change_reason").notNull(),
  consentRecordId: uuid("consent_record_id"),
  createdBy: uuid("created_by").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const membershipVersions = pgTable("membership_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  membershipId: uuid("membership_id").notNull(),
  version: integer().notNull(),
  seatRole: text("seat_role").notNull(),
  isChair: boolean("is_chair").default(false).notNull(),
  isSecretary: boolean("is_secretary").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  votingWeight: bigint("voting_weight", { mode: "number" }).notNull(),
  authoritySnapshot: jsonb("authority_snapshot").notNull(),
  snapshotSha256: bytea("snapshot_sha256").notNull(),
  changeReason: text("change_reason").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  consentRecordId: uuid("consent_record_id"),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesActionDeclarations = pgTable("minutes_action_declarations", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  minutesId: uuid("minutes_id").notNull(),
  minutesVersionId: uuid("minutes_version_id").notNull(),
  minutesSha256: bytea("minutes_sha256").notNull(),
  declaration: text().notNull(),
  completeManifest: bytea("complete_manifest").notNull(),
  manifestSha256: bytea("manifest_sha256").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  declaredAt: timestamp("declared_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesActionItemDispositions = pgTable("minutes_action_item_dispositions", {
  id: uuid().primaryKey().notNull(),
  taskId: uuid("task_id").notNull(),
  staleMinutesVersionId: uuid("stale_minutes_version_id").notNull(),
  replacementMinutesVersionId: uuid("replacement_minutes_version_id").notNull(),
  disposition: text().notNull(),
  reason: text().notNull(),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesCorrectionCycles = pgTable("minutes_correction_cycles", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  originalMinutesId: uuid("original_minutes_id").notNull(),
  replacementMinutesId: uuid("replacement_minutes_id").notNull(),
  reason: text().notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesDiffs = pgTable("minutes_diffs", {
  id: uuid().primaryKey().notNull(),
  minutesId: uuid("minutes_id").notNull(),
  baseVersionId: uuid("base_version_id").notNull(),
  newVersionId: uuid("new_version_id").notNull(),
  operations: jsonb().notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesResignRequirements = pgTable("minutes_resign_requirements", {
  id: uuid().primaryKey().notNull(),
  minutesId: uuid("minutes_id").notNull(),
  signerMemberId: uuid("signer_member_id").notNull(),
  fromPackageId: uuid("from_package_id").notNull(),
  toPackageId: uuid("to_package_id").notNull(),
  state: text().default("pending").notNull(),
  resolution: text(),
  resolvedSignatureId: uuid("resolved_signature_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  resolvedAt: timestamp("resolved_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const minutesReviewDispositions = pgTable("minutes_review_dispositions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  reviewItemId: uuid("review_item_id").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  decision: text().notNull(),
  reason: text().notNull(),
  resultingMinutesVersionId: uuid("resulting_minutes_version_id"),
  diffId: uuid("diff_id"),
  consentRecordId: uuid("consent_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesReviewItems = pgTable("minutes_review_items", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  minutesId: uuid("minutes_id").notNull(),
  itemKind: text("item_kind").notNull(),
  schemaVersion: text("schema_version").notNull(),
  authorMemberId: uuid("author_member_id").notNull(),
  authorSeatRole: text("author_seat_role").notNull(),
  baseVersionId: uuid("base_version_id").notNull(),
  baseSha256: bytea("base_sha256").notNull(),
  exactAnchor: jsonb("exact_anchor").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesReviewWithdrawals = pgTable("minutes_review_withdrawals", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  reviewItemId: uuid("review_item_id").notNull(),
  authorMemberId: uuid("author_member_id").notNull(),
  currentMinutesVersionId: uuid("current_minutes_version_id").notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  withdrawnAt: timestamp("withdrawn_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesSignatureSupersessions = pgTable("minutes_signature_supersessions", {
  id: uuid().primaryKey().notNull(),
  oldSignatureId: uuid("old_signature_id").notNull(),
  oldPackageId: uuid("old_package_id").notNull(),
  newMinutesVersionId: uuid("new_minutes_version_id").notNull(),
  newPackageId: uuid("new_package_id").notNull(),
  reason: text().notNull(),
  auditEventId: uuid("audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesSignatures = pgTable("minutes_signatures", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  packageId: uuid("package_id").notNull(),
  minutesVersionId: uuid("minutes_version_id").notNull(),
  packageSha256: bytea("package_sha256").notNull(),
  signerMemberId: uuid("signer_member_id").notNull(),
  signerSeatRole: text("signer_seat_role").notNull(),
  reservationSha256: bytea("reservation_sha256"),
  consentRecordId: uuid("consent_record_id").notNull(),
  accessTokenRecordId: uuid("access_token_record_id").notNull(),
  clientId: uuid("client_id").notNull(),
  exactOrigin: text("exact_origin").notNull(),
  stagedAt: timestamp("staged_at", { precision: 6, withTimezone: true, mode: "string" }).notNull(),
  signedAt: timestamp("signed_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  signatureRecordSha256: bytea("signature_record_sha256").notNull()
});

export const minutesVersions = pgTable("minutes_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  minutesId: uuid("minutes_id").notNull(),
  version: integer().notNull(),
  canonicalSchema: text("canonical_schema").notNull(),
  canonicalText: text("canonical_text").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  packageBaseSha256: bytea("package_base_sha256").notNull(),
  transcriptVersionId: uuid("transcript_version_id"),
  transcriptSha256: bytea("transcript_sha256"),
  createdBy: uuid("created_by").notNull(),
  supersedesId: uuid("supersedes_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const notificationAttempts = pgTable("notification_attempts", {
  id: uuid().primaryKey().notNull(),
  notificationJobId: uuid("notification_job_id").notNull(),
  attempt: integer().notNull(),
  requestSha256: bytea("request_sha256").notNull(),
  resultClass: text("result_class").notNull(),
  errorClass: text("error_class"),
  httpStatus: integer("http_status"),
  responseSha256: bytea("response_sha256"),
  startedAt: timestamp("started_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const onboardingAttestations = pgTable("onboarding_attestations", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  boardId: uuid("board_id").notNull(),
  termsVersionId: uuid("terms_version_id").notNull(),
  supportVersionId: uuid("support_version_id").notNull(),
  presentationChoice: text("presentation_choice").notNull(),
  localMemoryChoice: text("local_memory_choice").notNull(),
  consentRecordId: uuid("consent_record_id"),
  onboardingBrowserStageId: uuid("onboarding_browser_stage_id"),
  attestedAt: timestamp("attested_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const onboardingBrowserStages = pgTable("onboarding_browser_stages", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  sessionId: uuid("session_id").notNull(),
  clientId: uuid("client_id").notNull(),
  accessTokenRecordId: uuid("access_token_record_id").notNull(),
  tokenJti: uuid("token_jti").notNull(),
  termsVersionId: uuid("terms_version_id").notNull(),
  supportVersionId: uuid("support_version_id").notNull(),
  presentationChoice: text("presentation_choice").notNull(),
  localMemoryChoice: text("local_memory_choice").notNull(),
  requestSha256: bytea("request_sha256").notNull(),
  stageTokenSha256: bytea("stage_token_sha256").notNull(),
  safeResponseSha256: bytea("safe_response_sha256").notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  exactOrigin: text("exact_origin").notNull(),
  state: text().default("active").notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  createdAuditEventId: uuid("created_audit_event_id").notNull(),
  attestedAuditEventId: uuid("attested_audit_event_id"),
  completedAt: timestamp("completed_at", { precision: 6, withTimezone: true, mode: "string" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const onboardingTermsVersions = pgTable("onboarding_terms_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  seatRole: text("seat_role").notNull(),
  version: integer().notNull(),
  schemaVersion: text("schema_version").notNull(),
  canonicalText: text("canonical_text").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  materialChange: boolean("material_change").notNull(),
  effectiveAt: timestamp("effective_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  createdBy: uuid("created_by").notNull(),
  publicationConsentRecordId: uuid("publication_consent_record_id"),
  publicationAuditEventId: uuid("publication_audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const proxyGrants = pgTable("proxy_grants", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  principalMemberId: uuid("principal_member_id").notNull(),
  holderMemberId: uuid("holder_member_id").notNull(),
  policy: text().notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  grantedAt: timestamp("granted_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const proxyRevocations = pgTable("proxy_revocations", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  grantId: uuid("grant_id").notNull(),
  revokerMemberId: uuid("revoker_member_id").notNull(),
  reason: text().notNull(),
  effect: text().notNull(),
  consentRecordId: uuid("consent_record_id"),
  revokedAt: timestamp("revoked_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const questionDecisionLinks = pgTable("question_decision_links", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  questionId: uuid("question_id").notNull(),
  inclusiveTurnOrdinal: integer("inclusive_turn_ordinal").notNull(),
  inclusiveTurnSha256: bytea("inclusive_turn_sha256").notNull(),
  decisionPackageId: uuid("decision_package_id").notNull(),
  decisionPackageVersion: integer("decision_package_version").notNull(),
  decisionPackageSha256: bytea("decision_package_sha256").notNull(),
  selectedBy: uuid("selected_by").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const resolutionVersions = pgTable("resolution_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  version: integer().notNull(),
  canonicalSchema: text("canonical_schema").notNull(),
  canonicalText: text("canonical_text").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  supersedesId: uuid("supersedes_id"),
  authorMemberId: uuid("author_member_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const retentionSnapshots = pgTable("retention_snapshots", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  objectType: text("object_type").notNull(),
  objectId: uuid("object_id").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  objectVersion: bigint("object_version", { mode: "number" }).notNull(),
  canonicalSchema: text("canonical_schema").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  contentReferences: jsonb("content_references").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const ruleCitations = pgTable("rule_citations", {
  id: uuid().primaryKey().notNull(),
  ruleId: uuid("rule_id").notNull(),
  sourceDocumentVersionId: uuid("source_document_version_id").notNull(),
  sourceDocumentSha256: bytea("source_document_sha256").notNull(),
  clause: text().notNull(),
  locator: text().notNull()
});

export const rulesetRules = pgTable("ruleset_rules", {
  id: uuid().primaryKey().notNull(),
  rulesetId: uuid("ruleset_id").notNull(),
  matterTypeId: uuid("matter_type_id").notNull(),
  priority: integer().notNull(),
  specificity: integer().notNull(),
  conditionTree: jsonb("condition_tree").notNull(),
  approvalRuleId: uuid("approval_rule_id").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull()
});

export const secretarySupportVersions = pgTable("secretary_support_versions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  version: integer().notNull(),
  supportName: text("support_name").notNull(),
  contactMethods: jsonb("contact_methods").notNull(),
  canonicalSha256: bytea("canonical_sha256").notNull(),
  effectiveAt: timestamp("effective_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  createdBy: uuid("created_by").notNull(),
  publicationConsentRecordId: uuid("publication_consent_record_id"),
  publicationAuditEventId: uuid("publication_audit_event_id"),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const taskClosures = pgTable("task_closures", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  taskId: uuid("task_id").notNull(),
  primaryEvidenceId: uuid("primary_evidence_id").notNull(),
  acceptedEvidenceManifest: jsonb("accepted_evidence_manifest").notNull(),
  sourceMinutesSha256: bytea("source_minutes_sha256"),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  closureSha256: bytea("closure_sha256").notNull(),
  closedAt: timestamp("closed_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const taskCorrectionCycles = pgTable("task_correction_cycles", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  priorTaskId: uuid("prior_task_id").notNull(),
  priorClosureId: uuid("prior_closure_id").notNull(),
  replacementTaskId: uuid("replacement_task_id").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  reason: text().notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const taskEvidenceReviews = pgTable("task_evidence_reviews", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  evidenceId: uuid("evidence_id").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  decision: text().notNull(),
  reason: text().notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  reviewedAt: timestamp("reviewed_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const transcriptChallengeDispositions = pgTable("transcript_challenge_dispositions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  challengeId: uuid("challenge_id").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  decision: text().notNull(),
  reason: text().notNull(),
  correctedTranscriptVersionId: uuid("corrected_transcript_version_id"),
  consentRecordId: uuid("consent_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const transcriptQuestionLinks = pgTable("transcript_question_links", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  transcriptVersionId: uuid("transcript_version_id").notNull(),
  firstTurnId: uuid("first_turn_id").notNull(),
  lastTurnId: uuid("last_turn_id").notNull(),
  turnsSha256: bytea("turns_sha256").notNull(),
  managementQuestionId: uuid("management_question_id").notNull(),
  managementQuestionSha256: bytea("management_question_sha256").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const transcriptTurns = pgTable("transcript_turns", {
  id: uuid().primaryKey().notNull(),
  transcriptVersionId: uuid("transcript_version_id").notNull(),
  ordinal: integer().notNull(),
  speakerMemberId: uuid("speaker_member_id"),
  speakerLabel: text("speaker_label").notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  startsAtMs: bigint("starts_at_ms", { mode: "number" }),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  endsAtMs: bigint("ends_at_ms", { mode: "number" }),
  canonicalText: text("canonical_text").notNull(),
  textSha256: bytea("text_sha256").notNull()
});

export const transcriptVerifications = pgTable("transcript_verifications", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  transcriptVersionId: uuid("transcript_version_id").notNull(),
  transcriptSha256: bytea("transcript_sha256").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  status: text().notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  verifiedAt: timestamp("verified_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteCertificates = pgTable("vote_certificates", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  outcomeId: uuid("outcome_id").notNull(),
  publicId: bytea("public_id").notNull(),
  schemaVersion: text("schema_version").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  signature: bytea("signature").notNull(),
  signingKeyId: uuid("signing_key_id").notNull(),
  certificateIssuedAuditEventId: uuid("certificate_issued_audit_event_id").notNull(),
  voteClosedAuditEventId: uuid("vote_closed_audit_event_id").notNull(),
  state: text().default("current").notNull(),
  supersedesId: uuid("supersedes_id"),
  issuedAt: timestamp("issued_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteCloseStageMaterial = pgTable("vote_close_stage_material", {
  stageId: uuid("stage_id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  outcomeId: uuid("outcome_id").notNull(),
  certificateId: uuid("certificate_id").notNull(),
  certificatePublicId: bytea("certificate_public_id").notNull(),
  certificatePublicIdSha256: bytea("certificate_public_id_sha256").notNull(),
  signingKeyId: uuid("signing_key_id").notNull(),
  closeConsentRecordId: uuid("close_consent_record_id").notNull(),
  closingAuditEventId: uuid("closing_audit_event_id").notNull(),
  expectedTallySha256: bytea("expected_tally_sha256").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteCreationStageMaterial = pgTable("vote_creation_stage_material", {
  stageId: uuid("stage_id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  wizardDraftId: uuid("wizard_draft_id").notNull(),
  wizardStepId: uuid("wizard_step_id").notNull(),
  resolutionVersionId: uuid("resolution_version_id").notNull(),
  decisionPackageId: uuid("decision_package_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  voteOpenedAuditEventId: uuid("vote_opened_audit_event_id").notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  ruleOverrideId: uuid("rule_override_id"),
  ruleOverrideAuditEventId: uuid("rule_override_audit_event_id"),
  ruleOverrideIdempotencyRecordId: uuid("rule_override_idempotency_record_id"),
  decisionPackageComponentIds: uuid("decision_package_component_ids").array().notNull(),
  questionDecisionLinkIds: uuid("question_decision_link_ids").array().notNull(),
  electorateEntryIds: uuid("electorate_entry_ids").array().notNull(),
  deliveryMemberIds: uuid("delivery_member_ids").array().notNull(),
  deliveryNoticeIds: uuid("delivery_notice_ids").array().notNull(),
  deliveryFeedIds: uuid("delivery_feed_ids").array().notNull(),
  deliveryAuditEventIds: uuid("delivery_audit_event_ids").array().notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteReplacementStageMaterial = pgTable("vote_replacement_stage_material", {
  stageId: uuid("stage_id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  oldVoteId: uuid("old_vote_id").notNull(),
  newVoteId: uuid("new_vote_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  canonicalMaterial: bytea("canonical_material").notNull(),
  materialSha256: bytea("material_sha256").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteElectorate = pgTable("vote_electorate", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  memberId: uuid("member_id").notNull(),
  membershipVersionId: uuid("membership_version_id").notNull(),
  seatRole: text("seat_role").notNull(),
  isChair: boolean("is_chair").default(false).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  votingWeight: bigint("voting_weight", { mode: "number" }).notNull(),
  eligibilitySnapshot: jsonb("eligibility_snapshot").notNull(),
  eligibilitySha256: bytea("eligibility_sha256").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteOutcomes = pgTable("vote_outcomes", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  decisionPackageId: uuid("decision_package_id").notNull(),
  electorateSha256: bytea("electorate_sha256").notNull(),
  approvalRuleId: uuid("approval_rule_id").notNull(),
  canonicalTally: jsonb("canonical_tally").notNull(),
  tallySha256: bytea("tally_sha256").notNull(),
  outcome: text().notNull(),
  closeMode: text("close_mode").notNull(),
  closeActorMemberId: uuid("close_actor_member_id"),
  closeConsentRecordId: uuid("close_consent_record_id"),
  certificateId: uuid("certificate_id").notNull(),
  certificatePublicId: bytea("certificate_public_id").notNull(),
  canonicalCertificatePayload: bytea("canonical_certificate_payload").notNull(),
  certificatePayloadSha256: bytea("certificate_payload_sha256").notNull(),
  signingKeyId: uuid("signing_key_id").notNull(),
  clockSampleId: uuid("clock_sample_id").notNull(),
  closingAuditEventId: uuid("closing_audit_event_id").notNull(),
  closeRequestSha256: bytea("close_request_sha256").notNull(),
  finalizedAt: timestamp("finalized_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteSupersessions = pgTable("vote_supersessions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  oldVoteId: uuid("old_vote_id").notNull(),
  newVoteId: uuid("new_vote_id").notNull(),
  changedComponentClasses: text("changed_component_classes").array().notNull(),
  oldPackageSha256: bytea("old_package_sha256").notNull(),
  newPackageSha256: bytea("new_package_sha256").notNull(),
  secretaryMemberId: uuid("secretary_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  reason: text().notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteSourceUpdateCauses = pgTable("vote_source_update_causes", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  voteId: uuid("vote_id").notNull(),
  sourceClass: text("source_class").notNull(),
  sourceId: uuid("source_id").notNull(),
  sourceVersion: integer("source_version").notNull(),
  sourceSha256: bytea("source_sha256").notNull(),
  triggerAuditEventId: uuid("trigger_audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const voteSourceUpdateDispositions = pgTable("vote_source_update_dispositions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  causeId: uuid("cause_id").notNull(),
  sourceVoteId: uuid("source_vote_id").notNull(),
  replacementVoteId: uuid("replacement_vote_id"),
  effect: text().notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  reason: text().notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const wizardSteps = pgTable("wizard_steps", {
  id: uuid().primaryKey().notNull(),
  draftId: uuid("draft_id").notNull(),
  ordinal: integer().notNull(),
  questionCode: text("question_code").notNull(),
  valueSchema: text("value_schema").notNull(),
  canonicalValue: bytea("canonical_value").notNull(),
  valueSha256: bytea("value_sha256").notNull(),
  recommendedRuleId: uuid("recommended_rule_id"),
  citationSnapshot: jsonb("citation_snapshot").notNull(),
  overrideSelected: boolean("override_selected").default(false).notNull(),
  overrideReason: text("override_reason"),
  attempt: integer().notNull(),
  recordedAt: timestamp("recorded_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const oauthClientGrants = pgTable("oauth_client_grants", {
  clientId: uuid("client_id").notNull(),
  grantType: text("grant_type").notNull(),
  scope: text().notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const oauthClientRedirectUris = pgTable("oauth_client_redirect_uris", {
  clientId: uuid("client_id").notNull(),
  redirectUri: text("redirect_uri").notNull(),
  redirectUriSha256: bytea("redirect_uri_sha256").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesSignatureRequirements = pgTable("minutes_signature_requirements", {
  packageId: uuid("package_id").notNull(),
  memberId: uuid("member_id").notNull(),
  seatRole: text("seat_role").notNull(),
  requirement: text().notNull(),
  memberSnapshotSha256: bytea("member_snapshot_sha256").notNull()
});

export const rateLimitBuckets = pgTable("rate_limit_buckets", {
  bucketClass: text("bucket_class").notNull(),
  subjectSha256: bytea("subject_sha256").notNull(),
  windowStartedAt: timestamp("window_started_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  windowSeconds: integer("window_seconds").notNull(),
  requestCount: integer("request_count").notNull(),
  blockedUntil: timestamp("blocked_until", { precision: 6, withTimezone: true, mode: "string" })
});

export const circulationRecipients = pgTable("circulation_recipients", {
  circulationId: uuid("circulation_id").notNull(),
  memberId: uuid("member_id").notNull(),
  documentVersionId: uuid("document_version_id").notNull(),
  entitlementSnapshotSha256: bytea("entitlement_snapshot_sha256").notNull(),
  noticeId: uuid("notice_id"),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  feedSequence: bigint("feed_sequence", { mode: "number" }),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const clockHealthSamples = pgTable("clock_health_samples", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  source: text().notNull(),
  measuredAt: timestamp("measured_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  // You can use { mode: "bigint" } if numbers are exceeding js number limitations
  driftMicroseconds: bigint("drift_microseconds", { mode: "number" }).notNull(),
  validUntil: timestamp("valid_until", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  recordedAt: timestamp("recorded_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  healthy: boolean()
});

export const proposals = pgTable("proposals", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  proposerMemberId: uuid("proposer_member_id").notNull(),
  proposalType: text("proposal_type").notNull(),
  title: text().notNull(),
  schemaVersion: text("schema_version").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  resourceReferences: jsonb("resource_references").notNull(),
  state: text().default("pending").notNull(),
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  lastAuditEventId: uuid("last_audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  closedAt: timestamp("closed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const proposalDispositions = pgTable("proposal_dispositions", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  proposalId: uuid("proposal_id").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  disposition: text().notNull(),
  reason: text(),
  resultingDraftId: uuid("resulting_draft_id"),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const secretariatRequests = pgTable("secretariat_requests", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  requesterMemberId: uuid("requester_member_id").notNull(),
  topic: text().notNull(),
  state: text().default("open").notNull(),
  currentTurnId: uuid("current_turn_id"),
  rowVersion: bigint("row_version", { mode: "number" }).default(1).notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  lastAuditEventId: uuid("last_audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  closedAt: timestamp("closed_at", { precision: 6, withTimezone: true, mode: "string" })
});

export const secretariatRequestTurns = pgTable("secretariat_request_turns", {
  id: uuid().primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  requestId: uuid("request_id").notNull(),
  ordinal: integer().notNull(),
  turnKind: text("turn_kind").notNull(),
  authorMemberId: uuid("author_member_id").notNull(),
  authorRole: text("author_role").notNull(),
  canonicalText: text("canonical_text").notNull(),
  textSha256: bytea("text_sha256").notNull(),
  resourceReferences: jsonb("resource_references").notNull(),
  idempotencyRecordId: uuid("idempotency_record_id").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const FROZEN_SCHEMA_TABLES = Object.freeze({
  schemaMigrations,
  accessTokenRecords,
  accountablePrincipals,
  actionStages,
  agendaItems,
  agendaVersions,
  auditChainHead,
  authSessions,
  backupReceipts,
  boardMemberships,
  boards,
  cryptoKeyRegistry,
  documentAccessGrants,
  documentExclusions,
  documentSearch,
  documents,
  enrollmentActivationChallenges,
  enrollmentInvitations,
  exportArtifacts,
  exportChunks,
  exportRequests,
  externalIdentityLinks,
  governanceProfiles,
  idempotencyRecords,
  identityRecoveryRequests,
  inputRequiredAttempts,
  jobAttemptResults,
  jobs,
  managementQuestions,
  managementSubmissionThreads,
  matterTypes,
  meetingRsvps,
  meetingTranscripts,
  meetings,
  memberContactPoints,
  memberWebhooks,
  members,
  minutes,
  minutesSignaturePackages,
  notices,
  notificationJobs,
  oauthAuthorizationCodes,
  oauthAuthorizationRequests,
  oauthClients,
  oauthConsents,
  oidcLoginTransactions,
  organizationRoleAssignments,
  organizations,
  pendingActionFeed,
  questionVisibility,
  refreshFamilies,
  refreshTokens,
  ruleOverrides,
  rulesets,
  systemInstance,
  taskEvidence,
  tasks,
  totpCredentials,
  transcriptChallenges,
  voteExclusions,
  votes,
  webauthnChallenges,
  webauthnCredentials,
  wizardDrafts,
  approvalRules,
  auditCheckpoints,
  auditEvents,
  ballotDispositions,
  ballots,
  boardVersions,
  configReceipts,
  consentRecords,
  decisionPackageComponents,
  decisionPackages,
  deletionTombstones,
  documentCirculations,
  documentValidationAttempts,
  documentVersions,
  feedTombstones,
  governanceCitations,
  governanceRuleTemplates,
  governanceSeatRules,
  managementQuestionAnswers,
  managementQuestionTurns,
  managementRevisionReplies,
  managementRevisionRequests,
  managementSubmissionDispositions,
  managementSubmissionVersions,
  matterEvaluations,
  meetingAttendance,
  meetingTranscriptVersions,
  meetingVersions,
  membershipVersions,
  minutesActionDeclarations,
  minutesActionItemDispositions,
  minutesCorrectionCycles,
  minutesDiffs,
  minutesResignRequirements,
  minutesReviewDispositions,
  minutesReviewItems,
  minutesReviewWithdrawals,
  minutesSignatureSupersessions,
  minutesSignatures,
  minutesVersions,
  notificationAttempts,
  onboardingAttestations,
  onboardingBrowserStages,
  onboardingTermsVersions,
  proxyGrants,
  proxyRevocations,
  questionDecisionLinks,
  resolutionVersions,
  retentionSnapshots,
  ruleCitations,
  rulesetRules,
  secretarySupportVersions,
  taskClosures,
  taskCorrectionCycles,
  taskEvidenceReviews,
  transcriptChallengeDispositions,
  transcriptQuestionLinks,
  transcriptTurns,
  transcriptVerifications,
  voteCertificates,
  voteCloseStageMaterial,
  voteCreationStageMaterial,
  voteReplacementStageMaterial,
  voteElectorate,
  voteOutcomes,
  voteSourceUpdateCauses,
  voteSourceUpdateDispositions,
  voteSupersessions,
  wizardSteps,
  oauthClientGrants,
  oauthClientRedirectUris,
  minutesSignatureRequirements,
  rateLimitBuckets,
  circulationRecipients,
  clockHealthSamples,
  proposals,
  proposalDispositions,
  secretariatRequests,
  secretariatRequestTurns
});

export const companyAdminProposals = pgTable("company_admin_proposals", {
  id: uuid("id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  operation: text("operation").notNull(),
  issuerMemberId: uuid("issuer_member_id").notNull(),
  issuerAssignmentId: uuid("issuer_assignment_id").notNull(),
  targetMemberId: uuid("target_member_id").notNull(),
  issuerIdentityGeneration: bigint("issuer_identity_generation", { mode: "bigint" }).notNull(),
  targetIdentityGeneration: bigint("target_identity_generation", { mode: "bigint" }).notNull(),
  targetMemberVersion: bigint("target_member_version", { mode: "bigint" }).notNull(),
  reason: text("reason").notNull(),
  state: text("state").default("pending").notNull(),
  rowVersion: bigint("row_version", { mode: "bigint" }).default(1n).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true, mode: "string" }).notNull(),
  creationConsentId: uuid("creation_consent_id").notNull(),
  creationAuditId: uuid("creation_audit_id").notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true, mode: "string" }),
  completionConsentId: uuid("completion_consent_id"),
  completionAuditId: uuid("completion_audit_id"),
  grantedAssignmentId: uuid("granted_assignment_id")
});

export const memberAdminDelegations = pgTable("member_admin_delegations", {
  id: uuid("id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  issuerMemberId: uuid("issuer_member_id").notNull(),
  secretaryMembershipId: uuid("secretary_membership_id").notNull(),
  secretaryMembershipVersion: integer("secretary_membership_version").notNull(),
  reason: text("reason").notNull(),
  authorityEvidence: jsonb("authority_evidence").notNull(),
  state: text("state").default("active").notNull(),
  rowVersion: bigint("row_version", { mode: "bigint" }).default(1n).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true, mode: "string" }).notNull(),
  creationConsentId: uuid("creation_consent_id").notNull(),
  creationAuditId: uuid("creation_audit_id").notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "string" }),
  revocationConsentId: uuid("revocation_consent_id"),
  revocationAuditId: uuid("revocation_audit_id")
});

export const administrativeAuthorityChanges = pgTable("administrative_authority_changes", {
  id: uuid("id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id"),
  recordType: text("record_type").notNull(),
  recordId: uuid("record_id").notNull(),
  recordVersion: bigint("record_version", { mode: "bigint" }).notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  actionCode: text("action_code").notNull(),
  operation: text("operation").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  canonicalPayload: bytea("canonical_payload").notNull(),
  payloadSha256: bytea("payload_sha256").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const ADMINISTRATIVE_SCHEMA_TABLES = Object.freeze({
  companyAdminProposals,
  memberAdminDelegations,
  administrativeAuthorityChanges
});
export const recoveryRegistrationGrants = pgTable("recovery_registration_grants", {
  recoveryRequestId: uuid("recovery_request_id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  issuedBy: uuid("issued_by").notNull(),
  issuerIdentityGeneration: bigint("issuer_identity_generation", { mode: "bigint" }).notNull(),
  targetIdentityGeneration: bigint("target_identity_generation", { mode: "bigint" }).notNull(),
  tokenSha256: bytea("token_sha256").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  consumedAt: timestamp("consumed_at", { precision: 6, withTimezone: true, mode: "string" }),
  credentialId: uuid("credential_id"),
  auditEventId: uuid("audit_event_id"),
  pendingCredential: jsonb("pending_credential"),
  activationChallengeId: uuid("activation_challenge_id"),
  activationCodeSha256: bytea("activation_code_sha256"),
  activationExpiresAt: timestamp("activation_expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }),
  attemptCount: integer("attempt_count").default(0).notNull(),
  activatedAt: timestamp("activated_at", { precision: 6, withTimezone: true, mode: "string" }),
  activationAuditId: uuid("activation_audit_id")
});

export const activationRestartGrants = pgTable("activation_restart_grants", {
  id: uuid("id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  issuedBy: uuid("issued_by"),
  issuerKind: text("issuer_kind").notNull(),
  proofingMethod: text("proofing_method").notNull(),
  tokenSha256: bytea("token_sha256").notNull(),
  staleChallengeId: uuid("stale_challenge_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull(),
  expiresAt: timestamp("expires_at", {
    precision: 6,
    withTimezone: true,
    mode: "string"
  }).notNull(),
  consumedAt: timestamp("consumed_at", { precision: 6, withTimezone: true, mode: "string" }),
  freshChallengeId: uuid("fresh_challenge_id"),
  issuedAuditEventId: uuid("issued_audit_event_id").notNull(),
  completedAuditEventId: uuid("completed_audit_event_id")
});

export const identityAdminConsentUses = pgTable("identity_admin_consent_uses", {
  consentRecordId: uuid("consent_record_id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  actionCode: text("action_code").notNull(),
  usedAt: timestamp("used_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const memberFeedSyncCounters = pgTable("member_feed_sync_counters", {
  organizationId: uuid("organization_id").notNull(),
  memberId: uuid("member_id").notNull(),
  lastSequence: bigint("last_sequence", { mode: "bigint" }).notNull()
});

export const memberFeedSyncPositions = pgTable("member_feed_sync_positions", {
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  entryKind: text("entry_kind").notNull(),
  entryId: uuid("entry_id").notNull(),
  feedId: uuid("feed_id"),
  tombstoneId: uuid("tombstone_id"),
  changeSequence: bigint("change_sequence", { mode: "bigint" }).notNull()
});

export const boardExclusions = pgTable("board_exclusions", {
  id: uuid("id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  memberId: uuid("member_id").notNull(),
  version: integer("version").notNull(),
  state: text("state").notNull(),
  reason: text("reason").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const meetingExclusions = pgTable("meeting_exclusions", {
  id: uuid("id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  meetingId: uuid("meeting_id").notNull(),
  memberId: uuid("member_id").notNull(),
  version: integer("version").notNull(),
  state: text("state").notNull(),
  reason: text("reason").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const minutesExclusions = pgTable("minutes_exclusions", {
  id: uuid("id").primaryKey().notNull(),
  organizationId: uuid("organization_id").notNull(),
  boardId: uuid("board_id").notNull(),
  minutesId: uuid("minutes_id").notNull(),
  memberId: uuid("member_id").notNull(),
  version: integer("version").notNull(),
  state: text("state").notNull(),
  reason: text("reason").notNull(),
  actorMemberId: uuid("actor_member_id").notNull(),
  consentRecordId: uuid("consent_record_id").notNull(),
  auditEventId: uuid("audit_event_id").notNull(),
  createdAt: timestamp("created_at", { precision: 6, withTimezone: true, mode: "string" })
    .default(sql`transaction_timestamp()`)
    .notNull()
});

export const ACTIVE_SCHEMA_TABLES = Object.freeze({
  memberFeedSyncCounters,
  memberFeedSyncPositions,
  boardExclusions,
  meetingExclusions,
  minutesExclusions,
  keyLifecycleContactEffects,
  keyLifecycleWebhookRewraps,
  keyLifecycleWebhookDisables,
  keyLifecycleTotpEffects,
  keyLifecycleBrowserEffects,
  keyLifecycleAffectedFamilies,
  keyLifecycleOperations,
  keyLifecycleCompletions,
  auditRecoveries,
  auditRecoveryCompletions,
  recoveryRegistrationGrants,
  activationRestartGrants,
  identityAdminConsentUses,
  ...FROZEN_SCHEMA_TABLES,
  ...ADMINISTRATIVE_SCHEMA_TABLES
});
