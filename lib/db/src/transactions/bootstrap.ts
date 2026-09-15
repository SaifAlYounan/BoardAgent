import type { PoolClient } from "pg";
import { z } from "zod";

import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type JsonValue
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";

const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.boolean(),
    z.null(),
    z.number().finite(),
    z.string(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema)
  ])
);
const CanonicalNameSchema = z
  .string()
  .min(1)
  .max(512)
  .transform((value) => canonicalText(value));
const SlugSchema = z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u);
const TimezoneSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => {
    try {
      new Intl.DateTimeFormat("en", { timeZone: value }).format(0);
      return true;
    } catch {
      return false;
    }
  }, "timezone must be a supported IANA name");
const CanonicalResourceSchema = z
  .string()
  .url()
  .superRefine((value, context) => {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      parsed.pathname !== "/mcp" ||
      parsed.search !== "" ||
      parsed.hash !== "" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.href !== value ||
      parsed.hostname !== parsed.hostname.toLowerCase()
    ) {
      context.addIssue({
        code: "custom",
        message: "resource URI must be exact canonical HTTPS /mcp"
      });
    }
  });

export const BootstrapInstanceInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    organizationLegalName: CanonicalNameSchema,
    organizationDisplayName: CanonicalNameSchema,
    organizationSlug: SlugSchema,
    timezone: TimezoneSchema,
    instanceId: UuidV7Schema,
    canonicalResourceUri: CanonicalResourceSchema,
    boardId: UuidV7Schema,
    boardVersionId: UuidV7Schema,
    boardSlug: SlugSchema,
    boardName: CanonicalNameSchema,
    boardCanonicalPayload: z.record(z.string(), JsonValueSchema),
    memberId: UuidV7Schema,
    memberLegalName: CanonicalNameSchema,
    memberDisplayName: CanonicalNameSchema,
    adminRoleAssignmentId: UuidV7Schema,
    secretariatRoleAssignmentId: UuidV7Schema,
    membershipId: UuidV7Schema,
    membershipVersionId: UuidV7Schema,
    votingWeight: z.number().int().min(1).max(1_000_000_000),
    supportVersionId: UuidV7Schema,
    supportName: CanonicalNameSchema,
    supportContactMethods: z.array(JsonValueSchema).max(32),
    onboardingTermsVersionId: UuidV7Schema,
    onboardingTermsText: z
      .string()
      .min(1)
      .max(1_048_576)
      .transform((value) => canonicalText(value)),
    invitationId: UuidV7Schema,
    invitationTokenSha256: Sha256HexSchema,
    invitationHandoffMethod: z
      .string()
      .min(1)
      .max(512)
      .transform((value) => canonicalText(value)),
    auditEventId: UuidV7Schema
  })
  .strict();
export type BootstrapInstanceInput = z.input<typeof BootstrapInstanceInputSchema>;

export interface BootstrapInstanceResult {
  readonly alreadyBootstrapped: boolean;
  readonly instanceId: string;
  readonly organizationId: string;
  readonly boardId: string;
  readonly firstMemberId: string;
  readonly invitationId: string;
  readonly invitationExpiresAt?: string;
  readonly auditEventId?: string;
  readonly auditSequence?: string;
}

const BootstrapActivationFeedEntrySchema = z
  .object({ boardId: UuidV7Schema, feedId: UuidV7Schema })
  .strict();

export const BootstrapEnrollmentActivationInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    invitationId: UuidV7Schema,
    challengeId: UuidV7Schema,
    protectedCodeSha256: Sha256HexSchema,
    proofingMethod: z.enum(["in_person", "verified_number_call"]),
    feedEntries: z.array(BootstrapActivationFeedEntrySchema).min(1).max(25),
    auditEventId: UuidV7Schema
  })
  .strict();
export type BootstrapEnrollmentActivationInput = z.input<
  typeof BootstrapEnrollmentActivationInputSchema
>;

export type BootstrapEnrollmentActivationResult =
  | {
      readonly activated: true;
      readonly memberId: string;
      readonly rowVersion: string;
      readonly feedCount: number;
      readonly auditEventId: string;
      readonly auditSequence: string;
    }
  | {
      readonly activated: false;
      readonly reason: "code_mismatch";
      readonly challengeState: "issued" | "revoked";
      readonly attemptCount: number;
      readonly auditEventId: string;
      readonly auditSequence: string;
    };

export class BootstrapTransactionError extends Error {
  public constructor(
    public readonly code:
      | "bootstrap_context_invalid"
      | "already_bootstrapped"
      | "bootstrap_conflict"
      | "bootstrap_renewal_unavailable"
      | "bootstrap_restart_unavailable"
      | "bootstrap_activation_unavailable",
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "BootstrapTransactionError";
  }
}

const BOOTSTRAP_ADVISORY_LOCK = 4_242_486_065_882_902n;

interface ExistingBootstrapRow {
  readonly instance_id: string;
  readonly organization_id: string;
  readonly board_id: string | null;
  readonly member_id: string | null;
  readonly invitation_id: string | null;
  readonly invitation_token_sha256: Buffer | null;
}

async function assertBootstrapContext(client: PoolClient): Promise<void> {
  const result = await client.query<{
    role_name: string;
    scope: string;
    isolation: string;
  }>(
    `select current_user as role_name,
            current_setting('boardagent.transaction_scope',true) as scope,
            current_setting('transaction_isolation') as isolation`
  );
  const row = result.rows[0];
  if (
    !row ||
    row.role_name !== "boardagent_migrator" ||
    row.scope !== "bootstrap" ||
    row.isolation !== "serializable"
  ) {
    throw new BootstrapTransactionError(
      "bootstrap_context_invalid",
      "bootstrap requires the managed serializable migrator transaction"
    );
  }
}

export async function bootstrapInstanceInTransaction(
  client: PoolClient,
  rawInput: BootstrapInstanceInput
): Promise<BootstrapInstanceResult> {
  const input = BootstrapInstanceInputSchema.parse(rawInput);
  await assertBootstrapContext(client);
  await client.query("select pg_advisory_xact_lock($1)", [BOOTSTRAP_ADVISORY_LOCK.toString()]);
  const existing = await client.query<ExistingBootstrapRow>(
    `select instance.instance_id,instance.organization_id,
            (select id from boards where organization_id=instance.organization_id order by id limit 1) as board_id,
            (select id from members where organization_id=instance.organization_id order by id limit 1) as member_id,
            (select invitation.id from enrollment_invitations as invitation
              where invitation.organization_id=instance.organization_id order by invitation.issued_at,id limit 1
            ) as invitation_id,
            (select invitation.token_sha256 from enrollment_invitations as invitation
              where invitation.organization_id=instance.organization_id order by invitation.issued_at,id limit 1
            ) as invitation_token_sha256
       from system_instance as instance where instance.singleton_key`
  );
  const prior = existing.rows[0];
  if (prior) {
    if (
      prior.instance_id === input.instanceId &&
      prior.organization_id === input.organizationId &&
      prior.board_id === input.boardId &&
      prior.member_id === input.memberId &&
      prior.invitation_id === input.invitationId &&
      prior.invitation_token_sha256 !== null &&
      safeHashEqual(prior.invitation_token_sha256.toString("hex"), input.invitationTokenSha256)
    ) {
      return {
        alreadyBootstrapped: true,
        instanceId: input.instanceId,
        organizationId: input.organizationId,
        boardId: input.boardId,
        firstMemberId: input.memberId,
        invitationId: input.invitationId
      };
    }
    throw new BootstrapTransactionError(
      "bootstrap_conflict",
      "the singleton instance is already bootstrapped with different identifiers"
    );
  }

  const roots = await client.query<{ organizations: string; members: string }>(
    `select (select count(*)::text from organizations) as organizations,
            (select count(*)::text from members) as members`
  );
  if (roots.rows[0]?.organizations !== "0" || roots.rows[0]?.members !== "0") {
    throw new BootstrapTransactionError(
      "already_bootstrapped",
      "bootstrap refuses a partially initialized identity root"
    );
  }

  const boardCanonicalPayload = JSON.parse(canonicalJson(input.boardCanonicalPayload)) as JsonValue;
  const boardCanonicalSha256 = canonicalSha256(boardCanonicalPayload);
  const supportCanonicalSha256 = canonicalSha256({
    schemaVersion: "boardagent.secretary-support.v1",
    boardId: input.boardId,
    version: 1,
    supportName: input.supportName,
    contactMethods: input.supportContactMethods
  });
  const onboardingTermsSha256 = sha256Hex(input.onboardingTermsText);
  const authoritySnapshot = {
    schemaVersion: "boardagent.membership-authority.v1",
    memberId: input.memberId,
    boardId: input.boardId,
    seatRole: "voting_member",
    isSecretary: true,
    votingWeight: input.votingWeight
  } as const;
  const authoritySnapshotSha256 = canonicalSha256(authoritySnapshot);

  await client.query(
    `insert into organizations(id,legal_name,display_name,slug,timezone)
     values ($1,$2,$3,$4,$5)`,
    [
      input.organizationId,
      input.organizationLegalName,
      input.organizationDisplayName,
      input.organizationSlug,
      input.timezone
    ]
  );
  await client.query(
    `insert into system_instance(instance_id,organization_id,canonical_resource_uri)
     values ($1,$2,$3)`,
    [input.instanceId, input.organizationId, input.canonicalResourceUri]
  );
  await client.query(
    `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
     values ($1,$2,'human',$3,$4,'invited')`,
    [input.memberId, input.organizationId, input.memberLegalName, input.memberDisplayName]
  );
  await client.query(
    `insert into boards(
       id,organization_id,slug,name,timezone,current_version_id
     ) values ($1,$2,$3,$4,$5,$6)`,
    [
      input.boardId,
      input.organizationId,
      input.boardSlug,
      input.boardName,
      input.timezone,
      input.boardVersionId
    ]
  );
  await client.query(
    `insert into board_versions(
       id,organization_id,board_id,version,canonical_schema,canonical_payload,
       canonical_sha256,change_reason,created_by
     ) values ($1,$2,$3,1,'boardagent.board.v1',$4,$5,'initial bootstrap',$6)`,
    [
      input.boardVersionId,
      input.organizationId,
      input.boardId,
      boardCanonicalPayload,
      Buffer.from(boardCanonicalSha256, "hex"),
      input.memberId
    ]
  );
  await client.query(
    `insert into organization_role_assignments(
       id,organization_id,member_id,role,change_reason
     ) values
       ($1,$3,$4,'admin','initial bootstrap'),
       ($2,$3,$4,'secretariat','initial bootstrap')`,
    [
      input.adminRoleAssignmentId,
      input.secretariatRoleAssignmentId,
      input.organizationId,
      input.memberId
    ]
  );
  await client.query(
    `insert into board_memberships(
       id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
     ) values ($1,$2,$3,$4,'voting_member',true,$5,'active')`,
    [input.membershipId, input.organizationId, input.boardId, input.memberId, input.votingWeight]
  );
  await client.query(
    `insert into membership_versions(
       id,organization_id,board_id,member_id,membership_id,version,seat_role,is_secretary,
       voting_weight,authority_snapshot,snapshot_sha256,change_reason,actor_member_id
     ) values ($1,$2,$3,$4,$5,1,'voting_member',true,$6,$7,$8,
               'initial bootstrap',$4)`,
    [
      input.membershipVersionId,
      input.organizationId,
      input.boardId,
      input.memberId,
      input.membershipId,
      input.votingWeight,
      authoritySnapshot,
      Buffer.from(authoritySnapshotSha256, "hex")
    ]
  );
  await client.query(
    `insert into secretary_support_versions(
       id,organization_id,board_id,version,support_name,contact_methods,canonical_sha256,
       effective_at,created_by
     ) values ($1,$2,$3,1,$4,$5,$6,transaction_timestamp(),$7)`,
    [
      input.supportVersionId,
      input.organizationId,
      input.boardId,
      input.supportName,
      canonicalJson(input.supportContactMethods),
      Buffer.from(supportCanonicalSha256, "hex"),
      input.memberId
    ]
  );
  await client.query(
    `insert into onboarding_terms_versions(
       id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
       material_change,effective_at,created_by
     ) select case when initial_role.seat_role='voting_member' then $1::uuid
                   else pg_catalog.uuidv7() end,
              $2,initial_role.seat_role,1,'boardagent.onboarding-terms.v1',$3,$4,true,
              transaction_timestamp(),$5
         from (values ('voting_member'),('management'),('observer')) as initial_role(seat_role)`,
    [
      input.onboardingTermsVersionId,
      input.organizationId,
      input.onboardingTermsText,
      Buffer.from(onboardingTermsSha256, "hex"),
      input.memberId
    ]
  );
  const invitation = await client.query<{ expires_at: string }>(
    `insert into enrollment_invitations(
       id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at
     ) values ($1,$2,$3,$4,$3,$5,transaction_timestamp()+interval '24 hours')
     returning to_char(expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at`,
    [
      input.invitationId,
      input.organizationId,
      input.memberId,
      Buffer.from(input.invitationTokenSha256, "hex"),
      input.invitationHandoffMethod
    ]
  );
  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.auditEventId,
        eventType: "enrollment_issued",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "enrollment_invitation",
        entityId: input.invitationId,
        boardId: input.boardId,
        origin: "cli",
        details: {
          bootstrap: true,
          instanceId: input.instanceId,
          organizationId: input.organizationId,
          boardId: input.boardId,
          firstMemberId: input.memberId,
          boardCanonicalSha256,
          authoritySnapshotSha256,
          onboardingTermsSha256,
          onboardingSeatRoles: ["voting_member", "management", "observer"],
          supportCanonicalSha256,
          invitationTokenSha256: input.invitationTokenSha256,
          expiresInSeconds: 86_400
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit || !invitation.rows[0]) throw new Error("bootstrap did not return its evidence rows");
  return {
    alreadyBootstrapped: false,
    instanceId: input.instanceId,
    organizationId: input.organizationId,
    boardId: input.boardId,
    firstMemberId: input.memberId,
    invitationId: input.invitationId,
    invitationExpiresAt: invitation.rows[0].expires_at,
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}

interface BootstrapActivationMemberRow {
  readonly organization_id: string;
  readonly display_name: string;
  readonly state: string;
  readonly row_version: string;
}

interface BootstrapActivationInvitationRow {
  readonly organization_id: string;
  readonly member_id: string;
  readonly consumption_valid: boolean;
  readonly pending_activation_member_id: string | null;
  readonly revoked_at: string | null;
}

interface BootstrapActivationChallengeRow {
  readonly organization_id: string;
  readonly member_id: string;
  readonly invitation_id: string;
  readonly protected_code: Buffer;
  readonly proofing_method: string;
  readonly state: string;
  readonly current: boolean;
  readonly attempt_count: number;
}

interface BootstrapActivationMembershipRow {
  readonly board_id: string;
  readonly entitlement_generation: string;
}

function bootstrapActivationUnavailable(): BootstrapTransactionError {
  return new BootstrapTransactionError(
    "bootstrap_activation_unavailable",
    "the first-secretary bootstrap activation is unavailable"
  );
}

function validBootstrapIssuancePayload(
  rawPayload: Buffer,
  input: Pick<
    z.output<typeof BootstrapEnrollmentActivationInputSchema>,
    "organizationId" | "memberId" | "invitationId"
  >
): boolean {
  let payload: unknown;
  try {
    payload = JSON.parse(rawPayload.toString("utf8"));
  } catch {
    return false;
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return false;
  const record = payload as Record<string, unknown>;
  const details = record["details"];
  if (typeof details !== "object" || details === null || Array.isArray(details)) return false;
  const detailRecord = details as Record<string, unknown>;
  return (
    record["eventType"] === "enrollment_issued" &&
    record["actorMemberId"] === null &&
    record["actorClientId"] === null &&
    record["tokenJti"] === null &&
    record["entityType"] === "enrollment_invitation" &&
    record["entityId"] === input.invitationId &&
    record["origin"] === "cli" &&
    detailRecord["bootstrap"] === true &&
    detailRecord["organizationId"] === input.organizationId &&
    detailRecord["firstMemberId"] === input.memberId
  );
}

export const BootstrapInvitationRenewalRequestSchema = z
  .object({
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    previousInvitationId: UuidV7Schema,
    canonicalResourceUri: CanonicalResourceSchema,
    handoffMethod: CanonicalNameSchema,
    reason: z
      .string()
      .min(1)
      .max(4096)
      .transform((value) => canonicalText(value))
  })
  .strict();

const BootstrapInvitationRenewalInputSchema = BootstrapInvitationRenewalRequestSchema.extend({
  invitationId: UuidV7Schema,
  invitationTokenSha256: Sha256HexSchema,
  revokedAuditEventId: UuidV7Schema,
  issuedAuditEventId: UuidV7Schema
}).strict();

/** A local operator may replace only the expired, unredeemed invitation of the untouched first person. */
export async function renewBootstrapInvitationInTransaction(
  client: PoolClient,
  rawInput: z.input<typeof BootstrapInvitationRenewalInputSchema>
) {
  const input = BootstrapInvitationRenewalInputSchema.parse(rawInput);
  await assertBootstrapContext(client);
  await client.query("select pg_advisory_xact_lock($1)", [BOOTSTRAP_ADVISORY_LOCK.toString()]);
  const unavailable = () =>
    new BootstrapTransactionError(
      "bootstrap_renewal_unavailable",
      "the untouched first invitation cannot be renewed"
    );
  const instance = await client.query<{
    instance_id: string;
    organization_id: string;
    canonical_resource_uri: string;
  }>(
    "select instance_id,organization_id,canonical_resource_uri from system_instance where singleton_key"
  );
  if (
    instance.rows.length !== 1 ||
    instance.rows[0]?.instance_id !== input.instanceId ||
    instance.rows[0]?.organization_id !== input.organizationId ||
    instance.rows[0]?.canonical_resource_uri !== input.canonicalResourceUri
  )
    throw unavailable();
  // Match enrollment's invitation -> member order. Revoking the old row invalidates an in-flight redemption.
  const previous = await client.query<{
    member_id: string;
    issued_by: string;
    untouched_expired: boolean;
    token_sha256: Buffer;
  }>(
    `select member_id,issued_by,token_sha256,
       expires_at<=transaction_timestamp() and consumed_at is null and revoked_at is null
       and pending_activation_member_id is null as untouched_expired
     from enrollment_invitations where organization_id=$1 and id=$2 for update`,
    [input.organizationId, input.previousInvitationId]
  );
  const member = await client.query<{ state: string; member_kind: string; row_version: string }>(
    "select state,member_kind,row_version::text from members where organization_id=$1 and id=$2 for update",
    [input.organizationId, input.memberId]
  );
  const prior = previous.rows[0];
  if (
    previous.rows.length !== 1 ||
    !prior?.untouched_expired ||
    prior.member_id !== input.memberId ||
    prior.issued_by !== input.memberId ||
    member.rows.length !== 1 ||
    member.rows[0]?.state !== "invited" ||
    member.rows[0]?.member_kind !== "human" ||
    member.rows[0]?.row_version !== "1"
  )
    throw unavailable();
  const roots = await client.query<{
    member_count: string;
    role_count: string;
    credentials: string;
    activations: string;
    latest_invitation: string;
  }>(
    `select (select count(*)::text from members where organization_id=$1) as member_count,
       (select count(distinct role)::text from organization_role_assignments where organization_id=$1
         and member_id=$2 and role in ('admin','secretariat') and active_from<=transaction_timestamp()
         and (active_until is null or active_until>transaction_timestamp())) as role_count,
       (select count(*)::text from webauthn_credentials where organization_id=$1) as credentials,
       (select count(*)::text from enrollment_activation_challenges where organization_id=$1) as activations,
       (select id from enrollment_invitations where organization_id=$1 and member_id=$2 order by issued_at desc,id desc limit 1) as latest_invitation`,
    [input.organizationId, input.memberId]
  );
  const root = roots.rows[0];
  if (
    !root ||
    root.member_count !== "1" ||
    root.role_count !== "2" ||
    root.credentials !== "0" ||
    root.activations !== "0" ||
    root.latest_invitation !== input.previousInvitationId
  )
    throw unavailable();
  const evidence = await client.query<{ canonical_payload: Buffer; board_id: string | null }>(
    `select canonical_payload,board_id from audit_events where organization_id=$1 and event_type='enrollment_issued'
       and object_type='enrollment_invitation' and object_id=$2 order by sequence`,
    [input.organizationId, input.previousInvitationId]
  );
  const issuance = evidence.rows[0];
  if (
    evidence.rows.length !== 1 ||
    !issuance?.board_id ||
    !validBootstrapIssuancePayload(issuance.canonical_payload, {
      organizationId: input.organizationId,
      memberId: input.memberId,
      invitationId: input.previousInvitationId
    })
  )
    throw unavailable();
  const seats = await client.query<{ board_id: string }>(
    `select board_id from board_memberships where organization_id=$1 and member_id=$2
      and is_secretary and state='active' and active_from<=transaction_timestamp()
      and (active_until is null or active_until>transaction_timestamp()) order by board_id`,
    [input.organizationId, input.memberId]
  );
  if (seats.rows.length !== 1 || seats.rows[0]?.board_id !== issuance.board_id) throw unavailable();
  if (safeHashEqual(prior.token_sha256.toString("hex"), input.invitationTokenSha256))
    throw unavailable();
  const revoked = await client.query(
    "update enrollment_invitations set revoked_at=transaction_timestamp() where organization_id=$1 and id=$2 and revoked_at is null and consumed_at is null",
    [input.organizationId, input.previousInvitationId]
  );
  if (revoked.rowCount !== 1) throw unavailable();
  const inserted = await client.query<{ expires_at: string }>(
    `insert into enrollment_invitations(id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at)
     values($1,$2,$3,$4,$3,$5,transaction_timestamp()+interval '24 hours')
     returning to_char(expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at`,
    [
      input.invitationId,
      input.organizationId,
      input.memberId,
      Buffer.from(input.invitationTokenSha256, "hex"),
      input.handoffMethod
    ]
  );
  const details = {
    bootstrap: true,
    renewal: true,
    instanceId: input.instanceId,
    organizationId: input.organizationId,
    firstMemberId: input.memberId,
    boardId: issuance.board_id,
    previousInvitationId: input.previousInvitationId,
    newInvitationId: input.invitationId,
    reason: input.reason,
    handoffMethod: input.handoffMethod
  };
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.revokedAuditEventId,
        eventType: "enrollment_revoked",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "enrollment_invitation",
        entityId: input.previousInvitationId,
        boardId: issuance.board_id,
        origin: "cli",
        details,
        schemaVersion: 1
      }
    },
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.issuedAuditEventId,
        eventType: "enrollment_issued",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "enrollment_invitation",
        entityId: input.invitationId,
        boardId: issuance.board_id,
        origin: "cli",
        details: {
          ...details,
          invitationTokenSha256: input.invitationTokenSha256,
          expiresInSeconds: 86_400
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!inserted.rows[0]) throw unavailable();
  return {
    instanceId: input.instanceId,
    organizationId: input.organizationId,
    firstMemberId: input.memberId,
    boardId: issuance.board_id,
    previousInvitationId: input.previousInvitationId,
    invitationId: input.invitationId,
    invitationExpiresAt: inserted.rows[0].expires_at
  };
}

export const BootstrapActivationRestartRequestSchema = z
  .object({
    instanceId: UuidV7Schema,
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    canonicalResourceUri: CanonicalResourceSchema,
    proofingMethod: z.enum(["in_person", "verified_number_call"]),
    reason: z
      .string()
      .min(1)
      .max(4096)
      .transform((value) => canonicalText(value))
  })
  .strict();

const BootstrapActivationRestartInputSchema = BootstrapActivationRestartRequestSchema.extend({
  grantId: UuidV7Schema,
  /** SHA-256 of the 256-bit restart token. The raw token must never cross this boundary. */
  tokenSha256: Sha256HexSchema,
  auditEventId: UuidV7Schema
}).strict();

const BootstrapActivationRestartResultSchema = z
  .object({
    grantId: UuidV7Schema,
    memberId: UuidV7Schema,
    staleChallengeId: UuidV7Schema,
    memberDisplayName: z.string().min(1).max(512),
    expiresAt: z.string().min(1).max(64)
  })
  .strict();

/**
 * A local operator may restart only the singleton first person's stuck activation: the
 * registered setup administrator whose ten-minute code expired or was exhausted before
 * `activate-first`. SQL0170 owns every eligibility rule; this appends the `cli` issuance
 * audit the function verifies, then records the one-use ten-minute handoff.
 */
export async function issueFirstActivationRestartInTransaction(
  client: PoolClient,
  rawInput: z.input<typeof BootstrapActivationRestartInputSchema>
) {
  const input = BootstrapActivationRestartInputSchema.parse(rawInput);
  await assertBootstrapContext(client);
  await client.query("select pg_advisory_xact_lock($1)", [BOOTSTRAP_ADVISORY_LOCK.toString()]);
  const unavailable = (cause?: unknown) =>
    new BootstrapTransactionError(
      "bootstrap_restart_unavailable",
      "the first activation cannot be restarted",
      cause === undefined ? undefined : { cause }
    );
  const instance = await client.query<{
    instance_id: string;
    organization_id: string;
    canonical_resource_uri: string;
  }>(
    "select instance_id,organization_id,canonical_resource_uri from system_instance where singleton_key"
  );
  if (
    instance.rows.length !== 1 ||
    instance.rows[0]?.instance_id !== input.instanceId ||
    instance.rows[0]?.organization_id !== input.organizationId ||
    instance.rows[0]?.canonical_resource_uri !== input.canonicalResourceUri
  )
    throw unavailable();
  const latest = await client.query<{ id: string; expires_at: string }>(
    `select id,to_char((transaction_timestamp()+interval '10 minutes') at time zone 'UTC',
              'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at
       from enrollment_activation_challenges where organization_id=$1 and member_id=$2
      order by issued_at desc,id desc limit 1`,
    [input.organizationId, input.memberId]
  );
  const stale = latest.rows[0];
  if (!stale) throw unavailable();
  await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.auditEventId,
        eventType: "activation_restart_issued",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "activation_restart_grant",
        entityId: input.grantId,
        boardId: null,
        origin: "cli",
        details: {
          bootstrap: true,
          restart: true,
          instanceId: input.instanceId,
          organizationId: input.organizationId,
          firstMemberId: input.memberId,
          memberId: input.memberId,
          staleChallengeId: stale.id,
          grantId: input.grantId,
          proofingMethod: input.proofingMethod,
          expiresAt: stale.expires_at,
          reason: input.reason
        },
        schemaVersion: 1
      }
    }
  ]);
  let issued: unknown;
  try {
    const result = await client.query<{ issued: unknown }>(
      "select boardagent_issue_first_activation_restart($1,$2,$3,$4) as issued",
      [
        Buffer.from(input.tokenSha256, "hex"),
        input.grantId,
        input.auditEventId,
        input.proofingMethod
      ]
    );
    issued = result.rows[0]?.issued;
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error.code === "42501" || error.code === "22023" || error.code === "23514")
    )
      throw unavailable(error);
    throw error;
  }
  const row = BootstrapActivationRestartResultSchema.parse(issued);
  if (
    row.grantId !== input.grantId ||
    row.memberId !== input.memberId ||
    row.staleChallengeId !== stale.id ||
    row.expiresAt !== stale.expires_at
  )
    throw unavailable();
  return {
    instanceId: input.instanceId,
    organizationId: input.organizationId,
    firstMemberId: input.memberId,
    grantId: row.grantId,
    staleChallengeId: row.staleChallengeId,
    expiresAt: row.expiresAt
  };
}

/**
 * Completes only the initial bootstrap invitation after its passkey ceremony. This is
 * the sole preidentity activation path; it cannot target later members and permanently
 * closes as soon as the first member becomes active.
 */
export async function activateBootstrapEnrollmentInTransaction(
  client: PoolClient,
  rawInput: BootstrapEnrollmentActivationInput
): Promise<BootstrapEnrollmentActivationResult> {
  const input = BootstrapEnrollmentActivationInputSchema.parse(rawInput);
  await assertBootstrapContext(client);
  if (
    new Set(input.feedEntries.map(({ boardId }) => boardId)).size !== input.feedEntries.length ||
    new Set(input.feedEntries.map(({ feedId }) => feedId)).size !== input.feedEntries.length
  ) {
    throw bootstrapActivationUnavailable();
  }
  await client.query("select pg_advisory_xact_lock($1)", [BOOTSTRAP_ADVISORY_LOCK.toString()]);
  const instance = await client.query<{ organization_id: string }>(
    "select organization_id from system_instance where singleton_key"
  );
  if (instance.rows.length !== 1 || instance.rows[0]?.organization_id !== input.organizationId) {
    throw bootstrapActivationUnavailable();
  }

  // Preserve the ordinary activation lock order: invitation, target, challenge.
  const invitationResult = await client.query<BootstrapActivationInvitationRow>(
    `select organization_id,member_id,pending_activation_member_id,
            revoked_at::text,
            consumed_at is not null
              and consumed_at<=expires_at
              and consumed_at<=transaction_timestamp() as consumption_valid
       from enrollment_invitations
      where id=$1 and organization_id=$2
      for update`,
    [input.invitationId, input.organizationId]
  );
  const memberResult = await client.query<BootstrapActivationMemberRow>(
    `select organization_id,display_name,state,row_version::text
       from members where id=$1 and organization_id=$2 for update`,
    [input.memberId, input.organizationId]
  );
  const challengeResult = await client.query<BootstrapActivationChallengeRow>(
    `select organization_id,member_id,invitation_id,protected_code,proofing_method,
            state,expires_at>transaction_timestamp() as current,attempt_count
       from enrollment_activation_challenges
      where id=$1 and organization_id=$2 for update`,
    [input.challengeId, input.organizationId]
  );
  const invitation = invitationResult.rows[0];
  const member = memberResult.rows[0];
  const challenge = challengeResult.rows[0];

  const identityRoots = await client.query<{
    member_count: string;
    admin_count: string;
    secretariat_count: string;
    credential_count: string;
  }>(
    `select
       (select count(*)::text from members where organization_id=$1) as member_count,
       (select count(*)::text from organization_role_assignments
         where organization_id=$1 and member_id=$2 and role='admin'
           and active_from<=transaction_timestamp()
           and (active_until is null or active_until>transaction_timestamp())) as admin_count,
       (select count(*)::text from organization_role_assignments
         where organization_id=$1 and member_id=$2 and role='secretariat'
           and active_from<=transaction_timestamp()
           and (active_until is null or active_until>transaction_timestamp()))
         as secretariat_count,
       (select count(*)::text from webauthn_credentials
         where organization_id=$1 and member_id=$2 and state='active') as credential_count`,
    [input.organizationId, input.memberId]
  );
  const roots = identityRoots.rows[0];
  const memberships = await client.query<BootstrapActivationMembershipRow>(
    `select board_id,entitlement_generation::text
       from board_memberships
      where organization_id=$1 and member_id=$2 and is_secretary and state='active'
        and active_from<=transaction_timestamp()
        and (active_until is null or active_until>transaction_timestamp())
      order by board_id`,
    [input.organizationId, input.memberId]
  );
  const bootstrapAudit = await client.query<{
    canonical_payload: Buffer;
    event_type: string;
    object_id: string | null;
  }>(
    `select canonical_payload,event_type,object_id
       from audit_events
      where organization_id=$1 and event_type='enrollment_issued'
        and object_type='enrollment_invitation' and object_id=$2
      order by sequence`,
    [input.organizationId, input.invitationId]
  );
  const initialAudit = bootstrapAudit.rows[0];
  const expectedBoardIds = memberships.rows.map(({ board_id }) => board_id);
  const suppliedEntries = [...input.feedEntries].toSorted((left, right) =>
    left.boardId.localeCompare(right.boardId)
  );
  if (
    !invitation ||
    !member ||
    !challenge ||
    !roots ||
    !initialAudit ||
    bootstrapAudit.rows.length !== 1 ||
    invitation.organization_id !== input.organizationId ||
    invitation.member_id !== input.memberId ||
    invitation.pending_activation_member_id !== input.memberId ||
    !invitation.consumption_valid ||
    invitation.revoked_at !== null ||
    member.state !== "pending_activation" ||
    challenge.member_id !== input.memberId ||
    challenge.invitation_id !== input.invitationId ||
    challenge.proofing_method !== input.proofingMethod ||
    challenge.state !== "issued" ||
    !challenge.current ||
    challenge.attempt_count >= 20 ||
    roots.member_count !== "1" ||
    roots.admin_count !== "1" ||
    roots.secretariat_count !== "1" ||
    roots.credential_count === "0" ||
    expectedBoardIds.length === 0 ||
    expectedBoardIds.length > 25 ||
    canonicalJson(suppliedEntries.map(({ boardId }) => boardId)) !==
      canonicalJson(expectedBoardIds) ||
    initialAudit.event_type !== "enrollment_issued" ||
    initialAudit.object_id !== input.invitationId ||
    !validBootstrapIssuancePayload(initialAudit.canonical_payload, input)
  ) {
    throw bootstrapActivationUnavailable();
  }

  if (!safeHashEqual(challenge.protected_code.toString("hex"), input.protectedCodeSha256)) {
    const nextAttempt = challenge.attempt_count + 1;
    const nextState = nextAttempt >= 20 ? "revoked" : "issued";
    const [audit] = await appendAuditEventsInTransaction(client, [
      {
        organizationId: input.organizationId,
        event: {
          eventId: input.auditEventId,
          eventType: "authorization_denied",
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "enrollment_activation",
          entityId: input.challengeId,
          boardId: null,
          origin: "cli",
          details: {
            bootstrap: true,
            reason: "code_mismatch",
            memberId: input.memberId,
            invitationId: input.invitationId,
            attemptCount: nextAttempt,
            challengeState: nextState
          },
          schemaVersion: 1
        }
      }
    ]);
    if (!audit) throw new Error("bootstrap activation denial audit is unavailable");
    const changed = await client.query(
      `update enrollment_activation_challenges
          set attempt_count=$2,state=$3
        where id=$1 and state='issued' and attempt_count=$4`,
      [input.challengeId, nextAttempt, nextState, challenge.attempt_count]
    );
    if (changed.rowCount !== 1) throw bootstrapActivationUnavailable();
    return {
      activated: false,
      reason: "code_mismatch",
      challengeState: nextState,
      attemptCount: nextAttempt,
      auditEventId: audit.eventId,
      auditSequence: audit.sequence.toString(10)
    };
  }

  const nextRowVersion = (BigInt(member.row_version) + 1n).toString(10);
  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      objectVersion: BigInt(nextRowVersion),
      event: {
        eventId: input.auditEventId,
        eventType: "member_activated",
        actorMemberId: null,
        actorClientId: null,
        tokenJti: null,
        entityType: "member",
        entityId: input.memberId,
        boardId: null,
        origin: "cli",
        details: {
          bootstrap: true,
          invitationId: input.invitationId,
          challengeId: input.challengeId,
          proofingMethod: input.proofingMethod,
          passkeyEnrolled: true,
          feedBoardCount: memberships.rows.length
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("bootstrap activation audit is unavailable");
  for (const membership of memberships.rows) {
    const feedId = suppliedEntries.find(({ boardId }) => boardId === membership.board_id)?.feedId;
    if (!feedId) throw new Error("validated bootstrap feed identifier disappeared");
    const sequence = await client.query<{ next_sequence: string }>(
      `select (coalesce(max(feed_sequence),0)+1)::text as next_sequence
         from pending_action_feed
        where member_id=$1 and board_id=$2 and entitlement_generation=$3`,
      [input.memberId, membership.board_id, membership.entitlement_generation]
    );
    const nextSequence = sequence.rows[0]?.next_sequence;
    if (!nextSequence) throw new Error("bootstrap activation feed sequence is unavailable");
    const visibility = {
      memberId: input.memberId,
      boardId: membership.board_id,
      entitlementGeneration: membership.entitlement_generation
    } as const;
    const payload = {
      schemaVersion: "boardagent.pending-action.v1",
      actionType: "complete_onboarding",
      memberId: input.memberId,
      boardId: membership.board_id,
      objectType: "member",
      objectId: input.memberId,
      objectVersion: nextRowVersion
    } as const;
    await client.query(
      `insert into pending_action_feed(
         id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
         action_type,object_type,object_id,object_version,visibility_sha256,
         canonical_payload,payload_sha256,audit_event_id
       ) values ($1,$2,$3,$4,$5,$6,'complete_onboarding','member',$4,$7,$8,$9,$10,$11)`,
      [
        feedId,
        input.organizationId,
        membership.board_id,
        input.memberId,
        membership.entitlement_generation,
        nextSequence,
        nextRowVersion,
        Buffer.from(canonicalSha256(visibility), "hex"),
        Buffer.from(canonicalJson(payload), "utf8"),
        Buffer.from(canonicalSha256(payload), "hex"),
        audit.eventId
      ]
    );
  }
  const challengeUpdate = await client.query(
    `update enrollment_activation_challenges
        set state='consumed',consumed_at=transaction_timestamp()
      where id=$1 and state='issued' and attempt_count=$2`,
    [input.challengeId, challenge.attempt_count]
  );
  const memberUpdate = await client.query(
    `update members set state='active',row_version=row_version+1
      where id=$1 and state='pending_activation' and row_version=$2`,
    [input.memberId, member.row_version]
  );
  if (challengeUpdate.rowCount !== 1 || memberUpdate.rowCount !== 1) {
    throw bootstrapActivationUnavailable();
  }
  return {
    activated: true,
    memberId: input.memberId,
    rowVersion: nextRowVersion,
    feedCount: memberships.rows.length,
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}
