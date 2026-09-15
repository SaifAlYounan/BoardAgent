import type { PoolClient } from "pg";
import { z } from "zod";

import {
  OAuthRedirectUriSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  sha256Bytes
} from "@boardagent/contracts";

import { appendAuditEventsInTransaction } from "./audit.js";

const ScopeSchema = z.enum([
  "governance:read",
  "documents:read",
  "vote:act",
  "proxy:manage",
  "minutes:act",
  "member:propose",
  "secretariat:admin",
  "audit:read",
  "meeting:act",
  "task:act",
  "documents:contribute",
  "secretariat:message",
  "management:question",
  "notifications:manage",
  "onboarding:read"
]);
export type IdentityScope = z.infer<typeof ScopeSchema>;

const ExactHttpsSchema = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return (
      url.protocol === "https:" && url.href === value && url.username === "" && url.password === ""
    );
  }, "URL must be exact canonical HTTPS");

const EnrollmentFeedEntrySchema = z
  .object({ boardId: UuidV7Schema, feedId: UuidV7Schema })
  .strict();

export const ActivateEnrollmentInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    memberId: UuidV7Schema,
    invitationId: UuidV7Schema,
    challengeId: UuidV7Schema,
    protectedCodeSha256: Sha256HexSchema,
    proofingMethod: z.string().min(1).max(1024),
    secretaryMemberId: UuidV7Schema,
    secretarySessionId: UuidV7Schema,
    feedEntries: z.array(EnrollmentFeedEntrySchema).max(25),
    auditEventId: UuidV7Schema
  })
  .strict();
export type ActivateEnrollmentInput = z.input<typeof ActivateEnrollmentInputSchema>;

export type EnrollmentActivationResult =
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

export const IssueTokenInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    clientId: UuidV7Schema,
    authorizationCodeSha256: Sha256HexSchema,
    pkceVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/u),
    redirectUri: OAuthRedirectUriSchema,
    resourceUri: ExactHttpsSchema,
    refreshFamilyId: UuidV7Schema,
    refreshTokenId: UuidV7Schema,
    refreshTokenSha256: Sha256HexSchema,
    accessTokenRecordId: UuidV7Schema,
    accessTokenJti: UuidV7Schema,
    signingKeyId: UuidV7Schema,
    auditEventId: UuidV7Schema
  })
  .strict();
export type IssueTokenInput = z.input<typeof IssueTokenInputSchema>;

export const RefreshTokenInputSchema = z
  .object({
    organizationId: UuidV7Schema,
    clientId: UuidV7Schema,
    resourceUri: ExactHttpsSchema,
    presentedRefreshTokenSha256: Sha256HexSchema,
    replacementRefreshTokenId: UuidV7Schema,
    replacementRefreshTokenSha256: Sha256HexSchema,
    accessTokenRecordId: UuidV7Schema,
    accessTokenJti: UuidV7Schema,
    signingKeyId: UuidV7Schema,
    auditEventId: UuidV7Schema
  })
  .strict();
export type RefreshTokenInput = z.input<typeof RefreshTokenInputSchema>;

export interface TokenClaimsMaterial {
  readonly issuer: string;
  readonly audience: string;
  readonly resource: string;
  readonly subject: string;
  readonly clientId: string;
  readonly jti: string;
  readonly scopes: readonly IdentityScope[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly signingKeyId: string;
  readonly signingKeyKid: string;
  readonly signingKeyLocator: string;
}

export type TokenRefreshResult =
  | {
      readonly refreshed: true;
      readonly familyId: string;
      readonly generation: string;
      readonly claims: TokenClaimsMaterial;
      readonly auditEventId: string;
      readonly auditSequence: string;
    }
  | {
      readonly refreshed: false;
      readonly familyId: string;
      readonly state: "compromised" | "expired" | "revoked";
      readonly reuseDetected: boolean;
      readonly auditEventId?: string;
      readonly auditSequence?: string;
    };

export class IdentityTransactionError extends Error {
  public constructor(
    public readonly code:
      | "identity_context_invalid"
      | "enrollment_unavailable"
      | "secretary_confirmation_invalid"
      | "token_code_invalid"
      | "token_client_invalid"
      | "token_member_invalid"
      | "token_onboarding_required"
      | "token_signing_key_invalid"
      | "refresh_token_invalid",
    message: string
  ) {
    super(message);
    this.name = "IdentityTransactionError";
  }
}

interface IdentityContextRow {
  readonly role_name: string;
  readonly scope: string;
  readonly isolation: string;
  readonly organization_id: string | null;
}

async function assertIdentityContext(client: PoolClient, organizationId: string): Promise<void> {
  const result = await client.query<IdentityContextRow>(
    `select current_user as role_name,
            current_setting('boardagent.transaction_scope',true) as scope,
            current_setting('transaction_isolation') as isolation,
            boardagent_context_uuid('boardagent.organization_id')::text as organization_id`
  );
  const row = result.rows[0];
  if (
    !row ||
    row.role_name !== "boardagent_server" ||
    row.scope !== "identity" ||
    row.isolation !== "serializable" ||
    row.organization_id !== organizationId
  ) {
    throw new IdentityTransactionError(
      "identity_context_invalid",
      "identity operation requires a managed serializable server transaction"
    );
  }
}

interface EnrollmentPreparationRow {
  readonly result_status: "activated" | "code_mismatch" | "secretary_invalid" | "unavailable";
  readonly result_challenge_state: "consumed" | "issued" | "revoked" | null;
  readonly result_attempt_count: number | null;
  readonly result_member_row_version: string | null;
  readonly result_secretary_client_id: string | null;
  readonly result_board_ids: string[] | null;
}

interface EnrollmentFinalizationRow {
  readonly result_status: "activated" | "code_mismatch";
  readonly result_challenge_state: "consumed" | "issued" | "revoked";
  readonly result_attempt_count: number;
  readonly result_member_row_version: string | null;
}

interface MembershipFeedRow {
  readonly board_id: string;
  readonly entitlement_generation: string;
  readonly next_sequence: string;
}

export async function activateEnrollmentInTransaction(
  client: PoolClient,
  rawInput: ActivateEnrollmentInput
): Promise<EnrollmentActivationResult> {
  const input = ActivateEnrollmentInputSchema.parse(rawInput);
  await assertIdentityContext(client, input.organizationId);
  const suppliedEntries = [...input.feedEntries].toSorted((left, right) =>
    left.boardId.localeCompare(right.boardId)
  );
  if (new Set(suppliedEntries.map((entry) => entry.feedId)).size !== suppliedEntries.length) {
    throw new IdentityTransactionError(
      "enrollment_unavailable",
      "activation feed identifiers must be unique"
    );
  }
  const feedBoardIds = suppliedEntries.map((entry) => entry.boardId);
  const preparationResult = await client.query<EnrollmentPreparationRow>(
    `select result_status,result_challenge_state,result_attempt_count,
            result_member_row_version::text,result_secretary_client_id,result_board_ids
       from boardagent_prepare_enrollment_activation($1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[])`,
    [
      input.organizationId,
      input.memberId,
      input.invitationId,
      input.challengeId,
      Buffer.from(input.protectedCodeSha256, "hex"),
      input.proofingMethod,
      input.secretaryMemberId,
      input.secretarySessionId,
      feedBoardIds
    ]
  );
  const preparation = preparationResult.rows[0];
  if (!preparation || preparation.result_status === "unavailable") {
    throw new IdentityTransactionError(
      "enrollment_unavailable",
      "enrollment activation is unavailable"
    );
  }
  if (preparation.result_status === "secretary_invalid") {
    throw new IdentityTransactionError(
      "secretary_confirmation_invalid",
      "activation requires a recently authenticated secretary or admin"
    );
  }
  if (preparation.result_status === "code_mismatch") {
    const nextAttempt = preparation.result_attempt_count;
    const nextState = preparation.result_challenge_state;
    if (nextAttempt === null || (nextState !== "issued" && nextState !== "revoked")) {
      throw new Error("protected activation mismatch returned an invalid projection");
    }
    const [audit] = await appendAuditEventsInTransaction(client, [
      {
        organizationId: input.organizationId,
        event: {
          eventId: input.auditEventId,
          eventType: "authorization_denied",
          actorMemberId: input.secretaryMemberId,
          actorClientId: preparation.result_secretary_client_id,
          tokenJti: null,
          entityType: "enrollment_activation",
          entityId: input.challengeId,
          boardId: null,
          origin: "browser",
          details: {
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
    if (!audit) throw new Error("activation denial did not append its audit event");
    const finalized = await client.query<EnrollmentFinalizationRow>(
      `select result_status,result_challenge_state,result_attempt_count,
              result_member_row_version::text
         from boardagent_finalize_enrollment_activation(
           $1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[],$10,$11::uuid[]
         )`,
      [
        input.organizationId,
        input.memberId,
        input.invitationId,
        input.challengeId,
        Buffer.from(input.protectedCodeSha256, "hex"),
        input.proofingMethod,
        input.secretaryMemberId,
        input.secretarySessionId,
        feedBoardIds,
        audit.eventId,
        []
      ]
    );
    const finalizedMismatch = finalized.rows[0];
    if (
      !finalizedMismatch ||
      finalizedMismatch.result_status !== "code_mismatch" ||
      finalizedMismatch.result_challenge_state !== nextState ||
      finalizedMismatch.result_attempt_count !== nextAttempt ||
      finalizedMismatch.result_member_row_version !== null
    ) {
      throw new Error("protected activation mismatch finalization returned an invalid projection");
    }
    return {
      activated: false,
      reason: "code_mismatch",
      challengeState: nextState,
      attemptCount: nextAttempt,
      auditEventId: audit.eventId,
      auditSequence: audit.sequence.toString(10)
    };
  }

  const rowVersion = preparation.result_member_row_version;
  if (
    preparation.result_status !== "activated" ||
    rowVersion === null ||
    canonicalJson(preparation.result_board_ids) !== canonicalJson(feedBoardIds)
  ) {
    throw new Error("protected activation preparation returned an invalid success projection");
  }
  const activeMemberships = await client.query<Omit<MembershipFeedRow, "next_sequence">>(
    `select membership.board_id,membership.entitlement_generation::text
       from board_memberships as membership
      where membership.organization_id=$1 and membership.member_id=$2
        and membership.state='active'
        and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
      order by membership.board_id`,
    [input.organizationId, input.memberId]
  );
  const membershipRows: MembershipFeedRow[] = [];
  for (const membership of activeMemberships.rows) {
    const sequence = await client.query<{ next_sequence: string }>(
      `select (coalesce(max(feed_sequence),0)+1)::text as next_sequence
         from pending_action_feed
        where member_id=$1 and board_id=$2 and entitlement_generation=$3`,
      [input.memberId, membership.board_id, membership.entitlement_generation]
    );
    const nextSequence = sequence.rows[0]?.next_sequence;
    if (!nextSequence) throw new Error("activation feed sequence was unavailable");
    membershipRows.push({ ...membership, next_sequence: nextSequence });
  }
  const memberships = { rows: membershipRows };
  const expectedBoards = memberships.rows.map((row) => row.board_id);
  if (
    canonicalJson(suppliedEntries.map((entry) => entry.boardId)) !== canonicalJson(expectedBoards)
  ) {
    throw new IdentityTransactionError(
      "enrollment_unavailable",
      "activation feed identifiers do not cover the member's exact active boards"
    );
  }

  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      objectVersion: BigInt(rowVersion),
      event: {
        eventId: input.auditEventId,
        eventType: "member_activated",
        actorMemberId: input.secretaryMemberId,
        actorClientId: preparation.result_secretary_client_id,
        tokenJti: null,
        entityType: "member",
        entityId: input.memberId,
        boardId: null,
        origin: "browser",
        details: {
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
  if (!audit) throw new Error("activation did not append its audit event");
  for (const membership of memberships.rows) {
    const feedId = suppliedEntries.find((entry) => entry.boardId === membership.board_id)?.feedId;
    if (!feedId) throw new Error("validated activation feed entry disappeared");
    const payload = {
      schemaVersion: "boardagent.pending-action.v1",
      actionType: "complete_onboarding",
      memberId: input.memberId,
      boardId: membership.board_id,
      objectType: "member",
      objectId: input.memberId,
      objectVersion: rowVersion
    } as const;
    const visibility = {
      memberId: input.memberId,
      boardId: membership.board_id,
      entitlementGeneration: membership.entitlement_generation
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
        membership.next_sequence,
        rowVersion,
        Buffer.from(canonicalSha256(visibility), "hex"),
        Buffer.from(canonicalJson(payload), "utf8"),
        Buffer.from(canonicalSha256(payload), "hex"),
        audit.eventId
      ]
    );
  }
  const finalized = await client.query<EnrollmentFinalizationRow>(
    `select result_status,result_challenge_state,result_attempt_count,
            result_member_row_version::text
       from boardagent_finalize_enrollment_activation(
         $1,$2,$3,$4,$5,$6,$7,$8,$9::uuid[],$10,$11::uuid[]
       )`,
    [
      input.organizationId,
      input.memberId,
      input.invitationId,
      input.challengeId,
      Buffer.from(input.protectedCodeSha256, "hex"),
      input.proofingMethod,
      input.secretaryMemberId,
      input.secretarySessionId,
      feedBoardIds,
      audit.eventId,
      suppliedEntries.map((entry) => entry.feedId)
    ]
  );
  const finalizedActivation = finalized.rows[0];
  if (
    !finalizedActivation ||
    finalizedActivation.result_status !== "activated" ||
    finalizedActivation.result_challenge_state !== "consumed" ||
    finalizedActivation.result_member_row_version !== rowVersion
  ) {
    throw new Error("protected activation finalization returned an invalid projection");
  }
  return {
    activated: true,
    memberId: input.memberId,
    rowVersion,
    feedCount: memberships.rows.length,
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}

function normalizeScopes(values: readonly string[]): readonly IdentityScope[] {
  const parsed = values.map((value) => ScopeSchema.parse(value));
  if (new Set(parsed).size !== parsed.length) {
    throw new IdentityTransactionError(
      "token_client_invalid",
      "OAuth scope set contains duplicates"
    );
  }
  return parsed.toSorted();
}

const ONBOARDING_SCOPE: IdentityScope = "onboarding:read";

/**
 * The scopes an access token may carry right now. Ordinary scopes are issued only while
 * the member's onboarding is current on every active board; until then the token is
 * narrowed to `onboarding:read` (RFC 6749 §3.3; the token response states the issued
 * scope) so an agent that requested its normal scopes can still read and attest the
 * onboarding terms. A request that carries no `onboarding:read` at all still refuses.
 */
async function onboardingBoundedScopes(
  client: PoolClient,
  organizationId: string,
  memberId: string,
  granted: readonly IdentityScope[],
  refusal: string
): Promise<readonly IdentityScope[]> {
  const onboarding = await client.query<{ current: boolean }>(
    "select boardagent_identity_member_onboarding_current($1,$2,$3) as current",
    [organizationId, memberId, [...granted]]
  );
  if (onboarding.rows[0]?.current) return granted;
  const narrowed = granted.filter((scope) => scope === ONBOARDING_SCOPE);
  if (narrowed.length === 0) {
    throw new IdentityTransactionError("token_onboarding_required", refusal);
  }
  return narrowed;
}

interface TokenCodeRow {
  readonly id: string;
  readonly organization_id: string;
  readonly authorization_request_id: string;
  readonly client_id: string;
  readonly member_id: string;
  readonly redirect_uri: string;
  readonly resource_uri: string;
  readonly scope_set: string[];
  readonly session_id: string;
  readonly pkce_s256_challenge: string;
  readonly consumed_at: string | null;
  readonly revoked_at: string | null;
  readonly code_current: boolean;
  readonly request_state: string;
  readonly member_state: string;
  readonly client_state: string;
}

interface SigningKeyRow {
  readonly id: string;
  readonly kid: string;
  readonly nonsecret_locator: string;
}

interface IssuedAccessRow {
  readonly issued_at: string;
  readonly expires_at: string;
}

async function loadSigningKey(
  client: PoolClient,
  organizationId: string,
  signingKeyId: string
): Promise<SigningKeyRow> {
  const result = await client.query<SigningKeyRow>(
    `select id,kid,nonsecret_locator from crypto_key_registry
      where id=$1 and organization_id=$2 and purpose='oauth_signing' and algorithm='ES256'
        and public_jwk is not null and activated_at<=transaction_timestamp()
        and (retired_at is null or retired_at>transaction_timestamp())
        and (compromised_at is null or compromised_at>transaction_timestamp())`,
    [signingKeyId, organizationId]
  );
  const key = result.rows[0];
  if (!key || result.rows.length !== 1) {
    throw new IdentityTransactionError(
      "token_signing_key_invalid",
      "access token signing key is unavailable"
    );
  }
  return key;
}

function claimsMaterial(
  resourceUri: string,
  memberId: string,
  clientId: string,
  jti: string,
  scopes: readonly IdentityScope[],
  key: SigningKeyRow,
  issued: IssuedAccessRow
): TokenClaimsMaterial {
  return {
    issuer: new URL(resourceUri).origin,
    audience: resourceUri,
    resource: resourceUri,
    subject: memberId,
    clientId,
    jti,
    scopes,
    issuedAt: issued.issued_at,
    expiresAt: issued.expires_at,
    signingKeyId: key.id,
    signingKeyKid: key.kid,
    signingKeyLocator: key.nonsecret_locator
  };
}

export async function issueTokensFromAuthorizationCodeInTransaction(
  client: PoolClient,
  rawInput: IssueTokenInput
): Promise<{
  readonly familyId: string;
  readonly generation: "1";
  readonly claims: TokenClaimsMaterial;
  readonly auditEventId: string;
  readonly auditSequence: string;
}> {
  const input = IssueTokenInputSchema.parse(rawInput);
  await assertIdentityContext(client, input.organizationId);
  const codeResult = await client.query<TokenCodeRow>(
    `select code.id,code.organization_id,code.authorization_request_id,code.client_id,
            code.member_id,code.redirect_uri,code.resource_uri,code.scope_set,
            request.session_id,code.pkce_s256_challenge,
            case when code.consumed_at is null then null else code.consumed_at::text end as consumed_at,
            case when code.revoked_at is null then null else code.revoked_at::text end as revoked_at,
            code.expires_at>transaction_timestamp() as code_current,
            request.request_state,member.state as member_state,oauth_client.state as client_state
       from oauth_authorization_codes as code
       join oauth_authorization_requests as request on request.id=code.authorization_request_id
       join members as member on member.id=code.member_id and member.organization_id=code.organization_id
       join oauth_clients as oauth_client on oauth_client.id=code.client_id
      where code.organization_id=$1 and code.code_sha256=$2
      for update of code,request`,
    [input.organizationId, Buffer.from(input.authorizationCodeSha256, "hex")]
  );
  const code = codeResult.rows[0];
  const expectedChallenge = Buffer.from(sha256Bytes(input.pkceVerifier)).toString("base64url");
  if (
    !code ||
    codeResult.rows.length !== 1 ||
    code.client_id !== input.clientId ||
    code.redirect_uri !== input.redirectUri ||
    code.resource_uri !== input.resourceUri ||
    code.consumed_at !== null ||
    code.revoked_at !== null ||
    !code.code_current ||
    code.request_state !== "approved" ||
    code.pkce_s256_challenge !== expectedChallenge
  ) {
    throw new IdentityTransactionError("token_code_invalid", "authorization code exchange failed");
  }
  if (code.member_state !== "active") {
    throw new IdentityTransactionError("token_member_invalid", "token subject is not active");
  }
  if (code.client_state !== "active") {
    throw new IdentityTransactionError("token_client_invalid", "OAuth client is not active");
  }
  const grantedScopes = normalizeScopes(code.scope_set);
  const missingGrant = await client.query<{ count: string }>(
    `select count(*)::text as count
       from unnest($2::text[]) as requested(scope)
       cross join (values ('authorization_code'),('refresh_token')) as required(grant_type)
      where not exists (
        select 1 from oauth_client_grants as grant_row
         where grant_row.client_id=$1 and grant_row.grant_type=required.grant_type
           and grant_row.scope=requested.scope
      )`,
    [input.clientId, [...grantedScopes]]
  );
  if (missingGrant.rows[0]?.count !== "0") {
    throw new IdentityTransactionError(
      "token_client_invalid",
      "OAuth client lacks a requested grant"
    );
  }
  const scopes = await onboardingBoundedScopes(
    client,
    input.organizationId,
    code.member_id,
    grantedScopes,
    "ordinary token scopes require current onboarding on every active board"
  );
  const key = await loadSigningKey(client, input.organizationId, input.signingKeyId);
  await client.query(
    `update oauth_authorization_codes set consumed_at=transaction_timestamp() where id=$1`,
    [code.id]
  );
  await client.query(
    `update oauth_authorization_requests set request_state='consumed'
      where id=$1 and request_state='approved'`,
    [code.authorization_request_id]
  );
  await client.query(
    `insert into refresh_families(
       id,organization_id,member_id,client_id,resource_uri,generation,state,
       idle_expires_at,absolute_expires_at,granted_scope_set
     ) values ($1,$2,$3,$4,$5,1,'active',
               transaction_timestamp()+interval '30 days',
               transaction_timestamp()+interval '90 days',$6)`,
    [
      input.refreshFamilyId,
      input.organizationId,
      code.member_id,
      input.clientId,
      input.resourceUri,
      [...grantedScopes]
    ]
  );
  await client.query(
    `insert into refresh_tokens(id,family_id,generation,token_sha256)
     values ($1,$2,1,$3)`,
    [input.refreshTokenId, input.refreshFamilyId, Buffer.from(input.refreshTokenSha256, "hex")]
  );
  const issuedResult = await client.query<IssuedAccessRow>(
    `insert into access_token_records(
       id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,
       refresh_family_id,signing_key_id,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,transaction_timestamp()+interval '15 minutes')
     returning
       to_char(issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as issued_at,
       to_char(expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at`,
    [
      input.accessTokenRecordId,
      input.organizationId,
      input.accessTokenJti,
      code.member_id,
      input.clientId,
      input.resourceUri,
      [...scopes],
      code.session_id,
      input.refreshFamilyId,
      input.signingKeyId
    ]
  );
  const issued = issuedResult.rows[0];
  if (!issued) throw new Error("token issue did not return its database time boundary");
  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.auditEventId,
        eventType: "token_issued",
        actorMemberId: code.member_id,
        actorClientId: input.clientId,
        tokenJti: input.accessTokenJti,
        entityType: "refresh_family",
        entityId: input.refreshFamilyId,
        boardId: null,
        origin: "oauth",
        details: {
          accessTokenRecordId: input.accessTokenRecordId,
          authorizationRequestId: code.authorization_request_id,
          grantedScopes,
          onboardingNarrowed: scopes.length !== grantedScopes.length,
          resourceUri: input.resourceUri,
          scopes,
          lifetimeSeconds: 900,
          refreshIdleDays: 30,
          refreshAbsoluteDays: 90,
          signingKeyId: input.signingKeyId
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("token issue did not append its audit event");
  return {
    familyId: input.refreshFamilyId,
    generation: "1",
    claims: claimsMaterial(
      input.resourceUri,
      code.member_id,
      input.clientId,
      input.accessTokenJti,
      scopes,
      key,
      issued
    ),
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}

interface RefreshLookupRow {
  readonly family_id: string;
}

interface LockedFamilyRow {
  readonly id: string;
  readonly organization_id: string;
  readonly member_id: string;
  readonly client_id: string;
  readonly resource_uri: string;
  readonly granted_scope_set: string[] | null;
  readonly generation: string;
  readonly state: "active" | "revoked" | "compromised" | "expired";
  readonly idle_current: boolean;
  readonly absolute_current: boolean;
}

interface LockedRefreshTokenRow {
  readonly id: string;
  readonly generation: string;
  readonly used_at: string | null;
  readonly revoked_at: string | null;
}

interface PriorAccessRow {
  readonly scope_set: string[];
  readonly session_id: string | null;
  readonly jti: string;
  readonly member_state: string;
  readonly client_state: string;
  readonly session_state: string | null;
  readonly session_authenticated: boolean;
}

async function terminateRefreshFamily(
  client: PoolClient,
  family: LockedFamilyRow,
  state: "compromised" | "expired",
  eventType: "token_reuse_detected" | "session_revoked",
  auditEventId: string,
  prior: PriorAccessRow | undefined,
  details: Readonly<Record<string, string | boolean | number>>
): Promise<TokenRefreshResult> {
  await client.query(
    `update auth_sessions set state='revoked'
      where state in ('authenticated','expired') and id in (
        select session_id from access_token_records
         where refresh_family_id=$1 and session_id is not null
      )`,
    [family.id]
  );
  await client.query(
    `update access_token_records set revoked_at=transaction_timestamp()
      where refresh_family_id=$1 and revoked_at is null`,
    [family.id]
  );
  await client.query(
    `update refresh_tokens set revoked_at=transaction_timestamp()
      where family_id=$1 and used_at is null and revoked_at is null`,
    [family.id]
  );
  await client.query(
    `update refresh_families set state=$2,revoked_at=transaction_timestamp()
      where id=$1 and state='active'`,
    [family.id, state]
  );
  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: family.organization_id,
      event: {
        eventId: auditEventId,
        eventType,
        actorMemberId: family.member_id,
        actorClientId: family.client_id,
        tokenJti: prior?.jti ?? null,
        entityType: "refresh_family",
        entityId: family.id,
        boardId: null,
        origin: "oauth",
        details,
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("refresh-family termination did not append its audit event");
  return {
    refreshed: false,
    familyId: family.id,
    state,
    reuseDetected: state === "compromised",
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}

export async function rotateRefreshTokenInTransaction(
  client: PoolClient,
  rawInput: RefreshTokenInput
): Promise<TokenRefreshResult> {
  const input = RefreshTokenInputSchema.parse(rawInput);
  await assertIdentityContext(client, input.organizationId);
  const lookup = await client.query<RefreshLookupRow>(
    `select token.family_id
       from refresh_tokens as token
       join refresh_families as family on family.id=token.family_id
      where family.organization_id=$1 and token.token_sha256=$2`,
    [input.organizationId, Buffer.from(input.presentedRefreshTokenSha256, "hex")]
  );
  const familyId = lookup.rows[0]?.family_id;
  if (!familyId || lookup.rows.length !== 1) {
    throw new IdentityTransactionError("refresh_token_invalid", "refresh token is invalid");
  }
  const familyResult = await client.query<LockedFamilyRow>(
    `select id,organization_id,member_id,client_id,resource_uri,granted_scope_set,
            generation::text,state,
            idle_expires_at>transaction_timestamp() as idle_current,
            absolute_expires_at>transaction_timestamp() as absolute_current
       from refresh_families where id=$1 and organization_id=$2 for update`,
    [familyId, input.organizationId]
  );
  const family = familyResult.rows[0];
  if (!family || family.client_id !== input.clientId || family.resource_uri !== input.resourceUri) {
    throw new IdentityTransactionError("refresh_token_invalid", "refresh family binding failed");
  }
  const tokenResult = await client.query<LockedRefreshTokenRow>(
    `select id,generation::text,
            case when used_at is null then null else used_at::text end as used_at,
            case when revoked_at is null then null else revoked_at::text end as revoked_at
       from refresh_tokens where family_id=$1 and token_sha256=$2 for update`,
    [family.id, Buffer.from(input.presentedRefreshTokenSha256, "hex")]
  );
  const token = tokenResult.rows[0];
  if (!token) throw new IdentityTransactionError("refresh_token_invalid", "refresh token vanished");
  const priorResult = await client.query<PriorAccessRow>(
    `select access.scope_set,access.session_id,access.jti,
            member.state as member_state,oauth_client.state as client_state,
            session.state as session_state,
            session.last_authenticated_at is not null as session_authenticated
       from access_token_records as access
       join members as member on member.id=access.member_id and member.organization_id=access.organization_id
       join oauth_clients as oauth_client on oauth_client.id=access.client_id
       left join auth_sessions as session on session.id=access.session_id
        and session.organization_id=access.organization_id
        and session.member_id=access.member_id and session.client_id=access.client_id
      where access.refresh_family_id=$1
        and access.organization_id=$2 and access.member_id=$3
        and access.client_id=$4 and access.resource_uri=$5
      order by access.issued_at desc,access.id desc limit 1`,
    [family.id, family.organization_id, family.member_id, family.client_id, family.resource_uri]
  );
  const prior = priorResult.rows[0];
  if (family.state !== "active") {
    return {
      refreshed: false,
      familyId: family.id,
      state: family.state,
      reuseDetected: family.state === "compromised"
    };
  }
  if (token.used_at !== null || token.revoked_at !== null) {
    return terminateRefreshFamily(
      client,
      family,
      "compromised",
      "token_reuse_detected",
      input.auditEventId,
      prior,
      {
        presentedGeneration: Number(token.generation),
        currentGeneration: Number(family.generation),
        successorRevoked: true,
        sessionsRevoked: true
      }
    );
  }
  if (!family.idle_current || !family.absolute_current) {
    return terminateRefreshFamily(
      client,
      family,
      "expired",
      "session_revoked",
      input.auditEventId,
      prior,
      { reason: "refresh_family_expired", sessionsRevoked: true }
    );
  }
  if (
    !prior ||
    prior.member_state !== "active" ||
    prior.client_state !== "active" ||
    (prior.session_id !== null &&
      (!prior.session_authenticated ||
        (prior.session_state !== "authenticated" && prior.session_state !== "expired")))
  ) {
    throw new IdentityTransactionError(
      "token_member_invalid",
      "refresh subject, client, or session is unavailable"
    );
  }
  // Families created before the granted set was recorded keep their prior token's scopes.
  const grantedScopes = normalizeScopes(family.granted_scope_set ?? prior.scope_set);
  const missingRefreshGrant = await client.query<{ count: string }>(
    `select count(*)::text as count
       from unnest($2::text[]) as requested(scope)
      where not exists (
        select 1 from oauth_client_grants as grant_row
         where grant_row.client_id=$1 and grant_row.grant_type='refresh_token'
           and grant_row.scope=requested.scope
      )`,
    [family.client_id, [...grantedScopes]]
  );
  if (missingRefreshGrant.rows[0]?.count !== "0") {
    throw new IdentityTransactionError(
      "token_client_invalid",
      "OAuth client lacks a requested refresh grant"
    );
  }
  const scopes = await onboardingBoundedScopes(
    client,
    input.organizationId,
    family.member_id,
    grantedScopes,
    "refresh refuses stale onboarding for ordinary scopes"
  );
  const key = await loadSigningKey(client, input.organizationId, input.signingKeyId);
  const nextGeneration = BigInt(family.generation) + 1n;
  await client.query(
    `update refresh_tokens
        set used_at=transaction_timestamp(),replaced_by_id=$2
      where id=$1 and used_at is null and revoked_at is null`,
    [token.id, input.replacementRefreshTokenId]
  );
  await client.query(
    `insert into refresh_tokens(id,family_id,generation,token_sha256)
     values ($1,$2,$3,$4)`,
    [
      input.replacementRefreshTokenId,
      family.id,
      nextGeneration.toString(10),
      Buffer.from(input.replacementRefreshTokenSha256, "hex")
    ]
  );
  await client.query(
    `update refresh_families
        set generation=$2,last_used_at=transaction_timestamp(),
            idle_expires_at=least(transaction_timestamp()+interval '30 days',absolute_expires_at)
      where id=$1 and state='active'`,
    [family.id, nextGeneration.toString(10)]
  );
  const issuedResult = await client.query<IssuedAccessRow>(
    `insert into access_token_records(
       id,organization_id,jti,member_id,client_id,resource_uri,scope_set,session_id,
       refresh_family_id,signing_key_id,expires_at
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,transaction_timestamp()+interval '15 minutes')
     returning
       to_char(issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as issued_at,
       to_char(expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as expires_at`,
    [
      input.accessTokenRecordId,
      input.organizationId,
      input.accessTokenJti,
      family.member_id,
      family.client_id,
      family.resource_uri,
      [...scopes],
      prior.session_id,
      family.id,
      input.signingKeyId
    ]
  );
  const issued = issuedResult.rows[0];
  if (!issued) throw new Error("refresh did not return its database time boundary");
  const [audit] = await appendAuditEventsInTransaction(client, [
    {
      organizationId: input.organizationId,
      event: {
        eventId: input.auditEventId,
        eventType: "token_refreshed",
        actorMemberId: family.member_id,
        actorClientId: family.client_id,
        tokenJti: input.accessTokenJti,
        entityType: "refresh_family",
        entityId: family.id,
        boardId: null,
        origin: "oauth",
        details: {
          previousGeneration: family.generation,
          generation: nextGeneration.toString(10),
          accessTokenRecordId: input.accessTokenRecordId,
          resourceUri: family.resource_uri,
          scopes,
          grantedScopes,
          onboardingNarrowed: scopes.length !== grantedScopes.length,
          lifetimeSeconds: 900,
          signingKeyId: input.signingKeyId
        },
        schemaVersion: 1
      }
    }
  ]);
  if (!audit) throw new Error("refresh did not append its audit event");
  return {
    refreshed: true,
    familyId: family.id,
    generation: nextGeneration.toString(10),
    claims: claimsMaterial(
      family.resource_uri,
      family.member_id,
      family.client_id,
      input.accessTokenJti,
      scopes,
      key,
      issued
    ),
    auditEventId: audit.eventId,
    auditSequence: audit.sequence.toString(10)
  };
}
