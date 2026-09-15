import { randomBytes } from "node:crypto";

import { z } from "zod";

import { UuidV7Schema, sha256Hex, type JsonValue } from "@boardagent/contracts";
import {
  BootstrapActivationRestartRequestSchema,
  BootstrapInstanceInputSchema,
  BootstrapInvitationRenewalRequestSchema,
  BootstrapTransactionError,
  activateBootstrapEnrollmentInTransaction,
  bootstrapInstanceInTransaction,
  issueFirstActivationRestartInTransaction,
  renewBootstrapInvitationInTransaction,
  withBootstrapTransaction,
  type BootstrapEnrollmentActivationResult
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";

type BootstrapPool = Parameters<typeof withBootstrapTransaction>[0];

export const BootstrapActivationInputSchema = z
  .object({
    activationCode: z
      .string()
      .trim()
      .transform((value) => value.toUpperCase())
      .pipe(z.string().regex(/^[A-HJ-NP-Z2-9]{3}-[A-HJ-NP-Z2-9]{4}$/u)),
    proofingMethod: z.enum(["in_person", "verified_number_call"])
  })
  .strict();

export interface FirstSecretaryBootstrapSetup {
  readonly organizationLegalName: string;
  readonly organizationDisplayName: string;
  readonly organizationSlug: string;
  readonly timezone: string;
  readonly canonicalResourceUri: string;
  readonly boardSlug: string;
  readonly boardName: string;
  readonly boardCanonicalPayload: Readonly<Record<string, JsonValue>>;
  readonly firstSecretaryLegalName: string;
  readonly firstSecretaryDisplayName: string;
  readonly votingWeight: number;
  readonly supportName: string;
  readonly supportContactMethods: readonly JsonValue[];
  readonly onboardingTermsText: string;
  readonly invitationHandoffMethod: string;
}

export type FirstSecretaryBootstrapResult =
  | {
      readonly status: "created";
      readonly secretOnce: true;
      readonly instanceId: string;
      readonly organizationId: string;
      readonly boardId: string;
      readonly firstMemberId: string;
      readonly invitationId: string;
      readonly invitationExpiresAt: string;
      readonly enrollmentUrl: string;
    }
  | {
      readonly status: "already_initialized";
      readonly secretOnce: true;
    };

export interface BoardAgentBootstrapOperatorOptions {
  /** Test seam only. Production bootstrap connects as boardagent_migrator directly. */
  readonly assumeRole?: "boardagent_migrator";
  /** CLI configuration binding, never a caller-selected identity or board. */
  readonly expectedCanonicalResourceUri?: string;
  readonly now?: () => Date;
  readonly newId?: () => string;
  readonly entropy?: (length: number) => Buffer;
}

interface ActivationTargetRow {
  readonly organization_id: string;
  readonly member_id: string;
  readonly invitation_id: string;
  readonly challenge_id: string;
}

interface ActivationBoardRow {
  readonly board_id: string;
}

function exactBytes(entropy: (length: number) => Buffer, length: number): Buffer {
  const bytes = entropy(length);
  if (!Buffer.isBuffer(bytes) || bytes.length !== length) {
    throw new Error(`bootstrap entropy must return exactly ${String(length)} bytes`);
  }
  return bytes;
}

function enrollmentUrl(canonicalResourceUri: string, invitationToken: string): string {
  const target = new URL(canonicalResourceUri);
  target.pathname = "/enroll";
  target.hash = invitationToken;
  return target.href;
}

function restartUrl(canonicalResourceUri: string, restartToken: string): string {
  const target = new URL(canonicalResourceUri);
  target.pathname = "/enroll/restart";
  target.hash = restartToken;
  return target.href;
}

function unavailableActivation(): BootstrapTransactionError {
  return new BootstrapTransactionError(
    "bootstrap_activation_unavailable",
    "the first-secretary bootstrap activation is unavailable"
  );
}

/**
 * Local operator composition for the sole preidentity ceremony. It prints no output and
 * persists no recoverable secret; a future CLI may render the returned one-use URL once.
 */
export class BoardAgentBootstrapOperator {
  private readonly pool: BootstrapPool;
  private readonly assumeRole: "boardagent_migrator" | undefined;
  private readonly expectedCanonicalResourceUri: string | undefined;
  private readonly newId: () => string;
  private readonly entropy: (length: number) => Buffer;

  public constructor(pool: BootstrapPool, options: BoardAgentBootstrapOperatorOptions = {}) {
    this.pool = pool;
    this.assumeRole = options.assumeRole;
    this.expectedCanonicalResourceUri = options.expectedCanonicalResourceUri;
    this.entropy = options.entropy ?? randomBytes;
    const now = options.now ?? (() => new Date());
    this.newId = options.newId ?? (() => uuidV7(now().getTime(), exactBytes(this.entropy, 10)));
  }

  private identifier(): string {
    return UuidV7Schema.parse(this.newId());
  }

  private transactionOptions(): { readonly assumeRole?: "boardagent_migrator" } {
    return this.assumeRole === undefined ? {} : { assumeRole: this.assumeRole };
  }

  public async initialize(
    setup: FirstSecretaryBootstrapSetup
  ): Promise<FirstSecretaryBootstrapResult> {
    const invitationToken = exactBytes(this.entropy, 32).toString("base64url");
    const input = BootstrapInstanceInputSchema.parse({
      organizationId: this.identifier(),
      organizationLegalName: setup.organizationLegalName,
      organizationDisplayName: setup.organizationDisplayName,
      organizationSlug: setup.organizationSlug,
      timezone: setup.timezone,
      instanceId: this.identifier(),
      canonicalResourceUri: setup.canonicalResourceUri,
      boardId: this.identifier(),
      boardVersionId: this.identifier(),
      boardSlug: setup.boardSlug,
      boardName: setup.boardName,
      boardCanonicalPayload: { ...setup.boardCanonicalPayload },
      memberId: this.identifier(),
      memberLegalName: setup.firstSecretaryLegalName,
      memberDisplayName: setup.firstSecretaryDisplayName,
      adminRoleAssignmentId: this.identifier(),
      secretariatRoleAssignmentId: this.identifier(),
      membershipId: this.identifier(),
      membershipVersionId: this.identifier(),
      votingWeight: setup.votingWeight,
      supportVersionId: this.identifier(),
      supportName: setup.supportName,
      supportContactMethods: [...setup.supportContactMethods],
      onboardingTermsVersionId: this.identifier(),
      onboardingTermsText: setup.onboardingTermsText,
      invitationId: this.identifier(),
      invitationTokenSha256: sha256Hex(invitationToken),
      invitationHandoffMethod: setup.invitationHandoffMethod,
      auditEventId: this.identifier()
    });

    let result;
    try {
      result = await withBootstrapTransaction(
        this.pool,
        (client) => bootstrapInstanceInTransaction(client, input),
        this.transactionOptions()
      );
    } catch (error) {
      if (error instanceof BootstrapTransactionError && error.code === "bootstrap_conflict") {
        return { status: "already_initialized", secretOnce: true };
      }
      throw error;
    }
    if (result.alreadyBootstrapped) {
      return { status: "already_initialized", secretOnce: true };
    }
    if (result.invitationExpiresAt === undefined) {
      throw new Error("new bootstrap did not return the invitation expiry");
    }
    return {
      status: "created",
      secretOnce: true,
      instanceId: result.instanceId,
      organizationId: result.organizationId,
      boardId: result.boardId,
      firstMemberId: result.firstMemberId,
      invitationId: result.invitationId,
      invitationExpiresAt: result.invitationExpiresAt,
      enrollmentUrl: enrollmentUrl(input.canonicalResourceUri, invitationToken)
    };
  }

  public async renewFirstInvitation(rawInput: unknown) {
    const input = BootstrapInvitationRenewalRequestSchema.parse(rawInput);
    if (
      this.expectedCanonicalResourceUri !== undefined &&
      this.expectedCanonicalResourceUri !== input.canonicalResourceUri
    ) {
      throw new BootstrapTransactionError(
        "bootstrap_renewal_unavailable",
        "configured instance does not match renewal"
      );
    }
    const invitationToken = exactBytes(this.entropy, 32).toString("base64url");
    const staged = {
      ...input,
      invitationId: this.identifier(),
      invitationTokenSha256: sha256Hex(invitationToken),
      revokedAuditEventId: this.identifier(),
      issuedAuditEventId: this.identifier()
    };
    const result = await withBootstrapTransaction(
      this.pool,
      (client) => renewBootstrapInvitationInTransaction(client, staged),
      this.transactionOptions()
    );
    return {
      status: "renewed" as const,
      secretOnce: true as const,
      ...result,
      enrollmentUrl: enrollmentUrl(input.canonicalResourceUri, invitationToken)
    };
  }

  /**
   * Operator half of the approved activation restart for the singleton first person: the
   * registered setup administrator's activation code expired or was exhausted before the
   * operator confirmed it. Mints one ten-minute restart handoff; the person re-proves with
   * their existing passkey and receives a fresh code for `activate-first`.
   */
  public async reissueFirstActivation(rawInput: unknown) {
    const input = BootstrapActivationRestartRequestSchema.parse(rawInput);
    if (
      this.expectedCanonicalResourceUri !== undefined &&
      this.expectedCanonicalResourceUri !== input.canonicalResourceUri
    ) {
      throw new BootstrapTransactionError(
        "bootstrap_restart_unavailable",
        "configured instance does not match the restart request"
      );
    }
    const restartToken = exactBytes(this.entropy, 32).toString("base64url");
    const result = await withBootstrapTransaction(
      this.pool,
      (client) =>
        issueFirstActivationRestartInTransaction(client, {
          ...input,
          grantId: this.identifier(),
          tokenSha256: sha256Hex(restartToken),
          auditEventId: this.identifier()
        }),
      this.transactionOptions()
    );
    return {
      status: "restart_issued" as const,
      secretOnce: true as const,
      ...result,
      restartUrl: restartUrl(input.canonicalResourceUri, restartToken)
    };
  }

  public async activateFirstSecretary(rawInput: {
    readonly activationCode: string;
    readonly proofingMethod: "in_person" | "verified_number_call";
  }): Promise<BootstrapEnrollmentActivationResult> {
    const input = BootstrapActivationInputSchema.parse(rawInput);
    return withBootstrapTransaction(
      this.pool,
      async (client) => {
        const targetResult = await client.query<ActivationTargetRow>(
          `select instance.organization_id,member.id as member_id,
                  invitation.id as invitation_id,challenge.id as challenge_id
             from system_instance as instance
             join members as member on member.organization_id=instance.organization_id
             join enrollment_invitations as invitation
               on invitation.organization_id=instance.organization_id
              and invitation.member_id=member.id
             join enrollment_activation_challenges as challenge
               on challenge.organization_id=instance.organization_id
              and challenge.member_id=member.id
              and challenge.invitation_id=invitation.id
            where instance.singleton_key
              and ($1::text is null or instance.canonical_resource_uri=$1)
              and member.state='pending_activation'
              and challenge.state='issued' and challenge.expires_at>transaction_timestamp()
            order by invitation.id,challenge.id`,
          [this.expectedCanonicalResourceUri ?? null]
        );
        const target = targetResult.rows[0];
        if (!target || targetResult.rows.length !== 1) throw unavailableActivation();
        const boards = await client.query<ActivationBoardRow>(
          `select board_id
             from board_memberships
            where organization_id=$1 and member_id=$2 and is_secretary and state='active'
              and active_from<=transaction_timestamp()
              and (active_until is null or active_until>transaction_timestamp())
            order by board_id`,
          [target.organization_id, target.member_id]
        );
        if (boards.rows.length === 0 || boards.rows.length > 25) throw unavailableActivation();
        return activateBootstrapEnrollmentInTransaction(client, {
          organizationId: target.organization_id,
          memberId: target.member_id,
          invitationId: target.invitation_id,
          challengeId: target.challenge_id,
          protectedCodeSha256: sha256Hex(input.activationCode),
          proofingMethod: input.proofingMethod,
          feedEntries: boards.rows.map(({ board_id }) => ({
            boardId: board_id,
            feedId: this.identifier()
          })),
          auditEventId: this.identifier()
        });
      },
      this.transactionOptions()
    );
  }
}
