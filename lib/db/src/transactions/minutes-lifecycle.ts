import { randomBytes } from "node:crypto";

import type { PoolClient } from "pg";
import { z } from "zod";

import {
  MinutesActionManifestSchema,
  MinutesRedlineSchema,
  PendingActionDeltaSchema,
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type JsonValue,
  type MinutesActionManifest
} from "@boardagent/contracts";
import { activationManifestHash, applyExactMinutesRedline, uuidV7 } from "@boardagent/domain";

import {
  confirmStagedActionInTransaction,
  stageActionInTransaction,
  type ConfirmStagedActionInput,
  type StagedAction,
  type StagedActionResolution,
  type StageActionInput
} from "./consent.js";
import type { AuditAppendInput } from "./audit.js";
import { readRequestContext, type ActiveRequestContext } from "./request-context.js";

const ReasonSchema = z
  .string()
  .transform((value) => canonicalText(value))
  .pipe(z.string().min(1).max(65_536));
const ReservationSchema = z
  .string()
  .transform((value) => canonicalText(value))
  .pipe(z.string().min(1).max(65_536));

export interface MinutesSignerRequirementInput {
  readonly memberId: string;
  readonly requirement: "required" | "permitted";
}

export type MinutesLifecycleAction =
  | {
      readonly kind: "publication";
      readonly minutesId: string;
      readonly versionId: string;
      readonly minutesSha256: string;
      readonly signerMemberIds: readonly string[];
    }
  | {
      readonly kind: "review_disposition";
      readonly minutesId: string;
      readonly reviewItemId: string;
      readonly decision: "accepted" | "rejected";
      readonly reason: string;
      readonly replacementText?: string;
    }
  | {
      readonly kind: "package_correction";
      readonly minutesId: string;
      readonly expectedVersionId: string;
      readonly canonicalText: string;
      readonly reason: string;
    }
  | {
      readonly kind: "action_declaration";
      readonly minutesId: string;
      readonly manifest: unknown;
    }
  | {
      readonly kind: "signature_package_issue";
      readonly minutesId: string;
      readonly expectedVersionId: string;
      readonly requirements: readonly MinutesSignerRequirementInput[];
    }
  | {
      readonly kind: "signature";
      readonly minutesId: string;
      readonly packageId: string;
      readonly reservation: string | null;
    }
  | {
      readonly kind: "finalization";
      readonly minutesId: string;
      readonly packageId: string;
    }
  | {
      readonly kind: "finalized_correction";
      readonly minutesId: string;
      readonly replacementMinutesId: string;
      readonly canonicalText: string;
      readonly reason: string;
    }
  | {
      readonly kind: "cancellation";
      readonly minutesId: string;
      readonly reason: string;
    };

export interface MinutesLifecycleStageInput {
  readonly action: MinutesLifecycleAction;
  readonly stage: Omit<
    StageActionInput,
    | "boardId"
    | "actingForMemberId"
    | "actionCode"
    | "targetType"
    | "targetId"
    | "canonicalSchema"
    | "canonicalPayload"
    | "packageSha256"
    | "originalName"
  >;
}

export interface MinutesLifecycleConfirmationInput {
  readonly action: MinutesLifecycleAction;
  readonly confirmation: ConfirmStagedActionInput;
}

export type MinutesLifecycleResult =
  | {
      readonly kind: "publication";
      readonly minutesId: string;
      readonly minutesVersionId: string;
      readonly minutesSha256: string;
      readonly reviewRecipientMemberIds: readonly string[];
    }
  | {
      readonly kind: "review_disposition";
      readonly dispositionId: string;
      readonly minutesId: string;
      readonly minutesVersionId: string;
      readonly minutesSha256: string;
      readonly decision: "accepted" | "rejected";
    }
  | {
      readonly kind: "package_correction";
      readonly minutesId: string;
      readonly minutesVersionId: string;
      readonly minutesSha256: string;
    }
  | {
      readonly kind: "action_declaration";
      readonly minutesId: string;
      readonly declarationId: string;
      readonly manifestSha256: string;
      readonly taskIds: readonly string[];
    }
  | {
      readonly kind: "signature_package_issue";
      readonly minutesId: string;
      readonly signaturePackageId: string;
      readonly packageSha256: string;
      readonly signerMemberIds: readonly string[];
    }
  | {
      readonly kind: "signature";
      readonly minutesId: string;
      readonly signatureId: string;
      readonly signatureRecordSha256: string;
    }
  | {
      readonly kind: "finalization";
      readonly minutesId: string;
      readonly activationManifestSha256: string;
      readonly activatedTaskIds: readonly string[];
    }
  | {
      readonly kind: "finalized_correction";
      readonly originalMinutesId: string;
      readonly replacementMinutesId: string;
      readonly replacementVersionId: string;
      readonly replacementSha256: string;
    }
  | {
      readonly kind: "cancellation";
      readonly minutesId: string;
      readonly supersededDraftTaskIds: readonly string[];
    };

export interface PreparedMinutesLifecycleAction {
  readonly actionCode: string;
  readonly boardId: string;
  readonly targetId: string;
  readonly canonicalSchema: string;
  readonly canonicalPayload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
}

export interface StagedMinutesLifecycleAction extends StagedAction {
  readonly actionCode: string;
  readonly boardId: string;
  readonly targetId: string;
}

export class MinutesLifecycleTransactionError extends Error {
  public constructor(
    public readonly code:
      | "minutes_lifecycle_unavailable"
      | "minutes_lifecycle_invalid"
      | "minutes_review_pending"
      | "minutes_signature_incomplete",
    message: string
  ) {
    super(message);
    this.name = "MinutesLifecycleTransactionError";
  }
}

interface MinutesRootRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly meeting_id: string;
  readonly minutes_id: string;
  readonly state:
    "unpublished_draft" | "published_review" | "signature_ready" | "finalized" | "cancelled";
  readonly row_version: string;
  readonly version_id: string;
  readonly version: number;
  readonly canonical_text: string;
  readonly canonical_sha256: Buffer;
  readonly package_base_sha256: Buffer;
  readonly transcript_version_id: string | null;
  readonly transcript_sha256: Buffer | null;
  readonly signature_package_id: string | null;
  readonly signature_package_sha256: Buffer | null;
  readonly actor_seat_role: "voting_member" | "management" | "observer";
  readonly actor_is_secretary: boolean;
  readonly entitlement_generation: string;
  readonly token_scopes: string[];
}

interface PreparedAction {
  readonly action: NormalizedAction;
  readonly root: MinutesRootRow;
  readonly context: ActiveRequestContext;
  readonly payload: JsonValue;
  readonly payloadSha256: string;
  readonly packageSha256: string;
  readonly details: PreparedDetails;
}

type NormalizedAction =
  | (Extract<MinutesLifecycleAction, { readonly kind: "publication" }> & {
      readonly minutesId: string;
      readonly versionId: string;
      readonly minutesSha256: string;
      readonly signerMemberIds: readonly string[];
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "review_disposition" }> & {
      readonly minutesId: string;
      readonly reviewItemId: string;
      readonly reason: string;
      readonly replacementText?: string;
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "package_correction" }> & {
      readonly minutesId: string;
      readonly expectedVersionId: string;
      readonly canonicalText: string;
      readonly reason: string;
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "action_declaration" }> & {
      readonly minutesId: string;
      readonly manifest: MinutesActionManifest;
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "signature_package_issue" }> & {
      readonly minutesId: string;
      readonly expectedVersionId: string;
      readonly requirements: readonly MinutesSignerRequirementInput[];
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "signature" }> & {
      readonly minutesId: string;
      readonly packageId: string;
      readonly reservation: string | null;
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "finalization" }> & {
      readonly minutesId: string;
      readonly packageId: string;
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "finalized_correction" }> & {
      readonly minutesId: string;
      readonly replacementMinutesId: string;
      readonly canonicalText: string;
      readonly reason: string;
    })
  | (Extract<MinutesLifecycleAction, { readonly kind: "cancellation" }> & {
      readonly minutesId: string;
      readonly reason: string;
    });

interface ReviewItemRow {
  readonly id: string;
  readonly item_kind: "comment" | "redline";
  readonly canonical_payload: Buffer;
  readonly payload_sha256: Buffer;
  readonly withdrawn: boolean;
  readonly dispositioned: boolean;
}

interface ReviewManifestRow {
  readonly id: string;
  readonly item_kind: "comment" | "redline";
  readonly payload_sha256: Buffer;
  readonly withdrawal_id: string | null;
  readonly disposition_id: string | null;
  readonly decision: "accepted" | "rejected" | null;
}

interface SignerRow {
  readonly member_id: string;
  readonly seat_role: "voting_member" | "management" | "observer";
  readonly entitlement_generation: string;
  readonly member_snapshot_sha256: string;
}

interface DraftTaskRow {
  readonly id: string;
  readonly owner_member_id: string;
  readonly source_minutes_sha256: Buffer;
  readonly row_version: string;
}

type PreparedDetails =
  | { readonly kind: "publication"; readonly signers: readonly SignerRow[] }
  | {
      readonly kind: "review_disposition";
      readonly item: ReviewItemRow;
      readonly resultingText: string | null;
      readonly resultingSha256: string | null;
    }
  | { readonly kind: "package_correction"; readonly resultingSha256: string }
  | { readonly kind: "action_declaration"; readonly manifestSha256: string }
  | {
      readonly kind: "signature_package_issue";
      readonly packageVersion: number;
      readonly transcriptManifestSha256: string;
      readonly actionManifestSha256: string;
      readonly reviewManifestSha256: string;
      readonly signerManifestSha256: string;
      readonly proposedPackageSha256: string;
      readonly signers: readonly SignerRow[];
      readonly priorPackageId: string | null;
    }
  | { readonly kind: "signature"; readonly requirement: SignerRow }
  | {
      readonly kind: "finalization";
      readonly activationManifestSha256: string;
      readonly tasks: readonly DraftTaskRow[];
      readonly manifest: MinutesActionManifest;
    }
  | { readonly kind: "finalized_correction"; readonly replacementSha256: string }
  | { readonly kind: "cancellation"; readonly draftTaskIds: readonly string[] };

function newId(): string {
  return uuidV7(Date.now(), randomBytes(10));
}

function normalizeAction(input: MinutesLifecycleAction): NormalizedAction {
  const minutesId = UuidV7Schema.parse(input.minutesId);
  switch (input.kind) {
    case "publication": {
      const signerMemberIds = input.signerMemberIds
        .map((memberId) => UuidV7Schema.parse(memberId))
        .toSorted();
      if (
        signerMemberIds.length < 1 ||
        signerMemberIds.length > 1_000 ||
        new Set(signerMemberIds).size !== signerMemberIds.length
      ) {
        throw new MinutesLifecycleTransactionError(
          "minutes_lifecycle_invalid",
          "minutes publication requires one through 1000 unique proposed signers"
        );
      }
      return {
        ...input,
        minutesId,
        versionId: UuidV7Schema.parse(input.versionId),
        minutesSha256: Sha256HexSchema.parse(input.minutesSha256),
        signerMemberIds
      };
    }
    case "review_disposition": {
      const replacementText =
        input.replacementText === undefined ? undefined : canonicalText(input.replacementText);
      return {
        ...input,
        minutesId,
        reviewItemId: UuidV7Schema.parse(input.reviewItemId),
        reason: ReasonSchema.parse(input.reason),
        ...(replacementText === undefined ? {} : { replacementText })
      };
    }
    case "package_correction":
      return {
        ...input,
        minutesId,
        expectedVersionId: UuidV7Schema.parse(input.expectedVersionId),
        canonicalText: canonicalText(input.canonicalText),
        reason: ReasonSchema.parse(input.reason)
      };
    case "finalized_correction":
      return {
        ...input,
        minutesId,
        replacementMinutesId: UuidV7Schema.parse(input.replacementMinutesId),
        canonicalText: canonicalText(input.canonicalText),
        reason: ReasonSchema.parse(input.reason)
      };
    case "cancellation":
      return { ...input, minutesId, reason: ReasonSchema.parse(input.reason) };
    case "action_declaration":
      return { ...input, minutesId, manifest: MinutesActionManifestSchema.parse(input.manifest) };
    case "signature_package_issue": {
      const requirements = input.requirements
        .map((requirement) => ({
          memberId: UuidV7Schema.parse(requirement.memberId),
          requirement: requirement.requirement
        }))
        .toSorted((left, right) => left.memberId.localeCompare(right.memberId));
      if (
        requirements.length === 0 ||
        new Set(requirements.map(({ memberId }) => memberId)).size !== requirements.length
      ) {
        throw new MinutesLifecycleTransactionError(
          "minutes_lifecycle_invalid",
          "signature package requires a nonempty unique signer set"
        );
      }
      if (!requirements.some(({ requirement }) => requirement === "required")) {
        throw new MinutesLifecycleTransactionError(
          "minutes_lifecycle_invalid",
          "signature package requires at least one required signer"
        );
      }
      return {
        ...input,
        minutesId,
        expectedVersionId: UuidV7Schema.parse(input.expectedVersionId),
        requirements
      };
    }
    case "signature":
      return {
        ...input,
        minutesId,
        packageId: UuidV7Schema.parse(input.packageId),
        reservation: input.reservation === null ? null : ReservationSchema.parse(input.reservation)
      };
    case "finalization":
      return { ...input, minutesId, packageId: UuidV7Schema.parse(input.packageId) };
  }
}

function operation(action: NormalizedAction): {
  readonly actionCode: string;
  readonly canonicalSchema: string;
} {
  switch (action.kind) {
    case "publication":
      return {
        actionCode: "publish_minutes",
        canonicalSchema: "boardagent.minutes-publication.v1"
      };
    case "review_disposition":
      return {
        actionCode: "resolve_minutes_review_item",
        canonicalSchema: "boardagent.minutes-review-disposition.v1"
      };
    case "package_correction":
      return {
        actionCode: "correct_minutes_package",
        canonicalSchema: "boardagent.minutes-package-correction.v1"
      };
    case "action_declaration":
      return {
        actionCode:
          action.manifest.declaration === "items_logged"
            ? "log_minutes_action_items"
            : "declare_no_minutes_action_items",
        canonicalSchema: "boardagent.minutes-action-manifest.v1"
      };
    case "signature_package_issue":
      return {
        actionCode: "prepare_minutes_for_signature",
        canonicalSchema: "boardagent.minutes-signature-package-request.v1"
      };
    case "signature":
      return {
        actionCode: "stage_minutes_signature",
        canonicalSchema: "boardagent.minutes-signature.v1"
      };
    case "finalization":
      return {
        actionCode: "finalize_minutes",
        canonicalSchema: "boardagent.minutes-finalization.v1"
      };
    case "finalized_correction":
      return {
        actionCode: "create_minutes_correction_cycle",
        canonicalSchema: "boardagent.minutes-finalized-correction.v1"
      };
    case "cancellation":
      return {
        actionCode: "cancel_minutes",
        canonicalSchema: "boardagent.minutes-cancellation.v1"
      };
  }
}

async function lockAuthorizedRoot(
  client: PoolClient,
  minutesId: string,
  authority: "secretary" | "signer"
): Promise<{ readonly root: MinutesRootRow; readonly context: ActiveRequestContext }> {
  const context = await readRequestContext(client);
  const result = await client.query<MinutesRootRow>(
    `select minutes.organization_id,minutes.board_id,minutes.meeting_id,
            minutes.id as minutes_id,minutes.state,minutes.row_version::text,
            version.id as version_id,version.version,version.canonical_text,
            version.canonical_sha256,version.package_base_sha256,
            version.transcript_version_id,version.transcript_sha256,
            package.id as signature_package_id,package.package_sha256 as signature_package_sha256,
            membership.seat_role as actor_seat_role,membership.is_secretary as actor_is_secretary,
            membership.entitlement_generation::text,token.scope_set as token_scopes
       from minutes
       join minutes_versions as version on version.id=minutes.current_version_id
       join board_memberships as membership
         on membership.organization_id=minutes.organization_id
        and membership.board_id=minutes.board_id
        and membership.member_id=boardagent_context_uuid('boardagent.member_id')
       join members as actor on actor.id=membership.member_id
       join access_token_records as token
         on token.organization_id=actor.organization_id and token.member_id=actor.id
        and token.client_id=boardagent_context_uuid('boardagent.client_id')
        and token.jti=boardagent_context_uuid('boardagent.token_jti')
       join oauth_clients as oauth_client on oauth_client.id=token.client_id
       join system_instance as instance
         on instance.organization_id=actor.organization_id
        and instance.canonical_resource_uri=token.resource_uri
       left join minutes_signature_packages as package
         on package.id=minutes.current_signature_package_id
      where minutes.id=$1
        and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
        and boardagent_context_board_allowed(minutes.board_id)
        and actor.state='active' and membership.state='active'
        and membership.active_from<=transaction_timestamp()
        and (membership.active_until is null or membership.active_until>transaction_timestamp())
        and oauth_client.state='active' and token.revoked_at is null
        and token.expires_at>transaction_timestamp()
        and (($2='secretary' and membership.is_secretary and 'secretariat:admin'=any(token.scope_set))
          or ($2='signer' and 'minutes:act'=any(token.scope_set)))
        and exists (
          select 1 from onboarding_attestations as attestation
           where attestation.organization_id=actor.organization_id
             and attestation.member_id=actor.id and attestation.board_id=minutes.board_id
             and attestation.terms_version_id=(
               select terms.id from onboarding_terms_versions as terms
                where terms.organization_id=actor.organization_id
                  and terms.seat_role=membership.seat_role
                  and terms.effective_at<=transaction_timestamp()
                order by terms.effective_at desc,terms.version desc,terms.id desc limit 1
             )
             and attestation.support_version_id=(
               select support.id from secretary_support_versions as support
                where support.organization_id=actor.organization_id
                  and (support.board_id=minutes.board_id or support.board_id is null)
                  and support.effective_at<=transaction_timestamp()
                order by (support.board_id=minutes.board_id) desc,
                         support.effective_at desc,support.version desc,support.id desc limit 1
             )
        )
      for update of minutes`,
    [minutesId, authority]
  );
  const root = result.rows[0];
  if (!root || result.rows.length !== 1) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "minutes lifecycle action is unavailable"
    );
  }
  return { root, context };
}

function requireState(root: MinutesRootRow, states: readonly MinutesRootRow["state"][]): void {
  if (!states.includes(root.state)) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "minutes lifecycle action is unavailable in the current state"
    );
  }
}

function currentMinutesSha256(root: MinutesRootRow): string {
  return root.canonical_sha256.toString("hex");
}

async function preparePublication(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "publication" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["unpublished_draft"]);
  if (
    action.versionId !== root.version_id ||
    !safeHashEqual(action.minutesSha256, currentMinutesSha256(root))
  ) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "minutes publication must bind the exact current draft version and hash"
    );
  }
  const members = await client.query<{
    member_id: string;
    seat_role: "voting_member" | "management" | "observer";
    entitlement_generation: string;
    active_now: boolean;
  }>(
    `select member_id,seat_role,entitlement_generation::text,active_now
       from boardagent_lock_board_members($1,$2,$3::uuid[])
      where not boardagent_member_record_recused('minutes',$4,member_id)
      order by member_id`,
    [root.organization_id, root.board_id, action.signerMemberIds, root.minutes_id]
  );
  if (
    members.rows.length !== action.signerMemberIds.length ||
    members.rows.some(
      (member, index) => member.member_id !== action.signerMemberIds[index] || !member.active_now
    )
  ) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "proposed minutes signers must be exact active board participants"
    );
  }
  const signers: SignerRow[] = members.rows.map((member) => ({
    member_id: member.member_id,
    seat_role: member.seat_role,
    entitlement_generation: member.entitlement_generation,
    member_snapshot_sha256: canonicalSha256({
      memberId: member.member_id,
      seatRole: member.seat_role,
      entitlementGeneration: member.entitlement_generation
    })
  }));
  return {
    payload: {
      schemaVersion: "boardagent.minutes-publication.v1",
      minutesId: root.minutes_id,
      minutesVersionId: root.version_id,
      minutesVersion: root.version,
      minutesSha256: currentMinutesSha256(root),
      transcriptVersionId: root.transcript_version_id,
      transcriptSha256: root.transcript_sha256?.toString("hex") ?? null,
      proposedSigners: signers.map((signer) => ({
        memberId: signer.member_id,
        seatRole: signer.seat_role,
        entitlementGeneration: signer.entitlement_generation,
        memberSnapshotSha256: signer.member_snapshot_sha256
      }))
    },
    details: { kind: "publication", signers }
  };
}

async function lockPendingReviewItem(
  client: PoolClient,
  root: MinutesRootRow,
  reviewItemId: string
): Promise<ReviewItemRow> {
  const result = await client.query<ReviewItemRow>(
    `select item.id,item.item_kind,item.canonical_payload,item.payload_sha256,
            withdrawal.id is not null as withdrawn,
            disposition.id is not null as dispositioned
       from minutes_review_items as item
       left join minutes_review_withdrawals as withdrawal on withdrawal.review_item_id=item.id
       left join minutes_review_dispositions as disposition on disposition.review_item_id=item.id
      where item.id=$1 and item.minutes_id=$2`,
    [reviewItemId, root.minutes_id]
  );
  const item = result.rows[0];
  if (!item || result.rows.length !== 1 || item.withdrawn || item.dispositioned) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "pending minutes review item is unavailable"
    );
  }
  return item;
}

async function lockReviewManifest(
  client: PoolClient,
  root: MinutesRootRow
): Promise<readonly ReviewManifestRow[]> {
  const result = await client.query<ReviewManifestRow>(
    `select item.id,item.item_kind,item.payload_sha256,
            withdrawal.id as withdrawal_id,disposition.id as disposition_id,
            disposition.decision
       from minutes_review_items as item
       left join minutes_review_withdrawals as withdrawal on withdrawal.review_item_id=item.id
       left join minutes_review_dispositions as disposition on disposition.review_item_id=item.id
      where item.minutes_id=$1
      order by item.id`,
    [root.minutes_id]
  );
  return result.rows;
}

function assertReviewResolved(rows: readonly ReviewManifestRow[]): void {
  if (rows.some((row) => row.withdrawal_id === null && row.disposition_id === null)) {
    throw new MinutesLifecycleTransactionError(
      "minutes_review_pending",
      "every minutes review item across all versions must be withdrawn or dispositioned"
    );
  }
}

async function prepareReviewDisposition(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "review_disposition" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["published_review"]);
  const item = await lockPendingReviewItem(client, root, action.reviewItemId);
  let resultingText: string | null = null;
  let resultingSha256: string | null = null;
  if (action.decision === "accepted" && item.item_kind === "redline") {
    if (action.replacementText === undefined) {
      throw new MinutesLifecycleTransactionError(
        "minutes_lifecycle_invalid",
        "accepted redline requires the exact resulting canonical minutes text"
      );
    }
    const redline = MinutesRedlineSchema.parse(
      JSON.parse(item.canonical_payload.toString("utf8")) as unknown
    );
    resultingText = applyExactMinutesRedline(root.canonical_text, redline);
    if (resultingText !== action.replacementText) {
      throw new MinutesLifecycleTransactionError(
        "minutes_lifecycle_invalid",
        "supplied replacement is not the exact accepted redline result"
      );
    }
    resultingSha256 = sha256Hex(resultingText);
  } else if (action.replacementText !== undefined) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "only an accepted redline may supply replacement minutes text"
    );
  }
  const payload: JsonValue = {
    schemaVersion: "boardagent.minutes-review-disposition.v1",
    minutesId: root.minutes_id,
    minutesVersionId: root.version_id,
    minutesVersion: root.version,
    minutesSha256: currentMinutesSha256(root),
    reviewItemId: item.id,
    reviewItemKind: item.item_kind,
    reviewPayloadSha256: item.payload_sha256.toString("hex"),
    decision: action.decision,
    reason: action.reason,
    resultingSha256
  };
  return {
    payload,
    details: {
      kind: "review_disposition",
      item,
      resultingText,
      resultingSha256
    }
  };
}

async function preparePackageCorrection(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "package_correction" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["published_review", "signature_ready"]);
  if (action.expectedVersionId !== root.version_id) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "minutes correction must bind the exact current version"
    );
  }
  if (action.canonicalText === root.canonical_text) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "minutes correction must change the canonical package"
    );
  }
  await client.query(
    `select id from tasks
      where source_minutes_id=$1 and state='draft'
      order by id for update`,
    [root.minutes_id]
  );
  await client.query(
    `select id from action_stages
      where target_type='minutes' and target_id=$1 and state='active'
      order by id for update`,
    [root.minutes_id]
  );
  await client.query(
    `select id from minutes_resign_requirements
      where minutes_id=$1 and state='pending'
      order by id for update`,
    [root.minutes_id]
  );
  const resultingSha256 = sha256Hex(action.canonicalText);
  return {
    payload: {
      schemaVersion: "boardagent.minutes-package-correction.v1",
      minutesId: root.minutes_id,
      baseVersionId: root.version_id,
      baseVersion: root.version,
      baseSha256: currentMinutesSha256(root),
      resultingVersion: root.version + 1,
      resultingSha256,
      reason: action.reason
    },
    details: { kind: "package_correction", resultingSha256 }
  };
}

async function prepareActionDeclaration(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "action_declaration" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["published_review"]);
  const manifest = action.manifest;
  if (
    manifest.minutesId !== root.minutes_id ||
    manifest.minutesVersion !== root.version ||
    !safeHashEqual(manifest.minutesSha256, currentMinutesSha256(root))
  ) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "action declaration must bind the exact current minutes version and hash"
    );
  }
  assertReviewResolved(await lockReviewManifest(client, root));
  const existing = await client.query<{ id: string }>(
    "select id from minutes_action_declarations where minutes_version_id=$1",
    [root.version_id]
  );
  if (existing.rows.length !== 0) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "current minutes package already has an action declaration"
    );
  }
  if (manifest.declaration === "items_logged") {
    const owners = manifest.items.map(({ ownerMemberId }) => ownerMemberId).toSorted();
    const expected = [...new Set(owners)];
    const eligible = await client.query<{ member_id: string }>(
      `select member_id
         from boardagent_lock_board_members($1,$2,$3::uuid[])
        where active_now and seat_role<>'observer'
        order by member_id`,
      [root.organization_id, root.board_id, expected]
    );
    if (
      eligible.rows.length !== expected.length ||
      eligible.rows.some((row, index) => row.member_id !== expected[index])
    ) {
      throw new MinutesLifecycleTransactionError(
        "minutes_lifecycle_invalid",
        "every action owner must be an active non-observer board participant"
      );
    }
  }
  const manifestSha256 = canonicalSha256(manifest);
  return {
    payload: manifest as unknown as JsonValue,
    details: { kind: "action_declaration", manifestSha256 }
  };
}

async function prepareSignaturePackageIssue(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "signature_package_issue" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["published_review"]);
  if (action.expectedVersionId !== root.version_id) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "signature preparation must bind the exact current minutes version"
    );
  }
  const reviewRows = await lockReviewManifest(client, root);
  assertReviewResolved(reviewRows);
  const declaration = await client.query<{
    complete_manifest: Buffer;
    manifest_sha256: Buffer;
  }>(
    `select complete_manifest,manifest_sha256
       from minutes_action_declarations
      where minutes_version_id=$1`,
    [root.version_id]
  );
  const declarationRow = declaration.rows[0];
  if (!declarationRow || declaration.rows.length !== 1) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "signature package requires the exact current action declaration"
    );
  }
  const requestedIds = action.requirements.map(({ memberId }) => memberId);
  const members = await client.query<{
    member_id: string;
    seat_role: "voting_member" | "management" | "observer";
    entitlement_generation: string;
    member_state: string;
    membership_state: string;
    active_now: boolean;
  }>(
    `select member_id,seat_role,entitlement_generation::text,
            member_state,membership_state,active_now
       from boardagent_lock_board_members($1,$2,$3::uuid[])
      where not boardagent_member_record_recused('minutes',$4,member_id)
      order by member_id`,
    [root.organization_id, root.board_id, requestedIds, root.minutes_id]
  );
  if (
    members.rows.length !== requestedIds.length ||
    members.rows.some(
      (row, index) =>
        row.member_id !== requestedIds[index] ||
        row.member_state !== "active" ||
        row.membership_state !== "active" ||
        !row.active_now
    )
  ) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "signature requirements must name exact active board participants"
    );
  }
  const signers: SignerRow[] = members.rows.map((row, index) => {
    const requested = action.requirements[index]!;
    return {
      member_id: row.member_id,
      seat_role: row.seat_role,
      entitlement_generation: row.entitlement_generation,
      member_snapshot_sha256: canonicalSha256({
        memberId: row.member_id,
        seatRole: row.seat_role,
        requirement: requested.requirement,
        entitlementGeneration: row.entitlement_generation
      })
    };
  });
  const priorVersion = await client.query<{ maximum: number }>(
    "select coalesce(max(version),0)::integer as maximum from minutes_signature_packages where minutes_id=$1",
    [root.minutes_id]
  );
  const packageVersion = (priorVersion.rows[0]?.maximum ?? 0) + 1;
  const transcriptManifestSha256 = canonicalSha256({
    transcriptVersionId: root.transcript_version_id,
    transcriptSha256: root.transcript_sha256?.toString("hex") ?? null
  });
  const actionManifestSha256 = declarationRow.manifest_sha256.toString("hex");
  const reviewManifestSha256 = canonicalSha256(
    reviewRows.map((row) => ({
      reviewItemId: row.id,
      itemKind: row.item_kind,
      payloadSha256: row.payload_sha256.toString("hex"),
      withdrawalId: row.withdrawal_id,
      dispositionId: row.disposition_id,
      decision: row.decision
    }))
  );
  const signerManifestSha256 = canonicalSha256(
    action.requirements.map((requirement, index) => ({
      ...requirement,
      seatRole: signers[index]!.seat_role,
      memberSnapshotSha256: signers[index]!.member_snapshot_sha256
    }))
  );
  const proposedPackageSha256 = canonicalSha256({
    schemaVersion: "boardagent.minutes-signature-package.v1",
    minutesId: root.minutes_id,
    minutesVersionId: root.version_id,
    minutesVersion: root.version,
    minutesSha256: currentMinutesSha256(root),
    transcriptManifestSha256,
    actionManifestSha256,
    reviewManifestSha256,
    signerManifestSha256,
    packageVersion
  });
  const priorPackage = await client.query<{ id: string }>(
    `select id from minutes_signature_packages
      where minutes_id=$1 and state='superseded'
      order by version desc,id desc limit 1 for update`,
    [root.minutes_id]
  );
  await client.query(
    `select signature.id
       from minutes_signatures as signature
       join minutes_signature_packages as package on package.id=signature.package_id
       left join minutes_signature_supersessions as supersession
         on supersession.old_signature_id=signature.id
      where package.minutes_id=$1 and package.state='superseded' and supersession.id is null
      order by signature.id`,
    [root.minutes_id]
  );
  await client.query(
    `select id from minutes_resign_requirements
      where minutes_id=$1 and state='pending'
      order by id for update`,
    [root.minutes_id]
  );
  const payload: JsonValue = {
    schemaVersion: "boardagent.minutes-signature-package-request.v1",
    minutesId: root.minutes_id,
    minutesVersionId: root.version_id,
    minutesVersion: root.version,
    minutesSha256: currentMinutesSha256(root),
    transcriptManifestSha256,
    actionManifestSha256,
    reviewManifestSha256,
    signerManifestSha256,
    proposedPackageSha256,
    requirements: action.requirements as unknown as JsonValue
  };
  return {
    payload,
    details: {
      kind: "signature_package_issue",
      packageVersion,
      transcriptManifestSha256,
      actionManifestSha256,
      reviewManifestSha256,
      signerManifestSha256,
      proposedPackageSha256,
      signers,
      priorPackageId: priorPackage.rows[0]?.id ?? null
    }
  };
}

async function prepareSignature(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "signature" }>,
  root: MinutesRootRow,
  context: ActiveRequestContext
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["signature_ready"]);
  if (!root.signature_package_id || !root.signature_package_sha256) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "current signature package is unavailable"
    );
  }
  if (action.packageId !== root.signature_package_id) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "signature must bind the exact current signature package"
    );
  }
  const requirement = await client.query<{
    member_id: string;
    seat_role: "voting_member" | "management" | "observer";
    requirement: "required" | "permitted";
    member_snapshot_sha256: Buffer;
  }>(
    `select member_id,seat_role,requirement,member_snapshot_sha256
       from minutes_signature_requirements
      where package_id=$1 and member_id=$2`,
    [root.signature_package_id, context.memberId]
  );
  const row = requirement.rows[0];
  if (!row || requirement.rows.length !== 1 || row.seat_role !== root.actor_seat_role) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "actor is not an exact signer on the current package"
    );
  }
  const existing = await client.query<{ id: string }>(
    "select id from minutes_signatures where package_id=$1 and signer_member_id=$2",
    [root.signature_package_id, context.memberId]
  );
  if (existing.rows.length !== 0) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "actor already signed the current package"
    );
  }
  const normalized: SignerRow = {
    member_id: row.member_id,
    seat_role: row.seat_role,
    entitlement_generation: root.entitlement_generation,
    member_snapshot_sha256: row.member_snapshot_sha256.toString("hex")
  };
  return {
    payload: {
      schemaVersion: "boardagent.minutes-signature.v1",
      minutesId: root.minutes_id,
      minutesVersionId: root.version_id,
      minutesSha256: currentMinutesSha256(root),
      signaturePackageId: root.signature_package_id,
      packageSha256: root.signature_package_sha256.toString("hex"),
      signerMemberId: context.memberId,
      signerSeatRole: root.actor_seat_role,
      signerRequirement: row.requirement,
      memberSnapshotSha256: normalized.member_snapshot_sha256,
      reservation: action.reservation,
      reservationSha256: action.reservation === null ? null : sha256Hex(action.reservation)
    },
    details: { kind: "signature", requirement: normalized }
  };
}

async function prepareFinalization(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "finalization" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["signature_ready"]);
  if (!root.signature_package_id || !root.signature_package_sha256) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "current signature package is unavailable"
    );
  }
  if (action.packageId !== root.signature_package_id) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "finalization must bind the exact current signature package"
    );
  }
  const missing = await client.query<{ member_id: string }>(
    `select requirement.member_id
       from minutes_signature_requirements as requirement
       left join minutes_signatures as signature
         on signature.package_id=requirement.package_id
        and signature.signer_member_id=requirement.member_id
      where requirement.package_id=$1 and requirement.requirement='required'
        and signature.id is null
      order by requirement.member_id`,
    [root.signature_package_id]
  );
  if (missing.rows.length !== 0) {
    throw new MinutesLifecycleTransactionError(
      "minutes_signature_incomplete",
      "every required current-package signature must exist before finalization"
    );
  }
  const declaration = await client.query<{
    complete_manifest: Buffer;
    manifest_sha256: Buffer;
  }>(
    `select complete_manifest,manifest_sha256
       from minutes_action_declarations
      where minutes_version_id=$1`,
    [root.version_id]
  );
  const declarationRow = declaration.rows[0];
  if (!declarationRow || declaration.rows.length !== 1) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "finalization requires the exact current action declaration"
    );
  }
  const manifest = MinutesActionManifestSchema.parse(
    JSON.parse(declarationRow.complete_manifest.toString("utf8")) as unknown
  );
  const tasksResult = await client.query<DraftTaskRow>(
    `select id,owner_member_id,source_minutes_sha256,row_version::text
       from tasks
      where source_minutes_id=$1 and source_minutes_version_id=$2
      order by id for update`,
    [root.minutes_id, root.version_id]
  );
  if (tasksResult.rows.some((task) => task.source_minutes_sha256.length !== 32)) {
    throw new Error("draft task source hash has invalid length");
  }
  const activationManifestSha256 = activationManifestHash(
    manifest,
    tasksResult.rows.map((task) => ({
      taskId: task.id,
      state: "draft" as const,
      sourceMinutesSha256: task.source_minutes_sha256.toString("hex")
    }))
  );
  return {
    payload: {
      schemaVersion: "boardagent.minutes-finalization.v1",
      minutesId: root.minutes_id,
      minutesVersionId: root.version_id,
      minutesSha256: currentMinutesSha256(root),
      signaturePackageId: root.signature_package_id,
      packageSha256: root.signature_package_sha256.toString("hex"),
      actionManifestSha256: declarationRow.manifest_sha256.toString("hex"),
      activationManifestSha256,
      taskIds: tasksResult.rows.map(({ id }) => id)
    },
    details: {
      kind: "finalization",
      activationManifestSha256,
      tasks: tasksResult.rows,
      manifest
    }
  };
}

async function prepareFinalizedCorrection(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "finalized_correction" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["finalized"]);
  if (action.replacementMinutesId === root.minutes_id) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "finalized correction requires a distinct replacement minutes id"
    );
  }
  if (action.canonicalText === root.canonical_text) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_invalid",
      "finalized correction must create a changed replacement package"
    );
  }
  const current = await client.query<{ current_minutes_id: string | null }>(
    "select current_minutes_id from meetings where id=$1 for update",
    [root.meeting_id]
  );
  if (current.rows[0]?.current_minutes_id !== root.minutes_id) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "only the current finalized aggregate may start a correction cycle"
    );
  }
  const existing = await client.query<{ id: string }>(
    "select id from minutes_correction_cycles where original_minutes_id=$1",
    [root.minutes_id]
  );
  if (existing.rows.length !== 0) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "finalized minutes already have a direct correction cycle"
    );
  }
  const replacementSha256 = sha256Hex(action.canonicalText);
  return {
    payload: {
      schemaVersion: "boardagent.minutes-finalized-correction.v1",
      originalMinutesId: root.minutes_id,
      originalVersionId: root.version_id,
      originalSha256: currentMinutesSha256(root),
      replacementMinutesId: action.replacementMinutesId,
      replacementSha256,
      reason: action.reason
    },
    details: { kind: "finalized_correction", replacementSha256 }
  };
}

async function prepareCancellation(
  client: PoolClient,
  action: Extract<NormalizedAction, { readonly kind: "cancellation" }>,
  root: MinutesRootRow
): Promise<{ readonly payload: JsonValue; readonly details: PreparedDetails }> {
  requireState(root, ["unpublished_draft", "published_review", "signature_ready"]);
  const draftTasks = await client.query<{ id: string }>(
    `select id from tasks
      where source_minutes_id=$1 and state='draft'
      order by id for update`,
    [root.minutes_id]
  );
  await client.query(
    `select id from action_stages
      where target_type='minutes' and target_id=$1 and state='active'
      order by id for update`,
    [root.minutes_id]
  );
  await client.query(
    `select id from minutes_resign_requirements
      where minutes_id=$1 and state='pending'
      order by id for update`,
    [root.minutes_id]
  );
  return {
    payload: {
      schemaVersion: "boardagent.minutes-cancellation.v1",
      minutesId: root.minutes_id,
      minutesVersionId: root.version_id,
      minutesVersion: root.version,
      minutesSha256: currentMinutesSha256(root),
      signaturePackageId: root.signature_package_id,
      signaturePackageSha256: root.signature_package_sha256?.toString("hex") ?? null,
      supersededDraftTaskIds: draftTasks.rows.map(({ id }) => id),
      reason: action.reason
    },
    details: { kind: "cancellation", draftTaskIds: draftTasks.rows.map(({ id }) => id) }
  };
}

async function prepareAction(
  client: PoolClient,
  rawAction: MinutesLifecycleAction
): Promise<PreparedAction> {
  const action = normalizeAction(rawAction);
  const authority = action.kind === "signature" ? "signer" : "secretary";
  const { root, context } = await lockAuthorizedRoot(client, action.minutesId, authority);
  let prepared: { readonly payload: JsonValue; readonly details: PreparedDetails };
  switch (action.kind) {
    case "publication":
      prepared = await preparePublication(client, action, root);
      break;
    case "review_disposition":
      prepared = await prepareReviewDisposition(client, action, root);
      break;
    case "package_correction":
      prepared = await preparePackageCorrection(client, action, root);
      break;
    case "action_declaration":
      prepared = await prepareActionDeclaration(client, action, root);
      break;
    case "signature_package_issue":
      prepared = await prepareSignaturePackageIssue(client, action, root);
      break;
    case "signature":
      prepared = await prepareSignature(client, action, root, context);
      break;
    case "finalization":
      prepared = await prepareFinalization(client, action, root);
      break;
    case "finalized_correction":
      prepared = await prepareFinalizedCorrection(client, action, root);
      break;
    case "cancellation":
      prepared = await prepareCancellation(client, action, root);
      break;
  }
  const packageSha256 =
    action.kind === "signature" || action.kind === "finalization"
      ? root.signature_package_sha256?.toString("hex")
      : currentMinutesSha256(root);
  if (!packageSha256) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "exact minutes package binding is unavailable"
    );
  }
  return {
    action,
    root,
    context,
    payload: prepared.payload,
    payloadSha256: canonicalSha256(prepared.payload),
    packageSha256,
    details: prepared.details
  };
}

function auditInput(
  prepared: Pick<PreparedAction, "root" | "context">,
  consentRecordId: string | null,
  eventType: AuditAppendInput["event"]["eventType"],
  entityType: string,
  entityId: string,
  details: Readonly<Record<string, JsonValue>>,
  eventId = newId(),
  objectVersion?: bigint
): AuditAppendInput {
  return {
    organizationId: prepared.root.organization_id,
    consentRecordId,
    ...(objectVersion === undefined ? {} : { objectVersion }),
    event: {
      eventId,
      eventType,
      actorMemberId: prepared.context.memberId,
      actorClientId: prepared.context.clientId,
      tokenJti: prepared.context.tokenJti,
      entityType,
      entityId,
      boardId: prepared.root.board_id,
      origin: "mcp",
      details,
      schemaVersion: 1
    }
  };
}

async function assertConsentBinding(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<void> {
  const expected = operation(prepared.action);
  const result = await client.query<{ valid: boolean }>(
    `select exists (
       select 1 from consent_records as consent
       join action_stages as stage on stage.id=consent.stage_id
       join input_required_attempts as attempt on attempt.id=consent.input_required_attempt_id
       where consent.id=$1 and consent.organization_id=$2 and consent.board_id=$3
         and consent.actor_member_id=$4 and consent.client_id=$5 and consent.token_jti=$6
         and consent.action_code=$7 and consent.target_type='minutes' and consent.target_id=$8
         and consent.payload_sha256=$9 and consent.package_sha256=$10
         and stage.id=consent.stage_id and stage.state='active'
         and stage.payload_sha256=consent.payload_sha256
         and stage.package_sha256=consent.package_sha256
         and attempt.stage_id=stage.id and attempt.state='prepared'
         and attempt.original_name=$7
     ) as valid`,
    [
      consentRecordId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.context.memberId,
      prepared.context.clientId,
      prepared.context.tokenJti,
      expected.actionCode,
      prepared.root.minutes_id,
      Buffer.from(prepared.payloadSha256, "hex"),
      Buffer.from(prepared.packageSha256, "hex")
    ]
  );
  if (result.rows[0]?.valid !== true) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "exact confirmed minutes action binding is unavailable"
    );
  }
}

interface VersionAppendResult {
  readonly versionId: string;
  readonly version: number;
  readonly canonicalSha256: string;
  readonly diffId: string;
  readonly draftAuditInputs: readonly AuditAppendInput[];
}

async function appendVersionAndInvalidate(
  client: PoolClient,
  prepared: Pick<PreparedAction, "root" | "context">,
  consentRecordId: string | null,
  canonicalMinutesText: string,
  reason: string,
  operations: JsonValue,
  transcriptOverride?: {
    readonly versionId: string;
    readonly sha256: string;
  },
  nextState: "unpublished_draft" | "published_review" = "published_review"
): Promise<VersionAppendResult> {
  const root = prepared.root;
  const versionId = newId();
  const diffId = newId();
  const version = root.version + 1;
  const canonicalSha256Hex = sha256Hex(canonicalMinutesText);
  const transcriptVersionId = transcriptOverride?.versionId ?? root.transcript_version_id;
  const transcriptSha256 =
    transcriptOverride === undefined
      ? root.transcript_sha256
      : Buffer.from(transcriptOverride.sha256, "hex");
  const packageBaseSha256 = canonicalSha256({
    schemaVersion: "boardagent.minutes-package-base.v1",
    minutesId: root.minutes_id,
    version,
    canonicalSha256: canonicalSha256Hex,
    transcriptVersionId,
    transcriptSha256: transcriptSha256?.toString("hex") ?? null
  });
  const diffSha256 = canonicalSha256({
    schemaVersion: "boardagent.minutes-diff.v1",
    minutesId: root.minutes_id,
    baseVersionId: root.version_id,
    newVersionId: versionId,
    operations
  });
  await client.query(
    `insert into minutes_versions(
       id,organization_id,board_id,minutes_id,version,canonical_schema,canonical_text,
       canonical_sha256,package_base_sha256,transcript_version_id,transcript_sha256,
       created_by,supersedes_id
     ) values ($1,$2,$3,$4,$5,'boardagent.minutes.v1',$6,$7,$8,$9,$10,$11,$12)`,
    [
      versionId,
      root.organization_id,
      root.board_id,
      root.minutes_id,
      version,
      canonicalMinutesText,
      Buffer.from(canonicalSha256Hex, "hex"),
      Buffer.from(packageBaseSha256, "hex"),
      transcriptVersionId,
      transcriptSha256,
      prepared.context.memberId,
      root.version_id
    ]
  );
  await client.query(
    `insert into minutes_diffs(
       id,minutes_id,base_version_id,new_version_id,operations,canonical_sha256
     ) values ($1,$2,$3,$4,$5,$6)`,
    [
      diffId,
      root.minutes_id,
      root.version_id,
      versionId,
      JSON.stringify(operations),
      Buffer.from(diffSha256, "hex")
    ]
  );

  const staleTasks = await client.query<{ id: string }>(
    `select id from tasks
      where source_minutes_id=$1 and source_minutes_version_id=$2 and state='draft'
      order by id for update`,
    [root.minutes_id, root.version_id]
  );
  const draftAuditInputs: AuditAppendInput[] = [];
  for (const task of staleTasks.rows) {
    const auditEventId = newId();
    const dispositionId = newId();
    const updated = await client.query(
      `update tasks set state='superseded',row_version=row_version+1
        where id=$1 and state='draft'`,
      [task.id]
    );
    if (updated.rowCount !== 1) throw new Error("stale draft task changed during correction");
    await client.query(
      `insert into minutes_action_item_dispositions(
         id,task_id,stale_minutes_version_id,replacement_minutes_version_id,
         disposition,reason,audit_event_id
       ) values ($1,$2,$3,$4,'superseded',$5,$6)`,
      [dispositionId, task.id, root.version_id, versionId, reason, auditEventId]
    );
    draftAuditInputs.push(
      auditInput(
        prepared,
        consentRecordId,
        "minutes_action_item_draft_superseded",
        "task",
        task.id,
        {
          minutesId: root.minutes_id,
          staleMinutesVersionId: root.version_id,
          replacementMinutesVersionId: versionId,
          dispositionId,
          reason
        },
        auditEventId
      )
    );
  }

  if (root.signature_package_id) {
    const superseded = await client.query(
      `update minutes_signature_packages set state='superseded'
        where id=$1 and state='current'`,
      [root.signature_package_id]
    );
    if (superseded.rowCount !== 1) {
      throw new Error("current signature package changed during minutes correction");
    }
  }
  await client.query(
    `update action_stages set state='replaced'
      where target_type='minutes' and target_id=$1 and action_code='stage_minutes_signature'
        and state='active'`,
    [root.minutes_id]
  );
  await client.query(
    `update minutes_resign_requirements
        set state='resolved',resolution='package_superseded',resolved_at=transaction_timestamp()
      where minutes_id=$1 and state='pending'`,
    [root.minutes_id]
  );
  await client.query(
    `update pending_action_feed
        set state='superseded',resolved_at=transaction_timestamp()
      where organization_id=$1 and board_id=$2 and object_type='minutes' and object_id=$3
        and state='pending'
        and action_type in ('minutes_signature_required','minutes_resign_required')`,
    [root.organization_id, root.board_id, root.minutes_id]
  );
  const updated = await client.query<{ row_version: string }>(
    `update minutes
        set current_version_id=$1,current_signature_package_id=null,
            state=$4,row_version=row_version+1
      where id=$2 and row_version=$3::bigint
      returning row_version::text`,
    [versionId, root.minutes_id, root.row_version, nextState]
  );
  if (updated.rows.length !== 1) throw new Error("minutes changed during version correction");
  return {
    versionId,
    version,
    canonicalSha256: canonicalSha256Hex,
    diffId,
    draftAuditInputs
  };
}

export interface TranscriptMinutesRefreshInput {
  readonly meetingId: string;
  readonly transcriptVersionId: string;
  readonly transcriptSha256: string;
}

export interface TranscriptMinutesRefreshResult {
  readonly minutesId: string;
  readonly minutesVersionId: string;
  readonly version: number;
  readonly canonicalSha256: string;
  readonly packageBaseSha256: string;
  readonly state: "unpublished_draft" | "published_review";
  readonly auditEvents: readonly AuditAppendInput[];
}

/**
 * Mechanical consequence of an immutable transcript successor. A current nonterminal
 * minutes aggregate is re-versioned with unchanged text and the new annex hash; stale
 * draft actions, signature packages and active signature stages are invalidated through
 * the same implementation used by an explicit package correction.
 */
export async function refreshMinutesTranscriptAnnexInTransaction(
  client: PoolClient,
  input: TranscriptMinutesRefreshInput
): Promise<TranscriptMinutesRefreshResult | null> {
  const meetingId = UuidV7Schema.parse(input.meetingId);
  const transcriptVersionId = UuidV7Schema.parse(input.transcriptVersionId);
  const transcriptSha256 = Sha256HexSchema.parse(input.transcriptSha256);
  const context = await readRequestContext(client);
  const current = await client.query<{ current_minutes_id: string | null }>(
    `select current_minutes_id from meetings
      where id=$1 and boardagent_meeting_secretary_for_board(board_id)
      for update`,
    [meetingId]
  );
  const minutesId = current.rows[0]?.current_minutes_id;
  if (minutesId === undefined) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "meeting is unavailable for transcript-bound minutes refresh"
    );
  }
  if (minutesId === null) return null;
  const { root } = await lockAuthorizedRoot(client, minutesId, "secretary");
  if (root.meeting_id !== meetingId) {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "current meeting minutes changed before transcript refresh"
    );
  }
  if (root.state === "finalized" || root.state === "cancelled") {
    throw new MinutesLifecycleTransactionError(
      "minutes_lifecycle_unavailable",
      "a finalized or cancelled minutes aggregate requires its explicit correction cycle before the transcript annex can change"
    );
  }
  if (
    root.transcript_version_id === transcriptVersionId &&
    root.transcript_sha256 !== null &&
    safeHashEqual(root.transcript_sha256.toString("hex"), transcriptSha256)
  ) {
    return null;
  }
  const reason = "Current minutes re-versioned because the meeting transcript annex changed.";
  const nextState = root.state === "unpublished_draft" ? "unpublished_draft" : "published_review";
  const appended = await appendVersionAndInvalidate(
    client,
    { root, context },
    null,
    root.canonical_text,
    reason,
    [
      {
        operation: "replace_transcript_annex",
        priorTranscriptVersionId: root.transcript_version_id,
        priorTranscriptSha256: root.transcript_sha256?.toString("hex") ?? null,
        resultingTranscriptVersionId: transcriptVersionId,
        resultingTranscriptSha256: transcriptSha256
      }
    ],
    { versionId: transcriptVersionId, sha256: transcriptSha256 },
    nextState
  );
  const packageBaseSha256 = canonicalSha256({
    schemaVersion: "boardagent.minutes-package-base.v1",
    minutesId: root.minutes_id,
    version: appended.version,
    canonicalSha256: appended.canonicalSha256,
    transcriptVersionId,
    transcriptSha256
  });
  const primary = auditInput(
    { root, context },
    null,
    "minutes_package_corrected",
    "minutes",
    root.minutes_id,
    {
      cause: "transcript_annex_changed",
      baseVersionId: root.version_id,
      baseSha256: currentMinutesSha256(root),
      resultingVersionId: appended.versionId,
      resultingSha256: appended.canonicalSha256,
      transcriptVersionId,
      transcriptSha256,
      diffId: appended.diffId,
      supersededSignaturePackageId: root.signature_package_id,
      reason
    },
    newId(),
    BigInt(root.row_version) + 1n
  );
  return {
    minutesId: root.minutes_id,
    minutesVersionId: appended.versionId,
    version: appended.version,
    canonicalSha256: appended.canonicalSha256,
    packageBaseSha256,
    state: nextState,
    auditEvents: [primary, ...appended.draftAuditInputs]
  };
}

async function actReviewDisposition(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "review_disposition" ||
    prepared.details.kind !== "review_disposition"
  ) {
    throw new Error("review disposition preparation mismatch");
  }
  const action = prepared.action;
  const details = prepared.details;
  const dispositionId = newId();
  let versionId = prepared.root.version_id;
  let canonicalSha256Hex = currentMinutesSha256(prepared.root);
  let diffId: string | null = null;
  let draftAuditInputs: readonly AuditAppendInput[] = [];
  if (
    action.decision === "accepted" &&
    details.item.item_kind === "redline" &&
    details.resultingText !== null &&
    details.resultingSha256 !== null
  ) {
    const version = await appendVersionAndInvalidate(
      client,
      prepared,
      consentRecordId,
      details.resultingText,
      action.reason,
      [JSON.parse(details.item.canonical_payload.toString("utf8")) as JsonValue]
    );
    versionId = version.versionId;
    canonicalSha256Hex = version.canonicalSha256;
    diffId = version.diffId;
    draftAuditInputs = version.draftAuditInputs;
  }
  await client.query(
    `insert into minutes_review_dispositions(
       id,organization_id,review_item_id,secretary_member_id,decision,reason,
       resulting_minutes_version_id,diff_id,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      dispositionId,
      prepared.root.organization_id,
      action.reviewItemId,
      prepared.context.memberId,
      action.decision,
      action.reason,
      diffId === null ? null : versionId,
      diffId,
      consentRecordId
    ]
  );
  const primary = auditInput(
    prepared,
    consentRecordId,
    "minutes_review_dispositioned",
    "minutes_review_disposition",
    dispositionId,
    {
      minutesId: prepared.root.minutes_id,
      reviewItemId: action.reviewItemId,
      reviewItemKind: details.item.item_kind,
      decision: action.decision,
      reason: action.reason,
      resultingMinutesVersionId: diffId === null ? null : versionId,
      resultingMinutesSha256: diffId === null ? null : canonicalSha256Hex,
      diffId
    },
    newId(),
    BigInt(prepared.root.row_version) + (diffId === null ? 0n : 1n)
  );
  return {
    value: {
      kind: "review_disposition",
      dispositionId,
      minutesId: prepared.root.minutes_id,
      minutesVersionId: versionId,
      minutesSha256: canonicalSha256Hex,
      decision: action.decision
    },
    auditEvents: [primary, ...draftAuditInputs]
  };
}

async function actPackageCorrection(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "package_correction" ||
    prepared.details.kind !== "package_correction"
  ) {
    throw new Error("package correction preparation mismatch");
  }
  const version = await appendVersionAndInvalidate(
    client,
    prepared,
    consentRecordId,
    prepared.action.canonicalText,
    prepared.action.reason,
    [
      {
        operation: "replace_package",
        baseSha256: currentMinutesSha256(prepared.root),
        resultingSha256: prepared.details.resultingSha256,
        reason: prepared.action.reason
      }
    ]
  );
  const primary = auditInput(
    prepared,
    consentRecordId,
    "minutes_package_corrected",
    "minutes",
    prepared.root.minutes_id,
    {
      baseVersionId: prepared.root.version_id,
      baseSha256: currentMinutesSha256(prepared.root),
      resultingVersionId: version.versionId,
      resultingSha256: version.canonicalSha256,
      diffId: version.diffId,
      supersededSignaturePackageId: prepared.root.signature_package_id,
      reason: prepared.action.reason
    },
    newId(),
    BigInt(prepared.root.row_version) + 1n
  );
  return {
    value: {
      kind: "package_correction",
      minutesId: prepared.root.minutes_id,
      minutesVersionId: version.versionId,
      minutesSha256: version.canonicalSha256
    },
    auditEvents: [primary, ...version.draftAuditInputs]
  };
}

async function actActionDeclaration(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "action_declaration" ||
    prepared.details.kind !== "action_declaration"
  ) {
    throw new Error("action declaration preparation mismatch");
  }
  const declarationId = newId();
  const manifest = prepared.action.manifest;
  const canonicalManifest = Buffer.from(canonicalJson(manifest), "utf8");
  await client.query(
    `insert into minutes_action_declarations(
       id,organization_id,board_id,minutes_id,minutes_version_id,minutes_sha256,
       declaration,complete_manifest,manifest_sha256,secretary_member_id,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      declarationId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.minutes_id,
      prepared.root.version_id,
      prepared.root.canonical_sha256,
      manifest.declaration,
      canonicalManifest,
      Buffer.from(prepared.details.manifestSha256, "hex"),
      prepared.context.memberId,
      consentRecordId
    ]
  );
  const taskIds: string[] = [];
  if (manifest.declaration === "items_logged") {
    for (const item of manifest.items) {
      const taskSha256 = canonicalSha256({
        schemaVersion: "boardagent.task.v1",
        item,
        sourceMinutesId: prepared.root.minutes_id,
        sourceMinutesVersionId: prepared.root.version_id,
        sourceMinutesSha256: manifest.minutesSha256
      });
      await client.query(
        `insert into tasks(
           id,organization_id,board_id,source_meeting_id,source_minutes_id,
           source_minutes_version_id,source_minutes_sha256,source_locator,owner_member_id,
           due_at,description_schema,canonical_description,required_evidence,task_sha256,
           state,created_by
         ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'boardagent.task.v1',$11,$12,$13,'draft',$14)`,
        [
          item.itemId,
          prepared.root.organization_id,
          prepared.root.board_id,
          prepared.root.meeting_id,
          prepared.root.minutes_id,
          prepared.root.version_id,
          prepared.root.canonical_sha256,
          JSON.stringify(item.sourceLocator),
          item.ownerMemberId,
          item.dueAt,
          item.description,
          JSON.stringify({ text: item.requiredEvidence, visibility: item.visibility }),
          Buffer.from(taskSha256, "hex"),
          prepared.context.memberId
        ]
      );
      taskIds.push(item.itemId);
    }
  }
  const event = auditInput(
    prepared,
    consentRecordId,
    "minutes_action_items_declared",
    "minutes_action_declaration",
    declarationId,
    {
      minutesId: prepared.root.minutes_id,
      minutesVersionId: prepared.root.version_id,
      minutesSha256: currentMinutesSha256(prepared.root),
      declaration: manifest.declaration,
      manifestSha256: prepared.details.manifestSha256,
      taskIds
    },
    newId(),
    BigInt(prepared.root.row_version)
  );
  return {
    value: {
      kind: "action_declaration",
      minutesId: prepared.root.minutes_id,
      declarationId,
      manifestSha256: prepared.details.manifestSha256,
      taskIds
    },
    auditEvents: [event]
  };
}

async function transactionTimestamp(client: PoolClient): Promise<string> {
  const result = await client.query<{ occurred_at: string }>(
    `select to_char(transaction_timestamp() at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as occurred_at`
  );
  const occurredAt = result.rows[0]?.occurred_at;
  if (!occurredAt) throw new Error("transaction timestamp is unavailable");
  return occurredAt;
}

async function nextMemberFeedSequence(
  client: PoolClient,
  boardId: string,
  memberId: string
): Promise<bigint> {
  const result = await client.query<{ next_sequence: string }>(
    `select (coalesce(max(feed_sequence),0)+1)::text as next_sequence
       from pending_action_feed where board_id=$1 and member_id=$2`,
    [boardId, memberId]
  );
  return BigInt(result.rows[0]?.next_sequence ?? "1");
}

async function insertPendingNotice(
  client: PoolClient,
  input: {
    readonly prepared: PreparedAction;
    readonly recipientMemberId: string;
    readonly entitlementGeneration: string;
    readonly noticeType: string;
    readonly actionType: string;
    readonly objectType: "minutes" | "task";
    readonly objectId: string;
    readonly objectVersion: number;
    readonly deltaType: "action_required" | "minutes_resign_required" | "task_assigned";
    readonly safeRefs: Readonly<Record<string, string | number>>;
    readonly auditEventId: string;
  }
): Promise<{ readonly noticeId: string; readonly feedId: string; readonly feedSequence: bigint }> {
  const noticeId = newId();
  const feedId = newId();
  const feedSequence = await nextMemberFeedSequence(
    client,
    input.prepared.root.board_id,
    input.recipientMemberId
  );
  const entitlementGeneration = Number(input.entitlementGeneration);
  if (!Number.isSafeInteger(entitlementGeneration) || entitlementGeneration < 1) {
    throw new Error("member entitlement generation is invalid");
  }
  const occurredAt = await transactionTimestamp(client);
  const delta = PendingActionDeltaSchema.parse({
    schemaVersion: "boardagent.pending-action.v1",
    sequence: feedSequence.toString(10),
    deltaType: input.deltaType,
    objectType: input.objectType,
    objectId: input.objectId,
    objectVersion: input.objectVersion,
    entitlementGeneration,
    actionState: "pending",
    safeRefs: input.safeRefs,
    createdAt: occurredAt
  });
  const contentSha256 = canonicalSha256({
    noticeType: input.noticeType,
    objectType: input.objectType,
    objectId: input.objectId,
    objectVersion: input.objectVersion,
    recipientMemberId: input.recipientMemberId,
    safeRefs: input.safeRefs
  });
  await client.query(
    `insert into notices(
       id,organization_id,board_id,notice_type,object_type,object_id,object_version,
       recipient_member_id,content_sha256,feed_sequence,audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      noticeId,
      input.prepared.root.organization_id,
      input.prepared.root.board_id,
      input.noticeType,
      input.objectType,
      input.objectId,
      input.objectVersion,
      input.recipientMemberId,
      Buffer.from(contentSha256, "hex"),
      feedSequence.toString(10),
      input.auditEventId
    ]
  );
  const canonicalPayload = Buffer.from(canonicalJson(delta), "utf8");
  await client.query(
    `insert into pending_action_feed(
       id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
       action_type,object_type,object_id,object_version,visibility_sha256,
       canonical_payload,payload_sha256,notice_id,audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
    [
      feedId,
      input.prepared.root.organization_id,
      input.prepared.root.board_id,
      input.recipientMemberId,
      input.entitlementGeneration,
      feedSequence.toString(10),
      input.actionType,
      input.objectType,
      input.objectId,
      input.objectVersion,
      Buffer.from(
        canonicalSha256({ recipientMemberId: input.recipientMemberId, safeRefs: input.safeRefs }),
        "hex"
      ),
      canonicalPayload,
      Buffer.from(canonicalSha256(delta), "hex"),
      noticeId,
      input.auditEventId
    ]
  );
  return { noticeId, feedId, feedSequence };
}

async function actPublication(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "publication" || prepared.details.kind !== "publication") {
    throw new Error("minutes publication preparation mismatch");
  }
  const updated = await client.query(
    `update minutes set state='published_review',row_version=row_version+1
      where id=$1 and row_version=$2::bigint and state='unpublished_draft'
        and current_version_id=$3`,
    [prepared.root.minutes_id, prepared.root.row_version, prepared.root.version_id]
  );
  if (updated.rowCount !== 1) throw new Error("minutes changed during publication");

  const auditEvents: AuditAppendInput[] = [
    auditInput(
      prepared,
      consentRecordId,
      "minutes_published",
      "minutes",
      prepared.root.minutes_id,
      {
        minutesVersionId: prepared.root.version_id,
        minutesVersion: prepared.root.version,
        minutesSha256: currentMinutesSha256(prepared.root),
        transcriptVersionId: prepared.root.transcript_version_id,
        transcriptSha256: prepared.root.transcript_sha256?.toString("hex") ?? null,
        proposedSignerMemberIds: prepared.details.signers.map(({ member_id }) => member_id),
        proposedSignerManifestSha256: canonicalSha256(
          prepared.details.signers.map((signer) => ({
            memberId: signer.member_id,
            seatRole: signer.seat_role,
            entitlementGeneration: signer.entitlement_generation,
            memberSnapshotSha256: signer.member_snapshot_sha256
          }))
        )
      },
      newId(),
      BigInt(prepared.root.row_version) + 1n
    )
  ];
  for (const signer of prepared.details.signers) {
    const noticeAuditEventId = newId();
    await insertPendingNotice(client, {
      prepared,
      recipientMemberId: signer.member_id,
      entitlementGeneration: signer.entitlement_generation,
      noticeType: "minutes_review_requested",
      actionType: "minutes_review_requested",
      objectType: "minutes",
      objectId: prepared.root.minutes_id,
      objectVersion: Number(prepared.root.row_version) + 1,
      deltaType: "action_required",
      safeRefs: {
        minutesVersionId: prepared.root.version_id,
        minutesSha256: currentMinutesSha256(prepared.root)
      },
      auditEventId: noticeAuditEventId
    });
    auditEvents.push(
      auditInput(
        prepared,
        consentRecordId,
        "notice_delivered",
        "minutes",
        prepared.root.minutes_id,
        {
          meaning: "committed_recipient_feed_handoff",
          recipientMemberId: signer.member_id,
          noticeType: "minutes_review_requested",
          minutesVersionId: prepared.root.version_id,
          minutesSha256: currentMinutesSha256(prepared.root)
        },
        noticeAuditEventId,
        BigInt(prepared.root.row_version) + 1n
      )
    );
  }
  return {
    value: {
      kind: "publication",
      minutesId: prepared.root.minutes_id,
      minutesVersionId: prepared.root.version_id,
      minutesSha256: currentMinutesSha256(prepared.root),
      reviewRecipientMemberIds: prepared.details.signers.map(({ member_id }) => member_id)
    },
    auditEvents
  };
}

async function actSignaturePackageIssue(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "signature_package_issue" ||
    prepared.details.kind !== "signature_package_issue"
  ) {
    throw new Error("signature package preparation mismatch");
  }
  const action = prepared.action;
  const details = prepared.details;
  const signaturePackageId = newId();
  await client.query(
    `insert into minutes_signature_packages(
       id,organization_id,board_id,minutes_id,minutes_version_id,version,minutes_sha256,
       transcript_manifest_sha256,action_manifest_sha256,review_manifest_sha256,
       signer_manifest_sha256,package_sha256,state,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'current',$13)`,
    [
      signaturePackageId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.minutes_id,
      prepared.root.version_id,
      details.packageVersion,
      prepared.root.canonical_sha256,
      Buffer.from(details.transcriptManifestSha256, "hex"),
      Buffer.from(details.actionManifestSha256, "hex"),
      Buffer.from(details.reviewManifestSha256, "hex"),
      Buffer.from(details.signerManifestSha256, "hex"),
      Buffer.from(details.proposedPackageSha256, "hex"),
      consentRecordId
    ]
  );
  for (const [index, signer] of details.signers.entries()) {
    const requirement = action.requirements[index]!;
    await client.query(
      `insert into minutes_signature_requirements(
         package_id,member_id,seat_role,requirement,member_snapshot_sha256
       ) values ($1,$2,$3,$4,$5)`,
      [
        signaturePackageId,
        signer.member_id,
        signer.seat_role,
        requirement.requirement,
        Buffer.from(signer.member_snapshot_sha256, "hex")
      ]
    );
  }

  const auditEvents: AuditAppendInput[] = [];
  const packageAuditEventId = newId();
  auditEvents.push(
    auditInput(
      prepared,
      consentRecordId,
      "minutes_signature_package_issued",
      "minutes_signature_package",
      signaturePackageId,
      {
        minutesId: prepared.root.minutes_id,
        minutesVersionId: prepared.root.version_id,
        minutesSha256: currentMinutesSha256(prepared.root),
        packageVersion: details.packageVersion,
        packageSha256: details.proposedPackageSha256,
        transcriptManifestSha256: details.transcriptManifestSha256,
        actionManifestSha256: details.actionManifestSha256,
        reviewManifestSha256: details.reviewManifestSha256,
        signerManifestSha256: details.signerManifestSha256
      },
      packageAuditEventId,
      BigInt(prepared.root.row_version) + 1n
    )
  );

  const oldSignatures = await client.query<{
    id: string;
    package_id: string;
    signer_member_id: string;
  }>(
    `select signature.id,signature.package_id,signature.signer_member_id
       from minutes_signatures as signature
       join minutes_signature_packages as package on package.id=signature.package_id
       left join minutes_signature_supersessions as supersession
         on supersession.old_signature_id=signature.id
      where package.minutes_id=$1 and package.state='superseded' and supersession.id is null
      order by signature.id`,
    [prepared.root.minutes_id]
  );
  const requestedSignerIds = new Set(details.signers.map(({ member_id }) => member_id));
  for (const signature of oldSignatures.rows) {
    const auditEventId = newId();
    const supersessionId = newId();
    await client.query(
      `insert into minutes_signature_supersessions(
         id,old_signature_id,old_package_id,new_minutes_version_id,new_package_id,reason,
         audit_event_id
       ) values ($1,$2,$3,$4,$5,'minutes package changed',$6)`,
      [
        supersessionId,
        signature.id,
        signature.package_id,
        prepared.root.version_id,
        signaturePackageId,
        auditEventId
      ]
    );
    auditEvents.push(
      auditInput(
        prepared,
        consentRecordId,
        "minutes_signature_superseded",
        "minutes_signature",
        signature.id,
        {
          supersessionId,
          oldPackageId: signature.package_id,
          newPackageId: signaturePackageId,
          newMinutesVersionId: prepared.root.version_id
        },
        auditEventId
      )
    );
  }
  await client.query(
    `update minutes_resign_requirements
        set state='resolved',resolution='package_superseded',resolved_at=transaction_timestamp()
      where minutes_id=$1 and state='pending'`,
    [prepared.root.minutes_id]
  );
  const resigningMemberIds = new Set<string>();
  if (details.priorPackageId) {
    const historicallyAffected = await client.query<{ signer_member_id: string }>(
      `select distinct signer_member_id
         from (
           select signature.signer_member_id
             from minutes_signatures as signature
             join minutes_signature_packages as package on package.id=signature.package_id
            where package.minutes_id=$1
           union all
           select requirement.signer_member_id
             from minutes_resign_requirements as requirement
            where requirement.minutes_id=$1
         ) as affected
        order by signer_member_id`,
      [prepared.root.minutes_id]
    );
    for (const affected of historicallyAffected.rows) {
      if (!requestedSignerIds.has(affected.signer_member_id)) continue;
      resigningMemberIds.add(affected.signer_member_id);
      const resignId = newId();
      const resignAuditEventId = newId();
      await client.query(
        `insert into minutes_resign_requirements(
           id,minutes_id,signer_member_id,from_package_id,to_package_id
         ) values ($1,$2,$3,$4,$5)`,
        [
          resignId,
          prepared.root.minutes_id,
          affected.signer_member_id,
          details.priorPackageId,
          signaturePackageId
        ]
      );
      auditEvents.push(
        auditInput(
          prepared,
          consentRecordId,
          "minutes_resign_required",
          "minutes_resign_requirement",
          resignId,
          {
            signerMemberId: affected.signer_member_id,
            fromPackageId: details.priorPackageId,
            toPackageId: signaturePackageId
          },
          resignAuditEventId
        )
      );
    }
  }

  const updated = await client.query(
    `update minutes
        set state='signature_ready',current_signature_package_id=$1,row_version=row_version+1
      where id=$2 and row_version=$3::bigint and state='published_review'`,
    [signaturePackageId, prepared.root.minutes_id, prepared.root.row_version]
  );
  if (updated.rowCount !== 1) throw new Error("minutes changed during signature package issue");
  await client.query(
    `update pending_action_feed
        set state='resolved',resolved_at=transaction_timestamp()
      where board_id=$1 and object_type='minutes' and object_id=$2
        and action_type='minutes_review_requested' and state='pending'`,
    [prepared.root.board_id, prepared.root.minutes_id]
  );

  for (const signer of details.signers) {
    const noticeAuditEventId = newId();
    const resign = resigningMemberIds.has(signer.member_id);
    await insertPendingNotice(client, {
      prepared,
      recipientMemberId: signer.member_id,
      entitlementGeneration: signer.entitlement_generation,
      noticeType: resign ? "minutes_resign_required" : "minutes_signature_required",
      actionType: resign ? "minutes_resign_required" : "minutes_signature_required",
      objectType: "minutes",
      objectId: prepared.root.minutes_id,
      objectVersion: Number(prepared.root.row_version) + 1,
      deltaType: resign ? "minutes_resign_required" : "action_required",
      safeRefs: {
        signaturePackageId,
        packageSha256: details.proposedPackageSha256
      },
      auditEventId: noticeAuditEventId
    });
    auditEvents.push(
      auditInput(
        prepared,
        consentRecordId,
        "notice_delivered",
        "minutes_signature_package",
        signaturePackageId,
        {
          meaning: "committed_recipient_feed_handoff",
          recipientMemberId: signer.member_id,
          noticeType: resign ? "minutes_resign_required" : "minutes_signature_required"
        },
        noticeAuditEventId
      )
    );
  }
  return {
    value: {
      kind: "signature_package_issue",
      minutesId: prepared.root.minutes_id,
      signaturePackageId,
      packageSha256: details.proposedPackageSha256,
      signerMemberIds: details.signers.map(({ member_id }) => member_id)
    },
    auditEvents
  };
}

async function actSignature(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "signature" || prepared.details.kind !== "signature") {
    throw new Error("minutes signature preparation mismatch");
  }
  if (!prepared.root.signature_package_id || !prepared.root.signature_package_sha256) {
    throw new Error("signature package disappeared after preparation");
  }
  const consent = await client.query<{
    access_token_record_id: string;
    client_id: string;
    exact_origin: string;
    staged_at: string;
  }>(
    `select access_token_record_id,client_id,exact_origin,
            to_char(staged_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as staged_at
       from consent_records where id=$1`,
    [consentRecordId]
  );
  const consentRow = consent.rows[0];
  if (!consentRow || consent.rows.length !== 1) throw new Error("signature consent disappeared");
  const signatureId = newId();
  const reservationSha256 =
    prepared.action.reservation === null ? null : sha256Hex(prepared.action.reservation);
  const signedAt = await transactionTimestamp(client);
  const signatureRecordSha256 = canonicalSha256({
    schemaVersion: "boardagent.minutes-signature-record.v1",
    signatureId,
    minutesId: prepared.root.minutes_id,
    minutesVersionId: prepared.root.version_id,
    packageId: prepared.root.signature_package_id,
    packageSha256: prepared.root.signature_package_sha256.toString("hex"),
    signerMemberId: prepared.context.memberId,
    signerSeatRole: prepared.root.actor_seat_role,
    reservationSha256,
    consentRecordId,
    accessTokenRecordId: consentRow.access_token_record_id,
    clientId: consentRow.client_id,
    exactOrigin: consentRow.exact_origin,
    stagedAt: consentRow.staged_at,
    signedAt
  });
  await client.query(
    `insert into minutes_signatures(
       id,organization_id,board_id,package_id,minutes_version_id,package_sha256,
       signer_member_id,signer_seat_role,reservation_sha256,consent_record_id,
       access_token_record_id,client_id,exact_origin,staged_at,signed_at,
       signature_record_sha256
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      signatureId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.signature_package_id,
      prepared.root.version_id,
      prepared.root.signature_package_sha256,
      prepared.context.memberId,
      prepared.root.actor_seat_role,
      reservationSha256 === null ? null : Buffer.from(reservationSha256, "hex"),
      consentRecordId,
      consentRow.access_token_record_id,
      consentRow.client_id,
      consentRow.exact_origin,
      consentRow.staged_at,
      signedAt,
      Buffer.from(signatureRecordSha256, "hex")
    ]
  );
  await client.query(
    `update minutes_resign_requirements
        set state='resolved',resolution='signed_current_package',
            resolved_signature_id=$1,resolved_at=transaction_timestamp()
      where minutes_id=$2 and signer_member_id=$3 and to_package_id=$4 and state='pending'`,
    [
      signatureId,
      prepared.root.minutes_id,
      prepared.context.memberId,
      prepared.root.signature_package_id
    ]
  );
  await client.query(
    `update pending_action_feed
        set state='resolved',resolved_at=transaction_timestamp()
      where board_id=$1 and member_id=$2 and object_type='minutes' and object_id=$3
        and state='pending'
        and action_type in ('minutes_signature_required','minutes_resign_required')`,
    [prepared.root.board_id, prepared.context.memberId, prepared.root.minutes_id]
  );
  const updated = await client.query(
    `update minutes set row_version=row_version+1
      where id=$1 and row_version=$2::bigint and state='signature_ready'`,
    [prepared.root.minutes_id, prepared.root.row_version]
  );
  if (updated.rowCount !== 1) throw new Error("minutes changed during signature");
  return {
    value: {
      kind: "signature",
      minutesId: prepared.root.minutes_id,
      signatureId,
      signatureRecordSha256
    },
    auditEvents: [
      auditInput(
        prepared,
        consentRecordId,
        "minutes_signed",
        "minutes_signature",
        signatureId,
        {
          minutesId: prepared.root.minutes_id,
          minutesVersionId: prepared.root.version_id,
          signaturePackageId: prepared.root.signature_package_id,
          packageSha256: prepared.root.signature_package_sha256.toString("hex"),
          signerMemberId: prepared.context.memberId,
          signerSeatRole: prepared.root.actor_seat_role,
          reservationSha256,
          signatureRecordSha256
        },
        newId(),
        BigInt(prepared.root.row_version) + 1n
      )
    ]
  };
}

async function actFinalization(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "finalization" || prepared.details.kind !== "finalization") {
    throw new Error("minutes finalization preparation mismatch");
  }
  if (!prepared.root.signature_package_id || !prepared.root.signature_package_sha256) {
    throw new Error("signature package disappeared after preparation");
  }
  const activationAuditEventId = newId();
  const auditEvents: AuditAppendInput[] = [];
  for (const task of prepared.details.tasks) {
    const updatedTask = await client.query(
      `update tasks set state='open',row_version=row_version+1
        where id=$1 and row_version=$2::bigint and state='draft'
          and source_minutes_id=$3 and source_minutes_version_id=$4`,
      [task.id, task.row_version, prepared.root.minutes_id, prepared.root.version_id]
    );
    if (updatedTask.rowCount !== 1) throw new Error("draft activation task changed");
    const membership = await client.query<{ entitlement_generation: string }>(
      `select entitlement_generation::text from board_memberships
        where board_id=$1 and member_id=$2 and state='active'
          and not boardagent_member_record_recused('minutes',$3,member_id)
          and active_from<=transaction_timestamp()
          and (active_until is null or active_until>transaction_timestamp())`,
      [prepared.root.board_id, task.owner_member_id, prepared.root.minutes_id]
    );
    const generation = membership.rows[0]?.entitlement_generation;
    if (!generation) throw new Error("task owner lost authority during finalization");
    await insertPendingNotice(client, {
      prepared,
      recipientMemberId: task.owner_member_id,
      entitlementGeneration: generation,
      noticeType: "task_assigned",
      actionType: "task_assigned",
      objectType: "task",
      objectId: task.id,
      objectVersion: Number(task.row_version) + 1,
      deltaType: "task_assigned",
      safeRefs: {
        sourceMinutesId: prepared.root.minutes_id,
        sourceMinutesVersionId: prepared.root.version_id
      },
      auditEventId: activationAuditEventId
    });
  }
  const updated = await client.query<{ next_row_version: string | null }>(
    `select next_row_version::text
       from boardagent_apply_minutes_terminal_transition($1,$2::bigint,'finalized',$3)`,
    [prepared.root.minutes_id, prepared.root.row_version, consentRecordId]
  );
  if (updated.rows[0]?.next_row_version !== (BigInt(prepared.root.row_version) + 1n).toString()) {
    throw new Error("minutes changed during guarded finalization");
  }
  auditEvents.push(
    auditInput(
      prepared,
      consentRecordId,
      "minutes_action_items_activated",
      "minutes",
      prepared.root.minutes_id,
      {
        minutesVersionId: prepared.root.version_id,
        signaturePackageId: prepared.root.signature_package_id,
        packageSha256: prepared.root.signature_package_sha256.toString("hex"),
        activationManifestSha256: prepared.details.activationManifestSha256,
        activatedTaskIds: prepared.details.tasks.map(({ id }) => id)
      },
      activationAuditEventId,
      BigInt(prepared.root.row_version) + 1n
    ),
    auditInput(
      prepared,
      consentRecordId,
      "minutes_finalized",
      "minutes",
      prepared.root.minutes_id,
      {
        minutesVersionId: prepared.root.version_id,
        minutesSha256: currentMinutesSha256(prepared.root),
        signaturePackageId: prepared.root.signature_package_id,
        packageSha256: prepared.root.signature_package_sha256.toString("hex"),
        activationManifestSha256: prepared.details.activationManifestSha256
      },
      newId(),
      BigInt(prepared.root.row_version) + 1n
    )
  );
  return {
    value: {
      kind: "finalization",
      minutesId: prepared.root.minutes_id,
      activationManifestSha256: prepared.details.activationManifestSha256,
      activatedTaskIds: prepared.details.tasks.map(({ id }) => id)
    },
    auditEvents
  };
}

async function actFinalizedCorrection(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (
    prepared.action.kind !== "finalized_correction" ||
    prepared.details.kind !== "finalized_correction"
  ) {
    throw new Error("finalized correction preparation mismatch");
  }
  const replacementMinutesId = prepared.action.replacementMinutesId;
  const replacementVersionId = newId();
  const correctionCycleId = newId();
  const packageBaseSha256 = canonicalSha256({
    schemaVersion: "boardagent.minutes-package-base.v1",
    minutesId: replacementMinutesId,
    version: 1,
    canonicalSha256: prepared.details.replacementSha256,
    transcriptVersionId: prepared.root.transcript_version_id,
    transcriptSha256: prepared.root.transcript_sha256?.toString("hex") ?? null
  });
  await client.query(
    `insert into minutes(
       id,organization_id,board_id,meeting_id,state,current_version_id,
       correction_of_minutes_id,created_by
     ) values ($1,$2,$3,$4,'published_review',$5,$6,$7)`,
    [
      replacementMinutesId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.meeting_id,
      replacementVersionId,
      prepared.root.minutes_id,
      prepared.context.memberId
    ]
  );
  await client.query(
    `insert into minutes_versions(
       id,organization_id,board_id,minutes_id,version,canonical_schema,canonical_text,
       canonical_sha256,package_base_sha256,transcript_version_id,transcript_sha256,created_by
     ) values ($1,$2,$3,$4,1,'boardagent.minutes.v1',$5,$6,$7,$8,$9,$10)`,
    [
      replacementVersionId,
      prepared.root.organization_id,
      prepared.root.board_id,
      replacementMinutesId,
      prepared.action.canonicalText,
      Buffer.from(prepared.details.replacementSha256, "hex"),
      Buffer.from(packageBaseSha256, "hex"),
      prepared.root.transcript_version_id,
      prepared.root.transcript_sha256,
      prepared.context.memberId
    ]
  );
  await client.query(
    `insert into minutes_correction_cycles(
       id,organization_id,board_id,original_minutes_id,replacement_minutes_id,reason,
       secretary_member_id,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      correctionCycleId,
      prepared.root.organization_id,
      prepared.root.board_id,
      prepared.root.minutes_id,
      replacementMinutesId,
      prepared.action.reason,
      prepared.context.memberId,
      consentRecordId
    ]
  );
  const meeting = await client.query(
    `update meetings set current_minutes_id=$1,row_version=row_version+1
      where id=$2 and current_minutes_id=$3`,
    [replacementMinutesId, prepared.root.meeting_id, prepared.root.minutes_id]
  );
  if (meeting.rowCount !== 1) throw new Error("meeting minutes lineage changed");
  return {
    value: {
      kind: "finalized_correction",
      originalMinutesId: prepared.root.minutes_id,
      replacementMinutesId,
      replacementVersionId,
      replacementSha256: prepared.details.replacementSha256
    },
    auditEvents: [
      auditInput(
        prepared,
        consentRecordId,
        "minutes_correction_cycle_created",
        "minutes_correction_cycle",
        correctionCycleId,
        {
          originalMinutesId: prepared.root.minutes_id,
          originalVersionId: prepared.root.version_id,
          originalSha256: currentMinutesSha256(prepared.root),
          replacementMinutesId,
          replacementVersionId,
          replacementSha256: prepared.details.replacementSha256,
          reason: prepared.action.reason
        }
      )
    ]
  };
}

async function actCancellation(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  if (prepared.action.kind !== "cancellation" || prepared.details.kind !== "cancellation") {
    throw new Error("minutes cancellation preparation mismatch");
  }
  const cancellationAction = prepared.action;
  const consent = await client.query<{ stage_id: string }>(
    "select stage_id from consent_records where id=$1",
    [consentRecordId]
  );
  const currentStageId = consent.rows[0]?.stage_id;
  if (!currentStageId) throw new Error("minutes cancellation consent disappeared");
  await client.query(
    `update action_stages set state='replaced'
      where target_type='minutes' and target_id=$1 and state='active' and id<>$2`,
    [prepared.root.minutes_id, currentStageId]
  );
  const terminal = await client.query<{
    next_row_version: string | null;
    superseded_task_ids: string[];
  }>(
    `select next_row_version::text,superseded_task_ids
       from boardagent_apply_minutes_terminal_transition($1,$2::bigint,'cancelled',$3)`,
    [prepared.root.minutes_id, prepared.root.row_version, consentRecordId]
  );
  const terminalRow = terminal.rows[0];
  if (terminalRow?.next_row_version !== (BigInt(prepared.root.row_version) + 1n).toString()) {
    throw new Error("minutes changed during guarded cancellation");
  }
  const supersededIds = [...(terminalRow.superseded_task_ids ?? [])].toSorted();
  if (
    canonicalJson(supersededIds) !== canonicalJson([...prepared.details.draftTaskIds].toSorted())
  ) {
    throw new Error("draft minutes actions changed during cancellation");
  }
  await client.query(
    `update pending_action_feed
        set state='resolved',resolved_at=transaction_timestamp()
      where board_id=$1 and object_type='minutes' and object_id=$2 and state='pending'`,
    [prepared.root.board_id, prepared.root.minutes_id]
  );
  const auditEvents: AuditAppendInput[] = supersededIds.map((taskId) =>
    auditInput(
      prepared,
      consentRecordId,
      "minutes_action_item_draft_superseded",
      "task",
      taskId,
      {
        minutesId: prepared.root.minutes_id,
        staleMinutesVersionId: prepared.root.version_id,
        replacementMinutesVersionId: null,
        reason: cancellationAction.reason,
        terminalDisposition: "minutes_cancelled"
      },
      newId()
    )
  );
  auditEvents.push(
    auditInput(
      prepared,
      consentRecordId,
      "minutes_cancelled",
      "minutes",
      prepared.root.minutes_id,
      {
        minutesVersionId: prepared.root.version_id,
        minutesSha256: currentMinutesSha256(prepared.root),
        signaturePackageId: prepared.root.signature_package_id,
        supersededDraftTaskIds: supersededIds,
        reason: cancellationAction.reason
      },
      newId(),
      BigInt(prepared.root.row_version) + 1n
    )
  );
  return {
    value: {
      kind: "cancellation",
      minutesId: prepared.root.minutes_id,
      supersededDraftTaskIds: supersededIds
    },
    auditEvents
  };
}

async function performPreparedAction(
  client: PoolClient,
  prepared: PreparedAction,
  consentRecordId: string
): Promise<{
  readonly value: MinutesLifecycleResult;
  readonly auditEvents: readonly AuditAppendInput[];
}> {
  await assertConsentBinding(client, prepared, consentRecordId);
  switch (prepared.action.kind) {
    case "publication":
      return actPublication(client, prepared, consentRecordId);
    case "review_disposition":
      return actReviewDisposition(client, prepared, consentRecordId);
    case "package_correction":
      return actPackageCorrection(client, prepared, consentRecordId);
    case "action_declaration":
      return actActionDeclaration(client, prepared, consentRecordId);
    case "signature_package_issue":
      return actSignaturePackageIssue(client, prepared, consentRecordId);
    case "signature":
      return actSignature(client, prepared, consentRecordId);
    case "finalization":
      return actFinalization(client, prepared, consentRecordId);
    case "finalized_correction":
      return actFinalizedCorrection(client, prepared, consentRecordId);
    case "cancellation":
      return actCancellation(client, prepared, consentRecordId);
  }
}

export async function stageMinutesLifecycleActionInTransaction(
  client: PoolClient,
  input: MinutesLifecycleStageInput
): Promise<StagedMinutesLifecycleAction> {
  const prepared = await prepareAction(client, input.action);
  const descriptor = operation(prepared.action);
  const staged = await stageActionInTransaction(
    client,
    {
      ...input.stage,
      boardId: prepared.root.board_id,
      actingForMemberId: null,
      actionCode: descriptor.actionCode,
      targetType: "minutes",
      targetId: prepared.root.minutes_id,
      canonicalSchema: descriptor.canonicalSchema,
      canonicalPayload: prepared.payload,
      packageSha256: prepared.packageSha256,
      originalName: descriptor.actionCode
    },
    async () => {
      // prepareAction already acquired and retained the aggregate/dependent locks in this
      // transaction before the stage/idempotency boundary.
    }
  );
  return {
    ...staged,
    actionCode: descriptor.actionCode,
    boardId: prepared.root.board_id,
    targetId: prepared.root.minutes_id
  };
}

/** Read-only preparation for protocol presentation; the caller persists no stage here. */
export async function prepareMinutesLifecycleActionInTransaction(
  client: PoolClient,
  action: MinutesLifecycleAction
): Promise<PreparedMinutesLifecycleAction> {
  const prepared = await prepareAction(client, action);
  const descriptor = operation(prepared.action);
  return {
    actionCode: descriptor.actionCode,
    boardId: prepared.root.board_id,
    targetId: prepared.root.minutes_id,
    canonicalSchema: descriptor.canonicalSchema,
    canonicalPayload: prepared.payload,
    payloadSha256: prepared.payloadSha256,
    packageSha256: prepared.packageSha256
  };
}

export async function confirmMinutesLifecycleActionInTransaction(
  client: PoolClient,
  input: MinutesLifecycleConfirmationInput
): Promise<StagedActionResolution<MinutesLifecycleResult>> {
  let prepared: PreparedAction | undefined;
  return confirmStagedActionInTransaction(
    client,
    input.confirmation,
    async (requestClient) => {
      prepared = await prepareAction(requestClient, input.action);
      return {
        payloadSha256: prepared.payloadSha256,
        packageSha256: prepared.packageSha256
      };
    },
    async (requestClient, consentRecordId) => {
      if (!prepared) throw new Error("minutes lifecycle preparation is unavailable");
      return performPreparedAction(requestClient, prepared, consentRecordId);
    }
  );
}
