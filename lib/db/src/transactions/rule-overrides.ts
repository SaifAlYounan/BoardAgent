import type { PoolClient } from "pg";
import { z } from "zod";

import type { AuditEvent } from "@boardagent/audit";
import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalJson,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex
} from "@boardagent/contracts";
import {
  ruleOverrideConsentHash,
  ruleOverrideEvidenceHash,
  type RuleSelectionCitation
} from "@boardagent/domain";

import { appendAuditEventsInTransaction } from "./audit.js";
import { RuleSelectionCitationSchema, loadRuleSelectionEvidence } from "./rule-selection.js";
import { readRequestContext } from "./request-context.js";

export class RuleOverrideTransactionError extends Error {
  public constructor(
    public readonly code:
      | "rule_override_unavailable"
      | "rule_override_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "RuleOverrideTransactionError";
  }
}

export interface RecordRuleOverrideInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly evaluationId: string;
  readonly evaluationResultSha256: string;
  readonly wizardDraftId: string;
  readonly finalVoteId: string;
  readonly selectedRuleId: string;
  readonly selectedRuleSha256: string;
  readonly reason: string;
  readonly citations: readonly RuleSelectionCitation[];
  readonly packageSha256: string;
  readonly consentRecordId: string;
  readonly ruleOverrideId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
  /** A guided create-vote final confirmation may bind the whole package directly. */
  readonly consentPayloadMode?: "override" | "package";
}

export type RecordRuleOverrideResult =
  | {
      readonly replayed: true;
      readonly ruleOverrideId: string;
      readonly canonicalSha256: string;
    }
  | {
      readonly replayed: false;
      readonly ruleOverrideId: string;
      readonly evaluationId: string;
      readonly selectedRuleId: string;
      readonly recommendedRuleId: string | null;
      readonly canonicalSha256: string;
      readonly auditEvents: readonly AuditEvent[];
    };

interface BoardRootRow {
  readonly organization_id: string;
  readonly state: string;
  readonly current_governance_profile_id: string | null;
  readonly current_ruleset_id: string | null;
  readonly actor_ready: boolean;
}

interface VoteDraftRow {
  readonly approval_rule_id: string;
  readonly governance_profile_id: string;
  readonly ruleset_id: string;
  readonly state: string;
}

interface WizardDraftRow {
  readonly creator_member_id: string;
  readonly draft_type: string;
  readonly state: string;
  readonly ruleset_id: string | null;
  readonly package_sha256: Buffer | null;
  readonly unexpired: boolean;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

function validateIdempotencyKey(value: string): string {
  if (value.length < 16 || value.length > 256) {
    throw new RangeError("idempotency key must contain 16 through 256 characters");
  }
  return value;
}

async function lockBoardRoot(
  client: PoolClient,
  boardId: string
): Promise<BoardRootRow | undefined> {
  const query = `select organization_id,state,current_governance_profile_id,
                        current_ruleset_id,actor_ready
                   from boardagent_lock_board_root($1)`;
  await client.query<BoardRootRow>(query, [boardId]);
  const refreshed = await client.query<BoardRootRow>(query, [boardId]);
  return refreshed.rows.length === 1 ? refreshed.rows[0] : undefined;
}

async function readIdempotency(
  client: PoolClient,
  actorMemberId: string,
  clientId: string,
  key: string
): Promise<IdempotencyRow | undefined> {
  const result = await client.query<IdempotencyRow>(
    `select request_sha256,state,safe_response_type,safe_response_id,safe_response_sha256
       from idempotency_records
      where actor_member_id=$1 and client_id=$2
        and operation='record_rule_override' and idempotency_key=$3
      for update`,
    [actorMemberId, clientId, key]
  );
  return result.rows[0];
}

function replayResult(
  row: IdempotencyRow | undefined,
  requestSha256: string
): RecordRuleOverrideResult | undefined {
  if (!row) return undefined;
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new RuleOverrideTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for another rule override"
    );
  }
  if (
    row.state === "succeeded" &&
    row.safe_response_type === "rule_override" &&
    row.safe_response_id &&
    row.safe_response_sha256
  ) {
    return {
      replayed: true,
      ruleOverrideId: row.safe_response_id,
      canonicalSha256: row.safe_response_sha256.toString("hex")
    };
  }
  throw new RuleOverrideTransactionError(
    "idempotency_in_progress",
    "identical rule override is already in progress"
  );
}

async function consentValid(
  client: PoolClient,
  input: {
    readonly consentRecordId: string;
    readonly finalVoteId: string;
    readonly payloadSha256: string;
    readonly packageSha256: string;
  }
): Promise<boolean> {
  const result = await client.query<{ valid: boolean }>(
    `select exists (
       select 1
         from consent_records as consent
         join action_stages as stage on stage.id=consent.stage_id
         join input_required_attempts as attempt
           on attempt.id=consent.input_required_attempt_id
        where consent.id=$1
          and consent.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
          and consent.client_id=boardagent_context_uuid('boardagent.client_id')
          and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
          and consent.action_code='create_vote'
          and consent.target_type='vote'
          and consent.target_id=$2
          and consent.payload_sha256=$3
          and consent.package_sha256=$4
          and stage.organization_id=consent.organization_id
          and stage.board_id=consent.board_id
          and stage.actor_member_id=consent.actor_member_id
          and stage.client_id=consent.client_id
          and stage.token_jti=consent.token_jti
          and stage.action_code=consent.action_code
          and stage.target_type=consent.target_type
          and stage.target_id=consent.target_id
          and stage.payload_sha256=consent.payload_sha256
          and stage.package_sha256=consent.package_sha256
          and stage.state='confirmed' and stage.confirmed_at is not null
          and attempt.organization_id=consent.organization_id
          and attempt.stage_id=stage.id
          and attempt.original_method='tools/call'
          and attempt.original_name='create_vote'
          and attempt.response_action='accept'
          and attempt.state='confirmed'
     ) as valid`,
    [
      input.consentRecordId,
      input.finalVoteId,
      Buffer.from(input.payloadSha256, "hex"),
      Buffer.from(input.packageSha256, "hex")
    ]
  );
  return result.rows[0]?.valid === true;
}

export async function recordRuleOverrideInTransaction(
  client: PoolClient,
  input: RecordRuleOverrideInput
): Promise<RecordRuleOverrideResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const evaluationId = UuidV7Schema.parse(input.evaluationId);
  const evaluationResultSha256 = Sha256HexSchema.parse(input.evaluationResultSha256);
  const wizardDraftId = UuidV7Schema.parse(input.wizardDraftId);
  const finalVoteId = UuidV7Schema.parse(input.finalVoteId);
  const selectedRuleId = UuidV7Schema.parse(input.selectedRuleId);
  const selectedRuleSha256 = Sha256HexSchema.parse(input.selectedRuleSha256);
  const reason = canonicalText(input.reason);
  if (reason.trim().length < 1 || reason.length > 65_536) {
    throw new RangeError("rule-override reason must contain 1 through 65536 characters");
  }
  const citations = z.array(RuleSelectionCitationSchema).min(1).parse(input.citations);
  const packageSha256 = Sha256HexSchema.parse(input.packageSha256);
  const consentRecordId = UuidV7Schema.parse(input.consentRecordId);
  const ruleOverrideId = UuidV7Schema.parse(input.ruleOverrideId);
  const idempotencyRecordId = UuidV7Schema.parse(input.idempotencyRecordId);
  const auditEventId = UuidV7Schema.parse(input.auditEventId);
  const generatedIds = [ruleOverrideId, idempotencyRecordId, auditEventId];
  if (new Set(generatedIds).size !== generatedIds.length) {
    throw new TypeError("rule-override generated IDs must be globally unique");
  }
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const consentPayloadMode = input.consentPayloadMode ?? "override";
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new RuleOverrideTransactionError(
      "rule_override_unavailable",
      "rule override is unavailable"
    );
  }
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.rule-override-request.v1",
    organizationId,
    boardId,
    evaluationId,
    evaluationResultSha256,
    wizardDraftId,
    finalVoteId,
    selectedRuleId,
    selectedRuleSha256,
    reason,
    citations,
    packageSha256,
    consentRecordId,
    consentPayloadMode
  });
  const board = await lockBoardRoot(client, boardId);
  if (
    !board ||
    board.organization_id !== organizationId ||
    board.state !== "active" ||
    !board.current_governance_profile_id ||
    !board.current_ruleset_id ||
    !board.actor_ready
  ) {
    throw new RuleOverrideTransactionError(
      "rule_override_unavailable",
      "rule override is unavailable"
    );
  }
  const replay = replayResult(
    await readIdempotency(client, context.memberId, context.clientId, idempotencyKey),
    requestSha256
  );
  if (replay) return replay;

  const voteResult = await client.query<VoteDraftRow>(
    `select approval_rule_id,governance_profile_id,ruleset_id,state
       from votes
      where id=$1 and organization_id=$2 and board_id=$3
      for update`,
    [finalVoteId, organizationId, boardId]
  );
  const vote = voteResult.rows[0];
  if (
    !vote ||
    voteResult.rows.length !== 1 ||
    vote.state !== "draft" ||
    vote.governance_profile_id !== board.current_governance_profile_id ||
    vote.ruleset_id !== board.current_ruleset_id
  ) {
    throw new RuleOverrideTransactionError(
      "rule_override_unavailable",
      "override target vote is unavailable"
    );
  }
  const wizardResult = await client.query<WizardDraftRow>(
    `select creator_member_id,draft_type,state,ruleset_id,package_sha256,
            unexpired
       from boardagent_lock_wizard_draft($1,$2)`,
    [wizardDraftId, boardId]
  );
  const wizard = wizardResult.rows[0];
  if (
    !wizard ||
    wizardResult.rows.length !== 1 ||
    wizard.creator_member_id !== context.memberId ||
    wizard.draft_type !== "vote" ||
    wizard.state !== "ready_to_confirm" ||
    wizard.ruleset_id !== vote.ruleset_id ||
    !wizard.package_sha256 ||
    !safeHashEqual(wizard.package_sha256.toString("hex"), packageSha256) ||
    !wizard.unexpired
  ) {
    throw new RuleOverrideTransactionError(
      "rule_override_unavailable",
      "override wizard package is unavailable"
    );
  }
  const selection = await loadRuleSelectionEvidence(client, {
    boardId,
    profileId: vote.governance_profile_id,
    rulesetId: vote.ruleset_id,
    approvalRuleId: vote.approval_rule_id,
    evaluationId,
    selectedRuleId
  });
  const actualEvaluationResultSha256 = selection.row.evaluation_result_sha256.toString("hex");
  const actualSelectedRuleSha256 = selection.row.selected_rule_sha256.toString("hex");
  if (
    !safeHashEqual(actualEvaluationResultSha256, evaluationResultSha256) ||
    !safeHashEqual(actualSelectedRuleSha256, selectedRuleSha256) ||
    canonicalJson(selection.citations) !== canonicalJson(citations)
  ) {
    throw new RuleOverrideTransactionError(
      "rule_override_invalid",
      "override does not bind the exact evaluation, rule and citations"
    );
  }
  if (
    selection.resultDetails.status !== "matched" ||
    selection.row.recommended_rule_id === null ||
    selection.template.overridePolicy !== "reasoned_within_bounds"
  ) {
    throw new RuleOverrideTransactionError(
      "rule_override_invalid",
      "failed or nonpermitted matter evaluation cannot be overridden"
    );
  }
  if (selection.row.recommended_rule_id === selectedRuleId) {
    throw new RuleOverrideTransactionError(
      "rule_override_invalid",
      "the deterministic recommendation does not require an override"
    );
  }
  const payloadSha256 = ruleOverrideConsentHash({
    evaluationId,
    evaluationResultSha256,
    wizardDraftId,
    finalVoteId,
    recommendedRuleId: selection.row.recommended_rule_id,
    selectedRuleId,
    selectedRuleSha256,
    reason,
    citations,
    packageSha256
  });
  const consentPayloadSha256 = consentPayloadMode === "package" ? packageSha256 : payloadSha256;
  if (
    !(await consentValid(client, {
      consentRecordId,
      finalVoteId,
      payloadSha256: consentPayloadSha256,
      packageSha256
    }))
  ) {
    throw new RuleOverrideTransactionError(
      "rule_override_unavailable",
      "confirmed exact rule override is unavailable"
    );
  }
  const canonicalOverrideSha256 = ruleOverrideEvidenceHash({
    evaluationId,
    evaluationResultSha256,
    wizardDraftId,
    finalVoteId,
    recommendedRuleId: selection.row.recommended_rule_id,
    selectedRuleId,
    selectedRuleSha256,
    reason,
    citations,
    consentRecordId,
    auditEventId
  });

  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'record_rule_override',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      idempotencyRecordId,
      organizationId,
      context.memberId,
      context.clientId,
      idempotencyKey,
      Buffer.from(requestSha256, "hex")
    ]
  );
  if (inserted.rowCount !== 1) {
    const raced = replayResult(
      await readIdempotency(client, context.memberId, context.clientId, idempotencyKey),
      requestSha256
    );
    if (raced) return raced;
  }
  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      consentRecordId,
      event: {
        eventId: auditEventId,
        eventType: "rule_overridden",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "rule_override",
        entityId: ruleOverrideId,
        boardId,
        origin: "mcp",
        details: {
          evaluationId,
          evaluationResultSha256,
          wizardDraftId,
          finalVoteId,
          recommendedRuleId: selection.row.recommended_rule_id,
          selectedRuleId,
          selectedRuleSha256,
          reasonSha256: sha256Hex(reason),
          citationCount: citations.length,
          packageSha256,
          canonicalOverrideSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  await client.query(
    `insert into rule_overrides(
       id,organization_id,board_id,evaluation_id,wizard_draft_id,final_object_type,
       final_object_id,recommended_rule_id,selected_rule_id,reason,citation_snapshot,
       consent_record_id,audit_event_id,canonical_sha256
     ) values ($1,$2,$3,$4,$5,'vote',$6,$7,$8,$9,$10,$11,$12,$13)`,
    [
      ruleOverrideId,
      organizationId,
      boardId,
      evaluationId,
      wizardDraftId,
      finalVoteId,
      selection.row.recommended_rule_id,
      selectedRuleId,
      reason,
      JSON.stringify(citations),
      consentRecordId,
      auditEventId,
      Buffer.from(canonicalOverrideSha256, "hex")
    ]
  );
  const completed = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='rule_override',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [ruleOverrideId, Buffer.from(canonicalOverrideSha256, "hex"), idempotencyRecordId]
  );
  if (completed.rowCount !== 1) throw new Error("rule-override idempotency completion failed");
  return {
    replayed: false,
    ruleOverrideId,
    evaluationId,
    selectedRuleId,
    recommendedRuleId: selection.row.recommended_rule_id,
    canonicalSha256: canonicalOverrideSha256,
    auditEvents
  };
}
