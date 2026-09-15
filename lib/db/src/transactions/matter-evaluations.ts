import type { PoolClient } from "pg";
import { z } from "zod";

import type { AuditEvent } from "@boardagent/audit";
import {
  Sha256HexSchema,
  UuidV7Schema,
  canonicalSha256,
  safeHashEqual
} from "@boardagent/contracts";
import {
  MatterTypeSchema,
  MatterValueSchema,
  RulesetVersionSchema,
  evaluateMatter,
  type MatterFacts,
  type Rule,
  type RulesetVersion
} from "@boardagent/ruleset";

import { appendAuditEventsInTransaction } from "./audit.js";
import { readRequestContext } from "./request-context.js";

const ENGINE_VERSION = "boardagent.rules-engine.v1" as const;
const MatterTypeCodeSchema = z.string().regex(/^[a-z][a-z0-9_]{0,127}$/u);
const MatterFactsSchema = z.record(MatterTypeCodeSchema, MatterValueSchema);

const CitationSnapshotSchema = z
  .object({
    ruleId: UuidV7Schema,
    sourceDocumentVersionId: UuidV7Schema,
    sourceDocumentSha256: Sha256HexSchema,
    clause: z.string().min(1).max(512),
    locator: z.string().min(1).max(1024)
  })
  .strict();

export const MatterEvaluationResultDetailsSchema = z
  .object({
    schemaVersion: z.literal("boardagent.matter-evaluation-result.v1"),
    engineVersion: z.literal(ENGINE_VERSION),
    profile: z
      .object({
        id: UuidV7Schema,
        version: z.number().int().positive().safe(),
        canonicalSha256: Sha256HexSchema
      })
      .strict(),
    ruleset: z
      .object({
        id: UuidV7Schema,
        version: z.number().int().positive().safe(),
        canonicalSha256: Sha256HexSchema
      })
      .strict(),
    matterType: z
      .object({
        id: UuidV7Schema,
        code: MatterTypeCodeSchema,
        schemaSha256: Sha256HexSchema
      })
      .strict(),
    factsSha256: Sha256HexSchema,
    status: z.enum(["matched", "ambiguous", "missing", "no_match"]),
    matchedRuleId: UuidV7Schema.nullable(),
    selectedApprovalRuleId: UuidV7Schema.nullable(),
    candidateRuleIds: z.array(UuidV7Schema),
    missingFields: z.array(MatterTypeCodeSchema),
    citations: z.array(CitationSnapshotSchema)
  })
  .strict();

export type MatterEvaluationResultDetails = z.infer<typeof MatterEvaluationResultDetailsSchema>;
type ResultDetails = MatterEvaluationResultDetails;
type EvaluationStatus = ResultDetails["status"];
type CitationSnapshot = z.infer<typeof CitationSnapshotSchema>;

export class MatterEvaluationTransactionError extends Error {
  public constructor(
    public readonly code:
      | "matter_evaluation_unavailable"
      | "matter_evaluation_invalid"
      | "idempotency_conflict"
      | "idempotency_in_progress",
    message: string
  ) {
    super(message);
    this.name = "MatterEvaluationTransactionError";
  }
}

export interface EvaluateMatterInput {
  readonly organizationId: string;
  readonly boardId: string;
  readonly matterTypeId: string;
  readonly matterTypeCode: string;
  readonly facts: MatterFacts;
  readonly expectedProfileId: string;
  readonly expectedRulesetId: string;
  readonly evaluationId: string;
  readonly idempotencyRecordId: string;
  readonly idempotencyKey: string;
  readonly auditEventId: string;
}

export interface EvaluateMatterResult {
  readonly replayed: boolean;
  readonly evaluationId: string;
  readonly status: EvaluationStatus;
  readonly matchedRuleId: string | null;
  readonly selectedApprovalRuleId: string | null;
  readonly candidateRuleIds: readonly string[];
  readonly missingFields: readonly string[];
  readonly resultSha256: string;
  readonly auditEvents?: readonly AuditEvent[];
}

interface BoardRootRow {
  readonly organization_id: string;
  readonly state: string;
  readonly actor_ready: boolean;
}

interface MatterSnapshotRow {
  readonly organization_id: string;
  readonly board_id: string;
  readonly profile_id: string;
  readonly profile_version: number;
  readonly profile_sha256: Buffer;
  readonly ruleset_id: string;
  readonly ruleset_version: number;
  readonly ruleset_sha256: Buffer;
  readonly matter_type_id: string;
  readonly matter_type_schema_sha256: Buffer;
  readonly matter_definitions: unknown;
  readonly rule_definitions: unknown;
  readonly snapshot_valid: boolean;
}

interface IdempotencyRow {
  readonly request_sha256: Buffer;
  readonly state: string;
  readonly safe_response_type: string | null;
  readonly safe_response_id: string | null;
  readonly safe_response_sha256: Buffer | null;
}

interface PersistedEvaluationRow {
  readonly result: EvaluationStatus;
  readonly result_details: unknown;
  readonly result_sha256: Buffer;
}

const MatterDefinitionEnvelopeSchema = z
  .object({
    definition: z.unknown(),
    schemaSha256: Sha256HexSchema
  })
  .strict();

function uniqueGeneratedIds(values: readonly string[]): readonly string[] {
  const parsed = values.map((value) => UuidV7Schema.parse(value));
  if (new Set(parsed).size !== parsed.length) {
    throw new TypeError("matter-evaluation generated IDs must be globally unique");
  }
  return parsed;
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
  const query = `select organization_id,state,actor_ready
                   from boardagent_lock_board_root($1)`;
  await client.query<BoardRootRow>(query, [boardId]);
  // A waiter needs a new READ COMMITTED snapshot after acquiring the board root.
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
        and operation='evaluate_matter' and idempotency_key=$3
      for update`,
    [actorMemberId, clientId, key]
  );
  return result.rows[0];
}

function checkedReplay(
  row: IdempotencyRow | undefined,
  requestSha256: string
): { readonly evaluationId: string; readonly resultSha256: string } | undefined {
  if (!row) return undefined;
  if (!safeHashEqual(row.request_sha256.toString("hex"), requestSha256)) {
    throw new MatterEvaluationTransactionError(
      "idempotency_conflict",
      "idempotency key was already used for a different matter evaluation"
    );
  }
  if (
    row.state === "succeeded" &&
    row.safe_response_type === "matter_evaluation" &&
    row.safe_response_id &&
    row.safe_response_sha256
  ) {
    return {
      evaluationId: row.safe_response_id,
      resultSha256: row.safe_response_sha256.toString("hex")
    };
  }
  throw new MatterEvaluationTransactionError(
    "idempotency_in_progress",
    "identical matter evaluation is already in progress"
  );
}

async function replayEvaluation(
  client: PoolClient,
  boardId: string,
  replay: { readonly evaluationId: string; readonly resultSha256: string }
): Promise<EvaluateMatterResult> {
  const result = await client.query<PersistedEvaluationRow>(
    `select result,result_details,result_sha256
       from matter_evaluations
      where id=$1
        and board_id=$2
        and organization_id=boardagent_context_uuid('boardagent.organization_id')`,
    [replay.evaluationId, boardId]
  );
  const persisted = result.rows[0];
  if (!persisted || result.rows.length !== 1) {
    throw new MatterEvaluationTransactionError(
      "matter_evaluation_invalid",
      "persisted matter-evaluation replay is unavailable"
    );
  }
  const details = MatterEvaluationResultDetailsSchema.parse(persisted.result_details);
  const resultSha256 = persisted.result_sha256.toString("hex");
  if (
    persisted.result !== details.status ||
    !safeHashEqual(resultSha256, replay.resultSha256) ||
    !safeHashEqual(resultSha256, canonicalSha256(details))
  ) {
    throw new MatterEvaluationTransactionError(
      "matter_evaluation_invalid",
      "persisted matter-evaluation replay failed its evidence binding"
    );
  }
  return {
    replayed: true,
    evaluationId: replay.evaluationId,
    status: details.status,
    matchedRuleId: details.matchedRuleId,
    selectedApprovalRuleId: details.selectedApprovalRuleId,
    candidateRuleIds: details.candidateRuleIds,
    missingFields: details.missingFields,
    resultSha256
  };
}

async function insertIdempotency(
  client: PoolClient,
  input: {
    readonly id: string;
    readonly organizationId: string;
    readonly actorMemberId: string;
    readonly clientId: string;
    readonly key: string;
    readonly requestSha256: string;
  }
): Promise<void> {
  const inserted = await client.query(
    `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values ($1,$2,$3,$4,'evaluate_matter',$5,$6,'in_progress',
       transaction_timestamp()+interval '24 hours')
     on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing`,
    [
      input.id,
      input.organizationId,
      input.actorMemberId,
      input.clientId,
      input.key,
      Buffer.from(input.requestSha256, "hex")
    ]
  );
  const row = await readIdempotency(client, input.actorMemberId, input.clientId, input.key);
  if (!row) throw new Error("matter-evaluation idempotency record disappeared");
  if (inserted.rowCount === 0) checkedReplay(row, input.requestSha256);
  if (!safeHashEqual(row.request_sha256.toString("hex"), input.requestSha256)) {
    throw new MatterEvaluationTransactionError(
      "idempotency_conflict",
      "matter-evaluation idempotency record does not bind this request"
    );
  }
}

async function finishIdempotency(
  client: PoolClient,
  id: string,
  evaluationId: string,
  resultSha256: string
): Promise<void> {
  const result = await client.query(
    `update idempotency_records
        set state='succeeded',safe_response_type='matter_evaluation',safe_response_id=$1,
            safe_response_sha256=$2,completed_at=transaction_timestamp()
      where id=$3 and state='in_progress'`,
    [evaluationId, Buffer.from(resultSha256, "hex"), id]
  );
  if (result.rowCount !== 1) throw new Error("matter-evaluation idempotency completion failed");
}

async function lockSnapshot(
  client: PoolClient,
  boardId: string,
  matterTypeCode: string
): Promise<MatterSnapshotRow | undefined> {
  const result = await client.query<MatterSnapshotRow>(
    "select * from boardagent_lock_matter_evaluation_snapshot($1,$2)",
    [boardId, matterTypeCode]
  );
  return result.rows.length === 1 ? result.rows[0] : undefined;
}

function buildRuleset(snapshot: MatterSnapshotRow): RulesetVersion {
  if (!snapshot.snapshot_valid) {
    throw new MatterEvaluationTransactionError(
      "matter_evaluation_invalid",
      "active ruleset citations or approval rules failed integrity checks"
    );
  }
  const envelopes = z
    .array(MatterDefinitionEnvelopeSchema)
    .min(1)
    .parse(snapshot.matter_definitions);
  const matterTypes = envelopes.map((envelope) => {
    if (!safeHashEqual(canonicalSha256(envelope.definition), envelope.schemaSha256)) {
      throw new MatterEvaluationTransactionError(
        "matter_evaluation_invalid",
        "active matter-type schema failed its canonical hash"
      );
    }
    return MatterTypeSchema.parse(envelope.definition);
  });
  const rulesetSha256 = Sha256HexSchema.parse(snapshot.ruleset_sha256.toString("hex"));
  return RulesetVersionSchema.parse({
    schemaVersion: "boardagent.ruleset.v1",
    id: snapshot.ruleset_id,
    boardId: snapshot.board_id,
    version: snapshot.ruleset_version,
    canonicalHash: rulesetSha256,
    matterTypes,
    rules: snapshot.rule_definitions
  });
}

function resultParts(evaluation: ReturnType<typeof evaluateMatter>): {
  readonly matchedRuleId: string | null;
  readonly selectedApprovalRuleId: string | null;
  readonly candidateRuleIds: readonly string[];
  readonly missingFields: readonly string[];
} {
  switch (evaluation.status) {
    case "matched":
      return {
        matchedRuleId: evaluation.rule.id,
        selectedApprovalRuleId: evaluation.rule.approvalRuleId,
        candidateRuleIds: [evaluation.rule.id],
        missingFields: []
      };
    case "ambiguous":
    case "no_match":
      return {
        matchedRuleId: null,
        selectedApprovalRuleId: null,
        candidateRuleIds: [...evaluation.candidateRuleIds].toSorted(),
        missingFields: []
      };
    case "missing":
      return {
        matchedRuleId: null,
        selectedApprovalRuleId: null,
        candidateRuleIds: [],
        missingFields: [...evaluation.missingFields].toSorted()
      };
  }
}

function citationSnapshot(
  ruleset: RulesetVersion,
  candidateRuleIds: readonly string[]
): readonly CitationSnapshot[] {
  const rules = new Map<string, Rule>(ruleset.rules.map((rule) => [rule.id, rule]));
  return candidateRuleIds
    .flatMap((ruleId) => {
      const rule = rules.get(ruleId);
      if (!rule) {
        throw new MatterEvaluationTransactionError(
          "matter_evaluation_invalid",
          "evaluation selected a rule outside its locked ruleset"
        );
      }
      return rule.citations.map((citation) =>
        CitationSnapshotSchema.parse({ ruleId, ...citation })
      );
    })
    .toSorted(
      (left, right) =>
        left.ruleId.localeCompare(right.ruleId) ||
        left.sourceDocumentVersionId.localeCompare(right.sourceDocumentVersionId) ||
        left.clause.localeCompare(right.clause) ||
        left.locator.localeCompare(right.locator)
    );
}

export async function evaluateMatterInTransaction(
  client: PoolClient,
  input: EvaluateMatterInput
): Promise<EvaluateMatterResult> {
  const organizationId = UuidV7Schema.parse(input.organizationId);
  const boardId = UuidV7Schema.parse(input.boardId);
  const matterTypeId = UuidV7Schema.parse(input.matterTypeId);
  const matterTypeCode = MatterTypeCodeSchema.parse(input.matterTypeCode);
  const facts = MatterFactsSchema.parse(input.facts);
  const expectedProfileId = UuidV7Schema.parse(input.expectedProfileId);
  const expectedRulesetId = UuidV7Schema.parse(input.expectedRulesetId);
  const [evaluationId, idempotencyRecordId, auditEventId] = uniqueGeneratedIds([
    input.evaluationId,
    input.idempotencyRecordId,
    input.auditEventId
  ]) as readonly [string, string, string];
  const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
  const context = await readRequestContext(client);
  if (context.organizationId !== organizationId) {
    throw new MatterEvaluationTransactionError(
      "matter_evaluation_unavailable",
      "matter evaluation is unavailable"
    );
  }
  const requestSha256 = canonicalSha256({
    schemaVersion: "boardagent.matter-evaluation-request.v1",
    organizationId,
    boardId,
    matterTypeId,
    matterTypeCode,
    facts,
    expectedProfileId,
    expectedRulesetId
  });
  const board = await lockBoardRoot(client, boardId);
  if (
    !board ||
    board.organization_id !== organizationId ||
    board.state !== "active" ||
    !board.actor_ready
  ) {
    throw new MatterEvaluationTransactionError(
      "matter_evaluation_unavailable",
      "matter evaluation is unavailable"
    );
  }
  const replay = checkedReplay(
    await readIdempotency(client, context.memberId, context.clientId, idempotencyKey),
    requestSha256
  );
  if (replay) return replayEvaluation(client, boardId, replay);

  const snapshot = await lockSnapshot(client, boardId, matterTypeCode);
  if (
    !snapshot ||
    snapshot.organization_id !== organizationId ||
    snapshot.board_id !== boardId ||
    snapshot.matter_type_id !== matterTypeId ||
    snapshot.profile_id !== expectedProfileId ||
    snapshot.ruleset_id !== expectedRulesetId
  ) {
    throw new MatterEvaluationTransactionError(
      "matter_evaluation_unavailable",
      "active matter type is unavailable"
    );
  }
  const ruleset = buildRuleset(snapshot);
  const evaluation = evaluateMatter(ruleset, matterTypeCode, facts);
  const parts = resultParts(evaluation);
  const citations = citationSnapshot(ruleset, parts.candidateRuleIds);
  const selectedDefinition = z
    .array(MatterDefinitionEnvelopeSchema)
    .parse(snapshot.matter_definitions)
    .find(({ definition }) => MatterTypeSchema.parse(definition).code === matterTypeCode);
  if (
    !selectedDefinition ||
    !safeHashEqual(
      selectedDefinition.schemaSha256,
      snapshot.matter_type_schema_sha256.toString("hex")
    )
  ) {
    throw new MatterEvaluationTransactionError(
      "matter_evaluation_invalid",
      "selected matter type does not match its locked snapshot"
    );
  }
  const resultDetails = MatterEvaluationResultDetailsSchema.parse({
    schemaVersion: "boardagent.matter-evaluation-result.v1",
    engineVersion: ENGINE_VERSION,
    profile: {
      id: snapshot.profile_id,
      version: snapshot.profile_version,
      canonicalSha256: snapshot.profile_sha256.toString("hex")
    },
    ruleset: {
      id: snapshot.ruleset_id,
      version: snapshot.ruleset_version,
      canonicalSha256: snapshot.ruleset_sha256.toString("hex")
    },
    matterType: {
      id: snapshot.matter_type_id,
      code: matterTypeCode,
      schemaSha256: selectedDefinition.schemaSha256
    },
    factsSha256: evaluation.factsHash,
    status: evaluation.status,
    ...parts,
    citations
  });
  const resultSha256 = canonicalSha256(resultDetails);

  await insertIdempotency(client, {
    id: idempotencyRecordId,
    organizationId,
    actorMemberId: context.memberId,
    clientId: context.clientId,
    key: idempotencyKey,
    requestSha256
  });
  await client.query(
    `insert into matter_evaluations(
       id,organization_id,board_id,requester_member_id,profile_id,ruleset_id,
       matter_type_id,engine_version,canonical_facts,facts_sha256,result,matched_rule_id,
       candidate_rule_ids,citation_snapshot,result_details,result_sha256
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      evaluationId,
      organizationId,
      boardId,
      context.memberId,
      snapshot.profile_id,
      snapshot.ruleset_id,
      snapshot.matter_type_id,
      ENGINE_VERSION,
      JSON.stringify(facts),
      Buffer.from(evaluation.factsHash, "hex"),
      evaluation.status,
      parts.matchedRuleId,
      parts.candidateRuleIds,
      JSON.stringify(citations),
      JSON.stringify(resultDetails),
      Buffer.from(resultSha256, "hex")
    ]
  );
  const auditEvents = await appendAuditEventsInTransaction(client, [
    {
      organizationId,
      event: {
        eventId: auditEventId,
        eventType: "matter_evaluated",
        actorMemberId: context.memberId,
        actorClientId: context.clientId,
        tokenJti: context.tokenJti,
        entityType: "matter_evaluation",
        entityId: evaluationId,
        boardId,
        origin: "mcp",
        details: {
          profileId: snapshot.profile_id,
          profileVersion: snapshot.profile_version,
          profileSha256: snapshot.profile_sha256.toString("hex"),
          rulesetId: snapshot.ruleset_id,
          rulesetVersion: snapshot.ruleset_version,
          rulesetSha256: snapshot.ruleset_sha256.toString("hex"),
          matterTypeId: snapshot.matter_type_id,
          matterTypeCode,
          factsSha256: evaluation.factsHash,
          status: evaluation.status,
          matchedRuleId: parts.matchedRuleId,
          selectedApprovalRuleId: parts.selectedApprovalRuleId,
          candidateRuleIds: parts.candidateRuleIds,
          missingFields: parts.missingFields,
          citationCount: citations.length,
          resultSha256
        },
        schemaVersion: 1
      }
    }
  ]);
  await finishIdempotency(client, idempotencyRecordId, evaluationId, resultSha256);
  return {
    replayed: false,
    evaluationId,
    status: evaluation.status,
    matchedRuleId: parts.matchedRuleId,
    selectedApprovalRuleId: parts.selectedApprovalRuleId,
    candidateRuleIds: parts.candidateRuleIds,
    missingFields: parts.missingFields,
    resultSha256,
    auditEvents
  };
}
