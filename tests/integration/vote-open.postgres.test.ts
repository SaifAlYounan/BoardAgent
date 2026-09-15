import {
  DirectReadRepository,
  withDirectResponseAllocation
} from "../helpers/direct-response-allocation.js";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
  administrativeService,
  freshAdministrativeTestCredential,
  stageAdministrativeAction
} from "../helpers/administrative-service.js";
import { seedCapacitySeats } from "../helpers/capacity-seats.js";
import { withConfiguredFixtureWorker } from "../helpers/configured-worker.js";
import { dropClosedTestDatabase } from "../helpers/drop-test-database.js";
import {
  preserveHistoricRecords,
  replaceDirectorThroughDelegate
} from "../helpers/delegated-director-replacement.js";

import {
  BoardAgentCoreWorkerHandlers,
  BoardAgentTypedWorker,
  PgBoardAgentSurfaceService,
  PgPublicCertificateVerifier,
  PgRateLimiter,
  loadBoardAgentKeyMaterial,
  type BoardAgentRuntimeBinding,
  type BoardAgentSurfaceService,
  type PreparedHumanAction,
  type SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import { parseConfig } from "../../lib/config/src/index.js";

import {
  certificatePublicIdSha256,
  issueVoteCertificate,
  OfflineCertificateBundleSchema,
  VoteCertificatePayloadSchema,
  verifyOfflineCertificateBundle,
  verifyVoteCertificate
} from "../../lib/audit/src/index.js";

import {
  canonicalJson,
  canonicalSha256,
  DecisionPackageSchema,
  TOOL_INPUT_SCHEMA_VERSION,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import {
  appendAuditEventsInTransaction,
  castBallotInTransaction,
  enqueueRequestJobInTransaction,
  evaluateMatterInTransaction,
  excludePendingVoteSourceInTransaction,
  finalizeVoteCloseInTransaction,
  grantProxyInTransaction,
  initiateAutomaticVoteCloseInTransaction,
  initiateVoteCloseInTransaction,
  manageVoteRecusalInTransaction,
  migrate,
  openVoteInTransaction,
  recordRuleOverrideInTransaction,
  scheduleAuditCheckpointInTransaction,
  scheduleDueAutomaticVoteClosesInTransaction,
  schedulePeriodicJobsInTransaction,
  verifyPersistedAuditEvidence,
  replaceVoteInTransaction,
  revokeProxyInTransaction,
  verifyPersistedVoteCertificateInTransaction,
  verifyPublicPersistedVoteCertificateInTransaction,
  withIdentityTransaction,
  withRequestTransaction,
  withWorkerTransaction,
  type CastBallotInput,
  type ExcludePendingVoteSourceInput,
  type GrantProxyInput,
  type OpenVoteInput,
  type RecordRuleOverrideInput,
  type ManageVoteRecusalInput,
  type ReplaceVoteInput,
  type RevokeProxyInput
} from "../../lib/db/src/index.js";
import {
  ballotConsentHash,
  prepareVoteElectorate,
  proxyGrantConsentHash,
  proxyRevokeConsentHash,
  ruleOverrideConsentHash,
  ruleOverrideEvidenceHash,
  voteRecusalConsentHash,
  voteCloseConsentHash,
  voteReplacementConsentHash,
  voteSourceExclusionConsentHash
} from "../../lib/domain/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_vote_open_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 6 });
  try {
    await migrate(pool, MIGRATIONS, "vote-open-test");
    return await run(pool);
  } finally {
    await pool.end();
    await dropClosedTestDatabase(admin, database);
    await admin.end();
  }
}

async function voteWorker(
  pool: Pool,
  actor: AuthorizedActorFixture,
  evidencePrivateKey: KeyObject,
  signingKeyId: string,
  signingKeyLocator: string,
  idBase: number
): Promise<BoardAgentTypedWorker> {
  const config = parseConfig({
    BOARDAGENT_ENV: "test",
    BOARDAGENT_DATABASE_URL: "postgresql://unused",
    BOARDAGENT_ORGANIZATION_ID: actor.organizationId,
    BOARDAGENT_PUBLIC_BASE_URL: "https://boardagent.test",
    BOARDAGENT_AUTHORIZATION_MODE: "builtin",
    BOARDAGENT_BLOB_ROOT: "/tmp/boardagent-vote-worker-test",
    BOARDAGENT_DEV_MASTER_SECRET: "vote-worker-test-secret-material-is-long-enough"
  });
  const baseKeys = await loadBoardAgentKeyMaterial(config);
  const binding: BoardAgentRuntimeBinding = {
    instanceId: testId(15),
    organizationId: actor.organizationId,
    canonicalResourceUri: "https://boardagent.test/mcp",
    keyIds: {
      oauth_signing: testId(8),
      evidence_signing: signingKeyId,
      browser_session: testId(idBase + 90),
      data_kek: testId(idBase + 91)
    },
    keyLocators: {
      oauth_signing: "local-test-key",
      evidence_signing: signingKeyLocator,
      browser_session: "test:browser",
      data_kek: "test:data"
    }
  };
  let nextId = idBase;
  const handlers = new BoardAgentCoreWorkerHandlers(pool, {
    config,
    binding,
    keys: { ...baseKeys, evidencePrivateKey },
    newId: () => testId(nextId++),
    randomBytes: (length) => Buffer.alloc(length, idBase % 256),
    assumeRole: "boardagent_worker"
  }).handlers();
  return new BoardAgentTypedWorker(pool, {
    handlers,
    workerId: `vote-worker-${String(idBase)}`,
    assumeRole: "boardagent_worker"
  });
}

const unavailableSurfaceReads: Pick<BoardAgentSurfaceService, "executeRead" | "readResource"> = {
  executeRead: async () => {
    throw new Error("read not used by ballot lifecycle surface test");
  },
  readResource: async () => {
    throw new Error("resource read not used by ballot lifecycle surface test");
  }
};

function surfacePrincipal(
  actor: AuthorizedActorFixture,
  roles: readonly ("member" | "observer" | "secretariat")[],
  scopes: readonly string[]
): SurfacePrincipal {
  return {
    organizationId: actor.organizationId,
    memberId: actor.memberId,
    serviceOrigin: "https://boardagent.test",
    clientId: actor.clientId,
    protocolClientId: `https://vote-agent.test/${actor.memberId}.json`,
    accessTokenRecordId: actor.accessTokenRecordId,
    tokenJti: actor.tokenJti,
    keyId: "test-oauth",
    scopes,
    roles,
    boardIds: [actor.boardId]
  };
}

let surfaceConfirmationSequence = 0;

async function confirmSurfaceVoteAction(
  service: BoardAgentSurfaceService,
  actor: SurfacePrincipal,
  tool:
    | "amend_resolution_text"
    | "create_vote"
    | "close_vote"
    | "cancel_vote"
    | "exclude_pending_vote_source"
    | "extend_vote_deadline"
    | "grant_proxy"
    | "manage_member"
    | "manage_recusal"
    | "replace_open_vote"
    | "revoke_proxy"
    | "stage_ballot",
  input: JsonValue,
  afterStage?: () => Promise<void>
) {
  surfaceConfirmationSequence += 1;
  const label = `surface-vote-${tool}-${String(surfaceConfirmationSequence).padStart(4, "0")}`;
  const prepared: PreparedHumanAction = await service.prepareHumanAction(actor, tool, input);
  const capabilities = { elicitation: { form: {} } } as const;
  const requestState = `${label}-request-state-bound-to-the-exact-agent-and-action`;
  await service.persistHumanStage({
    principal: actor,
    tool,
    input,
    prepared,
    client_capabilities: capabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm exact ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${label}-prepare`)
  });
  await afterStage?.();
  const resolved = await service.resolveHumanAction({
    principal: actor,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: capabilities,
    request_state: requestState,
    retry_request_id: Buffer.from(`${label}-retry-${prepared.stage_id}`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolved.confirmed) throw new Error(`${tool} failed: ${resolved.reason}`);
  return { prepared, result: resolved.result };
}

async function seedAnsweredQuestionComponent(
  pool: Pool,
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>
) {
  const questionId = testId(300);
  const initialTurnId = testId(301);
  const answerTurnId = testId(302);
  const answerRecordId = testId(303);
  const initialIdempotencyId = testId(304);
  const answerIdempotencyId = testId(305);
  const answerSha256 = testHash(112).toString("hex");
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query(
      `insert into idempotency_records(
       id,organization_id,actor_member_id,client_id,operation,idempotency_key,
       request_sha256,state,expires_at
     ) values
       ($1,$2,$3,$4,'seed_question','vote-open-question-seed-0001',$5,'in_progress',
        transaction_timestamp()+interval '1 day'),
       ($6,$2,$3,$4,'seed_question_answer','vote-open-answer-seed-0001',$7,'in_progress',
        transaction_timestamp()+interval '1 day')`,
      [
        initialIdempotencyId,
        actor.organizationId,
        actor.memberId,
        actor.clientId,
        testHash(110),
        answerIdempotencyId,
        testHash(111)
      ]
    );
    await client.query(
      `insert into management_questions(
       id,organization_id,board_id,asker_member_id,assigned_owner_ids,due_at,acl_policy,
       current_turn_id
     ) values ($1,$2,$3,$4,$5,'2099-09-01T12:00:00Z',$6,$7)`,
      [
        questionId,
        actor.organizationId,
        actor.boardId,
        actor.memberId,
        [actor.memberId],
        { schemaVersion: "boardagent.question-acl.v1", grants: [], inheritedDocumentIds: [] },
        initialTurnId
      ]
    );
    await client.query(
      `insert into management_question_turns(
       id,organization_id,board_id,question_id,ordinal,turn_kind,author_member_id,
       author_role,canonical_text,text_sha256,citation_snapshot,idempotency_record_id
     ) values
       ($1,$2,$3,$4,1,'question',$5,'voting_member','What is the exact basis?',$6,'[]',$7),
       ($8,$2,$3,$4,2,'answer',$5,'secretariat','The cited package is the exact basis.',$9,'[]',$10)`,
      [
        initialTurnId,
        actor.organizationId,
        actor.boardId,
        questionId,
        actor.memberId,
        testHash(113),
        initialIdempotencyId,
        answerTurnId,
        Buffer.from(answerSha256, "hex"),
        answerIdempotencyId
      ]
    );
    await client.query(
      `insert into management_question_answers(
       id,organization_id,question_id,answer_turn_id,management_author_id
     ) values ($1,$2,$3,$4,$5)`,
      [answerRecordId, actor.organizationId, questionId, answerTurnId, actor.memberId]
    );
    await client.query(
      `update management_questions
        set state='answered',current_turn_id=$1,row_version=row_version+1
      where id=$2`,
      [answerTurnId, questionId]
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return {
    type: "question_cutoff" as const,
    ordinal: 1,
    id: questionId,
    version: 2,
    sha256: answerSha256
  };
}

async function seedVoteOpenFixture(
  pool: Pool,
  options: {
    readonly includeAnsweredQuestion?: boolean;
    readonly overridePolicy?: "forbidden" | "reasoned_within_bounds";
    readonly closeMode?: "automatic" | "secretariat_confirmed";
    readonly deadlineAt?: string;
    readonly nearTermDatabaseDeadline?: boolean;
    readonly precreateVote?: boolean;
    readonly approvalRule?: {
      readonly proxyPolicy?: "principal_supersedes_proxy" | "first_ballot_final" | "forbidden";
      readonly approval?: { readonly numerator: number; readonly denominator: number };
      readonly quorum?: { readonly numerator: number; readonly denominator: number };
    };
  } = {}
) {
  const closeMode = options.closeMode ?? "secretariat_confirmed";
  const secretary = await seedAuthorizedActor(pool, {
    seatRole: "voting_member",
    scopes: ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"],
    isSecretary: true
  });
  const voter = await seedAdditionalAuthorizedActor(pool, secretary, {
    idBase: 100,
    seatRole: "voting_member",
    scopes: ["governance:read", "proxy:manage", "vote:act"]
  });
  const approvalRuleId = testId(200);
  const governanceProfileId = testId(201);
  const rulesetId = testId(202);
  const voteId = testId(203);
  const resolutionVersionId = testId(204);
  const decisionPackageId = testId(205);
  const membershipVersionIds = [testId(206), testId(207)] as const;
  const governanceRuleTemplateId = testId(150);
  const rulesetDocumentId = testId(151);
  const rulesetDocumentVersionId = testId(152);
  const matterTypeId = testId(153);
  const selectedRulesetRuleId = testId(154);
  const ruleCitationId = testId(155);
  const matterEvaluationId = testId(156);
  const overrideRulesetRuleId = testId(159);
  const overrideRuleCitationId = testId(160);
  const selectedRulesetRuleSha256 = canonicalSha256({
    schemaVersion: "boardagent.ruleset-rule.v1",
    ruleId: selectedRulesetRuleId,
    condition: { kind: "equals", field: "requires_approval", value: true },
    approvalRuleId
  });
  const overrideRulesetRuleSha256 = canonicalSha256({
    schemaVersion: "boardagent.ruleset-rule.v1",
    ruleId: overrideRulesetRuleId,
    condition: { kind: "equals", field: "requires_approval", value: false },
    approvalRuleId
  });
  const eligibilitySnapshots = [
    { memberId: secretary.memberId, eligible: true, reason: "active voting seat" },
    { memberId: voter.memberId, eligible: true, reason: "active voting seat" }
  ] as const;

  for (const [index, actor] of [secretary, voter].entries()) {
    const membership = await pool.query<{ id: string; voting_weight: string }>(
      `select id,voting_weight::text
         from board_memberships
        where board_id=$1 and member_id=$2 and state='active'`,
      [secretary.boardId, actor.memberId]
    );
    const row = membership.rows[0];
    if (!row) throw new Error("vote-open fixture membership is unavailable");
    await pool.query(
      `insert into membership_versions(
         id,organization_id,board_id,member_id,membership_id,version,seat_role,
         is_secretary,voting_weight,authority_snapshot,snapshot_sha256,change_reason,
         actor_member_id
       ) values ($1,$2,$3,$4,$5,1,'voting_member',$6,$7,$8,$9,
         'vote-open fixture',$10)`,
      [
        membershipVersionIds[index],
        secretary.organizationId,
        secretary.boardId,
        actor.memberId,
        row.id,
        actor.memberId === secretary.memberId,
        row.voting_weight,
        eligibilitySnapshots[index],
        Buffer.from(canonicalSha256(eligibilitySnapshots[index]!), "hex"),
        secretary.memberId
      ]
    );
  }

  const approvalRule = {
    schemaVersion: "boardagent.approval-rule.v1",
    thresholdNumerator: options.approvalRule?.approval?.numerator ?? 1,
    thresholdDenominator: options.approvalRule?.approval?.denominator ?? 2,
    quorumNumerator: options.approvalRule?.quorum?.numerator ?? 1,
    quorumDenominator: options.approvalRule?.quorum?.denominator ?? 2,
    approvalDenominator: "eligible",
    abstentionsCountForQuorum: true,
    tieBehavior: "reject",
    proxyPolicy: options.approvalRule?.proxyPolicy ?? "principal_supersedes_proxy",
    closeMode
  } as const;
  const approvalRuleSha256 = canonicalSha256(approvalRule);
  const governanceRuleTemplatePayload = {
    schemaVersion: "boardagent.governance-rule-template.v1",
    approvalRuleSha256,
    overridePolicy: options.overridePolicy ?? "reasoned_within_bounds"
  } as const;
  const governanceRuleTemplateSha256 = canonicalSha256(governanceRuleTemplatePayload);
  const governanceProfileSha256 = testHash(41).toString("hex");
  const rulesetSha256 = testHash(42).toString("hex");
  const resolutionText = "RESOLVED: approve the exact persisted decision package.";
  const resolutionSha256 = canonicalSha256({
    schemaVersion: "boardagent.resolution.v1",
    text: resolutionText
  });

  await pool.query(
    `insert into approval_rules(
       id,organization_id,board_id,schema_version,threshold_numerator,
       threshold_denominator,quorum_numerator,quorum_denominator,approval_denominator,
       abstentions_count_for_quorum,tie_behavior,proxy_policy,close_mode,canonical_sha256,
       created_by
     ) values ($1,$2,$3,'boardagent.approval-rule.v1',$7,$8,$9,$10,'eligible',true,'reject',
       $11,$6,$4,$5)`,
    [
      approvalRuleId,
      secretary.organizationId,
      secretary.boardId,
      Buffer.from(approvalRuleSha256, "hex"),
      secretary.memberId,
      closeMode,
      approvalRule.thresholdNumerator,
      approvalRule.thresholdDenominator,
      approvalRule.quorumNumerator,
      approvalRule.quorumDenominator,
      approvalRule.proxyPolicy
    ]
  );
  await pool.query(
    `insert into governance_profiles(
       id,organization_id,board_id,version,state,schema_version,canonical_payload,
       canonical_sha256,source_agreement_references,activation_consent_record_id,created_by,
       activated_at
     ) values ($1,$2,$3,1,'active','boardagent.governance-profile.v1','{}',$4,'[]',$5,$6,
       transaction_timestamp())`,
    [
      governanceProfileId,
      secretary.organizationId,
      secretary.boardId,
      Buffer.from(governanceProfileSha256, "hex"),
      secretary.consentRecordId,
      secretary.memberId
    ]
  );
  await pool.query(
    `insert into rulesets(
       id,organization_id,board_id,profile_id,version,state,schema_version,
       canonical_payload,canonical_sha256,activation_consent_record_id,created_by,activated_at
     ) values ($1,$2,$3,$4,1,'active','boardagent.ruleset.v1','{}',$5,$6,$7,
       transaction_timestamp())`,
    [
      rulesetId,
      secretary.organizationId,
      secretary.boardId,
      governanceProfileId,
      Buffer.from(rulesetSha256, "hex"),
      secretary.consentRecordId,
      secretary.memberId
    ]
  );
  await pool.query(
    `update boards
        set current_governance_profile_id=$1,current_ruleset_id=$2,row_version=row_version+1
      where id=$3`,
    [governanceProfileId, rulesetId, secretary.boardId]
  );
  await pool.query(
    `insert into governance_rule_templates(
       id,profile_id,code,approval_rule_id,exact_rule_payload,canonical_sha256
     ) values ($1,$2,'general_vote',$3,$4,$5)`,
    [
      governanceRuleTemplateId,
      governanceProfileId,
      approvalRuleId,
      JSON.stringify(governanceRuleTemplatePayload),
      Buffer.from(governanceRuleTemplateSha256, "hex")
    ]
  );
  const rulesetSourceSha256 = canonicalSha256({
    schemaVersion: "boardagent.synthetic-rules-source.v1",
    clause: "General vote rule"
  });
  await pool.query(
    `insert into documents(id,organization_id,board_id,title,created_by)
     values ($1,$2,$3,'Synthetic governance source',$4)`,
    [rulesetDocumentId, secretary.organizationId, secretary.boardId, secretary.memberId]
  );
  const rulesetSourceBytes = Buffer.from("General vote rule.\n", "utf8");
  await pool.query(
    `insert into document_versions(
       id,organization_id,board_id,document_id,version,media_type,
       canonicalization_version,canonical_bytes,byte_length,sha256,canonical_metadata,created_by
     ) values ($1,$2,$3,$4,1,'text/plain; charset=utf-8','RFC8785+NFC-LF-v1',$5,$6,$7,'{}',$8)`,
    [
      rulesetDocumentVersionId,
      secretary.organizationId,
      secretary.boardId,
      rulesetDocumentId,
      rulesetSourceBytes,
      rulesetSourceBytes.length,
      Buffer.from(rulesetSourceSha256, "hex"),
      secretary.memberId
    ]
  );
  await pool.query(
    "update documents set current_version_id=$1,row_version=row_version+1 where id=$2",
    [rulesetDocumentVersionId, rulesetDocumentId]
  );
  const matterDefinition = {
    code: "general_vote",
    fields: [{ name: "requires_approval", type: "boolean", required: true }]
  } as const;
  await pool.query(
    `insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256)
     values ($1,$2,'general_vote','General vote',$3,$4)`,
    [
      matterTypeId,
      rulesetId,
      JSON.stringify(matterDefinition),
      Buffer.from(canonicalSha256(matterDefinition), "hex")
    ]
  );
  await pool.query(
    `insert into ruleset_rules(
       id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
       approval_rule_id,canonical_sha256
     ) values ($1,$2,$3,10,10,$4,$5,$6)`,
    [
      selectedRulesetRuleId,
      rulesetId,
      matterTypeId,
      JSON.stringify({ kind: "equals", field: "requires_approval", value: true }),
      approvalRuleId,
      Buffer.from(selectedRulesetRuleSha256, "hex")
    ]
  );
  await pool.query(
    `insert into rule_citations(
       id,rule_id,source_document_version_id,source_document_sha256,clause,locator
     ) values ($1,$2,$3,$4,'General vote rule','synthetic governance source')`,
    [
      ruleCitationId,
      selectedRulesetRuleId,
      rulesetDocumentVersionId,
      Buffer.from(rulesetSourceSha256, "hex")
    ]
  );
  await pool.query(
    `insert into ruleset_rules(
       id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
       approval_rule_id,canonical_sha256
     ) values ($1,$2,$3,5,10,$4,$5,$6)`,
    [
      overrideRulesetRuleId,
      rulesetId,
      matterTypeId,
      JSON.stringify({ kind: "equals", field: "requires_approval", value: false }),
      approvalRuleId,
      Buffer.from(overrideRulesetRuleSha256, "hex")
    ]
  );
  const overrideRuleCitations = [
    {
      ruleId: overrideRulesetRuleId,
      sourceDocumentVersionId: rulesetDocumentVersionId,
      sourceDocumentSha256: rulesetSourceSha256,
      clause: "Alternative general vote rule",
      locator: "synthetic governance source"
    }
  ] as const;
  await pool.query(
    `insert into rule_citations(
       id,rule_id,source_document_version_id,source_document_sha256,clause,locator
     ) values ($1,$2,$3,$4,$5,$6)`,
    [
      overrideRuleCitationId,
      overrideRulesetRuleId,
      rulesetDocumentVersionId,
      Buffer.from(rulesetSourceSha256, "hex"),
      overrideRuleCitations[0].clause,
      overrideRuleCitations[0].locator
    ]
  );
  const matterEvaluation = await withRequestTransaction(
    pool,
    secretary.context,
    (client) =>
      evaluateMatterInTransaction(client, {
        organizationId: secretary.organizationId,
        boardId: secretary.boardId,
        matterTypeId,
        matterTypeCode: "general_vote",
        expectedProfileId: governanceProfileId,
        expectedRulesetId: rulesetId,
        facts: { requires_approval: true },
        evaluationId: matterEvaluationId,
        idempotencyRecordId: testId(157),
        idempotencyKey: "vote-open-matter-evaluation-0001",
        auditEventId: testId(158)
      }),
    { assumeRole: "boardagent_server" }
  );
  if (matterEvaluation.status !== "matched") {
    throw new Error("vote-open fixture requires one matched matter rule");
  }
  if (options.precreateVote !== false) {
    await pool.query(
      `insert into votes(
         id,organization_id,board_id,title,approval_rule_id,governance_profile_id,
         ruleset_id,close_mode,created_by
       ) values ($1,$2,$3,'Exact package vote',$4,$5,$6,$8,$7)`,
      [
        voteId,
        secretary.organizationId,
        secretary.boardId,
        approvalRuleId,
        governanceProfileId,
        rulesetId,
        secretary.memberId,
        closeMode
      ]
    );
    await pool.query(
      `insert into resolution_versions(
         id,organization_id,board_id,vote_id,version,canonical_schema,canonical_text,
         canonical_sha256,author_member_id
       ) values ($1,$2,$3,$4,1,'boardagent.resolution.v1',$5,$6,$7)`,
      [
        resolutionVersionId,
        secretary.organizationId,
        secretary.boardId,
        voteId,
        resolutionText,
        Buffer.from(resolutionSha256, "hex"),
        secretary.memberId
      ]
    );
  }

  const electorate = prepareVoteElectorate({
    voteId,
    entries: [
      {
        id: testId(210),
        memberId: secretary.memberId,
        membershipVersionId: membershipVersionIds[0],
        votingWeight: 1n,
        eligibilitySnapshot: eligibilitySnapshots[0]
      },
      {
        id: testId(211),
        memberId: voter.memberId,
        membershipVersionId: membershipVersionIds[1],
        votingWeight: 1n,
        eligibilitySnapshot: eligibilitySnapshots[1]
      }
    ]
  });
  const components = options.includeAnsweredQuestion
    ? [await seedAnsweredQuestionComponent(pool, secretary)]
    : [];
  // Create the draft first, then bind its short test deadline to the authoritative
  // database clock before hashing the package/consent. Host time and seed duration
  // must not make deadline_at precede the database-generated created_at.
  const deadlineAt = options.nearTermDatabaseDeadline
    ? (
        await pool.query<{ deadline: string }>(
          `select to_char((clock_timestamp()+interval '3 seconds') at time zone 'UTC',
                          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as deadline`
        )
      ).rows[0]!.deadline
    : (options.deadlineAt ?? "2099-09-30T12:00:00Z");
  const decisionPackage = DecisionPackageSchema.parse({
    schemaVersion: "boardagent.decision-package.v1",
    voteId,
    packageVersion: 1,
    resolutionVersionId,
    resolutionSha256,
    governanceProfileVersionId: governanceProfileId,
    governanceProfileSha256,
    rulesetVersionId: rulesetId,
    rulesetSha256,
    approvalRuleId,
    approvalRuleSha256,
    matterEvaluationId,
    matterEvaluationResultSha256: matterEvaluation.resultSha256,
    selectedRulesetRuleId,
    selectedRulesetRuleSha256,
    ruleOverride: null,
    electorateSha256: electorate.electorateSha256,
    closeMode,
    deadlineAt,
    components
  });
  const packageSha256 = canonicalSha256(decisionPackage);
  const voteConsentRecordId = testId(212);
  const voteStageId = testId(213);
  const voteAttemptId = testId(214);
  if (options.precreateVote !== false) {
    await pool.query(
      `insert into action_stages(
       id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
       canonical_schema,canonicalization_version,canonical_payload,payload_sha256,
       package_sha256,nonce_sha256,protected_code_sha256,client_id,access_token_record_id,
       token_jti,exact_origin,context_sha256,state,expires_at,confirmed_at
     ) select $1,$2,$3,$4,'create_vote','vote',$5,'boardagent.vote-open.v1',
       'RFC8785+NFC-LF-v1',$6,$7,$7,$8,$9,$10,token.id,$11,'https://client.example',$12,
       'active',transaction_timestamp()+interval '10 minutes',null
         from access_token_records as token where token.jti=$11`,
      [
        voteStageId,
        secretary.organizationId,
        secretary.boardId,
        secretary.memberId,
        voteId,
        Buffer.from(canonicalJson(decisionPackage), "utf8"),
        Buffer.from(packageSha256, "hex"),
        testHash(80),
        testHash(81),
        secretary.clientId,
        secretary.tokenJti,
        testHash(82)
      ]
    );
    await pool.query(
      "update action_stages set state='confirmed',confirmed_at=transaction_timestamp() where id=$1",
      [voteStageId]
    );
    await pool.query(
      `insert into input_required_attempts(
       id,organization_id,stage_id,protocol_version,protocol_header_version,
       result_meta_version,original_method,original_name,original_arguments_sha256,
       capabilities_sha256,embedded_form_sha256,embedded_result_sha256,request_state_bytes,
       request_state_sha256,prepared_request_id,retry_request_id,input_response_sha256,
       response_action,state,completed_at
     ) values ($1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call',
       'create_vote',$4,$5,$6,$7,$8,$9,$10,$11,$12,'accept','confirmed',
       transaction_timestamp())`,
      [
        voteAttemptId,
        secretary.organizationId,
        voteStageId,
        testHash(83),
        testHash(84),
        testHash(85),
        testHash(86),
        Buffer.alloc(32, 87),
        testHash(87),
        Buffer.from("request-open-1"),
        Buffer.from("request-open-2"),
        testHash(88)
      ]
    );
    await pool.query(
      `insert into consent_records(
       id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
       action_code,target_type,target_id,canonical_schema,payload_sha256,package_sha256,
       protected_code_record_sha256,access_token_record_id,token_jti,client_id,exact_origin,
       staged_at,record_sha256
     ) select $1,$2,$3,$4,$5,$6,'create_vote','vote',$7,
       'boardagent.consent-record.v1',$8,$8,$9,token.id,$10,$11,'https://client.example',
       transaction_timestamp(),$12
         from access_token_records as token where token.jti=$10`,
      [
        voteConsentRecordId,
        secretary.organizationId,
        secretary.boardId,
        voteStageId,
        voteAttemptId,
        secretary.memberId,
        voteId,
        Buffer.from(packageSha256, "hex"),
        testHash(89),
        secretary.tokenJti,
        secretary.clientId,
        testHash(90)
      ]
    );
  }

  return {
    secretary,
    voter,
    voteId,
    decisionPackageId,
    decisionPackage,
    electorate,
    governanceProfileId,
    rulesetId,
    approvalRuleId,
    closeMode,
    deadlineAt,
    resolutionText,
    matterEvaluationId,
    matterEvaluationResultSha256: matterEvaluation.resultSha256,
    selectedRulesetRuleId,
    selectedRulesetRuleSha256,
    overrideRulesetRuleId,
    overrideRulesetRuleSha256,
    overrideRuleCitations,
    voteConsentRecordId,
    deliveries: [
      {
        memberId: secretary.memberId,
        noticeId: testId(220),
        feedId: testId(221),
        noticeAuditEventId: testId(222)
      },
      {
        memberId: voter.memberId,
        noticeId: testId(223),
        feedId: testId(224),
        noticeAuditEventId: testId(225)
      }
    ]
  };
}

function voteOpenInput(
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  overrides: Partial<OpenVoteInput> = {}
): OpenVoteInput {
  return {
    organizationId: fixture.secretary.organizationId,
    voteId: fixture.voteId,
    decisionPackageId: fixture.decisionPackageId,
    decisionPackage: fixture.decisionPackage,
    decisionPackageComponentIds: Array.from(
      { length: 7 + fixture.decisionPackage.components.length },
      (_, index) => testId(230 + index)
    ),
    questionDecisionLinkIds: fixture.decisionPackage.components
      .filter(({ type }) => type === "question_cutoff")
      .map((_, index) => testId(240 + index)),
    electorate: fixture.electorate,
    consentRecordId: fixture.voteConsentRecordId,
    auditEventId: testId(235),
    idempotencyRecordId: testId(236),
    idempotencyKey: "vote-open-exact-package-0001",
    deliveries: fixture.deliveries,
    ...overrides
  };
}

function voteCreationSurfaceInput(
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  options: { readonly selectedRuleId?: string; readonly overrideReason?: string | null } = {}
): JsonValue {
  return JSON.parse(
    canonicalJson({
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      board_id: fixture.secretary.boardId,
      vote_id: fixture.voteId,
      title: "Exact package vote",
      resolution_text: fixture.resolutionText,
      decision_package: {
        schema_version: "boardagent.vote-package-components.v1",
        values: { components: fixture.decisionPackage.components }
      },
      approval_rule_id: fixture.approvalRuleId,
      matter_evaluation_id: fixture.matterEvaluationId,
      selected_ruleset_rule_id: options.selectedRuleId ?? fixture.selectedRulesetRuleId,
      override_reason: options.overrideReason ?? null,
      close_mode: fixture.closeMode,
      deadline_at: fixture.deadlineAt,
      idempotency_key: "surface-guided-vote-create-0001"
    })
  ) as JsonValue;
}

async function seedConfirmedVoteAction(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  input: {
    readonly idBase: number;
    readonly actionCode: string;
    readonly originalName: string;
    readonly targetId: string;
    readonly targetType?: "proxy_grant" | "vote";
    readonly payloadSha256: string;
    readonly canonicalPayload?: JsonValue;
    readonly packageSha256?: string;
    readonly actor?: Awaited<ReturnType<typeof seedAuthorizedActor>>;
  }
) {
  if (input.canonicalPayload && canonicalSha256(input.canonicalPayload) !== input.payloadSha256)
    throw new Error("Fixture consent payload must match its declared hash");
  const actionActor = input.actor ?? fixture.secretary;
  const stageId = testId(input.idBase);
  const attemptId = testId(input.idBase + 1);
  const consentRecordId = testId(input.idBase + 2);
  const hash = (offset: number) => testHash((input.idBase + offset) % 256);
  await pool.query(
    `insert into action_stages(
       id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
       canonical_schema,canonicalization_version,canonical_payload,payload_sha256,
       package_sha256,nonce_sha256,protected_code_sha256,client_id,access_token_record_id,
       token_jti,exact_origin,context_sha256,state,expires_at,confirmed_at
     ) select $1,$2,$3,$4,$5,$15,$6,'boardagent.vote-action.v1',
       'RFC8785+NFC-LF-v1',$7,$8,$9,$10,$11,$12,token.id,$13,'https://client.example',$14,
       'active',transaction_timestamp()+interval '10 minutes',null
         from access_token_records as token where token.jti=$13`,
    [
      stageId,
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      actionActor.memberId,
      input.actionCode,
      input.targetId,
      Buffer.from(canonicalJson(input.canonicalPayload ?? {})),
      Buffer.from(input.payloadSha256, "hex"),
      input.packageSha256 ? Buffer.from(input.packageSha256, "hex") : null,
      hash(10),
      hash(11),
      actionActor.clientId,
      actionActor.tokenJti,
      hash(12),
      input.targetType ?? "vote"
    ]
  );
  await pool.query(
    "update action_stages set state='confirmed',confirmed_at=transaction_timestamp() where id=$1",
    [stageId]
  );
  await pool.query(
    `insert into input_required_attempts(
       id,organization_id,stage_id,protocol_version,protocol_header_version,
       result_meta_version,original_method,original_name,original_arguments_sha256,
       capabilities_sha256,embedded_form_sha256,embedded_result_sha256,request_state_bytes,
       request_state_sha256,prepared_request_id,retry_request_id,input_response_sha256,
       response_action,state,completed_at
     ) values ($1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call',$4,
       $5,$6,$7,$8,$9,$10,$11,$12,$13,'accept','confirmed',transaction_timestamp())`,
    [
      attemptId,
      fixture.secretary.organizationId,
      stageId,
      input.originalName,
      hash(13),
      hash(14),
      hash(15),
      hash(16),
      Buffer.alloc(32, (input.idBase + 17) % 256),
      hash(17),
      Buffer.from(`prepared-${String(input.idBase)}`),
      Buffer.from(`retry-${String(input.idBase)}`),
      hash(18)
    ]
  );
  await pool.query(
    `insert into consent_records(
       id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
       action_code,target_type,target_id,canonical_schema,payload_sha256,package_sha256,
       protected_code_record_sha256,access_token_record_id,token_jti,client_id,exact_origin,
       staged_at,record_sha256
     ) select $1,$2,$3,$4,$5,$6,$7,$15,$8,'boardagent.consent-record.v1',$9,$10,
       $11,token.id,$12,$13,'https://client.example',transaction_timestamp(),$14
         from access_token_records as token where token.jti=$12`,
    [
      consentRecordId,
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      stageId,
      attemptId,
      actionActor.memberId,
      input.actionCode,
      input.targetId,
      Buffer.from(input.payloadSha256, "hex"),
      input.packageSha256 ? Buffer.from(input.packageSha256, "hex") : null,
      hash(19),
      actionActor.tokenJti,
      actionActor.clientId,
      hash(20),
      input.targetType ?? "vote"
    ]
  );
  return { stageId, attemptId, consentRecordId };
}

async function prepareRuleOverrideFixture(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  idBase = 1650
) {
  const wizardDraftId = testId(idBase);
  const ruleOverrideId = testId(idBase + 1);
  const auditEventId = testId(idBase + 2);
  const idempotencyRecordId = testId(idBase + 3);
  const overrideConsentBase = idBase + 10;
  const overrideConsentRecordId = testId(overrideConsentBase + 2);
  const reason = "The secretary confirms the cited alternative rule for this exact vote.";
  const canonicalOverrideSha256 = ruleOverrideEvidenceHash({
    evaluationId: fixture.matterEvaluationId,
    evaluationResultSha256: fixture.matterEvaluationResultSha256,
    wizardDraftId,
    finalVoteId: fixture.voteId,
    recommendedRuleId: fixture.selectedRulesetRuleId,
    selectedRuleId: fixture.overrideRulesetRuleId,
    selectedRuleSha256: fixture.overrideRulesetRuleSha256,
    reason,
    citations: fixture.overrideRuleCitations,
    consentRecordId: overrideConsentRecordId,
    auditEventId
  });
  const decisionPackage = DecisionPackageSchema.parse({
    ...fixture.decisionPackage,
    selectedRulesetRuleId: fixture.overrideRulesetRuleId,
    selectedRulesetRuleSha256: fixture.overrideRulesetRuleSha256,
    ruleOverride: { id: ruleOverrideId, canonicalSha256: canonicalOverrideSha256 }
  });
  const packageSha256 = canonicalSha256(decisionPackage);
  await pool.query(
    `insert into wizard_drafts(
       id,organization_id,board_id,draft_type,creator_member_id,signed_context,
       context_sha256,state,ruleset_id,package_sha256,expires_at
     ) values ($1,$2,$3,'vote',$4,$5,$6,'ready_to_confirm',$7,$8,
       transaction_timestamp()+interval '5 minutes')`,
    [
      wizardDraftId,
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      fixture.secretary.memberId,
      Buffer.alloc(32, idBase % 256),
      testHash((idBase + 4) % 256),
      fixture.rulesetId,
      Buffer.from(packageSha256, "hex")
    ]
  );
  const overridePayloadSha256 = ruleOverrideConsentHash({
    evaluationId: fixture.matterEvaluationId,
    evaluationResultSha256: fixture.matterEvaluationResultSha256,
    wizardDraftId,
    finalVoteId: fixture.voteId,
    recommendedRuleId: fixture.selectedRulesetRuleId,
    selectedRuleId: fixture.overrideRulesetRuleId,
    selectedRuleSha256: fixture.overrideRulesetRuleSha256,
    reason,
    citations: fixture.overrideRuleCitations,
    packageSha256
  });
  const overrideConsent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: overrideConsentBase,
    actionCode: "create_vote",
    originalName: "create_vote",
    targetId: fixture.voteId,
    payloadSha256: overridePayloadSha256,
    packageSha256
  });
  if (overrideConsent.consentRecordId !== overrideConsentRecordId) {
    throw new Error("prepared override consent ID drifted");
  }
  const openConsent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: idBase + 20,
    actionCode: "create_vote",
    originalName: "create_vote",
    targetId: fixture.voteId,
    payloadSha256: packageSha256,
    packageSha256
  });
  const input: RecordRuleOverrideInput = {
    organizationId: fixture.secretary.organizationId,
    boardId: fixture.secretary.boardId,
    evaluationId: fixture.matterEvaluationId,
    evaluationResultSha256: fixture.matterEvaluationResultSha256,
    wizardDraftId,
    finalVoteId: fixture.voteId,
    selectedRuleId: fixture.overrideRulesetRuleId,
    selectedRuleSha256: fixture.overrideRulesetRuleSha256,
    reason,
    citations: fixture.overrideRuleCitations,
    packageSha256,
    consentRecordId: overrideConsentRecordId,
    ruleOverrideId,
    idempotencyRecordId,
    idempotencyKey: `rule-override-${String(idBase).padStart(16, "0")}`,
    auditEventId
  };
  return {
    input,
    decisionPackage,
    packageSha256,
    openConsentRecordId: openConsent.consentRecordId,
    canonicalOverrideSha256
  };
}

async function seedActiveOldVoteStage(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  stageId: string,
  packageSha256: string,
  actor: "secretary" | "voter" = "voter"
): Promise<void> {
  const stageActor = actor === "secretary" ? fixture.secretary : fixture.voter;
  await pool.query(
    `insert into action_stages(
       id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
       canonical_schema,canonicalization_version,canonical_payload,payload_sha256,
       package_sha256,nonce_sha256,protected_code_sha256,client_id,access_token_record_id,
       token_jti,exact_origin,context_sha256,state,expires_at
     ) select $1,$2,$3,$4,'cast_ballot','vote',$5,'boardagent.ballot.v1',
       'RFC8785+NFC-LF-v1','{}',$6,$6,$7,$8,$9,token.id,$10,
       'https://client.example',$11,'active',transaction_timestamp()+interval '10 minutes'
         from access_token_records as token where token.jti=$10`,
    [
      stageId,
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      stageActor.memberId,
      fixture.voteId,
      Buffer.from(packageSha256, "hex"),
      Buffer.from(canonicalSha256({ stageId }), "hex"),
      Buffer.from(canonicalSha256({ kind: "protected-code", stageId }), "hex"),
      stageActor.clientId,
      stageActor.tokenJti,
      testHash(193)
    ]
  );
}

async function seedVoteReplacementFixture(
  pool: Pool,
  options: { readonly includeAnsweredQuestion?: boolean } = {}
) {
  const fixture = await seedVoteOpenFixture(pool, options);
  await withRequestTransaction(
    pool,
    fixture.secretary.context,
    (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
    { assumeRole: "boardagent_server" }
  );
  const oldPackageSha256 = canonicalSha256(fixture.decisionPackage);
  const ballotConsent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: 400,
    actionCode: "cast_ballot",
    originalName: "cast_ballot",
    targetId: fixture.voteId,
    payloadSha256: testHash(194).toString("hex"),
    packageSha256: oldPackageSha256
  });
  const ballotId = testId(410);
  await pool.query(
    `insert into ballots(
       id,organization_id,board_id,vote_id,decision_package_id,principal_member_id,
       caster_member_id,choice,voting_weight,ballot_source,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,$6,'yes',1,'own',$7)`,
    [
      ballotId,
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      fixture.voteId,
      fixture.decisionPackageId,
      fixture.secretary.memberId,
      ballotConsent.consentRecordId
    ]
  );
  const proxyConsent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: 420,
    actionCode: "grant_proxy",
    originalName: "grant_proxy",
    targetId: fixture.voteId,
    payloadSha256: testHash(195).toString("hex"),
    packageSha256: oldPackageSha256
  });
  const proxyGrantId = testId(430);
  await pool.query(
    `insert into proxy_grants(
       id,organization_id,board_id,vote_id,principal_member_id,holder_member_id,policy,
       consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,'principal_supersedes_proxy',$7)`,
    [
      proxyGrantId,
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      fixture.voteId,
      fixture.voter.memberId,
      fixture.secretary.memberId,
      proxyConsent.consentRecordId
    ]
  );
  const activeStageId = testId(440);
  await seedActiveOldVoteStage(pool, fixture, activeStageId, oldPackageSha256);

  const newVoteId = testId(450);
  const newResolutionVersionId = testId(451);
  const decisionPackageId = testId(452);
  const newResolutionText = "RESOLVED: approve the exact replacement decision package.";
  const newResolutionSha256 = canonicalSha256({
    schemaVersion: "boardagent.resolution.v1",
    text: newResolutionText
  });
  const electorateRows = await pool.query<{
    member_id: string;
    membership_version_id: string;
    voting_weight: string;
    eligibility_snapshot: JsonValue;
  }>(
    `select member_id,membership_version_id,voting_weight::text,eligibility_snapshot
       from vote_electorate where vote_id=$1 order by member_id`,
    [fixture.voteId]
  );
  const electorate = prepareVoteElectorate({
    voteId: newVoteId,
    entries: electorateRows.rows.map((row, index) => ({
      id: testId(470 + index),
      memberId: row.member_id,
      membershipVersionId: row.membership_version_id,
      votingWeight: BigInt(row.voting_weight),
      eligibilitySnapshot: row.eligibility_snapshot
    }))
  });
  const decisionPackage = DecisionPackageSchema.parse({
    ...fixture.decisionPackage,
    voteId: newVoteId,
    resolutionVersionId: newResolutionVersionId,
    resolutionSha256: newResolutionSha256,
    electorateSha256: electorate.electorateSha256
  });
  const newPackageSha256 = canonicalSha256(decisionPackage);
  const newTitle = "Exact replacement package vote";
  const replacementReason = "The confirmed resolution bytes changed.";
  const confirmedPayloadSha256 = voteReplacementConsentHash({
    oldVoteId: fixture.voteId,
    newVoteId,
    newTitle,
    newResolutionVersionId,
    newResolutionSha256,
    decisionPackageId,
    newPackageSha256,
    reason: replacementReason
  });
  const replacementConsent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: 460,
    actionCode: "replace_open_vote",
    originalName: "replace_open_vote",
    targetId: fixture.voteId,
    payloadSha256: confirmedPayloadSha256,
    packageSha256: newPackageSha256
  });
  return {
    ...fixture,
    oldPackageSha256,
    ballotId,
    proxyGrantId,
    activeStageId,
    newVoteId,
    newResolutionVersionId,
    newResolutionText,
    replacementTitle: newTitle,
    replacementReason,
    replacementDecisionPackageId: decisionPackageId,
    replacementDecisionPackage: decisionPackage,
    replacementElectorate: electorate,
    replacementConsentRecordId: replacementConsent.consentRecordId
  };
}

function voteReplacementInput(
  fixture: Awaited<ReturnType<typeof seedVoteReplacementFixture>>,
  overrides: Partial<ReplaceVoteInput> = {}
): ReplaceVoteInput {
  return {
    organizationId: fixture.secretary.organizationId,
    oldVoteId: fixture.voteId,
    newVoteId: fixture.newVoteId,
    newTitle: fixture.replacementTitle,
    newResolutionVersionId: fixture.newResolutionVersionId,
    newResolutionText: fixture.newResolutionText,
    decisionPackageId: fixture.replacementDecisionPackageId,
    decisionPackage: fixture.replacementDecisionPackage,
    decisionPackageComponentIds: Array.from(
      { length: 7 + fixture.replacementDecisionPackage.components.length },
      (_, index) => testId(520 + index)
    ),
    questionDecisionLinkIds: fixture.replacementDecisionPackage.components
      .filter(({ type }) => type === "question_cutoff")
      .map((_, index) => testId(540 + index)),
    electorate: fixture.replacementElectorate,
    consentRecordId: fixture.replacementConsentRecordId,
    supersessionId: testId(508),
    reason: fixture.replacementReason,
    idempotencyRecordId: testId(507),
    idempotencyKey: "replace-vote-exact-package-0001",
    stageDispositions: [{ stageId: fixture.activeStageId, auditEventId: testId(480) }],
    proxyDispositions: [
      {
        proxyGrantId: fixture.proxyGrantId,
        proxyRevocationId: testId(481),
        auditEventId: testId(482)
      }
    ],
    ballotDispositions: [
      {
        ballotId: fixture.ballotId,
        ballotDispositionId: testId(483),
        auditEventId: testId(484)
      }
    ],
    feedTombstones: [
      { removedFeedId: testId(221), tombstoneId: testId(509) },
      { removedFeedId: testId(224), tombstoneId: testId(510) }
    ],
    sourceUpdateDispositions: [],
    newVoteDeliveries: [
      {
        memberId: fixture.secretary.memberId,
        noticeId: testId(490),
        feedId: testId(491),
        noticeAuditEventId: testId(492)
      },
      {
        memberId: fixture.voter.memberId,
        noticeId: testId(493),
        feedId: testId(494),
        noticeAuditEventId: testId(495)
      }
    ],
    replacementDeliveries: [
      {
        memberId: fixture.secretary.memberId,
        noticeId: testId(496),
        feedId: testId(497),
        noticeAuditEventId: testId(498)
      },
      {
        memberId: fixture.voter.memberId,
        noticeId: testId(499),
        feedId: testId(500),
        noticeAuditEventId: testId(501)
      }
    ],
    revoteDeliveries: [
      {
        memberId: fixture.secretary.memberId,
        noticeId: testId(502),
        feedId: testId(503),
        noticeAuditEventId: testId(504)
      }
    ],
    voteSupersededAuditEventId: testId(505),
    voteOpenedAuditEventId: testId(506),
    ...overrides
  };
}

interface PendingSourceCauseFixture {
  readonly causeId: string;
  readonly sourceClass: "management_submission" | "document" | "question_cutoff";
  readonly sourceId: string;
  readonly sourceVersion: number;
  readonly sourceSha256: string;
}

async function seedPendingSourceCause(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  idBase: number,
  sourceClass: PendingSourceCauseFixture["sourceClass"] = "document"
): Promise<PendingSourceCauseFixture> {
  const causeId = testId(idBase);
  const sourceId = testId(idBase + 1);
  const triggerAuditEventId = testId(idBase + 2);
  const sourceVersion = 2;
  const sourceSha256 = canonicalSha256({
    schemaVersion: "boardagent.synthetic-source-update.v1",
    sourceClass,
    sourceId,
    sourceVersion
  });
  await withRequestTransaction(
    pool,
    fixture.secretary.context,
    (client) =>
      appendAuditEventsInTransaction(client, [
        {
          organizationId: fixture.secretary.organizationId,
          event: {
            eventId: triggerAuditEventId,
            eventType: "vote_source_update_pending",
            actorMemberId: fixture.secretary.memberId,
            actorClientId: fixture.secretary.clientId,
            tokenJti: fixture.secretary.tokenJti,
            entityType: "vote",
            entityId: fixture.voteId,
            boardId: fixture.secretary.boardId,
            origin: "mcp",
            details: { causeId, sourceClass, sourceId, sourceVersion, sourceSha256 },
            schemaVersion: 1
          }
        }
      ]),
    { assumeRole: "boardagent_server" }
  );
  await pool.query(
    `insert into vote_source_update_causes(
       id,organization_id,board_id,vote_id,source_class,source_id,source_version,
       source_sha256,trigger_audit_event_id
     ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      causeId,
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      fixture.voteId,
      sourceClass,
      sourceId,
      sourceVersion,
      Buffer.from(sourceSha256, "hex"),
      triggerAuditEventId
    ]
  );
  await pool.query(
    `update votes
        set state='source_update_pending',row_version=row_version+1
      where id=$1 and state in ('open','source_update_pending')`,
    [fixture.voteId]
  );
  return { causeId, sourceClass, sourceId, sourceVersion, sourceSha256 };
}

async function confirmedSourceExclusionInput(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  cause: PendingSourceCauseFixture,
  options: {
    readonly idBase: number;
    readonly reason?: string;
    readonly actor?: Awaited<ReturnType<typeof seedAuthorizedActor>>;
  }
): Promise<ExcludePendingVoteSourceInput> {
  const reason = options.reason ?? "The secretary confirms this exact update is nonmaterial.";
  const packageSha256 = canonicalSha256(fixture.decisionPackage);
  const payloadSha256 = voteSourceExclusionConsentHash({
    voteId: fixture.voteId,
    causeId: cause.causeId,
    sourceClass: cause.sourceClass,
    sourceId: cause.sourceId,
    sourceVersion: cause.sourceVersion,
    sourceSha256: cause.sourceSha256,
    reason,
    packageSha256
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: options.idBase,
    actionCode: "exclude_pending_vote_source",
    originalName: "exclude_pending_vote_source",
    targetId: fixture.voteId,
    payloadSha256,
    packageSha256,
    ...(options.actor ? { actor: options.actor } : {})
  });
  return {
    organizationId: fixture.secretary.organizationId,
    voteId: fixture.voteId,
    causeId: cause.causeId,
    decisionPackageSha256: packageSha256,
    reason,
    consentRecordId: consent.consentRecordId,
    dispositionId: testId(options.idBase + 30),
    idempotencyRecordId: testId(options.idBase + 31),
    idempotencyKey: `exclude-pending-source-${String(options.idBase).padStart(4, "0")}`,
    auditEventId: testId(options.idBase + 32)
  };
}

async function secondVoteReplacementInput(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteReplacementFixture>>
): Promise<ReplaceVoteInput> {
  const newVoteId = testId(600);
  const newResolutionVersionId = testId(601);
  const decisionPackageId = testId(602);
  const newResolutionText = "RESOLVED: approve the second exact replacement package.";
  const resolutionSha256 = canonicalSha256({
    schemaVersion: "boardagent.resolution.v1",
    text: newResolutionText
  });
  const electorateRows = await pool.query<{
    member_id: string;
    membership_version_id: string;
    voting_weight: string;
    eligibility_snapshot: JsonValue;
  }>(
    `select member_id,membership_version_id,voting_weight::text,eligibility_snapshot
       from vote_electorate where vote_id=$1 order by member_id`,
    [fixture.newVoteId]
  );
  const electorate = prepareVoteElectorate({
    voteId: newVoteId,
    entries: electorateRows.rows.map((row, index) => ({
      id: testId(603 + index),
      memberId: row.member_id,
      membershipVersionId: row.membership_version_id,
      votingWeight: BigInt(row.voting_weight),
      eligibilitySnapshot: row.eligibility_snapshot
    }))
  });
  const decisionPackage = DecisionPackageSchema.parse({
    ...fixture.replacementDecisionPackage,
    voteId: newVoteId,
    resolutionVersionId: newResolutionVersionId,
    resolutionSha256,
    electorateSha256: electorate.electorateSha256
  });
  const packageSha256 = canonicalSha256(decisionPackage);
  const newTitle = "Second exact replacement package vote";
  const reason = "The confirmed resolution bytes changed again.";
  const confirmedPayloadSha256 = voteReplacementConsentHash({
    oldVoteId: fixture.newVoteId,
    newVoteId,
    newTitle,
    newResolutionVersionId,
    newResolutionSha256: resolutionSha256,
    decisionPackageId,
    newPackageSha256: packageSha256,
    reason
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: 610,
    actionCode: "replace_open_vote",
    originalName: "replace_open_vote",
    targetId: fixture.newVoteId,
    payloadSha256: confirmedPayloadSha256,
    packageSha256
  });
  return {
    organizationId: fixture.secretary.organizationId,
    oldVoteId: fixture.newVoteId,
    newVoteId,
    newTitle,
    newResolutionVersionId,
    newResolutionText,
    decisionPackageId,
    decisionPackage,
    decisionPackageComponentIds: Array.from({ length: 7 }, (_, index) => testId(620 + index)),
    questionDecisionLinkIds: [],
    electorate,
    consentRecordId: consent.consentRecordId,
    supersessionId: testId(647),
    reason,
    idempotencyRecordId: testId(648),
    idempotencyKey: "replace-vote-second-lineage-0001",
    stageDispositions: [],
    proxyDispositions: [],
    ballotDispositions: [],
    feedTombstones: [
      { removedFeedId: testId(494), tombstoneId: testId(627) },
      { removedFeedId: testId(503), tombstoneId: testId(628) }
    ],
    sourceUpdateDispositions: [],
    newVoteDeliveries: [
      {
        memberId: fixture.secretary.memberId,
        noticeId: testId(630),
        feedId: testId(631),
        noticeAuditEventId: testId(632)
      },
      {
        memberId: fixture.voter.memberId,
        noticeId: testId(633),
        feedId: testId(634),
        noticeAuditEventId: testId(635)
      }
    ],
    replacementDeliveries: [
      {
        memberId: fixture.secretary.memberId,
        noticeId: testId(636),
        feedId: testId(637),
        noticeAuditEventId: testId(638)
      },
      {
        memberId: fixture.voter.memberId,
        noticeId: testId(639),
        feedId: testId(640),
        noticeAuditEventId: testId(641)
      }
    ],
    revoteDeliveries: [
      {
        memberId: fixture.secretary.memberId,
        noticeId: testId(644),
        feedId: testId(645),
        noticeAuditEventId: testId(646)
      }
    ],
    voteSupersededAuditEventId: testId(642),
    voteOpenedAuditEventId: testId(643)
  };
}

async function ineligiblePrincipalReplacementInput(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteReplacementFixture>>
): Promise<ReplaceVoteInput> {
  const membership = await pool.query<{ id: string }>(
    `select id from board_memberships where board_id=$1 and member_id=$2`,
    [fixture.secretary.boardId, fixture.secretary.memberId]
  );
  const membershipId = membership.rows[0]?.id;
  if (!membershipId) throw new Error("secretary membership is unavailable");
  const managementTermsId = testId(700);
  await pool.query(
    `insert into onboarding_terms_versions(
       id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,
       material_change,effective_at,created_by
     ) values ($1,$2,'management',1,'boardagent.onboarding-terms.v1','Management terms',$3,
       true,transaction_timestamp()-interval '1 minute',$4)`,
    [managementTermsId, fixture.secretary.organizationId, testHash(201), fixture.secretary.memberId]
  );
  await pool.query(
    `insert into onboarding_attestations(
       id,organization_id,member_id,board_id,terms_version_id,support_version_id,
       presentation_choice,local_memory_choice,consent_record_id
     ) values ($1,$2,$3,$4,$5,$6,'structured','local-only',$7)`,
    [
      testId(701),
      fixture.secretary.organizationId,
      fixture.secretary.memberId,
      fixture.secretary.boardId,
      managementTermsId,
      fixture.secretary.supportVersionId,
      fixture.secretary.consentRecordId
    ]
  );
  await pool.query(
    `update board_memberships
        set seat_role='management',voting_weight=0,entitlement_generation=entitlement_generation+1
      where id=$1`,
    [membershipId]
  );
  const managementSnapshot = {
    memberId: fixture.secretary.memberId,
    eligible: false,
    reason: "secretary now holds a nonvoting management seat"
  };
  await pool.query(
    `insert into membership_versions(
       id,organization_id,board_id,member_id,membership_id,version,seat_role,is_secretary,
       voting_weight,authority_snapshot,snapshot_sha256,change_reason,actor_member_id
     ) values ($1,$2,$3,$4,$5,2,'management',true,0,$6,$7,
       'test current nonvoting seat',$4)`,
    [
      testId(702),
      fixture.secretary.organizationId,
      fixture.secretary.boardId,
      fixture.secretary.memberId,
      membershipId,
      managementSnapshot,
      Buffer.from(canonicalSha256(managementSnapshot), "hex")
    ]
  );

  const voterEvidence = await pool.query<{
    member_id: string;
    membership_version_id: string;
    voting_weight: string;
    eligibility_snapshot: JsonValue;
  }>(
    `select member_id,membership_version_id,voting_weight::text,eligibility_snapshot
       from vote_electorate where vote_id=$1 and member_id=$2`,
    [fixture.voteId, fixture.voter.memberId]
  );
  const row = voterEvidence.rows[0];
  if (!row) throw new Error("remaining eligible voter evidence is unavailable");
  const newVoteId = testId(710);
  const newResolutionVersionId = testId(711);
  const decisionPackageId = testId(712);
  const newResolutionText = "RESOLVED: approve after the prior principal became nonvoting.";
  const newResolutionSha256 = canonicalSha256({
    schemaVersion: "boardagent.resolution.v1",
    text: newResolutionText
  });
  const electorate = prepareVoteElectorate({
    voteId: newVoteId,
    entries: [
      {
        id: testId(713),
        memberId: row.member_id,
        membershipVersionId: row.membership_version_id,
        votingWeight: BigInt(row.voting_weight),
        eligibilitySnapshot: row.eligibility_snapshot
      }
    ]
  });
  const decisionPackage = DecisionPackageSchema.parse({
    ...fixture.decisionPackage,
    voteId: newVoteId,
    resolutionVersionId: newResolutionVersionId,
    resolutionSha256: newResolutionSha256,
    electorateSha256: electorate.electorateSha256
  });
  const packageSha256 = canonicalSha256(decisionPackage);
  const newTitle = "Replacement after eligibility change";
  const reason = "The prior ballot principal is no longer voting-eligible.";
  const confirmedPayloadSha256 = voteReplacementConsentHash({
    oldVoteId: fixture.voteId,
    newVoteId,
    newTitle,
    newResolutionVersionId,
    newResolutionSha256,
    decisionPackageId,
    newPackageSha256: packageSha256,
    reason
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: 720,
    actionCode: "replace_open_vote",
    originalName: "replace_open_vote",
    targetId: fixture.voteId,
    payloadSha256: confirmedPayloadSha256,
    packageSha256
  });
  return {
    organizationId: fixture.secretary.organizationId,
    oldVoteId: fixture.voteId,
    newVoteId,
    newTitle,
    newResolutionVersionId,
    newResolutionText,
    decisionPackageId,
    decisionPackage,
    decisionPackageComponentIds: Array.from({ length: 7 }, (_, index) => testId(730 + index)),
    questionDecisionLinkIds: [],
    electorate,
    consentRecordId: consent.consentRecordId,
    supersessionId: testId(755),
    reason,
    idempotencyRecordId: testId(756),
    idempotencyKey: "replace-vote-ineligible-principal-0001",
    stageDispositions: [{ stageId: fixture.activeStageId, auditEventId: testId(737) }],
    proxyDispositions: [
      {
        proxyGrantId: fixture.proxyGrantId,
        proxyRevocationId: testId(738),
        auditEventId: testId(739)
      }
    ],
    ballotDispositions: [
      {
        ballotId: fixture.ballotId,
        ballotDispositionId: testId(740),
        auditEventId: testId(741)
      }
    ],
    feedTombstones: [
      { removedFeedId: testId(221), tombstoneId: testId(753) },
      { removedFeedId: testId(224), tombstoneId: testId(754) }
    ],
    sourceUpdateDispositions: [],
    newVoteDeliveries: [
      {
        memberId: fixture.voter.memberId,
        noticeId: testId(742),
        feedId: testId(743),
        noticeAuditEventId: testId(744)
      }
    ],
    replacementDeliveries: [
      {
        memberId: fixture.secretary.memberId,
        noticeId: testId(745),
        feedId: testId(746),
        noticeAuditEventId: testId(747)
      },
      {
        memberId: fixture.voter.memberId,
        noticeId: testId(748),
        feedId: testId(749),
        noticeAuditEventId: testId(750)
      }
    ],
    revoteDeliveries: [],
    voteSupersededAuditEventId: testId(751),
    voteOpenedAuditEventId: testId(752)
  };
}

async function seedVoteRecusalFixture(pool: Pool) {
  const fixture = await seedVoteReplacementFixture(pool);
  const state = "excluded" as const;
  const reason = "  The confirmed conflict requires live recusal.  ";
  const exclusionId = testId(870);
  const payloadSha256 = voteRecusalConsentHash({
    voteId: fixture.voteId,
    memberId: fixture.secretary.memberId,
    state,
    reason,
    packageSha256: fixture.oldPackageSha256
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: 850,
    canonicalPayload: {
      schemaVersion: "boardagent.vote-recusal-consent.v1",
      voteId: fixture.voteId,
      memberId: fixture.secretary.memberId,
      state,
      reason,
      packageSha256: fixture.oldPackageSha256
    },
    actionCode: "manage_recusal",
    originalName: "manage_recusal",
    targetId: fixture.voteId,
    payloadSha256,
    packageSha256: fixture.oldPackageSha256
  });
  const recusalStageId = testId(872);
  await seedActiveOldVoteStage(
    pool,
    fixture,
    recusalStageId,
    fixture.oldPackageSha256,
    "secretary"
  );
  return {
    ...fixture,
    state,
    reason,
    exclusionId,
    recusalStageId,
    recusalConsentRecordId: consent.consentRecordId
  };
}

async function seedEligibleRecusalSecretary(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
  idBase: number
) {
  const actor = await seedAdditionalAuthorizedActor(pool, fixture.secretary, {
    idBase,
    seatRole: "management",
    isSecretary: true,
    scopes: ["secretariat:admin", "governance:read"],
    uniqueHashes: true
  });
  return administrativeService(
    pool,
    await freshAdministrativeTestCredential(pool, actor, idBase + 100)
  );
}

function voteRecusalInput(
  fixture: Awaited<ReturnType<typeof seedVoteRecusalFixture>>,
  overrides: Partial<ManageVoteRecusalInput> = {}
): ManageVoteRecusalInput {
  return {
    organizationId: fixture.secretary.organizationId,
    voteId: fixture.voteId,
    memberId: fixture.secretary.memberId,
    decisionPackageSha256: fixture.oldPackageSha256,
    state: fixture.state,
    exclusionId: fixture.exclusionId,
    reason: fixture.reason,
    consentRecordId: fixture.recusalConsentRecordId,
    idempotencyRecordId: testId(871),
    idempotencyKey: "manage-live-vote-recusal-0001",
    stageDispositions: [{ stageId: fixture.recusalStageId, auditEventId: testId(860) }],
    proxyDispositions: [
      {
        proxyGrantId: fixture.proxyGrantId,
        proxyRevocationId: testId(861),
        auditEventId: testId(862)
      }
    ],
    ballotDispositions: [
      {
        ballotId: fixture.ballotId,
        ballotDispositionId: testId(863),
        auditEventId: testId(864)
      }
    ],
    feedTombstones: [{ removedFeedId: testId(221), tombstoneId: testId(865) }],
    deliveries: [
      {
        memberId: fixture.voter.memberId,
        noticeId: testId(866),
        feedId: testId(867),
        noticeAuditEventId: testId(868)
      }
    ],
    auditEventId: testId(869),
    ...overrides
  };
}

async function seedOpenVoteActFixture(
  pool: Pool,
  options: Parameters<typeof seedVoteOpenFixture>[1] = {}
) {
  const fixture = await seedVoteOpenFixture(pool, options);
  await withRequestTransaction(
    pool,
    fixture.secretary.context,
    (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
    { assumeRole: "boardagent_server" }
  );
  return { ...fixture, packageSha256: canonicalSha256(fixture.decisionPackage) };
}

async function confirmedProxyGrantInput(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedOpenVoteActFixture>>,
  input: {
    readonly actor: typeof fixture.secretary;
    readonly holderMemberId: string;
    readonly idBase: number;
    readonly expiresAt?: string | null;
  }
): Promise<GrantProxyInput> {
  const policy = "principal_supersedes_proxy" as const;
  const expiresAt = input.expiresAt ?? null;
  const payloadSha256 = proxyGrantConsentHash({
    voteId: fixture.voteId,
    principalMemberId: input.actor.memberId,
    holderMemberId: input.holderMemberId,
    policy,
    expiresAt,
    packageSha256: fixture.packageSha256
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: input.idBase,
    actionCode: "grant_proxy",
    originalName: "grant_proxy",
    targetId: fixture.voteId,
    payloadSha256,
    packageSha256: fixture.packageSha256,
    actor: input.actor
  });
  return {
    organizationId: fixture.secretary.organizationId,
    voteId: fixture.voteId,
    holderMemberId: input.holderMemberId,
    decisionPackageSha256: fixture.packageSha256,
    policy,
    expiresAt,
    consentRecordId: consent.consentRecordId,
    proxyGrantId: testId(input.idBase + 20),
    idempotencyRecordId: testId(input.idBase + 21),
    idempotencyKey: `grant-proxy-${String(input.idBase).padStart(16, "0")}`,
    auditEventId: testId(input.idBase + 22)
  };
}

async function confirmedBallotInput(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedOpenVoteActFixture>>,
  input: {
    readonly actor: typeof fixture.secretary;
    readonly principalMemberId: string;
    readonly proxyGrantId?: string | null;
    readonly choice: "yes" | "no" | "abstain";
    readonly statement?: string | null;
    readonly idBase: number;
  }
): Promise<CastBallotInput> {
  const proxyGrantId = input.proxyGrantId ?? null;
  const statement = input.statement ?? null;
  const payloadSha256 = ballotConsentHash({
    voteId: fixture.voteId,
    principalMemberId: input.principalMemberId,
    casterMemberId: input.actor.memberId,
    choice: input.choice,
    statement,
    proxyGrantId,
    packageSha256: fixture.packageSha256
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: input.idBase,
    actionCode: "stage_ballot",
    originalName: "stage_ballot",
    targetId: fixture.voteId,
    payloadSha256,
    packageSha256: fixture.packageSha256,
    actor: input.actor
  });
  return {
    organizationId: fixture.secretary.organizationId,
    voteId: fixture.voteId,
    principalMemberId: input.principalMemberId,
    decisionPackageSha256: fixture.packageSha256,
    choice: input.choice,
    statement,
    proxyGrantId,
    consentRecordId: consent.consentRecordId,
    ballotId: testId(input.idBase + 20),
    supersessionDispositionId: testId(input.idBase + 21),
    supersessionAuditEventId: testId(input.idBase + 22),
    idempotencyRecordId: testId(input.idBase + 23),
    idempotencyKey: `cast-ballot-${String(input.idBase).padStart(16, "0")}`,
    auditEventId: testId(input.idBase + 24)
  };
}

async function confirmedProxyRevokeInput(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedOpenVoteActFixture>>,
  input: {
    readonly actor: typeof fixture.secretary;
    readonly proxyGrantId: string;
    readonly reason: string;
    readonly idBase: number;
  }
): Promise<RevokeProxyInput> {
  const payloadSha256 = proxyRevokeConsentHash({
    voteId: fixture.voteId,
    proxyGrantId: input.proxyGrantId,
    principalMemberId: input.actor.memberId,
    reason: input.reason,
    packageSha256: fixture.packageSha256
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: input.idBase,
    actionCode: "revoke_proxy",
    originalName: "revoke_proxy",
    targetId: input.proxyGrantId,
    targetType: "proxy_grant",
    payloadSha256,
    packageSha256: fixture.packageSha256,
    actor: input.actor
  });
  return {
    organizationId: fixture.secretary.organizationId,
    voteId: fixture.voteId,
    proxyGrantId: input.proxyGrantId,
    decisionPackageSha256: fixture.packageSha256,
    reason: input.reason,
    consentRecordId: consent.consentRecordId,
    proxyRevocationId: testId(input.idBase + 20),
    idempotencyRecordId: testId(input.idBase + 21),
    idempotencyKey: `revoke-proxy-${String(input.idBase).padStart(16, "0")}`,
    auditEventId: testId(input.idBase + 22)
  };
}

async function seedCloseReadyFixture(
  pool: Pool,
  ballotMember: "secretary" | "voter" = "secretary",
  options: Parameters<typeof seedVoteOpenFixture>[1] = {}
) {
  const fixture = await seedOpenVoteActFixture(pool, options);
  const ballotActor = fixture[ballotMember];
  const ballot = await confirmedBallotInput(pool, fixture, {
    actor: ballotActor,
    principalMemberId: ballotActor.memberId,
    choice: "yes",
    statement: "Approved on the exact circulated record.",
    idBase: 2300
  });
  await withRequestTransaction(
    pool,
    ballotActor.context,
    (client) => castBallotInTransaction(client, ballot),
    { assumeRole: "boardagent_server" }
  );
  const evidenceKey = generateKeyPairSync("ed25519");
  const signingKeyId = testId(2400);
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,'evidence-close-1','evidence_signing','EdDSA',$3,
       'local-test-key://evidence-close-1',transaction_timestamp()-interval '1 minute')`,
    [
      signingKeyId,
      fixture.secretary.organizationId,
      JSON.stringify(evidenceKey.publicKey.export({ format: "jwk" }))
    ]
  );
  const clockSampleId = testId(2401);
  await withWorkerTransaction(
    pool,
    (client) =>
      client.query(
        `select * from boardagent_record_clock_health(
           $1,$2,'test.ntp',transaction_timestamp(),0,
           transaction_timestamp()+interval '5 minutes'
         )`,
        [clockSampleId, fixture.secretary.organizationId]
      ),
    { assumeRole: "boardagent_worker" }
  );
  const tally = {
    schemaVersion: "boardagent.vote-tally.v1" as const,
    eligibleWeight: "2",
    participatingWeight: "1",
    yesWeight: "1",
    noWeight: "0",
    abstainWeight: "0",
    quorumMet: true,
    approvalMet: true,
    outcome: "approved" as const
  };
  const expectedTallySha256 = canonicalSha256(tally);
  const outcomeId = testId(2410);
  const certificateId = testId(2411);
  const certificatePublicId = Buffer.alloc(32, 0xa7).toString("base64url");
  const closeConsentSha256 = voteCloseConsentHash({
    voteId: fixture.voteId,
    packageSha256: fixture.packageSha256,
    expectedTallySha256,
    outcomeId,
    certificateId,
    certificatePublicIdSha256: certificatePublicIdSha256(certificatePublicId),
    signingKeyId
  });
  const closeConsent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: 2420,
    actionCode: "close_vote",
    originalName: "close_vote",
    targetId: fixture.voteId,
    payloadSha256: closeConsentSha256,
    packageSha256: fixture.packageSha256
  });
  return {
    ...fixture,
    evidenceKey,
    signingKeyId,
    clockSampleId,
    expectedTallySha256,
    outcomeId,
    certificateId,
    certificatePublicId,
    closeConsentRecordId: closeConsent.consentRecordId
  };
}

async function seedClosingVoteFixture(pool: Pool) {
  const fixture = await seedCloseReadyFixture(pool);
  const draft = await withRequestTransaction(
    pool,
    fixture.secretary.context,
    (client) =>
      initiateVoteCloseInTransaction(client, {
        organizationId: fixture.secretary.organizationId,
        voteId: fixture.voteId,
        outcomeId: fixture.outcomeId,
        certificateId: fixture.certificateId,
        certificatePublicId: fixture.certificatePublicId,
        expectedPackageSha256: fixture.packageSha256,
        expectedTallySha256: fixture.expectedTallySha256,
        signingKeyId: fixture.signingKeyId,
        consentRecordId: fixture.closeConsentRecordId,
        closingAuditEventId: testId(2430),
        idempotencyRecordId: testId(2431),
        idempotencyKey: "close-vote-scheduler-race-0001"
      }),
    { assumeRole: "boardagent_server" }
  );
  expect(draft.state).toBe("closing");
  return { ...fixture, draft };
}

async function seedAutomaticCloseReadyFixture(pool: Pool) {
  const fixture = await seedOpenVoteActFixture(pool, {
    closeMode: "automatic",
    nearTermDatabaseDeadline: true
  });
  const ballot = await confirmedBallotInput(pool, fixture, {
    actor: fixture.secretary,
    principalMemberId: fixture.secretary.memberId,
    choice: "yes",
    idBase: 2350
  });
  await withRequestTransaction(
    pool,
    fixture.secretary.context,
    (client) => castBallotInTransaction(client, ballot),
    { assumeRole: "boardagent_server" }
  );
  const evidenceKey = generateKeyPairSync("ed25519");
  const signingKeyId = testId(2450);
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,'evidence-auto-1','evidence_signing','EdDSA',$3,
       'local-test-key://evidence-auto-1',transaction_timestamp()-interval '1 minute')`,
    [
      signingKeyId,
      fixture.secretary.organizationId,
      JSON.stringify(evidenceKey.publicKey.export({ format: "jwk" }))
    ]
  );
  await withWorkerTransaction(
    pool,
    (client) =>
      client.query(
        `select * from boardagent_record_clock_health(
           $1,$2,'test.ntp',transaction_timestamp(),0,
           transaction_timestamp()+interval '5 minutes'
         )`,
        [testId(2451), fixture.secretary.organizationId]
      ),
    { assumeRole: "boardagent_worker" }
  );
  const tally = {
    schemaVersion: "boardagent.vote-tally.v1" as const,
    eligibleWeight: "2",
    participatingWeight: "1",
    yesWeight: "1",
    noWeight: "0",
    abstainWeight: "0",
    quorumMet: true,
    approvalMet: true,
    outcome: "approved" as const
  };
  return {
    ...fixture,
    evidenceKey,
    signingKeyId,
    expectedTallySha256: canonicalSha256(tally),
    outcomeId: testId(2452),
    certificateId: testId(2453),
    certificatePublicId: Buffer.alloc(32, 0xb8).toString("base64url")
  };
}

describe("vote-open transaction boundary", () => {
  it("BA58 skips a closing candidate finalized after the scheduler cursor opens and commits unrelated jobs", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedClosingVoteFixture(pool);
      const issued = issueVoteCertificate(fixture.draft.payload, fixture.evidenceKey.privateKey);
      expect(verifyVoteCertificate(issued, fixture.evidenceKey.publicKey)).toBe(true);

      // Pause the first insert, after the ordered candidate cursor has selected the
      // closing vote. A separate real request then commits its signed close while
      // that cursor still contains the old candidate. No governance guard is disabled.
      await pool.query(`
        create function public.boardagent_test_pause_periodic_clock_health()
        returns trigger language plpgsql as $$
        begin
          if new.job_type='clock_health' then
            perform pg_advisory_xact_lock(58,152);
          end if;
          return new;
        end;
        $$;
        create trigger aaa_test_pause_periodic_clock_health
        before insert on public.jobs
        for each row execute function public.boardagent_test_pause_periodic_clock_health();
      `);
      const barrier = await pool.connect();
      await barrier.query("begin");
      await barrier.query("select pg_advisory_xact_lock(58,152)");
      let schedulerPid = 0;
      const scheduling = withWorkerTransaction(
        pool,
        async (client) => {
          schedulerPid = (await client.query<{ pid: number }>("select pg_backend_pid() as pid"))
            .rows[0]!.pid;
          return schedulePeriodicJobsInTransaction(client);
        },
        { assumeRole: "boardagent_worker" }
      ).then(
        (scheduled) => ({ ok: true as const, scheduled }),
        (error: unknown) => ({ ok: false as const, error })
      );
      try {
        await expect
          .poll(
            async () =>
              (
                await pool.query<{ waiting: boolean }>(
                  `select exists (
                    select 1 from pg_locks where pid=$1 and locktype='advisory'
                      and classid=58 and objid=152 and objsubid=2 and not granted
                  ) as waiting`,
                  [schedulerPid]
                )
              ).rows[0]?.waiting,
            { timeout: 5_000, interval: 20 }
          )
          .toBe(true);
        const finalized = await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            finalizeVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              signatureBase64Url: issued.signatureBase64Url,
              certificateIssuedAuditEventId: testId(2432),
              voteClosedAuditEventId: testId(2433)
            }),
          { assumeRole: "boardagent_server" }
        );
        expect(finalized.state).toBe("closed");
        await barrier.query("commit");
        const result = await scheduling;
        if (!result.ok) throw result.error;
        expect(result.scheduled).toBeGreaterThan(0);
        expect(
          (
            await pool.query<{ job_type: string; state: string }>(
              `select job_type,state from jobs
                where job_type in ('clock_health','job_lease_reaper','vote_deadline_scan')
                order by job_type`
            )
          ).rows
        ).toEqual([
          { job_type: "clock_health", state: "queued" },
          { job_type: "job_lease_reaper", state: "queued" },
          { job_type: "vote_deadline_scan", state: "queued" }
        ]);
        expect(
          (
            await pool.query<{ count: number }>(
              "select count(*)::int as count from jobs where job_type='certificate_recovery' and subject_id=$1",
              [fixture.voteId]
            )
          ).rows[0]?.count
        ).toBe(0);
        const verification = await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            verifyPersistedVoteCertificateInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              certificatePublicId: fixture.certificatePublicId
            }),
          { assumeRole: "boardagent_server" }
        );
        expect(verification).toEqual({
          valid: true,
          voteId: fixture.voteId,
          certificateId: fixture.certificateId
        });
      } finally {
        await barrier.query("rollback");
        barrier.release();
        await scheduling;
        await pool.query(`
          drop trigger aaa_test_pause_periodic_clock_health on public.jobs;
          drop function public.boardagent_test_pause_periodic_clock_health();
        `);
      }
    });
  }, 25_000);

  it("BA58 defers a locked closing vote without blocking other jobs, then coalesces eligible recovery", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedClosingVoteFixture(pool);
      const holder = await pool.connect();
      await holder.query("begin");
      await holder.query("select id from votes where id=$1 for update", [fixture.voteId]);
      try {
        const scheduled = await withWorkerTransaction(pool, schedulePeriodicJobsInTransaction, {
          assumeRole: "boardagent_worker",
          lockTimeoutMs: 500,
          statementTimeoutMs: 2_000
        });
        expect(scheduled).toBeGreaterThan(0);
        expect(
          (
            await pool.query<{ count: number }>(
              "select count(*)::int as count from jobs where job_type='certificate_recovery' and subject_id=$1",
              [fixture.voteId]
            )
          ).rows[0]?.count
        ).toBe(0);
        expect(
          (
            await pool.query<{ state: string }>(
              "select state from jobs where job_type='clock_health'"
            )
          ).rows
        ).toEqual([{ state: "queued" }]);
      } finally {
        await holder.query("rollback");
        holder.release();
      }

      expect(
        await withWorkerTransaction(pool, schedulePeriodicJobsInTransaction, {
          assumeRole: "boardagent_worker"
        })
      ).toBe(1);
      expect(
        await withWorkerTransaction(pool, schedulePeriodicJobsInTransaction, {
          assumeRole: "boardagent_worker"
        })
      ).toBe(0);
      expect(
        (
          await pool.query<{ state: string; board_id: string; protected_producer: boolean }>(
            `select state,board_id,
                    idempotency_key like 'worker-v2:periodic:certificate_recovery:%' as protected_producer
               from jobs where job_type='certificate_recovery' and subject_id=$1`,
            [fixture.voteId]
          )
        ).rows
      ).toEqual([
        { state: "queued", board_id: fixture.secretary.boardId, protected_producer: true }
      ]);
    });
  }, 25_000);

  it("the production worker discovers and recovers a confirmed close after signer failure without an injected recovery job", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const ballot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.secretary,
        principalMemberId: fixture.secretary.memberId,
        choice: "yes",
        idBase: 2_150_000
      });
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => castBallotInTransaction(client, ballot),
        { assumeRole: "boardagent_server" }
      );
      await withConfiguredFixtureWorker(pool, fixture.secretary.organizationId, async (worker) => {
        // Normal production startup schedules its own checkpoint and clock samples.
        for (let attempt = 0; attempt < 8; attempt++) {
          if (
            (await pool.query("select count(*)::int as count from clock_health_samples")).rows[0]
              ?.count > 0
          )
            break;
          expect((await worker.worker.runOnce()).status).toBe("succeeded");
        }
        expect(
          (await pool.query("select count(*)::int as count from clock_health_samples")).rows[0]
            ?.count
        ).toBeGreaterThan(0);
        let nextId = 2_160_000;
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableSurfaceReads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(nextId++),
          voteCertificateSigner: {
            signVoteCertificate: () => Promise.reject(new Error("synthetic request signer outage"))
          }
        });
        const secretary = surfacePrincipal(
          fixture.secretary,
          ["member", "secretariat"],
          ["secretariat:admin", "governance:read", "vote:act"]
        );
        await expect(
          confirmSurfaceVoteAction(service, secretary, "close_vote", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            vote_id: fixture.voteId,
            expected_package_sha256: fixture.packageSha256,
            idempotency_key: "production-certificate-recovery-0001"
          })
        ).rejects.toThrow("synthetic request signer outage");
        expect(
          (await pool.query("select state from votes where id=$1", [fixture.voteId])).rows
        ).toEqual([{ state: "closing" }]);
        expect(
          (
            await pool.query(
              "select count(*)::int as count from jobs where job_type='certificate_recovery'"
            )
          ).rows[0]?.count
        ).toBe(0);
        expect(
          (
            await pool.query(
              "select count(*)::int as count from vote_certificates where vote_id=$1",
              [fixture.voteId]
            )
          ).rows[0]?.count
        ).toBe(0);

        const abort = new AbortController();
        let failure: unknown;
        const loop = worker.run(abort.signal).catch((error: unknown) => {
          failure = error;
        });
        try {
          await expect
            .poll(
              async () => {
                if (failure) throw failure;
                return (
                  await pool.query(
                    "select state from jobs where job_type='certificate_recovery' and subject_id=$1",
                    [fixture.voteId]
                  )
                ).rows[0]?.state;
              },
              { timeout: 10_000, interval: 50 }
            )
            .toBe("succeeded");
          const certificate = (
            await pool.query("select public_id from vote_certificates where vote_id=$1", [
              fixture.voteId
            ])
          ).rows;
          expect(certificate).toHaveLength(1);
          expect(
            await withRequestTransaction(
              pool,
              fixture.secretary.context,
              (client) =>
                verifyPersistedVoteCertificateInTransaction(client, {
                  organizationId: fixture.secretary.organizationId,
                  certificatePublicId: (certificate[0]!.public_id as Buffer).toString("base64url")
                }),
              { assumeRole: "boardagent_server" }
            )
          ).toMatchObject({ valid: true });
          expect(
            (
              await pool.query(
                `select vote.state,event.actor_member_id,
            event.consent_record_id=outcome.close_consent_record_id as original_consent,
            convert_from(event.canonical_payload,'UTF8')::jsonb->>'origin' as origin
            from votes as vote join vote_outcomes as outcome on outcome.vote_id=vote.id
            join audit_events as event on event.object_id=vote.id
            where vote.id=$1 and event.event_type='vote_closed'`,
                [fixture.voteId]
              )
            ).rows
          ).toEqual([
            {
              state: "closed",
              actor_member_id: fixture.secretary.memberId,
              original_consent: true,
              origin: "worker"
            }
          ]);
          expect(
            (
              await pool.query(
                "select idempotency_key like 'worker-v2:periodic:certificate_recovery:%' as protected_producer from jobs where job_type='certificate_recovery' and subject_id=$1",
                [fixture.voteId]
              )
            ).rows
          ).toEqual([{ protected_producer: true }]);
        } finally {
          abort.abort();
          await loop;
        }
      });
    });
  }, 25_000);

  it("BA58 sibling: the deadline scan defers a due automatic vote until a healthy clock sample exists instead of raising 23514", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool, {
        closeMode: "automatic",
        nearTermDatabaseDeadline: true
      });
      const organizationId = fixture.secretary.organizationId;
      const boardId = fixture.secretary.boardId;
      await pool.query(
        "select pg_sleep(greatest(0,extract(epoch from ($1::timestamptz-clock_timestamp()))+0.05))",
        [fixture.deadlineAt]
      );
      expect(
        (await pool.query("select count(*)::int as count from clock_health_samples")).rows[0]?.count
      ).toBe(0);
      const through = async () =>
        (
          await pool.query<{ through: string }>(
            `select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as through`
          )
        ).rows[0]!.through;
      let counter = 0;
      const newId = () => testId(990_100 + counter++);
      const scan = (watermark: string) =>
        withWorkerTransaction(
          pool,
          (client) =>
            scheduleDueAutomaticVoteClosesInTransaction(client, {
              organizationId,
              boardId,
              through: watermark,
              newId,
              limit: 100
            }),
          { assumeRole: "boardagent_worker" }
        );
      const jobs = () =>
        pool.query<{ count: number }>(
          "select count(*)::int as count from jobs where job_type='automatic_vote_close' and subject_id=$1",
          [fixture.voteId]
        );
      // Due, but the typed-job guard would refuse without a current healthy clock sample:
      // the scan must leave the vote for a later tick rather than fail the scan job.
      expect(await scan(await through())).toEqual([]);
      expect((await jobs()).rows[0]?.count).toBe(0);
      expect(
        (await pool.query("select state from votes where id=$1", [fixture.voteId])).rows[0]?.state
      ).toBe("open");
      // An expired or unhealthy sample is not a current one either.
      await pool.query(
        `insert into clock_health_samples(id,organization_id,source,measured_at,
         drift_microseconds,valid_until) values($1,$2,'synthetic-stale',
         transaction_timestamp()-interval '10 minutes',0,transaction_timestamp()-interval '5 minutes')`,
        [testId(990_050), organizationId]
      );
      expect(await scan(await through())).toEqual([]);
      expect((await jobs()).rows[0]?.count).toBe(0);
      // With a current healthy sample the same scan enqueues exactly one close job.
      await pool.query(
        `insert into clock_health_samples(id,organization_id,source,measured_at,
         drift_microseconds,valid_until) values($1,$2,'synthetic-current',
         transaction_timestamp(),0,transaction_timestamp()+interval '5 minutes')`,
        [testId(990_051), organizationId]
      );
      const scheduled = await scan(await through());
      expect(scheduled).toHaveLength(1);
      expect(scheduled[0]).toMatchObject({ voteId: fixture.voteId, replayed: false });
      expect((await jobs()).rows[0]?.count).toBe(1);
      // A repeated scan replays the same job instead of inserting another.
      expect(await scan(await through())).toEqual([]);
      expect((await jobs()).rows[0]?.count).toBe(1);
    });
  }, 25_000);

  it("the production worker schedules clock health and closes a due automatic vote without injected work", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool, {
        closeMode: "automatic",
        nearTermDatabaseDeadline: true
      });
      expect(
        (await pool.query("select count(*)::int as count from clock_health_samples")).rows[0]?.count
      ).toBe(0);
      expect(
        (
          await pool.query(
            "select count(*)::int as count from jobs where job_type in ('clock_health','vote_deadline_scan','automatic_vote_close')"
          )
        ).rows[0]?.count
      ).toBe(0);
      await pool.query(
        "select pg_sleep(greatest(0,extract(epoch from ($1::timestamptz-clock_timestamp()))+0.05))",
        [fixture.deadlineAt]
      );
      await withConfiguredFixtureWorker(pool, fixture.secretary.organizationId, async (worker) => {
        const abort = new AbortController();
        let error: unknown;
        const loop = worker.run(abort.signal).catch((value: unknown) => {
          error = value;
        });
        try {
          await expect
            .poll(
              async () => {
                if (error) throw error;
                return (await pool.query("select state from votes where id=$1", [fixture.voteId]))
                  .rows[0]?.state;
              },
              { timeout: 10_000, interval: 50 }
            )
            .toBe("closed");
          // Finish any in-flight job before inspecting its committed state.
          abort.abort();
          await loop;
          if (error) throw error;
          const certificate = await pool.query(
            "select public_id from vote_certificates where vote_id=$1",
            [fixture.voteId]
          );
          expect(certificate.rows).toHaveLength(1);
          const verified = await withRequestTransaction(
            pool,
            fixture.secretary.context,
            (client) =>
              verifyPersistedVoteCertificateInTransaction(client, {
                organizationId: fixture.secretary.organizationId,
                certificatePublicId: (certificate.rows[0]!.public_id as Buffer).toString(
                  "base64url"
                )
              }),
            { assumeRole: "boardagent_server" }
          );
          expect(verified).toMatchObject({ valid: true });
          const jobs = await pool.query(
            "select job_type,state from jobs where job_type in ('clock_health','vote_deadline_scan','automatic_vote_close') order by job_type"
          );
          expect(jobs.rows.filter(({ job_type }) => job_type === "automatic_vote_close")).toEqual([
            { job_type: "automatic_vote_close", state: "succeeded" }
          ]);
          for (const jobType of ["clock_health", "vote_deadline_scan"]) {
            const periodicJobs = jobs.rows.filter(({ job_type }) => job_type === jobType);
            expect(periodicJobs.some(({ state }) => state === "succeeded")).toBe(true);
            // A real database-minute boundary may schedule another periodic job.
            // A later queued job is legitimate after graceful stop; failed/retry/leased is not.
            expect(
              periodicJobs.every(({ state }) => state === "succeeded" || state === "queued")
            ).toBe(true);
          }
        } finally {
          abort.abort();
          await loop;
        }
      });
    });
  }, 25_000);

  it("AC16 preserves a departed director's ballot, electorate, deadlines and verified certificate through delegated replacement", async () => {
    await withDatabase(async (pool) => {
      const f = await seedCloseReadyFixture(pool, "voter");
      const draft = await withRequestTransaction(
        pool,
        f.secretary.context,
        (client) =>
          initiateVoteCloseInTransaction(client, {
            organizationId: f.secretary.organizationId,
            voteId: f.voteId,
            outcomeId: f.outcomeId,
            certificateId: f.certificateId,
            certificatePublicId: f.certificatePublicId,
            expectedPackageSha256: f.packageSha256,
            expectedTallySha256: f.expectedTallySha256,
            signingKeyId: f.signingKeyId,
            consentRecordId: f.closeConsentRecordId,
            closingAuditEventId: testId(195_000),
            idempotencyRecordId: testId(195_001),
            idempotencyKey: "history-close-director-vote-0001"
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(draft.payload.ballots).toHaveLength(1);
      expect(draft.payload.ballots[0]).toMatchObject({
        principalMemberId: f.voter.memberId,
        casterMemberId: f.voter.memberId
      });
      const issued = issueVoteCertificate(draft.payload, f.evidenceKey.privateKey);
      expect(verifyVoteCertificate(issued, f.evidenceKey.publicKey)).toBe(true);
      const result = await withRequestTransaction(
        pool,
        f.secretary.context,
        (client) =>
          finalizeVoteCloseInTransaction(client, {
            organizationId: f.secretary.organizationId,
            voteId: f.voteId,
            outcomeId: f.outcomeId,
            certificateId: f.certificateId,
            signatureBase64Url: issued.signatureBase64Url,
            certificateIssuedAuditEventId: testId(195_002),
            voteClosedAuditEventId: testId(195_003)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(result.state).toBe("closed");
      const history = await preserveHistoricRecords(pool, [
        "votes",
        "decision_packages",
        "decision_package_components",
        "vote_electorate",
        "ballots",
        "ballot_dispositions",
        "vote_outcomes",
        "vote_certificates",
        "membership_versions",
        "consent_records",
        "audit_events"
      ]);
      expect(history.counts).toMatchObject({
        votes: 1,
        vote_electorate: 2,
        ballots: 1,
        vote_outcomes: 1,
        vote_certificates: 1
      });
      const { successorId } = await replaceDirectorThroughDelegate(
        pool,
        f.secretary,
        f.voter,
        history.assertPreserved
      );
      const verification = await withIdentityTransaction(
        pool,
        { organizationId: f.secretary.organizationId, boardIds: [] },
        (client) =>
          verifyPublicPersistedVoteCertificateInTransaction(client, {
            certificatePublicId: f.certificatePublicId
          }),
        { isolation: "read committed", assumeRole: "boardagent_server" }
      );
      expect(verification).toEqual({ valid: true });
      expect(verifyVoteCertificate(issued, f.evidenceKey.publicKey)).toBe(true);
      expect(
        (
          await pool.query("select count(*)::int as n from vote_electorate where member_id=$1", [
            successorId
          ])
        ).rows[0]
      ).toEqual({ n: 0 });
      await history.assertPreserved();
    });
  }, 60_000);

  it("MR-MEC-001 chair appointment preserves the closed electorate and certificate while the next creation snapshot binds the new chair version", async () => {
    await withDatabase(async (pool) => {
      const f = await seedCloseReadyFixture(pool, "voter");
      const draft = await withRequestTransaction(
        pool,
        f.secretary.context,
        (client) =>
          initiateVoteCloseInTransaction(client, {
            organizationId: f.secretary.organizationId,
            voteId: f.voteId,
            outcomeId: f.outcomeId,
            certificateId: f.certificateId,
            certificatePublicId: f.certificatePublicId,
            expectedPackageSha256: f.packageSha256,
            expectedTallySha256: f.expectedTallySha256,
            signingKeyId: f.signingKeyId,
            consentRecordId: f.closeConsentRecordId,
            closingAuditEventId: testId(195_000),
            idempotencyRecordId: testId(195_001),
            idempotencyKey: "history-close-before-chair-0001"
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(draft.payload.ballots).toHaveLength(1);
      expect(draft.payload.ballots[0]).toMatchObject({
        principalMemberId: f.voter.memberId,
        casterMemberId: f.voter.memberId
      });
      const issued = issueVoteCertificate(draft.payload, f.evidenceKey.privateKey);
      expect(verifyVoteCertificate(issued, f.evidenceKey.publicKey)).toBe(true);
      const result = await withRequestTransaction(
        pool,
        f.secretary.context,
        (client) =>
          finalizeVoteCloseInTransaction(client, {
            organizationId: f.secretary.organizationId,
            voteId: f.voteId,
            outcomeId: f.outcomeId,
            certificateId: f.certificateId,
            signatureBase64Url: issued.signatureBase64Url,
            certificateIssuedAuditEventId: testId(195_002),
            voteClosedAuditEventId: testId(195_003)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(result.state).toBe("closed");
      const history = await preserveHistoricRecords(pool, [
        "votes",
        "decision_packages",
        "decision_package_components",
        "vote_electorate",
        "ballots",
        "ballot_dispositions",
        "vote_outcomes",
        "vote_certificates",
        "membership_versions",
        "consent_records",
        "audit_events"
      ]);
      expect(history.counts).toMatchObject({
        votes: 1,
        vote_electorate: 2,
        ballots: 1,
        vote_outcomes: 1,
        vote_certificates: 1
      });
      await pool.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Synthetic chair history administrator')",
        [testId(197000), f.secretary.organizationId, f.secretary.memberId]
      );
      const admin = await freshAdministrativeTestCredential(pool, f.secretary, 197010);
      const staged = await stageAdministrativeAction(pool, admin, "manage_member", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        idempotency_key: "history-chair-appointment-0001",
        change: {
          operation: "change_seat",
          member_id: f.voter.memberId,
          board_id: admin.boardId,
          seat_role: "voting_member",
          voting_weight: 1,
          is_secretary: false,
          is_chair: true,
          reason:
            "New chair appointment applies to current authority, never rewrites closed evidence"
        }
      });
      expect((await staged.confirm()).confirmed).toBe(true);
      await history.assertPreserved();
      const current = await withRequestTransaction(
        pool,
        admin.context,
        async (client) =>
          (
            await client.query(
              "select member_id,membership_version_id,is_chair from boardagent_lock_vote_creation_electorate($1)",
              [admin.boardId]
            )
          ).rows,
        { assumeRole: "boardagent_server" }
      );
      const nextChair = current.find((row) => row.member_id === f.voter.memberId);
      expect(nextChair).toMatchObject({ is_chair: true });
      expect(
        (
          await pool.query("select is_chair from membership_versions where id=$1", [
            nextChair.membership_version_id
          ])
        ).rows
      ).toEqual([{ is_chair: true }]);
      const frozen = (
        await pool.query(
          "select is_chair,membership_version_id from vote_electorate where vote_id=$1 and member_id=$2",
          [f.voteId, f.voter.memberId]
        )
      ).rows[0];
      expect(frozen.is_chair).toBe(false);
      expect(nextChair.membership_version_id).not.toBe(frozen.membership_version_id);
      const verification = await withIdentityTransaction(
        pool,
        { organizationId: admin.organizationId, boardIds: [] },
        (client) =>
          verifyPublicPersistedVoteCertificateInTransaction(client, {
            certificatePublicId: f.certificatePublicId
          }),
        { isolation: "read committed", assumeRole: "boardagent_server" }
      );
      expect(verification).toEqual({ valid: true });
      expect(verifyVoteCertificate(issued, f.evidenceKey.publicKey)).toBe(true);
      await history.assertPreserved();
    });
  }, 60_000);

  it("preserves an open vote electorate and package when an administrator changes a current seat weight", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      await pool.query(
        "insert into organization_role_assignments(id,organization_id,member_id,role,change_reason) values($1,$2,$3,'admin','Synthetic lifecycle regression')",
        [testId(193000), fixture.secretary.organizationId, fixture.secretary.memberId]
      );
      await pool.query(
        "insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at) values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',transaction_timestamp()+interval '1 hour',transaction_timestamp())",
        [
          testId(193001),
          fixture.secretary.organizationId,
          testHash(211),
          fixture.secretary.memberId,
          fixture.secretary.clientId
        ]
      );
      await pool.query("update access_token_records set session_id=$1 where id=$2", [
        testId(193001),
        fixture.secretary.accessTokenRecordId
      ]);
      const before = (
        await pool.query("select * from vote_electorate where vote_id=$1 order by member_id", [
          fixture.voteId
        ])
      ).rows;
      const packages = (
        await pool.query("select * from decision_packages where id=$1", [fixture.decisionPackageId])
      ).rows;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: {
          executeRead: async () => {
            throw new Error("unused read");
          },
          readResource: async () => {
            throw new Error("unused resource");
          }
        },
        transaction: { assumeRole: "boardagent_server" }
      });
      const actor = {
        ...surfacePrincipal(fixture.secretary, ["member", "secretariat"], ["secretariat:admin"]),
        protocolClientId: "authorized-test-client",
        roles: ["admin", "member", "secretariat"] as const
      };
      await confirmSurfaceVoteAction(service, actor, "manage_member", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        change: {
          operation: "change_seat",
          member_id: fixture.voter.memberId,
          board_id: fixture.secretary.boardId,
          seat_role: "voting_member",
          voting_weight: 7,
          is_secretary: false,
          reason: "Synthetic seat weight change during existing vote"
        },
        idempotency_key: "seat-weight-frozen-vote-0001"
      });
      expect(
        (
          await pool.query("select voting_weight::text from board_memberships where member_id=$1", [
            fixture.voter.memberId
          ])
        ).rows[0]
      ).toEqual({ voting_weight: "7" });
      expect(
        (
          await pool.query("select * from vote_electorate where vote_id=$1 order by member_id", [
            fixture.voteId
          ])
        ).rows
      ).toEqual(before);
      expect(
        (
          await pool.query("select * from decision_packages where id=$1", [
            fixture.decisionPackageId
          ])
        ).rows
      ).toEqual(packages);
      expect(
        (await pool.query("select state from votes where id=$1", [fixture.voteId])).rows[0]
      ).toEqual({ state: "open" });
    });
  });

  it("freezes persisted truth and commits every entitled delivery before one vote-open event", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      const result = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );

      expect(result).toMatchObject({
        replayed: false,
        voteId: fixture.voteId,
        decisionPackageId: fixture.decisionPackageId,
        state: "open"
      });
      const persisted = await pool.query<{
        state: string;
        package_hash: string;
        electorate_count: string;
        notice_count: string;
        feed_count: string;
        event_types: string[];
      }>(
        `select vote.state,
                encode(package.package_sha256,'hex') as package_hash,
                (select count(*)::text from vote_electorate where vote_id=vote.id) as electorate_count,
                (select count(*)::text from notices where object_id=vote.id) as notice_count,
                (select count(*)::text from pending_action_feed where object_id=vote.id) as feed_count,
                (select array_agg(event_type order by sequence) from audit_events) as event_types
           from votes as vote
           join decision_packages as package on package.id=vote.current_decision_package_id
          where vote.id=$1`,
        [fixture.voteId]
      );
      expect(persisted.rows[0]).toEqual({
        state: "open",
        package_hash: canonicalSha256(fixture.decisionPackage),
        electorate_count: "2",
        notice_count: "2",
        feed_count: "2",
        event_types: ["matter_evaluated", "notice_delivered", "notice_delivered", "vote_opened"]
      });
      const replayed = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      expect(replayed).toMatchObject({
        replayed: true,
        voteId: fixture.voteId,
        decisionPackageId: fixture.decisionPackageId,
        responseSha256: result.responseSha256
      });
    });
  });

  it("serializes concurrent identical opens into one commit and one safe replay", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      const results = await Promise.all(
        [0, 1].map(() =>
          withRequestTransaction(
            pool,
            fixture.secretary.context,
            (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
            { assumeRole: "boardagent_server" }
          )
        )
      );
      expect(results.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);
      const counts = await pool.query<{
        packages: string;
        electorate: string;
        notices: string;
        events: string;
      }>(
        `select
           (select count(*)::text from decision_packages where vote_id=$1) as packages,
           (select count(*)::text from vote_electorate where vote_id=$1) as electorate,
           (select count(*)::text from notices where object_id=$1) as notices,
           (select count(*)::text from audit_events where object_id=$1) as events`,
        [fixture.voteId]
      );
      expect(counts.rows[0]).toEqual({
        packages: "1",
        electorate: "2",
        notices: "2",
        events: "3"
      });
    });
  });

  it("rejects nonsecretary context and a package that no longer matches confirmed bytes", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await expect(
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_open_unavailable" });
      const changedPackage = DecisionPackageSchema.parse({
        ...fixture.decisionPackage,
        deadlineAt: "2099-10-01T12:00:00Z"
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            openVoteInTransaction(
              client,
              voteOpenInput(fixture, { decisionPackage: changedPackage })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_open_unavailable" });
      const state = await pool.query<{ state: string; packages: string; audit_events: string }>(
        `select state,
                (select count(*)::text from decision_packages where vote_id=$1) as packages,
                (select count(*)::text from audit_events where object_id=$1) as audit_events
           from votes where id=$1`,
        [fixture.voteId]
      );
      expect(state.rows[0]).toEqual({ state: "draft", packages: "0", audit_events: "0" });
    });
  });

  it("persists an exact answered Q&A cutoff link that satisfies the close state wall", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool, { includeAnsweredQuestion: true });
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const linked = await pool.query<{
        manifest_count: string;
        component_count: string;
        link_count: string;
        cutoff_ordinal: number;
        cutoff_sha256: string;
      }>(
        `select jsonb_array_length(package.question_cutoff_manifest)::text as manifest_count,
                (select count(*)::text from decision_package_components
                  where decision_package_id=package.id) as component_count,
                (select count(*)::text from question_decision_links
                  where decision_package_id=package.id) as link_count,
                link.inclusive_turn_ordinal as cutoff_ordinal,
                encode(link.inclusive_turn_sha256,'hex') as cutoff_sha256
           from decision_packages as package
           join question_decision_links as link on link.decision_package_id=package.id
          where package.id=$1`,
        [fixture.decisionPackageId]
      );
      expect(linked.rows[0]).toEqual({
        manifest_count: "1",
        component_count: "8",
        link_count: "1",
        cutoff_ordinal: 2,
        cutoff_sha256: fixture.decisionPackage.components[0]!.sha256
      });
      const closing = await pool.query<{ ready: boolean }>(
        `select boardagent_vote_qna_close_ready($1) as ready`,
        [fixture.voteId]
      );
      expect(closing.rows).toEqual([{ ready: true }]);
    });
  });

  it.each([
    { label: "ordinary rule", approvalRule: {} },
    { label: "forbidden proxies", approvalRule: { proxyPolicy: "forbidden" as const } },
    { label: "zero quorum", approvalRule: { quorum: { numerator: 0, denominator: 1 } } },
    { label: "zero approval", approvalRule: { approval: { numerator: 0, denominator: 1 } } }
  ])(
    "MR-CERT-001 agrees on authenticated and public certificate verification for $label",
    async ({ approvalRule }) => {
      await withDatabase(async (pool) => {
        const fixture = await seedCloseReadyFixture(pool, "secretary", { approvalRule });
        const draft = await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            initiateVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              certificatePublicId: fixture.certificatePublicId,
              expectedPackageSha256: fixture.packageSha256,
              expectedTallySha256: fixture.expectedTallySha256,
              signingKeyId: fixture.signingKeyId,
              consentRecordId: fixture.closeConsentRecordId,
              closingAuditEventId: testId(2430),
              idempotencyRecordId: testId(2431),
              idempotencyKey: "public-certificate-rule-boundary-0001"
            }),
          { assumeRole: "boardagent_server" }
        );
        const issued = issueVoteCertificate(draft.payload, fixture.evidenceKey.privateKey);
        expect(verifyVoteCertificate(issued, fixture.evidenceKey.publicKey)).toBe(true);
        const finalized = await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            finalizeVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              signatureBase64Url: issued.signatureBase64Url,
              certificateIssuedAuditEventId: testId(2432),
              voteClosedAuditEventId: testId(2433)
            }),
          { assumeRole: "boardagent_server" }
        );
        expect(finalized).toMatchObject({ state: "closed", payloadSha256: issued.payloadSha256 });
        const authenticated = () =>
          withRequestTransaction(
            pool,
            fixture.secretary.context,
            (client) =>
              verifyPersistedVoteCertificateInTransaction(client, {
                organizationId: fixture.secretary.organizationId,
                certificatePublicId: fixture.certificatePublicId
              }),
            { assumeRole: "boardagent_server" }
          );
        const anonymous = () =>
          withIdentityTransaction(
            pool,
            { organizationId: fixture.secretary.organizationId, boardIds: [] },
            (client) =>
              verifyPublicPersistedVoteCertificateInTransaction(client, {
                certificatePublicId: fixture.certificatePublicId
              }),
            { isolation: "read committed", assumeRole: "boardagent_server" }
          );
        expect(await authenticated()).toEqual({
          valid: true,
          voteId: fixture.voteId,
          certificateId: fixture.certificateId
        });
        expect.soft(await anonymous()).toEqual({ valid: true });

        // The broader admitted rule vocabulary must not turn signature corruption
        // into a valid certificate. This changes only the disposable attack fixture.
        await pool.query("alter table vote_certificates disable trigger boardagent_immutable");
        await pool.query(
          "update vote_certificates set signature=decode(repeat('00',64),'hex') where id=$1",
          [fixture.certificateId]
        );
        await pool.query("alter table vote_certificates enable trigger boardagent_immutable");
        expect(await authenticated()).toEqual({ valid: false });
        expect(await anonymous()).toEqual({ valid: false });
      });
    }
  );

  it("persists a recomputable close draft, survives signer failure, and closes only with its trusted Ed25519 certificate", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCloseReadyFixture(pool);
      const closeInput = {
        organizationId: fixture.secretary.organizationId,
        voteId: fixture.voteId,
        outcomeId: fixture.outcomeId,
        certificateId: fixture.certificateId,
        certificatePublicId: fixture.certificatePublicId,
        expectedPackageSha256: fixture.packageSha256,
        expectedTallySha256: fixture.expectedTallySha256,
        signingKeyId: fixture.signingKeyId,
        consentRecordId: fixture.closeConsentRecordId,
        closingAuditEventId: testId(2430),
        idempotencyRecordId: testId(2431),
        idempotencyKey: "close-vote-recoverable-0001"
      } as const;
      const draft = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => initiateVoteCloseInTransaction(client, closeInput),
        { assumeRole: "boardagent_server" }
      );
      expect(draft).toMatchObject({
        replayed: false,
        voteId: fixture.voteId,
        outcomeId: fixture.outcomeId,
        certificateId: fixture.certificateId,
        state: "closing",
        payloadSha256: canonicalSha256(draft.payload)
      });
      expect(draft.payload.tally).toEqual({
        schemaVersion: "boardagent.vote-tally.v1",
        eligibleWeight: "2",
        participatingWeight: "1",
        yesWeight: "1",
        noWeight: "0",
        abstainWeight: "0",
        quorumMet: true,
        approvalMet: true,
        outcome: "approved"
      });
      expect(draft.payload.ballots).toHaveLength(1);
      expect(draft.payload.ballots[0]).toMatchObject({
        principalMemberId: fixture.secretary.memberId,
        casterMemberId: fixture.secretary.memberId,
        source: "own"
      });
      const draftReplay = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => initiateVoteCloseInTransaction(client, closeInput),
        { assumeRole: "boardagent_server" }
      );
      expect(draftReplay).toMatchObject({
        replayed: true,
        state: "closing",
        responseSha256: draft.responseSha256,
        payloadSha256: draft.payloadSha256
      });

      const attacker = generateKeyPairSync("ed25519");
      const forged = issueVoteCertificate(draft.payload, attacker.privateKey);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            finalizeVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              signatureBase64Url: forged.signatureBase64Url,
              certificateIssuedAuditEventId: testId(2432),
              voteClosedAuditEventId: testId(2433)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_close_signer_invalid" });
      const afterFailure = await pool.query<{ state: string; certificates: string }>(
        `select state,
                (select count(*)::text from vote_certificates where vote_id=$1) as certificates
           from votes where id=$1`,
        [fixture.voteId]
      );
      expect(afterFailure.rows[0]).toEqual({ state: "closing", certificates: "0" });

      const issued = issueVoteCertificate(draft.payload, fixture.evidenceKey.privateKey);
      expect(verifyVoteCertificate(issued, fixture.evidenceKey.publicKey)).toBe(true);
      const finalizeInput = {
        organizationId: fixture.secretary.organizationId,
        voteId: fixture.voteId,
        outcomeId: fixture.outcomeId,
        certificateId: fixture.certificateId,
        signatureBase64Url: issued.signatureBase64Url,
        certificateIssuedAuditEventId: testId(2432),
        voteClosedAuditEventId: testId(2433)
      } as const;
      const finalized = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => finalizeVoteCloseInTransaction(client, finalizeInput),
        { assumeRole: "boardagent_server" }
      );
      expect(finalized).toMatchObject({
        replayed: false,
        state: "closed",
        payloadSha256: draft.payloadSha256
      });
      const finalizeReplay = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => finalizeVoteCloseInTransaction(client, finalizeInput),
        { assumeRole: "boardagent_server" }
      );
      expect(finalizeReplay).toMatchObject({
        replayed: true,
        state: "closed",
        payloadSha256: draft.payloadSha256
      });
      const certificateMetadata = await pool.query<{ issued_at: string }>(
        `select to_char(issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as issued_at
           from vote_certificates where id=$1`,
        [fixture.certificateId]
      );
      const certificateBundle = {
        schema_version: "boardagent.vote-certificate-bundle.v1" as const,
        certificate_id: fixture.certificateId,
        vote_id: fixture.voteId,
        outcome_id: fixture.outcomeId,
        public_id: fixture.certificatePublicId,
        canonical_payload: draft.payload,
        payload_sha256: issued.payloadSha256,
        signature_base64url: issued.signatureBase64Url,
        signing_key: {
          id: fixture.signingKeyId,
          kid: "evidence-close-1",
          algorithm: "EdDSA" as const,
          public_jwk: fixture.evidenceKey.publicKey.export({ format: "jwk" })
        },
        issued_at: certificateMetadata.rows[0]!.issued_at
      };
      const verification = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          verifyPersistedVoteCertificateInTransaction(client, {
            organizationId: fixture.secretary.organizationId,
            certificatePublicId: fixture.certificatePublicId
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(verification).toEqual({
        valid: true,
        voteId: fixture.voteId,
        certificateId: fixture.certificateId
      });
      const publicVerification = await withIdentityTransaction(
        pool,
        { organizationId: fixture.secretary.organizationId, boardIds: [] },
        (client) =>
          verifyPublicPersistedVoteCertificateInTransaction(client, {
            certificatePublicId: fixture.certificatePublicId
          }),
        { isolation: "read committed", assumeRole: "boardagent_server" }
      );
      expect(publicVerification).toEqual({ valid: true });
      const publicBundleVerification = await withIdentityTransaction(
        pool,
        { organizationId: fixture.secretary.organizationId, boardIds: [] },
        (client) =>
          verifyPublicPersistedVoteCertificateInTransaction(client, {
            certificatePublicId: fixture.certificatePublicId,
            assertedBundle: certificateBundle
          }),
        { isolation: "read committed", assumeRole: "boardagent_server" }
      );
      expect(publicBundleVerification).toEqual({ valid: true });
      const mismatchedPublicBundleVerification = await withIdentityTransaction(
        pool,
        { organizationId: fixture.secretary.organizationId, boardIds: [] },
        (client) =>
          verifyPublicPersistedVoteCertificateInTransaction(client, {
            certificatePublicId: fixture.certificatePublicId,
            assertedBundle: { ...certificateBundle, issued_at: "2026-09-01T00:00:00.000000Z" }
          }),
        { isolation: "read committed", assumeRole: "boardagent_server" }
      );
      expect(mismatchedPublicBundleVerification).toEqual({ valid: false });
      const unknownVerification = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          verifyPersistedVoteCertificateInTransaction(client, {
            organizationId: fixture.secretary.organizationId,
            certificatePublicId: Buffer.alloc(32, 0xc9).toString("base64url")
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(unknownVerification).toEqual({ valid: false });
      const unknownPublicVerification = await withIdentityTransaction(
        pool,
        { organizationId: fixture.secretary.organizationId, boardIds: [] },
        (client) =>
          verifyPublicPersistedVoteCertificateInTransaction(client, {
            certificatePublicId: Buffer.alloc(32, 0xc9).toString("base64url")
          }),
        { isolation: "read committed", assumeRole: "boardagent_server" }
      );
      expect(unknownPublicVerification).toEqual({ valid: false });

      const publicVerifier = new PgPublicCertificateVerifier(
        pool,
        new PgRateLimiter(pool, {
          hmacKey: Buffer.alloc(32, 0xd1),
          assumeRole: "boardagent_server"
        }),
        {
          organizationId: fixture.secretary.organizationId,
          policy: { windowSeconds: 60, maxRequests: 3, blockSeconds: 60 },
          assumeRole: "boardagent_server"
        }
      );
      const publicIpClass = "ipv4:198.51.100.0/24";
      await expect(
        publicVerifier.verify({
          candidatePublicId: null,
          candidateBundle: null,
          clientIpClass: publicIpClass
        })
      ).resolves.toEqual({ status: "complete", valid: false });
      await expect(
        publicVerifier.verify({
          candidatePublicId: null,
          candidateBundle: certificateBundle,
          clientIpClass: publicIpClass
        })
      ).resolves.toEqual({ status: "complete", valid: true });
      await expect(
        publicVerifier.verify({
          candidatePublicId: fixture.certificatePublicId,
          candidateBundle: null,
          clientIpClass: publicIpClass
        })
      ).resolves.toEqual({ status: "complete", valid: true });
      await expect(
        publicVerifier.verify({
          candidatePublicId: Buffer.alloc(32, 0xda).toString("base64url"),
          candidateBundle: null,
          clientIpClass: publicIpClass
        })
      ).resolves.toMatchObject({
        status: "rate_limited",
        retryAfterSeconds: expect.any(Number)
      });

      await pool.query("alter table vote_certificates disable trigger boardagent_immutable");
      await pool.query(
        "update vote_certificates set signature=decode(repeat('00',64),'hex') where id=$1",
        [fixture.certificateId]
      );
      await pool.query("alter table vote_certificates enable trigger boardagent_immutable");
      const tamperedPublicVerification = await withIdentityTransaction(
        pool,
        { organizationId: fixture.secretary.organizationId, boardIds: [] },
        (client) =>
          verifyPublicPersistedVoteCertificateInTransaction(client, {
            certificatePublicId: fixture.certificatePublicId
          }),
        { isolation: "read committed", assumeRole: "boardagent_server" }
      );
      expect(tamperedPublicVerification).toEqual({ valid: false });
      const lineage = await pool.query<{ types: string[]; outcome: string; state: string }>(
        `select array_agg(event_type order by sequence) filter (
                  where event_type in ('vote_closing','certificate_issued','vote_closed')
                ) as types,
                (select outcome from vote_outcomes where vote_id=$1) as outcome,
                (select state from votes where id=$1) as state
           from audit_events`,
        [fixture.voteId]
      );
      expect(lineage.rows[0]).toEqual({
        types: ["vote_closing", "certificate_issued", "vote_closed"],
        outcome: "approved",
        state: "closed"
      });
    });
  });

  it("seeds automatic-close deadlines from the database despite application clock skew", async () => {
    await withDatabase(async (pool) => {
      const applicationClock = vi.spyOn(Date, "now").mockReturnValue(Date.now() - 60_000);
      let fixture: Awaited<ReturnType<typeof seedAutomaticCloseReadyFixture>>;
      try {
        fixture = await seedAutomaticCloseReadyFixture(pool);
      } finally {
        applicationClock.mockRestore();
      }
      const timing = await pool.query<{ valid: boolean; bound: boolean }>(
        `select deadline_at > created_at as valid, deadline_at=$2::timestamptz as bound
           from votes where id=$1`,
        [fixture.voteId, fixture.decisionPackage.deadlineAt]
      );
      expect(timing.rows).toEqual([{ valid: true, bound: true }]);
    });
  }, 30_000);

  it("suppresses automatic close before deadline and lets only the worker close after healthy-clock expiry", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedAutomaticCloseReadyFixture(pool);
      const automaticInput = {
        organizationId: fixture.secretary.organizationId,
        voteId: fixture.voteId,
        outcomeId: fixture.outcomeId,
        certificateId: fixture.certificateId,
        certificatePublicId: fixture.certificatePublicId,
        expectedPackageSha256: fixture.packageSha256,
        expectedTallySha256: fixture.expectedTallySha256,
        signingKeyId: fixture.signingKeyId,
        closingAuditEventId: testId(2454)
      } as const;
      await expect(
        withWorkerTransaction(
          pool,
          (client) => initiateAutomaticVoteCloseInTransaction(client, automaticInput),
          { assumeRole: "boardagent_worker" }
        )
      ).rejects.toMatchObject({ code: "vote_close_unavailable" });
      await pool.query(
        `select pg_sleep(greatest(
           0,
           extract(epoch from ($1::timestamptz-clock_timestamp())) + 0.05
         ))`,
        [fixture.deadlineAt]
      );
      const deadlineScanJobId = testId(2460);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: deadlineScanJobId,
            idempotencyKey: "vote-deadline-scan-worker-0001",
            availableAt: "2020-01-01T00:00:00Z",
            envelope: {
              schemaVersion: "boardagent.job.vote_deadline_scan.v1",
              organizationId: fixture.secretary.organizationId,
              boardId: fixture.secretary.boardId,
              jobType: "vote_deadline_scan",
              subjectType: "board",
              subjectId: fixture.secretary.boardId,
              parameters: { through: fixture.deadlineAt }
            }
          }),
        { assumeRole: "boardagent_server" }
      );
      const worker = await voteWorker(
        pool,
        fixture.secretary,
        fixture.evidenceKey.privateKey,
        fixture.signingKeyId,
        "local-test-key://evidence-auto-1",
        970_000
      );
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: deadlineScanJobId,
        jobType: "vote_deadline_scan"
      });
      await pool.query(
        `update jobs set available_at='2099-01-01T00:00:00Z'
          where job_type='notice_fanout' and state in ('queued','retry')`
      );
      const automaticJobId = testId(970_000);
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: automaticJobId,
        jobType: "automatic_vote_close"
      });
      const automaticCertificate = await pool.query<{ close: JsonValue }>(
        `select convert_from(canonical_payload,'UTF8')::jsonb->'close' as close
           from vote_certificates where vote_id=$1`,
        [fixture.voteId]
      );
      expect(automaticCertificate.rows[0]?.close).toMatchObject({
        actorMemberId: null,
        consentRecordId: null,
        consentRecordSha256: null
      });
      const automaticEvents = await pool.query<{
        actor_member_id: string | null;
        event_type: string;
        origin: string;
      }>(
        `select event_type,actor_member_id,
                convert_from(canonical_payload,'UTF8')::jsonb->>'origin' as origin
           from audit_events
          where event_type in ('vote_closing','certificate_issued','vote_closed')
          order by sequence`
      );
      expect(automaticEvents.rows).toEqual([
        { event_type: "vote_closing", actor_member_id: null, origin: "worker" },
        { event_type: "certificate_issued", actor_member_id: null, origin: "worker" },
        { event_type: "vote_closed", actor_member_id: null, origin: "worker" }
      ]);
    });
  }, 30_000);

  it("denies direct close writes and suppresses close on unhealthy clock or pending source evidence", async () => {
    await withDatabase(async (pool) => {
      const directFixture = await seedOpenVoteActFixture(pool);
      await expect(
        withRequestTransaction(
          pool,
          directFixture.secretary.context,
          (client) =>
            client.query("update votes set state='closing',row_version=row_version+1 where id=$1", [
              directFixture.voteId
            ]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/cannot enter closing without its immutable outcome/u);
      await expect(
        withRequestTransaction(
          pool,
          directFixture.secretary.context,
          (client) => client.query("insert into vote_outcomes(id) values ($1)", [testId(2490)]),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/permission denied for table vote_outcomes/u);
    });

    await withDatabase(async (pool) => {
      const unhealthy = await seedCloseReadyFixture(pool);
      await withWorkerTransaction(
        pool,
        (client) =>
          client.query(
            `select * from boardagent_record_clock_health(
               $1,$2,'test.ntp',transaction_timestamp(),2000001,
               transaction_timestamp()+interval '5 minutes'
             )`,
            [testId(2491), unhealthy.secretary.organizationId]
          ),
        { assumeRole: "boardagent_worker" }
      );
      const unhealthyInput = {
        organizationId: unhealthy.secretary.organizationId,
        voteId: unhealthy.voteId,
        outcomeId: unhealthy.outcomeId,
        certificateId: unhealthy.certificateId,
        certificatePublicId: unhealthy.certificatePublicId,
        expectedPackageSha256: unhealthy.packageSha256,
        expectedTallySha256: unhealthy.expectedTallySha256,
        signingKeyId: unhealthy.signingKeyId,
        consentRecordId: unhealthy.closeConsentRecordId,
        closingAuditEventId: testId(2492),
        idempotencyRecordId: testId(2493),
        idempotencyKey: "close-vote-unhealthy-clock-0001"
      } as const;
      await expect(
        withRequestTransaction(
          pool,
          unhealthy.secretary.context,
          (client) => initiateVoteCloseInTransaction(client, unhealthyInput),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_close_clock_unhealthy" });
      const noDraft = await pool.query<{ outcomes: string; state: string }>(
        `select state,
                (select count(*)::text from vote_outcomes where vote_id=$1) as outcomes
           from votes where id=$1`,
        [unhealthy.voteId]
      );
      expect(noDraft.rows[0]).toEqual({ state: "open", outcomes: "0" });
    });

    await withDatabase(async (pool) => {
      const pending = await seedCloseReadyFixture(pool);
      await seedPendingSourceCause(pool, pending, 2494);
      await expect(
        withRequestTransaction(
          pool,
          pending.secretary.context,
          (client) =>
            initiateVoteCloseInTransaction(client, {
              organizationId: pending.secretary.organizationId,
              voteId: pending.voteId,
              outcomeId: pending.outcomeId,
              certificateId: pending.certificateId,
              certificatePublicId: pending.certificatePublicId,
              expectedPackageSha256: pending.packageSha256,
              expectedTallySha256: pending.expectedTallySha256,
              signingKeyId: pending.signingKeyId,
              consentRecordId: pending.closeConsentRecordId,
              closingAuditEventId: testId(2497),
              idempotencyRecordId: testId(2498),
              idempotencyKey: "close-vote-source-pending-0001"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_close_source_pending" });
    });
  }, 30_000);

  it("detects persisted outcome tampering before certificate issuance and remains recoverably closing", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCloseReadyFixture(pool);
      const draft = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          initiateVoteCloseInTransaction(client, {
            organizationId: fixture.secretary.organizationId,
            voteId: fixture.voteId,
            outcomeId: fixture.outcomeId,
            certificateId: fixture.certificateId,
            certificatePublicId: fixture.certificatePublicId,
            expectedPackageSha256: fixture.packageSha256,
            expectedTallySha256: fixture.expectedTallySha256,
            signingKeyId: fixture.signingKeyId,
            consentRecordId: fixture.closeConsentRecordId,
            closingAuditEventId: testId(2500),
            idempotencyRecordId: testId(2501),
            idempotencyKey: "close-vote-tamper-detection-0001"
          }),
        { assumeRole: "boardagent_server" }
      );
      await pool.query("alter table vote_outcomes disable trigger boardagent_immutable");
      await pool.query(
        `update vote_outcomes
            set canonical_tally=jsonb_set(canonical_tally,'{yesWeight}','"999"'::jsonb)
          where id=$1`,
        [fixture.outcomeId]
      );
      await pool.query("alter table vote_outcomes enable trigger boardagent_immutable");
      const issued = issueVoteCertificate(draft.payload, fixture.evidenceKey.privateKey);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            finalizeVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              signatureBase64Url: issued.signatureBase64Url,
              certificateIssuedAuditEventId: testId(2502),
              voteClosedAuditEventId: testId(2503)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_close_integrity_failure" });
      const state = await pool.query<{ state: string; certificates: string }>(
        `select state,
                (select count(*)::text from vote_certificates where vote_id=$1) as certificates
           from votes where id=$1`,
        [fixture.voteId]
      );
      expect(state.rows[0]).toEqual({ state: "closing", certificates: "0" });
    });
  });

  it("serializes a final ballot against close so the confirmed tally is never silently stale", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCloseReadyFixture(pool);
      const finalBallot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.voter,
        principalMemberId: fixture.voter.memberId,
        choice: "yes",
        idBase: 2520
      });
      const results = await Promise.allSettled([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            initiateVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              certificatePublicId: fixture.certificatePublicId,
              expectedPackageSha256: fixture.packageSha256,
              expectedTallySha256: fixture.expectedTallySha256,
              signingKeyId: fixture.signingKeyId,
              consentRecordId: fixture.closeConsentRecordId,
              closingAuditEventId: testId(2550),
              idempotencyRecordId: testId(2551),
              idempotencyKey: "close-vote-final-ballot-race-0001"
            }),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => castBallotInTransaction(client, finalBallot),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      const persisted = await pool.query<{
        active_ballots: string;
        outcomes: string;
        state: string;
      }>(
        `select vote.state,
                (select count(*)::text from vote_outcomes where vote_id=vote.id) as outcomes,
                (select count(*)::text
                   from ballots as ballot
                   left join ballot_dispositions as disposition
                     on disposition.prior_ballot_id=ballot.id
                  where ballot.vote_id=vote.id and disposition.id is null) as active_ballots
           from votes as vote where vote.id=$1`,
        [fixture.voteId]
      );
      const row = persisted.rows[0];
      expect(
        (row?.state === "closing" && row.outcomes === "1" && row.active_ballots === "1") ||
          (row?.state === "open" && row.outcomes === "0" && row.active_ballots === "2")
      ).toBe(true);
    });
  });

  it("rolls close initiation and finalization back when their required final audit append fails", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCloseReadyFixture(pool);
      const seedCollision = (eventId: string) =>
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            appendAuditEventsInTransaction(client, [
              {
                organizationId: fixture.secretary.organizationId,
                event: {
                  eventId,
                  eventType: "context_read",
                  actorMemberId: fixture.secretary.memberId,
                  actorClientId: fixture.secretary.clientId,
                  tokenJti: fixture.secretary.tokenJti,
                  entityType: "vote",
                  entityId: fixture.voteId,
                  boardId: fixture.secretary.boardId,
                  origin: "mcp",
                  details: { test: "forced_audit_id_collision" },
                  schemaVersion: 1
                }
              }
            ]),
          { assumeRole: "boardagent_server" }
        );
      await seedCollision(testId(2560));
      const closeInput = {
        organizationId: fixture.secretary.organizationId,
        voteId: fixture.voteId,
        outcomeId: fixture.outcomeId,
        certificateId: fixture.certificateId,
        certificatePublicId: fixture.certificatePublicId,
        expectedPackageSha256: fixture.packageSha256,
        expectedTallySha256: fixture.expectedTallySha256,
        signingKeyId: fixture.signingKeyId,
        consentRecordId: fixture.closeConsentRecordId,
        closingAuditEventId: testId(2560),
        idempotencyRecordId: testId(2561),
        idempotencyKey: "close-vote-audit-rollback-0001"
      } as const;
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => initiateVoteCloseInTransaction(client, closeInput),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const initiationRollback = await pool.query<{
        idempotency: string;
        outcomes: string;
        state: string;
      }>(
        `select state,
                (select count(*)::text from vote_outcomes where vote_id=$1) as outcomes,
                (select count(*)::text from idempotency_records where id=$2) as idempotency
           from votes where id=$1`,
        [fixture.voteId, closeInput.idempotencyRecordId]
      );
      expect(initiationRollback.rows[0]).toEqual({
        state: "open",
        outcomes: "0",
        idempotency: "0"
      });
      const draft = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          initiateVoteCloseInTransaction(client, {
            ...closeInput,
            closingAuditEventId: testId(2562)
          }),
        { assumeRole: "boardagent_server" }
      );
      await seedCollision(testId(2563));
      const issued = issueVoteCertificate(draft.payload, fixture.evidenceKey.privateKey);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            finalizeVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              signatureBase64Url: issued.signatureBase64Url,
              certificateIssuedAuditEventId: testId(2563),
              voteClosedAuditEventId: testId(2564)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const finalizationRollback = await pool.query<{ certificates: string; state: string }>(
        `select state,
                (select count(*)::text from vote_certificates where vote_id=$1) as certificates
           from votes where id=$1`,
        [fixture.voteId]
      );
      expect(finalizationRollback.rows[0]).toEqual({ state: "closing", certificates: "0" });
      const recovered = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          finalizeVoteCloseInTransaction(client, {
            organizationId: fixture.secretary.organizationId,
            voteId: fixture.voteId,
            outcomeId: fixture.outcomeId,
            certificateId: fixture.certificateId,
            signatureBase64Url: issued.signatureBase64Url,
            certificateIssuedAuditEventId: testId(2565),
            voteClosedAuditEventId: testId(2566)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(recovered.state).toBe("closed");
    });
  });

  it("rolls the whole open back on final audit failure and permits a clean retry", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        async (client) => {
          await appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: testId(235),
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "member",
                entityId: fixture.secretary.memberId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { purpose: "vote-open crash fixture" },
                schemaVersion: 1
              }
            }
          ]);
        },
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "23505" });
      const rolledBack = await pool.query<{
        state: string;
        packages: string;
        electorate: string;
        notices: string;
        idempotency: string;
      }>(
        `select state,
                (select count(*)::text from decision_packages where vote_id=$1) as packages,
                (select count(*)::text from vote_electorate where vote_id=$1) as electorate,
                (select count(*)::text from notices where object_id=$1) as notices,
                (select count(*)::text from idempotency_records
                  where operation='create_vote') as idempotency
           from votes where id=$1`,
        [fixture.voteId]
      );
      expect(rolledBack.rows[0]).toEqual({
        state: "draft",
        packages: "0",
        electorate: "0",
        notices: "0",
        idempotency: "0"
      });
      const retried = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          openVoteInTransaction(client, voteOpenInput(fixture, { auditEventId: testId(237) })),
        { assumeRole: "boardagent_server" }
      );
      expect(retried).toMatchObject({ replayed: false, state: "open" });
    });
  });
});

describe("rule-override transaction boundary", () => {
  it("records one exact confirmed override, safely replays it and opens only its bound package", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      const prepared = await prepareRuleOverrideFixture(pool, fixture);
      const results = await Promise.all(
        [0, 1].map(() =>
          withRequestTransaction(
            pool,
            fixture.secretary.context,
            (client) => recordRuleOverrideInTransaction(client, prepared.input),
            { assumeRole: "boardagent_server" }
          )
        )
      );
      expect(results.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);
      expect(results[0]).toMatchObject({
        ruleOverrideId: prepared.input.ruleOverrideId,
        canonicalSha256: prepared.canonicalOverrideSha256
      });

      const opened = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          openVoteInTransaction(
            client,
            voteOpenInput(fixture, {
              decisionPackage: prepared.decisionPackage,
              consentRecordId: prepared.openConsentRecordId
            })
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(opened).toMatchObject({ replayed: false, state: "open" });
      const persisted = await pool.query<{
        matter_evaluation_id: string;
        selected_ruleset_rule_id: string;
        rule_override_id: string;
        vote_override_sha256: string;
        package_override_sha256: string;
        override_events: string;
      }>(
        `select vote.matter_evaluation_id,vote.selected_ruleset_rule_id,vote.rule_override_id,
                encode(vote.rule_override_sha256,'hex') as vote_override_sha256,
                encode(package.rule_override_sha256,'hex') as package_override_sha256,
                (select count(*)::text from audit_events
                  where event_type='rule_overridden' and object_id=vote.rule_override_id)
                  as override_events
           from votes as vote
           join decision_packages as package on package.id=vote.current_decision_package_id
          where vote.id=$1`,
        [fixture.voteId]
      );
      expect(persisted.rows[0]).toEqual({
        matter_evaluation_id: fixture.matterEvaluationId,
        selected_ruleset_rule_id: fixture.overrideRulesetRuleId,
        rule_override_id: prepared.input.ruleOverrideId,
        vote_override_sha256: prepared.canonicalOverrideSha256,
        package_override_sha256: prepared.canonicalOverrideSha256,
        override_events: "1"
      });
      await expect(
        pool.query("update rule_overrides set reason='mutated' where id=$1", [
          prepared.input.ruleOverrideId
        ])
      ).rejects.toMatchObject({ code: "55000" });
    });
  });

  it("rejects an unproved selection, tampered evidence and a profile-forbidden override", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      const unprovedPackage = DecisionPackageSchema.parse({
        ...fixture.decisionPackage,
        selectedRulesetRuleId: fixture.overrideRulesetRuleId,
        selectedRulesetRuleSha256: fixture.overrideRulesetRuleSha256,
        ruleOverride: null
      });
      const unprovedSha256 = canonicalSha256(unprovedPackage);
      const unprovedConsent = await seedConfirmedVoteAction(pool, fixture, {
        idBase: 1690,
        actionCode: "create_vote",
        originalName: "create_vote",
        targetId: fixture.voteId,
        payloadSha256: unprovedSha256,
        packageSha256: unprovedSha256
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            openVoteInTransaction(
              client,
              voteOpenInput(fixture, {
                decisionPackage: unprovedPackage,
                consentRecordId: unprovedConsent.consentRecordId
              })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_package_invalid" });

      const prepared = await prepareRuleOverrideFixture(pool, fixture, 1700);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            recordRuleOverrideInTransaction(client, {
              ...prepared.input,
              reason: `${prepared.input.reason} tampered`
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "rule_override_unavailable" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            recordRuleOverrideInTransaction(client, {
              ...prepared.input,
              citations: [
                { ...prepared.input.citations[0]!, clause: "Tampered alternative clause" }
              ]
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "rule_override_invalid" });
      const absent = await pool.query<{ overrides: string; override_events: string }>(
        `select (select count(*)::text from rule_overrides) as overrides,
                (select count(*)::text from audit_events where event_type='rule_overridden')
                  as override_events`
      );
      expect(absent.rows[0]).toEqual({ overrides: "0", override_events: "0" });
    });

    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool, { overridePolicy: "forbidden" });
      const prepared = await prepareRuleOverrideFixture(pool, fixture, 1740);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => recordRuleOverrideInTransaction(client, prepared.input),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "rule_override_invalid" });
    });
  });

  it("rolls back all override state on required audit failure and permits a clean retry", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      const failed = await prepareRuleOverrideFixture(pool, fixture, 1780);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: failed.input.auditEventId,
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "member",
                entityId: fixture.secretary.memberId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { purpose: "rule-override crash fixture" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => recordRuleOverrideInTransaction(client, failed.input),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "23505" });
      const rolledBack = await pool.query<{ overrides: string; idempotency: string }>(
        `select (select count(*)::text from rule_overrides) as overrides,
                (select count(*)::text from idempotency_records
                  where operation='record_rule_override') as idempotency`
      );
      expect(rolledBack.rows[0]).toEqual({ overrides: "0", idempotency: "0" });

      const retry = await prepareRuleOverrideFixture(pool, fixture, 1820);
      const recorded = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => recordRuleOverrideInTransaction(client, retry.input),
        { assumeRole: "boardagent_server" }
      );
      expect(recorded).toMatchObject({
        replayed: false,
        ruleOverrideId: retry.input.ruleOverrideId
      });
    });
  });
});

describe("vote-replacement transaction boundary", () => {
  it("atomically opens an empty replacement, dispositions every old act and emits exact recipient deltas", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const result = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => replaceVoteInTransaction(client, voteReplacementInput(fixture)),
        { assumeRole: "boardagent_server" }
      );

      expect(result).toMatchObject({
        replayed: false,
        oldVoteId: fixture.voteId,
        newVoteId: fixture.newVoteId,
        decisionPackageId: fixture.replacementDecisionPackageId,
        state: "open",
        changedComponentClasses: ["resolution"]
      });
      const votes = await pool.query<{
        id: string;
        state: string;
        current_decision_package_id: string;
      }>(
        `select id,state,current_decision_package_id
           from votes where id in ($1,$2) order by id`,
        [fixture.voteId, fixture.newVoteId]
      );
      expect(votes.rows).toEqual([
        {
          id: fixture.voteId,
          state: "superseded",
          current_decision_package_id: fixture.decisionPackageId
        },
        {
          id: fixture.newVoteId,
          state: "open",
          current_decision_package_id: fixture.replacementDecisionPackageId
        }
      ]);
      const noCarry = await pool.query<{
        ballots: string;
        proxies: string;
        stages: string;
      }>(
        `select
           (select count(*)::text from ballots where vote_id=$1) as ballots,
           (select count(*)::text from proxy_grants where vote_id=$1) as proxies,
           (select count(*)::text from action_stages where target_type='vote' and target_id=$1)
             as stages`,
        [fixture.newVoteId]
      );
      expect(noCarry.rows[0]).toEqual({ ballots: "0", proxies: "0", stages: "0" });
      const dispositions = await pool.query<{
        stage_state: string;
        proxy_effect: string;
        ballot_effect: string;
        replacement_vote_id: string;
      }>(
        `select stage.state as stage_state,
                revocation.effect as proxy_effect,
                disposition.effect as ballot_effect,
                disposition.replacement_vote_id
           from action_stages as stage
           cross join proxy_revocations as revocation
           cross join ballot_dispositions as disposition
          where stage.id=$1 and revocation.grant_id=$2 and disposition.prior_ballot_id=$3`,
        [fixture.activeStageId, fixture.proxyGrantId, fixture.ballotId]
      );
      expect(dispositions.rows[0]).toEqual({
        stage_state: "replaced",
        proxy_effect: "superseded",
        ballot_effect: "invalidated_by_vote_replacement",
        replacement_vote_id: fixture.newVoteId
      });
      const feeds = await pool.query<{
        action_type: string;
        member_id: string;
        state: string;
        payload: Record<string, unknown>;
      }>(
        `select action_type,member_id,state,convert_from(canonical_payload,'UTF8')::jsonb as payload
           from pending_action_feed
          where (object_id=$2 and action_type in ('vote_opened','revote_required'))
             or (object_id=$1 and action_type='vote_replaced')
          order by action_type,member_id`,
        [fixture.voteId, fixture.newVoteId]
      );
      expect(
        feeds.rows.map(({ action_type, member_id, state }) => ({
          action_type,
          member_id,
          state
        }))
      ).toEqual([
        {
          action_type: "revote_required",
          member_id: fixture.secretary.memberId,
          state: "pending"
        },
        {
          action_type: "vote_opened",
          member_id: fixture.secretary.memberId,
          state: "resolved"
        },
        {
          action_type: "vote_opened",
          member_id: fixture.voter.memberId,
          state: "pending"
        },
        {
          action_type: "vote_replaced",
          member_id: fixture.secretary.memberId,
          state: "resolved"
        },
        {
          action_type: "vote_replaced",
          member_id: fixture.voter.memberId,
          state: "resolved"
        }
      ]);
      expect(
        feeds.rows.every(
          ({ payload }) =>
            Array.isArray(payload["changedComponentClasses"]) && payload["safeRefs"] !== undefined
        )
      ).toBe(true);
      const oldActions = await pool.query<{ count: string }>(
        `select count(*)::text as count
           from pending_action_feed
          where object_id=$1 and action_type='vote_opened' and state='superseded'`,
        [fixture.voteId]
      );
      expect(oldActions.rows[0]?.count).toBe("2");
      const events = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where object_id in ($1,$2,$3,$4,$5)
          order by sequence`,
        [
          fixture.activeStageId,
          fixture.proxyGrantId,
          fixture.ballotId,
          fixture.voteId,
          fixture.newVoteId
        ]
      );
      expect(events.rows.map(({ event_type }) => event_type).slice(-10)).toEqual([
        "stage_replaced",
        "proxy_revoked",
        "ballot_superseded",
        "vote_superseded",
        "vote_opened",
        "notice_delivered",
        "notice_delivered",
        "vote_replaced",
        "vote_replaced",
        "revote_required"
      ]);
    });
  });

  it("rejects a post-confirmation title or reason change with zero replacement mutation", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            replaceVoteInTransaction(
              client,
              voteReplacementInput(fixture, { reason: "Unconfirmed changed reason." })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("unavailable");
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            replaceVoteInTransaction(
              client,
              voteReplacementInput(fixture, { newTitle: "Unconfirmed changed title" })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow("unavailable");
      const state = await pool.query<{ state: string; replacements: string }>(
        `select vote.state,
                (select count(*)::text from vote_supersessions where old_vote_id=vote.id)
                  as replacements
           from votes as vote where vote.id=$1`,
        [fixture.voteId]
      );
      expect(state.rows[0]).toEqual({ state: "open", replacements: "0" });
    });
  });

  it("persists exact confirmed canonical text and rejects any attempted canonical repair", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const exactInput = voteReplacementInput(fixture, {
        newTitle: "  Exact replacement title  ",
        reason: "  Exact confirmed replacement reason.  "
      });
      const packageSha256 = canonicalSha256(exactInput.decisionPackage);
      const payloadSha256 = voteReplacementConsentHash({
        oldVoteId: exactInput.oldVoteId,
        newVoteId: exactInput.newVoteId,
        newTitle: exactInput.newTitle,
        newResolutionVersionId: exactInput.newResolutionVersionId,
        newResolutionSha256: exactInput.decisionPackage.resolutionSha256,
        decisionPackageId: exactInput.decisionPackageId,
        newPackageSha256: packageSha256,
        reason: exactInput.reason
      });
      const consent = await seedConfirmedVoteAction(pool, fixture, {
        idBase: 810,
        actionCode: "replace_open_vote",
        originalName: "replace_open_vote",
        targetId: fixture.voteId,
        payloadSha256,
        packageSha256
      });
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          replaceVoteInTransaction(client, {
            ...exactInput,
            consentRecordId: consent.consentRecordId
          }),
        { assumeRole: "boardagent_server" }
      );
      const exact = await pool.query<{ reason: string; title: string }>(
        `select vote.title,supersession.reason
           from votes as vote
           join vote_supersessions as supersession on supersession.new_vote_id=vote.id
          where vote.id=$1`,
        [fixture.newVoteId]
      );
      expect(exact.rows).toEqual([
        {
          title: "  Exact replacement title  ",
          reason: "  Exact confirmed replacement reason.  "
        }
      ]);
    });

    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            replaceVoteInTransaction(
              client,
              voteReplacementInput(fixture, {
                newResolutionText: "line one\r\nline two"
              })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/LF line endings/u);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            replaceVoteInTransaction(
              client,
              voteReplacementInput(fixture, { newTitle: "Cafe\u0301" })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/Unicode NFC/u);
    });
  });

  it("rejects a semantic no-op despite fresh vote-bound IDs and hashes", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const oldResolutionText = "RESOLVED: approve the exact persisted decision package.";
      const noOpPackage = DecisionPackageSchema.parse({
        ...fixture.decisionPackage,
        voteId: fixture.newVoteId,
        resolutionVersionId: fixture.newResolutionVersionId,
        electorateSha256: fixture.replacementElectorate.electorateSha256
      });
      const noOpInput = voteReplacementInput(fixture, {
        newResolutionText: oldResolutionText,
        decisionPackage: noOpPackage
      });
      const packageSha256 = canonicalSha256(noOpPackage);
      const payloadSha256 = voteReplacementConsentHash({
        oldVoteId: noOpInput.oldVoteId,
        newVoteId: noOpInput.newVoteId,
        newTitle: noOpInput.newTitle,
        newResolutionVersionId: noOpInput.newResolutionVersionId,
        newResolutionSha256: noOpPackage.resolutionSha256,
        decisionPackageId: noOpInput.decisionPackageId,
        newPackageSha256: packageSha256,
        reason: noOpInput.reason
      });
      const consent = await seedConfirmedVoteAction(pool, fixture, {
        idBase: 820,
        actionCode: "replace_open_vote",
        originalName: "replace_open_vote",
        targetId: fixture.voteId,
        payloadSha256,
        packageSha256
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            replaceVoteInTransaction(client, {
              ...noOpInput,
              consentRecordId: consent.consentRecordId
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/at least one changed package component/u);
      const source = await pool.query<{ state: string }>("select state from votes where id=$1", [
        fixture.voteId
      ]);
      expect(source.rows).toEqual([{ state: "open" }]);
    });
  });

  it("rejects an arbitrary same-board approval rule without selection evidence", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const alternateRule = {
        schemaVersion: "boardagent.approval-rule.v1",
        thresholdNumerator: 2,
        thresholdDenominator: 3,
        quorumNumerator: 1,
        quorumDenominator: 2,
        approvalDenominator: "eligible",
        abstentionsCountForQuorum: true,
        tieBehavior: "reject",
        proxyPolicy: "principal_supersedes_proxy",
        closeMode: "secretariat_confirmed"
      } as const;
      const alternateRuleId = testId(829);
      const alternateRuleSha256 = canonicalSha256(alternateRule);
      await pool.query(
        `insert into approval_rules(
           id,organization_id,board_id,schema_version,threshold_numerator,
           threshold_denominator,quorum_numerator,quorum_denominator,approval_denominator,
           abstentions_count_for_quorum,tie_behavior,proxy_policy,close_mode,canonical_sha256,
           created_by
         ) values ($1,$2,$3,'boardagent.approval-rule.v1',2,3,1,2,'eligible',true,'reject',
           'principal_supersedes_proxy','secretariat_confirmed',$4,$5)`,
        [
          alternateRuleId,
          fixture.secretary.organizationId,
          fixture.secretary.boardId,
          Buffer.from(alternateRuleSha256, "hex"),
          fixture.secretary.memberId
        ]
      );
      const changedPackage = DecisionPackageSchema.parse({
        ...fixture.replacementDecisionPackage,
        approvalRuleId: alternateRuleId,
        approvalRuleSha256: alternateRuleSha256
      });
      const changedInput = voteReplacementInput(fixture, { decisionPackage: changedPackage });
      const packageSha256 = canonicalSha256(changedPackage);
      const payloadSha256 = voteReplacementConsentHash({
        oldVoteId: changedInput.oldVoteId,
        newVoteId: changedInput.newVoteId,
        newTitle: changedInput.newTitle,
        newResolutionVersionId: changedInput.newResolutionVersionId,
        newResolutionSha256: changedPackage.resolutionSha256,
        decisionPackageId: changedInput.decisionPackageId,
        newPackageSha256: packageSha256,
        reason: changedInput.reason
      });
      const consent = await seedConfirmedVoteAction(pool, fixture, {
        idBase: 830,
        actionCode: "replace_open_vote",
        originalName: "replace_open_vote",
        targetId: fixture.voteId,
        payloadSha256,
        packageSha256
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            replaceVoteInTransaction(client, {
              ...changedInput,
              consentRecordId: consent.consentRecordId
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_replacement_unavailable" });
    });
  });

  it("fails closed until every pending source cause is incorporated and dispositioned", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool, { includeAnsweredQuestion: true });
      const questionComponent = fixture.replacementDecisionPackage.components[0];
      if (!questionComponent || questionComponent.type !== "question_cutoff") {
        throw new Error("source-update replacement fixture lacks its question cutoff");
      }
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: testId(800),
                eventType: "vote_source_update_pending",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "vote",
                entityId: fixture.voteId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { fixture: "persisted source cause" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await pool.query(
        `insert into vote_source_update_causes(
           id,organization_id,board_id,vote_id,source_class,source_id,source_version,
           source_sha256,trigger_audit_event_id
         ) values ($1,$2,$3,$4,'question_cutoff',$5,$6,$7,$8)`,
        [
          testId(801),
          fixture.secretary.organizationId,
          fixture.secretary.boardId,
          fixture.voteId,
          questionComponent.id,
          questionComponent.version,
          Buffer.from(questionComponent.sha256, "hex"),
          testId(800)
        ]
      );
      await pool.query(
        `update votes set state='source_update_pending',row_version=row_version+1 where id=$1`,
        [fixture.voteId]
      );

      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => replaceVoteInTransaction(client, voteReplacementInput(fixture)),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/disposition every exact pending source-update cause/u);

      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          replaceVoteInTransaction(
            client,
            voteReplacementInput(fixture, {
              sourceUpdateDispositions: [{ causeId: testId(801), dispositionId: testId(802) }]
            })
          ),
        { assumeRole: "boardagent_server" }
      );
      const disposition = await pool.query<{
        effect: string;
        replacement_vote_id: string;
      }>(
        `select effect,replacement_vote_id
           from vote_source_update_dispositions where cause_id=$1`,
        [testId(801)]
      );
      expect(disposition.rows).toEqual([
        { effect: "incorporated", replacement_vote_id: fixture.newVoteId }
      ]);
    });
  });

  it("serializes identical concurrent replacements into one commit and one safe replay", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const input = voteReplacementInput(fixture);
      const results = await Promise.all([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => replaceVoteInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => replaceVoteInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(results.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);
      const committed = await pool.query<{ count: string }>(
        `select count(*)::text as count from vote_supersessions where old_vote_id=$1`,
        [fixture.voteId]
      );
      expect(committed.rows[0]?.count).toBe("1");
    });
  });

  it("resolves prior pending replacement lineage before opening a second empty replacement", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => replaceVoteInTransaction(client, voteReplacementInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const secondInput = await secondVoteReplacementInput(pool, fixture);
      const second = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => replaceVoteInTransaction(client, secondInput),
        { assumeRole: "boardagent_server" }
      );
      expect(second).toMatchObject({
        replayed: false,
        oldVoteId: fixture.newVoteId,
        newVoteId: secondInput.newVoteId,
        state: "open"
      });
      const priorRevote = await pool.query<{ state: string }>(
        `select state from pending_action_feed
          where object_id=$1 and action_type='revote_required' and member_id=$2`,
        [fixture.newVoteId, fixture.secretary.memberId]
      );
      expect(priorRevote.rows[0]?.state).toBe("superseded");
      const carriedNextRevote = await pool.query<{ member_id: string; state: string }>(
        `select member_id,state from pending_action_feed
          where object_id=$1 and action_type='revote_required'`,
        [secondInput.newVoteId]
      );
      expect(carriedNextRevote.rows).toEqual([
        { member_id: fixture.secretary.memberId, state: "pending" }
      ]);
      const supersededTombstones = await pool.query<{ removed_feed_id: string }>(
        `select removed_feed_id from feed_tombstones
          where object_id=$1 and reason_class='superseded'
          order by removed_feed_id`,
        [fixture.newVoteId]
      );
      expect(supersededTombstones.rows).toEqual([
        { removed_feed_id: testId(494) },
        { removed_feed_id: testId(503) }
      ]);
      const lineage = await pool.query<{ old_vote_id: string; new_vote_id: string }>(
        `select old_vote_id,new_vote_id from vote_supersessions order by created_at,id`
      );
      expect(lineage.rows).toEqual([
        { old_vote_id: fixture.voteId, new_vote_id: fixture.newVoteId },
        { old_vote_id: fixture.newVoteId, new_vote_id: secondInput.newVoteId }
      ]);
    });
  });

  it("informs an entitled prior principal who became nonvoting without creating an impossible revote action", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const input = await ineligiblePrincipalReplacementInput(pool, fixture);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => replaceVoteInTransaction(client, input),
        { assumeRole: "boardagent_server" }
      );
      const electorate = await pool.query<{ member_id: string }>(
        "select member_id from vote_electorate where vote_id=$1 order by member_id",
        [input.newVoteId]
      );
      expect(electorate.rows).toEqual([{ member_id: fixture.voter.memberId }]);
      const priorPrincipal = await pool.query<{ action_type: string; state: string }>(
        `select action_type,state from pending_action_feed
          where member_id=$1 and object_id in ($2,$3)
            and action_type in ('vote_replaced','revote_required')
          order by action_type`,
        [fixture.secretary.memberId, fixture.voteId, input.newVoteId]
      );
      expect(priorPrincipal.rows).toEqual([{ action_type: "vote_replaced", state: "resolved" }]);
    });
  });

  it("rolls every replacement projection back when the final audit append fails", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: testId(506),
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "vote",
                entityId: fixture.voteId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { seededFailure: true },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => replaceVoteInTransaction(client, voteReplacementInput(fixture)),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const rolledBack = await pool.query<{
        old_state: string;
        new_vote: string | null;
        supersessions: string;
        dispositions: string;
        revocations: string;
      }>(
        `select
           (select state from votes where id=$1) as old_state,
           (select id::text from votes where id=$2) as new_vote,
           (select count(*)::text from vote_supersessions where old_vote_id=$1) as supersessions,
           (select count(*)::text from ballot_dispositions where replacement_vote_id=$2)
             as dispositions,
           (select count(*)::text from proxy_revocations where effect='superseded')
             as revocations`,
        [fixture.voteId, fixture.newVoteId]
      );
      expect(rolledBack.rows[0]).toMatchObject({
        old_state: "open",
        new_vote: null,
        supersessions: "0",
        dispositions: "0",
        revocations: "0"
      });
      const stage = await pool.query<{ state: string }>(
        "select state from action_stages where id=$1",
        [fixture.activeStageId]
      );
      expect(stage.rows[0]?.state).toBe("active");

      const retry = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          replaceVoteInTransaction(
            client,
            voteReplacementInput(fixture, { voteOpenedAuditEventId: testId(550) })
          ),
        { assumeRole: "boardagent_server" }
      );
      expect(retry.replayed).toBe(false);
    });
  });
});

describe("pending vote-source exclusion transaction boundary", () => {
  it("excludes the exact confirmed source, preserves package bytes and replays concurrently", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const cause = await seedPendingSourceCause(pool, fixture, 1800);
      const input = await confirmedSourceExclusionInput(pool, fixture, cause, { idBase: 1810 });
      const before = await pool.query<{ canonical_payload: Buffer; package_sha256: Buffer }>(
        "select canonical_payload,package_sha256 from decision_packages where id=$1",
        [fixture.decisionPackageId]
      );
      const results = await Promise.all([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => excludePendingVoteSourceInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => excludePendingVoteSourceInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(results.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);
      expect(results.find(({ replayed }) => !replayed)).toMatchObject({
        sourceClass: "document",
        remainingPendingSources: 0,
        voteState: "open"
      });
      const after = await pool.query<{
        canonical_payload: Buffer;
        package_sha256: Buffer;
        state: string;
      }>(
        `select package.canonical_payload,package.package_sha256,vote.state
           from decision_packages as package
           join votes as vote on vote.current_decision_package_id=package.id
          where package.id=$1`,
        [fixture.decisionPackageId]
      );
      expect(after.rows[0]?.canonical_payload.equals(before.rows[0]!.canonical_payload)).toBe(true);
      expect(after.rows[0]?.package_sha256.equals(before.rows[0]!.package_sha256)).toBe(true);
      expect(after.rows[0]?.state).toBe("open");
      const evidence = await pool.query<{
        effect: string;
        reason: string;
        replacement_vote_id: string | null;
        event_type: string;
      }>(
        `select disposition.effect,disposition.reason,disposition.replacement_vote_id,
                audit.event_type
           from vote_source_update_dispositions as disposition
           join audit_events as audit on audit.id=disposition.audit_event_id
          where disposition.id=$1`,
        [input.dispositionId]
      );
      expect(evidence.rows).toEqual([
        {
          effect: "excluded",
          reason: input.reason,
          replacement_vote_id: null,
          event_type: "vote_source_excluded"
        }
      ]);
    });
  });

  it("keeps the vote blocked until every independent pending cause is dispositioned", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const firstCause = await seedPendingSourceCause(pool, fixture, 1840, "document");
      const secondCause = await seedPendingSourceCause(
        pool,
        fixture,
        1850,
        "management_submission"
      );
      const firstInput = await confirmedSourceExclusionInput(pool, fixture, firstCause, {
        idBase: 1860
      });
      const first = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => excludePendingVoteSourceInTransaction(client, firstInput),
        { assumeRole: "boardagent_server" }
      );
      expect(first).toMatchObject({
        replayed: false,
        remainingPendingSources: 1,
        voteState: "source_update_pending"
      });
      const secondInput = await confirmedSourceExclusionInput(pool, fixture, secondCause, {
        idBase: 1900
      });
      const second = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => excludePendingVoteSourceInTransaction(client, secondInput),
        { assumeRole: "boardagent_server" }
      );
      expect(second).toMatchObject({
        replayed: false,
        remainingPendingSources: 0,
        voteState: "open"
      });
      const state = await pool.query<{ dispositions: string; state: string }>(
        `select vote.state,
                (select count(*)::text from vote_source_update_dispositions
                  where source_vote_id=vote.id) as dispositions
           from votes as vote where vote.id=$1`,
        [fixture.voteId]
      );
      expect(state.rows).toEqual([{ state: "open", dispositions: "2" }]);
    });
  });

  it("rejects unauthorized or tampered confirmation and rolls back on final audit failure", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const cause = await seedPendingSourceCause(pool, fixture, 1940);
      const unauthorized = await confirmedSourceExclusionInput(pool, fixture, cause, {
        idBase: 1950,
        actor: fixture.voter
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => excludePendingVoteSourceInTransaction(client, unauthorized),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_source_exclusion_unavailable" });

      const input = await confirmedSourceExclusionInput(pool, fixture, cause, { idBase: 1990 });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            excludePendingVoteSourceInTransaction(client, {
              ...input,
              reason: `${input.reason} Tampered.`
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_source_exclusion_unavailable" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            excludePendingVoteSourceInTransaction(client, {
              ...input,
              decisionPackageSha256: testHash(254).toString("hex")
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_source_exclusion_unavailable" });

      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: input.auditEventId,
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "vote",
                entityId: fixture.voteId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { seededFailure: true },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => excludePendingVoteSourceInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const rolledBack = await pool.query<{
        dispositions: string;
        idempotency: string;
        state: string;
      }>(
        `select vote.state,
                (select count(*)::text from vote_source_update_dispositions where id=$2)
                  as dispositions,
                (select count(*)::text from idempotency_records where id=$3) as idempotency
           from votes as vote where vote.id=$1`,
        [fixture.voteId, input.dispositionId, input.idempotencyRecordId]
      );
      expect(rolledBack.rows).toEqual([
        { state: "source_update_pending", dispositions: "0", idempotency: "0" }
      ]);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            excludePendingVoteSourceInTransaction(client, {
              ...input,
              auditEventId: testId(2030)
            }),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ replayed: false, voteState: "open" });
    });
  });
});

describe("live vote-recusal transaction boundary", () => {
  it("atomically excludes, invalidates, re-notices, replays and lifts without restoring acts", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteRecusalFixture(pool);
      const input = voteRecusalInput(fixture);
      const excluded = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => manageVoteRecusalInTransaction(client, input),
        { assumeRole: "boardagent_server" }
      );
      expect(excluded).toMatchObject({
        replayed: false,
        voteId: fixture.voteId,
        memberId: fixture.secretary.memberId,
        exclusionVersion: 1,
        state: "excluded",
        eligibleWeight: 1n
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => manageVoteRecusalInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ replayed: true, responseSha256: excluded.responseSha256 });

      const excludedState = await pool.query<{
        ballot_effect: string;
        excluded_member_feed: string | null;
        exclusion_reason: string;
        exclusion_state: string;
        proxy_effect: string;
        stage_state: string;
        tombstone_count: string;
      }>(
        `select exclusion.state as exclusion_state,exclusion.reason as exclusion_reason,
                stage.state as stage_state,revocation.effect as proxy_effect,
                disposition.effect as ballot_effect,
                (select state from pending_action_feed where id=$6) as excluded_member_feed,
                (select count(*)::text from feed_tombstones
                  where removed_feed_id=$6 and reason_class='recused') as tombstone_count
           from vote_exclusions as exclusion
           join action_stages as stage on stage.id=$2
           join proxy_revocations as revocation on revocation.grant_id=$3
           join ballot_dispositions as disposition on disposition.prior_ballot_id=$4
          where exclusion.id=$1 and exclusion.member_id=$5`,
        [
          fixture.exclusionId,
          fixture.recusalStageId,
          fixture.proxyGrantId,
          fixture.ballotId,
          fixture.secretary.memberId,
          testId(221)
        ]
      );
      expect(excludedState.rows).toEqual([
        {
          exclusion_state: "excluded",
          exclusion_reason: fixture.reason,
          stage_state: "replaced",
          proxy_effect: "revoked",
          ballot_effect: "invalidated_by_recusal",
          excluded_member_feed: "superseded",
          tombstone_count: "1"
        }
      ]);
      const targetLeak = await pool.query<{ count: string }>(
        `select count(*)::text as count from pending_action_feed
          where object_id=$1 and member_id=$2 and action_type='recusal_changed'`,
        [fixture.voteId, fixture.secretary.memberId]
      );
      expect(targetLeak.rows[0]?.count).toBe("0");

      const liftReason = "The confirmed conflict has ended; prior acts remain invalid.";
      const liftExclusionId = testId(890);
      const liftPayloadSha256 = voteRecusalConsentHash({
        voteId: fixture.voteId,
        memberId: fixture.secretary.memberId,
        state: "lifted",
        reason: liftReason,
        packageSha256: fixture.oldPackageSha256
      });
      const liftConsent = await seedConfirmedVoteAction(pool, fixture, {
        idBase: 880,
        canonicalPayload: {
          schemaVersion: "boardagent.vote-recusal-consent.v1",
          voteId: fixture.voteId,
          memberId: fixture.secretary.memberId,
          state: "lifted",
          reason: liftReason,
          packageSha256: fixture.oldPackageSha256
        },
        actionCode: "manage_recusal",
        originalName: "manage_recusal",
        targetId: fixture.voteId,
        payloadSha256: liftPayloadSha256,
        packageSha256: fixture.oldPackageSha256
      });
      const lifted = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          manageVoteRecusalInTransaction(client, {
            organizationId: fixture.secretary.organizationId,
            voteId: fixture.voteId,
            memberId: fixture.secretary.memberId,
            decisionPackageSha256: fixture.oldPackageSha256,
            state: "lifted",
            exclusionId: liftExclusionId,
            reason: liftReason,
            consentRecordId: liftConsent.consentRecordId,
            idempotencyRecordId: testId(891),
            idempotencyKey: "lift-live-vote-recusal-0001",
            stageDispositions: [],
            proxyDispositions: [],
            ballotDispositions: [],
            feedTombstones: [],
            deliveries: [
              {
                memberId: fixture.secretary.memberId,
                noticeId: testId(900),
                feedId: testId(901),
                noticeAuditEventId: testId(902)
              },
              {
                memberId: fixture.voter.memberId,
                noticeId: testId(903),
                feedId: testId(904),
                noticeAuditEventId: testId(905)
              }
            ],
            auditEventId: testId(892)
          }),
        { assumeRole: "boardagent_server" }
      );
      expect(lifted).toMatchObject({
        replayed: false,
        exclusionVersion: 2,
        state: "lifted",
        eligibleWeight: 2n
      });
      const liftState = await pool.query<{
        active_ballots: string;
        active_proxies: string;
        active_stages: string;
        exclusion_states: string[];
        target_action_state: string;
      }>(
        `select
           (select array_agg(state order by version) from vote_exclusions
             where vote_id=$1 and member_id=$2) as exclusion_states,
           (select count(*)::text from action_stages where id=$3 and state='active') as active_stages,
           (select count(*)::text from proxy_grants as proxy
             left join proxy_revocations as revocation on revocation.grant_id=proxy.id
             where proxy.id=$4 and revocation.id is null) as active_proxies,
           (select count(*)::text from ballots as ballot
             left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
             where ballot.id=$5 and disposition.id is null) as active_ballots,
           (select state from pending_action_feed where id=$6) as target_action_state`,
        [
          fixture.voteId,
          fixture.secretary.memberId,
          fixture.recusalStageId,
          fixture.proxyGrantId,
          fixture.ballotId,
          testId(901)
        ]
      );
      expect(liftState.rows).toEqual([
        {
          exclusion_states: ["excluded", "lifted"],
          active_stages: "0",
          active_proxies: "0",
          active_ballots: "0",
          target_action_state: "pending"
        }
      ]);
    });
  });

  it("refuses nonsecretary, noncanonical and post-confirmation recusal changes", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteRecusalFixture(pool);
      await expect(
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => manageVoteRecusalInTransaction(client, voteRecusalInput(fixture)),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_recusal_unavailable" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            manageVoteRecusalInTransaction(
              client,
              voteRecusalInput(fixture, { reason: "unconfirmed changed reason" })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "vote_recusal_unavailable" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            manageVoteRecusalInTransaction(
              client,
              voteRecusalInput(fixture, { reason: "invalid\r\nreason" })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/LF line endings/u);
    });
  });

  it("serializes identical concurrent exclusion and rolls every projection back on audit failure", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteRecusalFixture(pool);
      const input = voteRecusalInput(fixture);
      const results = await Promise.all([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => manageVoteRecusalInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => manageVoteRecusalInTransaction(client, input),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(results.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);
      const exclusions = await pool.query<{ count: string }>(
        "select count(*)::text as count from vote_exclusions where vote_id=$1",
        [fixture.voteId]
      );
      expect(exclusions.rows[0]?.count).toBe("1");
    });

    await withDatabase(async (pool) => {
      const fixture = await seedVoteRecusalFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: testId(869),
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "vote",
                entityId: fixture.voteId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { seededFailure: true },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => manageVoteRecusalInTransaction(client, voteRecusalInput(fixture)),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const rolledBack = await pool.query<{
        ballot_dispositions: string;
        exclusions: string;
        stage_state: string;
        tombstones: string;
      }>(
        `select
           (select count(*)::text from vote_exclusions where vote_id=$1) as exclusions,
           (select count(*)::text from ballot_dispositions where prior_ballot_id=$2)
             as ballot_dispositions,
           (select state from action_stages where id=$3) as stage_state,
           (select count(*)::text from feed_tombstones where removed_feed_id=$4) as tombstones`,
        [fixture.voteId, fixture.ballotId, fixture.recusalStageId, testId(221)]
      );
      expect(rolledBack.rows).toEqual([
        {
          exclusions: "0",
          ballot_dispositions: "0",
          stage_state: "active",
          tombstones: "0"
        }
      ]);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            manageVoteRecusalInTransaction(
              client,
              voteRecusalInput(fixture, { auditEventId: testId(899) })
            ),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ replayed: false, state: "excluded" });
    });
  });
});

describe("ballot and proxy transaction boundary", () => {
  it("grants an exact proxy, casts by attribution, lets the principal supersede and revokes prospectively", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const grantInput = await confirmedProxyGrantInput(pool, fixture, {
        actor: fixture.voter,
        holderMemberId: fixture.secretary.memberId,
        idBase: 1000
      });
      const grants = await Promise.all([
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => grantProxyInTransaction(client, grantInput),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => grantProxyInTransaction(client, grantInput),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(grants.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);

      const proxyBallotInput = await confirmedBallotInput(pool, fixture, {
        actor: fixture.secretary,
        principalMemberId: fixture.voter.memberId,
        proxyGrantId: grantInput.proxyGrantId,
        choice: "yes",
        statement: "  Exact proxy statement.  ",
        idBase: 1040
      });
      const proxyCasts = await Promise.all([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => castBallotInTransaction(client, proxyBallotInput),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => castBallotInTransaction(client, proxyBallotInput),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(proxyCasts.map(({ replayed }) => replayed).toSorted()).toEqual([false, true]);

      const directBallotInput = await confirmedBallotInput(pool, fixture, {
        actor: fixture.voter,
        principalMemberId: fixture.voter.memberId,
        choice: "no",
        statement: "  Principal controls the final ballot.  ",
        idBase: 1080
      });
      const direct = await withRequestTransaction(
        pool,
        fixture.voter.context,
        (client) => castBallotInTransaction(client, directBallotInput),
        { assumeRole: "boardagent_server" }
      );
      expect(direct).toMatchObject({
        replayed: false,
        ballotId: directBallotInput.ballotId,
        source: "own",
        supersededBallotId: proxyBallotInput.ballotId
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => castBallotInTransaction(client, directBallotInput),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ replayed: true, responseSha256: direct.responseSha256 });

      const revokeInput = await confirmedProxyRevokeInput(pool, fixture, {
        actor: fixture.voter,
        proxyGrantId: grantInput.proxyGrantId,
        reason: "  Principal ends future proxy authority.  ",
        idBase: 1120
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => revokeProxyInTransaction(client, revokeInput),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ replayed: false, effect: "revoked" });

      const persisted = await pool.query<{
        id: string;
        ballot_source: string;
        statement_text: string | null;
        disposition_effect: string | null;
      }>(
        `select ballot.id,ballot.ballot_source,ballot.statement_text,
                disposition.effect as disposition_effect
           from ballots as ballot
           left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
          where ballot.vote_id=$1 order by ballot.cast_at,ballot.id`,
        [fixture.voteId]
      );
      expect(persisted.rows).toEqual([
        {
          id: proxyBallotInput.ballotId,
          ballot_source: "proxy",
          statement_text: proxyBallotInput.statement,
          disposition_effect: "superseded"
        },
        {
          id: directBallotInput.ballotId,
          ballot_source: "own",
          statement_text: directBallotInput.statement,
          disposition_effect: null
        }
      ]);
      const actionState = await pool.query<{ state: string }>(
        "select state from pending_action_feed where id=$1",
        [testId(224)]
      );
      expect(actionState.rows[0]?.state).toBe("resolved");
      const events = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where object_id=any($1::uuid[]) order by sequence`,
        [[grantInput.proxyGrantId, proxyBallotInput.ballotId, directBallotInput.ballotId]]
      );
      expect(events.rows.map(({ event_type }) => event_type)).toEqual([
        "proxy_granted",
        "ballot_cast",
        "ballot_superseded",
        "ballot_cast",
        "proxy_revoked"
      ]);
    });
  });

  it("rejects proxy chains and every post-confirmation payload change", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const firstGrant = await confirmedProxyGrantInput(pool, fixture, {
        actor: fixture.voter,
        holderMemberId: fixture.secretary.memberId,
        idBase: 1160
      });
      await withRequestTransaction(
        pool,
        fixture.voter.context,
        (client) => grantProxyInTransaction(client, firstGrant),
        { assumeRole: "boardagent_server" }
      );
      const cycleGrant = await confirmedProxyGrantInput(pool, fixture, {
        actor: fixture.secretary,
        holderMemberId: fixture.voter.memberId,
        idBase: 1200
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => grantProxyInTransaction(client, cycleGrant),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "proxy_invalid" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            grantProxyInTransaction(client, {
              ...cycleGrant,
              expiresAt: "2099-09-29T12:00:00Z"
            }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "proxy_unavailable" });

      const ballot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.secretary,
        principalMemberId: fixture.voter.memberId,
        proxyGrantId: firstGrant.proxyGrantId,
        choice: "yes",
        statement: "Canonical statement",
        idBase: 1240
      });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            castBallotInTransaction(client, { ...ballot, statement: "changed after consent" }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toMatchObject({ code: "ballot_unavailable" });
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => castBallotInTransaction(client, { ...ballot, statement: "bad\r\ntext" }),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow(/LF line endings/u);
    });
  });

  it("serializes direct and proxy casts to one effective principal ballot", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const grant = await confirmedProxyGrantInput(pool, fixture, {
        actor: fixture.voter,
        holderMemberId: fixture.secretary.memberId,
        idBase: 1280
      });
      await withRequestTransaction(
        pool,
        fixture.voter.context,
        (client) => grantProxyInTransaction(client, grant),
        { assumeRole: "boardagent_server" }
      );
      const proxyBallot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.secretary,
        principalMemberId: fixture.voter.memberId,
        proxyGrantId: grant.proxyGrantId,
        choice: "yes",
        idBase: 1320
      });
      const directBallot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.voter,
        principalMemberId: fixture.voter.memberId,
        choice: "no",
        idBase: 1360
      });
      const raced = await Promise.allSettled([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => castBallotInTransaction(client, proxyBallot),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => castBallotInTransaction(client, directBallot),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(raced[1]?.status).toBe("fulfilled");
      if (raced[0]?.status === "rejected") {
        expect(raced[0].reason).toMatchObject({ code: "ballot_invalid" });
      }
      const active = await pool.query<{ id: string; ballot_source: string }>(
        `select ballot.id,ballot.ballot_source from ballots as ballot
          left join ballot_dispositions as disposition on disposition.prior_ballot_id=ballot.id
         where ballot.vote_id=$1 and ballot.principal_member_id=$2 and disposition.id is null`,
        [fixture.voteId, fixture.voter.memberId]
      );
      expect(active.rows).toEqual([{ id: directBallot.ballotId, ballot_source: "own" }]);
    });
  });

  it("serializes recusal and cast so no excluded principal retains an effective ballot", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const ballot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.voter,
        principalMemberId: fixture.voter.memberId,
        choice: "yes",
        idBase: 1400
      });
      const reason = "The member is recused while the vote remains live.";
      const exclusionId = testId(1460);
      const recusalPayload = voteRecusalConsentHash({
        voteId: fixture.voteId,
        memberId: fixture.voter.memberId,
        state: "excluded",
        reason,
        packageSha256: fixture.packageSha256
      });
      const recusalConsent = await seedConfirmedVoteAction(pool, fixture, {
        idBase: 1440,
        canonicalPayload: {
          schemaVersion: "boardagent.vote-recusal-consent.v1",
          voteId: fixture.voteId,
          memberId: fixture.voter.memberId,
          state: "excluded",
          reason,
          packageSha256: fixture.packageSha256
        },
        actionCode: "manage_recusal",
        originalName: "manage_recusal",
        targetId: fixture.voteId,
        payloadSha256: recusalPayload,
        packageSha256: fixture.packageSha256
      });
      const recusal: ManageVoteRecusalInput = {
        organizationId: fixture.secretary.organizationId,
        voteId: fixture.voteId,
        memberId: fixture.voter.memberId,
        decisionPackageSha256: fixture.packageSha256,
        state: "excluded",
        exclusionId,
        reason,
        consentRecordId: recusalConsent.consentRecordId,
        idempotencyRecordId: testId(1461),
        idempotencyKey: "race-recusal-against-cast-0001",
        stageDispositions: [],
        proxyDispositions: [],
        ballotDispositions: [],
        feedTombstones: [{ removedFeedId: testId(224), tombstoneId: testId(1462) }],
        deliveries: [
          {
            memberId: fixture.secretary.memberId,
            noticeId: testId(1463),
            feedId: testId(1464),
            noticeAuditEventId: testId(1465)
          }
        ],
        auditEventId: testId(1466)
      };
      const raced = await Promise.allSettled([
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => castBallotInTransaction(client, ballot),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => manageVoteRecusalInTransaction(client, recusal),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(raced.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      if (raced[0]?.status === "fulfilled") {
        expect(raced[1]).toMatchObject({
          status: "rejected",
          reason: { code: "vote_recusal_invalid" }
        });
        await expect(
          withRequestTransaction(
            pool,
            fixture.secretary.context,
            (client) =>
              manageVoteRecusalInTransaction(client, {
                ...recusal,
                ballotDispositions: [
                  {
                    ballotId: ballot.ballotId,
                    ballotDispositionId: testId(1467),
                    auditEventId: testId(1468)
                  }
                ],
                feedTombstones: []
              }),
            { assumeRole: "boardagent_server" }
          )
        ).resolves.toMatchObject({ state: "excluded" });
      } else {
        expect(raced[0]?.reason).toMatchObject({ code: "ballot_unavailable" });
        expect(raced[1]?.status).toBe("fulfilled");
      }
      const state = await pool.query<{ active_ballots: string; exclusions: string }>(
        `select
           (select count(*)::text from ballots as ballot
             left join ballot_dispositions as disposition
               on disposition.prior_ballot_id=ballot.id
            where ballot.vote_id=$1 and ballot.principal_member_id=$2
              and disposition.id is null) as active_ballots,
           (select count(*)::text from vote_exclusions
             where vote_id=$1 and member_id=$2 and state='excluded') as exclusions`,
        [fixture.voteId, fixture.voter.memberId]
      );
      expect(state.rows).toEqual([{ active_ballots: "0", exclusions: "1" }]);
    });
  });

  it("makes proxy revocation prospective across a concurrent attributed cast", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const grant = await confirmedProxyGrantInput(pool, fixture, {
        actor: fixture.voter,
        holderMemberId: fixture.secretary.memberId,
        idBase: 1480
      });
      await withRequestTransaction(
        pool,
        fixture.voter.context,
        (client) => grantProxyInTransaction(client, grant),
        { assumeRole: "boardagent_server" }
      );
      const ballot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.secretary,
        principalMemberId: fixture.voter.memberId,
        proxyGrantId: grant.proxyGrantId,
        choice: "abstain",
        idBase: 1520
      });
      const revoke = await confirmedProxyRevokeInput(pool, fixture, {
        actor: fixture.voter,
        proxyGrantId: grant.proxyGrantId,
        reason: "Revoke prospectively without rewriting a prior attributed act.",
        idBase: 1560
      });
      const raced = await Promise.allSettled([
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => castBallotInTransaction(client, ballot),
          { assumeRole: "boardagent_server" }
        ),
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => revokeProxyInTransaction(client, revoke),
          { assumeRole: "boardagent_server" }
        )
      ]);
      expect(raced[1]?.status).toBe("fulfilled");
      if (raced[0]?.status === "rejected") {
        expect(raced[0].reason).toMatchObject({ code: "ballot_unavailable" });
      }
      const state = await pool.query<{
        active_ballots: string;
        ballot_dispositions: string;
        revocations: string;
      }>(
        `select
           (select count(*)::text from ballots as ballot
             left join ballot_dispositions as disposition
               on disposition.prior_ballot_id=ballot.id
            where ballot.id=$1 and disposition.id is null) as active_ballots,
           (select count(*)::text from ballot_dispositions
             where prior_ballot_id=$1) as ballot_dispositions,
           (select count(*)::text from proxy_revocations
             where grant_id=$2 and effect='revoked') as revocations`,
        [ballot.ballotId, grant.proxyGrantId]
      );
      expect(state.rows[0]?.revocations).toBe("1");
      expect(state.rows[0]?.ballot_dispositions).toBe("0");
      expect(["0", "1"]).toContain(state.rows[0]?.active_ballots);
    });
  });

  it("rolls ballot, grant and revocation projections back when their final audit append fails", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const ballot = await confirmedBallotInput(pool, fixture, {
        actor: fixture.voter,
        principalMemberId: fixture.voter.memberId,
        choice: "yes",
        idBase: 1600
      });
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: ballot.auditEventId,
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "vote",
                entityId: fixture.voteId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { seededFailure: "ballot" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.voter.context,
          (client) => castBallotInTransaction(client, ballot),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const ballotRollback = await pool.query<{
        ballots: string;
        feed_state: string;
        idempotency: string;
        row_version: string;
      }>(
        `select
           (select count(*)::text from ballots where id=$1) as ballots,
           (select state from pending_action_feed where id=$2) as feed_state,
           (select count(*)::text from idempotency_records where id=$3) as idempotency,
           (select row_version::text from votes where id=$4) as row_version`,
        [ballot.ballotId, testId(224), ballot.idempotencyRecordId, fixture.voteId]
      );
      expect(ballotRollback.rows).toEqual([
        { ballots: "0", feed_state: "pending", idempotency: "0", row_version: "2" }
      ]);
      await withRequestTransaction(
        pool,
        fixture.voter.context,
        (client) => castBallotInTransaction(client, { ...ballot, auditEventId: testId(1625) }),
        { assumeRole: "boardagent_server" }
      );

      const grant = await confirmedProxyGrantInput(pool, fixture, {
        actor: fixture.secretary,
        holderMemberId: fixture.voter.memberId,
        idBase: 1640
      });
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: grant.auditEventId,
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "vote",
                entityId: fixture.voteId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { seededFailure: "grant" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => grantProxyInTransaction(client, grant),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const grantRollback = await pool.query<{ grants: string; idempotency: string }>(
        `select
           (select count(*)::text from proxy_grants where id=$1) as grants,
           (select count(*)::text from idempotency_records where id=$2) as idempotency`,
        [grant.proxyGrantId, grant.idempotencyRecordId]
      );
      expect(grantRollback.rows).toEqual([{ grants: "0", idempotency: "0" }]);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => grantProxyInTransaction(client, { ...grant, auditEventId: testId(1663) }),
        { assumeRole: "boardagent_server" }
      );

      const revoke = await confirmedProxyRevokeInput(pool, fixture, {
        actor: fixture.secretary,
        proxyGrantId: grant.proxyGrantId,
        reason: "Revoke after proving rollback of the grant projection.",
        idBase: 1680
      });
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          appendAuditEventsInTransaction(client, [
            {
              organizationId: fixture.secretary.organizationId,
              event: {
                eventId: revoke.auditEventId,
                eventType: "context_read",
                actorMemberId: fixture.secretary.memberId,
                actorClientId: fixture.secretary.clientId,
                tokenJti: fixture.secretary.tokenJti,
                entityType: "vote",
                entityId: fixture.voteId,
                boardId: fixture.secretary.boardId,
                origin: "mcp",
                details: { seededFailure: "revoke" },
                schemaVersion: 1
              }
            }
          ]),
        { assumeRole: "boardagent_server" }
      );
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => revokeProxyInTransaction(client, revoke),
          { assumeRole: "boardagent_server" }
        )
      ).rejects.toThrow();
      const revokeRollback = await pool.query<{ idempotency: string; revocations: string }>(
        `select
           (select count(*)::text from proxy_revocations where id=$1) as revocations,
           (select count(*)::text from idempotency_records where id=$2) as idempotency`,
        [revoke.proxyRevocationId, revoke.idempotencyRecordId]
      );
      expect(revokeRollback.rows).toEqual([{ revocations: "0", idempotency: "0" }]);
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => revokeProxyInTransaction(client, { ...revoke, auditEventId: testId(1703) }),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toMatchObject({ effect: "revoked", replayed: false });
    });
  });
});

describe("guided vote creation MCP lifecycle surface", () => {
  it("opens a 1000-seat vote through confirmation and signs every recipient notice", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool, { precreateVote: false });
      await seedCapacitySeats(pool, fixture.secretary, 998, { readyForVote: true });
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      await withConfiguredFixtureWorker(pool, fixture.secretary.organizationId, async (worker) => {
        let headBefore = 0n;
        const result = await confirmSurfaceVoteAction(
          service,
          surfacePrincipal(
            fixture.secretary,
            ["member", "secretariat"],
            ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
          ),
          "create_vote",
          voteCreationSurfaceInput(fixture),
          async () => {
            await worker.worker.runOnce();
            headBefore = BigInt(
              (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
                .last_sequence as string
            );
          }
        );
        expect(result.result).toMatchObject({ status: "accepted", reference: fixture.voteId });
        expect(
          (
            await pool.query(
              `select
          (select count(*)::int from vote_electorate where vote_id=$1) as electorate,
          (select count(*)::int from notices where object_id=$1 and notice_type='vote_opened') as notices`,
              [fixture.voteId]
            )
          ).rows
        ).toEqual([{ electorate: 1000, notices: 1000 }]);
        const headAfter = BigInt(
          (await pool.query("select last_sequence::text from audit_chain_head")).rows[0]!
            .last_sequence as string
        );
        expect(headAfter - headBefore).toBe(1002n);
        await withWorkerTransaction(
          pool,
          (client) => scheduleAuditCheckpointInTransaction(client, testId(7_900_000)),
          { assumeRole: "boardagent_worker" }
        );
        await worker.worker.runOnce();
        await expect(
          withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
            assumeRole: "boardagent_worker"
          })
        ).resolves.toMatchObject({
          valid: true,
          ready: true
        });
      });
    });
  }, 60000);

  it("opens only the exact active-profile package after secretary confirmation", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool, {
        includeAnsweredQuestion: true,
        precreateVote: false
      });
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
      );
      const ordinaryMember = surfacePrincipal(
        fixture.voter,
        ["member"],
        ["governance:read", "proxy:manage", "vote:act"]
      );
      const createInput = voteCreationSurfaceInput(fixture);

      await expect(
        service.prepareHumanAction(ordinaryMember, "create_vote", createInput)
      ).rejects.toThrow(/unavailable/u);
      expect(await pool.query("select id from votes where id=$1", [fixture.voteId])).toMatchObject({
        rowCount: 0
      });

      const prepared = await service.prepareHumanAction(secretary, "create_vote", createInput);
      expect(prepared).toMatchObject({
        action_code: "create_vote",
        board_id: fixture.secretary.boardId,
        target_type: "vote",
        target_id: fixture.voteId
      });
      expect(prepared.package_sha256).toMatch(/^[0-9a-f]{64}$/u);
      expect(prepared.confirmation_lines.join("\n")).toContain("General vote rule");
      const capabilities = { elicitation: { form: {} } } as const;
      const requestState = "guided-vote-create-request-state-bound-to-exact-package";
      await service.persistHumanStage({
        principal: secretary,
        tool: "create_vote",
        input: createInput,
        prepared,
        client_capabilities: capabilities,
        embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
        embedded_result: { message: "Confirm exact create_vote" },
        request_state: requestState,
        prepared_request_id: Buffer.from("guided-vote-create-prepare")
      });
      const staged = await pool.query<{ votes: string; wizards: string }>(
        `select
           (select count(*)::text from votes where id=$1) as votes,
           (select count(*)::text from wizard_drafts
             where board_id=$2 and draft_type='vote' and state='ready_to_confirm') as wizards`,
        [fixture.voteId, fixture.secretary.boardId]
      );
      expect(staged.rows).toEqual([{ votes: "0", wizards: "1" }]);

      const resolved = await service.resolveHumanAction({
        principal: secretary,
        tool: "create_vote",
        input: createInput,
        stage_id: prepared.stage_id,
        client_capabilities: capabilities,
        request_state: requestState,
        retry_request_id: Buffer.from(`guided-vote-create-retry-${prepared.stage_id}`),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: prepared.confirmation_code }
      });
      if (!resolved.confirmed) throw new Error(`create_vote failed: ${resolved.reason}`);
      expect(resolved.result).toMatchObject({
        tool: "create_vote",
        status: "accepted",
        reference: fixture.voteId,
        data: {
          schema_version: "boardagent.vote-open-result.v1",
          vote_id: fixture.voteId,
          state: "open",
          replayed: false
        }
      });

      const persisted = await pool.query<{
        state: string;
        packages: string;
        electorate: string;
        notices: string;
        wizard_state: string;
      }>(
        `select vote.state,
                (select count(*)::text from decision_packages where vote_id=vote.id) as packages,
                (select count(*)::text from vote_electorate where vote_id=vote.id) as electorate,
                (select count(*)::text from notices
                  where object_type='vote' and object_id=vote.id and notice_type='vote_opened') as notices,
                (select wizard.state from wizard_drafts as wizard
                  join input_required_attempts as attempt on attempt.wizard_draft_id=wizard.id
                  where attempt.stage_id=$1) as wizard_state
           from votes as vote where vote.id=$2`,
        [prepared.stage_id, fixture.voteId]
      );
      expect(persisted.rows).toEqual([
        {
          state: "open",
          packages: "1",
          electorate: "2",
          notices: "2",
          wizard_state: "posted"
        }
      ]);
      const audit = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where object_id in ($1,$2)
             or consent_record_id=(select id from consent_records where stage_id=$1)
          order by sequence`,
        [prepared.stage_id, fixture.voteId]
      );
      expect(audit.rows.map(({ event_type }) => event_type).slice(-4)).toEqual([
        "consent_recorded",
        "notice_delivered",
        "notice_delivered",
        "vote_opened"
      ]);
    });
  });

  it("binds one permitted reasoned override into the exact opened package", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool, { precreateVote: false });
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
      );
      const overrideReason = "Use the cited alternative for this exact vote.";
      const input = voteCreationSurfaceInput(fixture, {
        selectedRuleId: fixture.overrideRulesetRuleId,
        overrideReason
      });
      const prepared = await service.prepareHumanAction(secretary, "create_vote", input);
      expect(prepared.confirmation_lines.join("\n")).toContain(overrideReason);
      expect(prepared.confirmation_lines.join("\n")).toContain(fixture.overrideRulesetRuleId);
      const capabilities = { elicitation: { form: {} } } as const;
      const requestState = "guided-vote-create-override-state-bound-to-exact-package";
      await service.persistHumanStage({
        principal: secretary,
        tool: "create_vote",
        input,
        prepared,
        client_capabilities: capabilities,
        embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
        embedded_result: { message: "Confirm exact create_vote with rule override" },
        request_state: requestState,
        prepared_request_id: Buffer.from("guided-vote-create-override-prepare")
      });
      const resolved = await service.resolveHumanAction({
        principal: secretary,
        tool: "create_vote",
        input,
        stage_id: prepared.stage_id,
        client_capabilities: capabilities,
        request_state: requestState,
        retry_request_id: Buffer.from(`guided-vote-create-override-retry-${prepared.stage_id}`),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: prepared.confirmation_code }
      });
      if (!resolved.confirmed) throw new Error(`create_vote override failed: ${resolved.reason}`);
      expect(resolved.result).toMatchObject({
        tool: "create_vote",
        status: "accepted",
        reference: fixture.voteId,
        data: { state: "open", replayed: false }
      });

      const persisted = await pool.query<{
        override_reason: string;
        package_override_sha256: string;
        selected_ruleset_rule_id: string;
        state: string;
        vote_override_sha256: string;
      }>(
        `select vote.state,vote.selected_ruleset_rule_id,
                encode(vote.rule_override_sha256,'hex') as vote_override_sha256,
                encode(package.rule_override_sha256,'hex') as package_override_sha256,
                override.reason as override_reason
           from votes as vote
           join decision_packages as package on package.id=vote.current_decision_package_id
           join rule_overrides as override on override.id=vote.rule_override_id
          where vote.id=$1`,
        [fixture.voteId]
      );
      expect(persisted.rows).toHaveLength(1);
      expect(persisted.rows[0]).toMatchObject({
        state: "open",
        selected_ruleset_rule_id: fixture.overrideRulesetRuleId,
        override_reason: overrideReason
      });
      expect(persisted.rows[0]?.vote_override_sha256).toMatch(/^[0-9a-f]{64}$/u);
      expect(persisted.rows[0]?.package_override_sha256).toBe(
        persisted.rows[0]?.vote_override_sha256
      );
      const audit = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where consent_record_id=(select id from consent_records where stage_id=$1)
             or object_id=$2
          order by sequence`,
        [prepared.stage_id, fixture.voteId]
      );
      expect(audit.rows.map(({ event_type }) => event_type).slice(0, 2)).toEqual([
        "consent_recorded",
        "rule_overridden"
      ]);
      expect(audit.rows.at(-1)?.event_type).toBe("vote_opened");
    });
  });

  it("rejects a stale electorate with zero vote", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool, { precreateVote: false });
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
      );
      const input = voteCreationSurfaceInput(fixture);
      const prepared = await service.prepareHumanAction(secretary, "create_vote", input);
      const capabilities = { elicitation: { form: {} } } as const;
      const requestState = "stale-guided-vote-create-request-state-bound-to-exact-package";
      await service.persistHumanStage({
        principal: secretary,
        tool: "create_vote",
        input,
        prepared,
        client_capabilities: capabilities,
        embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
        embedded_result: { message: "Confirm exact create_vote" },
        request_state: requestState,
        prepared_request_id: Buffer.from("stale-guided-vote-create-prepare")
      });
      await pool.query(
        "update board_memberships set voting_weight=2 where board_id=$1 and member_id=$2",
        [fixture.secretary.boardId, fixture.voter.memberId]
      );
      const resolved = await service.resolveHumanAction({
        principal: secretary,
        tool: "create_vote",
        input,
        stage_id: prepared.stage_id,
        client_capabilities: capabilities,
        request_state: requestState,
        retry_request_id: Buffer.from(`stale-guided-vote-create-retry-${prepared.stage_id}`),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: prepared.confirmation_code }
      });
      expect(resolved).toEqual({ confirmed: false, reason: "canonical_stale" });
      const persisted = await pool.query<{
        votes: string;
        consents: string;
        stage_state: string;
        rejected_events: string;
      }>(
        `select
           (select count(*)::text from votes where id=$1) as votes,
           (select count(*)::text from consent_records where stage_id=$2) as consents,
           (select state from action_stages where id=$2) as stage_state,
           (select count(*)::text from audit_events
             where object_id=$2 and event_type='consent_rejected') as rejected_events`,
        [fixture.voteId, prepared.stage_id]
      );
      expect(persisted.rows).toEqual([
        { votes: "0", consents: "0", stage_state: "rejected", rejected_events: "1" }
      ]);
    });
  });
});

describe("open-vote replacement MCP lifecycle surface", () => {
  it("MR-VOTE-PRIVACY-003 refuses replacement confirmation material for an exact-recused secretary", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const caller = await administrativeService(
        pool,
        await freshAdministrativeTestCredential(pool, fixture.secretary, 999100)
      );
      const liftingSecretary = await seedEligibleRecusalSecretary(pool, fixture, 2_200_000);
      let nextId = 999200;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: caller.reads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const prepare = (recused: boolean) =>
        service.prepareHumanAction(caller.principal, "replace_open_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          replacement_vote_id: fixture.newVoteId,
          changed_component_classes: recused ? ["resolution", "electorate"] : ["resolution"],
          replacement_package: {
            schema_version: "boardagent.vote-replacement-draft.v1",
            values: {
              title: fixture.replacementTitle,
              resolution_text: fixture.newResolutionText,
              components: fixture.replacementDecisionPackage.components,
              approval_rule_id: fixture.replacementDecisionPackage.approvalRuleId,
              matter_evaluation_id: fixture.replacementDecisionPackage.matterEvaluationId,
              selected_ruleset_rule_id: fixture.replacementDecisionPackage.selectedRulesetRuleId,
              override_reason: null,
              close_mode: fixture.replacementDecisionPackage.closeMode,
              deadline_at: fixture.replacementDecisionPackage.deadlineAt
            }
          },
          reason: fixture.replacementReason,
          idempotency_key: "replacement-confirmation-privacy"
        });
      const read = () =>
        caller.reads.executeRead(caller.principal, "get_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId
        });
      const recuse = (actingSecretary: SurfacePrincipal, operation: "add" | "lift") =>
        confirmSurfaceVoteAction(service, actingSecretary, "manage_recusal", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.secretary.boardId,
          member_id: fixture.secretary.memberId,
          object_type: "vote",
          object_id: fixture.voteId,
          operation,
          reason: "Keep manual confirmation visibility separate from internal replacement effects.",
          idempotency_key: `replacement-privacy-${operation}`
        });
      const original = await prepare(false);
      expect(original.confirmation_lines.join("\n")).toContain(fixture.newResolutionText);
      expect(original.confirmation_lines.join("\n")).toContain("boardagent.decision-package.v1");
      expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });

      await recuse(caller.principal, "add");
      expect((await read()).data).toMatchObject({ vote: null });
      const evidence = async () =>
        (
          await pool.query(
            `select vote.state,vote.row_version::text,
              (select count(*)::int from votes) as votes,
              (select count(*)::int from decision_packages) as packages,
              (select count(*)::int from vote_exclusions) as exclusions,
              (select count(*)::int from ballot_dispositions) as ballot_dispositions,
              (select count(*)::int from proxy_revocations) as proxy_revocations,
              (select count(*)::int from action_stages) as stages,
              (select count(*)::int from vote_replacement_stage_material) as stage_material,
              (select count(*)::int from consent_records) as consents,
              (select count(*)::int from audit_events) as audit_events,
              (select count(*)::int from notices) as notices
             from votes vote where vote.id=$1`,
            [fixture.voteId]
          )
        ).rows;
      const before = await evidence();
      const hidden = await prepare(true).then(
        (prepared) => prepared,
        (error: unknown) => {
          expect(error).toMatchObject({ code: "vote_replacement_unavailable" });
          return null;
        }
      );
      expect(await evidence()).toEqual(before);

      await recuse(liftingSecretary.principal, "lift");
      expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });
      const restored = await prepare(false);
      expect(restored.confirmation_lines.join("\n")).toContain(fixture.newResolutionText);
      expect(restored.confirmation_lines.join("\n")).toContain("boardagent.decision-package.v1");
      expect({
        hiddenPreparationReturned: hidden !== null,
        canonicalPackageReturned:
          hidden?.confirmation_lines.join("\n").includes("boardagent.decision-package.v1") ?? false
      }).toEqual({ hiddenPreparationReturned: false, canonicalPackageReturned: false });
    });
  });

  it.each(["amend_resolution_text", "extend_vote_deadline"] as const)(
    "MR-VOTE-PRIVACY-003 applies current recusal before deriving %s confirmation material",
    async (tool) => {
      await withDatabase(async (pool) => {
        const fixture = await seedVoteReplacementFixture(pool);
        const caller = await administrativeService(
          pool,
          await freshAdministrativeTestCredential(pool, fixture.secretary, 999700)
        );
        const liftingSecretary = await seedEligibleRecusalSecretary(pool, fixture, 2_201_000);
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          reason: "Keep derived replacement material within current vote visibility.",
          idempotency_key: `replacement-privacy-${tool}`,
          ...(tool === "amend_resolution_text"
            ? {
                expected_resolution_version_id: fixture.decisionPackage.resolutionVersionId,
                resolution_text: fixture.newResolutionText
              }
            : { deadline_at: new Date(Date.parse(fixture.deadlineAt) + 86_400_000).toISOString() })
        };
        const prepare = () => caller.service.prepareHumanAction(caller.principal, tool, input);
        const recuse = (actingSecretary: SurfacePrincipal, operation: "add" | "lift") =>
          confirmSurfaceVoteAction(caller.service, actingSecretary, "manage_recusal", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.secretary.boardId,
            member_id: fixture.secretary.memberId,
            object_type: "vote",
            object_id: fixture.voteId,
            operation,
            reason: "Exercise derived manual preparation with current exact recusal.",
            idempotency_key: `derived-replacement-privacy-${operation}`
          });
        const expectedResolution =
          tool === "amend_resolution_text" ? fixture.newResolutionText : fixture.resolutionText;
        expect((await prepare()).confirmation_lines.join("\n")).toContain(expectedResolution);
        await recuse(caller.principal, "add");
        const hidden = await caller.reads.executeRead(caller.principal, "get_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId
        });
        expect(hidden.data).toMatchObject({ vote: null });
        await expect(prepare()).rejects.toMatchObject({
          code: "vote_replacement_unavailable",
          message: "vote replacement is unavailable"
        });
        await recuse(liftingSecretary.principal, "lift");
        expect((await prepare()).confirmation_lines.join("\n")).toContain(expectedResolution);
      });
    }
  );

  it.each([
    { label: "lifted", operations: ["add", "lift"] as const, remainsExcluded: false },
    { label: "excluded again", operations: ["add", "lift", "add"] as const, remainsExcluded: true }
  ])(
    "MR-VOTE-001 uses the latest recusal when a $label voter enters a replacement electorate",
    async ({ operations, remainsExcluded }) => {
      await withDatabase(async (pool) => {
        const fixture = await seedVoteRecusalFixture(pool);
        const replacementSecretary = await seedAdditionalAuthorizedActor(pool, fixture.secretary, {
          idBase: 1_551_000,
          seatRole: "management",
          isSecretary: true,
          scopes: ["secretariat:admin", "governance:read"],
          uniqueHashes: true
        });
        const replacementPrincipal = surfacePrincipal(
          replacementSecretary,
          ["member", "secretariat"],
          ["secretariat:admin", "governance:read"]
        );
        let nextId = 1_550_000;
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableSurfaceReads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(nextId++)
        });
        const secretary = surfacePrincipal(
          fixture.secretary,
          ["member", "secretariat"],
          ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"]
        );
        for (const [index, operation] of operations.entries()) {
          const recusal = await confirmSurfaceVoteAction(
            service,
            operation === "lift" ? replacementPrincipal : secretary,
            "manage_recusal",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              board_id: fixture.secretary.boardId,
              member_id: fixture.secretary.memberId,
              object_type: "vote",
              object_id: fixture.voteId,
              operation,
              reason: `Exact replacement eligibility regression ${String(index + 1)}: ${operation}.`,
              idempotency_key: `latest-recusal-replacement-${String(index + 1).padStart(4, "0")}`
            }
          );
          expect(recusal.result).toMatchObject({
            status: "accepted",
            data: {
              exclusion_version: index + 1,
              state: operation === "add" ? "excluded" : "lifted",
              eligible_weight: operation === "add" ? "1" : "2"
            }
          });
        }
        const exclusionHistory = await pool.query<{ version: number; state: string }>(
          "select version,state from vote_exclusions where vote_id=$1 and member_id=$2 order by version",
          [fixture.voteId, fixture.secretary.memberId]
        );
        expect(exclusionHistory.rows).toEqual(
          operations.map((operation, index) => ({
            version: index + 1,
            state: operation === "add" ? "excluded" : "lifted"
          }))
        );
        const expectedMemberIds = (
          remainsExcluded
            ? [fixture.voter.memberId]
            : [fixture.secretary.memberId, fixture.voter.memberId]
        ).toSorted();
        const currentElectorate = await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            client.query<{ member_id: string }>(
              "select member_id from boardagent_lock_replacement_electorate($1)",
              [fixture.voteId]
            ),
          { assumeRole: "boardagent_server" }
        );
        expect
          .soft(currentElectorate.rows.map(({ member_id }) => member_id))
          .toEqual(expectedMemberIds);
        const historicEvidence = () =>
          pool.query<{ evidence: unknown }>(
            `select jsonb_build_object(
          'package',(select to_jsonb(package) from decision_packages package where vote_id=$1),
          'electorate',(select jsonb_agg(to_jsonb(elector) order by elector.member_id)
            from vote_electorate elector where vote_id=$1),
          'ballots',(select jsonb_agg(to_jsonb(ballot) order by ballot.id) from ballots ballot where vote_id=$1),
          'proxies',(select jsonb_agg(to_jsonb(proxy) order by proxy.id) from proxy_grants proxy where vote_id=$1),
          'exclusions',(select jsonb_agg(to_jsonb(exclusion) order by exclusion.version)
            from vote_exclusions exclusion where vote_id=$1)) as evidence`,
            [fixture.voteId]
          );
        const before = await historicEvidence();
        const replaced = await confirmSurfaceVoteAction(
          service,
          replacementPrincipal,
          "replace_open_vote",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            vote_id: fixture.voteId,
            replacement_vote_id: fixture.newVoteId,
            changed_component_classes: remainsExcluded
              ? ["resolution", "electorate"]
              : ["resolution"],
            replacement_package: {
              schema_version: "boardagent.vote-replacement-draft.v1",
              values: {
                title: fixture.replacementTitle,
                resolution_text: fixture.newResolutionText,
                components: fixture.replacementDecisionPackage.components,
                approval_rule_id: fixture.replacementDecisionPackage.approvalRuleId,
                matter_evaluation_id: fixture.replacementDecisionPackage.matterEvaluationId,
                selected_ruleset_rule_id: fixture.replacementDecisionPackage.selectedRulesetRuleId,
                override_reason: null,
                close_mode: fixture.replacementDecisionPackage.closeMode,
                deadline_at: fixture.replacementDecisionPackage.deadlineAt
              }
            },
            reason: fixture.replacementReason,
            idempotency_key: "latest-recusal-exact-replacement-0001"
          }
        );
        expect(replaced.result).toMatchObject({ status: "accepted", reference: fixture.newVoteId });
        expect((await historicEvidence()).rows).toEqual(before.rows);
        const final = await pool.query<{
          old_state: string;
          new_state: string;
          new_members: string[];
          notified_members: string[];
          new_ballots: number;
          new_proxies: number;
          active_new_stages: number;
        }>(
          `select old.state as old_state,new.state as new_state,
          (select array_agg(member_id::text order by member_id) from vote_electorate where vote_id=new.id) as new_members,
          (select array_agg(member_id::text order by member_id) from pending_action_feed
            where object_id=new.id and action_type='vote_opened' and state='pending') as notified_members,
          (select count(*)::int from ballots where vote_id=new.id) as new_ballots,
          (select count(*)::int from proxy_grants where vote_id=new.id) as new_proxies,
          (select count(*)::int from action_stages where target_id=new.id and state='active') as active_new_stages
          from votes old join votes new on new.id=$2 where old.id=$1`,
          [fixture.voteId, fixture.newVoteId]
        );
        expect(final.rows).toEqual([
          {
            old_state: "superseded",
            new_state: "open",
            new_members: expectedMemberIds,
            notified_members: expectedMemberIds,
            new_ballots: 0,
            new_proxies: 0,
            active_new_stages: 0
          }
        ]);
      });
    }
  );

  it("confirms one exact replacement package and carries no prior act", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
      );
      const ordinaryMember = surfacePrincipal(
        fixture.voter,
        ["member"],
        ["governance:read", "proxy:manage", "vote:act"]
      );
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        replacement_vote_id: fixture.newVoteId,
        changed_component_classes: ["resolution"],
        replacement_package: {
          schema_version: "boardagent.vote-replacement-draft.v1",
          values: {
            title: fixture.replacementTitle,
            resolution_text: fixture.newResolutionText,
            components: fixture.replacementDecisionPackage.components,
            approval_rule_id: fixture.replacementDecisionPackage.approvalRuleId,
            matter_evaluation_id: fixture.replacementDecisionPackage.matterEvaluationId,
            selected_ruleset_rule_id: fixture.replacementDecisionPackage.selectedRulesetRuleId,
            override_reason: null,
            close_mode: fixture.replacementDecisionPackage.closeMode,
            deadline_at: fixture.replacementDecisionPackage.deadlineAt
          }
        },
        reason: fixture.replacementReason,
        idempotency_key: "surface-replace-open-vote-0001"
      } as const;

      await expect(
        service.prepareHumanAction(ordinaryMember, "replace_open_vote", input)
      ).rejects.toThrow(/unavailable/u);
      const prepared = await service.prepareHumanAction(secretary, "replace_open_vote", input);
      expect(prepared.confirmation_lines.join("\n")).toContain(fixture.newResolutionText);
      expect(prepared.confirmation_lines.join("\n")).toContain(fixture.replacementReason);
      const before = await pool.query<{ new_votes: string; old_state: string }>(
        `select state as old_state,
                (select count(*)::text from votes where id=$2) as new_votes
           from votes where id=$1`,
        [fixture.voteId, fixture.newVoteId]
      );
      expect(before.rows).toEqual([{ old_state: "open", new_votes: "0" }]);

      const replaced = await confirmSurfaceVoteAction(
        service,
        secretary,
        "replace_open_vote",
        input
      );
      expect(replaced.result).toMatchObject({
        tool: "replace_open_vote",
        status: "accepted",
        reference: fixture.newVoteId,
        data: {
          old_vote_id: fixture.voteId,
          new_vote_id: fixture.newVoteId,
          state: "open",
          changed_component_classes: ["resolution"],
          replayed: false
        }
      });
      const persisted = await pool.query<{
        active_ballots: string;
        active_proxies: string;
        active_stages: string;
        new_state: string;
        old_state: string;
        revote_rows: string;
      }>(
        `select old.state as old_state,new.state as new_state,
                (select count(*)::text from ballots as ballot
                  left join ballot_dispositions as disposition
                    on disposition.prior_ballot_id=ballot.id
                  where ballot.vote_id=new.id and disposition.id is null) as active_ballots,
                (select count(*)::text from proxy_grants as proxy
                  left join proxy_revocations as revocation on revocation.grant_id=proxy.id
                  where proxy.vote_id=new.id and revocation.id is null) as active_proxies,
                (select count(*)::text from action_stages
                  where target_id=new.id and state='active') as active_stages,
                (select count(*)::text from pending_action_feed
                  where object_id=new.id and action_type='revote_required' and state='pending')
                  as revote_rows
           from votes as old
           join vote_supersessions as supersession on supersession.old_vote_id=old.id
           join votes as new on new.id=supersession.new_vote_id
          where old.id=$1`,
        [fixture.voteId]
      );
      expect(persisted.rows).toEqual([
        {
          old_state: "superseded",
          new_state: "open",
          active_ballots: "0",
          active_proxies: "0",
          active_stages: "0",
          revote_rows: "1"
        }
      ]);
    });
  });

  it("rejects a stale replacement and mismatched declared delta without creating a new vote", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
      );
      const replacementPackage = {
        schema_version: "boardagent.vote-replacement-draft.v1",
        values: {
          title: fixture.replacementTitle,
          resolution_text: fixture.newResolutionText,
          components: fixture.replacementDecisionPackage.components,
          approval_rule_id: fixture.replacementDecisionPackage.approvalRuleId,
          matter_evaluation_id: fixture.replacementDecisionPackage.matterEvaluationId,
          selected_ruleset_rule_id: fixture.replacementDecisionPackage.selectedRulesetRuleId,
          override_reason: null,
          close_mode: fixture.replacementDecisionPackage.closeMode,
          deadline_at: fixture.replacementDecisionPackage.deadlineAt
        }
      } as const;
      await expect(
        service.prepareHumanAction(secretary, "replace_open_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          replacement_vote_id: fixture.newVoteId,
          changed_component_classes: ["deadline"],
          replacement_package: replacementPackage,
          reason: fixture.replacementReason,
          idempotency_key: "surface-replace-wrong-delta-0001"
        })
      ).rejects.toThrow("declared replacement component classes");

      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        replacement_vote_id: fixture.newVoteId,
        changed_component_classes: ["resolution"],
        replacement_package: replacementPackage,
        reason: fixture.replacementReason,
        idempotency_key: "surface-replace-stale-vote-0001"
      } as const;
      const prepared = await service.prepareHumanAction(secretary, "replace_open_vote", input);
      const capabilities = { elicitation: { form: {} } } as const;
      const requestState = "surface-replace-stale-state-bound-to-exact-package";
      await service.persistHumanStage({
        principal: secretary,
        tool: "replace_open_vote",
        input,
        prepared,
        client_capabilities: capabilities,
        embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
        embedded_result: { message: "Confirm exact stale replacement test" },
        request_state: requestState,
        prepared_request_id: Buffer.from("surface-replace-stale-prepare")
      });
      await pool.query(
        "update board_memberships set voting_weight=2 where board_id=$1 and member_id=$2",
        [fixture.secretary.boardId, fixture.voter.memberId]
      );
      const resolved = await service.resolveHumanAction({
        principal: secretary,
        tool: "replace_open_vote",
        input,
        stage_id: prepared.stage_id,
        client_capabilities: capabilities,
        request_state: requestState,
        retry_request_id: Buffer.from(`surface-replace-stale-retry-${prepared.stage_id}`),
        response_action: "accept",
        input_response: { approve: true, confirmation_code: prepared.confirmation_code }
      });
      expect(resolved).toEqual({ confirmed: false, reason: "canonical_stale" });
      const persisted = await pool.query<{
        consents: string;
        new_votes: string;
        old_state: string;
        stage_state: string;
      }>(
        `select state as old_state,
                (select count(*)::text from votes where id=$2) as new_votes,
                (select count(*)::text from consent_records where stage_id=$3) as consents,
                (select state from action_stages where id=$3) as stage_state
           from votes where id=$1`,
        [fixture.voteId, fixture.newVoteId, prepared.stage_id]
      );
      expect(persisted.rows).toEqual([
        { old_state: "open", new_votes: "0", consents: "0", stage_state: "rejected" }
      ]);
    });
  });
});

describe("open-vote amendment and deadline MCP replacement aliases", () => {
  it("amends an open resolution only by superseding it with an empty linked vote", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
      );
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        expected_resolution_version_id: fixture.decisionPackage.resolutionVersionId,
        resolution_text: fixture.newResolutionText,
        reason: fixture.replacementReason,
        idempotency_key: "surface-amend-open-resolution-0001"
      } as const;
      const amended = await confirmSurfaceVoteAction(
        service,
        secretary,
        "amend_resolution_text",
        input
      );
      expect(amended.prepared.confirmation_lines.join("\n")).toContain(
        "Changed component classes: resolution"
      );
      expect(amended.result).toMatchObject({
        tool: "amend_resolution_text",
        status: "accepted",
        data: {
          old_vote_id: fixture.voteId,
          state: "open",
          changed_component_classes: ["resolution"],
          replayed: false
        }
      });
      const data = amended.result.data as { readonly new_vote_id: string };
      const persisted = await pool.query<{
        active_ballots: string;
        amendment_events: string;
        current_text: string;
        new_state: string;
        old_state: string;
        revote_rows: string;
      }>(
        `select old.state as old_state,new.state as new_state,
                resolution.canonical_text as current_text,
                (select count(*)::text from audit_events
                  where object_id=resolution.id and event_type='resolution_amended')
                  as amendment_events,
                (select count(*)::text from ballots as ballot
                  left join ballot_dispositions as disposition
                    on disposition.prior_ballot_id=ballot.id
                  where ballot.vote_id=new.id and disposition.id is null) as active_ballots,
                (select count(*)::text from pending_action_feed
                  where object_id=new.id and action_type='revote_required' and state='pending')
                  as revote_rows
           from votes as old
           join vote_supersessions as supersession on supersession.old_vote_id=old.id
           join votes as new on new.id=supersession.new_vote_id
           join resolution_versions as resolution on resolution.id=new.current_resolution_version_id
          where old.id=$1 and new.id=$2`,
        [fixture.voteId, data.new_vote_id]
      );
      expect(persisted.rows).toEqual([
        {
          old_state: "superseded",
          new_state: "open",
          current_text: fixture.newResolutionText,
          active_ballots: "0",
          amendment_events: "1",
          revote_rows: "1"
        }
      ]);
    });
  });

  it("extends an open deadline only through a linked replacement and rejects shortening", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["governance:read", "proxy:manage", "secretariat:admin", "vote:act"]
      );
      await expect(
        service.prepareHumanAction(secretary, "extend_vote_deadline", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          deadline_at: fixture.deadlineAt,
          reason: "No extension is represented by the same deadline.",
          idempotency_key: "surface-deadline-not-later-0001"
        })
      ).rejects.toThrow("strictly later");

      const extendedDeadline = new Date(Date.parse(fixture.deadlineAt) + 86_400_000).toISOString();
      const extended = await confirmSurfaceVoteAction(service, secretary, "extend_vote_deadline", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        deadline_at: extendedDeadline,
        reason: "Allow one additional day for the exact unchanged package.",
        idempotency_key: "surface-extend-open-deadline-0001"
      });
      expect(extended.result).toMatchObject({
        tool: "extend_vote_deadline",
        status: "accepted",
        data: {
          old_vote_id: fixture.voteId,
          state: "open",
          changed_component_classes: ["deadline"],
          replayed: false
        }
      });
      const data = extended.result.data as { readonly new_vote_id: string };
      const persisted = await pool.query<{
        deadline_at: string;
        new_state: string;
        old_state: string;
      }>(
        `select old.state as old_state,new.state as new_state,
                to_char(new.deadline_at at time zone 'UTC',
                  'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') as deadline_at
           from votes as old
           join vote_supersessions as supersession on supersession.old_vote_id=old.id
           join votes as new on new.id=supersession.new_vote_id
          where old.id=$1 and new.id=$2`,
        [fixture.voteId, data.new_vote_id]
      );
      expect(persisted.rows).toEqual([
        { old_state: "superseded", new_state: "open", deadline_at: extendedDeadline }
      ]);
    });
  });
});

describe("ballot and proxy MCP lifecycle surface", () => {
  it("confirms grant, attributed proxy ballot, revocation and direct precedence in audit order", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const observer = await seedAdditionalAuthorizedActor(pool, fixture.secretary, {
        idBase: 910_000,
        seatRole: "observer",
        scopes: ["governance:read", "proxy:manage", "vote:act"]
      });
      let nextId = 920_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"]
      );
      const voter = surfacePrincipal(
        fixture.voter,
        ["member"],
        ["governance:read", "proxy:manage", "vote:act"]
      );
      const observerPrincipal = surfacePrincipal(
        observer,
        ["observer"],
        ["governance:read", "proxy:manage", "vote:act"]
      );

      await expect(
        service.prepareHumanAction(observerPrincipal, "stage_ballot", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          principal_member_id: null,
          choice: "yes",
          statement: null,
          idempotency_key: "surface-observer-ballot-denied-0001"
        })
      ).rejects.toThrow("ballot or proxy action is unavailable");

      const granted = await confirmSurfaceVoteAction(service, secretary, "grant_proxy", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        holder_member_id: fixture.voter.memberId,
        idempotency_key: "surface-proxy-grant-0001"
      });
      expect(granted.prepared.confirmation_lines.join("\n")).toContain(
        fixture.decisionPackage.resolutionSha256
      );
      expect(granted.prepared.confirmation_lines.join("\n")).toContain(
        canonicalJson(fixture.decisionPackage)
      );
      expect(granted.result).toMatchObject({
        tool: "grant_proxy",
        status: "accepted",
        data: {
          vote_id: fixture.voteId,
          principal_member_id: fixture.secretary.memberId,
          holder_member_id: fixture.voter.memberId,
          policy: "principal_supersedes_proxy"
        }
      });
      if (granted.result.reference === null) throw new Error("proxy grant is missing");

      const proxyReads = new DirectReadRepository(pool, {
        cursorKey: Buffer.alloc(32, 0x53),
        transaction: { assumeRole: "boardagent_server" }
      });
      const nonPartySecretary = await seedAdditionalAuthorizedActor(pool, fixture.secretary, {
        idBase: 930_000,
        seatRole: "management",
        isSecretary: true,
        scopes: ["governance:read"]
      });
      const readPrincipals: SurfacePrincipal[] = [];
      for (const [index, actor] of [
        secretary,
        voter,
        observerPrincipal,
        surfacePrincipal(nonPartySecretary, ["member", "secretariat"], ["governance:read"])
      ].entries()) {
        const sessionId = testId(925_000 + index);
        await pool.query(
          `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,
             client_id,state,exact_origin,expires_at,last_authenticated_at)
           values($1,$2,$3,$4,$5,'authenticated','https://boardagent.test',
             transaction_timestamp()+interval '1 hour',transaction_timestamp())`,
          [
            sessionId,
            actor.organizationId,
            Buffer.alloc(32, 210 + index),
            actor.memberId,
            actor.clientId
          ]
        );
        await pool.query("update access_token_records set session_id=$1 where id=$2", [
          sessionId,
          actor.accessTokenRecordId
        ]);
        const live = await pool.query(
          "select protocol_client_id,scope_set,roles,board_ids from boardagent_resolve_access_token($1)",
          [actor.tokenJti]
        );
        expect(live.rows).toHaveLength(1);
        readPrincipals.push({
          ...actor,
          protocolClientId: live.rows[0].protocol_client_id,
          scopes: live.rows[0].scope_set,
          roles: live.rows[0].roles,
          boardIds: live.rows[0].board_ids
        });
      }
      for (const actor of readPrincipals.slice(0, 2)) {
        const status = await proxyReads.executeRead(actor, "get_proxy_status", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          member_id: null
        });
        expect(status.data).toMatchObject({
          grants: [{ grant_id: granted.result.reference, active: true, expires_at: null }]
        });
      }
      const unrelated = await proxyReads.executeRead(readPrincipals[2]!, "get_proxy_status", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        member_id: fixture.secretary.memberId
      });
      expect(unrelated.data).toMatchObject({ grants: [] });
      const unrelatedFilter = await proxyReads.executeRead(readPrincipals[1]!, "get_proxy_status", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        member_id: observer.memberId
      });
      expect(unrelatedFilter.data).toMatchObject({ grants: [] });
      const secretaryView = await proxyReads.executeRead(readPrincipals[3]!, "get_proxy_status", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        member_id: fixture.secretary.memberId
      });
      expect(secretaryView.data).toMatchObject({
        grants: [{ grant_id: granted.result.reference, active: true, expires_at: null }]
      });

      const proxyBallot = await confirmSurfaceVoteAction(service, voter, "stage_ballot", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        principal_member_id: fixture.secretary.memberId,
        choice: "yes",
        statement: "Proxy vote cast over the displayed immutable package.",
        idempotency_key: "surface-proxy-ballot-0001"
      });
      expect(proxyBallot.result).toMatchObject({
        tool: "stage_ballot",
        status: "accepted",
        data: {
          principal_member_id: fixture.secretary.memberId,
          caster_member_id: fixture.voter.memberId,
          source: "proxy"
        }
      });

      const proxyRetryInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        principal_member_id: fixture.secretary.memberId,
        choice: "yes",
        statement: "Proxy vote cast over the displayed immutable package.",
        idempotency_key: "surface-proxy-ballot-0001"
      } as const;
      const beforeRetry = await pool.query(
        `select (select count(*) from action_stages)::text as stages,
                (select count(*) from consent_records)::text as consents,
                (select count(*) from audit_events)::text as audit,
                (select count(*) from ballots)::text as ballots`
      );
      await expect(
        service.replayHumanAction(voter, "stage_ballot", proxyRetryInput)
      ).resolves.toMatchObject({
        status: "already_applied",
        reference: proxyBallot.result.reference,
        data: {
          replayed: true,
          response_sha256: (proxyBallot.result.data as Record<string, JsonValue>)["response_sha256"]
        }
      });
      await expect(
        service.replayHumanAction(voter, "stage_ballot", {
          ...proxyRetryInput,
          choice: "no"
        })
      ).rejects.toThrow("idempotency");
      await expect(
        service.replayHumanAction(voter, "stage_ballot", {
          ...proxyRetryInput,
          statement: "Different statement"
        })
      ).rejects.toThrow("idempotency");
      await expect(
        service.replayHumanAction(voter, "stage_ballot", {
          ...proxyRetryInput,
          idempotency_key: "new-uncast-ballot-key"
        })
      ).resolves.toBeNull();
      await expect(
        service.replayHumanAction(observerPrincipal, "stage_ballot", proxyRetryInput)
      ).rejects.toThrow("ballot or proxy action is unavailable");
      expect(
        (
          await pool.query(
            `select (select count(*) from action_stages)::text as stages,
                (select count(*) from consent_records)::text as consents,
                (select count(*) from audit_events)::text as audit,
                (select count(*) from ballots)::text as ballots`
          )
        ).rows
      ).toEqual(beforeRetry.rows);

      const revoked = await confirmSurfaceVoteAction(service, secretary, "revoke_proxy", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        grant_id: granted.result.reference,
        reason: "The principal now intends to vote directly.",
        idempotency_key: "surface-proxy-revoke-0001"
      });
      expect(revoked.result).toMatchObject({
        tool: "revoke_proxy",
        status: "accepted",
        data: { effect: "revoked", proxy_grant_id: granted.result.reference }
      });

      for (const actor of readPrincipals.slice(0, 2)) {
        const status = await proxyReads.executeRead(actor, "get_proxy_status", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          member_id: null
        });
        expect(status.data).toMatchObject({
          grants: [{ grant_id: granted.result.reference, active: false, expires_at: null }]
        });
      }

      await expect(
        service.replayHumanAction(voter, "stage_ballot", proxyRetryInput)
      ).rejects.toThrow("ballot or proxy action is unavailable");

      const directBallot = await confirmSurfaceVoteAction(service, secretary, "stage_ballot", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        principal_member_id: null,
        choice: "no",
        statement: "Direct principal ballot supersedes the earlier proxy ballot.",
        idempotency_key: "surface-direct-ballot-0001"
      });
      expect(directBallot.result).toMatchObject({
        data: {
          principal_member_id: fixture.secretary.memberId,
          caster_member_id: fixture.secretary.memberId,
          source: "own",
          superseded_ballot_id: proxyBallot.result.reference
        }
      });

      await expect(
        confirmSurfaceVoteAction(service, voter, "stage_ballot", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          principal_member_id: null,
          choice: "abstain",
          statement: null,
          idempotency_key: "surface-voter-own-ballot-0001"
        })
      ).resolves.toMatchObject({
        result: {
          data: {
            principal_member_id: fixture.voter.memberId,
            caster_member_id: fixture.voter.memberId,
            source: "own"
          }
        }
      });

      const evidence = await pool.query<{
        active_ballots: string;
        ballot_dispositions: string;
        ballots: string;
        grants: string;
        proxy_acting_for: string | null;
        revocations: string;
      }>(
        `select
           (select count(*)::text from proxy_grants where vote_id=$1) as grants,
           (select count(*)::text from proxy_revocations) as revocations,
           (select count(*)::text from ballots where vote_id=$1) as ballots,
           (select count(*)::text from ballot_dispositions) as ballot_dispositions,
           (select count(*)::text from ballots as ballot
             left join ballot_dispositions as disposition
               on disposition.prior_ballot_id=ballot.id
            where ballot.vote_id=$1 and disposition.id is null) as active_ballots,
           (select acting_for_member_id::text from consent_records
             where action_code='stage_ballot' and actor_member_id=$2
               and acting_for_member_id is not null order by confirmed_at limit 1)
             as proxy_acting_for`,
        [fixture.voteId, fixture.voter.memberId]
      );
      expect(evidence.rows[0]).toEqual({
        grants: "1",
        revocations: "1",
        ballots: "3",
        ballot_dispositions: "1",
        active_ballots: "2",
        proxy_acting_for: fixture.secretary.memberId
      });

      const ordered = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where event_type in (
            'consent_recorded','proxy_granted','proxy_revoked',
            'ballot_cast','ballot_superseded'
          ) order by sequence`
      );
      expect(ordered.rows.map(({ event_type }) => event_type)).toEqual([
        "consent_recorded",
        "proxy_granted",
        "consent_recorded",
        "ballot_cast",
        "consent_recorded",
        "proxy_revoked",
        "consent_recorded",
        "ballot_superseded",
        "ballot_cast",
        "consent_recorded",
        "ballot_cast"
      ]);
    });
  });
});

describe("pending vote-source exclusion MCP lifecycle surface", () => {
  it("MR-VOTE-PRIVACY-002 does not disclose source-exclusion material to an exact-recused secretary", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const cause = await seedPendingSourceCause(pool, fixture, 995400, "document");
      const caller = await administrativeService(
        pool,
        await freshAdministrativeTestCredential(pool, fixture.secretary, 995500)
      );
      const liftingSecretary = await seedEligibleRecusalSecretary(pool, fixture, 2_202_000);
      let nextId = 995600;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: caller.reads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        source_type: cause.sourceClass,
        source_id: cause.sourceId,
        source_version: cause.sourceVersion,
        source_sha256: cause.sourceSha256,
        reason: "This exact synthetic pending update is confirmed nonmaterial.",
        idempotency_key: "source-exclusion-confirmation-privacy"
      };
      const prepare = () =>
        service.prepareHumanAction(caller.principal, "exclude_pending_vote_source", input);
      const read = () =>
        caller.reads.executeRead(caller.principal, "get_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId
        });
      const recuse = (actingSecretary: SurfacePrincipal, operation: "add" | "lift") =>
        confirmSurfaceVoteAction(service, actingSecretary, "manage_recusal", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.secretary.boardId,
          member_id: fixture.secretary.memberId,
          object_type: "vote",
          object_id: fixture.voteId,
          operation,
          reason: "Separate current visibility from internal pending-source effects.",
          idempotency_key: `source-exclusion-privacy-${operation}`
        });
      const original = await prepare();
      expect(original.confirmation_lines.join("\n")).toContain(fixture.resolutionText);
      expect(original.confirmation_lines.join("\n")).toContain(
        canonicalJson(fixture.decisionPackage)
      );
      expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });

      await recuse(caller.principal, "add");
      expect((await read()).data).toMatchObject({ vote: null });
      const evidence = async () =>
        (
          await pool.query(
            `select vote.state,vote.row_version::text,
              (select count(*)::int from vote_source_update_causes) as causes,
              (select count(*)::int from vote_source_update_dispositions) as dispositions,
              (select count(*)::int from action_stages) as stages,
              (select count(*)::int from consent_records) as consents,
              (select count(*)::int from audit_events) as audit_events,
              (select count(*)::int from notices) as notices
             from votes vote where vote.id=$1`,
            [fixture.voteId]
          )
        ).rows;
      const before = await evidence();
      const hidden = await prepare().then(
        (prepared) => prepared,
        (error: unknown) => {
          expect(error).toMatchObject({ code: "vote_source_exclusion_unavailable" });
          return null;
        }
      );
      expect(await evidence()).toEqual(before);

      await recuse(liftingSecretary.principal, "lift");
      expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });
      const restored = await prepare();
      expect(restored.confirmation_lines.join("\n")).toContain(fixture.resolutionText);
      expect(restored.confirmation_lines.join("\n")).toContain(
        canonicalJson(fixture.decisionPackage)
      );
      const disclosed = hidden
        ? [...hidden.confirmation_lines, canonicalJson(hidden.canonical_payload)].join("\n")
        : "";
      expect({
        resolutionDisclosed: disclosed.includes(fixture.resolutionText),
        packageDisclosed: disclosed.includes(canonicalJson(fixture.decisionPackage))
      }).toEqual({ resolutionDisclosed: false, packageDisclosed: false });
    });
  });

  it("denies an observer and excludes only the exact pending source after confirmation", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteOpenFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => openVoteInTransaction(client, voteOpenInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const cause = await seedPendingSourceCause(pool, fixture, 970_000, "document");
      const observer = await seedAdditionalAuthorizedActor(pool, fixture.secretary, {
        idBase: 971_000,
        seatRole: "observer",
        scopes: ["governance:read", "secretariat:admin"]
      });
      let nextId = 972_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["secretariat:admin", "governance:read"]
      );
      const observerPrincipal = surfacePrincipal(
        observer,
        ["observer"],
        ["secretariat:admin", "governance:read"]
      );
      const sourceInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        source_type: cause.sourceClass,
        source_id: cause.sourceId,
        source_version: cause.sourceVersion,
        source_sha256: cause.sourceSha256,
        reason: "This exact post-opening document update is confirmed nonmaterial.",
        idempotency_key: "surface-source-exclusion-0001"
      } as const;

      await expect(
        service.prepareHumanAction(observerPrincipal, "exclude_pending_vote_source", sourceInput)
      ).rejects.toMatchObject({ code: "vote_source_exclusion_unavailable" });

      const excluded = await confirmSurfaceVoteAction(
        service,
        secretary,
        "exclude_pending_vote_source",
        sourceInput
      );
      expect(excluded.prepared.confirmation_lines.join("\n")).toContain(cause.sourceSha256);
      expect(excluded.prepared.confirmation_lines.join("\n")).toContain(
        canonicalJson(fixture.decisionPackage)
      );
      expect(canonicalSha256(excluded.prepared.canonical_payload)).toBe(
        voteSourceExclusionConsentHash({
          voteId: fixture.voteId,
          causeId: cause.causeId,
          sourceClass: cause.sourceClass,
          sourceId: cause.sourceId,
          sourceVersion: cause.sourceVersion,
          sourceSha256: cause.sourceSha256,
          reason: sourceInput.reason,
          packageSha256: canonicalSha256(fixture.decisionPackage)
        })
      );
      expect(excluded.result).toMatchObject({
        tool: "exclude_pending_vote_source",
        status: "accepted",
        data: {
          vote_id: fixture.voteId,
          cause_id: cause.causeId,
          source_type: "document",
          source_id: cause.sourceId,
          source_version: cause.sourceVersion,
          source_sha256: cause.sourceSha256,
          remaining_pending_sources: 0,
          vote_state: "open",
          replayed: false
        }
      });
      const persisted = await pool.query<{
        effect: string;
        package_sha256: string;
        state: string;
      }>(
        `select vote.state,encode(package.package_sha256,'hex') as package_sha256,
                disposition.effect
           from votes as vote
           join decision_packages as package on package.id=vote.current_decision_package_id
           join vote_source_update_dispositions as disposition
             on disposition.source_vote_id=vote.id and disposition.cause_id=$2
          where vote.id=$1`,
        [fixture.voteId, cause.causeId]
      );
      expect(persisted.rows).toEqual([
        {
          state: "open",
          package_sha256: canonicalSha256(fixture.decisionPackage),
          effect: "excluded"
        }
      ]);
      const ordered = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where event_type in ('consent_recorded','vote_source_excluded')
          order by sequence desc limit 2`
      );
      expect(ordered.rows.toReversed().map(({ event_type }) => event_type)).toEqual([
        "consent_recorded",
        "vote_source_excluded"
      ]);
    });
  });
});

describe("live vote-recusal MCP lifecycle surface", () => {
  it("MR-VOTE-PRIVACY-004 requires another eligible secretary to prepare a recused secretary's lift", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteRecusalFixture(pool);
      const liftingActor = await seedAdditionalAuthorizedActor(pool, fixture.secretary, {
        idBase: 2_100_000,
        seatRole: "management",
        isSecretary: true,
        scopes: ["secretariat:admin", "governance:read"],
        uniqueHashes: true
      });
      const caller = await administrativeService(
        pool,
        await freshAdministrativeTestCredential(pool, fixture.secretary, 2_101_000)
      );
      const liftingSecretary = await administrativeService(
        pool,
        await freshAdministrativeTestCredential(pool, liftingActor, 2_102_000)
      );
      const input = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: fixture.secretary.boardId,
        member_id: fixture.secretary.memberId,
        object_type: "vote",
        object_id: fixture.voteId,
        reason: "Manual lift requires a currently entitled acting secretary.",
        operation: "add",
        idempotency_key: "recusal-confirmation-privacy-add"
      };
      const read = () =>
        caller.reads.executeRead(caller.principal, "get_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId
        });
      expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });
      const added = await confirmSurfaceVoteAction(
        caller.service,
        caller.principal,
        "manage_recusal",
        input
      );
      expect(added.result.data).toMatchObject({ state: "excluded", exclusion_version: 1 });
      expect((await read()).data).toMatchObject({ vote: null });
      const lift = {
        ...input,
        operation: "lift",
        idempotency_key: "recusal-confirmation-privacy-lift"
      };
      const evidence = async () =>
        (
          await pool.query(
            `select vote.state,vote.row_version::text,
              (select count(*)::int from vote_exclusions) as exclusions,
              (select count(*)::int from ballot_dispositions) as ballot_dispositions,
              (select count(*)::int from proxy_revocations) as proxy_revocations,
              (select count(*)::int from action_stages) as stages,
              (select count(*)::int from consent_records) as consents,
              (select count(*)::int from audit_events) as audit_events,
              (select count(*)::int from notices) as notices
             from votes vote where vote.id=$1`,
            [fixture.voteId]
          )
        ).rows;
      const before = await evidence();
      const hidden = await caller.service
        .prepareHumanAction(caller.principal, "manage_recusal", lift)
        .then(
          (prepared) => prepared,
          (error: unknown) => {
            expect(error).toMatchObject({ code: "vote_recusal_unavailable" });
            return null;
          }
        );
      expect(await evidence()).toEqual(before);

      const lifted = await confirmSurfaceVoteAction(
        liftingSecretary.service,
        liftingSecretary.principal,
        "manage_recusal",
        lift
      );
      expect(lifted.prepared.confirmation_lines.join("\n")).toContain(fixture.resolutionText);
      expect(lifted.prepared.confirmation_lines.join("\n")).toContain(
        canonicalJson(fixture.decisionPackage)
      );
      expect(lifted.result.data).toMatchObject({ state: "lifted", exclusion_version: 2 });
      expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });
      expect(
        (
          await pool.query(
            `select (select state from action_stages where id=$1) as old_stage_state,
              (select effect from ballot_dispositions where prior_ballot_id=$2) as ballot_effect,
              (select effect from proxy_revocations where grant_id=$3) as proxy_effect,
              (select array_agg(state order by version) from vote_exclusions
                where vote_id=$4 and member_id=$5) as exclusion_history`,
            [
              fixture.recusalStageId,
              fixture.ballotId,
              fixture.proxyGrantId,
              fixture.voteId,
              fixture.secretary.memberId
            ]
          )
        ).rows
      ).toEqual([
        {
          old_stage_state: "replaced",
          ballot_effect: "invalidated_by_recusal",
          proxy_effect: "revoked",
          exclusion_history: ["excluded", "lifted"]
        }
      ]);
      const disclosed = hidden?.confirmation_lines.join("\n") ?? "";
      expect({
        hiddenPreparationReturned: hidden !== null,
        resolutionReturned: disclosed.includes(fixture.resolutionText),
        canonicalPackageReturned: disclosed.includes(canonicalJson(fixture.decisionPackage))
      }).toEqual({
        hiddenPreparationReturned: false,
        resolutionReturned: false,
        canonicalPackageReturned: false
      });
    });
  });

  it("confirms the exact member conflict and atomically invalidates every affected projection", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteRecusalFixture(pool);
      let nextId = 980_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["secretariat:admin", "governance:read"]
      );
      const memberPrincipal = surfacePrincipal(
        fixture.voter,
        ["member"],
        ["secretariat:admin", "governance:read"]
      );
      const recusalInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: fixture.secretary.boardId,
        member_id: fixture.secretary.memberId,
        object_type: "vote",
        object_id: fixture.voteId,
        operation: "add",
        reason: fixture.reason,
        idempotency_key: "surface-live-vote-recusal-0001"
      } as const;

      await expect(
        service.prepareHumanAction(memberPrincipal, "manage_recusal", recusalInput)
      ).rejects.toMatchObject({ code: "vote_recusal_unavailable" });

      const recused = await confirmSurfaceVoteAction(
        service,
        secretary,
        "manage_recusal",
        recusalInput
      );
      const confirmation = recused.prepared.confirmation_lines.join("\n");
      expect(confirmation).toContain(canonicalJson(fixture.decisionPackage));
      expect(confirmation).toContain("Affected active stages: 1");
      expect(confirmation).toContain("Affected active proxies: 1");
      expect(confirmation).toContain("Affected effective ballots: 1");
      expect(confirmation).toContain("Pending feed items removed: 1");
      expect(recused.result).toMatchObject({
        tool: "manage_recusal",
        status: "accepted",
        data: {
          vote_id: fixture.voteId,
          member_id: fixture.secretary.memberId,
          exclusion_version: 1,
          state: "excluded",
          operation: "add",
          eligible_weight: "1",
          replayed: false
        }
      });
      const persisted = await pool.query<{
        ballot_effect: string;
        exclusion_state: string;
        feed_state: string;
        proxy_effect: string;
        stage_state: string;
      }>(
        `select exclusion.state as exclusion_state,stage.state as stage_state,
                revocation.effect as proxy_effect,disposition.effect as ballot_effect,
                feed.state as feed_state
           from vote_exclusions as exclusion
           join action_stages as stage on stage.id=$2
           join proxy_revocations as revocation on revocation.grant_id=$3
           join ballot_dispositions as disposition on disposition.prior_ballot_id=$4
           join pending_action_feed as feed on feed.id=$5
          where exclusion.vote_id=$1 and exclusion.member_id=$6`,
        [
          fixture.voteId,
          fixture.recusalStageId,
          fixture.proxyGrantId,
          fixture.ballotId,
          testId(221),
          fixture.secretary.memberId
        ]
      );
      expect(persisted.rows).toEqual([
        {
          exclusion_state: "excluded",
          stage_state: "replaced",
          proxy_effect: "revoked",
          ballot_effect: "invalidated_by_recusal",
          feed_state: "superseded"
        }
      ]);
      const ordered = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where event_type in (
            'consent_recorded','stage_replaced','proxy_revoked','ballot_superseded',
            'recusal_changed','notice_delivered'
          ) order by sequence desc limit 6`
      );
      expect(ordered.rows.toReversed().map(({ event_type }) => event_type)).toEqual([
        "consent_recorded",
        "stage_replaced",
        "proxy_revoked",
        "ballot_superseded",
        "recusal_changed",
        "notice_delivered"
      ]);
    });
  });
});

describe("vote cancellation MCP lifecycle surface", () => {
  it("denies a nonsecretary and cancels while retaining every prior act as evidence", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      let nextId = 990_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++)
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["secretariat:admin", "governance:read"]
      );
      const memberPrincipal = surfacePrincipal(
        fixture.voter,
        ["member"],
        ["secretariat:admin", "governance:read"]
      );
      const cancellationInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        reason: "The board secretary withdraws this vote before any outcome is declared.",
        idempotency_key: "surface-vote-cancellation-0001"
      } as const;

      await expect(
        service.prepareHumanAction(memberPrincipal, "cancel_vote", cancellationInput)
      ).rejects.toMatchObject({ code: "vote_cancellation_unavailable" });

      const cancelled = await confirmSurfaceVoteAction(
        service,
        secretary,
        "cancel_vote",
        cancellationInput
      );
      const confirmation = cancelled.prepared.confirmation_lines.join("\n");
      expect(confirmation).toContain(canonicalJson(fixture.decisionPackage));
      expect(confirmation).toContain("Recipients notified: 2");
      expect(confirmation).toContain(
        "Existing stages, proxies, and ballots remain immutable evidence"
      );
      expect(cancelled.result).toMatchObject({
        tool: "cancel_vote",
        status: "accepted",
        reference: fixture.voteId,
        data: {
          vote_id: fixture.voteId,
          state: "cancelled",
          package_sha256: fixture.oldPackageSha256,
          retained_acts_non_outcome_bearing: true,
          notice_count: 2
        }
      });
      const persisted = await pool.query<{
        active_stage: string;
        ballot_dispositions: string;
        ballots: string;
        cancellation_notices: string;
        cancelled: boolean;
        outcomes: string;
        proxy_grants: string;
        proxy_revocations: string;
        state: string;
      }>(
        `select vote.state,(vote.cancelled_at is not null) as cancelled,
                (select count(*)::text from ballots where vote_id=vote.id) as ballots,
                (select count(*)::text from ballot_dispositions
                  where prior_ballot_id=$2) as ballot_dispositions,
                (select count(*)::text from proxy_grants where vote_id=vote.id) as proxy_grants,
                (select count(*)::text from proxy_revocations
                  where grant_id=$3) as proxy_revocations,
                (select count(*)::text from vote_outcomes where vote_id=vote.id) as outcomes,
                (select count(*)::text from notices
                  where object_id=vote.id and notice_type='vote_cancelled')
                  as cancellation_notices,
                (select state from action_stages where id=$4) as active_stage
           from votes as vote where vote.id=$1`,
        [fixture.voteId, fixture.ballotId, fixture.proxyGrantId, fixture.activeStageId]
      );
      expect(persisted.rows).toEqual([
        {
          state: "cancelled",
          cancelled: true,
          ballots: "1",
          ballot_dispositions: "0",
          proxy_grants: "1",
          proxy_revocations: "0",
          outcomes: "0",
          cancellation_notices: "2",
          active_stage: "active"
        }
      ]);
      const ordered = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where event_type in ('consent_recorded','vote_cancelled','notice_delivered')
          order by sequence desc limit 4`
      );
      expect(ordered.rows.toReversed().map(({ event_type }) => event_type)).toEqual([
        "consent_recorded",
        "vote_cancelled",
        "notice_delivered",
        "notice_delivered"
      ]);
    });
  });
});

describe("MR-VOTE-PRIVACY-001 exact recusal confirmation material", () => {
  it("rechecks close preparation when a supported recusal commits after the initial visibility read", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCloseReadyFixture(pool, "voter");
      const caller = await administrativeService(
        pool,
        await freshAdministrativeTestCredential(pool, fixture.secretary, 994500)
      );
      let recusalCommitted = false;
      const interleavedPool = new Proxy(pool, {
        get(target, property) {
          if (property === "connect") {
            return async () => {
              const client = await target.connect();
              return new Proxy(client, {
                get(connection, member) {
                  if (member === "query") {
                    return async (sql: string, values?: unknown[]) => {
                      const result = await connection.query(sql, values);
                      if (
                        !recusalCommitted &&
                        sql.includes("select boardagent_member_vote_recused($1,")
                      ) {
                        expect(result.rows).toEqual([{ recused: false }]);
                        expect((await connection.query("show transaction_isolation")).rows).toEqual(
                          [{ transaction_isolation: "serializable" }]
                        );
                        await confirmSurfaceVoteAction(
                          caller.service,
                          caller.principal,
                          "manage_recusal",
                          {
                            schema_version: TOOL_INPUT_SCHEMA_VERSION,
                            board_id: fixture.secretary.boardId,
                            member_id: fixture.secretary.memberId,
                            object_type: "vote",
                            object_id: fixture.voteId,
                            operation: "add",
                            reason: "Commit supported recusal between visibility and vote locking.",
                            idempotency_key: "confirmation-privacy-interleaved-recusal"
                          }
                        );
                        recusalCommitted = true;
                      }
                      return result;
                    };
                  }
                  const value: unknown = Reflect.get(connection, member);
                  return typeof value === "function" ? value.bind(connection) : value;
                }
              });
            };
          }
          const value: unknown = Reflect.get(target, property);
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
      const service = new PgBoardAgentSurfaceService(interleavedPool, {
        reads: caller.reads,
        transaction: { assumeRole: "boardagent_server" },
        voteCertificateSigner: {
          signVoteCertificate: async () => {
            throw new Error("confirmation preparation must not sign a certificate");
          }
        }
      });
      await expect(
        service.prepareHumanAction(caller.principal, "close_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          expected_package_sha256: fixture.packageSha256,
          idempotency_key: "confirmation-privacy-interleaved-close"
        })
      ).rejects.toMatchObject({ code: "vote_close_unavailable" });
      expect(recusalCommitted).toBe(true);
      expect(
        (
          await caller.reads.executeRead(caller.principal, "get_vote", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            vote_id: fixture.voteId
          })
        ).data
      ).toMatchObject({ vote: null });
    });
  });

  it.each(["cancel_vote", "close_vote"] as const)(
    "%s does not disclose the hidden package to an exact-recused secretary",
    async (tool) => {
      await withDatabase(async (pool) => {
        const fixture = await seedCloseReadyFixture(pool, "voter");
        const caller = await administrativeService(
          pool,
          await freshAdministrativeTestCredential(pool, fixture.secretary, 993500)
        );
        const liftingSecretary = await seedEligibleRecusalSecretary(pool, fixture, 2_203_000);
        let nextId = 993600;
        const signVoteCertificate = vi.fn(async () => {
          throw new Error("confirmation preparation must not sign a certificate");
        });
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: caller.reads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(nextId++),
          voteCertificateSigner: { signVoteCertificate }
        });
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          ...(tool === "close_vote"
            ? { expected_package_sha256: fixture.packageSha256 }
            : { reason: "Withdraw this exact synthetic vote before an outcome." }),
          idempotency_key: `confirmation-privacy-${tool}`
        };
        const prepare = () => service.prepareHumanAction(caller.principal, tool, input);
        const read = () =>
          caller.reads.executeRead(caller.principal, "get_vote", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            vote_id: fixture.voteId
          });
        const recuse = (actingSecretary: SurfacePrincipal, operation: "add" | "lift") =>
          confirmSurfaceVoteAction(service, actingSecretary, "manage_recusal", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.secretary.boardId,
            member_id: fixture.secretary.memberId,
            object_type: "vote",
            object_id: fixture.voteId,
            operation,
            reason: "Separate personal record visibility from administrative effects.",
            idempotency_key: `confirmation-privacy-${tool}-${operation}`
          });
        const original = await prepare();
        expect(original.confirmation_lines.join("\n")).toContain(fixture.resolutionText);
        expect(original.confirmation_lines.join("\n")).toContain(
          canonicalJson(fixture.decisionPackage)
        );
        expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });

        await recuse(caller.principal, "add");
        expect((await read()).data).toMatchObject({ vote: null });
        const evidence = async () =>
          (
            await pool.query(
              `select vote.state,vote.row_version::text,
                (select count(*)::int from action_stages) as stages,
                (select count(*)::int from consent_records) as consents,
                (select count(*)::int from notices) as notices,
                (select count(*)::int from audit_events) as audit_events,
                (select count(*)::int from vote_outcomes) as outcomes,
                (select count(*)::int from vote_certificates) as certificates
               from votes vote where vote.id=$1`,
              [fixture.voteId]
            )
          ).rows;
        const before = await evidence();
        const hidden = await prepare().then(
          (prepared) => prepared,
          () => null
        );
        expect(await evidence()).toEqual(before);
        expect(signVoteCertificate).not.toHaveBeenCalled();

        await recuse(liftingSecretary.principal, "lift");
        expect((await read()).data).toMatchObject({ vote: { vote_id: fixture.voteId } });
        const restored = await prepare();
        expect(restored.confirmation_lines.join("\n")).toContain(fixture.resolutionText);
        expect(restored.confirmation_lines.join("\n")).toContain(
          canonicalJson(fixture.decisionPackage)
        );
        const disclosed = hidden
          ? [...hidden.confirmation_lines, canonicalJson(hidden.canonical_payload)].join("\n")
          : "";
        expect({
          resolutionDisclosed: disclosed.includes(fixture.resolutionText),
          packageDisclosed: disclosed.includes(canonicalJson(fixture.decisionPackage))
        }).toEqual({ resolutionDisclosed: false, packageDisclosed: false });
      });
    }
  );
});

describe("vote close and signed certificate MCP lifecycle surface", () => {
  it("denies an observer and closes only after the configured Ed25519 signer is verified", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCloseReadyFixture(pool);
      const observer = await seedAdditionalAuthorizedActor(pool, fixture.secretary, {
        idBase: 940_000,
        seatRole: "observer",
        scopes: ["governance:read", "secretariat:admin"]
      });
      let nextId = 950_000;
      let signerCalls = 0;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++),
        voteCertificateSigner: {
          signVoteCertificate: async (request) => {
            signerCalls += 1;
            expect(request.signingKeyId).toBe(fixture.signingKeyId);
            expect(request.signingKeyLocator).toBe("local-test-key://evidence-close-1");
            const payload = VoteCertificatePayloadSchema.parse(
              JSON.parse(request.canonicalPayload) as unknown
            );
            expect(canonicalSha256(payload)).toBe(request.payloadSha256);
            const issued = issueVoteCertificate(payload, fixture.evidenceKey.privateKey);
            return { signatureBase64Url: issued.signatureBase64Url };
          }
        }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["secretariat:admin", "governance:read", "vote:act"]
      );
      const observerPrincipal = surfacePrincipal(
        observer,
        ["observer"],
        ["secretariat:admin", "governance:read"]
      );
      const closeInput = {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: fixture.voteId,
        expected_package_sha256: fixture.packageSha256,
        idempotency_key: "surface-confirmed-vote-close-0001"
      } as const;

      await expect(
        service.prepareHumanAction(observerPrincipal, "close_vote", closeInput)
      ).rejects.toMatchObject({ code: "vote_close_unavailable" });

      const closed = await confirmSurfaceVoteAction(service, secretary, "close_vote", closeInput);
      expect(closed.prepared.confirmation_lines.join("\n")).toContain(
        `Recomputed tally SHA-256: ${fixture.expectedTallySha256}`
      );
      expect(closed.prepared.confirmation_lines.join("\n")).toContain(
        canonicalJson(fixture.decisionPackage)
      );
      expect(closed.result).toMatchObject({
        tool: "close_vote",
        status: "accepted",
        reference: expect.any(String),
        resource_uri: expect.stringContaining(
          `board://${fixture.secretary.boardId}/votes/${fixture.voteId}/certificates/`
        ),
        data: {
          schema_version: "boardagent.vote-close-result.v1",
          vote_id: fixture.voteId,
          outcome: "approved",
          state: "closed",
          signing_key_id: fixture.signingKeyId,
          tally: {
            eligibleWeight: "2",
            participatingWeight: "1",
            yesWeight: "1",
            noWeight: "0",
            abstainWeight: "0",
            quorumMet: true,
            approvalMet: true,
            outcome: "approved"
          }
        }
      });
      expect(signerCalls).toBe(1);
      const publicId = (closed.result.data as Readonly<Record<string, JsonValue>>)[
        "certificate_public_id"
      ];
      if (typeof publicId !== "string") throw new Error("certificate public ID is unavailable");
      await expect(
        withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            verifyPersistedVoteCertificateInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              certificatePublicId: publicId
            }),
          { assumeRole: "boardagent_server" }
        )
      ).resolves.toEqual({
        valid: true,
        voteId: fixture.voteId,
        certificateId: closed.result.reference
      });
      const persisted = await pool.query<{
        certificates: string;
        material: string;
        outcomes: string;
        public_id_bytes: number;
        state: string;
      }>(
        `select vote.state,
                (select count(*)::text from vote_outcomes where vote_id=vote.id) as outcomes,
                (select count(*)::text from vote_certificates where vote_id=vote.id) as certificates,
                (select count(*)::text from vote_close_stage_material where vote_id=vote.id) as material,
                (select octet_length(certificate_public_id) from vote_close_stage_material
                  where vote_id=vote.id) as public_id_bytes
           from votes as vote where vote.id=$1`,
        [fixture.voteId]
      );
      expect(persisted.rows).toEqual([
        { state: "closed", outcomes: "1", certificates: "1", material: "1", public_id_bytes: 32 }
      ]);
      const ordered = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where event_type in ('consent_recorded','vote_closing','certificate_issued','vote_closed')
          order by sequence desc limit 4`
      );
      expect(ordered.rows.toReversed().map(({ event_type }) => event_type)).toEqual([
        "consent_recorded",
        "vote_closing",
        "certificate_issued",
        "vote_closed"
      ]);
    });
  });

  it("leaves a confirmed close recoverably closing when the external signer fails", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedCloseReadyFixture(pool);
      let nextId = 960_000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(nextId++),
        voteCertificateSigner: {
          signVoteCertificate: () => Promise.reject(new Error("synthetic signer outage"))
        }
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["secretariat:admin", "governance:read", "vote:act"]
      );
      await expect(
        confirmSurfaceVoteAction(service, secretary, "close_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          expected_package_sha256: fixture.packageSha256,
          idempotency_key: "surface-close-signer-outage-0001"
        })
      ).rejects.toThrow("synthetic signer outage");
      const persisted = await pool.query<{
        certificates: string;
        confirmed_stages: string;
        outcomes: string;
        state: string;
      }>(
        `select vote.state,
                (select count(*)::text from vote_outcomes where vote_id=vote.id) as outcomes,
                (select count(*)::text from vote_certificates where vote_id=vote.id) as certificates,
                (select count(*)::text from action_stages
                  where action_code='close_vote' and target_id=vote.id and state='confirmed')
                  as confirmed_stages
           from votes as vote where vote.id=$1`,
        [fixture.voteId]
      );
      expect(persisted.rows).toEqual([
        { state: "closing", outcomes: "1", certificates: "0", confirmed_stages: "2" }
      ]);
      const terminalEvents = await pool.query<{ event_type: string }>(
        `select event_type from audit_events
          where object_id=$1 and event_type in ('vote_closing','certificate_issued','vote_closed')
          order by sequence`,
        [fixture.voteId]
      );
      expect(terminalEvents.rows.map(({ event_type }) => event_type)).toEqual(["vote_closing"]);

      const recoveryJobId = testId(960_090);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) =>
          enqueueRequestJobInTransaction(client, {
            jobId: recoveryJobId,
            idempotencyKey: "certificate-recovery-worker-0001",
            availableAt: "2020-01-01T00:00:00Z",
            envelope: {
              schemaVersion: "boardagent.job.certificate_recovery.v1",
              organizationId: fixture.secretary.organizationId,
              boardId: fixture.secretary.boardId,
              jobType: "certificate_recovery",
              subjectType: "vote",
              subjectId: fixture.voteId,
              parameters: { voteId: fixture.voteId }
            }
          }),
        { assumeRole: "boardagent_server" }
      );
      const worker = await voteWorker(
        pool,
        fixture.secretary,
        fixture.evidenceKey.privateKey,
        fixture.signingKeyId,
        "local-test-key://evidence-close-1",
        980_000
      );
      expect(await worker.runOnce()).toMatchObject({
        status: "succeeded",
        jobId: recoveryJobId,
        jobType: "certificate_recovery"
      });
      const recovered = await pool.query<{
        actor_member_id: string | null;
        consent_record_id: string | null;
        expected_consent_record_id: string;
        origin: string;
        state: string;
      }>(
        `select vote.state,event.actor_member_id,event.consent_record_id,
                outcome.close_consent_record_id as expected_consent_record_id,
                convert_from(event.canonical_payload,'UTF8')::jsonb->>'origin' as origin
           from votes as vote
           join vote_outcomes as outcome on outcome.vote_id=vote.id
           join audit_events as event on event.object_id=vote.id
          where vote.id=$1 and event.event_type='vote_closed'`,
        [fixture.voteId]
      );
      expect(recovered.rows).toHaveLength(1);
      expect(recovered.rows[0]).toMatchObject({
        state: "closed",
        actor_member_id: fixture.secretary.memberId,
        origin: "worker"
      });
      expect(recovered.rows[0]?.consent_record_id).toBe(
        recovered.rows[0]?.expected_consent_record_id
      );
    });
  });
});

describe("board recusal across active votes", () => {
  it.each(["manual_before_board", "manual_during_board"] as const)(
    "%s retains independent causes and never restores old acts",
    async (order) => {
      await withDatabase(async (pool) => {
        const fixture = await seedOpenVoteActFixture(pool);
        let n = 993000;
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableSurfaceReads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(n++)
        });
        const secretary = surfacePrincipal(
          fixture.secretary,
          ["member", "secretariat"],
          ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"]
        );
        const member = surfacePrincipal(
          fixture.voter,
          ["member"],
          ["governance:read", "proxy:manage", "vote:act"]
        );
        const ballot = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          choice: "yes",
          statement: null,
          idempotency_key: "board-cascade-initial-ballot-0001"
        } as const;
        await confirmSurfaceVoteAction(service, member, "stage_ballot", ballot);
        const original = (
          await pool.query(
            "select canonical_payload,package_sha256 from decision_packages where id=$1",
            [fixture.decisionPackageId]
          )
        ).rows[0];
        const recusal = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.secretary.boardId,
          member_id: fixture.voter.memberId,
          object_type: "vote",
          object_id: fixture.voteId,
          operation: "add",
          reason: "Separate vote-specific conflict",
          idempotency_key: "board-cascade-manual-add-0001"
        } as const;
        const board = {
          ...recusal,
          object_type: "board",
          object_id: fixture.secretary.boardId,
          reason: "Board-wide conflict",
          idempotency_key: "board-cascade-board-add-0001"
        } as const;
        if (order === "manual_before_board")
          await confirmSurfaceVoteAction(service, secretary, "manage_recusal", recusal);
        const excluded = await confirmSurfaceVoteAction(
          service,
          secretary,
          "manage_recusal",
          board
        );
        expect(excluded.prepared.canonical_payload).toMatchObject({
          affectedVotes: [{ voteId: fixture.voteId, packageSha256: fixture.packageSha256 }]
        });
        if (order === "manual_during_board")
          await confirmSurfaceVoteAction(service, secretary, "manage_recusal", recusal);
        const latest = async () =>
          (
            await pool.query(
              "select state from vote_exclusions where vote_id=$1 and member_id=$2 order by version desc limit 1",
              [fixture.voteId, fixture.voter.memberId]
            )
          ).rows[0].state;
        expect(await latest()).toBe("excluded");
        const manualLift = {
          ...recusal,
          operation: "lift",
          idempotency_key: "board-cascade-manual-lift-0001"
        };
        const boardLift = {
          ...board,
          operation: "lift",
          idempotency_key: "board-cascade-board-lift-0001"
        };
        if (order === "manual_before_board")
          await confirmSurfaceVoteAction(service, secretary, "manage_recusal", manualLift);
        else await confirmSurfaceVoteAction(service, secretary, "manage_recusal", boardLift);
        expect(await latest()).toBe("excluded");
        await expect(
          service.prepareHumanAction(member, "stage_ballot", {
            ...ballot,
            idempotency_key: "board-cascade-denied-ballot-0001"
          })
        ).rejects.toThrow();
        if (order === "manual_before_board")
          await confirmSurfaceVoteAction(service, secretary, "manage_recusal", boardLift);
        else await confirmSurfaceVoteAction(service, secretary, "manage_recusal", manualLift);
        expect(await latest()).toBe("lifted");
        const active = await pool.query(
          `select b.id from ballots b left join ballot_dispositions d on d.prior_ballot_id=b.id where b.vote_id=$1 and b.principal_member_id=$2 and d.id is null`,
          [fixture.voteId, fixture.voter.memberId]
        );
        expect(active.rows).toEqual([]);
        await confirmSurfaceVoteAction(service, member, "stage_ballot", {
          ...ballot,
          idempotency_key: "board-cascade-new-ballot-after-lift-0001"
        });
        expect(
          (
            await pool.query(
              "select canonical_payload,package_sha256 from decision_packages where id=$1",
              [fixture.decisionPackageId]
            )
          ).rows[0]
        ).toEqual(original);
        const boardEvidence = await pool.query(
          `select c.target_type,c.target_id from vote_exclusions e join consent_records c on c.id=e.consent_record_id where e.vote_id=$1 and c.target_type='board'`,
          [fixture.voteId]
        );
        expect(boardEvidence.rows).toHaveLength(2);
        expect(boardEvidence.rows.every((row) => row.target_id === fixture.secretary.boardId)).toBe(
          true
        );
      });
    }
  );
});

describe("board recusal serialization and history", () => {
  it.each(["cast_before_confirmation", "competing_cast"] as const)(
    "%s leaves no effective ballot for an excluded director",
    async (order) => {
      await withDatabase(async (pool) => {
        const fixture = await seedOpenVoteActFixture(pool);
        let n = 994000;
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableSurfaceReads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(n++)
        });
        const secretary = surfacePrincipal(
          fixture.secretary,
          ["member", "secretariat"],
          ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"]
        );
        const member = surfacePrincipal(
          fixture.voter,
          ["member"],
          ["governance:read", "proxy:manage", "vote:act"]
        );
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.secretary.boardId,
          object_type: "board",
          object_id: fixture.secretary.boardId,
          member_id: fixture.voter.memberId,
          operation: "add",
          reason: "Conflict effective during an open vote",
          idempotency_key: "race-board-recusal-confirm-0001"
        } as const;
        const ballot = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          choice: "yes",
          statement: null,
          idempotency_key: "race-board-recusal-ballot-0001"
        } as const;
        if (order === "cast_before_confirmation") {
          await confirmSurfaceVoteAction(service, secretary, "manage_recusal", input, async () => {
            await confirmSurfaceVoteAction(service, member, "stage_ballot", ballot);
          });
        } else {
          const [recusal] = await Promise.allSettled([
            confirmSurfaceVoteAction(service, secretary, "manage_recusal", input),
            confirmSurfaceVoteAction(service, member, "stage_ballot", ballot)
          ]);
          expect(recusal.status).toBe("fulfilled");
        }
        expect(
          (
            await pool.query(
              "select state from board_exclusions where member_id=$1 order by version desc limit 1",
              [fixture.voter.memberId]
            )
          ).rows[0]
        ).toEqual({ state: "excluded" });
        expect(
          (
            await pool.query(
              `select b.id from ballots b where b.vote_id=$1 and b.principal_member_id=$2
        and not exists(select 1 from ballot_dispositions d where d.prior_ballot_id=b.id)`,
              [fixture.voteId, fixture.voter.memberId]
            )
          ).rows
        ).toEqual([]);
        const exclusion = (
          await pool.query(
            "select * from vote_exclusions where vote_id=$1 order by version desc limit 1",
            [fixture.voteId]
          )
        ).rows[0];
        await expect(
          withRequestTransaction(
            pool,
            fixture.secretary.context,
            (c) =>
              c.query(
                `insert into vote_exclusions(
        id,organization_id,board_id,vote_id,member_id,version,state,reason,actor_member_id,consent_record_id,cause_requested_state)
        values($1,$2,$3,$4,$5,2,'lifted','Runtime caller attempts to erase a board cause',$6,$7,'lifted')`,
                [
                  testId(n++),
                  fixture.secretary.organizationId,
                  fixture.secretary.boardId,
                  fixture.voteId,
                  fixture.voter.memberId,
                  fixture.secretary.memberId,
                  exclusion.consent_record_id
                ]
              ),
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toThrow("vote recusal lacks confirmed cause authority");
        expect(
          (
            await pool.query("select count(*)::text count from vote_exclusions where vote_id=$1", [
              fixture.voteId
            ])
          ).rows[0]
        ).toEqual({ count: "1" });
      });
    }
  );

  it.each(["closed", "closing"] as const)(
    "a %s vote makes the old manifest stale and its frozen outcome survives a fresh board recusal",
    async (state) => {
      await withDatabase(async (pool) => {
        const fixture = await seedCloseReadyFixture(pool, "voter");
        let n = 995000;
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableSurfaceReads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(n++),
          voteCertificateSigner: {
            signVoteCertificate: async (request) => {
              if (state === "closing") throw new Error("synthetic certificate signer unavailable");
              const payload = VoteCertificatePayloadSchema.parse(
                JSON.parse(request.canonicalPayload)
              );
              return {
                signatureBase64Url: issueVoteCertificate(payload, fixture.evidenceKey.privateKey)
                  .signatureBase64Url
              };
            }
          }
        });
        const secretary = surfacePrincipal(
          fixture.secretary,
          ["member", "secretariat"],
          ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"]
        );
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.secretary.boardId,
          object_type: "board",
          object_id: fixture.secretary.boardId,
          member_id: fixture.voter.memberId,
          operation: "add",
          reason: "Conflict after a close was confirmed",
          idempotency_key: "close-board-recusal-stale-0001"
        } as const;
        await expect(
          confirmSurfaceVoteAction(service, secretary, "manage_recusal", input, async () => {
            const close = confirmSurfaceVoteAction(service, secretary, "close_vote", {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              vote_id: fixture.voteId,
              expected_package_sha256: fixture.packageSha256,
              idempotency_key: "close-before-board-recusal-0001"
            });
            if (state === "closing")
              await expect(close).rejects.toThrow("synthetic certificate signer unavailable");
            else await close;
          })
        ).rejects.toThrow("canonical_stale");
        expect((await pool.query("select id from board_exclusions")).rows).toEqual([]);
        const frozen = await pool.query(
          "select row_to_json(o)::text bytes from vote_outcomes o where vote_id=$1",
          [fixture.voteId]
        );
        expect(frozen.rows).toHaveLength(1);
        const result = await confirmSurfaceVoteAction(service, secretary, "manage_recusal", {
          ...input,
          idempotency_key: "close-board-recusal-fresh-0001"
        });
        expect(result.prepared.canonical_payload).toMatchObject({ affectedVotes: [] });
        expect(
          (
            await pool.query(
              "select row_to_json(o)::text bytes from vote_outcomes o where vote_id=$1",
              [fixture.voteId]
            )
          ).rows
        ).toEqual(frozen.rows);
        expect(
          (await pool.query("select state from votes where id=$1", [fixture.voteId])).rows[0]
        ).toEqual({ state });
        expect((await pool.query("select id from ballot_dispositions")).rows).toEqual([]);
        expect((await pool.query("select id from vote_exclusions")).rows).toEqual([]);
      });
    }
  );

  it("self-recusal atomically disposes an open ballot and held proxy before removing the secretary authority", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      let n = 996000;
      const service = new PgBoardAgentSurfaceService(pool, {
        reads: unavailableSurfaceReads,
        transaction: { assumeRole: "boardagent_server" },
        newId: () => testId(n++)
      });
      const secretary = surfacePrincipal(
        fixture.secretary,
        ["member", "secretariat"],
        ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"]
      );
      const priorStageId = testId(996900);
      await seedActiveOldVoteStage(
        pool,
        fixture,
        priorStageId,
        fixture.oldPackageSha256,
        "secretary"
      );
      const recused = await confirmSurfaceVoteAction(service, secretary, "manage_recusal", {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: fixture.secretary.boardId,
        object_type: "board",
        object_id: fixture.secretary.boardId,
        member_id: fixture.secretary.memberId,
        operation: "add",
        reason: "Secretary declares their own board conflict",
        idempotency_key: "self-board-vote-recusal-0001"
      });
      // The fixture has an original board stage plus the explicitly added vote stage.
      expect(recused.result.data).toMatchObject({ invalidated_stages: 2, tombstones: 1 });
      expect(
        (await pool.query("select state from action_stages where id=$1", [priorStageId])).rows
      ).toEqual([{ state: "replaced" }]);
      expect(
        (
          await pool.query("select effect from ballot_dispositions where prior_ballot_id=$1", [
            fixture.ballotId
          ])
        ).rows
      ).toEqual([{ effect: "invalidated_by_recusal" }]);
      expect(
        (
          await pool.query("select effect from proxy_revocations where grant_id=$1", [
            fixture.proxyGrantId
          ])
        ).rows
      ).toEqual([{ effect: "revoked" }]);
      expect(
        (
          await pool.query("select state from board_exclusions where member_id=$1", [
            fixture.secretary.memberId
          ])
        ).rows
      ).toEqual([{ state: "excluded" }]);
    });
  });
});

describe("board recusal and new electorate", () => {
  it.each(["create_before_confirmation", "create_while_recused"] as const)(
    "%s preserves exact confirmation and frozen seats",
    async (order) => {
      await withDatabase(async (pool) => {
        const fixture = await seedVoteOpenFixture(pool, { precreateVote: false });
        let n = 997000;
        const service = new PgBoardAgentSurfaceService(pool, {
          reads: unavailableSurfaceReads,
          transaction: { assumeRole: "boardagent_server" },
          newId: () => testId(n++)
        });
        const secretary = surfacePrincipal(
          fixture.secretary,
          ["member", "secretariat"],
          ["secretariat:admin", "governance:read", "proxy:manage", "vote:act"]
        );
        const member = surfacePrincipal(
          fixture.voter,
          ["member"],
          ["governance:read", "proxy:manage", "vote:act"]
        );
        const input = {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: fixture.secretary.boardId,
          object_type: "board",
          object_id: fixture.secretary.boardId,
          member_id: fixture.voter.memberId,
          operation: "add",
          reason: "Conflict before a new vote",
          idempotency_key: "new-vote-board-recusal-0001"
        } as const;
        if (order === "create_before_confirmation") {
          await expect(
            confirmSurfaceVoteAction(service, secretary, "manage_recusal", input, async () => {
              await confirmSurfaceVoteAction(
                service,
                secretary,
                "create_vote",
                voteCreationSurfaceInput(fixture)
              );
            })
          ).rejects.toThrow("canonical_stale");
          expect((await pool.query("select id from board_exclusions")).rows).toEqual([]);
          await confirmSurfaceVoteAction(service, secretary, "manage_recusal", {
            ...input,
            idempotency_key: "new-vote-board-recusal-fresh-0001"
          });
          expect(
            (
              await pool.query("select member_id from vote_exclusions where vote_id=$1", [
                fixture.voteId
              ])
            ).rows
          ).toEqual([{ member_id: fixture.voter.memberId }]);
        } else {
          await confirmSurfaceVoteAction(service, secretary, "manage_recusal", input);
          await confirmSurfaceVoteAction(
            service,
            secretary,
            "create_vote",
            voteCreationSurfaceInput(fixture)
          );
          const electorate = (
            await pool.query(
              "select row_to_json(e)::text bytes from vote_electorate e where vote_id=$1",
              [fixture.voteId]
            )
          ).rows;
          expect(electorate).toHaveLength(1);
          expect(JSON.parse(electorate[0].bytes).member_id).toBe(fixture.secretary.memberId);
          const lifted = await confirmSurfaceVoteAction(service, secretary, "manage_recusal", {
            ...input,
            operation: "lift",
            idempotency_key: "new-vote-board-lift-0001"
          });
          expect(lifted.prepared.canonical_payload).toMatchObject({ affectedVotes: [] });
          expect(
            (
              await pool.query(
                "select row_to_json(e)::text bytes from vote_electorate e where vote_id=$1",
                [fixture.voteId]
              )
            ).rows
          ).toEqual(electorate);
          await expect(
            service.prepareHumanAction(member, "stage_ballot", {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              vote_id: fixture.voteId,
              choice: "yes",
              statement: null,
              idempotency_key: "new-vote-no-frozen-seat-ballot-0001"
            })
          ).rejects.toThrow();
        }
      });
    }
  );
});

describe("MR-CERT-002 canonical certificate signature wire format", () => {
  it.each(["tool", "resource"] as const)(
    "%s emits the exact unwrapped Ed25519 signature accepted by the offline bundle contract",
    async (surface) => {
      await withDatabase(async (pool) => {
        const fixture = await seedClosingVoteFixture(pool);
        const issued = issueVoteCertificate(fixture.draft.payload, fixture.evidenceKey.privateKey);
        await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) =>
            finalizeVoteCloseInTransaction(client, {
              organizationId: fixture.secretary.organizationId,
              voteId: fixture.voteId,
              outcomeId: fixture.outcomeId,
              certificateId: fixture.certificateId,
              signatureBase64Url: issued.signatureBase64Url,
              certificateIssuedAuditEventId: testId(2432),
              voteClosedAuditEventId: testId(2433)
            }),
          { assumeRole: "boardagent_server" }
        );
        const before = (
          await pool.query(
            "select encode(signature,'hex') as signature,encode(canonical_payload,'hex') as payload from vote_certificates where id=$1",
            [fixture.certificateId]
          )
        ).rows;
        expect(Buffer.from(before[0].signature, "hex")).toHaveLength(64);
        const publicVerdict = () =>
          withIdentityTransaction(
            pool,
            { organizationId: fixture.secretary.organizationId, boardIds: [] },
            (client) =>
              verifyPublicPersistedVoteCertificateInTransaction(client, {
                certificatePublicId: fixture.certificatePublicId
              }),
            { isolation: "read committed", assumeRole: "boardagent_server" }
          );
        expect(await publicVerdict()).toEqual({ valid: true });
        const caller = await administrativeService(
          pool,
          await freshAdministrativeTestCredential(pool, fixture.secretary, 994100)
        );
        if (surface === "tool") {
          const response = await caller.reads.executeRead(
            caller.principal,
            "get_vote_certificate",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              vote_id: fixture.voteId,
              certificate_id: null
            }
          );
          const certificate = (response.data as Record<string, JsonValue>)["certificate"] as Record<
            string,
            JsonValue
          >;
          expect(certificate["signature_base64url"]).toBe(issued.signatureBase64Url);
          expect(
            OfflineCertificateBundleSchema.shape.signature_base64url.parse(
              certificate["signature_base64url"]
            )
          ).toHaveLength(86);
        } else {
          const resource = await caller.reads.readResource(
            caller.principal,
            new URL(
              `board://${fixture.secretary.boardId}/votes/${fixture.voteId}/certificates/${fixture.certificateId}`
            )
          );
          if (resource.text === undefined) throw new Error("certificate resource lacks text");
          const bundle = OfflineCertificateBundleSchema.parse(JSON.parse(resource.text));
          expect(bundle.signature_base64url).toBe(issued.signatureBase64Url);
          expect(
            verifyOfflineCertificateBundle(bundle, {
              schema_version: "boardagent.trusted-evidence-keys.v1",
              keys: [
                {
                  id: fixture.signingKeyId,
                  kid: "evidence-close-1",
                  algorithm: "EdDSA",
                  public_jwk: fixture.evidenceKey.publicKey.export({ format: "jwk" })
                }
              ]
            })
          ).toBe(true);
        }
        expect(
          (
            await pool.query(
              "select encode(signature,'hex') as signature,encode(canonical_payload,'hex') as payload from vote_certificates where id=$1",
              [fixture.certificateId]
            )
          ).rows
        ).toEqual(before);
        expect(await publicVerdict()).toEqual({ valid: true });
      });
    }
  );
});

describe("MR-MEC-003 exact vote recusal read authority", () => {
  it.each([false, true])(
    "resubmission with exact vote exclusion=%s projects only readable IDs while invalidating its real opened source",
    async (excluded) => {
      await withDatabase(async (pool) => {
        const fixture = await seedVoteOpenFixture(pool, { precreateVote: false });
        await pool.query(
          `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
           values ($1,$2,$3,'management','Synthetic management authority on a voting seat')`,
          [testId(995900), fixture.voter.organizationId, fixture.voter.memberId]
        );
        const actor = await freshAdministrativeTestCredential(pool, fixture.voter, 995910);
        await pool.query(
          "update access_token_records set scope_set=scope_set||array['documents:contribute'] where id=$1",
          [actor.accessTokenRecordId]
        );
        const manager = await administrativeService(pool, actor);
        const { secretary } = await readers(pool, fixture);
        const documentId = testId(995920),
          submissionId = testId(995921);
        const document = await manager.service.executeDirect(
          manager.principal,
          "create_document_version",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.voter.boardId,
            document_id: documentId,
            title: "Exact management source",
            media_type: "text/plain; charset=utf-8",
            schema_name: null,
            canonical_body: "Canonical management source for the exact vote.\n",
            expected_current_version_id: null,
            idempotency_key: "recused-resubmission-document-0001"
          }
        );
        const documentData = document.data as Record<string, JsonValue>;
        const documentSha256 = documentData["sha256"];
        if (!document.reference || typeof documentSha256 !== "string")
          throw new Error("contributed source lacks exact version/hash");
        const references = [
          {
            document_id: documentId,
            version_id: document.reference,
            sha256: documentSha256
          }
        ];
        const submitted = await manager.service.executeDirect(
          manager.principal,
          "submit_document_to_secretariat",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.voter.boardId,
            submission_id: submissionId,
            document_references: references,
            purpose: "Exact source must invalidate every linked vote after revision.",
            idempotency_key: "recused-resubmission-submit-0001"
          }
        );
        const versionId = (submitted.data as Record<string, JsonValue>)["version_id"];
        if (typeof versionId !== "string") throw new Error("submitted source lacks its version");
        const version = (
          await pool.query<{ sha256: string }>(
            "select encode(payload_sha256,'hex') as sha256 from management_submission_versions where id=$1",
            [versionId]
          )
        ).rows[0]!;
        await confirmSurfaceVoteAction(secretary.service, secretary.principal, "create_vote", {
          ...(voteCreationSurfaceInput(fixture) as Record<string, JsonValue>),
          decision_package: {
            schema_version: "boardagent.vote-package-components.v1",
            values: {
              components: [
                {
                  type: "management_submission",
                  ordinal: 1,
                  id: versionId,
                  version: 1,
                  sha256: version.sha256
                }
              ]
            }
          }
        });
        if (excluded)
          await recuse(
            secretary,
            fixture,
            "vote",
            fixture.voteId,
            "add",
            "recused-resubmission-vote-exclude"
          );
        await secretary.service.executeDirect(secretary.principal, "request_management_revision", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          submission_id: submissionId,
          reason: "Update the exact submitted materials.",
          idempotency_key: "recused-resubmission-revision-0001"
        });
        const updated = await manager.service.executeDirect(
          manager.principal,
          "resubmit_management_materials",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            submission_id: submissionId,
            document_references: references,
            reason: "Updated submitted version with the exact accepted source.",
            idempotency_key: "recused-resubmission-complete-0001"
          }
        );
        expect(updated.status).toBe("accepted");
        expect(
          (
            await pool.query(
              `select vote.state,
            (select count(*)::int from vote_source_update_causes c where c.vote_id=vote.id and c.source_class='management_submission') as causes,
            (select count(*)::int from audit_events e where e.object_id=vote.id and e.event_type='vote_source_update_pending') as events
           from votes vote where vote.id=$1`,
              [fixture.voteId]
            )
          ).rows
        ).toEqual([{ state: "source_update_pending", causes: 1, events: 1 }]);
        expect(updated.data).toMatchObject({
          source_update_vote_ids: excluded ? [] : [fixture.voteId]
        });
        if (excluded) expect(JSON.stringify(updated)).not.toContain(fixture.voteId);
      });
    }
  );

  it.each(["follow_up", "answer"] as const)(
    "%s mutation omits hidden source-update vote IDs while preserving durable cutoff consequences",
    async (kind) => {
      await withDatabase(async (pool) => {
        const fixture = await seedVoteReplacementFixture(pool, { includeAnsweredQuestion: true });
        await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => replaceVoteInTransaction(client, voteReplacementInput(fixture)),
          { assumeRole: "boardagent_server" }
        );
        await pool.query(
          `insert into organization_role_assignments(id,organization_id,member_id,role,change_reason)
            values ($1,$2,$3,'management','Synthetic assigned management authority')`,
          [testId(996900), fixture.secretary.organizationId, fixture.secretary.memberId]
        );
        const actor = await freshAdministrativeTestCredential(pool, fixture.secretary, 996910);
        await pool.query(
          "update access_token_records set scope_set=scope_set||array['management:question'] where id=$1",
          [actor.accessTokenRecordId]
        );
        const caller = await administrativeService(pool, actor);
        const liftingSecretary = await seedEligibleRecusalSecretary(pool, fixture, 2_204_000);
        const questionId = fixture.decisionPackage.components[0]!.id;
        let sequence = 0;
        const append = async (turnKind: "follow_up" | "answer") => {
          sequence += 1;
          return caller.service.executeDirect(
            caller.principal,
            turnKind === "follow_up"
              ? "follow_up_management_question"
              : "answer_management_question",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              question_id: questionId,
              idempotency_key: `hidden-question-${kind}-${turnKind}-${sequence}`,
              ...(turnKind === "follow_up"
                ? {
                    follow_up: "Please quantify this later cutoff.",
                    due_at: "2099-09-12T12:00:00Z"
                  }
                : { answer: "The quantified later cutoff is retained in this answer." })
            }
          );
        };
        if (kind === "answer") {
          expect(await append("follow_up")).toMatchObject({
            status: "accepted",
            data: { source_update_vote_ids: [fixture.newVoteId] }
          });
        }
        await recuse(
          caller,
          fixture,
          "vote",
          fixture.newVoteId,
          "add",
          `hidden-question-${kind}-exclude`,
          fixture.secretary.memberId
        );
        const evidence = async () =>
          (
            await pool.query<{
              state: string;
              row_version: string;
              causes: string;
              events: string;
            }>(
              `select vote.state,vote.row_version::text,
            (select count(*)::text from vote_source_update_causes cause
              where cause.vote_id=vote.id and cause.source_class='question_cutoff') as causes,
            (select count(*)::text from audit_events event
              where event.object_id=vote.id and event.event_type='vote_source_update_pending') as events
            from votes vote where vote.id=$1`,
              [fixture.newVoteId]
            )
          ).rows[0]!;
        const before = await evidence();
        const response = await append(kind);
        expect(response.status).toBe("accepted");
        expect(await evidence()).toEqual({
          state: "source_update_pending",
          row_version: (BigInt(before.row_version) + 1n).toString(),
          causes: (BigInt(before.causes) + 1n).toString(),
          events: (BigInt(before.events) + 1n).toString()
        });
        const read = await caller.reads.executeRead(caller.principal, "get_management_question", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          question_id: questionId
        });
        expect(read.data).toMatchObject({ question: { questionId } });
        expect(JSON.stringify(read.data)).not.toContain(fixture.replacementDecisionPackageId);
        expect(response.data).toMatchObject({ source_update_vote_ids: [] });
        expect(JSON.stringify(response)).not.toContain(fixture.newVoteId);

        await recuse(
          liftingSecretary,
          fixture,
          "vote",
          fixture.newVoteId,
          "lift",
          `hidden-question-${kind}-lift`,
          fixture.secretary.memberId
        );
        expect(await append(kind === "follow_up" ? "answer" : "follow_up")).toMatchObject({
          status: "accepted",
          data: { source_update_vote_ids: [fixture.newVoteId] }
        });
      });
    }
  );

  async function readers(pool: Pool, fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>) {
    return {
      secretary: await administrativeService(
        pool,
        await freshAdministrativeTestCredential(pool, fixture.secretary, 997100)
      ),
      voter: await administrativeService(
        pool,
        await freshAdministrativeTestCredential(pool, fixture.voter, 997200)
      )
    };
  }

  async function recuse(
    secretary: Awaited<ReturnType<typeof administrativeService>>,
    fixture: Awaited<ReturnType<typeof seedVoteOpenFixture>>,
    objectType: "vote" | "board",
    objectId: string,
    operation: "add" | "lift",
    key: string,
    memberId = fixture.voter.memberId
  ) {
    return confirmSurfaceVoteAction(secretary.service, secretary.principal, "manage_recusal", {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      board_id: fixture.secretary.boardId,
      member_id: memberId,
      object_type: objectType,
      object_id: objectId,
      operation,
      reason: "Current personal read authority regression",
      idempotency_key: key
    });
  }

  it.each(["tool", "resource"] as const)(
    "%s keeps visible question content while omitting only hidden vote package links",
    async (surface) => {
      await withDatabase(async (pool) => {
        const fixture = await seedVoteReplacementFixture(pool, { includeAnsweredQuestion: true });
        await withRequestTransaction(
          pool,
          fixture.secretary.context,
          (client) => replaceVoteInTransaction(client, voteReplacementInput(fixture)),
          { assumeRole: "boardagent_server" }
        );
        const { secretary, voter } = await readers(pool, fixture);
        const liftingSecretary = await seedEligibleRecusalSecretary(pool, fixture, 2_205_000);
        const questionId = fixture.decisionPackage.components[0]!.id;
        const read = async (caller = secretary) => {
          if (surface === "resource") {
            const resource = await caller.reads.readResource(
              caller.principal,
              new URL(`board://${fixture.voter.boardId}/questions/${questionId}`)
            );
            if (resource.text === undefined)
              throw new Error("question fixture resource lacks text");
            return JSON.parse(resource.text);
          }
          const response = await caller.reads.executeRead(
            caller.principal,
            "get_management_question",
            {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              question_id: questionId
            }
          );
          return (response.data as Record<string, JsonValue>)["question"];
        };
        const original = await read();
        expect(original).toMatchObject({
          questionId,
          decisionLinks: [
            { decisionPackageId: fixture.decisionPackageId },
            { decisionPackageId: fixture.replacementDecisionPackageId }
          ]
        });
        await recuse(
          secretary,
          fixture,
          "vote",
          fixture.newVoteId,
          "add",
          `question-read-${surface}-exclude`,
          fixture.secretary.memberId
        );
        expect(await read()).toEqual({ ...original, decisionLinks: [original.decisionLinks[0]] });
        if (surface === "resource")
          await expect(read(voter)).rejects.toThrow("resource unavailable");
        else await expect(read(voter)).resolves.toBeNull();
        await recuse(
          liftingSecretary,
          fixture,
          "vote",
          fixture.newVoteId,
          "lift",
          `question-read-${surface}-lift`,
          fixture.secretary.memberId
        );
        expect(await read()).toEqual(original);
      });
    }
  );

  it("hides both directions of lineage and linked resolved feed payloads while retaining tombstones", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedVoteReplacementFixture(pool);
      await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => replaceVoteInTransaction(client, voteReplacementInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      const { secretary, voter } = await readers(pool, fixture);
      const lineage = (voteId: string, caller = voter) =>
        caller.reads.executeRead(caller.principal, "get_vote_lineage", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: voteId
        });
      const updates = async (caller = voter) => {
        const response = await caller.reads.executeRead(caller.principal, "list_my_updates", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          cursor: null,
          limit: 500
        });
        return (response.data as Record<string, JsonValue>)["items"] as Record<string, JsonValue>[];
      };
      const original = await updates();
      expect(original).toContainEqual(
        expect.objectContaining({
          object_id: fixture.voteId,
          action_type: "vote_replaced",
          state: "resolved"
        })
      );
      const originalLineage = await lineage(fixture.voteId);
      expect(originalLineage.data).toMatchObject({ lineage: [{ new_vote_id: fixture.newVoteId }] });
      await recuse(
        secretary,
        fixture,
        "vote",
        fixture.newVoteId,
        "add",
        "replacement-linked-read-exclude"
      );
      for (const voteId of [fixture.voteId, fixture.newVoteId])
        expect((await lineage(voteId)).data).toMatchObject({ lineage: [] });
      expect((await lineage(fixture.voteId, secretary)).data).toEqual(originalLineage.data);
      const hidden = await updates();
      expect(
        hidden.some(
          (item) =>
            item["entry_kind"] === "feed" && JSON.stringify(item).includes(fixture.newVoteId)
        )
      ).toBe(false);
      expect(hidden).toContainEqual(
        expect.objectContaining({
          entry_kind: "tombstone",
          object_id: fixture.newVoteId
        })
      );
      expect(hidden).toContainEqual(
        expect.objectContaining({
          entry_kind: "feed",
          object_id: fixture.voteId,
          action_type: "vote_opened"
        })
      );
      expect(
        (await updates(secretary)).some((item) => item["action_type"] === "vote_replaced")
      ).toBe(true);
      await recuse(
        secretary,
        fixture,
        "vote",
        fixture.newVoteId,
        "lift",
        "replacement-linked-read-lift"
      );
      expect((await lineage(fixture.voteId)).data).toEqual(originalLineage.data);
      expect(await updates()).toContainEqual(
        expect.objectContaining({
          object_id: fixture.voteId,
          action_type: "vote_replaced",
          state: "resolved"
        })
      );
    });
  });

  it("hides historical proxy grant and revocation metadata for an excluded reader", async () => {
    await withDatabase(async (pool) => {
      const fixture = await seedOpenVoteActFixture(pool);
      const grant = await confirmedProxyGrantInput(pool, fixture, {
        actor: fixture.voter,
        holderMemberId: fixture.secretary.memberId,
        idBase: 997300
      });
      await withRequestTransaction(
        pool,
        fixture.voter.context,
        (client) => grantProxyInTransaction(client, grant),
        { assumeRole: "boardagent_server" }
      );
      const { secretary, voter } = await readers(pool, fixture);
      const read = (caller = voter) =>
        caller.reads.executeRead(caller.principal, "get_proxy_status", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId,
          member_id: fixture.voter.memberId
        });
      expect((await read()).data).toMatchObject({ grants: [{ grant_id: grant.proxyGrantId }] });
      await recuse(secretary, fixture, "vote", fixture.voteId, "add", "proxy-history-read-exclude");
      expect((await read()).data).toMatchObject({ grants: [] });
      expect((await read(secretary)).data).toMatchObject({
        grants: [{ grant_id: grant.proxyGrantId, active: false }]
      });
      await recuse(secretary, fixture, "vote", fixture.voteId, "lift", "proxy-history-read-lift");
      expect((await read()).data).toMatchObject({
        grants: [{ grant_id: grant.proxyGrantId, active: false }]
      });
    });
  });

  it.each(["board_only", "manual_lifted", "manual_active"] as const)(
    "%s uses current causes after a supported board lift on a closed vote without changing its certificate",
    async (cause) => {
      await withDatabase(async (pool) => {
        const fixture = await seedCloseReadyFixture(pool);
        const { secretary, voter } = await readers(pool, fixture);
        await recuse(
          secretary,
          fixture,
          "board",
          fixture.secretary.boardId,
          "add",
          `closed-read-${cause}-board-add`
        );
        if (cause !== "board_only") {
          await recuse(
            secretary,
            fixture,
            "vote",
            fixture.voteId,
            "add",
            `closed-read-${cause}-vote-add`
          );
          if (cause === "manual_lifted")
            await recuse(
              secretary,
              fixture,
              "vote",
              fixture.voteId,
              "lift",
              `closed-read-${cause}-vote-lift`
            );
        }
        const closingService = new PgBoardAgentSurfaceService(pool, {
          reads: secretary.reads,
          transaction: { assumeRole: "boardagent_server" },
          voteCertificateSigner: {
            signVoteCertificate: async (request) => ({
              signatureBase64Url: issueVoteCertificate(
                VoteCertificatePayloadSchema.parse(JSON.parse(request.canonicalPayload)),
                fixture.evidenceKey.privateKey
              ).signatureBase64Url
            })
          }
        });
        const closed = await confirmSurfaceVoteAction(
          closingService,
          secretary.principal,
          "close_vote",
          {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            vote_id: fixture.voteId,
            expected_package_sha256: fixture.packageSha256,
            idempotency_key: `closed-read-${cause}-close-vote`
          }
        );
        expect(closed.result.data).toMatchObject({ state: "closed", outcome: "approved" });
        const data = closed.result.data as Record<string, JsonValue>;
        const publicId = data["certificate_public_id"];
        if (typeof publicId !== "string" || !closed.result.resource_uri)
          throw new Error("close fixture lacks certificate");
        const evidence = () =>
          pool.query(
            `select 'certificate' kind,row_to_json(c)::text bytes from vote_certificates c where c.vote_id=$1
           union all select 'outcome',row_to_json(o)::text from vote_outcomes o where o.vote_id=$1
           union all select 'exclusion',row_to_json(e)::text from vote_exclusions e where e.vote_id=$1 order by kind,bytes`,
            [fixture.voteId]
          );
        const before = (await evidence()).rows;
        const certificate = () =>
          voter.reads.executeRead(voter.principal, "get_vote_certificate", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            vote_id: fixture.voteId,
            certificate_id: null
          });
        expect((await certificate()).data).toEqual({ certificate: null });
        const lifted = await recuse(
          secretary,
          fixture,
          "board",
          fixture.secretary.boardId,
          "lift",
          `closed-read-${cause}-board-lift`
        );
        expect(lifted.prepared.canonical_payload).toMatchObject({ affectedVotes: [] });
        expect((await evidence()).rows).toEqual(before);
        const vote = await voter.reads.executeRead(voter.principal, "get_vote", {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          vote_id: fixture.voteId
        });
        if (cause === "manual_active") {
          expect(vote.data).toEqual({ vote: null });
          expect((await certificate()).data).toEqual({ certificate: null });
          await expect(
            voter.reads.readResource(voter.principal, new URL(closed.result.resource_uri))
          ).rejects.toThrow("resource unavailable");
        } else {
          expect(vote.data).toMatchObject({ vote: { vote_id: fixture.voteId, state: "closed" } });
          expect((await certificate()).data).toMatchObject({
            certificate: { vote_id: fixture.voteId }
          });
          expect(
            await voter.reads.readResource(voter.principal, new URL(closed.result.resource_uri))
          ).toMatchObject({ uri: closed.result.resource_uri });
        }
        expect(
          (
            await voter.reads.executeRead(voter.principal, "verify_certificate", {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              public_id: publicId,
              bundle: null
            })
          ).data
        ).toMatchObject({ valid: true });
        expect(
          await withIdentityTransaction(
            pool,
            { organizationId: fixture.secretary.organizationId, boardIds: [] },
            (client) =>
              verifyPublicPersistedVoteCertificateInTransaction(client, {
                certificatePublicId: publicId
              }),
            { isolation: "read committed", assumeRole: "boardagent_server" }
          )
        ).toEqual({ valid: true });
      });
    }
  );

  it.each(["point", "list", "vote_resource", "package_resource"] as const)(
    "%s hides a supported exact exclusion and restores access only after a supported lift",
    async (surface) => {
      await withDatabase(async (pool) => {
        const fixture = await seedOpenVoteActFixture(pool);
        const secretary = await administrativeService(
          pool,
          await freshAdministrativeTestCredential(pool, fixture.secretary, 998100)
        );
        const voter = await administrativeService(
          pool,
          await freshAdministrativeTestCredential(pool, fixture.voter, 998200)
        );
        const uri = new URL(
          `board://${fixture.voter.boardId}/votes/${fixture.voteId}${surface === "package_resource" ? "/packages/1" : ""}`
        );
        const read = (caller = voter) =>
          surface.endsWith("resource")
            ? surface === "package_resource"
              ? withDirectResponseAllocation(() => caller.reads.readResource(caller.principal, uri))
              : caller.reads.readResource(caller.principal, uri)
            : caller.reads.executeRead(
                caller.principal,
                surface === "point" ? "get_vote" : "list_votes",
                {
                  schema_version: TOOL_INPUT_SCHEMA_VERSION,
                  ...(surface === "point"
                    ? { vote_id: fixture.voteId }
                    : { board_id: fixture.voter.boardId, cursor: null, limit: 1 })
                }
              );
        const visible = async (caller = voter) => {
          if (surface.endsWith("resource"))
            expect(await read(caller)).toMatchObject({ uri: uri.href });
          else expect(JSON.stringify(await read(caller))).toContain(fixture.voteId);
        };
        const change = (operation: "add" | "lift") =>
          confirmSurfaceVoteAction(secretary.service, secretary.principal, "manage_recusal", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.voter.boardId,
            member_id: fixture.voter.memberId,
            object_type: "vote",
            object_id: fixture.voteId,
            operation,
            reason: "Exact vote read exclusion control",
            idempotency_key: `exact-vote-read-${surface}-${operation}`
          });
        await visible();
        const immutableBefore = (
          await pool.query(
            "select encode(canonical_payload,'hex') as bytes from decision_packages where vote_id=$1 order by version",
            [fixture.voteId]
          )
        ).rows;
        await change("add");
        const auditBefore = (
          await pool.query(
            "select count(*)::int as n from audit_events where event_type='resource_fetch'"
          )
        ).rows;
        if (surface.endsWith("resource"))
          await expect(read()).rejects.toThrow("resource unavailable");
        else if (surface === "point")
          expect(await read()).toMatchObject({ data: { vote: null }, resource_uri: null });
        else expect(await read()).toMatchObject({ data: { items: [], next_cursor: null } });
        expect(
          (
            await pool.query(
              "select count(*)::int as n from audit_events where event_type='resource_fetch'"
            )
          ).rows
        ).toEqual(auditBefore);
        await visible(secretary);
        await change("lift");
        await visible();
        expect(
          (
            await pool.query(
              "select version,state from vote_exclusions where vote_id=$1 and member_id=$2 order by version",
              [fixture.voteId, fixture.voter.memberId]
            )
          ).rows
        ).toEqual([
          { version: 1, state: "excluded" },
          { version: 2, state: "lifted" }
        ]);
        expect(
          (
            await pool.query(
              "select encode(canonical_payload,'hex') as bytes from decision_packages where vote_id=$1 order by version",
              [fixture.voteId]
            )
          ).rows
        ).toEqual(immutableBefore);
      });
    }
  );
});
