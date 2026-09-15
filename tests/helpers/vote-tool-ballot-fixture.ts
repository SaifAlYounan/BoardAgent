// Extracted test-only setup from tests/integration/vote-open.postgres.test.ts.
// Exact source spans, hashes, and questionless specialization are recorded in
// the separate ballot-supplement EXTRACT.py and EXTRACTION.json evidence.
// This module does not import the original test module or its runner.
import type { Pool } from "pg";

import {
  canonicalJson,
  canonicalSha256,
  DecisionPackageSchema,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import {
  evaluateMatterInTransaction,
  openVoteInTransaction,
  replaceVoteInTransaction,
  withRequestTransaction,
  type CastBallotInput,
  type GrantProxyInput,
  type RevokeProxyInput,
  type OpenVoteInput,
  type ReplaceVoteInput
} from "../../lib/db/src/index.js";
import {
  ballotConsentHash,
  prepareVoteElectorate,
  proxyGrantConsentHash,
  proxyRevokeConsentHash,
  voteReplacementConsentHash
} from "../../lib/domain/src/index.js";
import {
  seedAdditionalAuthorizedActor,
  seedAuthorizedActor,
  testHash,
  testId
} from "./authorized-actor.js";

async function seedVoteOpenFixture(
  pool: Pool,
  options: {
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
  const components: [] = [];
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

// Thin names and actor aliases for the separately selected read-projection test.
// The underlying fixture keeps the original default policy and normal open API.
export async function seedVoteToolBallotFixture(pool: Pool) {
  const fixture = await seedOpenVoteActFixture(pool);
  return {
    ...fixture,
    actorA: fixture.secretary,
    actorB: fixture.voter,
    context: fixture.secretary.context
  };
}

export {
  confirmedProxyGrantInput as confirmedVoteToolProxyGrantInput,
  confirmedBallotInput as confirmedVoteToolBallotInput
};

export type VoteToolBallotFixture = Awaited<ReturnType<typeof seedVoteToolBallotFixture>>;

// Specific test-only revoke input. The underlying consent fixture remains private;
// no generic action/service callback or public authorization bypass is exported.
export async function confirmedBoardVoteProxyRevokeInput(
  pool: Pool,
  fixture: VoteToolBallotFixture,
  input: {
    readonly actor: typeof fixture.actorB;
    readonly proxyGrantId: string;
    readonly idBase: number;
  }
): Promise<RevokeProxyInput> {
  const reason = "Requester revoked the synthetic proxy Δ.";
  const payloadSha256 = proxyRevokeConsentHash({
    voteId: fixture.voteId,
    proxyGrantId: input.proxyGrantId,
    principalMemberId: input.actor.memberId,
    reason,
    packageSha256: fixture.packageSha256
  });
  const consent = await seedConfirmedVoteAction(pool, fixture, {
    idBase: input.idBase,
    actionCode: "revoke_proxy",
    originalName: "revoke_proxy",
    targetType: "proxy_grant",
    targetId: input.proxyGrantId,
    payloadSha256,
    packageSha256: fixture.packageSha256,
    actor: input.actor
  });
  return {
    organizationId: fixture.secretary.organizationId,
    voteId: fixture.voteId,
    proxyGrantId: input.proxyGrantId,
    decisionPackageSha256: fixture.packageSha256,
    reason,
    consentRecordId: consent.consentRecordId,
    proxyRevocationId: testId(input.idBase + 20),
    idempotencyRecordId: testId(input.idBase + 21),
    idempotencyKey: `board-vote-revoke-${String(input.idBase).padStart(16, "0")}`,
    auditEventId: testId(input.idBase + 22)
  };
}

// Bounded extraction of four previously reviewed test-only replacement builders.
// No broad test-module import; synthetic old acts/consents are not public ceremonies.
async function seedBoardVoteActiveStage(
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

async function seedBoardVoteReplacementStorage(pool: Pool) {
  // Preserve the passed standalone fixture's questionless default.
  const fixture = await seedVoteOpenFixture(pool);
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
  await seedBoardVoteActiveStage(pool, fixture, activeStageId, oldPackageSha256);

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

function boardVoteReplacementInput(
  fixture: Awaited<ReturnType<typeof seedBoardVoteReplacementStorage>>,
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

async function secondBoardVoteReplacementInput(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof seedBoardVoteReplacementStorage>>
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

// Only these fixed normal replacement steps are exported. No arbitrary
// transaction/service callback, override input or consent seeding port escapes.
export async function seedBoardVoteReplacementFixture(pool: Pool) {
  const fixture = await seedBoardVoteReplacementStorage(pool);
  let firstDone = false;
  let secondDone = false;
  return {
    actorA: fixture.secretary,
    actorB: fixture.voter,
    context: fixture.secretary.context,
    boardId: fixture.secretary.boardId,
    originalVoteId: fixture.voteId,
    middleVoteId: fixture.newVoteId,
    successorVoteId: testId(600),
    async replaceOnce() {
      if (firstDone) throw new Error("first replacement already completed");
      const result = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => replaceVoteInTransaction(client, boardVoteReplacementInput(fixture)),
        { assumeRole: "boardagent_server" }
      );
      firstDone = true;
      return result;
    },
    async appendSuccessor() {
      if (!firstDone || secondDone) throw new Error("successor replacement is unavailable");
      const input = await secondBoardVoteReplacementInput(pool, fixture);
      const result = await withRequestTransaction(
        pool,
        fixture.secretary.context,
        (client) => replaceVoteInTransaction(client, input),
        { assumeRole: "boardagent_server" }
      );
      secondDone = true;
      return result;
    }
  };
}
