import { createHash } from "node:crypto";
import type { Pool } from "pg";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { appendAuditEventsInTransaction } from "../../lib/db/src/transactions/audit.js";
import { testId, type AuthorizedActorFixture } from "./authorized-actor.js";

const hash = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest();
const jsonBytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");

// Normal constrained synthetic storage only. These rows let a SELECT test
// exercise a standalone vote resource and a fresh recusal. They are not public
// governance creation, signing, confirmation or accepted corporate acts.
async function syntheticEvidence(
  pool: Pool,
  actor: AuthorizedActorFixture,
  target: {
    id: string;
    type: "vote";
    actionCode: "create_vote" | "manage_recusal";
    packageSha256: Buffer | null;
    idBase: number;
  }
) {
  const stage = testId(target.idBase),
    attempt = testId(target.idBase + 1);
  const consent = testId(target.idBase + 2),
    audit = testId(target.idBase + 3);
  const payload = jsonBytes({
    schemaVersion: "boardagent.synthetic-storage-consent.v1",
    targetType: target.type,
    targetId: target.id,
    memberId: actor.memberId
  });
  const digest = hash(payload);
  const unique = (label: string) => hash(`${String(target.idBase)}:${label}`);
  await pool.query(
    `insert into action_stages(id,organization_id,board_id,actor_member_id,action_code,target_type,target_id,
     canonical_schema,canonicalization_version,canonical_payload,payload_sha256,nonce_sha256,
     protected_code_sha256,client_id,access_token_record_id,token_jti,exact_origin,context_sha256,state,expires_at,package_sha256)
     values($1,$2,$3,$4,'${target.actionCode}',$5,$6,'boardagent.synthetic-storage-consent.v1',
     'RFC8785+NFC-LF-v1',$7,$8,$9,$10,$11,$12,$13,'https://client.example',$14,'active',transaction_timestamp()+interval '10 minutes',$15)`,
    [
      stage,
      actor.organizationId,
      actor.boardId,
      actor.memberId,
      target.type,
      target.id,
      payload,
      digest,
      unique("nonce"),
      unique("code"),
      actor.clientId,
      actor.accessTokenRecordId,
      actor.tokenJti,
      unique("context"),
      target.packageSha256
    ]
  );
  await pool.query(
    "update action_stages set state='confirmed',confirmed_at=transaction_timestamp() where id=$1",
    [stage]
  );
  const requestState = Buffer.from(unique("request-state"));
  await pool.query(
    `insert into input_required_attempts(id,organization_id,stage_id,protocol_version,protocol_header_version,
     result_meta_version,original_method,original_name,original_arguments_sha256,capabilities_sha256,
     embedded_form_sha256,embedded_result_sha256,request_state_bytes,request_state_sha256,
     prepared_request_id,retry_request_id,input_response_sha256,response_action,state,completed_at)
     values($1,$2,$3,'2026-07-28','2026-07-28','boardagent.mrtr.v1','tools/call','${target.actionCode}',
     $4,$5,$6,$7,$8,$9,$10,$11,$12,'accept','confirmed',transaction_timestamp())`,
    [
      attempt,
      actor.organizationId,
      stage,
      digest,
      unique("capabilities"),
      unique("form"),
      unique("result"),
      requestState,
      hash(requestState),
      Buffer.from(`prepared-${target.idBase}`),
      Buffer.from(`retry-${target.idBase}`),
      unique("response")
    ]
  );
  await pool.query(
    `insert into consent_records(id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
     action_code,target_type,target_id,canonical_schema,payload_sha256,protected_code_record_sha256,
     access_token_record_id,token_jti,client_id,exact_origin,staged_at,record_sha256,package_sha256)
     values($1,$2,$3,$4,$5,$6,'${target.actionCode}',$7,$8,'boardagent.consent-record.v1',$9,$10,
     $11,$12,$13,'https://client.example',transaction_timestamp(),$14,$15)`,
    [
      consent,
      actor.organizationId,
      actor.boardId,
      stage,
      attempt,
      actor.memberId,
      target.type,
      target.id,
      digest,
      unique("protected-code-record"),
      actor.accessTokenRecordId,
      actor.tokenJti,
      actor.clientId,
      unique("consent-record"),
      target.packageSha256
    ]
  );
  if (target.actionCode === "manage_recusal")
    await withRequestTransaction(
      pool,
      actor.context,
      (client) =>
        appendAuditEventsInTransaction(client, [
          {
            organizationId: actor.organizationId,
            consentRecordId: consent,
            event: {
              eventId: audit,
              eventType: "recusal_changed",
              actorMemberId: actor.memberId,
              actorClientId: actor.clientId,
              tokenJti: actor.tokenJti,
              entityType: target.type,
              entityId: target.id,
              boardId: actor.boardId,
              origin: "mcp",
              details: { syntheticStorageFixture: true, memberId: actor.memberId },
              schemaVersion: 1
            }
          }
        ]),
      { assumeRole: "boardagent_server" }
    );
  return { consent, audit };
}

export async function seedVoteProjectionFixture(pool: Pool, actor: AuthorizedActorFixture) {
  const approval = testId(222000),
    profile = testId(222001),
    ruleset = testId(222002),
    matter = testId(222003),
    rule = testId(222004),
    evaluation = testId(222005),
    vote = testId(222006),
    resolution = testId(222007),
    decision = testId(222008);
  const emptyObject = jsonBytes({}),
    emptyArray = jsonBytes([]),
    resolutionText = "RESOLVED: retain exact synthetic Mining record.\n";
  const packageBytes = jsonBytes({
    schemaVersion: "boardagent.decision-package.v1",
    fixture: "standalone vote resource SQL only Δ 🙂",
    voteId: vote,
    packageVersion: 1,
    resolutionVersionId: resolution,
    resolutionSha256: hash(resolutionText).toString("hex")
  });
  // The package is a constrained raw canonical storage fixture. The public
  // decision-package schema/creation ceremony is not exercised by this test.
  await pool.query(
    `insert into approval_rules(id,organization_id,board_id,schema_version,threshold_numerator,
      threshold_denominator,quorum_numerator,quorum_denominator,approval_denominator,abstentions_count_for_quorum,
      tie_behavior,proxy_policy,close_mode,canonical_sha256,created_by)
      values($1,$2,$3,'boardagent.approval-rule.v1',1,2,1,2,'eligible',true,'reject','principal_supersedes_proxy',
      'secretariat_confirmed',$4,$5)`,
    [approval, actor.organizationId, actor.boardId, hash("synthetic approval"), actor.memberId]
  );
  await pool.query(
    `insert into governance_profiles(id,organization_id,board_id,version,state,schema_version,
      canonical_payload,canonical_sha256,source_agreement_references,created_by)
      values($1,$2,$3,1,'draft','boardagent.governance-profile.v1','{}',$4,'[]',$5)`,
    [profile, actor.organizationId, actor.boardId, hash(emptyObject), actor.memberId]
  );
  await pool.query(
    `insert into rulesets(id,organization_id,board_id,profile_id,version,state,schema_version,
      canonical_payload,canonical_sha256,created_by) values($1,$2,$3,$4,1,'draft','boardagent.ruleset.v1','{}',$5,$6)`,
    [ruleset, actor.organizationId, actor.boardId, profile, hash(emptyObject), actor.memberId]
  );
  await pool.query(
    `insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256)
      values($1,$2,'synthetic_read','Synthetic resource read','{}',$3)`,
    [matter, ruleset, hash(emptyObject)]
  );
  await pool.query(
    `insert into ruleset_rules(id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
      approval_rule_id,canonical_sha256) values($1,$2,$3,1,1,'{}',$4,$5)`,
    [rule, ruleset, matter, approval, hash("synthetic selected rule")]
  );
  await pool.query(
    `insert into matter_evaluations(id,organization_id,board_id,requester_member_id,profile_id,ruleset_id,
      matter_type_id,engine_version,canonical_facts,facts_sha256,result,matched_rule_id,candidate_rule_ids,citation_snapshot,result_sha256)
      values($1,$2,$3,$4,$5,$6,$7,'boardagent.rules-engine.v1','{}',$8,'matched',$9,array[$9::uuid],'[]',$10)`,
    [
      evaluation,
      actor.organizationId,
      actor.boardId,
      actor.memberId,
      profile,
      ruleset,
      matter,
      hash(emptyObject),
      rule,
      hash("synthetic evaluation")
    ]
  );
  await pool.query(
    `insert into votes(id,organization_id,board_id,title,approval_rule_id,governance_profile_id,ruleset_id,
      close_mode,created_by) values($1,$2,$3,'Synthetic decision resource',$4,$5,$6,'secretariat_confirmed',$7)`,
    [vote, actor.organizationId, actor.boardId, approval, profile, ruleset, actor.memberId]
  );
  await pool.query(
    `insert into resolution_versions(id,organization_id,board_id,vote_id,version,canonical_schema,
      canonical_text,canonical_sha256,author_member_id) values($1,$2,$3,$4,1,'boardagent.resolution.v1',$5,$6,$7)`,
    [
      resolution,
      actor.organizationId,
      actor.boardId,
      vote,
      resolutionText,
      hash(resolutionText),
      actor.memberId
    ]
  );
  await pool.query(
    `insert into decision_packages(id,organization_id,board_id,vote_id,version,schema_version,resolution_version_id,
      resolution_sha256,submission_manifest,submission_manifest_sha256,document_manifest,document_manifest_sha256,
      question_cutoff_manifest,question_cutoff_sha256,approval_rule_id,approval_rule_sha256,governance_profile_id,
      governance_profile_sha256,ruleset_id,ruleset_sha256,electorate_sha256,canonical_payload,package_sha256,created_by,
      matter_evaluation_id,matter_evaluation_result_sha256,selected_ruleset_rule_id,selected_ruleset_rule_sha256)
      values($1,$2,$3,$4,1,'boardagent.decision-package.v1',$5,$6,'[]',$7,'[]',$7,'[]',$7,$8,$9,$10,$11,$12,$11,
      $7,$13,$14,$15,$16,$17,$18,$19)`,
    [
      decision,
      actor.organizationId,
      actor.boardId,
      vote,
      resolution,
      hash(resolutionText),
      hash(emptyArray),
      approval,
      hash("synthetic approval"),
      profile,
      hash(emptyObject),
      ruleset,
      packageBytes,
      hash(packageBytes),
      actor.memberId,
      evaluation,
      hash("synthetic evaluation"),
      rule,
      hash("synthetic selected rule")
    ]
  );
  await pool.query(
    "update votes set current_resolution_version_id=$2,current_decision_package_id=$3,row_version=row_version+1 where id=$1",
    [vote, resolution, decision]
  );

  const recusal = await syntheticEvidence(pool, actor, {
    id: vote,
    type: "vote",
    actionCode: "manage_recusal",
    packageSha256: null,
    idBase: 222200
  });
  return {
    voteId: vote,
    packageId: decision,
    exclude: async () => {
      const inserted = await pool.query(
        `insert into vote_exclusions(id,organization_id,board_id,vote_id,member_id,version,
        state,reason,actor_member_id,consent_record_id)
        values($1,$2,$3,$4,$5,1,'excluded','Synthetic question projection link recusal',$5,$6) returning id`,
        [testId(222204), actor.organizationId, actor.boardId, vote, actor.memberId, recusal.consent]
      );
      if (inserted.rowCount !== 1) throw new Error("vote fixture recusal was not stored");
    }
  };
}
