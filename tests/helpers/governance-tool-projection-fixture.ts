import { createHash } from "node:crypto";
import type { Pool } from "pg";
import { testId, type AuthorizedActorFixture } from "./authorized-actor.js";

// Ordinary constrained storage, not a public profile/ruleset activation or
// canonical-commitment validation ceremony. Deliberately preserve a decimal
// that native JSON parsing rounds; SQL text is the persisted-value oracle.
export async function seedGovernanceToolProjectionFixture(
  pool: Pool,
  actor: AuthorizedActorFixture
) {
  const profileId = testId(310001),
    alternateProfileId = testId(310002),
    rulesetId = testId(310003),
    alternateRulesetId = testId(310004),
    approvalRuleId = testId(310005),
    matterTypeId = testId(310006);
  const ruleIds = [testId(310010), testId(310011), testId(310012), testId(310013)] as const;
  const payloadText =
    '{"marker":"A","carry":9999999999999999,"small":1e-7,"nested":{"Δ":[null,true,{},[]]}}';
  const referencesText = "[9999999999999999]";
  const conditionText =
    '{"carry":9999999999999999,"small":1e-7,"all":[{"fact":"synthetic Δ","value":true},{}]}';
  const hash = (value: string) => createHash("sha256").update(value).digest();
  await pool.query(
    `insert into approval_rules(id,organization_id,board_id,schema_version,threshold_numerator,
      threshold_denominator,quorum_numerator,quorum_denominator,approval_denominator,
      abstentions_count_for_quorum,tie_behavior,proxy_policy,close_mode,canonical_sha256,created_by)
     values($1,$2,$3,'boardagent.approval-rule.v1',1,2,1,2,'eligible',true,'reject',
       'principal_supersedes_proxy','secretariat_confirmed',$4,$5)`,
    [
      approvalRuleId,
      actor.organizationId,
      actor.boardId,
      hash("synthetic approval"),
      actor.memberId
    ]
  );
  for (const [index, id] of [profileId, alternateProfileId].entries()) {
    await pool.query(
      `insert into governance_profiles(id,organization_id,board_id,version,state,schema_version,
        canonical_payload,canonical_sha256,source_agreement_references,created_by,created_at)
       values($1,$2,$3,$4,'draft','boardagent.governance-profile.v1',$5::jsonb,$6,$7::jsonb,$8,
         '2026-09-12T11:00:00Z')`,
      [
        id,
        actor.organizationId,
        actor.boardId,
        index + 1,
        payloadText,
        hash(`synthetic profile commitment ${index}`),
        index === 0 ? referencesText : "[]",
        actor.memberId
      ]
    );
  }
  for (const [index, id] of [rulesetId, alternateRulesetId].entries()) {
    await pool.query(
      `insert into rulesets(id,organization_id,board_id,profile_id,version,state,schema_version,
        canonical_payload,canonical_sha256,created_by,created_at)
       values($1,$2,$3,$4,$5,'draft','boardagent.ruleset.v1',$6::jsonb,$7,$8,'2026-09-12T11:00:00Z')`,
      [
        id,
        actor.organizationId,
        actor.boardId,
        index === 0 ? profileId : alternateProfileId,
        index + 1,
        payloadText,
        hash(`synthetic ruleset commitment ${index}`),
        actor.memberId
      ]
    );
  }
  await pool.query(
    `insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256)
     values($1,$2,'synthetic_read','Synthetic governance tool read','{}',$3)`,
    [matterTypeId, rulesetId, hash("{}")]
  );
  // Expected order is ruleIds: primary priority, then specificity, then UUID.
  // Insert a different order so the oracle cannot inherit insertion order.
  for (const [id, priority, specificity] of [
    [ruleIds[3], 10, 2],
    [ruleIds[1], 10, 3],
    [ruleIds[0], 20, 1],
    [ruleIds[2], 10, 2]
  ] as const) {
    await pool.query(
      `insert into ruleset_rules(id,ruleset_id,matter_type_id,priority,specificity,
        condition_tree,approval_rule_id,canonical_sha256) values($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`,
      [
        id,
        rulesetId,
        matterTypeId,
        priority,
        specificity,
        conditionText,
        approvalRuleId,
        hash(`synthetic rule commitment ${id}`)
      ]
    );
  }
  // Keep the reviewed original current-pointer semantics, including draft rows.
  // Normal row-version/FK/state guards stay enabled; setup failures are evidence.
  const changed = await pool.query(
    `update boards set current_governance_profile_id=$2,current_ruleset_id=$3,
      row_version=row_version+1 where id=$1 returning id`,
    [actor.boardId, profileId, rulesetId]
  );
  if (changed.rows.length !== 1)
    throw new Error("synthetic governance pointer update missed its board");
  return {
    profileId,
    alternateProfileId,
    rulesetId,
    alternateRulesetId,
    approvalRuleId,
    matterTypeId,
    ruleIds,
    payloadText,
    referencesText,
    conditionText
  };
}
