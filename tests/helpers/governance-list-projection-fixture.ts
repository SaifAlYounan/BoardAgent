import { createHash } from "node:crypto";
import type { Pool } from "pg";
import { testId, type AuthorizedActorFixture } from "./authorized-actor.js";
import { seedGovernanceToolProjectionFixture } from "./governance-tool-projection-fixture.js";

// Constrained synthetic storage; this is not a public governance activation ceremony.
// Reuse the already proven two-profile/two-ruleset setup without changing that fixture.
export async function seedGovernanceListProjectionFixture(
  pool: Pool,
  actor: AuthorizedActorFixture
) {
  const base = await seedGovernanceToolProjectionFixture(pool, actor);
  const templateIds = [testId(340001), testId(340002), testId(340003)] as const;
  const matterIds = [testId(340004), testId(340005), base.matterTypeId] as const;
  const payload =
    '{"carry":9999999999999999,"label":"Mining Δ","nested":{"array":[null,true,{},[]]}}';
  const hash = (v: string) => createHash("sha256").update(v).digest();
  for (const [i, id] of templateIds.entries()) {
    await pool.query(
      "insert into governance_rule_templates(id,profile_id,code,approval_rule_id,exact_rule_payload,canonical_sha256) values($1,$2,$3,$4,$5::jsonb,$6)",
      [
        id,
        base.profileId,
        ["alpha", "bravo", "charlie"][i],
        base.approvalRuleId,
        payload,
        hash("synthetic template " + i)
      ]
    );
  }
  for (const [i, id] of matterIds.slice(0, 2).entries()) {
    await pool.query(
      "insert into matter_types(id,ruleset_id,code,name,strict_fact_schema,schema_sha256) values($1,$2,$3,$4,$5::jsonb,$6)",
      [
        id,
        base.rulesetId,
        ["alpha", "bravo"][i],
        'Mining "permit" Δ\nPath \\ 🙂',
        payload,
        hash("synthetic schema " + i)
      ]
    );
  }
  return { ...base, templateIds, matterIds, payload };
}
