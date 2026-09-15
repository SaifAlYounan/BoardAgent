// Frozen original SQL, independent of the proposed projection field maps.
export const ORIGINAL_PROFILE_TOOL_SQL = `select jsonb_build_object(
           'profile_id',profile.id,'board_id',profile.board_id,'version',profile.version,
           'state',profile.state,'schema_version',profile.schema_version,
           'canonical_payload',profile.canonical_payload,
           'sha256',encode(profile.canonical_sha256,'hex'),
           'source_agreement_references',profile.source_agreement_references,
           'supersedes_id',profile.supersedes_id,
           'created_at',to_char(profile.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'activated_at',case when profile.activated_at is null then null else
              to_char(profile.activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as view
         from governance_profiles as profile
         join boards as board on board.id=profile.board_id
        where profile.board_id=$1
          and (($2::integer is null and profile.id=board.current_governance_profile_id)
            or profile.version=$2)
        order by profile.version desc limit 1`;
export const ORIGINAL_RULESET_TOOL_SQL = `select jsonb_build_object(
           'ruleset_id',ruleset.id,'board_id',ruleset.board_id,'profile_id',ruleset.profile_id,
           'version',ruleset.version,'state',ruleset.state,'schema_version',ruleset.schema_version,
           'canonical_payload',ruleset.canonical_payload,
           'sha256',encode(ruleset.canonical_sha256,'hex'),'supersedes_id',ruleset.supersedes_id,
           'rules',coalesce((select jsonb_agg(jsonb_build_object(
              'rule_id',rule.id,'matter_type_id',rule.matter_type_id,'priority',rule.priority,
              'specificity',rule.specificity,'condition',rule.condition_tree,
              'approval_rule_id',rule.approval_rule_id,
              'sha256',encode(rule.canonical_sha256,'hex')
            ) order by rule.priority desc,rule.specificity desc,rule.id)
              from ruleset_rules as rule where rule.ruleset_id=ruleset.id),'[]'::jsonb),
           'created_at',to_char(ruleset.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'activated_at',case when ruleset.activated_at is null then null else
              to_char(ruleset.activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as view
         from rulesets as ruleset join boards as board on board.id=ruleset.board_id
        where ruleset.board_id=$1
          and (($2::uuid is null and ruleset.id=board.current_ruleset_id) or ruleset.id=$2)
        limit 1`;
