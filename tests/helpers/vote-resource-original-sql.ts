// Frozen original vote resource SQL. Test-only; never a production fallback.
export const ORIGINAL_VOTE_RESOURCE_SQL = `select vote.id,vote.row_version::text,
                jsonb_build_object('schema_version','boardagent.vote-resource.v1',
                  'vote_id',vote.id,'board_id',vote.board_id,'title',vote.title,
                  'state',vote.state,'resolution_version_id',vote.current_resolution_version_id,
                  'decision_package_id',vote.current_decision_package_id,
                  'approval_rule_id',vote.approval_rule_id,
                  'governance_profile_id',vote.governance_profile_id,
                  'ruleset_id',vote.ruleset_id,
                  'electorate_sha256',case when vote.electorate_sha256 is null then null
                    else encode(vote.electorate_sha256,'hex') end,
                  'close_mode',vote.close_mode,
                  'deadline_at',to_char(vote.deadline_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                  'row_version',vote.row_version::text,
                  'outcome',(select jsonb_build_object('outcome_id',outcome.id,
                    'canonical_tally',outcome.canonical_tally,
                    'tally_sha256',encode(outcome.tally_sha256,'hex'),
                    'outcome',outcome.outcome,'certificate_id',outcome.certificate_id)
                    from vote_outcomes as outcome where outcome.vote_id=vote.id limit 1)) as payload
           from votes as vote where vote.board_id=$1 and vote.id=$2
             and not boardagent_member_vote_recused(vote.id,
               boardagent_context_uuid('boardagent.member_id'))`;
