// Frozen original get_vote SQL; deliberately independent of the admitted helper.
export const ORIGINAL_VOTE_TOOL_SQL = `select jsonb_build_object(
           'vote_id',vote.id,'board_id',vote.board_id,'title',vote.title,'state',vote.state,
           'resolution',jsonb_build_object(
              'version_id',resolution.id,'version',resolution.version,
              'canonical_text',resolution.canonical_text,
              'sha256',encode(resolution.canonical_sha256,'hex')
           ),
           'decision_package',jsonb_build_object(
              'package_id',package.id,'version',package.version,
              'schema_version',package.schema_version,
              'package_sha256',encode(package.package_sha256,'hex'),
              'canonical_payload',convert_from(package.canonical_payload,'UTF8')::jsonb,
              'governance_profile_id',package.governance_profile_id,
              'governance_profile_sha256',encode(package.governance_profile_sha256,'hex'),
              'ruleset_id',package.ruleset_id,'ruleset_sha256',encode(package.ruleset_sha256,'hex'),
              'approval_rule_id',package.approval_rule_id,
              'approval_rule_sha256',encode(package.approval_rule_sha256,'hex'),
              'electorate_sha256',encode(package.electorate_sha256,'hex')
           ),
           'close_mode',vote.close_mode,
           'deadline_at',to_char(vote.deadline_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'row_version',vote.row_version::text,
           'my_ballots',coalesce((select jsonb_agg(jsonb_build_object(
              'ballot_id',ballot.id,'principal_member_id',ballot.principal_member_id,
              'caster_member_id',ballot.caster_member_id,'choice',ballot.choice,
              'statement',ballot.statement_text,'voting_weight',ballot.voting_weight::text,
              'source',ballot.ballot_source,
              'cast_at',to_char(ballot.cast_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            ) order by ballot.cast_at,ballot.id) from ballots as ballot
             where ballot.vote_id=vote.id and
              (ballot.principal_member_id=$2 or ballot.caster_member_id=$2)),'[]'::jsonb),
           'outcome',case when outcome.id is null then null else jsonb_build_object(
              'outcome_id',outcome.id,'canonical_tally',outcome.canonical_tally,
              'tally_sha256',encode(outcome.tally_sha256,'hex'),'outcome',outcome.outcome,
              'finalized_at',to_char(outcome.finalized_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              'certificate_id',outcome.certificate_id
           ) end,
           'created_at',to_char(vote.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'opened_at',case when vote.opened_at is null then null else
             to_char(vote.opened_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end,
           'closed_at',case when vote.closed_at is null then null else
             to_char(vote.closed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as view
         from votes as vote
         left join resolution_versions as resolution on resolution.id=vote.current_resolution_version_id
         left join decision_packages as package on package.id=vote.current_decision_package_id
         left join vote_outcomes as outcome on outcome.vote_id=vote.id
        where vote.id=$1 and not boardagent_member_vote_recused(vote.id,$2)`;
