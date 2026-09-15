-- BoardAgent confirmed vote cancellation authority. Open-vote acts remain immutable
-- evidence and become non-outcome-bearing solely because the vote is terminal.

create function boardagent_apply_vote_cancellation(
  candidate_vote_id uuid,
  expected_row_version bigint,
  candidate_consent_record_id uuid,
  expected_payload_sha256 bytea,
  expected_package_sha256 bytea
)
returns table(row_version bigint,cancelled_at text)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_hash_is_sha256(expected_payload_sha256)
     or (expected_package_sha256 is not null
         and not boardagent_hash_is_sha256(expected_package_sha256))
     or not exists (
       select 1
         from votes as vote
         join consent_records as consent
           on consent.id=candidate_consent_record_id
          and consent.organization_id=vote.organization_id
          and consent.board_id=vote.board_id
         join action_stages as stage on stage.id=consent.stage_id
         join input_required_attempts as attempt
           on attempt.id=consent.input_required_attempt_id
         left join decision_packages as package
           on package.id=vote.current_decision_package_id and package.vote_id=vote.id
        where vote.id=candidate_vote_id
          and vote.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and boardagent_context_board_allowed(vote.board_id)
          and vote.row_version=expected_row_version
          and vote.state in ('draft','open','source_update_pending')
          and boardagent_vote_actor_ready(vote.board_id)
          and package.package_sha256 is not distinct from expected_package_sha256
          and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
          and consent.client_id=boardagent_context_uuid('boardagent.client_id')
          and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
          and consent.action_code='cancel_vote'
          and consent.target_type='vote'
          and consent.target_id=vote.id
          and consent.payload_sha256=expected_payload_sha256
          and consent.package_sha256 is not distinct from expected_package_sha256
          and stage.organization_id=consent.organization_id
          and stage.board_id=consent.board_id
          and stage.actor_member_id=consent.actor_member_id
          and stage.client_id=consent.client_id
          and stage.token_jti=consent.token_jti
          and stage.action_code=consent.action_code
          and stage.target_type=consent.target_type
          and stage.target_id=consent.target_id
          and stage.payload_sha256=consent.payload_sha256
          and stage.package_sha256 is not distinct from consent.package_sha256
          and stage.state='confirmed' and stage.confirmed_at is not null
          and attempt.organization_id=consent.organization_id
          and attempt.stage_id=stage.id
          and attempt.original_method='tools/call'
          and attempt.original_name='cancel_vote'
          and attempt.response_action='accept'
          and attempt.state='confirmed'
     ) then
    raise exception 'vote cancellation lacks exact confirmed authority' using errcode='42501';
  end if;

  return query
    update votes as vote
       set state='cancelled',cancelled_at=transaction_timestamp(),
           row_version=vote.row_version+1
     where vote.id=candidate_vote_id
       and vote.row_version=expected_row_version
       and vote.state in ('draft','open','source_update_pending')
     returning vote.row_version,
       to_char(vote.cancelled_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  if not found then
    raise exception 'vote changed before confirmed cancellation' using errcode='40001';
  end if;
end
$$;
alter function boardagent_apply_vote_cancellation(uuid,bigint,uuid,bytea,bytea)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_vote_cancellation(uuid,bigint,uuid,bytea,bytea)
  from public;
grant execute on function boardagent_apply_vote_cancellation(uuid,bigint,uuid,bytea,bytea)
  to boardagent_server;
