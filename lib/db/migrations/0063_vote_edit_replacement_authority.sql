-- Resolution amendment and deadline extension on an open vote are aliases of
-- the same immutable replacement invariant. Their own MCP action names remain
-- bound through consent while the lower transaction stays singular.

create or replace function boardagent_lock_vote_for_replacement(
  candidate_old_vote uuid,
  candidate_consent uuid,
  candidate_payload_sha256 bytea,
  candidate_new_package_sha256 bytea,
  candidate_approval_rule uuid,
  candidate_governance_profile uuid,
  candidate_ruleset uuid,
  candidate_close_mode text
)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_state text,
  vote_row_version bigint,
  old_package_payload bytea,
  old_package_sha256 bytea,
  approval_rule_sha256 bytea,
  governance_profile_version integer,
  governance_profile_sha256 bytea,
  ruleset_version integer,
  ruleset_sha256 bytea,
  actor_ready boolean,
  binding_valid boolean,
  consent_valid boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_payload_sha256 is null
     or octet_length(candidate_payload_sha256) <> 32
     or candidate_new_package_sha256 is null
     or octet_length(candidate_new_package_sha256) <> 32 then
    raise exception 'replacement confirmation hash is invalid' using errcode = '22023';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.state,
           vote.row_version,
           package.canonical_payload,
           package.package_sha256,
           rule.canonical_sha256,
           profile.version,
           profile.canonical_sha256,
           ruleset.version,
           ruleset.canonical_sha256,
           boardagent_vote_actor_ready(vote.board_id),
           (
             board.state = 'active'
             and board.current_governance_profile_id = profile.id
             and board.current_ruleset_id = ruleset.id
             and profile.state = 'active'
             and profile.organization_id = vote.organization_id
             and profile.board_id = vote.board_id
             and ruleset.state = 'active'
             and ruleset.organization_id = vote.organization_id
             and ruleset.board_id = vote.board_id
             and ruleset.profile_id = profile.id
             and rule.organization_id = vote.organization_id
             and rule.board_id = vote.board_id
             and rule.close_mode = candidate_close_mode
             and candidate_approval_rule = vote.approval_rule_id
             and candidate_governance_profile = vote.governance_profile_id
             and candidate_ruleset = vote.ruleset_id
             and candidate_close_mode = vote.close_mode
           ),
           exists (
             select 1
               from consent_records as consent
               join action_stages as stage on stage.id = consent.stage_id
               join input_required_attempts as attempt
                 on attempt.id = consent.input_required_attempt_id
              where consent.id = candidate_consent
                and consent.organization_id = vote.organization_id
                and consent.board_id = vote.board_id
                and consent.actor_member_id = boardagent_context_uuid('boardagent.member_id')
                and consent.client_id = boardagent_context_uuid('boardagent.client_id')
                and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
                and consent.action_code in (
                  'replace_open_vote', 'amend_resolution_text', 'extend_vote_deadline'
                )
                and consent.target_type = 'vote'
                and consent.target_id = vote.id
                and consent.payload_sha256 = candidate_payload_sha256
                and consent.package_sha256 = candidate_new_package_sha256
                and stage.organization_id = consent.organization_id
                and stage.board_id = consent.board_id
                and stage.actor_member_id = consent.actor_member_id
                and stage.client_id = consent.client_id
                and stage.token_jti = consent.token_jti
                and stage.action_code = consent.action_code
                and stage.target_type = consent.target_type
                and stage.target_id = consent.target_id
                and stage.payload_sha256 = consent.payload_sha256
                and stage.package_sha256 = consent.package_sha256
                and stage.state = 'confirmed'
                and stage.confirmed_at is not null
                and attempt.organization_id = consent.organization_id
                and attempt.stage_id = stage.id
                and attempt.original_method = 'tools/call'
                and attempt.original_name = consent.action_code
                and attempt.response_action = 'accept'
                and attempt.state = 'confirmed'
           )
      from votes as vote
      join decision_packages as package
        on package.id = vote.current_decision_package_id
       and package.vote_id = vote.id
      join boards as board on board.id = vote.board_id
      join approval_rules as rule on rule.id = candidate_approval_rule
      join governance_profiles as profile on profile.id = candidate_governance_profile
      join rulesets as ruleset on ruleset.id = candidate_ruleset
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(vote.board_id)
     for update of vote
     for share of package, board, rule, profile, ruleset;
end
$$;
alter function boardagent_lock_vote_for_replacement(uuid, uuid, bytea, bytea, uuid, uuid, uuid, text)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_for_replacement(uuid, uuid, bytea, bytea, uuid, uuid, uuid, text)
  from public;
grant execute on function boardagent_lock_vote_for_replacement(uuid, uuid, bytea, bytea, uuid, uuid, uuid, text)
  to boardagent_server;

drop policy boardagent_server_question_links_insert on question_decision_links;
create policy boardagent_server_question_links_insert on question_decision_links
  for insert to boardagent_server
  with check (
    question_decision_links.organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(question_decision_links.board_id)
    and question_decision_links.selected_by = boardagent_context_uuid('boardagent.member_id')
    and boardagent_vote_actor_ready(question_decision_links.board_id)
    and exists (
      select 1
        from decision_packages as package
        join votes as vote on vote.id = package.vote_id
        join consent_records as consent
          on consent.id = question_decision_links.consent_record_id
       where package.id = question_decision_links.decision_package_id
         and package.organization_id = question_decision_links.organization_id
         and package.board_id = question_decision_links.board_id
         and package.version = question_decision_links.decision_package_version
         and package.package_sha256 = question_decision_links.decision_package_sha256
         and consent.organization_id = question_decision_links.organization_id
         and consent.board_id = question_decision_links.board_id
         and consent.actor_member_id = question_decision_links.selected_by
         and consent.client_id = boardagent_context_uuid('boardagent.client_id')
         and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and consent.target_type = 'vote'
         and consent.package_sha256 = package.package_sha256
         and (
           (consent.action_code = 'create_vote' and consent.target_id = vote.id)
           or (
             consent.action_code in (
               'replace_open_vote', 'amend_resolution_text', 'extend_vote_deadline'
             )
             and exists (
               select 1
                 from vote_supersessions as supersession
                where supersession.old_vote_id = consent.target_id
                  and supersession.new_vote_id = vote.id
                  and supersession.consent_record_id = consent.id
                  and supersession.new_package_sha256 = package.package_sha256
             )
           )
         )
    )
  );
