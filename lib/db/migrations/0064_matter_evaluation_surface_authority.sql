-- BoardAgent Phase 4: resolve the caller-bound matter type without granting the
-- request role unrestricted ruleset-table visibility.

create function boardagent_resolve_matter_type_code(
  candidate_board uuid,
  candidate_matter_type uuid,
  candidate_profile uuid,
  candidate_ruleset uuid
)
returns text
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select matter_type.code
    from boards as board
    join governance_profiles as profile
      on profile.id=board.current_governance_profile_id
     and profile.board_id=board.id
    join rulesets as ruleset
      on ruleset.id=board.current_ruleset_id
     and ruleset.board_id=board.id
     and ruleset.profile_id=profile.id
    join matter_types as matter_type on matter_type.ruleset_id=ruleset.id
   where current_setting('boardagent.transaction_scope', true)='request'
     and board.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and board.id=candidate_board
     and board.state='active'
     and profile.id=candidate_profile
     and profile.state='active'
     and ruleset.id=candidate_ruleset
     and ruleset.state='active'
     and matter_type.id=candidate_matter_type
     and boardagent_vote_actor_ready(board.id)
$$;

alter function boardagent_resolve_matter_type_code(uuid,uuid,uuid,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_resolve_matter_type_code(uuid,uuid,uuid,uuid) from public;
grant execute on function boardagent_resolve_matter_type_code(uuid,uuid,uuid,uuid)
  to boardagent_server;
