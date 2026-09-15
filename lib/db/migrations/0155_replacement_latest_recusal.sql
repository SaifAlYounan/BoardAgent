-- A lifted vote recusal appends a new immutable state. Replacement eligibility
-- follows that latest state, while prior ballots/proxies/stages remain disposed.
-- Preserve the final board-recusal, actor, membership, chair and lock checks.
CREATE OR REPLACE FUNCTION public.boardagent_lock_replacement_electorate(candidate_old_vote uuid)
 RETURNS TABLE(member_id uuid, membership_id uuid, membership_version_id uuid, membership_version integer, is_chair boolean, voting_weight bigint, authority_snapshot jsonb, authority_snapshot_sha256 bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement electorate requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.id,
           version.id,
           version.version,
           membership.is_chair,
           membership.voting_weight,
           version.authority_snapshot,
           version.snapshot_sha256
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join lateral (
        select candidate.id,
               candidate.version,
               candidate.seat_role,
               candidate.is_chair,
               candidate.voting_weight,
               candidate.authority_snapshot,
               candidate.snapshot_sha256
          from membership_versions as candidate
         where candidate.membership_id = membership.id
         order by candidate.version desc, candidate.id desc
         limit 1
      ) as version on true
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state in ('open', 'source_update_pending')
       and boardagent_vote_actor_ready(vote.board_id)
       and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role = 'voting_member'
       and version.seat_role = membership.seat_role
       and version.is_chair = membership.is_chair
       and version.voting_weight = membership.voting_weight
       and not boardagent_vote_member_excluded(vote.id, membership.member_id)
     order by membership.member_id
     for update of membership
     for share of version;
end
$function$
;

alter function public.boardagent_lock_replacement_electorate(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_lock_replacement_electorate(uuid) from public;
grant execute on function public.boardagent_lock_replacement_electorate(uuid) to boardagent_server;
