-- Current personal read authority is separate from the frozen exclusion evidence
-- used to recompute an outcome. Board causes stop cascading when a vote closes.
create function public.boardagent_member_vote_recused(candidate_vote uuid,candidate_member uuid)
returns boolean language sql stable security definer
set search_path=pg_catalog,public,pg_temp as $$
  select coalesce((select
    public.boardagent_member_board_recused(vote.board_id,candidate_member)
    or coalesce((select coalesce(exclusion.cause_requested_state,exclusion.state)='excluded'
      from public.vote_exclusions exclusion
      where exclusion.organization_id=vote.organization_id
        and exclusion.vote_id=vote.id and exclusion.member_id=candidate_member
        and exclusion.source_board_exclusion_id is null
      order by exclusion.version desc limit 1),false)
    from public.votes vote
    where vote.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and vote.id=candidate_vote),false)
$$;
alter function public.boardagent_member_vote_recused(uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_member_vote_recused(uuid,uuid) from public;
grant execute on function public.boardagent_member_vote_recused(uuid,uuid) to boardagent_server;
