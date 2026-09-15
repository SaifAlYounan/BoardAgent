-- Return only current permission to retrieve an exact completed communication result.
-- In particular, a proposer may withdraw/retry without gaining proposal SELECT access.
create function public.boardagent_communication_replay_authorized(
  candidate_id uuid,candidate_operation text
)
returns boolean
language sql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
  select current_setting('boardagent.transaction_scope',true)='request' and case
    when candidate_operation in ('withdraw_proposal','approve_proposal','reject_proposal') then
      exists (select 1 from public.proposals as proposal
        where proposal.id=candidate_id
          and proposal.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
          and case candidate_operation
            when 'withdraw_proposal' then
              proposal.proposer_member_id=public.boardagent_context_uuid('boardagent.member_id')
              and public.boardagent_proposer_for_board(proposal.board_id)
            else public.boardagent_secretariat_for_board(proposal.board_id)
          end)
    when candidate_operation in ('reply_secretariat_request','close_secretariat_request') then
      exists (select 1 from public.secretariat_requests as request
        where request.id=candidate_id
          and request.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
          and (public.boardagent_secretariat_for_board(request.board_id)
            or (candidate_operation='close_secretariat_request'
              and request.requester_member_id=public.boardagent_context_uuid('boardagent.member_id')
              and public.boardagent_communication_actor_ready(request.board_id,'secretariat:message'))))
    else false end
$$;
alter function public.boardagent_communication_replay_authorized(uuid,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_communication_replay_authorized(uuid,text) from public;
grant execute on function public.boardagent_communication_replay_authorized(uuid,text)
  to boardagent_server;
