-- Evaluate search visibility as a statement-local set, preserving SQL0013 read predicates.
-- The current identity/token/onboarding/seat is checked for each ready board; document
-- state, creator/ACL and deny-wins exclusions are checked for every returned document.
-- No session cache, authority record, LEAKPROOF declaration or RLS bypass is introduced.
-- Documents and version metadata retain their independent existing read policies.
create function public.boardagent_search_readable_document_ids()
returns setof uuid
language sql stable security definer
set search_path=pg_catalog,public,pg_temp
as $function$
  with actor_context as materialized (
    select boardagent_context_uuid('boardagent.organization_id') as organization_id,
           boardagent_context_uuid('boardagent.member_id') as member_id
  ), ready_boards as materialized (
    select membership.organization_id,membership.board_id,membership.seat_role
      from board_memberships as membership cross join actor_context as actor
     where membership.organization_id=actor.organization_id
       and membership.member_id=actor.member_id
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
       and boardagent_actor_ready_for_board(membership.board_id,'documents:read')
  )
  select document.id
    from documents as document
    join ready_boards as membership
      on membership.organization_id=document.organization_id and membership.board_id=document.board_id
    cross join actor_context as actor
   where document.organization_id=actor.organization_id
     and document.state in ('active','archived')
     and (document.created_by=actor.member_id or exists (
       select 1 from document_access_grants as access_grant
        where access_grant.document_id=document.id
          and access_grant.organization_id=document.organization_id
          and access_grant.board_id=document.board_id
          and access_grant.active_from<=transaction_timestamp()
          and (access_grant.active_until is null or access_grant.active_until>transaction_timestamp())
          and (access_grant.grantee_member_id=actor.member_id or access_grant.grantee_seat_role=membership.seat_role)
          and access_grant.permission in ('read','contribute','circulate')
     ))
     and not exists (
       select 1 from document_exclusions as exclusion
        where exclusion.document_id=document.id
          and exclusion.organization_id=document.organization_id
          and exclusion.board_id=document.board_id
          and exclusion.member_id=actor.member_id
          and exclusion.active_from<=transaction_timestamp()
          and (exclusion.active_until is null or exclusion.active_until>transaction_timestamp())
     )
$function$;
alter function public.boardagent_search_readable_document_ids() owner to boardagent_migrator;
revoke all on function public.boardagent_search_readable_document_ids() from public;
grant execute on function public.boardagent_search_readable_document_ids() to boardagent_server;
alter policy boardagent_server_document_search_select on public.document_search
  using (document_id in (select public.boardagent_search_readable_document_ids()));
