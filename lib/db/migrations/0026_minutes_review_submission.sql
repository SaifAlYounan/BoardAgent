-- BoardAgent Phase 1 / group 26: exact published-minutes review submission authority.

grant insert on minutes_review_items to boardagent_server;

create function boardagent_lock_minutes_review_secretaries(
  candidate_organization_id uuid,
  candidate_board_id uuid
)
returns table(member_id uuid, entitlement_generation bigint)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_organization_id
          is distinct from boardagent_context_uuid('boardagent.organization_id')
     or not boardagent_context_board_allowed(candidate_board_id) then
    raise exception 'minutes secretary lock requires the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,membership.entitlement_generation
      from board_memberships as membership
     where membership.organization_id=candidate_organization_id
       and membership.board_id=candidate_board_id
       and membership.is_secretary
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null
            or membership.active_until>transaction_timestamp())
     order by membership.member_id
       for update;
end
$$;
alter function boardagent_lock_minutes_review_secretaries(uuid,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_minutes_review_secretaries(uuid,uuid) from public;
grant execute on function boardagent_lock_minutes_review_secretaries(uuid,uuid)
  to boardagent_server;

create unique index minutes_review_items_idempotency_uq
  on minutes_review_items(idempotency_record_id);
