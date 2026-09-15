-- BoardAgent Phase 4: creator-only, non-destructive wizard draft cancellation.

create function boardagent_lock_owned_wizard_draft_for_cancel(candidate_draft uuid)
returns table(
  organization_id uuid,
  board_id uuid,
  draft_state text,
  draft_row_version bigint
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'draft cancellation requires a managed request transaction'
      using errcode='25000';
  end if;
  return query
    select draft.organization_id,draft.board_id,draft.state,draft.row_version
      from wizard_drafts as draft
     where draft.id=candidate_draft
       and draft.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and draft.creator_member_id=boardagent_context_uuid('boardagent.member_id')
       and boardagent_context_board_allowed(draft.board_id)
       and draft.state in ('active','ready_to_confirm')
       and draft.expires_at>transaction_timestamp()
     for update of draft;
end
$$;

alter function boardagent_lock_owned_wizard_draft_for_cancel(uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_owned_wizard_draft_for_cancel(uuid) from public;
grant execute on function boardagent_lock_owned_wizard_draft_for_cancel(uuid)
  to boardagent_server;
