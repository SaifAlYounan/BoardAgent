-- The final vote preparation step has no organization/board columns of its own.
-- Resolve authority through its draft; the generic organization RLS policy never
-- covered this child table. This grants no step update/delete or broader read access.
create policy boardagent_server_vote_wizard_step_insert
  on public.wizard_steps for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and ordinal=0 and attempt=1 and question_code='final_package'
    and value_schema='boardagent.vote-wizard-final-review.v1'
    and exists (
      select 1 from public.wizard_drafts as draft
        join public.boards as board on board.id=draft.board_id
          and board.organization_id=draft.organization_id
       where draft.id=wizard_steps.draft_id
         and draft.organization_id=boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(draft.board_id)
         and draft.creator_member_id=boardagent_context_uuid('boardagent.member_id')
         and draft.draft_type='vote' and draft.state='ready_to_confirm'
         and draft.expires_at>transaction_timestamp() and board.state='active'
         and boardagent_vote_actor_ready(draft.board_id)
    )
  );
