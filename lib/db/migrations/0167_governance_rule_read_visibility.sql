-- Rules have no organization_id/board_id columns and received no implicit
-- server policy from the original root-table RLS generator. Match the existing
-- matter-type SELECT authority through the same scoped ruleset parent and live
-- governance reader predicate. No write policy, grant or definer change is added.

create policy boardagent_server_governance_rule_read
  on public.ruleset_rules for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1 from public.rulesets as ruleset
       where ruleset.id=ruleset_rules.ruleset_id
         and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
         and public.boardagent_meeting_actor_ready(ruleset.board_id,'governance:read')
    )
  );
