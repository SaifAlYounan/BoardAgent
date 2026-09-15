-- The governance catalogs have no organization_id/board_id columns, so the
-- original root-table RLS generator correctly gave them no implicit access.
-- Their supported list tools need SELECT through the scoped parent, with the
-- existing live board-member/token/onboarding predicate. No write policy is added.

create policy boardagent_server_governance_template_read
  on public.governance_rule_templates for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1 from public.governance_profiles as profile
       where profile.id=governance_rule_templates.profile_id
         and profile.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
         and public.boardagent_meeting_actor_ready(profile.board_id,'governance:read')
    )
  );

create policy boardagent_server_governance_matter_type_read
  on public.matter_types for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1 from public.rulesets as ruleset
       where ruleset.id=matter_types.ruleset_id
         and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
         and public.boardagent_meeting_actor_ready(ruleset.board_id,'governance:read')
    )
  );
