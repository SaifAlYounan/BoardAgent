-- BoardAgent Phase 2: narrowly extend the sole preidentity bootstrap scope through
-- activation of its exact first admin-secretary. This grants no HTTP/MCP role access.

grant select on public.webauthn_credentials,public.enrollment_activation_challenges,
  public.pending_action_feed to boardagent_migrator;
grant insert on public.pending_action_feed to boardagent_migrator;
grant update(state,row_version) on public.members to boardagent_migrator;
grant update(id) on public.enrollment_invitations to boardagent_migrator;
grant update(state,attempt_count,consumed_at,confirmed_by)
  on public.enrollment_activation_challenges to boardagent_migrator;

create policy boardagent_migrator_bootstrap
  on public.webauthn_credentials for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_migrator_bootstrap
  on public.enrollment_activation_challenges for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='bootstrap')
  with check (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_migrator_bootstrap
  on public.pending_action_feed for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='bootstrap')
  with check (current_setting('boardagent.transaction_scope',true)='bootstrap');
