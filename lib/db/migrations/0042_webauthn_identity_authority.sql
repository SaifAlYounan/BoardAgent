-- BoardAgent Phase 1 / group 42: exact browser WebAuthn identity authority.
-- Challenge issuance/consumption and credential counter advancement are not MCP request
-- mutations. Keep them inside the separately managed identity transaction scope.

grant insert on public.webauthn_challenges,public.webauthn_credentials
  to boardagent_server;
grant update(consumed_at) on public.webauthn_challenges
  to boardagent_server;
grant update(signature_counter,backup_state,last_used_at) on public.webauthn_credentials
  to boardagent_server;
grant execute on function public.boardagent_constant_time_sha256_equal(bytea,bytea)
  to boardagent_server;

drop policy boardagent_server_scope on public.webauthn_challenges;
create policy boardagent_server_identity_webauthn_challenges
  on public.webauthn_challenges
  for all to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

drop policy boardagent_server_scope on public.webauthn_credentials;
create policy boardagent_server_identity_webauthn_credentials
  on public.webauthn_credentials
  for all to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
