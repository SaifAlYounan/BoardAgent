-- A completed worker artifact is readable only through its live requesting principal.
-- These SELECT policies add no server write authority and preserve parent scope RLS.
create policy boardagent_server_own_export_artifact
  on public.export_artifacts for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1 from public.export_requests as request
      cross join public.boardagent_resolve_access_token(
        public.boardagent_context_uuid('boardagent.token_jti')
      ) as actor
      where request.id=export_artifacts.export_request_id
        and request.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
        and request.requester_member_id=public.boardagent_context_uuid('boardagent.member_id')
        and actor.organization_id=request.organization_id
        and actor.member_id=request.requester_member_id
        and actor.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
        and (request.board_id is null or request.board_id::text=any(actor.board_ids))
        and case request.export_type
          when 'system_data' then
            'secretariat:admin'=any(actor.scope_set) and 'admin'=any(actor.roles)
            and not ('observer'=any(actor.roles))
          when 'audit_chain' then
            'audit:read'=any(actor.scope_set) and (
              (request.board_id is null and actor.roles && array['admin','secretariat'])
              or exists (
                select 1 from public.board_memberships as membership
                 where membership.organization_id=request.organization_id
                   and membership.board_id=request.board_id
                   and membership.member_id=actor.member_id
                   and membership.seat_role<>'observer' and membership.state='active'
                   and membership.active_from<=transaction_timestamp()
                   and (membership.active_until is null
                        or membership.active_until>transaction_timestamp())
              )
            )
          else false
        end
    )
  );

-- Retained artifact metadata remains available after cleanup. Bytes require the
-- still-ready, unexpired artifact and request, plus actual recent authentication.
create policy boardagent_server_own_ready_export_chunk
  on public.export_chunks for select to boardagent_server
  using (
    exists (
      select 1 from public.export_artifacts as artifact
      join public.export_requests as request on request.id=artifact.export_request_id
       where artifact.id=export_chunks.artifact_id
         and artifact.state='ready' and artifact.expires_at>transaction_timestamp()
         and request.state='succeeded' and request.expires_at>transaction_timestamp()
    )
    and exists (select 1 from public.boardagent_recent_auth_context())
  );
