-- Organization administration may prepare its own exact confirmation evidence on a
-- board where the administrator has no seat. This grants no board/business reads.
-- Business mutations still consume verified consent in their existing finalizers.
create function public.boardagent_owned_administrative_stage(
  candidate_org uuid,candidate_board uuid,candidate_actor uuid,candidate_client uuid,
  candidate_token uuid,candidate_action text
) returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
as $$
  select current_setting('boardagent.transaction_scope',true)='request'
    and candidate_org=public.boardagent_context_uuid('boardagent.organization_id')
    and candidate_actor=public.boardagent_context_uuid('boardagent.member_id')
    and candidate_client=public.boardagent_context_uuid('boardagent.client_id')
    and candidate_token=public.boardagent_context_uuid('boardagent.token_jti')
    and candidate_action in ('manage_member','manage_member_admin_delegation',
      'update_board','archive_board','configure_board_governance','manage_ruleset')
    and exists(select 1 from public.boards b where b.id=candidate_board
      and b.organization_id=candidate_org)
    and exists(select 1 from public.boardagent_resolve_access_token(candidate_token) t
      where t.organization_id=candidate_org and t.member_id=candidate_actor
        and t.internal_client_id=candidate_client
        and 'admin'=any(t.roles) and 'secretariat:admin'=any(t.scope_set))
    and public.boardagent_administrative_member_eligible(candidate_actor)
$$;
alter function public.boardagent_owned_administrative_stage(uuid,uuid,uuid,uuid,uuid,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_owned_administrative_stage(uuid,uuid,uuid,uuid,uuid,text) from public;
grant execute on function public.boardagent_owned_administrative_stage(uuid,uuid,uuid,uuid,uuid,text)
  to boardagent_server;

create policy boardagent_server_own_admin_stage_read on public.action_stages for select to boardagent_server
  using(public.boardagent_owned_administrative_stage(organization_id,board_id,actor_member_id,client_id,token_jti,action_code));
create policy boardagent_server_own_admin_stage_insert on public.action_stages for insert to boardagent_server
  with check(public.boardagent_owned_administrative_stage(organization_id,board_id,actor_member_id,client_id,token_jti,action_code));
create policy boardagent_server_own_admin_stage_update on public.action_stages for update to boardagent_server
  using(public.boardagent_owned_administrative_stage(organization_id,board_id,actor_member_id,client_id,token_jti,action_code))
  with check(public.boardagent_owned_administrative_stage(organization_id,board_id,actor_member_id,client_id,token_jti,action_code));
create policy boardagent_server_own_admin_consent_read on public.consent_records for select to boardagent_server
  using(public.boardagent_owned_administrative_stage(organization_id,board_id,actor_member_id,client_id,token_jti,action_code));

-- Only evidence tied to this administrator's permitted stage/attempt/consent can
-- cross the board boundary. There is deliberately no audit SELECT policy here.
create function public.boardagent_owned_administrative_audit(
  candidate_org uuid,candidate_board uuid,candidate_actor uuid,candidate_client uuid,
  candidate_token uuid,candidate_event text,candidate_type text,candidate_id uuid,candidate_consent uuid
) returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
as $$
  select exists(select 1 from public.action_stages s
    where s.organization_id=candidate_org and s.board_id=candidate_board
      and s.actor_member_id=candidate_actor and s.client_id=candidate_client and s.token_jti=candidate_token
      and public.boardagent_owned_administrative_stage(s.organization_id,s.board_id,s.actor_member_id,s.client_id,s.token_jti,s.action_code)
      and (
        (candidate_event in ('stage_created','stage_replaced','consent_rejected')
          and candidate_type='action_stage' and candidate_id=s.id and candidate_consent is null)
        or (candidate_event='elicitation_sent' and candidate_type='input_required_attempt' and candidate_consent is null
          and exists(select 1 from public.input_required_attempts a where a.stage_id=s.id and a.id=candidate_id))
        or exists(select 1 from public.consent_records c where c.stage_id=s.id and c.id=candidate_consent
          and c.organization_id=s.organization_id and c.board_id=s.board_id
          and c.actor_member_id=s.actor_member_id and c.client_id=s.client_id and c.token_jti=s.token_jti
          and ((candidate_event='consent_recorded' and candidate_type='consent_record' and candidate_id=c.id)
            or (candidate_type=s.target_type and candidate_id=s.target_id and candidate_event=case s.action_code
              when 'manage_member' then 'member_changed'
              when 'update_board' then 'board_amended'
              when 'archive_board' then 'board_archived'
              when 'configure_board_governance' then 'governance_profile_activated'
              when 'manage_ruleset' then 'ruleset_amended'
            end)
            or (s.action_code='manage_member_admin_delegation'
              and candidate_type=s.target_type and candidate_id=s.target_id
              and candidate_event in ('member_admin_delegation_granted','member_admin_delegation_revoked'))))
      ))
$$;
alter function public.boardagent_owned_administrative_audit(uuid,uuid,uuid,uuid,uuid,text,text,uuid,uuid)
  owner to boardagent_migrator;
revoke all on function public.boardagent_owned_administrative_audit(uuid,uuid,uuid,uuid,uuid,text,text,uuid,uuid) from public;
grant execute on function public.boardagent_owned_administrative_audit(uuid,uuid,uuid,uuid,uuid,text,text,uuid,uuid)
  to boardagent_server;
create policy boardagent_server_own_admin_audit_insert on public.audit_events for insert to boardagent_server
  with check(public.boardagent_owned_administrative_audit(organization_id,board_id,actor_member_id,client_id,token_jti,event_type,object_type,object_id,consent_record_id));
