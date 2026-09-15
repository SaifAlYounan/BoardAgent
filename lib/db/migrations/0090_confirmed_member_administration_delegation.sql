create policy boardagent_migrator_delegation_idempotency on public.idempotency_records
  for insert to boardagent_migrator with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='manage_member_admin_delegation'
  );

create function public.boardagent_guard_member_admin_delegation()
returns trigger language plpgsql security invoker set search_path=pg_catalog,public
as $$
begin
  if current_user<>'boardagent_migrator' or current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or old.state<>'active' or new.state<>'revoked' or new.row_version<>old.row_version+1
    or row(new.id,new.organization_id,new.board_id,new.member_id,new.issuer_member_id,new.secretary_membership_id,
      new.secretary_membership_version,new.reason,new.authority_evidence,new.created_at,new.expires_at,new.creation_consent_id,new.creation_audit_id)
      is distinct from row(old.id,old.organization_id,old.board_id,old.member_id,old.issuer_member_id,old.secretary_membership_id,
      old.secretary_membership_version,old.reason,old.authority_evidence,old.created_at,old.expires_at,old.creation_consent_id,old.creation_audit_id) then
    raise exception 'administrative delegation history is immutable' using errcode='23514';
  end if;
  return new;
end
$$;
revoke all on function public.boardagent_guard_member_admin_delegation() from public;
create trigger boardagent_member_admin_delegation_transition before update on public.member_admin_delegations
  for each row execute function public.boardagent_guard_member_admin_delegation();

create function public.boardagent_finalize_member_admin_delegation(
  candidate_request jsonb,candidate_payload_sha256 bytea,candidate_consent_id uuid,candidate_audit_id uuid,
  candidate_change_id uuid,candidate_idempotency_id uuid,candidate_request_sha256 bytea
)
returns void language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  action text := candidate_request->'change'->>'operation';
  snapshot jsonb; payload jsonb; record_id uuid; selected_board uuid; affected_id uuid; effect jsonb;
  consent public.consent_records%rowtype; stage public.action_stages%rowtype;
begin
  snapshot := public.boardagent_member_admin_delegation_snapshot(candidate_request);
  record_id := (snapshot->>'recordId')::uuid; selected_board := (snapshot->>'boardId')::uuid;
  affected_id := (snapshot->>'targetMemberId')::uuid;
  payload := jsonb_build_object('schemaVersion','boardagent.administrative-authority.v1','tool','manage_member_admin_delegation',
    'request',candidate_request,'snapshot',snapshot);
  select c.* into consent from public.consent_records c where c.id=candidate_consent_id and c.organization_id=org and c.actor_member_id=actor
    and c.client_id=public.boardagent_context_uuid('boardagent.client_id') and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
    and c.board_id=selected_board and c.action_code='manage_member_admin_delegation' and c.target_type='member_admin_delegation'
    and c.target_id=record_id and c.payload_sha256=candidate_payload_sha256 and c.confirmed_at=transaction_timestamp();
  select s.* into stage from public.action_stages s where s.id=consent.stage_id and s.organization_id=org
    and s.state='active' and s.payload_sha256=candidate_payload_sha256;
  if consent.id is null or stage.id is null or pg_catalog.sha256(stage.canonical_payload)<>candidate_payload_sha256
    or convert_from(stage.canonical_payload,'UTF8')::jsonb<>payload then
    raise exception 'delegation requires exact fresh unchanged consent' using errcode='42501';
  end if;
  if not exists(select 1 from public.audit_events a where a.id=candidate_audit_id and a.organization_id=org
    and a.actor_member_id=actor and a.consent_record_id=candidate_consent_id and a.event_type=snapshot->>'eventType'
    and a.object_type='member_admin_delegation' and a.object_id=record_id and a.board_id=selected_board
    and a.client_id=consent.client_id and a.token_jti=consent.token_jti and a.object_version=(snapshot->>'recordVersion')::bigint
    and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'=jsonb_build_object('operation',action,
      'administrativeRecordId',record_id,'payloadSha256',encode(candidate_payload_sha256,'hex'),
      'before',snapshot->'before','after',snapshot->'after','affectedMemberIds',snapshot->'affectedMemberIds','memberChanges',snapshot->'memberChanges')) then
    raise exception 'delegation requires its appended audit' using errcode='42501';
  end if;
  if not exists(select 1 from public.input_required_attempts a where a.id=consent.input_required_attempt_id
    and a.stage_id=stage.id and a.original_arguments_sha256=candidate_request_sha256)
    or not public.boardagent_is_uuid_v7(candidate_change_id) or not public.boardagent_is_uuid_v7(candidate_idempotency_id) then
    raise exception 'delegation request binding is invalid' using errcode='42501';
  end if;
  insert into public.idempotency_records(id,organization_id,actor_member_id,client_id,operation,idempotency_key,
    request_sha256,state,expires_at,completed_at,safe_response_type,safe_response_id,safe_response_sha256)
    values(candidate_idempotency_id,org,actor,consent.client_id,'manage_member_admin_delegation',candidate_request->>'idempotency_key',
      candidate_request_sha256,'succeeded',transaction_timestamp()+interval '24 hours',transaction_timestamp(),
      'member_admin_delegation',record_id,candidate_payload_sha256);
  insert into public.administrative_authority_changes(id,organization_id,board_id,record_type,record_id,record_version,
    actor_member_id,action_code,operation,consent_record_id,audit_event_id,canonical_payload,payload_sha256)
    values(candidate_change_id,org,selected_board,'member_admin_delegation',record_id,(snapshot->>'recordVersion')::bigint,
      actor,'manage_member_admin_delegation',action,candidate_consent_id,candidate_audit_id,stage.canonical_payload,candidate_payload_sha256);
  if action='grant' then
    insert into public.member_admin_delegations(id,organization_id,board_id,member_id,issuer_member_id,secretary_membership_id,
      secretary_membership_version,reason,authority_evidence,expires_at,creation_consent_id,creation_audit_id)
      values(record_id,org,selected_board,affected_id,actor,(snapshot->'after'->>'secretaryMembershipId')::uuid,
        (snapshot->'after'->>'secretaryMembershipVersion')::integer,candidate_request->'change'->>'reason',
        snapshot->'after'->'authorityEvidence',(snapshot->'after'->>'expiresAt')::timestamptz,candidate_consent_id,candidate_audit_id);
  else
    update public.member_admin_delegations set state='revoked',row_version=2,revoked_at=transaction_timestamp(),
      revocation_consent_id=candidate_consent_id,revocation_audit_id=candidate_audit_id
      where organization_id=org and id=record_id;
  end if;
  effect := snapshot->'memberChanges'->0;
  update public.members set identity_generation=(effect->>'afterIdentityGeneration')::bigint,
    row_version=(effect->>'afterRowVersion')::bigint where organization_id=org and id=affected_id;
  update public.auth_sessions set state='revoked' where organization_id=org and member_id=affected_id and state in ('anonymous','authenticated','expired');
  update public.refresh_families set state='revoked',revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and state='active';
  update public.access_token_records set revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and revoked_at is null;
  update public.oauth_authorization_codes set revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and consumed_at is null and revoked_at is null;
  update public.enrollment_invitations set revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and consumed_at is null and revoked_at is null;
  update public.action_stages set state='replaced' where organization_id=org and actor_member_id=affected_id and state='active' and id<>stage.id;
end
$$;
alter function public.boardagent_finalize_member_admin_delegation(jsonb,bytea,uuid,uuid,uuid,uuid,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_finalize_member_admin_delegation(jsonb,bytea,uuid,uuid,uuid,uuid,bytea) from public;
grant execute on function public.boardagent_finalize_member_admin_delegation(jsonb,bytea,uuid,uuid,uuid,uuid,bytea) to boardagent_server;
