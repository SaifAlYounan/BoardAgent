-- Every runtime consent must be issued through the shared protected-response verifier.
-- Business authorization remains with each existing current-state/finalizer transaction.
-- Raw database INSERT can no longer manufacture a successful confirmation record.
revoke insert on public.consent_records from boardagent_server;

grant select,insert on public.consent_records to boardagent_migrator;
create policy boardagent_migrator_verified_consent_insert
  on public.consent_records for insert to boardagent_migrator with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and token_jti=public.boardagent_context_uuid('boardagent.token_jti')
    and confirmed_at=transaction_timestamp()
  );
-- FOR UPDATE requires an UPDATE privilege and matching policy. This helper only
-- locks these rows; their existing immutability/state guards remain in force.
grant select on public.action_stages,public.input_required_attempts to boardagent_migrator;
grant update(state) on public.action_stages,public.input_required_attempts to boardagent_migrator;
create policy boardagent_migrator_verified_stage_lock
  on public.action_stages for update to boardagent_migrator using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and token_jti=public.boardagent_context_uuid('boardagent.token_jti')
  ) with check (false);
create policy boardagent_migrator_verified_attempt_read
  on public.input_required_attempts for select to boardagent_migrator using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_verified_attempt_lock
  on public.input_required_attempts for update to boardagent_migrator using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ) with check (false);

create function public.boardagent_record_confirmed_consent(
  candidate_stage_id uuid,candidate_consent_id uuid,candidate_retry_request_id bytea,
  candidate_arguments bytea,candidate_capabilities bytea,candidate_request_state bytea,
  candidate_response bytea,candidate_record bytea
) returns void language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  client uuid := public.boardagent_context_uuid('boardagent.client_id');
  token uuid := public.boardagent_context_uuid('boardagent.token_jti');
  stage public.action_stages%rowtype;
  attempt public.input_required_attempts%rowtype;
  request jsonb;
  response jsonb;
  code text;
  snapshot jsonb;
  payload jsonb;
  protected_record jsonb;
  protected_record_sha bytea;
  expected_record jsonb;
  expected_record_bytes bytea;
  expected_response_bytes bytea;
begin
  if (current_setting('boardagent.transaction_scope',true)='request'
    and org is not null and actor is not null and client is not null and token is not null
    and public.boardagent_is_uuid_v7(candidate_stage_id)
    and public.boardagent_is_uuid_v7(candidate_consent_id)
    and octet_length(candidate_retry_request_id) between 1 and 1024
    and octet_length(candidate_arguments) between 2 and 10485760
    and octet_length(candidate_capabilities) between 2 and 10485760
    and octet_length(candidate_request_state) between 32 and 4096
    and octet_length(candidate_response) between 2 and 512
    and octet_length(candidate_record) between 2 and 8192) is distinct from true then
    raise exception 'confirmation is unavailable' using errcode='42501';
  end if;
  select s.* into stage from public.action_stages s where s.id=candidate_stage_id
    and s.organization_id=org and s.actor_member_id=actor and s.client_id=client and s.token_jti=token;
  if stage.id is null then
    raise exception 'confirmation is unavailable' using errcode='42501';
  end if;
  request := convert_from(candidate_arguments,'UTF8')::jsonb;
  response := convert_from(candidate_response,'UTF8')::jsonb;
  code := response->'content'->>'confirmation_code';
  if (code is not null and length(code)+(select count(*) from unnest(string_to_array(code,null)) c where ascii(c)>65535)=8
    and response=jsonb_build_object('action','accept',
    'content',jsonb_build_object('approve',true,'confirmation_code',code))) is distinct from true then
    raise exception 'confirmation is unavailable' using errcode='42501';
  end if;
  expected_response_bytes := convert_to('{"action":"accept","content":{"approve":true,"confirmation_code":'||to_json(code)::text||'}}','UTF8');
  if candidate_response<>expected_response_bytes then
    raise exception 'confirmation is unavailable' using errcode='42501';
  end if;
  -- Administrative actions retain their SQL current-state check and established
  -- org -> sorted member -> stage/attempt lock order. Other actions already enter
  -- here after their own aggregate locks; this shared verifier adds no new org lock.
  if stage.action_code in ('manage_company_admin','manage_member_admin_delegation') then
    snapshot := case when stage.action_code='manage_company_admin'
      then public.boardagent_company_admin_snapshot(request)
      else public.boardagent_member_admin_delegation_snapshot(request) end;
    payload := jsonb_build_object('schemaVersion','boardagent.administrative-authority.v1',
      'tool',stage.action_code,'request',request,'snapshot',snapshot);
    if (stage.acting_for_member_id is null and stage.package_sha256 is null
      and stage.canonical_schema='boardagent.administrative-authority.v1'
      and stage.target_type=snapshot->>'recordType' and stage.target_id=(snapshot->>'recordId')::uuid
      and stage.board_id is not distinct from (snapshot->>'boardId')::uuid
      and convert_from(stage.canonical_payload,'UTF8')::jsonb=payload) is distinct from true then
      raise exception 'confirmation is unavailable' using errcode='42501';
    end if;
  end if;
  select s.* into stage from public.action_stages s where s.id=candidate_stage_id for update;
  select a.* into strict attempt from public.input_required_attempts a where a.stage_id=stage.id for update;
  if (stage.organization_id=org and stage.actor_member_id=actor and stage.client_id=client and stage.token_jti=token
    and stage.state='active' and stage.created_at<=transaction_timestamp() and stage.expires_at>transaction_timestamp()
    and stage.context_sha256=decode(current_setting('boardagent.context_sha256',true),'hex')
    and stage.payload_sha256=pg_catalog.sha256(stage.canonical_payload)
    and stage.protected_code_sha256=pg_catalog.sha256(convert_to(code,'UTF8'))
    and attempt.organization_id=org and attempt.state='prepared'
    and attempt.original_name=stage.action_code and attempt.original_method='tools/call'
    and attempt.protocol_version='2026-07-28' and attempt.protocol_header_version='2026-07-28'
    and attempt.result_meta_version='boardagent.mrtr.v1'
    and attempt.prepared_request_id<>candidate_retry_request_id
    and attempt.original_arguments_sha256=pg_catalog.sha256(candidate_arguments)
    and attempt.capabilities_sha256=pg_catalog.sha256(candidate_capabilities)
    and attempt.request_state_bytes=candidate_request_state
    and attempt.request_state_sha256=pg_catalog.sha256(candidate_request_state)
    and attempt.retry_request_id is null and attempt.input_response_sha256 is null
    and attempt.response_action is null and attempt.completed_at is null
    and exists(select 1 from public.access_token_records t
      join public.oauth_clients c on c.id=t.client_id
      join public.system_instance i on i.organization_id=t.organization_id
      where t.id=stage.access_token_record_id
      and t.organization_id=org and t.member_id=actor and t.client_id=client and t.jti=token
      and t.revoked_at is null and t.expires_at>transaction_timestamp()
      and c.state='active' and i.canonical_resource_uri=t.resource_uri)
    and not exists(select 1 from public.consent_records c where c.stage_id=stage.id)) is distinct from true then
    raise exception 'confirmation is unavailable' using errcode='42501';
  end if;
  protected_record := jsonb_build_object('schemaVersion','boardagent.protected-code-record.v1',
    'stageId',stage.id,'protectedCodeSha256',encode(stage.protected_code_sha256,'hex'));
  -- These two fixed-schema records contain only strings/nulls (no arrays, nested
  -- objects or numbers). Ordered scalar serialization verifies the existing RFC8785
  -- bytes without introducing a general SQL canonicalization implementation.
  select pg_catalog.sha256(convert_to('{'||string_agg(to_json(e.key)::text||':'||e.value::text,',' order by e.key collate "C")||'}','UTF8'))
    into protected_record_sha from jsonb_each(protected_record) e;
  expected_record := jsonb_build_object(
    'schemaVersion','boardagent.consent-record.v1','id',candidate_consent_id,
    'stageId',stage.id,'inputRequiredAttemptId',attempt.id,'actorMemberId',actor,
    'actingForMemberId',stage.acting_for_member_id,'actionCode',stage.action_code,'targetType',stage.target_type,
    'targetId',stage.target_id,'payloadSha256',encode(stage.payload_sha256,'hex'),
    'packageSha256',encode(stage.package_sha256,'hex'),'protectedCodeRecordSha256',encode(protected_record_sha,'hex'),
    'accessTokenRecordId',stage.access_token_record_id,'tokenJti',token,'clientId',client,
    'exactOrigin',stage.exact_origin,
    'stagedAt',to_char(stage.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'confirmedAt',to_char(transaction_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'inputResponseSha256',encode(pg_catalog.sha256(candidate_response),'hex'));
  select convert_to('{'||string_agg(to_json(e.key)::text||':'||e.value::text,',' order by e.key collate "C")||'}','UTF8')
    into expected_record_bytes from jsonb_each(expected_record) e;
  if candidate_record<>expected_record_bytes then
    raise exception 'confirmation is unavailable' using errcode='42501';
  end if;
  insert into public.consent_records(
    id,organization_id,board_id,stage_id,input_required_attempt_id,actor_member_id,
    acting_for_member_id,action_code,target_type,target_id,canonical_schema,payload_sha256,
    package_sha256,protected_code_record_sha256,access_token_record_id,token_jti,client_id,
    exact_origin,staged_at,confirmed_at,record_sha256)
  values(candidate_consent_id,org,stage.board_id,stage.id,attempt.id,actor,stage.acting_for_member_id,
    stage.action_code,stage.target_type,stage.target_id,'boardagent.consent-record.v1',stage.payload_sha256,
    stage.package_sha256,protected_record_sha,stage.access_token_record_id,token,client,stage.exact_origin,
    stage.created_at,transaction_timestamp(),pg_catalog.sha256(candidate_record));
exception when no_data_found or too_many_rows or invalid_text_representation or character_not_in_repertoire then
  raise exception 'confirmation is unavailable' using errcode='42501';
end
$$;
alter function public.boardagent_record_confirmed_consent(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_record_confirmed_consent(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea) from public;
grant execute on function public.boardagent_record_confirmed_consent(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea) to boardagent_server;
