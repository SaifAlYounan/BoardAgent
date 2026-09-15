-- BoardAgent Phase 4 / group 70: encrypted per-member webhook lifecycle authority.

do $webhook_upgrade_empty$
begin
  if exists (select 1 from public.member_webhooks) then
    raise exception 'legacy member_webhooks rows require an explicit encrypted-secret migration';
  end if;
end
$webhook_upgrade_empty$;

alter table public.member_webhooks
  add column secret_ciphertext bytea not null
    check (octet_length(secret_ciphertext) between 32 and 4096),
  add column event_classes text[] not null
    check (
      event_classes in (
        array['notice']::text[],array['pending_action']::text[],array['security']::text[],
        array['notice','pending_action']::text[],array['notice','security']::text[],
        array['pending_action','security']::text[],
        array['notice','pending_action','security']::text[]
      )
    ),
  add column verified_at timestamptz(6) not null,
  add column updated_at timestamptz(6) not null default transaction_timestamp(),
  add constraint member_webhooks_terminal_projection_ck check (
    (state='active' and disabled_at is null) or (state in ('disabled','revoked') and disabled_at is not null)
  );

alter table public.notification_jobs
  alter column notice_id drop not null,
  add column source_kind text not null default 'notice'
    check (source_kind in ('notice','test')),
  add constraint notification_jobs_source_ck check (
    (source_kind='notice' and notice_id is not null)
    or (source_kind='test' and notice_id is null and wake_class='security')
  );

drop policy boardagent_server_scope on public.member_webhooks;
create policy boardagent_server_member_webhook_scope on public.member_webhooks
  for all to boardagent_server
  using (
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and member_id=public.boardagent_context_uuid('boardagent.member_id')
  )
  with check (
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and member_id=public.boardagent_context_uuid('boardagent.member_id')
  );

grant insert on public.member_webhooks,public.notification_jobs to boardagent_server;
grant update(
  secret_ciphertext,secret_sha256,key_id,state,generation,verified_at,updated_at,disabled_at
) on public.member_webhooks to boardagent_server;

grant select on public.member_webhooks,public.crypto_key_registry,public.auth_sessions,
  public.access_token_records,public.oauth_clients,public.members,public.system_instance,
  public.consent_records to boardagent_migrator;
grant insert,update on public.member_webhooks to boardagent_migrator;
create policy boardagent_migrator_webhook_read on public.member_webhooks
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_webhook_insert on public.member_webhooks
  for insert to boardagent_migrator with check (true);
create policy boardagent_migrator_webhook_update on public.member_webhooks
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_webhook_read on public.crypto_key_registry
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_webhook_read on public.auth_sessions
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_webhook_read on public.oauth_clients
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_webhook_read on public.members
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_webhook_read on public.system_instance
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_webhook_read on public.consent_records
  for select to boardagent_migrator using (true);

create function public.boardagent_guard_member_webhook_update()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if new.id<>old.id or new.organization_id<>old.organization_id or new.member_id<>old.member_id
     or new.endpoint_ciphertext<>old.endpoint_ciphertext
     or new.endpoint_sha256<>old.endpoint_sha256
     or new.ssrf_validation_receipt_sha256<>old.ssrf_validation_receipt_sha256
     or new.event_classes<>old.event_classes or new.created_at<>old.created_at
     or new.generation<>old.generation+1 or new.updated_at is distinct from transaction_timestamp()
     or old.state<>'active' then
    raise exception 'webhook update violates immutable ownership or generation binding'
      using errcode='55000';
  end if;
  if new.state='active' then
    if new.disabled_at is not null or new.secret_ciphertext=old.secret_ciphertext
       or new.secret_sha256=old.secret_sha256 or new.key_id<>old.key_id
       or new.verified_at<>old.verified_at then
      raise exception 'webhook secret rotation has an invalid projection' using errcode='55000';
    end if;
  elsif new.state='disabled' then
    if new.disabled_at is distinct from transaction_timestamp()
       or new.secret_ciphertext<>old.secret_ciphertext or new.secret_sha256<>old.secret_sha256
       or new.key_id<>old.key_id or new.verified_at<>old.verified_at then
      raise exception 'webhook disablement has an invalid projection' using errcode='55000';
    end if;
  else
    raise exception 'unsupported webhook transition' using errcode='55000';
  end if;
  return new;
end
$$;

create trigger boardagent_member_webhook_update_guard
before update on public.member_webhooks
for each row execute function public.boardagent_guard_member_webhook_update();

create function public.boardagent_webhook_snapshot(
  candidate_action text,
  candidate_webhook_id uuid,
  candidate_key_id uuid,
  candidate_exact_origin text
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  context_organization uuid;
  context_member uuid;
  context_client uuid;
  context_token uuid;
  webhook public.member_webhooks%rowtype;
  resolved_key_id uuid;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_action not in ('configure_webhook','rotate_webhook_secret','disable_webhook','test_webhook')
     or candidate_webhook_id is null or not public.boardagent_is_uuid_v7(candidate_webhook_id)
     or candidate_exact_origin !~ '^https://[^/?#]+$' then
    raise exception 'webhook authority requires one managed exact action' using errcode='25000';
  end if;
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  context_client := public.boardagent_context_uuid('boardagent.client_id');
  context_token := public.boardagent_context_uuid('boardagent.token_jti');

  perform 1
    from public.access_token_records as token
    join public.oauth_clients as oauth_client on oauth_client.id=token.client_id
    join public.auth_sessions as session on session.id=token.session_id
    join public.members as actor
      on actor.id=token.member_id and actor.organization_id=token.organization_id
    join public.system_instance as instance on instance.organization_id=token.organization_id
   where token.organization_id=context_organization and token.member_id=context_member
     and token.client_id=context_client and token.jti=context_token
     and token.revoked_at is null and token.expires_at>transaction_timestamp()
     and 'notifications:manage'=any(token.scope_set)
     and oauth_client.state='active' and actor.state='active'
     and instance.canonical_resource_uri=token.resource_uri
     and session.organization_id=token.organization_id and session.member_id=token.member_id
     and session.client_id=token.client_id and session.state='authenticated'
     and session.expires_at>transaction_timestamp() and session.exact_origin=candidate_exact_origin
     and (
       candidate_action not in ('configure_webhook','rotate_webhook_secret')
       or session.last_authenticated_at>=transaction_timestamp()-interval '15 minutes'
     )
   for update of token,session;
  if not found then
    raise exception 'webhook authority is unavailable' using errcode='42501';
  end if;

  select candidate.* into webhook from public.member_webhooks as candidate
   where candidate.id=candidate_webhook_id
     and candidate.organization_id=context_organization and candidate.member_id=context_member
   for update;

  if candidate_action='configure_webhook' then
    if webhook.id is not null or candidate_key_id is null then
      raise exception 'new webhook identity is unavailable' using errcode='55000';
    end if;
    resolved_key_id := candidate_key_id;
  else
    if webhook.id is null or webhook.state<>'active' then
      raise exception 'active owned webhook is unavailable' using errcode='P0002';
    end if;
    resolved_key_id := webhook.key_id;
    if candidate_key_id is not null and candidate_key_id<>resolved_key_id then
      raise exception 'webhook key binding changed' using errcode='40001';
    end if;
  end if;

  if candidate_action in ('configure_webhook','rotate_webhook_secret') and not exists (
    select 1 from public.crypto_key_registry as key
     where key.id=resolved_key_id and key.organization_id=context_organization
       and key.purpose='data_kek' and key.algorithm='A256GCM' and key.public_jwk is null
       and key.activated_at<=transaction_timestamp() and key.retired_at is null
       and key.compromised_at is null
  ) then
    raise exception 'active webhook encryption key is unavailable' using errcode='55000';
  end if;

  if candidate_action='configure_webhook' then
    return jsonb_build_object(
      'organizationId',context_organization,'memberId',context_member,
      'webhookId',candidate_webhook_id,'state','absent','generation','0',
      'endpointSha256',null,'keyId',resolved_key_id
    );
  end if;
  return jsonb_build_object(
    'organizationId',context_organization,'memberId',context_member,
    'webhookId',webhook.id,'state',webhook.state,'generation',webhook.generation::text,
    'endpointSha256',encode(webhook.endpoint_sha256,'hex'),'keyId',webhook.key_id,
    'eventClasses',to_jsonb(webhook.event_classes)
  );
end
$$;

create function public.boardagent_apply_webhook_action(
  candidate_action text,
  candidate_webhook_id uuid,
  candidate_payload jsonb,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid,
  candidate_secret_ciphertext bytea,
  candidate_secret_sha256 bytea
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  request jsonb;
  live_snapshot jsonb;
  context_organization uuid;
  context_member uuid;
  key_id uuid;
  next_generation bigint;
  classes text[];
begin
  if candidate_payload->>'schemaVersion' is distinct from 'boardagent.webhook-administration.v1'
     or candidate_payload->>'actionCode' is distinct from candidate_action
     or (candidate_payload->>'webhookId')::uuid is distinct from candidate_webhook_id
     or not public.boardagent_hash_is_sha256(candidate_payload_sha256) then
    raise exception 'webhook action payload is invalid' using errcode='22023';
  end if;
  request := candidate_payload->'request';
  key_id := nullif(request->>'keyId','')::uuid;
  live_snapshot := public.boardagent_webhook_snapshot(
    candidate_action,candidate_webhook_id,key_id,request->>'exactOrigin'
  );
  context_organization := (live_snapshot->>'organizationId')::uuid;
  context_member := (live_snapshot->>'memberId')::uuid;
  if live_snapshot is distinct from candidate_payload->'current'
     or not exists (
       select 1 from public.consent_records as consent
        where consent.id=candidate_consent_record_id
          and consent.organization_id=context_organization
          and consent.actor_member_id=context_member
          and consent.action_code=candidate_action and consent.target_type='webhook'
          and consent.target_id=candidate_webhook_id
          and consent.payload_sha256=candidate_payload_sha256
          and consent.package_sha256 is null
     ) then
    raise exception 'webhook consent or current state binding is invalid' using errcode='42501';
  end if;

  if candidate_action in ('configure_webhook','rotate_webhook_secret') then
    if candidate_secret_ciphertext is null
       or octet_length(candidate_secret_ciphertext) not between 32 and 4096
       or not public.boardagent_hash_is_sha256(candidate_secret_sha256) then
      raise exception 'webhook secret material is invalid' using errcode='22023';
    end if;
  elsif candidate_secret_ciphertext is not null or candidate_secret_sha256 is not null then
    raise exception 'webhook disablement cannot carry secret material' using errcode='22023';
  end if;

  if candidate_action='configure_webhook' then
    if jsonb_typeof(request->'eventClasses')<>'array'
       or jsonb_array_length(request->'eventClasses') not between 1 and 3
       or request->>'endpointCiphertext' is null
       or request->>'endpointSha256' !~ '^[0-9a-f]{64}$'
       or request->>'validationReceiptSha256' !~ '^[0-9a-f]{64}$' then
      raise exception 'webhook configuration material is invalid' using errcode='22023';
    end if;
    select array_agg(value order by value) into classes
      from jsonb_array_elements_text(request->'eventClasses') as value;
    insert into public.member_webhooks(
      id,organization_id,member_id,endpoint_ciphertext,endpoint_sha256,
      secret_ciphertext,secret_sha256,key_id,ssrf_validation_receipt_sha256,
      event_classes,state,generation,verified_at
    ) values (
      candidate_webhook_id,context_organization,context_member,
      decode(request->>'endpointCiphertext','base64'),decode(request->>'endpointSha256','hex'),
      candidate_secret_ciphertext,candidate_secret_sha256,key_id,
      decode(request->>'validationReceiptSha256','hex'),classes,'active',1,
      transaction_timestamp()
    );
    next_generation := 1;
  elsif candidate_action='rotate_webhook_secret' then
    update public.member_webhooks
       set secret_ciphertext=candidate_secret_ciphertext,secret_sha256=candidate_secret_sha256,
           generation=generation+1,updated_at=transaction_timestamp()
     where id=candidate_webhook_id and organization_id=context_organization
       and member_id=context_member and state='active'
     returning generation into strict next_generation;
  else
    update public.member_webhooks
       set state='disabled',generation=generation+1,disabled_at=transaction_timestamp(),
           updated_at=transaction_timestamp()
     where id=candidate_webhook_id and organization_id=context_organization
       and member_id=context_member and state='active'
     returning generation into strict next_generation;
  end if;
  return jsonb_build_object(
    'webhookId',candidate_webhook_id,
    'state',case when candidate_action='disable_webhook' then 'disabled' else 'active' end,
    'generation',next_generation::text,
    'endpointFingerprint',coalesce(request->>'endpointSha256',live_snapshot->>'endpointSha256'),
    'eventClasses',coalesce(request->'eventClasses',live_snapshot->'eventClasses')
  );
end
$$;

create function public.boardagent_owned_webhook_material(
  candidate_webhook_id uuid,
  candidate_exact_origin text
)
returns table(
  organization_id uuid,
  member_id uuid,
  webhook_id uuid,
  endpoint_ciphertext bytea,
  secret_ciphertext bytea,
  endpoint_sha256 bytea,
  secret_sha256 bytea,
  key_id uuid,
  generation bigint,
  event_classes text[]
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  perform public.boardagent_webhook_snapshot(
    'test_webhook',candidate_webhook_id,null,candidate_exact_origin
  );
  return query
    select webhook.organization_id,webhook.member_id,webhook.id,
           webhook.endpoint_ciphertext,webhook.secret_ciphertext,
           webhook.endpoint_sha256,webhook.secret_sha256,webhook.key_id,
           webhook.generation,webhook.event_classes
      from public.member_webhooks as webhook
     where webhook.id=candidate_webhook_id
       and webhook.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
       and webhook.member_id=public.boardagent_context_uuid('boardagent.member_id')
       and webhook.state='active';
end
$$;

alter function public.boardagent_webhook_snapshot(text,uuid,uuid,text)
  owner to boardagent_migrator;
alter function public.boardagent_apply_webhook_action(text,uuid,jsonb,bytea,uuid,bytea,bytea)
  owner to boardagent_migrator;
alter function public.boardagent_owned_webhook_material(uuid,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_webhook_snapshot(text,uuid,uuid,text) from public;
revoke all on function public.boardagent_apply_webhook_action(text,uuid,jsonb,bytea,uuid,bytea,bytea)
  from public;
revoke all on function public.boardagent_owned_webhook_material(uuid,text) from public;
grant execute on function public.boardagent_webhook_snapshot(text,uuid,uuid,text)
  to boardagent_server;
grant execute on function public.boardagent_apply_webhook_action(text,uuid,jsonb,bytea,uuid,bytea,bytea)
  to boardagent_server;
grant execute on function public.boardagent_owned_webhook_material(uuid,text)
  to boardagent_server;
