-- Retained contact ciphertext has no active writer in v1. Keep the exact bytes;
-- compromise withdraws its trusted status and binds that disposition to the incident.
create table public.key_lifecycle_contact_effects (
  operation_id uuid not null references public.key_lifecycle_operations(id) on delete restrict,
  contact_id uuid not null references public.member_contact_points(id) on delete restrict,
  before_sha256 bytea not null check(octet_length(before_sha256)=32),
  after_sha256 bytea not null check(octet_length(after_sha256)=32),
  primary key(operation_id,contact_id)
);
alter table public.key_lifecycle_contact_effects owner to boardagent_migrator;
alter table public.key_lifecycle_contact_effects enable row level security;
alter table public.key_lifecycle_contact_effects force row level security;
revoke all on public.key_lifecycle_contact_effects from public;
grant select on public.key_lifecycle_contact_effects to boardagent_backup;
create policy boardagent_key_contact_read on public.key_lifecycle_contact_effects for select to boardagent_migrator using(current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_key_contact_insert on public.key_lifecycle_contact_effects for insert to boardagent_migrator with check(current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_key_contact_backup on public.key_lifecycle_contact_effects for select to boardagent_backup using(true);
create trigger boardagent_immutable before update or delete on public.key_lifecycle_contact_effects for each row execute function public.boardagent_reject_evidence_mutation();
create function public.boardagent_guard_key_contact_effect()
returns trigger language plpgsql security definer set search_path=pg_catalog,public,pg_temp
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3 as $$
declare op public.key_lifecycle_operations%rowtype; original jsonb;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.operation_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time() or op.details->>'purpose'<>'data_kek'
    or op.details->>'operation'<>'mark_compromised' then
    raise exception 'contact containment lacks a current data key incident' using errcode='23514';
  end if;
  select to_jsonb(c) into original from public.member_contact_points c where c.id=new.contact_id
    and c.organization_id=op.organization_id and c.key_id=op.key_id and c.state='active' for update;
  if original is null then raise exception 'contact containment is outside the incident' using errcode='23514'; end if;
  new.before_sha256:=sha256(convert_to(original::text,'UTF8'));
  new.after_sha256:=sha256(convert_to((original||jsonb_build_object('state','revoked'))::text,'UTF8'));
  return new;
end;
$$;
alter function public.boardagent_guard_key_contact_effect() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_contact_effect() from public;
create trigger boardagent_key_contact_guard before insert on public.key_lifecycle_contact_effects for each row execute function public.boardagent_guard_key_contact_effect();
grant update(state) on public.member_contact_points to boardagent_migrator;
create policy boardagent_key_contact_update on public.member_contact_points for update to boardagent_migrator
  using(current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.key_lifecycle_operations op where op.organization_id=member_contact_points.organization_id
      and op.key_id=member_contact_points.key_id and op.details->>'purpose'='data_kek' and op.details->>'operation'='mark_compromised'
      and op.authorization_transaction_id=pg_current_xact_id() and op.authorization_server_start=pg_postmaster_start_time()))
  with check(current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.key_lifecycle_contact_effects e join public.key_lifecycle_operations op on op.id=e.operation_id
      where e.contact_id=member_contact_points.id and op.authorization_transaction_id=pg_current_xact_id()
        and op.authorization_server_start=pg_postmaster_start_time()));
create function public.boardagent_key_contact_effects_match(candidate_operation_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3 as $$
  select exists(select 1 from public.key_lifecycle_operations op where op.id=candidate_operation_id
    and (select count(*)::text from public.key_lifecycle_contact_effects e where e.operation_id=op.id)=
      case when op.details->>'purpose'='data_kek' and op.details->>'operation'='mark_compromised' then
        (select g->>'rowCount' from jsonb_array_elements(convert_from(op.canonical_request,'UTF8')::jsonb#>'{expectedInventory,groups}') g
          where g->>'name'='active_contact_points') else '0' end
    and not exists(select 1 from public.key_lifecycle_contact_effects e left join public.member_contact_points c on c.id=e.contact_id
      where e.operation_id=op.id and e.after_sha256 is distinct from sha256(convert_to(to_jsonb(c)::text,'UTF8'))))
$$;
alter function public.boardagent_key_contact_effects_match(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_contact_effects_match(uuid) from public;


-- Rewrapping retains actual external-secret identity so later incidents remain traceable.
create table public.key_lifecycle_webhook_rewraps (
  operation_id uuid not null references public.key_lifecycle_operations(id) on delete restrict,
  webhook_id uuid not null references public.member_webhooks(id) on delete restrict,
  source_key_id uuid not null references public.crypto_key_registry(id) on delete restrict,
  destination_key_id uuid not null references public.crypto_key_registry(id) on delete restrict,
  previous_generation bigint not null check(previous_generation>0),
  secret_sha256 bytea not null check(octet_length(secret_sha256)=32),
  endpoint_sha256 bytea not null check(octet_length(endpoint_sha256)=32),
  previous_endpoint_cipher_sha256 bytea not null check(octet_length(previous_endpoint_cipher_sha256)=32),
  previous_secret_cipher_sha256 bytea not null check(octet_length(previous_secret_cipher_sha256)=32),
  endpoint_ciphertext bytea not null check(octet_length(endpoint_ciphertext) between 32 and 4096),
  secret_ciphertext bytea not null check(octet_length(secret_ciphertext) between 32 and 4096),
  before_sha256 bytea not null check(octet_length(before_sha256)=32),
  after_sha256 bytea not null check(octet_length(after_sha256)=32),
  primary key(operation_id,webhook_id),
  unique(webhook_id,previous_generation),
  check(source_key_id<>destination_key_id)
);
create table public.key_lifecycle_webhook_disables (
  operation_id uuid not null references public.key_lifecycle_operations(id) on delete restrict,
  webhook_id uuid not null references public.member_webhooks(id) on delete restrict,
  before_sha256 bytea not null check(octet_length(before_sha256)=32),
  after_sha256 bytea not null check(octet_length(after_sha256)=32),
  primary key(operation_id,webhook_id)
);
do $policies$
declare tab text;
begin
  foreach tab in array array['key_lifecycle_webhook_rewraps','key_lifecycle_webhook_disables'] loop
    execute format('alter table public.%I owner to boardagent_migrator',tab);
    execute format('alter table public.%I enable row level security',tab);
    execute format('alter table public.%I force row level security',tab);
    execute format('revoke all on public.%I from public',tab);
    execute format('grant select on public.%I to boardagent_backup',tab);
    execute format('create policy boardagent_migrator_key_dependency_snapshot on public.%I for select to boardagent_migrator using(current_setting(''boardagent.transaction_scope'',true)=''bootstrap'')',tab);
    execute format('create policy boardagent_key_webhook_insert on public.%I for insert to boardagent_migrator with check(current_setting(''boardagent.transaction_scope'',true)=''bootstrap'')',tab);
    execute format('create policy boardagent_key_webhook_backup on public.%I for select to boardagent_backup using(true)',tab);
    execute format('create trigger boardagent_immutable before update or delete on public.%I for each row execute function public.boardagent_reject_evidence_mutation()',tab);
  end loop;
end;
$policies$;

create function public.boardagent_key_webhook_exposed(candidate_webhook_id uuid,candidate_key_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp as $$
  select current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.member_webhooks w where w.id=candidate_webhook_id and
      (w.key_id=candidate_key_id or exists(select 1 from public.key_lifecycle_webhook_rewraps history
        where history.webhook_id=w.id and history.secret_sha256=w.secret_sha256
          and (history.source_key_id=candidate_key_id or history.destination_key_id=candidate_key_id))))
$$;
alter function public.boardagent_key_webhook_exposed(uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_webhook_exposed(uuid,uuid) from public;

create function public.boardagent_guard_key_webhook_rewrap()
returns trigger language plpgsql security definer set search_path=pg_catalog,public,pg_temp
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3 as $$
declare op public.key_lifecycle_operations%rowtype; w public.member_webhooks%rowtype; following jsonb;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.operation_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time() or op.details->>'purpose'<>'data_kek'
    or op.details->>'operation'<>'replace' or op.replacement_key_id is null then
    raise exception 'webhook rewrapping lacks a current replacement operation' using errcode='23514';
  end if;
  select t.* into w from public.member_webhooks t where t.id=new.webhook_id
    and t.organization_id=op.organization_id and t.key_id=op.key_id and t.state='active' for update;
  if w.id is null or new.endpoint_ciphertext is null or new.secret_ciphertext is null
    or new.endpoint_ciphertext=w.endpoint_ciphertext or new.secret_ciphertext=w.secret_ciphertext
    or octet_length(new.endpoint_ciphertext)<>octet_length(w.endpoint_ciphertext)
    or octet_length(new.secret_ciphertext)<>octet_length(w.secret_ciphertext) then
    raise exception 'webhook rewrapping does not match its current material' using errcode='23514';
  end if;
  new.source_key_id:=w.key_id; new.destination_key_id:=op.replacement_key_id;
  new.previous_generation:=w.generation; new.secret_sha256:=w.secret_sha256; new.endpoint_sha256:=w.endpoint_sha256;
  new.previous_endpoint_cipher_sha256:=sha256(w.endpoint_ciphertext);
  new.previous_secret_cipher_sha256:=sha256(w.secret_ciphertext);
  new.before_sha256:=sha256(convert_to(to_jsonb(w)::text,'UTF8'));
  following:=to_jsonb(w)||jsonb_build_object('key_id',op.replacement_key_id,'generation',w.generation+1,'updated_at',op.recorded_at,
    'endpoint_ciphertext',new.endpoint_ciphertext,'secret_ciphertext',new.secret_ciphertext);
  new.after_sha256:=sha256(convert_to(following::text,'UTF8'));
  return new;
end;
$$;
alter function public.boardagent_guard_key_webhook_rewrap() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_webhook_rewrap() from public;
create trigger boardagent_key_webhook_rewrap_guard before insert on public.key_lifecycle_webhook_rewraps for each row execute function public.boardagent_guard_key_webhook_rewrap();

create function public.boardagent_guard_key_webhook_disable()
returns trigger language plpgsql security definer set search_path=pg_catalog,public,pg_temp
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3 as $$
declare op public.key_lifecycle_operations%rowtype; w public.member_webhooks%rowtype;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.operation_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time() or op.details->>'purpose'<>'data_kek'
    or op.details->>'operation' not in ('retire','mark_compromised') then
    raise exception 'webhook containment lacks a current data key operation' using errcode='23514';
  end if;
  select t.* into w from public.member_webhooks t where t.id=new.webhook_id
    and t.organization_id=op.organization_id and t.state='active'
    and (t.key_id=op.key_id or (op.details->>'operation'='mark_compromised' and public.boardagent_key_webhook_exposed(t.id,op.key_id))) for update;
  if w.id is null then raise exception 'webhook containment is outside the operation' using errcode='23514'; end if;
  new.before_sha256:=sha256(convert_to(to_jsonb(w)::text,'UTF8'));
  new.after_sha256:=sha256(convert_to((to_jsonb(w)||jsonb_build_object('state','disabled','generation',w.generation+1,
    'disabled_at',op.recorded_at,'updated_at',op.recorded_at))::text,'UTF8'));
  return new;
end;
$$;
alter function public.boardagent_guard_key_webhook_disable() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_webhook_disable() from public;
create trigger boardagent_key_webhook_disable_guard before insert on public.key_lifecycle_webhook_disables for each row execute function public.boardagent_guard_key_webhook_disable();

create function public.boardagent_key_webhook_effects_match(candidate_operation_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3 as $$
  select exists(select 1 from public.key_lifecycle_operations op where op.id=candidate_operation_id
    and (select count(*)::text from public.key_lifecycle_webhook_rewraps e where e.operation_id=op.id)=op.details#>>'{effects,rewrappedWebhooks}'
    and (select count(*)::text from public.key_lifecycle_webhook_disables e where e.operation_id=op.id)=op.details#>>'{effects,disabledWebhooks}'
    and not exists(select 1 from (
      select e.webhook_id,e.after_sha256 from public.key_lifecycle_webhook_rewraps e where e.operation_id=op.id
      union all select e.webhook_id,e.after_sha256 from public.key_lifecycle_webhook_disables e where e.operation_id=op.id
    ) effects left join public.member_webhooks w on w.id=effects.webhook_id
      where effects.after_sha256 is distinct from sha256(convert_to(to_jsonb(w)::text,'UTF8'))))
$$;
alter function public.boardagent_key_webhook_effects_match(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_webhook_effects_match(uuid) from public;

-- Private ciphertext is returned only to the actual operator transaction, in bounded batches.
create function public.boardagent_read_key_webhook_rewrap_batch(candidate_operation_id uuid)
returns table(webhook_id uuid,organization_id uuid,member_id uuid,key_id uuid,endpoint_ciphertext bytea,
  secret_ciphertext bytea,endpoint_sha256 bytea,secret_sha256 bytea)
language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp as $$
declare op public.key_lifecycle_operations%rowtype;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=candidate_operation_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time() or op.details->>'purpose'<>'data_kek'
    or op.details->>'operation'<>'replace' or op.replacement_key_id is null then
    raise exception 'webhook material requires the current replacement transaction' using errcode='23514';
  end if;
  return query select w.id,w.organization_id,w.member_id,w.key_id,w.endpoint_ciphertext,w.secret_ciphertext,w.endpoint_sha256,w.secret_sha256
    from public.member_webhooks w where w.organization_id=op.organization_id and w.key_id=op.key_id and w.state='active'
    order by w.id limit 128 for update of w;
end;
$$;
alter function public.boardagent_read_key_webhook_rewrap_batch(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_read_key_webhook_rewrap_batch(uuid) from public;

create function public.boardagent_apply_key_webhook_rewrap(candidate_operation_id uuid,candidate_webhook_id uuid,
  candidate_endpoint_ciphertext bytea,candidate_secret_ciphertext bytea)
returns void language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp as $$
declare effect public.key_lifecycle_webhook_rewraps%rowtype; op public.key_lifecycle_operations%rowtype;
begin
  -- Insert guard derives every immutable binding from the actual operation and old row.
  insert into public.key_lifecycle_webhook_rewraps(operation_id,webhook_id,endpoint_ciphertext,secret_ciphertext)
    values(candidate_operation_id,candidate_webhook_id,candidate_endpoint_ciphertext,candidate_secret_ciphertext) returning * into effect;
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=effect.operation_id;
  update public.member_webhooks set key_id=effect.destination_key_id,endpoint_ciphertext=effect.endpoint_ciphertext,
    secret_ciphertext=effect.secret_ciphertext,generation=effect.previous_generation+1,updated_at=op.recorded_at where id=effect.webhook_id;
  if not found then raise exception 'webhook rewrapping did not apply' using errcode='23514'; end if;
end;
$$;
alter function public.boardagent_apply_key_webhook_rewrap(uuid,uuid,bytea,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_apply_key_webhook_rewrap(uuid,uuid,bytea,bytea) from public;


-- Data-key lifecycle with exact transactional credential and notification effects.
create or replace function public.boardagent_key_lifecycle_state(candidate_key_id uuid)
returns jsonb language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare k public.crypto_key_registry%rowtype; fingerprint text; coordinate text;
begin
  select key.* into k from public.crypto_key_registry key where key.id=candidate_key_id;
  if k.purpose='data_kek' then
    if k.algorithm<>'A256GCM' or k.public_jwk is not null or k.kid!~'^data-[0-9a-f]{24}$' then
      raise exception 'invalid data key identity' using errcode='55000';
    end if;
    fingerprint:=null;
  elsif k.purpose='backup_kek' then
    if k.algorithm<>'A256GCM' or k.public_jwk is not null
      or k.kid<>'backup-'||k.id::text or k.nonsecret_locator!~'^sha256:[0-9a-f]{64}$' then
      raise exception 'invalid backup key identity' using errcode='55000';
    end if;
    fingerprint:=null;
  elsif k.purpose='browser_session' then
    if k.algorithm<>'HMAC-SHA256' or k.public_jwk is not null then
      raise exception 'invalid browser key identity' using errcode='55000';
    end if;
    fingerprint:=null;
  else
  if k.id is null or k.purpose not in ('evidence_signing','oauth_signing')
    or k.public_jwk is null or jsonb_typeof(k.public_jwk)<>'object'
    or exists(select 1 from jsonb_each(k.public_jwk) f where jsonb_typeof(f.value)<>'string') then
    raise exception 'invalid signing key identity' using errcode='55000';
  end if;
  if k.purpose='evidence_signing' then
    if k.algorithm<>'EdDSA' or not k.public_jwk ?& array['kty','crv','x']
      or k.public_jwk-array['kty','crv','x']<>'{}'::jsonb
      or k.public_jwk->>'kty'<>'OKP' or k.public_jwk->>'crv'<>'Ed25519' then
      raise exception 'invalid evidence key identity' using errcode='55000';
    end if;
    fingerprint:=encode(sha256(convert_to(format('{"crv":"Ed25519","kty":"OKP","x":"%s"}',k.public_jwk->>'x'),'UTF8')),'hex');
  else
    if k.algorithm<>'ES256' or not k.public_jwk ?& array['kty','crv','x','y','kid','use','alg']
      or k.public_jwk-array['kty','crv','x','y','kid','use','alg']<>'{}'::jsonb
      or k.public_jwk->>'kty'<>'EC' or k.public_jwk->>'crv'<>'P-256'
      or k.public_jwk->>'kid'<>k.kid or k.public_jwk->>'use'<>'sig' or k.public_jwk->>'alg'<>'ES256' then
      raise exception 'invalid OAuth key identity' using errcode='55000';
    end if;
    fingerprint:=encode(sha256(convert_to(format('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}',k.public_jwk->>'x',k.public_jwk->>'y'),'UTF8')),'hex');
  end if;
  foreach coordinate in array (case when k.purpose='oauth_signing' then array[k.public_jwk->>'x',k.public_jwk->>'y'] else array[k.public_jwk->>'x'] end) loop
    if coordinate!~'^[A-Za-z0-9_-]{43}$'
      or rtrim(translate(encode(decode(translate(coordinate,'-_','+/')||'=','base64'),'base64'),'+/','-_'),'=')<>coordinate then
      raise exception 'invalid public coordinate' using errcode='55000';
    end if;
  end loop;
  end if;
  return jsonb_build_object('keyId',k.id,'kid',k.kid,'algorithm',k.algorithm,
    'publicMaterialSha256',fingerprint,
    'activatedAt',to_char(k.activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'retiredAt',to_char(k.retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'compromisedAt',to_char(k.compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
end;
$$;

create or replace function public.boardagent_guard_key_lifecycle_authorization()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  request jsonb; inventory jsonb; previous jsonb; following jsonb;
  fields text[]:=array['instanceId','organizationId','keyId','operationId','operation','replacement',
    'declaredCompromisedAt','retainedMaterialSha256','operatorReference','reason','schemaVersion',
    'purpose','expectedKey','expectedInventory','preparedAt','expiresAt'];
  declared timestamptz; replacement jsonb; new_public jsonb; fingerprint text; locator text; algorithm text; coordinate text; affected_families text;
  recorded text:=to_char(transaction_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'key lifecycle requires a serializable operator transaction' using errcode='25000';
  end if;
  begin
    if new.canonical_request is null or octet_length(new.canonical_request) not between 2 and 262144
      or new.request_sha256 is distinct from sha256(new.canonical_request)
      or new.canonical_inventory is null or octet_length(new.canonical_inventory) not between 2 and 262144
      or not (convert_from(new.canonical_request,'UTF8') is json object with unique keys)
      or not (convert_from(new.canonical_inventory,'UTF8') is json object with unique keys) then
      raise exception 'invalid request';
    end if;
    request:=convert_from(new.canonical_request,'UTF8')::jsonb;
    if jsonb_typeof(request)<>'object' or not request ?& fields or request-fields<>'{}'::jsonb
      or request->>'schemaVersion'<>'boardagent.key-lifecycle-request.v1'
      or request->>'purpose' not in ('evidence_signing','oauth_signing','browser_session','backup_kek','data_kek')
      or request->>'operation' not in ('replace','retire','mark_compromised')
      or (request->>'operation'<>'replace' and request->'replacement'<>'null'::jsonb)
      or request->>'operationId' is distinct from new.id::text
      or request->>'retainedMaterialSha256'!~'^[0-9a-f]{64}$'
      or exists(select 1 from jsonb_each(request) field where field.key not in
        ('replacement','declaredCompromisedAt','expectedKey','expectedInventory') and jsonb_typeof(field.value)<>'string')
      or length(request->>'operatorReference') not between 1 and 512
      or length(request->>'reason') not between 1 and 4096
      or request->>'operatorReference'<>btrim(request->>'operatorReference')
      or request->>'reason'<>btrim(request->>'reason')
      or request->>'operatorReference'~'[[:cntrl:]]' or request->>'reason'~'[[:cntrl:]]'
      or request->>'operatorReference'<>normalize(request->>'operatorReference',NFC)
      or request->>'reason'<>normalize(request->>'reason',NFC) then
      raise exception 'unsupported or invalid lifecycle request';
    end if;
    new.instance_id:=(request->>'instanceId')::uuid;
    new.organization_id:=(request->>'organizationId')::uuid;
    new.key_id:=(request->>'keyId')::uuid;
    if not public.boardagent_is_uuid_v7(new.id)
      or convert_from(new.canonical_inventory,'UTF8')::jsonb
        is distinct from ((request->'expectedInventory') #- '{keyDependencies,observedAt}') then
      raise exception 'invalid inventory';
    end if;
  exception when others then
    raise exception 'key lifecycle request is invalid or unsupported' using errcode='55000';
  end;
  inventory:=public.boardagent_lock_key_maintenance_snapshot(new.instance_id,new.organization_id,new.key_id,
    request->'expectedInventory',request->>'preparedAt',request->>'expiresAt');
  previous:=public.boardagent_key_lifecycle_state(new.key_id);
  if previous is distinct from request->'expectedKey' or request->>'preparedAt'>recorded
    or exists(select 1 from jsonb_array_elements(inventory->'groups') g
      where g->>'name' in ('closing_votes','live_vote_close_stages','unfinished_vote_outcomes',
        'leased_jobs','leased_notifications','running_exports') and g->>'rowCount'<>'0') then
    raise exception 'key lifecycle has changed facts or unfinished signing work' using errcode='55000';
  end if;
  if inventory#>>'{keyDependencies,keyPurpose}'<>request->>'purpose' then
    raise exception 'key purpose does not match the operation' using errcode='55000';
  end if;

  if request->>'purpose'='data_kek' and request->>'operation'<>'mark_compromised' and exists(
    select 1 from public.member_webhooks w where w.organization_id=new.organization_id and w.state='active'
      and w.key_id<>new.key_id and public.boardagent_key_webhook_exposed(w.id,new.key_id)) then
    raise exception 'historical data key has current successor connections; retain it or report compromise' using errcode='55000';
  end if;
  algorithm:=case when request->>'purpose'='oauth_signing' then 'ES256' when request->>'purpose'='browser_session' then 'HMAC-SHA256' when request->>'purpose' in ('backup_kek','data_kek') then 'A256GCM' else 'EdDSA' end;
  select g->>'rowCount' into affected_families from jsonb_array_elements(inventory->'groups') g where g->>'name'='affected_refresh_families';
  if affected_families is null then raise exception 'refresh inventory unavailable' using errcode='55000'; end if;
  following:=previous;
  new.replacement_key_id:=null;
  if request->>'operation'='replace' then
    begin
      replacement:=request->'replacement'; new_public:=replacement->'publicJwk';
      if jsonb_typeof(replacement) is distinct from 'object'
        or not replacement ?& array['keyId','kid','algorithm','publicJwk','nonsecretLocator','materialSha256']
        or replacement-array['keyId','kid','algorithm','publicJwk','nonsecretLocator','materialSha256']<>'{}'::jsonb
        or exists(select 1 from jsonb_each(replacement) f where f.key<>'publicJwk' and jsonb_typeof(f.value)<>'string')
        or replacement->>'algorithm'<>algorithm or replacement->>'materialSha256'!~'^[0-9a-f]{64}$'
        or (request->>'purpose' in ('browser_session','backup_kek','data_kek') and new_public is distinct from 'null'::jsonb)
        or (request->>'purpose' not in ('browser_session','backup_kek','data_kek') and jsonb_typeof(new_public) is distinct from 'object')
        or request->'declaredCompromisedAt'<>'null'::jsonb then
        raise exception 'invalid replacement';
      end if;
      new.replacement_key_id:=(replacement->>'keyId')::uuid;
      if request->>'purpose'='data_kek' then
        fingerprint:=null;
        if replacement->>'kid'!~'^data-[0-9a-f]{24}$' then raise exception 'invalid data key id'; end if;
      elsif request->>'purpose'='backup_kek' then
        fingerprint:=null;
        if replacement->>'kid'<>'backup-'||new.replacement_key_id::text
          or replacement->>'nonsecretLocator'<>'sha256:'||(replacement->>'materialSha256')
          or exists(select 1 from public.crypto_key_registry k where k.organization_id=new.organization_id
            and k.purpose='backup_kek' and k.nonsecret_locator='sha256:'||(replacement->>'materialSha256')) then
          raise exception 'invalid or reused backup key identity';
        end if;
      elsif request->>'purpose'='browser_session' then
        fingerprint:=null;
        if replacement->>'kid'!~'^browser-[0-9a-f]{24}$' then raise exception 'invalid browser key id'; end if;
      else
        if exists(select 1 from jsonb_each(new_public) f where jsonb_typeof(f.value)<>'string') then
          raise exception 'invalid public key projection';
        end if;
      if request->>'purpose'='evidence_signing' then
        if not new_public ?& array['kty','crv','x'] or new_public-array['kty','crv','x']<>'{}'::jsonb
          or new_public->>'kty'<>'OKP' or new_public->>'crv'<>'Ed25519' then raise exception 'invalid public key'; end if;
        fingerprint:=encode(sha256(convert_to(format('{"crv":"Ed25519","kty":"OKP","x":"%s"}',new_public->>'x'),'UTF8')),'hex');
        if replacement->>'kid'<>'evidence-'||substr(fingerprint,1,24) then raise exception 'invalid evidence key id'; end if;
      else
        if not new_public ?& array['kty','crv','x','y','kid','use','alg']
          or new_public-array['kty','crv','x','y','kid','use','alg']<>'{}'::jsonb
          or new_public->>'kty'<>'EC' or new_public->>'crv'<>'P-256'
          or new_public->>'kid'<>replacement->>'kid' or new_public->>'use'<>'sig' or new_public->>'alg'<>'ES256' then
          raise exception 'invalid OAuth public key';
        end if;
        fingerprint:=encode(sha256(convert_to(format('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}',new_public->>'x',new_public->>'y'),'UTF8')),'hex');
      end if;
      foreach coordinate in array (case when request->>'purpose'='oauth_signing' then array[new_public->>'x',new_public->>'y'] else array[new_public->>'x'] end) loop
        if coordinate!~'^[A-Za-z0-9_-]{43}$'
          or rtrim(translate(encode(decode(translate(coordinate,'-_','+/')||'=','base64'),'base64'),'+/','-_'),'=')<>coordinate then
          raise exception 'invalid public coordinate';
        end if;
      end loop;
      end if;
      locator:=replacement->>'nonsecretLocator';
      if not public.boardagent_is_uuid_v7(new.replacement_key_id)
        or replacement->>'keyId'<>new.replacement_key_id::text
        or new.replacement_key_id=new.key_id or fingerprint<>replacement->>'materialSha256'
        or fingerprint=previous->>'publicMaterialSha256'
        or replacement->>'kid'!~'^[A-Za-z0-9._-]{1,128}$'
        or replacement->>'kid'=previous->>'kid'
        or (request->>'purpose'<>'backup_kek' and (length(locator) not between 7 and 2048 or locator not like 'file:/%'
        or locator~'[[:cntrl:]]' or locator<>normalize(locator,NFC)
        or substr(locator,6)~'//' or substr(locator,6)~'(^|/)\.{1,2}(/|$)'
        or right(locator,1)='/')) then raise exception 'invalid replacement'; end if;
      if exists(select 1 from public.crypto_key_registry k where k.id=new.replacement_key_id
          or (k.organization_id=new.organization_id and k.kid=replacement->>'kid'))
        or exists(select 1 from public.crypto_key_registry k where k.organization_id=new.organization_id
          and k.purpose=request->>'purpose' and k.retired_at is null and k.compromised_at is null and k.id<>new.key_id) then
        raise exception 'replacement conflicts with a registered key';
      end if;
    exception when others then
      raise exception 'key replacement is invalid or no longer applicable' using errcode='55000';
    end;
    following:=jsonb_set(following,'{retiredAt}',coalesce(nullif(previous->'retiredAt','null'::jsonb),to_jsonb(recorded)));
  elsif request->>'operation'='retire' then
    if previous->'retiredAt'<>'null'::jsonb or request->'declaredCompromisedAt'<>'null'::jsonb then
      raise exception 'key is already retired or retirement request is invalid' using errcode='55000';
    end if;
    following:=jsonb_set(following,'{retiredAt}',to_jsonb(recorded));
  else
    begin
      declared:=(request->>'declaredCompromisedAt')::timestamptz;
      if declared is null or request->>'declaredCompromisedAt'<>
        to_char(declared at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        or request->>'declaredCompromisedAt'<previous->>'activatedAt'
        or request->>'declaredCompromisedAt'>request->>'preparedAt'
        or (previous->'compromisedAt'<>'null'::jsonb and request->>'declaredCompromisedAt'>=previous->>'compromisedAt') then
        raise exception 'invalid compromise time';
      end if;
    exception when others then
      raise exception 'invalid compromise time' using errcode='55000';
    end;
    following:=jsonb_set(following,'{compromisedAt}',request->'declaredCompromisedAt');
  end if;
  new.recorded_at:=transaction_timestamp();
  new.authorizing_principal:=session_user;
  new.authorization_transaction_id:=pg_current_xact_id();
  new.authorization_server_start:=pg_postmaster_start_time();
  new.details:=jsonb_build_object('schemaVersion','boardagent.key-lifecycle-changed.v1',
    'operationId',new.id,'requestSha256',encode(new.request_sha256,'hex'),
    'instanceId',new.instance_id,'organizationId',new.organization_id,'purpose',request->>'purpose',
    'operation',request->>'operation','before',previous,'after',following,'replacement',
      case when new.replacement_key_id is null then null else jsonb_build_object(
        'keyId',new.replacement_key_id,'kid',replacement->>'kid','algorithm',algorithm,
        'publicMaterialSha256',fingerprint,'activatedAt',recorded,'retiredAt',null,'compromisedAt',null) end,
    'recordedAt',recorded,'declaredCompromisedAt',request->'declaredCompromisedAt',
    'dependencyStateSha256',encode(sha256(new.canonical_inventory),'hex'),
    'retainedMaterialSha256',request->>'retainedMaterialSha256',
    'operatorReference',request->>'operatorReference','reason',request->>'reason',
    'effects',jsonb_build_object('revokedSessions',
      case when (request->>'purpose'='browser_session' or (request->>'purpose'='data_kek' and request->>'operation'='mark_compromised')) then (select g->>'rowCount' from jsonb_array_elements(inventory->'groups') g where g->>'name'='browser_sessions') else '0' end,'revokedRefreshFamilies',
      case when (request->>'purpose'='browser_session' or (request->>'purpose'='data_kek' and request->>'operation'='mark_compromised')) or (request->>'purpose'='oauth_signing' and request->>'operation'='mark_compromised') then affected_families else '0' end,'cancelledStages',
      case when (request->>'purpose'='browser_session' or (request->>'purpose'='data_kek' and request->>'operation'='mark_compromised')) then (select g->>'rowCount' from jsonb_array_elements(inventory->'groups') g where g->>'name'='browser_action_stages') else '0' end,
      'affectedTotp',case when request->>'purpose'='data_kek' then
        ((select (g->>'rowCount')::bigint from jsonb_array_elements(inventory->'groups') g where g->>'name'='pending_totp')+
         case when request->>'operation'='mark_compromised' then (select (g->>'rowCount')::bigint from jsonb_array_elements(inventory->'groups') g where g->>'name'='active_totp') else 0 end)::text else '0' end,'disabledWebhooks',case when request->>'purpose'='data_kek' and request->>'operation' in ('retire','mark_compromised')
        then (select g->>'rowCount' from jsonb_array_elements(inventory->'groups') g where g->>'name'='active_webhooks') else '0' end,
      'rewrappedWebhooks',case when request->>'purpose'='data_kek' and request->>'operation'='replace'
        then (select g->>'rowCount' from jsonb_array_elements(inventory->'groups') g where g->>'name'='active_webhooks') else '0' end));
  return new;
end;
$$;


-- Historical TOTP membership remains relevant after a seed is disabled/replaced.
create function public.boardagent_key_data_member(candidate_organization_id uuid,candidate_key_id uuid,candidate_member_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp as $$
  select current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.totp_credentials t where t.organization_id=candidate_organization_id
      and t.key_id=candidate_key_id and t.member_id=candidate_member_id)
$$;
alter function public.boardagent_key_data_member(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_data_member(uuid,uuid,uuid) from public;

create function public.boardagent_key_lifecycle_member_scope(candidate_operation_id uuid,candidate_member_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp as $$
  select exists(select 1 from public.key_lifecycle_operations op where op.id=candidate_operation_id
    and current_setting('boardagent.transaction_scope',true)='bootstrap'
    and op.authorization_transaction_id=pg_current_xact_id() and op.authorization_server_start=pg_postmaster_start_time()
    and (op.details->>'purpose'='browser_session' or (op.details->>'purpose'='data_kek'
      and op.details->>'operation'='mark_compromised'
      and public.boardagent_key_data_member(op.organization_id,op.key_id,candidate_member_id))))
$$;
alter function public.boardagent_key_lifecycle_member_scope(uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_lifecycle_member_scope(uuid,uuid) from public;

create table public.key_lifecycle_totp_effects (
  operation_id uuid not null references public.key_lifecycle_operations(id) on delete restrict,
  credential_id uuid not null references public.totp_credentials(id) on delete restrict,
  before_sha256 bytea not null check(octet_length(before_sha256)=32),
  after_sha256 bytea not null check(octet_length(after_sha256)=32),
  primary key(operation_id,credential_id)
);
alter table public.key_lifecycle_totp_effects owner to boardagent_migrator;
alter table public.key_lifecycle_totp_effects enable row level security;
alter table public.key_lifecycle_totp_effects force row level security;
revoke all on public.key_lifecycle_totp_effects from public;
grant select on public.key_lifecycle_totp_effects to boardagent_backup;
create policy boardagent_key_totp_read on public.key_lifecycle_totp_effects for select to boardagent_migrator using(current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_key_totp_insert on public.key_lifecycle_totp_effects for insert to boardagent_migrator with check(current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_key_totp_backup on public.key_lifecycle_totp_effects for select to boardagent_backup using(true);
create trigger boardagent_immutable before update or delete on public.key_lifecycle_totp_effects for each row execute function public.boardagent_reject_evidence_mutation();

create function public.boardagent_guard_key_totp_effect()
returns trigger language plpgsql security definer set search_path=pg_catalog,public,pg_temp
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3 as $$
declare op public.key_lifecycle_operations%rowtype; original jsonb; following jsonb;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.operation_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time() or op.details->>'purpose'<>'data_kek' then
    raise exception 'TOTP invalidation lacks a current data key operation' using errcode='23514';
  end if;
  select to_jsonb(t) into original from public.totp_credentials t where t.id=new.credential_id
    and t.organization_id=op.organization_id and t.key_id=op.key_id
    and (t.state='pending_verification' or (t.state='active' and op.details->>'operation'='mark_compromised')) for update;
  if original is null then raise exception 'TOTP effect is outside the key operation' using errcode='23514'; end if;
  following:=original||jsonb_build_object('state',case when op.details->>'operation'='mark_compromised' then 'compromised' else 'disabled' end,
    'terminal_at',op.recorded_at,'failed_attempts',0,'locked_until',null);
  new.before_sha256:=sha256(convert_to(original::text,'UTF8'));
  new.after_sha256:=sha256(convert_to(following::text,'UTF8'));
  return new;
end;
$$;
alter function public.boardagent_guard_key_totp_effect() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_totp_effect() from public;
create trigger boardagent_key_totp_guard before insert on public.key_lifecycle_totp_effects for each row execute function public.boardagent_guard_key_totp_effect();
grant update(state,terminal_at,failed_attempts,locked_until) on public.totp_credentials to boardagent_migrator;
create policy boardagent_key_totp_update on public.totp_credentials for update to boardagent_migrator
  using(current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.key_lifecycle_operations op where op.organization_id=totp_credentials.organization_id
      and op.key_id=totp_credentials.key_id and op.details->>'purpose'='data_kek'
      and op.authorization_transaction_id=pg_current_xact_id() and op.authorization_server_start=pg_postmaster_start_time()
      and (totp_credentials.state='pending_verification' or (totp_credentials.state='active' and op.details->>'operation'='mark_compromised'))))
  with check(current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.key_lifecycle_totp_effects e join public.key_lifecycle_operations op on op.id=e.operation_id
      where e.credential_id=totp_credentials.id and op.authorization_transaction_id=pg_current_xact_id()
        and op.authorization_server_start=pg_postmaster_start_time()));

create function public.boardagent_key_totp_effects_match(candidate_operation_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3 as $$
  select exists(select 1 from public.key_lifecycle_operations op where op.id=candidate_operation_id
    and (select count(*)::text from public.key_lifecycle_totp_effects e where e.operation_id=op.id)=op.details#>>'{effects,affectedTotp}'
    and not exists(select 1 from public.key_lifecycle_totp_effects e left join public.totp_credentials t on t.id=e.credential_id
      where e.operation_id=op.id and e.after_sha256 is distinct from sha256(convert_to(to_jsonb(t)::text,'UTF8'))))
$$;
alter function public.boardagent_key_totp_effects_match(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_totp_effects_match(uuid) from public;


create or replace function public.boardagent_guard_key_browser_effect()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare op public.key_lifecycle_operations%rowtype; original jsonb; following jsonb;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.operation_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time()
    or not (op.details->>'purpose'='browser_session' or (op.details->>'purpose'='data_kek' and op.details->>'operation'='mark_compromised')) then
    raise exception 'browser invalidation lacks a current key operation' using errcode='23514';
  end if;
  case new.target_type
    when 'session' then
      select to_jsonb(s) into original from public.auth_sessions s where s.id=new.target_id
        and s.organization_id=op.organization_id and s.state in ('anonymous','authenticated') for update;
      following:=original||jsonb_build_object('state','revoked');
    when 'authorization_request' then
      select to_jsonb(a) into original from public.oauth_authorization_requests a where a.id=new.target_id
        and a.organization_id=op.organization_id and a.request_state in ('pending','approved') for update;
      following:=original||jsonb_build_object('request_state','expired');
    when 'action_stage' then
      select to_jsonb(s) into original from public.action_stages s where s.id=new.target_id
        and s.organization_id=op.organization_id and s.state='active' for update;
      following:=original||jsonb_build_object('state','cancelled','cancelled_at',op.recorded_at);
    when 'onboarding_stage' then
      select to_jsonb(t) into original from public.onboarding_browser_stages t where t.id=new.target_id
        and t.organization_id=op.organization_id and t.state='active' for update;
      following:=original||jsonb_build_object('state','expired');
    else raise exception 'unsupported browser effect' using errcode='23514';
  end case;
  if original is not null and not public.boardagent_key_lifecycle_member_scope(op.id,
    case when new.target_type='action_stage' then (original->>'actor_member_id')::uuid
      when new.target_type='authorization_request' then coalesce((original->>'member_id')::uuid,
        (select member_id from public.auth_sessions where id=(original->>'session_id')::uuid))
      else (original->>'member_id')::uuid end) then original:=null; end if;
  if original is null then raise exception 'browser effect is outside the operation' using errcode='23514'; end if;
  new.before_sha256:=sha256(convert_to(original::text,'UTF8'));
  new.after_sha256:=sha256(convert_to(following::text,'UTF8'));
  return new;
end;
$$;

alter policy boardagent_key_browser_update on public.auth_sessions using(
    current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(select 1 from public.key_lifecycle_operations op
      where op.organization_id=auth_sessions.organization_id and public.boardagent_key_lifecycle_member_scope(op.id,auth_sessions.member_id)));


alter policy boardagent_key_browser_update on public.oauth_authorization_requests using(
    current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(select 1 from public.key_lifecycle_operations op
      where op.organization_id=oauth_authorization_requests.organization_id and public.boardagent_key_lifecycle_member_scope(op.id,coalesce(oauth_authorization_requests.member_id,(select s.member_id from public.auth_sessions s where s.id=oauth_authorization_requests.session_id)))));


alter policy boardagent_key_browser_update on public.action_stages using(
    current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(select 1 from public.key_lifecycle_operations op
      where op.organization_id=action_stages.organization_id and public.boardagent_key_lifecycle_member_scope(op.id,action_stages.actor_member_id)));


alter policy boardagent_key_browser_update on public.onboarding_browser_stages using(
    current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(select 1 from public.key_lifecycle_operations op
      where op.organization_id=onboarding_browser_stages.organization_id and public.boardagent_key_lifecycle_member_scope(op.id,onboarding_browser_stages.member_id)));


create or replace function public.boardagent_key_browser_effects_match(candidate_operation_id uuid)
returns boolean language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare op public.key_lifecycle_operations%rowtype; expected jsonb; item record; actual bigint; wanted text;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=candidate_operation_id;
  if op.id is null then return false; end if;
  expected:=convert_from(op.canonical_request,'UTF8')::jsonb#>'{expectedInventory,groups}';
  for item in select * from (values ('session','browser_sessions'),
    ('authorization_request','browser_authorization_requests'),('action_stage','browser_action_stages')) as t(kind,group_name) loop
    select count(*) into actual from public.key_lifecycle_browser_effects e where e.operation_id=op.id and (e.target_type=item.kind or (item.kind='action_stage' and e.target_type='onboarding_stage'));
    if (op.details->>'purpose'='browser_session' or (op.details->>'purpose'='data_kek' and op.details->>'operation'='mark_compromised')) then
      select g->>'rowCount' into wanted from jsonb_array_elements(expected) g where g->>'name'=item.group_name;
    else wanted:='0'; end if;
    if wanted is null or actual::text<>wanted then return false; end if;
  end loop;
  return not exists(select 1 from public.key_lifecycle_browser_effects e
    left join public.auth_sessions s on e.target_type='session' and s.id=e.session_id
    left join public.oauth_authorization_requests a on e.target_type='authorization_request' and a.id=e.authorization_request_id
    left join public.action_stages stage on e.target_type='action_stage' and stage.id=e.action_stage_id
    left join public.onboarding_browser_stages onboarding on e.target_type='onboarding_stage' and onboarding.id=e.onboarding_stage_id
    where e.operation_id=op.id and e.after_sha256 is distinct from sha256(convert_to(
      case e.target_type when 'session' then to_jsonb(s)::text
        when 'authorization_request' then to_jsonb(a)::text when 'action_stage' then to_jsonb(stage)::text when 'onboarding_stage' then to_jsonb(onboarding)::text end,'UTF8')));
end;
$$;

create or replace function public.boardagent_guard_key_lifecycle_family()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare op public.key_lifecycle_operations%rowtype; family public.refresh_families%rowtype;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.operation_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time()
    or not (op.details->>'purpose'='browser_session' or (op.details->>'purpose' in ('oauth_signing','data_kek') and op.details->>'operation'='mark_compromised')) then
    raise exception 'refresh revocation lacks a current key operation' using errcode='23514';
  end if;
  select f.* into family from public.refresh_families f where f.id=new.family_id for update;
  if family.id is null or family.organization_id<>op.organization_id or family.state<>'active'
    or not (op.details->>'purpose'='browser_session'
      or (op.details->>'purpose'='oauth_signing' and exists(select 1 from public.access_token_records a where a.refresh_family_id=family.id and a.signing_key_id=op.key_id))
      or (op.details->>'purpose'='data_kek' and public.boardagent_key_data_member(op.organization_id,op.key_id,family.member_id))) then
    raise exception 'refresh family is outside the key operation' using errcode='23514';
  end if;
  new.before_sha256:=sha256(convert_to(to_jsonb(family)::text,'UTF8'));
  new.after_sha256:=sha256(convert_to((to_jsonb(family)||jsonb_build_object('state','revoked','revoked_at',op.recorded_at))::text,'UTF8'));
  return new;
end;
$$;

alter policy boardagent_key_family_revocation on public.refresh_families using(
 current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(select 1 from public.key_lifecycle_operations op
  where op.organization_id=refresh_families.organization_id and op.authorization_transaction_id=pg_current_xact_id()
    and op.authorization_server_start=pg_postmaster_start_time()
    and (public.boardagent_key_lifecycle_member_scope(op.id,refresh_families.member_id)
      or (op.details->>'purpose'='oauth_signing' and op.details->>'operation'='mark_compromised'
        and exists(select 1 from public.access_token_records a where a.refresh_family_id=refresh_families.id and a.signing_key_id=op.key_id)))));


create or replace function public.boardagent_key_lifecycle_state_matches(candidate_operation_id uuid)
returns boolean language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare op public.key_lifecycle_operations%rowtype; key_row public.crypto_key_registry%rowtype; original jsonb; replacement jsonb; replacement_row public.crypto_key_registry%rowtype;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=candidate_operation_id;
  if op.id is null or public.boardagent_key_contact_effects_match(op.id) is distinct from true or public.boardagent_key_webhook_effects_match(op.id) is distinct from true or public.boardagent_key_totp_effects_match(op.id) is distinct from true or public.boardagent_key_lifecycle_families_match(op.id) is distinct from true
    or public.boardagent_key_browser_effects_match(op.id) is distinct from true then return false; end if;
  select k.* into key_row from public.crypto_key_registry k where k.id=op.key_id;
  if key_row.id is null or public.boardagent_key_lifecycle_state(op.key_id) is distinct from op.details->'after' then
    return false;
  end if;
  original:=to_jsonb(key_row)||jsonb_build_object(
    'retired_at',(op.details#>>'{before,retiredAt}')::timestamptz,
    'compromised_at',(op.details#>>'{before,compromisedAt}')::timestamptz);
  if encode(sha256(convert_to(original::text,'UTF8')),'hex') is distinct from
    (convert_from(op.canonical_request,'UTF8')::jsonb#>>'{expectedInventory,keyDependencies,keyStateSha256}') then return false; end if;
  if op.replacement_key_id is null then return op.details->'replacement'='null'::jsonb; end if;
  replacement:=convert_from(op.canonical_request,'UTF8')::jsonb->'replacement';
  select k.* into replacement_row from public.crypto_key_registry k where k.id=op.replacement_key_id;
  return replacement_row.id is not null
    and public.boardagent_key_lifecycle_state(op.replacement_key_id)=op.details->'replacement'
    and to_jsonb(replacement_row)=jsonb_build_object('id',op.replacement_key_id,
      'organization_id',op.organization_id,'kid',replacement->>'kid','purpose',op.details->>'purpose',
      'algorithm',replacement->>'algorithm','public_jwk',replacement->'publicJwk','nonsecret_locator',replacement->>'nonsecretLocator',
      'activated_at',op.recorded_at,'retired_at',null,'compromised_at',null,'created_at',op.recorded_at);
end;
$$;

create or replace function public.boardagent_guard_oauth_request_state()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if old.member_id is not null and new.member_id is distinct from old.member_id then
    raise exception 'OAuth request member binding is immutable once established'
      using errcode='23514';
  end if;
  if new.member_id is distinct from old.member_id and old.request_state<>'pending' then
    raise exception 'OAuth request member binding requires a pending request'
      using errcode='23514';
  end if;
  if new.session_id is distinct from old.session_id then
    if old.request_state<>'pending' or new.member_id is null or not exists (
      select 1
        from public.auth_sessions as old_session
        join public.auth_sessions as new_session
          on new_session.id=new.session_id
         and new_session.organization_id=old.organization_id
         and new_session.client_id=old.client_id
         and new_session.member_id=new.member_id
         and new_session.state='authenticated'
       where old_session.id=old.session_id
         and old_session.organization_id=old.organization_id
         and old_session.state='anonymous'
    ) then
      raise exception 'OAuth request session replacement is not an authenticated continuation'
        using errcode='23514';
    end if;
  end if;
  if old.request_state='approved' and new.request_state='expired'
    and current_user='boardagent_migrator'
    and current_setting('boardagent.transaction_scope',true)='bootstrap' then
    if exists(select 1 from public.key_lifecycle_browser_effects effect
      join public.key_lifecycle_operations op on op.id=effect.operation_id
      where effect.target_type='authorization_request' and effect.authorization_request_id=old.id
        and op.authorization_transaction_id=pg_current_xact_id()
        and op.authorization_server_start=pg_postmaster_start_time()
        and op.organization_id=old.organization_id and (op.details->>'purpose'='browser_session' or (op.details->>'purpose'='data_kek' and op.details->>'operation'='mark_compromised'))) then
      return new;
    end if;
  end if;
  if new.request_state=old.request_state then return new; end if;
  if (old.request_state='pending' and new.request_state in ('approved','denied','expired'))
     or (old.request_state='approved' and new.request_state='consumed') then
    return new;
  end if;
  raise exception 'illegal OAuth request transition: % -> %',old.request_state,new.request_state
    using errcode='23514';
end
$$;

create or replace function public.boardagent_guard_onboarding_browser_stage()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
declare maintenance boolean:=false;
begin
  if tg_op='UPDATE' and current_user='boardagent_migrator'
    and current_setting('boardagent.transaction_scope',true)='bootstrap' then
    select exists(select 1 from public.key_lifecycle_browser_effects effect
      join public.key_lifecycle_operations op on op.id=effect.operation_id
      where effect.target_type='onboarding_stage' and effect.onboarding_stage_id=old.id
        and op.authorization_transaction_id=pg_current_xact_id()
        and op.authorization_server_start=pg_postmaster_start_time()
        and op.organization_id=old.organization_id and (op.details->>'purpose'='browser_session' or (op.details->>'purpose'='data_kek' and op.details->>'operation'='mark_compromised'))) into maintenance;
  end if;
  if tg_op='INSERT' then
    if new.state<>'active'
       or new.created_at is distinct from transaction_timestamp()
       or new.expires_at is distinct from new.created_at+interval '10 minutes'
       or new.completed_at is not null
       or new.attested_audit_event_id is not null then
      raise exception 'onboarding browser stage must start active for exactly ten minutes'
        using errcode='23514';
    end if;
    return new;
  end if;
  if row(
       new.id,new.organization_id,new.board_id,new.member_id,new.session_id,new.client_id,
       new.access_token_record_id,new.token_jti,new.terms_version_id,new.support_version_id,
       new.presentation_choice,new.local_memory_choice,new.request_sha256,
       new.stage_token_sha256,new.safe_response_sha256,new.idempotency_record_id,
       new.exact_origin,new.expires_at,new.created_audit_event_id,new.created_at
     ) is distinct from row(
       old.id,old.organization_id,old.board_id,old.member_id,old.session_id,old.client_id,
       old.access_token_record_id,old.token_jti,old.terms_version_id,old.support_version_id,
       old.presentation_choice,old.local_memory_choice,old.request_sha256,
       old.stage_token_sha256,old.safe_response_sha256,old.idempotency_record_id,
       old.exact_origin,old.expires_at,old.created_audit_event_id,old.created_at
     ) then
    raise exception 'onboarding browser stage binding is immutable' using errcode='55000';
  end if;
  if old.state<>'active' or new.state not in ('completed','expired') then
    raise exception 'illegal onboarding browser stage transition: % -> %',old.state,new.state
      using errcode='23514';
  end if;
  if (new.state='completed' and
      (new.completed_at is distinct from transaction_timestamp()
       or new.attested_audit_event_id is null))
     or (new.state='expired' and
         ((old.expires_at>transaction_timestamp() and not maintenance)
          or new.completed_at is not null or new.attested_audit_event_id is not null)) then
    raise exception 'onboarding browser stage terminal evidence is invalid' using errcode='23514';
  end if;
  return new;
end
$$;

create or replace function public.boardagent_snapshot_key_maintenance_work(
  candidate_instance_id uuid,candidate_organization_id uuid,candidate_key_id uuid
) returns jsonb
language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare
  dependency_inventory jsonb;
  work record;
  row_digest record;
  total_references bigint:=0;
  reference_count bigint;
  chain bytea;
  groups jsonb:='[]'::jsonb;
begin
  -- Reuse exact target, purpose, operator, snapshot-mode and unknown-FK policy checks.
  dependency_inventory:=public.boardagent_snapshot_key_dependencies(
    candidate_instance_id,candidate_organization_id,candidate_key_id);
  for work in select * from (values
    ('active_contact_points',$query$select to_jsonb(c) as value from public.member_contact_points c where c.organization_id=$1 and c.key_id=$2 and c.state='active'$query$),
    ('active_totp',$query$select to_jsonb(t) as value from public.totp_credentials t where t.organization_id=$1 and t.key_id=$2 and t.state='active'$query$),
    ('active_webhooks',$query$select to_jsonb(w) as value from public.member_webhooks w where w.organization_id=$1 and public.boardagent_key_webhook_exposed(w.id,$2) and w.state='active'$query$),
    ('affected_refresh_families',$query$select to_jsonb(f) as value from public.refresh_families f where f.organization_id=$1 and f.state='active' and ($3='browser_session' or ($3='oauth_signing' and exists(select 1 from public.access_token_records a where a.refresh_family_id=f.id and a.signing_key_id=$2)) or ($3='data_kek' and public.boardagent_key_data_member($1,$2,f.member_id)))$query$),
    ('browser_action_stages',$query$select jsonb_build_object('kind','action_stage','row',to_jsonb(s)) as value from public.action_stages s where s.organization_id=$1 and ($3='browser_session' or ($3='data_kek' and public.boardagent_key_data_member($1,$2,s.actor_member_id))) and s.state='active' union all select jsonb_build_object('kind','onboarding_stage','row',to_jsonb(t)) as value from public.onboarding_browser_stages t where t.organization_id=$1 and ($3='browser_session' or ($3='data_kek' and public.boardagent_key_data_member($1,$2,t.member_id))) and t.state='active'$query$),
    ('browser_authorization_requests',$query$select to_jsonb(a) as value from public.oauth_authorization_requests a where a.organization_id=$1 and ($3='browser_session' or ($3='data_kek' and public.boardagent_key_data_member($1,$2,coalesce(a.member_id,(select member_id from public.auth_sessions where id=a.session_id))))) and a.request_state in ('pending','approved')$query$),
    ('browser_sessions',$query$select to_jsonb(s) as value from public.auth_sessions s where s.organization_id=$1 and ($3='browser_session' or ($3='data_kek' and public.boardagent_key_data_member($1,$2,s.member_id))) and s.state in ('anonymous','authenticated')$query$),
    ('closing_votes',$query$select to_jsonb(v) as value from public.votes v where v.organization_id=$1 and v.state='closing' and $3='evidence_signing'$query$),
    ('leased_jobs',$query$select to_jsonb(j) as value from public.jobs j where j.organization_id=$1 and j.state='leased'$query$),
    ('leased_notifications',$query$select to_jsonb(n) as value from public.notification_jobs n where n.organization_id=$1 and n.state='leased'$query$),
    ('live_vote_close_stages',$query$select jsonb_build_object('material',to_jsonb(m),'stage',to_jsonb(s)) as value from public.vote_close_stage_material m join public.action_stages s on s.id=m.stage_id where m.organization_id=$1 and m.signing_key_id=$2 and s.state='active' and s.expires_at>transaction_timestamp()$query$),
    ('pending_exports',$query$select to_jsonb(e) as value from public.export_requests e where e.organization_id=$1 and e.state in ('confirmed','queued')$query$),
    ('pending_totp',$query$select to_jsonb(t) as value from public.totp_credentials t where t.organization_id=$1 and t.key_id=$2 and t.state='pending_verification'$query$),
    ('running_exports',$query$select to_jsonb(e) as value from public.export_requests e where e.organization_id=$1 and e.state='running'$query$),
    ('unfinished_jobs',$query$select to_jsonb(j) as value from public.jobs j where j.organization_id=$1 and j.state in ('queued','retry')$query$),
    ('unfinished_vote_outcomes',$query$select jsonb_build_object('outcome',to_jsonb(o),'vote',to_jsonb(v)) as value from public.vote_outcomes o join public.votes v on v.id=o.vote_id where o.organization_id=$1 and o.signing_key_id=$2 and (v.state='closing' or not exists(select 1 from public.vote_certificates c where c.id=o.certificate_id))$query$)
  ) as facts(name,query_text) order by name collate "C" loop
    execute 'select count(*) from ('||work.query_text||' limit $4) bounded'
      into reference_count using candidate_organization_id,candidate_key_id,
        dependency_inventory->>'keyPurpose',1000001-total_references;
    if total_references+reference_count>1000000 then
      raise exception 'key maintenance work exceeds supported inventory capacity' using errcode='54000';
    end if;
    total_references:=total_references+reference_count;
    chain:=decode(repeat('00',32),'hex');
    for row_digest in execute
      'select sha256(convert_to(value::text,''UTF8'')) as digest from ('||work.query_text||') selected order by digest'
      using candidate_organization_id,candidate_key_id,dependency_inventory->>'keyPurpose'
    loop
      chain:=sha256(chain||row_digest.digest);
    end loop;
    groups:=groups||jsonb_build_array(jsonb_build_object(
      'name',work.name,'rowCount',reference_count::text,'rowsSha256',encode(chain,'hex')));
  end loop;
  return jsonb_build_object('schemaVersion','boardagent.key-maintenance-work.v1',
    'keyDependencies',dependency_inventory,'groups',groups,
    'totalWorkReferences',total_references::text);
end;
$$;

create or replace function public.boardagent_begin_key_lifecycle(candidate_request bytea,candidate_sha256 bytea,candidate_inventory bytea)
returns table(operation_id uuid,replayed boolean,details jsonb)
language plpgsql volatile security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare candidate_id uuid; stored public.key_lifecycle_operations%rowtype; replacement jsonb; affected bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'key lifecycle requires a serializable operator transaction' using errcode='25000';
  end if;
  begin
    if candidate_request is null or octet_length(candidate_request) not between 2 and 262144
      or candidate_sha256 is distinct from sha256(candidate_request) then raise exception 'invalid request'; end if;
    candidate_id:=(convert_from(candidate_request,'UTF8')::jsonb->>'operationId')::uuid;
  exception when others then
    raise exception 'invalid key lifecycle request' using errcode='55000';
  end;
  perform 1 from public.audit_chain_head where singleton_key for update;
  select op.* into stored from public.key_lifecycle_operations op where op.id=candidate_id;
  if stored.id is not null then
    if stored.canonical_request is distinct from candidate_request or stored.request_sha256 is distinct from candidate_sha256
      or stored.canonical_inventory is distinct from candidate_inventory
      or not exists(select 1 from public.key_lifecycle_completions c where c.operation_id=stored.id) then
      raise exception 'key operation identifier belongs to a different or incomplete operation' using errcode='55000';
    end if;
    return query select stored.id,true,stored.details; return;
  end if;
  insert into public.key_lifecycle_operations(id,canonical_request,request_sha256,canonical_inventory)
    values(candidate_id,candidate_request,candidate_sha256,candidate_inventory) returning * into stored;
  update public.crypto_key_registry set
    retired_at=(stored.details#>>'{after,retiredAt}')::timestamptz,
    compromised_at=(stored.details#>>'{after,compromisedAt}')::timestamptz where id=stored.key_id;
  if not found then raise exception 'key transition did not apply' using errcode='55000'; end if;
  if stored.replacement_key_id is not null then
    replacement:=convert_from(stored.canonical_request,'UTF8')::jsonb->'replacement';
    insert into public.crypto_key_registry(id,organization_id,kid,purpose,algorithm,public_jwk,
      nonsecret_locator,activated_at) values(stored.replacement_key_id,stored.organization_id,
      replacement->>'kid',stored.details->>'purpose',replacement->>'algorithm',nullif(replacement->'publicJwk','null'::jsonb),replacement->>'nonsecretLocator',stored.recorded_at);
  end if;
  if stored.details->>'purpose'='browser_session' or (stored.details->>'purpose' in ('oauth_signing','data_kek') and stored.details->>'operation'='mark_compromised') then
    insert into public.key_lifecycle_affected_families(operation_id,family_id)
      select stored.id,f.id from public.refresh_families f
      where f.organization_id=stored.organization_id and f.state='active'
        and (public.boardagent_key_lifecycle_member_scope(stored.id,f.member_id)
          or (stored.details->>'purpose'='oauth_signing' and exists(select 1 from public.access_token_records token where token.refresh_family_id=f.id and token.signing_key_id=stored.key_id)))
      order by f.id;
    get diagnostics affected=row_count;
    if affected::text<>stored.details#>>'{effects,revokedRefreshFamilies}' then
      raise exception 'refresh revocation inventory changed' using errcode='55000';
    end if;
    update public.refresh_families family set state='revoked',revoked_at=stored.recorded_at
      from public.key_lifecycle_affected_families effect
      where effect.operation_id=stored.id and effect.family_id=family.id;
    get diagnostics affected=row_count;
    if affected::text<>stored.details#>>'{effects,revokedRefreshFamilies}' then
      raise exception 'refresh revocation was incomplete' using errcode='23514';
    end if;
  end if;
  if stored.details->>'purpose'='browser_session' or (stored.details->>'purpose'='data_kek' and stored.details->>'operation'='mark_compromised') then
    insert into public.key_lifecycle_browser_effects(operation_id,target_type,target_id,session_id)
      select stored.id,'session',t.id,t.id from public.auth_sessions t
        where public.boardagent_key_lifecycle_member_scope(stored.id,t.member_id) and t.organization_id=stored.organization_id and t.state in ('anonymous','authenticated') order by t.id;
    update public.auth_sessions t set state='revoked' from public.key_lifecycle_browser_effects effect
      where effect.operation_id=stored.id and effect.target_type='session' and effect.target_id=t.id;
    insert into public.key_lifecycle_browser_effects(operation_id,target_type,target_id,authorization_request_id)
      select stored.id,'authorization_request',t.id,t.id from public.oauth_authorization_requests t
        where public.boardagent_key_lifecycle_member_scope(stored.id,coalesce(t.member_id,(select member_id from public.auth_sessions where id=t.session_id))) and t.organization_id=stored.organization_id and t.request_state in ('pending','approved') order by t.id;
    update public.oauth_authorization_requests t set request_state='expired' from public.key_lifecycle_browser_effects effect
      where effect.operation_id=stored.id and effect.target_type='authorization_request' and effect.target_id=t.id;
    insert into public.key_lifecycle_browser_effects(operation_id,target_type,target_id,action_stage_id)
      select stored.id,'action_stage',t.id,t.id from public.action_stages t
        where public.boardagent_key_lifecycle_member_scope(stored.id,t.actor_member_id) and t.organization_id=stored.organization_id and t.state='active' order by t.id;
    update public.action_stages t set state='cancelled',cancelled_at=stored.recorded_at from public.key_lifecycle_browser_effects effect
      where effect.operation_id=stored.id and effect.target_type='action_stage' and effect.target_id=t.id;
  end if;
  if stored.details->>'purpose'='browser_session' or (stored.details->>'purpose'='data_kek' and stored.details->>'operation'='mark_compromised') then
    insert into public.key_lifecycle_browser_effects(operation_id,target_type,target_id,onboarding_stage_id)
      select stored.id,'onboarding_stage',t.id,t.id from public.onboarding_browser_stages t
        where public.boardagent_key_lifecycle_member_scope(stored.id,t.member_id) and t.organization_id=stored.organization_id and t.state='active' order by t.id;
    update public.onboarding_browser_stages t set state='expired' from public.key_lifecycle_browser_effects effect
      where effect.operation_id=stored.id and effect.target_type='onboarding_stage' and effect.target_id=t.id;
  end if;
  if stored.details->>'purpose'='data_kek' then
    insert into public.key_lifecycle_totp_effects(operation_id,credential_id)
      select stored.id,t.id from public.totp_credentials t where t.organization_id=stored.organization_id and t.key_id=stored.key_id
        and (t.state='pending_verification' or (t.state='active' and stored.details->>'operation'='mark_compromised')) order by t.id;
    update public.totp_credentials t set state=case when stored.details->>'operation'='mark_compromised' then 'compromised' else 'disabled' end,
      terminal_at=stored.recorded_at,failed_attempts=0,locked_until=null from public.key_lifecycle_totp_effects e
      where e.operation_id=stored.id and e.credential_id=t.id;
  end if;
  if stored.details->>'purpose'='data_kek' and stored.details->>'operation' in ('retire','mark_compromised') then
    insert into public.key_lifecycle_webhook_disables(operation_id,webhook_id)
      select stored.id,w.id from public.member_webhooks w where w.organization_id=stored.organization_id and w.state='active'
        and (w.key_id=stored.key_id or (stored.details->>'operation'='mark_compromised' and public.boardagent_key_webhook_exposed(w.id,stored.key_id))) order by w.id;
    update public.member_webhooks w set state='disabled',generation=w.generation+1,updated_at=stored.recorded_at,disabled_at=stored.recorded_at
      from public.key_lifecycle_webhook_disables e where e.operation_id=stored.id and e.webhook_id=w.id;
  end if;
  if stored.details->>'purpose'='data_kek' and stored.details->>'operation'='mark_compromised' then
    insert into public.key_lifecycle_contact_effects(operation_id,contact_id)
      select stored.id,c.id from public.member_contact_points c where c.organization_id=stored.organization_id and c.key_id=stored.key_id and c.state='active' order by c.id;
    update public.member_contact_points c set state='revoked' from public.key_lifecycle_contact_effects e where e.operation_id=stored.id and e.contact_id=c.id;
  end if;
  return query select stored.id,false,stored.details;
end;
$$;

create or replace function public.boardagent_guard_member_webhook_update()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
set timezone='UTC' set datestyle='ISO,YMD' set intervalstyle='iso_8601' set bytea_output='hex' set extra_float_digits=3
as $$
begin
  if current_user='boardagent_migrator' and current_setting('boardagent.transaction_scope',true)='bootstrap' then
    if exists(select 1 from public.key_lifecycle_webhook_rewraps e join public.key_lifecycle_operations op on op.id=e.operation_id
      where e.webhook_id=old.id and op.organization_id=old.organization_id
        and op.authorization_transaction_id=pg_current_xact_id() and op.authorization_server_start=pg_postmaster_start_time()
        and e.before_sha256=sha256(convert_to(to_jsonb(old)::text,'UTF8'))
        and e.after_sha256=sha256(convert_to(to_jsonb(new)::text,'UTF8'))) then return new; end if;
  end if;
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
