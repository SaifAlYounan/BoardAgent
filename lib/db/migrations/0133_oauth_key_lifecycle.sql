-- OAuth signing-key maintenance and exact refresh-family revocation evidence.
create table public.key_lifecycle_affected_families (
  operation_id uuid not null references public.key_lifecycle_operations(id) on delete restrict,
  family_id uuid not null references public.refresh_families(id) on delete restrict,
  before_sha256 bytea not null check (octet_length(before_sha256)=32),
  after_sha256 bytea not null check (octet_length(after_sha256)=32),
  primary key(operation_id,family_id)
);
alter table public.key_lifecycle_affected_families owner to boardagent_migrator;
alter table public.key_lifecycle_affected_families enable row level security;
alter table public.key_lifecycle_affected_families force row level security;
revoke all on public.key_lifecycle_affected_families from public;
grant select on public.key_lifecycle_affected_families to boardagent_backup;
create policy boardagent_key_family_operator_read on public.key_lifecycle_affected_families
  for select to boardagent_migrator using (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_key_family_operator_insert on public.key_lifecycle_affected_families
  for insert to boardagent_migrator with check (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_key_family_backup_read on public.key_lifecycle_affected_families
  for select to boardagent_backup using (true);
create trigger boardagent_immutable before update or delete on public.key_lifecycle_affected_families
  for each row execute function public.boardagent_reject_evidence_mutation();

create function public.boardagent_key_lifecycle_state(candidate_key_id uuid)
returns jsonb language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare k public.crypto_key_registry%rowtype; fingerprint text; coordinate text;
begin
  select key.* into k from public.crypto_key_registry key where key.id=candidate_key_id;
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
  return jsonb_build_object('keyId',k.id,'kid',k.kid,'algorithm',k.algorithm,
    'publicMaterialSha256',fingerprint,
    'activatedAt',to_char(k.activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'retiredAt',to_char(k.retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'compromisedAt',to_char(k.compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
end;
$$;
alter function public.boardagent_key_lifecycle_state(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_lifecycle_state(uuid) from public;

create function public.boardagent_guard_key_lifecycle_family()
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
    or op.details->>'purpose'<>'oauth_signing' or op.details->>'operation'<>'mark_compromised' then
    raise exception 'refresh revocation lacks a current key operation' using errcode='23514';
  end if;
  select f.* into family from public.refresh_families f where f.id=new.family_id for update;
  if family.id is null or family.organization_id<>op.organization_id or family.state<>'active'
    or not exists(select 1 from public.access_token_records a where a.refresh_family_id=family.id and a.signing_key_id=op.key_id) then
    raise exception 'refresh family is outside the key operation' using errcode='23514';
  end if;
  new.before_sha256:=sha256(convert_to(to_jsonb(family)::text,'UTF8'));
  new.after_sha256:=sha256(convert_to((to_jsonb(family)||jsonb_build_object('state','revoked','revoked_at',op.recorded_at))::text,'UTF8'));
  return new;
end;
$$;
alter function public.boardagent_guard_key_lifecycle_family() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_lifecycle_family() from public;
create trigger boardagent_key_family_guard before insert on public.key_lifecycle_affected_families
  for each row execute function public.boardagent_guard_key_lifecycle_family();

grant update(state,revoked_at) on public.refresh_families to boardagent_migrator;
create policy boardagent_key_family_revocation on public.refresh_families for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.key_lifecycle_operations op
      where op.authorization_transaction_id=pg_current_xact_id()
        and op.authorization_server_start=pg_postmaster_start_time()
        and op.organization_id=refresh_families.organization_id
        and op.details->>'purpose'='oauth_signing' and op.details->>'operation'='mark_compromised'
        and exists(select 1 from public.access_token_records token
          where token.refresh_family_id=refresh_families.id and token.signing_key_id=op.key_id)))
  with check (current_setting('boardagent.transaction_scope',true)='bootstrap' and exists(
    select 1 from public.key_lifecycle_affected_families effect join public.key_lifecycle_operations op on op.id=effect.operation_id
      where effect.family_id=refresh_families.id and op.authorization_transaction_id=pg_current_xact_id()
        and op.authorization_server_start=pg_postmaster_start_time()));

create function public.boardagent_key_lifecycle_families_match(candidate_operation_id uuid)
returns boolean language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare op public.key_lifecycle_operations%rowtype; actual_count bigint;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=candidate_operation_id;
  if op.id is null then return false; end if;
  select count(*) into actual_count from public.key_lifecycle_affected_families effect where effect.operation_id=op.id;
  return actual_count::text=op.details#>>'{effects,revokedRefreshFamilies}'
    and not exists(select 1 from public.key_lifecycle_affected_families effect
      left join public.refresh_families family on family.id=effect.family_id
      where effect.operation_id=op.id and (family.id is null
        or effect.after_sha256 is distinct from sha256(convert_to(to_jsonb(family)::text,'UTF8'))));
end;
$$;
alter function public.boardagent_key_lifecycle_families_match(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_lifecycle_families_match(uuid) from public;

-- GENERALIZED TRANSITIONS
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
  if op.id is null or public.boardagent_key_lifecycle_families_match(op.id) is distinct from true then return false; end if;
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
      or request->>'purpose' not in ('evidence_signing','oauth_signing')
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
  algorithm:=case when request->>'purpose'='oauth_signing' then 'ES256' else 'EdDSA' end;
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
        or jsonb_typeof(new_public) is distinct from 'object'
        or exists(select 1 from jsonb_each(new_public) f where jsonb_typeof(f.value)<>'string')
        or request->'declaredCompromisedAt'<>'null'::jsonb then
        raise exception 'invalid replacement';
      end if;
      new.replacement_key_id:=(replacement->>'keyId')::uuid;
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
      locator:=replacement->>'nonsecretLocator';
      if not public.boardagent_is_uuid_v7(new.replacement_key_id)
        or replacement->>'keyId'<>new.replacement_key_id::text
        or new.replacement_key_id=new.key_id or fingerprint<>replacement->>'materialSha256'
        or fingerprint=previous->>'publicMaterialSha256'
        or replacement->>'kid'!~'^[A-Za-z0-9._-]{1,128}$'
        or replacement->>'kid'=previous->>'kid'
        or length(locator) not between 7 and 2048 or locator not like 'file:/%'
        or locator~'[[:cntrl:]]' or locator<>normalize(locator,NFC)
        or substr(locator,6)~'//' or substr(locator,6)~'(^|/)\.{1,2}(/|$)'
        or right(locator,1)='/' then raise exception 'invalid replacement'; end if;
      if exists(select 1 from public.crypto_key_registry k where k.id=new.replacement_key_id
          or (k.organization_id=new.organization_id and k.kid=replacement->>'kid'))
        or exists(select 1 from public.crypto_key_registry k where k.organization_id=new.organization_id
          and k.purpose=request->>'purpose' and k.retired_at is null and k.compromised_at is null and k.id<>new.key_id) then
        raise exception 'replacement conflicts with a registered key';
      end if;
    exception when others then
      raise exception 'evidence key replacement is invalid or no longer applicable' using errcode='55000';
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
    'effects',jsonb_build_object('revokedSessions','0','revokedRefreshFamilies',
      case when request->>'purpose'='oauth_signing' and request->>'operation'='mark_compromised' then affected_families else '0' end,'cancelledStages','0',
      'affectedTotp','0','disabledWebhooks','0','rewrappedWebhooks','0'));
  return new;
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
      replacement->>'kid',stored.details->>'purpose',replacement->>'algorithm',replacement->'publicJwk',replacement->>'nonsecretLocator',stored.recorded_at);
  end if;
  if stored.details->>'purpose'='oauth_signing' and stored.details->>'operation'='mark_compromised' then
    insert into public.key_lifecycle_affected_families(operation_id,family_id)
      select stored.id,f.id from public.refresh_families f
      where f.organization_id=stored.organization_id and f.state='active'
        and exists(select 1 from public.access_token_records token where token.refresh_family_id=f.id and token.signing_key_id=stored.key_id)
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
  return query select stored.id,false,stored.details;
end;
$$;
