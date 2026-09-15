-- Backup-key lifecycle preserves every historical key row and recorded generation.
create or replace function public.boardagent_key_lifecycle_state(candidate_key_id uuid)
returns jsonb language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare k public.crypto_key_registry%rowtype; fingerprint text; coordinate text;
begin
  select key.* into k from public.crypto_key_registry key where key.id=candidate_key_id;
  if k.purpose='backup_kek' then
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
      or request->>'purpose' not in ('evidence_signing','oauth_signing','browser_session','backup_kek')
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
  algorithm:=case when request->>'purpose'='oauth_signing' then 'ES256' when request->>'purpose'='browser_session' then 'HMAC-SHA256' when request->>'purpose'='backup_kek' then 'A256GCM' else 'EdDSA' end;
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
        or (request->>'purpose' in ('browser_session','backup_kek') and new_public is distinct from 'null'::jsonb)
        or (request->>'purpose' not in ('browser_session','backup_kek') and jsonb_typeof(new_public) is distinct from 'object')
        or request->'declaredCompromisedAt'<>'null'::jsonb then
        raise exception 'invalid replacement';
      end if;
      new.replacement_key_id:=(replacement->>'keyId')::uuid;
      if request->>'purpose'='backup_kek' then
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
      case when request->>'purpose'='browser_session' then (select g->>'rowCount' from jsonb_array_elements(inventory->'groups') g where g->>'name'='browser_sessions') else '0' end,'revokedRefreshFamilies',
      case when request->>'purpose'='browser_session' or (request->>'purpose'='oauth_signing' and request->>'operation'='mark_compromised') then affected_families else '0' end,'cancelledStages',
      case when request->>'purpose'='browser_session' then (select g->>'rowCount' from jsonb_array_elements(inventory->'groups') g where g->>'name'='browser_action_stages') else '0' end,
      'affectedTotp','0','disabledWebhooks','0','rewrappedWebhooks','0'));
  return new;
end;
$$;
