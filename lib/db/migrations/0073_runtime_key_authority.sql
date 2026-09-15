-- BoardAgent Phase 4 / group 73: purpose-separated runtime-key registration authority.
-- Private material remains outside PostgreSQL. The local operator may register only the
-- public identity and nonsecret locator of one exact externally held key per purpose.

grant select,insert on public.crypto_key_registry to boardagent_migrator;

create policy boardagent_migrator_runtime_key_bootstrap
  on public.crypto_key_registry for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='bootstrap'
    or (
      current_setting('boardagent.transaction_scope',true) in ('identity','request','worker')
      and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    )
  );
create policy boardagent_migrator_runtime_key_insert
  on public.crypto_key_registry for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='bootstrap'
    and exists (
      select 1 from public.system_instance as instance
       where instance.singleton_key
         and instance.organization_id=crypto_key_registry.organization_id
    )
  );

create function public.boardagent_register_runtime_key(
  candidate_organization_id uuid,
  candidate_key_id uuid,
  candidate_kid text,
  candidate_purpose text,
  candidate_algorithm text,
  candidate_public_jwk jsonb,
  candidate_nonsecret_locator text
)
returns table(result_key_id uuid,replayed boolean)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  stored public.crypto_key_registry%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or not public.boardagent_is_uuid_v7(candidate_key_id)
     or candidate_kid is null
     or candidate_kid !~ '^[A-Za-z0-9._-]{1,128}$'
     or candidate_purpose not in (
       'oauth_signing','evidence_signing','browser_session','data_kek'
     )
     or candidate_algorithm is distinct from (case candidate_purpose
       when 'oauth_signing' then 'ES256'
       when 'evidence_signing' then 'EdDSA'
       when 'browser_session' then 'HMAC-SHA256'
       when 'data_kek' then 'A256GCM'
     end)
     or length(candidate_nonsecret_locator) not between 1 and 2048
     or (
       candidate_purpose in ('oauth_signing','evidence_signing')
       and (
         candidate_public_jwk is null
         or jsonb_typeof(candidate_public_jwk)<>'object'
         or candidate_public_jwk ? 'd'
       )
     )
     or (
       candidate_purpose in ('browser_session','data_kek')
       and candidate_public_jwk is not null
     ) then
    raise exception 'invalid runtime-key registration' using errcode='22023';
  end if;
  if not exists (
    select 1 from public.system_instance as instance
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'runtime-key organization is not the bootstrapped instance'
      using errcode='23503';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(candidate_purpose,424247));
  select key.* into stored
    from public.crypto_key_registry as key
   where key.organization_id=candidate_organization_id
     and key.purpose=candidate_purpose
     and key.retired_at is null
     and key.compromised_at is null
   order by key.activated_at desc,key.id desc
   limit 1
   for update;
  if stored.id is not null then
    if stored.id<>candidate_key_id
       or stored.kid<>candidate_kid
       or stored.algorithm<>candidate_algorithm
       or stored.public_jwk is distinct from candidate_public_jwk
       or stored.nonsecret_locator<>candidate_nonsecret_locator then
      raise exception 'a different active runtime key already exists for purpose %',candidate_purpose
        using errcode='23505';
    end if;
    result_key_id:=stored.id;
    replayed:=true;
    return next;
    return;
  end if;

  insert into public.crypto_key_registry(
    id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
  ) values (
    candidate_key_id,candidate_organization_id,candidate_kid,candidate_purpose,
    candidate_algorithm,candidate_public_jwk,candidate_nonsecret_locator,
    transaction_timestamp()
  );
  result_key_id:=candidate_key_id;
  replayed:=false;
  return next;
end;
$$;

alter function public.boardagent_register_runtime_key(uuid,uuid,text,text,text,jsonb,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_register_runtime_key(uuid,uuid,text,text,text,jsonb,text)
  from public;
grant execute on function public.boardagent_register_runtime_key(uuid,uuid,text,text,text,jsonb,text)
  to boardagent_migrator;
