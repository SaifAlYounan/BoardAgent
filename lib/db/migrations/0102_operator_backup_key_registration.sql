-- Commission an externally held backup KEK through the trusted migrator only.
-- An exact retry is harmless; replacement/rotation requires a separate lifecycle.
create function public.boardagent_register_backup_key(
  candidate_organization_id uuid,
  candidate_key_id uuid,
  candidate_fingerprint_sha256 text
)
returns table(result_key_id uuid,replayed boolean)
language plpgsql volatile security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  stored public.crypto_key_registry%rowtype;
  candidate_kid text := 'backup-' || candidate_key_id::text;
  candidate_locator text := 'sha256:' || candidate_fingerprint_sha256;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or candidate_key_id is null
     or not public.boardagent_is_uuid_v7(candidate_key_id)
     or candidate_fingerprint_sha256 is null
     or candidate_fingerprint_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid backup-key registration' using errcode='22023';
  end if;
  if not exists (
    select 1 from public.system_instance as instance
     where instance.singleton_key and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'backup-key organization is not the bootstrapped instance' using errcode='23503';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('backup_kek',424247));
  select key.* into stored from public.crypto_key_registry as key
   where key.organization_id=candidate_organization_id and key.purpose='backup_kek'
     and key.retired_at is null and key.compromised_at is null
   order by key.activated_at desc,key.id desc limit 1 for update;
  if stored.id is not null then
    if stored.id<>candidate_key_id or stored.kid<>candidate_kid
       or stored.algorithm<>'A256GCM' or stored.public_jwk is not null
       or stored.nonsecret_locator<>candidate_locator then
      raise exception 'a different active backup key already exists' using errcode='23505';
    end if;
    result_key_id:=stored.id; replayed:=true; return next; return;
  end if;
  insert into public.crypto_key_registry(
    id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
  ) values (
    candidate_key_id,candidate_organization_id,candidate_kid,'backup_kek','A256GCM',null,
    candidate_locator,transaction_timestamp()
  );
  result_key_id:=candidate_key_id; replayed:=false; return next;
end;
$$;
alter function public.boardagent_register_backup_key(uuid,uuid,text) owner to boardagent_migrator;
revoke all on function public.boardagent_register_backup_key(uuid,uuid,text) from public;
grant execute on function public.boardagent_register_backup_key(uuid,uuid,text) to boardagent_migrator;
