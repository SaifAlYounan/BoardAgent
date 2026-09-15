-- Preserve auditable incident containment at full signing debt and prevent
-- initial registrars from bypassing successor-key maintenance after retirement.
create or replace function public.boardagent_guard_audit_checkpoint_capacity()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  head public.audit_chain_head%rowtype;
  checkpoint_head bigint;
  body jsonb;
  transaction_id xid8 := pg_current_xact_id();
  server_start timestamptz := pg_postmaster_start_time();
  admitted_start bigint;
  admitted_bytes bigint;
begin
  select * into strict head from public.audit_chain_head where singleton_key for update;
  -- A newly recorded migration owns exactly one next-sequence audit append. The
  -- server incarnation and actual xid prevent old/restored metadata or runtime
  -- caller flags from granting admission. This does not admit ordinary work.
  if new.event_type='migration_applied' and new.object_type='schema_migration'
     and new.object_id is null and new.sequence=head.last_sequence+1
     and new.actor_member_id is null and new.client_id is null and new.token_jti is null
     and new.board_id is null then
    body:=convert_from(new.canonical_payload,'UTF8')::jsonb;
    if body->>'origin'='migration' and exists (
      select 1 from public.schema_migrations as migration
      join public.system_instance as instance on instance.singleton_key
      where migration.audit_transaction_id=transaction_id
        and migration.audit_server_start=server_start
        and migration.audit_sequence=new.sequence
        and instance.organization_id=new.organization_id
        and body->>'entityId'=migration.name
        and body->'details'=jsonb_build_object('version',migration.version,
          'name',migration.name,'sha256',migration.sha256,'appBuild',migration.app_build)
    ) then return new; end if;
  end if;
  -- Only the current applied operator operation owns this exact next-sequence
  -- receipt. Lost signing material must remain containable at full signing debt.
  -- The existing lifecycle trigger still verifies all effects and exact audit bytes;
  -- deferred completion remains mandatory. This does not admit ordinary work.
  if current_setting('boardagent.transaction_scope',true)='bootstrap'
     and new.event_type='key_lifecycle_changed' and new.object_type='key_lifecycle_operation'
     and new.sequence=head.last_sequence+1 and new.id=new.object_id
     and new.actor_member_id is null and new.acting_for_member_id is null
     and new.client_id is null and new.token_jti is null and new.board_id is null
     and new.consent_record_id is null and new.object_version is null then
    body:=convert_from(new.canonical_payload,'UTF8')::jsonb;
    if body->>'origin'='cli' and body->>'entityId'=new.object_id::text and exists (
      select 1 from public.key_lifecycle_operations as operation
      where operation.id=new.object_id and operation.organization_id=new.organization_id
        and operation.authorization_transaction_id=transaction_id
        and operation.authorization_server_start=server_start
        and operation.recorded_at=new.occurred_at
        and body->'details'=operation.details
        and new.sequence=(convert_from(operation.canonical_request,'UTF8')::jsonb
          #>>'{expectedInventory,keyDependencies,auditHead,sequence}')::bigint+1
    ) then return new; end if;
  end if;
  -- A checkpoint owns another matching, single-use attestation.
  -- It cannot establish ordinary transaction admission while signing debt is full.
  if new.event_type='audit_checkpoint_signed' and new.object_type='audit_checkpoint'
     and new.sequence=head.last_sequence+1
     and new.actor_member_id is null and new.client_id is null and new.token_jti is null
     and new.board_id is null then
    body := convert_from(new.canonical_payload,'UTF8')::jsonb;
    if body->>'origin' in ('worker','cli') and body->>'entityId'=new.object_id::text
       and exists (
         select 1 from public.audit_checkpoints as checkpoint
          where checkpoint.id=new.object_id
            and checkpoint.organization_id=new.organization_id
            and checkpoint.attestation_origin=body->>'origin'
            and checkpoint.attestation_server_start=server_start
            and checkpoint.attestation_transaction_id=transaction_id
            and checkpoint.attestation_sequence=new.sequence
            and body->'details'=jsonb_build_object(
              'manifestSha256',encode(checkpoint.manifest_sha256,'hex'),
              'firstSequence',checkpoint.first_sequence::text,
              'lastSequence',checkpoint.last_sequence::text,
              'signedHeadSha256',encode(checkpoint.last_event_sha256,'hex'),
              'signingKeyId',checkpoint.signing_key_id::text)
       ) then
      return new;
    end if;
  end if;

  if head.admission_transaction_id=transaction_id
     and head.admission_server_start=server_start then
    admitted_start := head.admission_start_sequence;
    admitted_bytes := head.admission_payload_bytes;
  else
    select coalesce(max(checkpoint.last_sequence),0) into checkpoint_head
      from public.audit_checkpoints as checkpoint;
    if head.last_sequence-checkpoint_head>=1000 then
      raise exception 'audit checkpoint capacity exhausted; retry after a signed checkpoint'
        using errcode='55000',constraint='boardagent_audit_checkpoint_capacity';
    end if;
    admitted_start := head.last_sequence;
    admitted_bytes := 0;
  end if;

  if head.last_sequence-admitted_start>=10000
     or admitted_bytes+octet_length(new.canonical_payload)>16777216 then
    raise exception 'audit effect exceeds the supported atomic action size'
      using errcode='54000',constraint='boardagent_audit_transaction_capacity';
  end if;

  update public.audit_chain_head set
    admission_transaction_id=transaction_id,
    admission_server_start=server_start,
    admission_start_sequence=admitted_start,
    admission_payload_bytes=admitted_bytes+octet_length(new.canonical_payload)
    where singleton_key;
  return new;
end;
$$;
alter function public.boardagent_guard_audit_checkpoint_capacity() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_checkpoint_capacity() from public;

create or replace function public.boardagent_register_runtime_key(
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

  -- Initial registration cannot restart a purpose with retained history. A trusted
  -- operator must use the audited, inventoried and fenced lifecycle for successors.
  if exists(select 1 from public.crypto_key_registry as prior
    where prior.organization_id=candidate_organization_id and prior.purpose=candidate_purpose) then
    raise exception 'key purpose has retained history; use key-lifecycle replacement'
      using errcode='23505',constraint='boardagent_key_registration_initial_only';
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

create or replace function public.boardagent_register_backup_key(
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
  -- Initial registration cannot restart a purpose with retained history. A trusted
  -- operator must use the audited, inventoried and fenced lifecycle for successors.
  if exists(select 1 from public.crypto_key_registry as prior
    where prior.organization_id=candidate_organization_id and prior.purpose='backup_kek') then
    raise exception 'key purpose has retained history; use key-lifecycle replacement'
      using errcode='23505',constraint='boardagent_key_registration_initial_only';
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
