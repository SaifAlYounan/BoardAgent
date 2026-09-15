-- Install an attributable recovery upgrade even when ordinary audit admission is full.
-- Only the exact receipt of a newly inserted ledger entry can cross that boundary.
-- Old ledger entries stay byte-for-byte unchanged in their published fields.
alter table public.schema_migrations
  add column audit_transaction_id xid8,
  add column audit_server_start timestamptz,
  add column audit_sequence bigint,
  add constraint boardagent_migration_audit_binding_shape check (
    (audit_transaction_id is null and audit_server_start is null and audit_sequence is null)
    or (audit_transaction_id is not null and audit_server_start is not null and audit_sequence>0)
  );

create function public.boardagent_bind_migration_audit()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare head public.audit_chain_head%rowtype;
begin
  -- Runtime roles have no ledger INSERT or metadata UPDATE privileges. Never accept
  -- supplied transaction coordinates, including during an unbootstrapped install.
  new.audit_transaction_id:=null;
  new.audit_server_start:=null;
  new.audit_sequence:=null;
  if exists(select 1 from public.system_instance where singleton_key) then
    if current_setting('boardagent.transaction_scope',true) is distinct from 'migration'
       or new.version not between 1 and 9999
       or new.name!~'^[0-9]{4}_[a-z0-9_]+\.sql$'
       or left(new.name,4)::integer<>new.version
       or length(new.app_build) not between 1 and 256 then
      raise exception 'new migration evidence requires a managed bounded migration'
        using errcode='23514';
    end if;
    select * into strict head from public.audit_chain_head where singleton_key for update;
    new.audit_transaction_id:=pg_current_xact_id();
    new.audit_server_start:=pg_postmaster_start_time();
    new.audit_sequence:=head.last_sequence+1;
  end if;
  return new;
end;
$$;
alter function public.boardagent_bind_migration_audit() owner to boardagent_migrator;
revoke all on function public.boardagent_bind_migration_audit() from public;
create trigger boardagent_migration_audit_binding before insert on public.schema_migrations
  for each row execute function public.boardagent_bind_migration_audit();

create function public.boardagent_require_migration_audit()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
begin
  if new.audit_transaction_id is not null and not exists (
    select 1 from public.audit_events as event
    join public.system_instance as instance on instance.singleton_key
    where event.sequence=new.audit_sequence and event.organization_id=instance.organization_id
      and event.event_type='migration_applied' and event.object_type='schema_migration'
      and event.object_id is null and event.actor_member_id is null and event.client_id is null
      and event.token_jti is null and event.board_id is null
      and convert_from(event.canonical_payload,'UTF8')::jsonb->>'origin'='migration'
      and convert_from(event.canonical_payload,'UTF8')::jsonb->>'entityId'=new.name
      and convert_from(event.canonical_payload,'UTF8')::jsonb->'details'=jsonb_build_object(
        'version',new.version,'name',new.name,'sha256',new.sha256,'appBuild',new.app_build)
  ) then
    raise exception 'new migration cannot commit without its exact retained audit receipt'
      using errcode='23514';
  end if;
  return null;
end;
$$;
alter function public.boardagent_require_migration_audit() owner to boardagent_migrator;
revoke all on function public.boardagent_require_migration_audit() from public;
create constraint trigger boardagent_migration_audit_required
  after insert on public.schema_migrations deferrable initially deferred
  for each row execute function public.boardagent_require_migration_audit();

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
  -- A checkpoint's matching, single-use attestation is the other special append.
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
