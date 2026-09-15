-- A recovery checkpoint can cross the historical time window only inside the
-- operator transaction that owns the exact immutable request. Normal v1 is unchanged.
create unique index boardagent_one_recovery_per_transaction
  on public.audit_recoveries(authorization_server_start,authorization_transaction_id);
alter table public.audit_checkpoints
  add column recovery_id uuid references public.audit_recoveries(id) on delete restrict,
  add column attestation_origin text check (attestation_origin in ('worker','cli')),
  add column attestation_server_start timestamptz;

create or replace function public.boardagent_guard_audit_checkpoint_insert()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  manifest jsonb;
  expected_manifest jsonb;
  instance_row public.system_instance%rowtype;
  head public.audit_chain_head%rowtype;
  evidence_key public.crypto_key_registry%rowtype;
  recovery public.audit_recoveries%rowtype;
  first_event public.audit_events%rowtype;
  last_event public.audit_events%rowtype;
  expected_first bigint;
  expected_last bigint;
  issued_at timestamptz;
  observed_at timestamptz;
  missed_microseconds bigint;
  is_recovery boolean;
begin
  begin
    manifest:=convert_from(new.canonical_manifest,'UTF8')::jsonb;
    issued_at:=(manifest->>'issuedAt')::timestamptz;
  exception when others then
    raise exception 'audit checkpoint manifest is invalid' using errcode='23514';
  end;
  select * into strict instance_row from public.system_instance where singleton_key;
  select * into strict head from public.audit_chain_head where singleton_key for update;
  select coalesce(max(checkpoint.last_sequence),0)+1 into expected_first from public.audit_checkpoints as checkpoint;
  select event.* into first_event from public.audit_events as event where event.sequence=new.first_sequence;
  select event.* into last_event from public.audit_events as event where event.sequence=new.last_sequence;
  select key.* into evidence_key from public.crypto_key_registry as key where key.id=new.signing_key_id;
  observed_at:=clock_timestamp();
  if current_setting('boardagent.transaction_scope',true)='bootstrap'
     and current_setting('transaction_isolation')='serializable' then
    select stored.* into recovery from public.audit_recoveries as stored
      where stored.authorization_transaction_id=pg_current_xact_id()
        and stored.authorization_server_start=pg_postmaster_start_time()
        and stored.expires_at>observed_at;
  end if;
  is_recovery:=manifest->>'schema'='boardagent.audit.recovery-checkpoint.v1';
  expected_last:=least(head.last_sequence,expected_first+999);
  if is_recovery then
    if recovery.id is null or recovery.organization_id<>new.organization_id
       or recovery.signing_key_id<>new.signing_key_id
       or issued_at<recovery.authorized_at or issued_at>=recovery.expires_at then
      raise exception 'checkpoint recovery is not authorized in this transaction' using errcode='23514';
    end if;
    expected_last:=least(recovery.last_sequence,expected_first+999);
    missed_microseconds:=(extract(epoch from (issued_at-first_event.occurred_at-interval '15 minutes'))*1000000)::bigint;
    if missed_microseconds is null or missed_microseconds<=0
       or manifest->'recovery' is distinct from jsonb_build_object(
         'request',convert_from(recovery.canonical_request,'UTF8')::jsonb,
         'requestSha256',encode(recovery.request_sha256,'hex'),
         'firstCoveredEventAt',to_char(first_event.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
         'missedByMicroseconds',missed_microseconds::text
       ) then
      raise exception 'checkpoint recovery does not describe its actual authorized missed interval' using errcode='23514';
    end if;
  elsif manifest->>'schema' is distinct from 'boardagent.audit.checkpoint.v1' then
    raise exception 'unsupported audit checkpoint format' using errcode='23514';
  end if;
  expected_manifest:=jsonb_build_object(
    'schema',case when is_recovery then 'boardagent.audit.recovery-checkpoint.v1' else 'boardagent.audit.checkpoint.v1' end,
    'checkpointId',new.id::text,'instanceId',instance_row.instance_id::text,
    'organizationId',new.organization_id::text,'auditSchema','boardagent.audit-event.v1',
    'firstSequence',new.first_sequence::text,'lastSequence',new.last_sequence::text,
    'firstEventSha256',encode(new.first_event_sha256,'hex'),
    'lastEventSha256',encode(new.last_event_sha256,'hex'),
    'issuedAt',manifest->>'issuedAt','signingKeyId',new.signing_key_id::text,'keyId',evidence_key.kid
  );
  if is_recovery then expected_manifest:=expected_manifest||jsonb_build_object('recovery',manifest->'recovery'); end if;
  if manifest is distinct from expected_manifest or issued_at is null
     or new.manifest_sha256 is distinct from sha256(new.canonical_manifest)
     or new.organization_id<>instance_row.organization_id
     or new.first_sequence<>expected_first or new.last_sequence<>expected_last
     or new.last_sequence<new.first_sequence or new.last_sequence-new.first_sequence>=1000
     or first_event.id is null or last_event.id is null
     or first_event.organization_id<>new.organization_id or last_event.organization_id<>new.organization_id
     or new.first_event_sha256<>first_event.event_sha256 or new.last_event_sha256<>last_event.event_sha256
     or issued_at is distinct from new.created_at or issued_at>observed_at or issued_at<observed_at-interval '15 minutes'
     or evidence_key.id is null or evidence_key.organization_id<>new.organization_id
     or evidence_key.purpose<>'evidence_signing' or evidence_key.algorithm<>'EdDSA'
     or (recovery.id is not null and recovery.signing_key_id<>new.signing_key_id)
     or evidence_key.public_jwk is null or evidence_key.activated_at>issued_at
     or (evidence_key.retired_at is not null and evidence_key.retired_at<=observed_at)
     or evidence_key.compromised_at is not null
     or exists(select 1 from public.audit_events as event where event.sequence between new.first_sequence and new.last_sequence
       and event.organization_id<>new.organization_id) then
    raise exception 'audit checkpoint does not bind the exact next chain segment and evidence key' using errcode='23514';
  end if;
  new.recovery_id:=recovery.id;
  new.attestation_origin:=case when recovery.id is null then 'worker' else 'cli' end;
  new.attestation_transaction_id:=pg_current_xact_id();
  new.attestation_server_start:=pg_postmaster_start_time();
  new.attestation_sequence:=head.last_sequence+1;
  return new;
end;
$$;
alter function public.boardagent_guard_audit_checkpoint_insert() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_checkpoint_insert() from public;

create or replace function public.boardagent_guard_checkpoint_cadence()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  oldest_at timestamptz;
  manifest jsonb;
begin
  select event.occurred_at into strict oldest_at from public.audit_events as event
    where event.sequence=new.first_sequence and event.organization_id=new.organization_id;
  manifest:=convert_from(new.canonical_manifest,'UTF8')::jsonb;
  if manifest->>'schema'='boardagent.audit.recovery-checkpoint.v1' then
    -- The insert guard also checks exact schema, interval, time, key and request. This
    -- independent check works regardless of BEFORE-trigger alphabetical ordering.
    if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
       or not exists(select 1 from public.audit_recoveries as recovery
         where recovery.id::text=manifest->'recovery'->'request'->>'recoveryId'
           and recovery.authorization_transaction_id=pg_current_xact_id()
           and recovery.authorization_server_start=pg_postmaster_start_time()
           and recovery.request_sha256=decode(manifest->'recovery'->>'requestSha256','hex')
           and recovery.expires_at>clock_timestamp()) then
      raise exception 'late checkpoint requires current operator authorization' using errcode='23514';
    end if;
  elsif new.created_at<oldest_at or new.created_at-oldest_at>interval '15 minutes' then
    raise exception 'checkpoint cannot satisfy the historical signing time window' using errcode='23514';
  end if;
  return new;
end;
$$;
alter function public.boardagent_guard_checkpoint_cadence() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_checkpoint_cadence() from public;

-- Preserve atomic business admission, with the guarded signer origin and incarnation.
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
  -- The only special append is a checkpoint's matching, single-use attestation.
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
