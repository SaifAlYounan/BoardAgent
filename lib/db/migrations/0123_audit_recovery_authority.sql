-- Recovery authority is an immutable operator record, never a caller-controlled flag.
-- Incomplete attempts cannot commit. Checkpoint acceptance is installed separately.
create table public.audit_recoveries (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  organization_id uuid not null references public.organizations(id) on delete restrict,
  instance_id uuid not null references public.system_instance(instance_id) on delete restrict,
  canonical_request bytea not null check (octet_length(canonical_request) between 2 and 16384),
  request_sha256 bytea not null check (octet_length(request_sha256)=32),
  signing_key_id uuid not null references public.crypto_key_registry(id) on delete restrict,
  first_sequence bigint not null check (first_sequence>0),
  last_sequence bigint not null check (last_sequence>=first_sequence and last_sequence-first_sequence<1000000),
  first_event_sha256 bytea not null check (octet_length(first_event_sha256)=32),
  head_sha256 bytea not null check (octet_length(head_sha256)=32),
  authorized_at timestamptz not null,
  expires_at timestamptz not null,
  authorizing_principal text not null,
  authorization_transaction_id xid8 not null,
  authorization_server_start timestamptz not null
);
create table public.audit_recovery_completions (
  recovery_id uuid primary key references public.audit_recoveries(id) on delete restrict,
  final_checkpoint_id uuid not null references public.audit_checkpoints(id) on delete restrict,
  final_head_sequence bigint not null check (final_head_sequence>0),
  final_head_sha256 bytea not null check (octet_length(final_head_sha256)=32),
  completed_at timestamptz not null
);
alter table public.audit_recoveries owner to boardagent_migrator;
alter table public.audit_recovery_completions owner to boardagent_migrator;
alter table public.audit_recoveries enable row level security;
alter table public.audit_recoveries force row level security;
alter table public.audit_recovery_completions enable row level security;
alter table public.audit_recovery_completions force row level security;
revoke all on public.audit_recoveries,public.audit_recovery_completions from public;
grant select on public.audit_recoveries,public.audit_recovery_completions
  to boardagent_server,boardagent_worker,boardagent_backup;
create policy boardagent_migrator_recovery_read on public.audit_recoveries for select to boardagent_migrator using (true);
create policy boardagent_migrator_recovery_insert on public.audit_recoveries for insert to boardagent_migrator
  with check (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_migrator_recovery_completion_read on public.audit_recovery_completions for select to boardagent_migrator using (true);
create policy boardagent_migrator_recovery_completion_insert on public.audit_recovery_completions for insert to boardagent_migrator
  with check (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_recovery_worker_backup_read on public.audit_recoveries for select to boardagent_worker,boardagent_backup using (true);
create policy boardagent_recovery_completion_worker_backup_read on public.audit_recovery_completions for select to boardagent_worker,boardagent_backup using (true);
create policy boardagent_recovery_server_read on public.audit_recoveries for select to boardagent_server
  using (organization_id=public.boardagent_context_uuid('boardagent.organization_id'));
create policy boardagent_recovery_completion_server_read on public.audit_recovery_completions for select to boardagent_server
  using (exists(select 1 from public.audit_recoveries as recovery where recovery.id=recovery_id));
create trigger boardagent_immutable before update or delete on public.audit_recoveries
  for each row execute function public.boardagent_reject_evidence_mutation();
create trigger boardagent_immutable before update or delete on public.audit_recovery_completions
  for each row execute function public.boardagent_reject_evidence_mutation();

create function public.boardagent_guard_audit_recovery_authorization()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  request jsonb;
  expected_fields text[]:=array['schemaVersion','recoveryId','instanceId','organizationId',
    'firstSequence','lastSequence','firstEventSha256','headSha256','signingKeyId','keyId',
    'firstUncoveredEventAt','preparedAt','expiresAt','operatorReference','reason'];
  instance_row public.system_instance%rowtype;
  head public.audit_chain_head%rowtype;
  evidence_key public.crypto_key_registry%rowtype;
  oldest public.audit_events%rowtype;
  covered bigint;
  prepared timestamptz;
  observed timestamptz;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'recovery authorization requires a serializable operator transaction' using errcode='25000';
  end if;
  begin
    if new.canonical_request is null or octet_length(new.canonical_request)>16384
       or new.request_sha256 is distinct from sha256(new.canonical_request) then
      raise exception 'invalid recovery request';
    end if;
    request:=convert_from(new.canonical_request,'UTF8')::jsonb;
    if jsonb_typeof(request)<>'object' or not request ?& expected_fields
       or request-expected_fields<>'{}'::jsonb
       or exists(select 1 from jsonb_each(request) as field where jsonb_typeof(field.value)<>'string')
       or request->>'schemaVersion'<>'boardagent.audit-recovery-request.v1'
       or request->>'recoveryId' is distinct from new.id::text
       or request->>'firstSequence'!~'^[1-9][0-9]{0,18}$'
       or request->>'lastSequence'!~'^[1-9][0-9]{0,18}$'
       or request->>'firstEventSha256'!~'^[0-9a-f]{64}$'
       or request->>'headSha256'!~'^[0-9a-f]{64}$'
       or length(request->>'operatorReference') not between 1 and 256
       or length(request->>'reason') not between 1 and 2048
       or request->>'operatorReference'<>btrim(request->>'operatorReference')
       or request->>'reason'<>btrim(request->>'reason')
       or request->>'operatorReference'~'[[:cntrl:]]' or request->>'reason'~'[[:cntrl:]]'
       or request->>'operatorReference'<>normalize(request->>'operatorReference',NFC)
       or request->>'reason'<>normalize(request->>'reason',NFC) then
      raise exception 'invalid recovery request';
    end if;
    new.organization_id:=(request->>'organizationId')::uuid;
    new.instance_id:=(request->>'instanceId')::uuid;
    new.signing_key_id:=(request->>'signingKeyId')::uuid;
    new.first_sequence:=(request->>'firstSequence')::bigint;
    new.last_sequence:=(request->>'lastSequence')::bigint;
    new.first_event_sha256:=decode(request->>'firstEventSha256','hex');
    new.head_sha256:=decode(request->>'headSha256','hex');
    prepared:=(request->>'preparedAt')::timestamptz;
    new.expires_at:=(request->>'expiresAt')::timestamptz;
    if not public.boardagent_is_uuid_v7(new.id)
       or new.first_sequence<1 or new.last_sequence<new.first_sequence
       or new.last_sequence-new.first_sequence>=1000000
       or new.expires_at-prepared<>interval '30 minutes'
       or request->>'preparedAt'<>to_char(prepared at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
       or request->>'expiresAt'<>to_char(new.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') then
      raise exception 'invalid recovery request';
    end if;
  exception when others then
    raise exception 'recovery request is invalid or no longer applicable' using errcode='55000';
  end;

  select * into strict instance_row from public.system_instance where singleton_key;
  select * into strict head from public.audit_chain_head where singleton_key for update;
  -- Future key-lifecycle maintenance must take the head before key row locks as well.
  select key.* into evidence_key from public.crypto_key_registry as key where key.id=new.signing_key_id for update;
  select coalesce(max(checkpoint.last_sequence),0) into covered from public.audit_checkpoints as checkpoint;
  select event.* into oldest from public.audit_events as event where event.sequence=new.first_sequence;
  observed:=clock_timestamp();
  if instance_row.instance_id<>new.instance_id or instance_row.organization_id<>new.organization_id
     or head.last_sequence<>new.last_sequence or head.last_event_sha256<>new.head_sha256
     or covered+1<>new.first_sequence or oldest.id is null
     or oldest.organization_id<>new.organization_id or oldest.event_sha256<>new.first_event_sha256
     or request->>'firstUncoveredEventAt'<>to_char(oldest.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
     or prepared-oldest.occurred_at<=interval '15 minutes'
     or prepared>observed or new.expires_at<=observed
     or evidence_key.id is null or evidence_key.organization_id<>new.organization_id
     or evidence_key.kid<>request->>'keyId' or evidence_key.purpose<>'evidence_signing'
     or evidence_key.algorithm<>'EdDSA' or evidence_key.activated_at>observed
     or evidence_key.retired_at is not null or evidence_key.compromised_at is not null
     or evidence_key.public_jwk is null or evidence_key.public_jwk ? 'd'
     or evidence_key.public_jwk->>'kty' is distinct from 'OKP'
     or evidence_key.public_jwk->>'crv' is distinct from 'Ed25519' then
    raise exception 'recovery request is invalid or no longer applicable' using errcode='55000';
  end if;
  new.authorized_at:=observed;
  new.authorizing_principal:=session_user;
  new.authorization_transaction_id:=pg_current_xact_id();
  new.authorization_server_start:=pg_postmaster_start_time();
  return new;
end;
$$;
alter function public.boardagent_guard_audit_recovery_authorization() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_recovery_authorization() from public;
create trigger boardagent_audit_recovery_authorization before insert on public.audit_recoveries
  for each row execute function public.boardagent_guard_audit_recovery_authorization();

create function public.boardagent_begin_audit_recovery(candidate_request bytea,candidate_sha256 bytea)
returns table(recovery_id uuid,replayed boolean)
language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  candidate_id uuid;
  existing public.audit_recoveries%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'recovery authorization requires a serializable operator transaction' using errcode='25000';
  end if;
  begin
    if candidate_request is null or octet_length(candidate_request)>16384
       or candidate_sha256 is distinct from sha256(candidate_request) then
      raise exception 'invalid recovery request';
    end if;
    candidate_id:=(convert_from(candidate_request,'UTF8')::jsonb->>'recoveryId')::uuid;
  exception when others then
    raise exception 'recovery request is invalid or no longer applicable' using errcode='55000';
  end;
  perform 1 from public.audit_chain_head where singleton_key for update;
  select recovery.* into existing from public.audit_recoveries as recovery where recovery.id=candidate_id;
  if existing.id is not null then
    if existing.canonical_request is distinct from candidate_request
       or existing.request_sha256 is distinct from candidate_sha256
       or not exists(select 1 from public.audit_recovery_completions as completion where completion.recovery_id=existing.id) then
      raise exception 'recovery identifier already belongs to a different or unfinished operation' using errcode='55000';
    end if;
    return query select existing.id,true;
    return;
  end if;
  insert into public.audit_recoveries(id,canonical_request,request_sha256)
    values(candidate_id,candidate_request,candidate_sha256);
  return query select candidate_id,false;
end;
$$;
alter function public.boardagent_begin_audit_recovery(bytea,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_begin_audit_recovery(bytea,bytea) from public;
grant execute on function public.boardagent_begin_audit_recovery(bytea,bytea) to boardagent_migrator;

create function public.boardagent_guard_audit_recovery_completion()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  recovery public.audit_recoveries%rowtype;
  head public.audit_chain_head%rowtype;
  checkpoint public.audit_checkpoints%rowtype;
  observed timestamptz;
begin
  select * into strict head from public.audit_chain_head where singleton_key for update;
  select stored.* into recovery from public.audit_recoveries as stored where stored.id=new.recovery_id;
  select stored.* into checkpoint from public.audit_checkpoints as stored order by stored.last_sequence desc limit 1;
  observed:=clock_timestamp();
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
     or recovery.id is null or recovery.authorization_transaction_id<>pg_current_xact_id()
     or recovery.authorization_server_start<>pg_postmaster_start_time() or recovery.expires_at<=observed
     or checkpoint.id is null or checkpoint.last_sequence<recovery.last_sequence
     or checkpoint.last_sequence<>head.last_sequence-1
     or checkpoint.attestation_transaction_id is distinct from pg_current_xact_id()
     or checkpoint.attestation_sequence is distinct from head.last_sequence
     or not exists(select 1 from public.audit_events as event where event.sequence=head.last_sequence
       and event.object_id=checkpoint.id and event.event_type='audit_checkpoint_signed'
       and convert_from(event.canonical_payload,'UTF8')::jsonb->>'origin'='cli'
       and convert_from(event.canonical_payload,'UTF8')::jsonb->'details'->>'manifestSha256'=encode(checkpoint.manifest_sha256,'hex')) then
    raise exception 'recovery does not have a complete signed and audited outcome' using errcode='23514';
  end if;
  new.final_checkpoint_id:=checkpoint.id;
  new.final_head_sequence:=head.last_sequence;
  new.final_head_sha256:=head.last_event_sha256;
  new.completed_at:=observed;
  return new;
end;
$$;
alter function public.boardagent_guard_audit_recovery_completion() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_recovery_completion() from public;
create trigger boardagent_audit_recovery_completion before insert on public.audit_recovery_completions
  for each row execute function public.boardagent_guard_audit_recovery_completion();

create function public.boardagent_require_audit_recovery_completion()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
begin
  if not exists(select 1 from public.audit_recovery_completions as completion
    join public.audit_chain_head as head on head.singleton_key
    where completion.recovery_id=new.id and completion.final_head_sequence=head.last_sequence
      and completion.final_head_sha256=head.last_event_sha256) then
    raise exception 'unfinished audit recovery cannot commit' using errcode='23514';
  end if;
  return null;
end;
$$;
alter function public.boardagent_require_audit_recovery_completion() owner to boardagent_migrator;
revoke all on function public.boardagent_require_audit_recovery_completion() from public;
create constraint trigger boardagent_audit_recovery_must_complete after insert on public.audit_recoveries
  deferrable initially deferred for each row execute function public.boardagent_require_audit_recovery_completion();
