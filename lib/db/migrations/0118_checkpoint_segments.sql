-- F8 prerequisite: sign consecutive prefixes without widening ordinary admission.
-- Historical checkpoint payloads and the 1000-event/15-minute segment limits stay intact.
-- Null authority fields on historical rows deliberately grant no append exception.
alter table public.audit_checkpoints
  add column attestation_transaction_id xid8,
  add column attestation_sequence bigint;

create or replace function boardagent_audit_checkpoint_snapshot(candidate_signing_key_id uuid)
returns table(
  instance_id uuid,
  organization_id uuid,
  first_sequence bigint,
  last_sequence bigint,
  first_event_sha256 bytea,
  last_event_sha256 bytea,
  issued_at text,
  signing_key_id uuid,
  key_id text,
  public_jwk jsonb
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  instance_row system_instance%rowtype;
  head audit_chain_head%rowtype;
  prior_last bigint;
  first_hash bytea;
  evidence_key crypto_key_registry%rowtype;
  candidate_first bigint;
  candidate_last bigint;
  last_hash bytea;
  observed_at timestamptz;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'audit checkpoint snapshot requires a managed worker transaction'
      using errcode = '25000';
  end if;

  select * into strict instance_row from system_instance where singleton_key;
  select * into strict head from audit_chain_head where singleton_key for update;
  observed_at := clock_timestamp();
  if head.last_sequence = 0 then
    raise exception 'audit checkpoint requires at least one event' using errcode = '55000';
  end if;

  select checkpoint.last_sequence
    into prior_last
    from audit_checkpoints as checkpoint
   order by checkpoint.last_sequence desc
   limit 1;
  candidate_first := coalesce(prior_last + 1, 1);
  if candidate_first > head.last_sequence then
    raise exception 'audit checkpoint has no uncovered events' using errcode = '55000';
  end if;
  candidate_last := least(head.last_sequence, candidate_first + 999);
  select event.event_sha256 into strict last_hash from audit_events as event
   where event.sequence=candidate_last
     and event.organization_id=instance_row.organization_id;

  select event.event_sha256
    into strict first_hash
    from audit_events as event
   where event.sequence = candidate_first
     and event.organization_id = instance_row.organization_id;
  if not exists (
    select 1 from audit_events as event
     where event.sequence = head.last_sequence
       and event.organization_id = instance_row.organization_id
       and event.event_sha256 = head.last_event_sha256
  ) or exists (
    select 1 from audit_events as event
     where event.sequence between candidate_first and head.last_sequence
       and event.organization_id <> instance_row.organization_id
  ) then
    raise exception 'audit checkpoint interval does not belong to the system instance'
      using errcode = '23514';
  end if;

  select * into strict evidence_key
    from crypto_key_registry as key
   where key.id = candidate_signing_key_id;
  if evidence_key.organization_id <> instance_row.organization_id
     or evidence_key.purpose <> 'evidence_signing'
     or evidence_key.algorithm <> 'EdDSA'
     or evidence_key.public_jwk is null
     or evidence_key.activated_at > observed_at
     or (evidence_key.retired_at is not null
         and evidence_key.retired_at <= observed_at)
     or evidence_key.compromised_at is not null then
    raise exception 'audit checkpoint requires an active uncompromised Ed25519 evidence key'
      using errcode = '23514';
  end if;

  return query select
    instance_row.instance_id,
    instance_row.organization_id,
    candidate_first,
    candidate_last,
    first_hash,
    last_hash,
    to_char(
      observed_at at time zone 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    evidence_key.id,
    evidence_key.kid,
    evidence_key.public_jwk;
end
$$;
alter function boardagent_audit_checkpoint_snapshot(uuid) owner to boardagent_migrator;
revoke all on function boardagent_audit_checkpoint_snapshot(uuid) from public;
grant execute on function boardagent_audit_checkpoint_snapshot(uuid) to boardagent_worker;


create or replace function boardagent_guard_audit_checkpoint_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  manifest jsonb;
  instance_row system_instance%rowtype;
  head audit_chain_head%rowtype;
  evidence_key crypto_key_registry%rowtype;
  expected_first bigint;
  payload_issued_at timestamptz;
  stored_first_hash bytea;
  stored_last_hash bytea;
  observed_at timestamptz;
begin
  begin
    manifest := convert_from(new.canonical_manifest, 'UTF8')::jsonb;
    payload_issued_at := (manifest ->> 'issuedAt')::timestamptz;
  exception when others then
    raise exception 'audit checkpoint manifest is not valid UTF-8 JSON evidence'
      using errcode = '23514';
  end;

  select * into strict instance_row from system_instance where singleton_key;
  select * into strict head from audit_chain_head where singleton_key for update;
  observed_at := clock_timestamp();
  select coalesce(max(checkpoint.last_sequence) + 1, 1)
    into expected_first
    from audit_checkpoints as checkpoint;
  select event.event_sha256
    into strict stored_first_hash
    from audit_events as event
   where event.sequence = new.first_sequence
     and event.organization_id = new.organization_id;
  select event.event_sha256 into strict stored_last_hash
    from audit_events as event where event.sequence=new.last_sequence
      and event.organization_id=new.organization_id;
  select * into strict evidence_key
    from crypto_key_registry as key
   where key.id = new.signing_key_id;

  if new.organization_id <> instance_row.organization_id
     or new.first_sequence <> expected_first
     or new.last_sequence <> least(head.last_sequence, expected_first + 999)
     or new.last_event_sha256 <> stored_last_hash
     or new.first_event_sha256 <> stored_first_hash
     or new.last_sequence - new.first_sequence + 1 > 1000
     or payload_issued_at <> new.created_at
     or payload_issued_at > observed_at
     or payload_issued_at < observed_at - interval '15 minutes'
     or manifest ->> 'schema' <> 'boardagent.audit.checkpoint.v1'
     or manifest ->> 'checkpointId' <> new.id::text
     or manifest ->> 'instanceId' <> instance_row.instance_id::text
     or manifest ->> 'organizationId' <> new.organization_id::text
     or manifest ->> 'auditSchema' <> 'boardagent.audit-event.v1'
     or manifest ->> 'firstSequence' <> new.first_sequence::text
     or manifest ->> 'lastSequence' <> new.last_sequence::text
     or manifest ->> 'firstEventSha256' <> encode(new.first_event_sha256, 'hex')
     or manifest ->> 'lastEventSha256' <> encode(new.last_event_sha256, 'hex')
     or manifest ->> 'signingKeyId' <> new.signing_key_id::text
     or manifest ->> 'keyId' <> evidence_key.kid
     or evidence_key.organization_id <> new.organization_id
     or evidence_key.purpose <> 'evidence_signing'
     or evidence_key.algorithm <> 'EdDSA'
     or evidence_key.public_jwk is null
     or evidence_key.activated_at > payload_issued_at
     or (evidence_key.retired_at is not null
         and evidence_key.retired_at <= observed_at)
     or evidence_key.compromised_at is not null
     or exists (
       select 1 from audit_events as event
        where event.sequence between new.first_sequence and new.last_sequence
          and event.organization_id <> new.organization_id
     ) then
    raise exception 'audit checkpoint does not bind the exact next chain segment and evidence key'
      using errcode = '23514';
  end if;
  -- These internal fields are always assigned by the guard, never trusted from INSERT.
  -- They permit only the matching signer audit event at the next exact chain sequence.
  new.attestation_transaction_id := pg_current_xact_id();
  new.attestation_sequence := head.last_sequence + 1;
  return new;
end
$$;
alter function boardagent_guard_audit_checkpoint_insert() owner to boardagent_migrator;
revoke all on function boardagent_guard_audit_checkpoint_insert() from public;

-- A partial checkpoint may leave >=1000 unsigned events. Only its exact, same-transaction
-- attestation may append through that closed boundary. The chain sequence is single-use;
-- copied metadata, a later transaction or an ordinary event cannot reuse the permission.
create or replace function public.boardagent_guard_audit_checkpoint_capacity()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  current_head bigint;
  checkpoint_head bigint;
  body jsonb;
begin
  select head.last_sequence into strict current_head from public.audit_chain_head as head
    where head.singleton_key for update;
  select coalesce(max(checkpoint.last_sequence),0) into checkpoint_head
    from public.audit_checkpoints as checkpoint;
  if current_head-checkpoint_head>=1000 then
    body := convert_from(new.canonical_payload,'UTF8')::jsonb;
    if new.event_type='audit_checkpoint_signed'
       and new.object_type='audit_checkpoint'
       and new.sequence=current_head+1
       and new.actor_member_id is null and new.client_id is null and new.token_jti is null
       and new.board_id is null
       and body->>'origin'='worker'
       and body->>'entityId'=new.object_id::text
       and exists (
         select 1 from public.audit_checkpoints as checkpoint
          where checkpoint.id=new.object_id
            and checkpoint.organization_id=new.organization_id
            and checkpoint.attestation_transaction_id=pg_current_xact_id()
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
    raise exception 'audit checkpoint capacity exhausted; retry after a signed checkpoint'
      using errcode='55000',constraint='boardagent_audit_checkpoint_capacity';
  end if;
  return new;
end;
$$;
alter function public.boardagent_guard_audit_checkpoint_capacity() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_checkpoint_capacity() from public;
