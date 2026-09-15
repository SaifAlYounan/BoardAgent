-- Signing time is observed after the head lock, never inherited from transaction start.
-- Retain exact-head binding, current key checks, future-time refusal and both15-minute guards.
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
set search_path = pg_catalog, public
as $$
declare
  instance_row system_instance%rowtype;
  head audit_chain_head%rowtype;
  prior_last bigint;
  first_hash bytea;
  evidence_key crypto_key_registry%rowtype;
  candidate_first bigint;
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
  if head.last_sequence - candidate_first + 1 > 1000 then
    raise exception 'audit checkpoint backlog exceeds the 1000-event signing window'
      using errcode = '55000';
  end if;

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
    head.last_sequence,
    first_hash,
    head.last_event_sha256,
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
set search_path = pg_catalog, public
as $$
declare
  manifest jsonb;
  instance_row system_instance%rowtype;
  head audit_chain_head%rowtype;
  evidence_key crypto_key_registry%rowtype;
  expected_first bigint;
  payload_issued_at timestamptz;
  stored_first_hash bytea;
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
  select * into strict evidence_key
    from crypto_key_registry as key
   where key.id = new.signing_key_id;

  if new.organization_id <> instance_row.organization_id
     or new.first_sequence <> expected_first
     or new.last_sequence <> head.last_sequence
     or new.last_event_sha256 <> head.last_event_sha256
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
    raise exception 'audit checkpoint does not bind the exact current chain head and evidence key'
      using errcode = '23514';
  end if;
  return new;
end
$$;
alter function boardagent_guard_audit_checkpoint_insert() owner to boardagent_migrator;
revoke all on function boardagent_guard_audit_checkpoint_insert() from public;
