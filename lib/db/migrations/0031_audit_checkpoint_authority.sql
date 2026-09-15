-- BoardAgent Phase 1 / group 31: exact audit-checkpoint snapshot and insert authority.

grant insert on audit_checkpoints to boardagent_worker;

-- Migration 0025 added migrator attribution after the vote-close worker path had
-- already widened this managed head lock. Preserve all three exact transaction scopes.
create or replace function boardagent_lock_audit_head()
returns table(last_sequence bigint, last_event_sha256 bytea, occurred_at text)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is null
     or current_setting('boardagent.transaction_scope', true) not in ('request', 'migration', 'worker') then
    raise exception 'audit append requires a managed request transaction, migration transaction, or worker transaction'
      using errcode = '25000';
  end if;
  return query
    select head.last_sequence,
           head.last_event_sha256,
           to_char(
             transaction_timestamp() at time zone 'UTC',
             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
           )
      from audit_chain_head as head
     where head.singleton_key
       for update;
  if not found then
    raise exception 'audit chain head is unavailable' using errcode = '55000';
  end if;
end
$$;
alter function boardagent_lock_audit_head() owner to boardagent_migrator;
revoke all on function boardagent_lock_audit_head() from public;
grant execute on function boardagent_lock_audit_head()
  to boardagent_server, boardagent_worker;

create policy boardagent_migrator_checkpoint_read on audit_checkpoints
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_checkpoint_insert on audit_checkpoints
  for insert to boardagent_migrator with check (true);
create policy boardagent_migrator_audit_event_read on audit_events
  for select to boardagent_migrator using (true);

create function boardagent_audit_checkpoint_snapshot(candidate_signing_key_id uuid)
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
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'audit checkpoint snapshot requires a managed worker transaction'
      using errcode = '25000';
  end if;

  select * into strict instance_row from system_instance where singleton_key;
  select * into strict head from audit_chain_head where singleton_key;
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
     or evidence_key.activated_at > transaction_timestamp()
     or (evidence_key.retired_at is not null
         and evidence_key.retired_at <= transaction_timestamp())
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
      transaction_timestamp() at time zone 'UTC',
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

create function boardagent_audit_checkpoint_key(
  candidate_signing_key_id uuid,
  candidate_issued_at timestamptz
)
returns table(
  instance_id uuid,
  organization_id uuid,
  key_id text,
  public_jwk jsonb
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
declare
  instance_row system_instance%rowtype;
  evidence_key crypto_key_registry%rowtype;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'audit checkpoint verification requires a managed worker transaction'
      using errcode = '25000';
  end if;
  select * into strict instance_row from system_instance where singleton_key;
  select * into strict evidence_key
    from crypto_key_registry as key
   where key.id = candidate_signing_key_id;
  if evidence_key.organization_id <> instance_row.organization_id
     or evidence_key.purpose <> 'evidence_signing'
     or evidence_key.algorithm <> 'EdDSA'
     or evidence_key.public_jwk is null
     or evidence_key.activated_at > candidate_issued_at
     or (evidence_key.retired_at is not null
         and evidence_key.retired_at <= candidate_issued_at)
     or evidence_key.compromised_at is not null then
    raise exception 'audit checkpoint key is invalid for the signed instant'
      using errcode = '23514';
  end if;
  return query select
    instance_row.instance_id,
    instance_row.organization_id,
    evidence_key.kid,
    evidence_key.public_jwk;
end
$$;
alter function boardagent_audit_checkpoint_key(uuid, timestamptz) owner to boardagent_migrator;
revoke all on function boardagent_audit_checkpoint_key(uuid, timestamptz) from public;
grant execute on function boardagent_audit_checkpoint_key(uuid, timestamptz)
  to boardagent_worker;

create function boardagent_audit_checkpoint_lookup(candidate_checkpoint_id uuid)
returns table(manifest_sha256 bytea, signature bytea)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'audit checkpoint lookup requires a managed worker transaction'
      using errcode = '25000';
  end if;
  return query
    select checkpoint.manifest_sha256, checkpoint.signature
      from audit_checkpoints as checkpoint
     where checkpoint.id = candidate_checkpoint_id;
end
$$;
alter function boardagent_audit_checkpoint_lookup(uuid) owner to boardagent_migrator;
revoke all on function boardagent_audit_checkpoint_lookup(uuid) from public;
grant execute on function boardagent_audit_checkpoint_lookup(uuid) to boardagent_worker;

create function boardagent_guard_audit_checkpoint_insert()
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
     or payload_issued_at > transaction_timestamp()
     or payload_issued_at < transaction_timestamp() - interval '15 minutes'
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
         and evidence_key.retired_at <= transaction_timestamp())
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
create trigger boardagent_audit_checkpoint_insert_guard
  before insert on audit_checkpoints
  for each row execute function boardagent_guard_audit_checkpoint_insert();
