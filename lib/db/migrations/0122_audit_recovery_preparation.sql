-- Read-only operator preparation is not recovery authorization. It cannot sign,
-- change history, or admit work through the ordinary checkpoint guards.
create function public.boardagent_audit_recovery_snapshot(candidate_signing_key_id uuid)
returns table(
  instance_id uuid,
  organization_id uuid,
  first_sequence bigint,
  last_sequence bigint,
  first_event_sha256 bytea,
  last_event_sha256 bytea,
  first_uncovered_event_at text,
  prepared_at text,
  expires_at text,
  signing_key_id uuid,
  key_id text,
  public_jwk jsonb
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  instance_row public.system_instance%rowtype;
  head public.audit_chain_head%rowtype;
  evidence_key public.crypto_key_registry%rowtype;
  prior_last bigint;
  candidate_first bigint;
  first_hash bytea;
  first_at timestamptz;
  observed_at timestamptz;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
     or current_setting('transaction_read_only') is distinct from 'on'
     or current_setting('transaction_isolation') not in ('serializable','repeatable read') then
    raise exception 'recovery preparation requires a consistent read-only operator transaction'
      using errcode='25000';
  end if;

  select instance.* into instance_row from public.system_instance as instance
    where instance.singleton_key;
  select chain.* into head from public.audit_chain_head as chain where chain.singleton_key;
  select coalesce(max(checkpoint.last_sequence),0) into prior_last
    from public.audit_checkpoints as checkpoint;
  if instance_row.instance_id is null or head.last_sequence is null
     or prior_last>=head.last_sequence or head.last_sequence-prior_last>1000000 then
    raise exception 'an overdue retained audit range is unavailable' using errcode='55000';
  end if;
  candidate_first:=prior_last+1;
  select event.event_sha256,event.occurred_at into first_hash,first_at
    from public.audit_events as event
    where event.sequence=candidate_first and event.organization_id=instance_row.organization_id;
  observed_at:=clock_timestamp();
  if first_hash is null or first_at is null or observed_at-first_at<=interval '15 minutes'
     or not exists (
       select 1 from public.audit_events as event
       where event.sequence=head.last_sequence and event.organization_id=instance_row.organization_id
         and event.event_sha256=head.last_event_sha256
     ) then
    raise exception 'an overdue retained audit range is unavailable' using errcode='55000';
  end if;
  select key.* into evidence_key from public.crypto_key_registry as key
    where key.id=candidate_signing_key_id and key.organization_id=instance_row.organization_id
      and key.purpose='evidence_signing' and key.algorithm='EdDSA'
      and key.public_jwk is not null and key.activated_at<=observed_at
      and key.retired_at is null and key.compromised_at is null;
  if evidence_key.id is null then
    raise exception 'an active recovery evidence key is unavailable' using errcode='55000';
  end if;

  return query select instance_row.instance_id,instance_row.organization_id,
    candidate_first,head.last_sequence,first_hash,head.last_event_sha256,
    to_char(first_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    to_char(observed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    to_char((observed_at+interval '30 minutes') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    evidence_key.id,evidence_key.kid,evidence_key.public_jwk;
end;
$$;
alter function public.boardagent_audit_recovery_snapshot(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_audit_recovery_snapshot(uuid) from public;
grant execute on function public.boardagent_audit_recovery_snapshot(uuid) to boardagent_migrator;
