-- Revalidate prepared database facts in the same writing transaction as a future
-- protected lifecycle operation. This function changes no key and creates no authority.
create function public.boardagent_lock_key_maintenance_snapshot(
  candidate_instance_id uuid,
  candidate_organization_id uuid,
  candidate_key_id uuid,
  expected_inventory jsonb,
  candidate_prepared_at text,
  candidate_expires_at text
) returns jsonb
language plpgsql volatile security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  prepared timestamptz;
  expires timestamptz;
  observed timestamptz;
  purpose_before_lock text;
  key_row public.crypto_key_registry%rowtype;
  current_inventory jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'key maintenance requires a serializable writing operator transaction'
      using errcode='25000';
  end if;
  begin
    if candidate_instance_id is null or candidate_organization_id is null or candidate_key_id is null
      or expected_inventory is null or jsonb_typeof(expected_inventory)<>'object'
      or octet_length(expected_inventory::text)>262144
      or candidate_prepared_at is null or candidate_expires_at is null
      or length(candidate_prepared_at)<>27 or length(candidate_expires_at)<>27 then
      raise exception 'invalid prepared facts';
    end if;
    prepared:=candidate_prepared_at::timestamptz;
    expires:=candidate_expires_at::timestamptz;
    if candidate_prepared_at<>to_char(prepared at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      or candidate_expires_at<>to_char(expires at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      or expires-prepared<>interval '30 minutes'
      or expected_inventory#>>'{keyDependencies,observedAt}' is distinct from candidate_prepared_at then
      raise exception 'invalid prepared facts';
    end if;
  exception when others then
    raise exception 'key maintenance request is invalid or no longer applicable' using errcode='55000';
  end;

  -- Shared order with audit recovery: head, purpose advisory lock, key row.
  perform 1 from public.audit_chain_head where singleton_key for update;
  if not found then
    raise exception 'key maintenance audit head unavailable' using errcode='55000';
  end if;
  select key.purpose into purpose_before_lock from public.crypto_key_registry key
    where key.id=candidate_key_id and key.organization_id=candidate_organization_id;
  if purpose_before_lock is null then
    raise exception 'key maintenance target unavailable' using errcode='23503';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(purpose_before_lock,424247));
  select key.* into key_row from public.crypto_key_registry key
    where key.id=candidate_key_id and key.organization_id=candidate_organization_id for update;
  observed:=clock_timestamp();
  if key_row.id is null or key_row.purpose is distinct from purpose_before_lock
    or prepared>observed or expires<=observed
    or key_row.activated_at>prepared
    or key_row.retired_at>prepared or key_row.compromised_at>prepared then
    raise exception 'key maintenance request is invalid or no longer applicable' using errcode='55000';
  end if;
  current_inventory:=public.boardagent_snapshot_key_maintenance_work(
    candidate_instance_id,candidate_organization_id,candidate_key_id);
  -- Compare complete typed facts, not a caller's claim that its digest matched.
  -- Only the fresh observation time differs between the two database snapshots.
  if (current_inventory #- '{keyDependencies,observedAt}')
      is distinct from (expected_inventory #- '{keyDependencies,observedAt}') then
    raise exception 'key maintenance request is invalid or no longer applicable' using errcode='55000';
  end if;
  return current_inventory;
end;
$$;
alter function public.boardagent_lock_key_maintenance_snapshot(uuid,uuid,uuid,jsonb,text,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_lock_key_maintenance_snapshot(uuid,uuid,uuid,jsonb,text,text)
  from public;
grant execute on function public.boardagent_lock_key_maintenance_snapshot(uuid,uuid,uuid,jsonb,text,text)
  to boardagent_migrator;
