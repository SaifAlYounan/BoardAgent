-- A due checkpoint cannot wait behind an arbitrarily long ordinary queue. Only
--0107's protected producer identity receives priority; request-created checkpoint
--jobs retain FIFO. Availability, attempt limits and exclusive leases stay unchanged.
create index jobs_checkpoint_priority_claim_idx on public.jobs (
  (case when job_type='audit_checkpoint'
          and idempotency_key like 'worker-v2:checkpoint:%' then 0 else 1 end),
  available_at,id
) where state in ('queued','retry') and attempts<10;

create or replace function public.boardagent_claim_typed_job(
  candidate_lease_owner text,
  candidate_lease_seconds integer
)
returns table(
  job_id uuid,
  organization_id uuid,
  board_id uuid,
  job_type text,
  schema_version text,
  subject_type text,
  subject_id uuid,
  canonical_payload bytea,
  payload_sha256 bytea,
  attempt integer,
  lease_token uuid,
  lease_started_at timestamptz,
  lease_expires_at timestamptz
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  now_at timestamptz(6);
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'job claim requires a managed worker transaction' using errcode='25000';
  end if;
  if candidate_lease_owner is null
     or candidate_lease_owner!~'^[A-Za-z0-9._:-]{1,128}$'
     or candidate_lease_seconds not between 5 and 300 then
    raise exception 'job claim lease inputs are invalid' using errcode='22023';
  end if;
  now_at := clock_timestamp();

  return query
    with candidate as (
      select queued.id
        from public.jobs as queued
       where queued.state in ('queued','retry')
         and queued.available_at<=now_at
         and queued.attempts<10
       order by case when queued.job_type='audit_checkpoint'
                          and queued.idempotency_key like 'worker-v2:checkpoint:%'
                     then 0 else 1 end,
                queued.available_at,queued.id
       for update skip locked
       limit 1
    ), leased as (
      update public.jobs as job
         set state='leased',
             attempts=job.attempts+1,
             lease_owner=candidate_lease_owner,
             lease_token=gen_random_uuid(),
             lease_started_at=now_at,
             lease_expires_at=now_at+make_interval(secs=>candidate_lease_seconds)
        from candidate
       where job.id=candidate.id
       returning job.*
    )
    select leased.id,
           leased.organization_id,
           leased.board_id,
           leased.job_type,
           leased.schema_version,
           leased.subject_type,
           leased.subject_id,
           leased.canonical_payload,
           leased.payload_sha256,
           leased.attempts,
           leased.lease_token,
           leased.lease_started_at,
           leased.lease_expires_at
      from leased;
end;
$$;

alter function public.boardagent_claim_typed_job(text,integer) owner to boardagent_migrator;
revoke all on function public.boardagent_claim_typed_job(text,integer) from public;
grant execute on function public.boardagent_claim_typed_job(text,integer) to boardagent_worker;
