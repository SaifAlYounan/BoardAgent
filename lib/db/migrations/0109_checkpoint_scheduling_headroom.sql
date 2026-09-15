-- Start signing before the hard1000-event/15-minute admission and validity limits.
-- These remain enforced by0106 and0105; scheduling earlier does not excuse a missed limit.
create or replace function public.boardagent_schedule_audit_checkpoint(candidate_job_id uuid)
returns table(result_job_id uuid,scheduling_status text)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  organization uuid;
  head_sequence bigint;
  prior_sequence bigint;
  first_uncovered_at timestamptz;
  pending public.jobs%rowtype;
  payload bytea;
  request_key text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'checkpoint scheduling requires a managed worker transaction'
      using errcode='25000';
  end if;
  if candidate_job_id is null or not public.boardagent_is_uuid_v7(candidate_job_id) then
    raise exception 'checkpoint scheduling requires a version-seven job identity'
      using errcode='22023';
  end if;
  select instance.organization_id into strict organization
    from public.system_instance as instance where instance.singleton_key;
  perform pg_advisory_xact_lock(hashtextextended(organization::text,103041));
  select head.last_sequence into strict head_sequence
    from public.audit_chain_head as head where head.singleton_key;
  select coalesce(max(checkpoint.last_sequence),0) into prior_sequence
    from public.audit_checkpoints as checkpoint where checkpoint.organization_id=organization;
  if head_sequence<=prior_sequence then
    result_job_id:=null;scheduling_status:='empty';return next;return;
  end if;
  select job.* into pending from public.jobs as job
    where job.organization_id=organization and job.job_type='audit_checkpoint'
      and job.idempotency_key like 'worker-v2:checkpoint:%'
      and job.state in ('queued','retry','leased')
    order by job.available_at,job.id limit 1;
  if pending.id is not null then
    result_job_id:=pending.id;scheduling_status:='pending';return next;return;
  end if;
  select event.occurred_at into strict first_uncovered_at
    from public.audit_events as event where event.sequence=prior_sequence+1;
  -- A fresh instance needs a first checkpoint for its first supported logical backup.
  -- Leave room for concurrent whole batches and real retry delays before the hard limits.
  if prior_sequence>0 and head_sequence-prior_sequence<900
     and first_uncovered_at>clock_timestamp()-interval '5 minutes' then
    result_job_id:=null;scheduling_status:='not_due';return next;return;
  end if;
  request_key:='worker-v2:checkpoint:'||(prior_sequence+1)::text;
  payload:=convert_to(format(
    '{"boardId":null,"jobType":"audit_checkpoint","organizationId":%s,"parameters":{"throughSequence":%s},"schemaVersion":"boardagent.job.audit_checkpoint.v1","subjectId":%s,"subjectType":"organization"}',
    to_jsonb(organization::text)::text,to_jsonb(head_sequence::text)::text,
    to_jsonb(organization::text)::text
  ),'UTF8');
  insert into public.jobs(
    id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
    canonical_payload,payload_sha256,idempotency_key,available_at
  ) values (
    candidate_job_id,organization,null,'audit_checkpoint','boardagent.job.audit_checkpoint.v1',
    'organization',organization,payload,sha256(payload),request_key,clock_timestamp()
  ) on conflict (organization_id,job_type,idempotency_key) do nothing
  returning jobs.id into result_job_id;
  if result_job_id is null then
    select job.* into strict pending from public.jobs as job
      where job.organization_id=organization and job.job_type='audit_checkpoint'
        and job.idempotency_key=request_key;
    result_job_id:=pending.id;
    if pending.state='dead' then scheduling_status:='blocked';
    else scheduling_status:='pending';
    end if;
  else scheduling_status:='scheduled';
  end if;
  return next;
end;
$$;
alter function public.boardagent_schedule_audit_checkpoint(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_schedule_audit_checkpoint(uuid) from public;
grant execute on function public.boardagent_schedule_audit_checkpoint(uuid) to boardagent_worker;

