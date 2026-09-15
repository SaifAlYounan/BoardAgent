-- Reserve producer identity before using it to coalesce recurring work. Never adopt a
-- pre-existing caller-chosen key as trusted provenance. Preserve all legacy queue rows.
lock table public.jobs in share row exclusive mode;
do $$
begin
  if exists (select 1 from public.jobs where idempotency_key like 'worker-v2:%') then
    raise exception 'worker producer identity already exists; preserve and investigate before migration'
      using errcode='55000';
  end if;
end;
$$;

-- Also guard the table boundary: an already-running old enqueue function must not
-- insert a newly reserved identity after the migration releases its table lock.
create function public.boardagent_guard_worker_producer_identity()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public
as $$
begin
  if new.idempotency_key like 'worker-v2:%'
     and current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'reserved job identity requires a managed worker producer'
      using errcode='42501';
  end if;
  return new;
end;
$$;
alter function public.boardagent_guard_worker_producer_identity() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_worker_producer_identity() from public;
create trigger boardagent_worker_producer_identity
before insert on public.jobs
for each row execute function public.boardagent_guard_worker_producer_identity();

create or replace function public.boardagent_enqueue_request_job(
  candidate_job_id uuid,
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_job_type text,
  candidate_schema_version text,
  candidate_subject_type text,
  candidate_subject_id uuid,
  candidate_canonical_payload bytea,
  candidate_payload_sha256 bytea,
  candidate_idempotency_key text,
  candidate_available_at timestamptz
)
returns table(
  job_id uuid,
  replayed boolean,
  stored_payload_sha256 bytea,
  stored_canonical_payload bytea
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  scope text;
  stored public.jobs%rowtype;
begin
  scope := current_setting('boardagent.transaction_scope',true);
  if scope is distinct from 'request' then
    raise exception 'typed job enqueue requires a managed request transaction'
      using errcode='25000';
  end if;
  if candidate_organization_id is distinct from
       public.boardagent_context_uuid('boardagent.organization_id')
     or (candidate_board_id is not null
         and not public.boardagent_context_board_allowed(candidate_board_id)) then
    raise exception 'typed job enqueue is outside the managed request context'
      using errcode='42501';
  end if;

  if candidate_idempotency_key like 'worker-v2:%' then
    raise exception 'request jobs cannot use the reserved worker producer identity'
      using errcode='42501';
  end if;

  insert into public.jobs(
    id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
    canonical_payload,payload_sha256,idempotency_key,available_at
  ) values (
    candidate_job_id,candidate_organization_id,candidate_board_id,candidate_job_type,
    candidate_schema_version,candidate_subject_type,candidate_subject_id,
    candidate_canonical_payload,candidate_payload_sha256,candidate_idempotency_key,
    coalesce(candidate_available_at,pg_catalog.clock_timestamp())
  )
  on conflict (organization_id,job_type,idempotency_key) do nothing
  returning * into stored;

  if found then
    job_id := stored.id;
    replayed := false;
    stored_payload_sha256 := stored.payload_sha256;
    stored_canonical_payload := stored.canonical_payload;
    return next;
    return;
  end if;

  select * into strict stored
    from public.jobs
   where organization_id=candidate_organization_id
     and job_type=candidate_job_type
     and idempotency_key=candidate_idempotency_key;
  job_id := stored.id;
  replayed := true;
  stored_payload_sha256 := stored.payload_sha256;
  stored_canonical_payload := stored.canonical_payload;
  return next;
end;
$$;


-- Produce audit-checkpoint work from the live database, without a human request context.
-- The worker may request a scheduling tick, but cannot select the organization, job type,
-- signing key, audit watermark, payload or deadline through this authority.
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
  -- Later ticks leave one minute of scheduling headroom under the 15-minute ceiling.
  if prior_sequence>0 and head_sequence-prior_sequence<1000
     and first_uncovered_at>clock_timestamp()-interval '14 minutes' then
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

create or replace function public.boardagent_schedule_periodic_jobs()
returns integer
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  organization uuid;
  tick_at timestamptz;
  target record;
  payload bytea;
  scheduled_count integer:=0;
  inserted_count integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'periodic scheduling requires a managed worker transaction'
      using errcode='25000';
  end if;
  select instance.organization_id into strict organization
    from public.system_instance as instance where instance.singleton_key;
  perform pg_advisory_xact_lock(hashtextextended(organization::text,104041));
  tick_at:=clock_timestamp();
  -- Cadence slots and the existing unique key survive restarts and serialize producers.
  -- A pending job coalesces future ticks; reapers may recover an older leased reaper too.
  -- Bound each tick; subsequent ticks select only candidates not already scheduled.
  for target in
    with organization_types(job_type,period_seconds,priority) as (values
      ('clock_health',60,0),
      ('job_lease_reaper',60,1),('notification_lease_reaper',60,1),
      ('action_stage_expiry',60,3),('wizard_expiry',60,3),
      ('oauth_ephemera_expiry',60,3),('refresh_session_revocation',60,3),
      ('export_artifact_expiry',60,3),('export_reconcile',60,3),
      ('audit_verify',300,5),('feed_consistency_check',300,5),
      ('backup_receipt_verify',300,5),
      ('rate_bucket_retention',3600,6),('job_retention',3600,6),('log_retention',3600,6),
      ('backup_trigger',86400,7),('restore_due_alert',86400,7),
      ('key_compatibility_alert',86400,7),
      ('compatibility_alert',604800,7),('protocol_compatibility_alert',604800,7),
      ('dependency_compatibility_alert',604800,7)
    ), candidates as (
      select kind.job_type,null::uuid as board_id,'organization'::text as subject_type,
             organization as subject_id,'{}'::text as parameters,
             kind.period_seconds,kind.priority
        from organization_types as kind
      union all
      select kind.job_type,board.id,'board',board.id,
             '{"through":'||to_jsonb(to_char(tick_at at time zone 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text||'}',60,2
        from public.boards as board
        cross join (values ('vote_deadline_scan'),('question_due_scan'),
                           ('task_due_scan'),('action_due_scan')) as kind(job_type)
       where board.organization_id=organization and board.state='active'
      union all
      select 'feed_reconcile',membership.board_id,'member',membership.member_id,
             '{"memberId":'||to_jsonb(membership.member_id::text)::text||'}',300,4
        from public.board_memberships as membership
        join public.boards as board on board.id=membership.board_id
          and board.organization_id=membership.organization_id and board.state='active'
       where membership.organization_id=organization
      union all
      select 'certificate_recovery',vote.board_id,'vote',vote.id,
             '{"voteId":'||to_jsonb(vote.id::text)::text||'}',60,2
        from public.votes as vote where vote.organization_id=organization and vote.state='closing'
    ), keyed as (
      select candidate.*,
        'worker-v2:periodic:'||candidate.job_type||':'||coalesce(candidate.board_id::text,'organization')||
        ':'||candidate.subject_id::text||':'||floor(extract(epoch from tick_at)/candidate.period_seconds)::text
          as request_key
      from candidates as candidate
    )
    select candidate.* from keyed as candidate
     where not exists (
       select 1 from public.jobs as job where job.organization_id=organization
         and job.job_type=candidate.job_type and job.idempotency_key=candidate.request_key
     ) and not exists (
       select 1 from public.jobs as job where job.organization_id=organization
         and job.job_type=candidate.job_type and job.subject_id=candidate.subject_id
         and job.board_id is not distinct from candidate.board_id
         and job.idempotency_key like 'worker-v2:periodic:%'
         and (job.state in ('queued','retry') or (job.state='leased'
           and candidate.job_type not in ('job_lease_reaper','notification_lease_reaper')))
     ) order by candidate.priority,candidate.job_type,candidate.board_id,candidate.subject_id
     limit 1000
  loop
    payload:=convert_to(format(
      '{"boardId":%s,"jobType":%s,"organizationId":%s,"parameters":%s,"schemaVersion":%s,"subjectId":%s,"subjectType":%s}',
      coalesce(to_jsonb(target.board_id::text)::text,'null'),to_jsonb(target.job_type)::text,
      to_jsonb(organization::text)::text,target.parameters,
      to_jsonb('boardagent.job.'||target.job_type||'.v1')::text,
      to_jsonb(target.subject_id::text)::text,to_jsonb(target.subject_type)::text
    ),'UTF8');
    insert into public.jobs(
      id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
      canonical_payload,payload_sha256,idempotency_key,available_at
    ) values (
      pg_catalog.uuidv7(),organization,target.board_id,target.job_type,
      'boardagent.job.'||target.job_type||'.v1',target.subject_type,target.subject_id,
      payload,sha256(payload),target.request_key,clock_timestamp()
    ) on conflict (organization_id,job_type,idempotency_key) do nothing;
    get diagnostics inserted_count=row_count;
    scheduled_count:=scheduled_count+inserted_count;
  end loop;
  return scheduled_count;
end;
$$;
alter function public.boardagent_schedule_periodic_jobs() owner to boardagent_migrator;
revoke all on function public.boardagent_schedule_periodic_jobs() from public;
grant execute on function public.boardagent_schedule_periodic_jobs() to boardagent_worker;
