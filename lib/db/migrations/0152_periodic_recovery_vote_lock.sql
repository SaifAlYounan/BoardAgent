-- Keep recovery job eligibility stable until insertion commits. Preserve the
-- existing producer authority, job guard, cadence, batch bound and trusted namespace.
create or replace function public.boardagent_schedule_periodic_jobs()
returns integer
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
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
    -- The cursor can outlive a concurrent signed close at READ COMMITTED.
    -- Lock and recheck the exact vote before the unchanged typed-job guard runs.
    -- A busy vote is deferred to another tick without stalling unrelated work.
    if target.job_type='certificate_recovery' then
      perform 1 from public.votes as vote
       where vote.organization_id=organization and vote.board_id=target.board_id
         and vote.id=target.subject_id and vote.state='closing'
       for update skip locked;
      if not found then
        continue;
      end if;
    end if;
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
