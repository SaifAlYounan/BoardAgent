-- BoardAgent Phase 4 / group 80: bounded 30-day operational retention.
-- The closed allowlist contains only generic worker execution receipts and terminal
-- webhook-attempt logs. Governance, content, audit, notices, feed, consent, export and
-- backup evidence have no delete path here.

grant delete on public.jobs,public.job_attempt_results,public.notification_attempts
  to boardagent_migrator;

create policy boardagent_migrator_operational_retention_delete
  on public.job_attempt_results for delete to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');

create policy boardagent_migrator_operational_retention_delete
  on public.notification_attempts for delete to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');

-- These two tables were initially guarded as immutable evidence. Gate-2 D2-049/U-33
-- instead classifies them as 30-day operational logs. Preserve update immutability and
-- admit DELETE only while the protected retention function owns the transaction.
drop trigger boardagent_job_attempt_results_immutable on public.job_attempt_results;
drop trigger boardagent_immutable on public.notification_attempts;

create function public.boardagent_guard_operational_log_mutation()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if tg_op='DELETE'
     and current_user='boardagent_migrator'
     and current_setting('boardagent.transaction_scope',true)='worker'
     and current_setting('boardagent.operational_retention',true)='30-day-v1' then
    return old;
  end if;
  raise exception 'protected operational log table % rejects %',tg_table_name,tg_op
    using errcode='55000';
end
$$;

create trigger boardagent_operational_log_guard
before update or delete on public.job_attempt_results
for each row execute function public.boardagent_guard_operational_log_mutation();

create trigger boardagent_operational_log_guard
before update or delete on public.notification_attempts
for each row execute function public.boardagent_guard_operational_log_mutation();

create function public.boardagent_run_operational_retention(
  candidate_job_type text,
  candidate_organization_id uuid,
  candidate_limit integer
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  candidate_ids uuid[];
  deleted_attempts integer;
  deleted_jobs integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'operational retention requires a managed worker transaction'
      using errcode='25000';
  end if;
  if candidate_job_type not in ('job_retention','log_retention')
     or candidate_limit is null
     or candidate_limit not between 1 and 10000 then
    raise exception 'operational retention input is invalid' using errcode='22023';
  end if;
  if not exists (
    select 1 from public.system_instance as instance
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'operational retention organization is unavailable' using errcode='42501';
  end if;

  perform set_config('boardagent.operational_retention','30-day-v1',true);

  if candidate_job_type='job_retention' then
    select coalesce(array_agg(candidate.id order by candidate.completed_at,candidate.id),'{}'::uuid[])
      into candidate_ids
      from (
        select job.id,job.completed_at
          from public.jobs as job
         where job.organization_id=candidate_organization_id
           and job.state in ('succeeded','dead','cancelled')
           and job.completed_at<=transaction_timestamp()-interval '30 days'
         order by job.completed_at,job.id
         for update skip locked
         limit candidate_limit
      ) as candidate;

    delete from public.job_attempt_results as attempt
     where attempt.job_id=any(candidate_ids);
    get diagnostics deleted_attempts=row_count;

    delete from public.jobs as job
     where job.id=any(candidate_ids)
       and job.organization_id=candidate_organization_id
       and job.state in ('succeeded','dead','cancelled')
       and job.completed_at<=transaction_timestamp()-interval '30 days';
    get diagnostics deleted_jobs=row_count;

    if deleted_jobs<>cardinality(candidate_ids) then
      raise exception 'locked job retention candidate changed before deletion'
        using errcode='40001';
    end if;
    return jsonb_build_object(
      'jobType','job_retention',
      'deletedJobAttempts',deleted_attempts,
      'deletedJobs',deleted_jobs
    );
  end if;

  select coalesce(array_agg(candidate.id order by candidate.completed_at,candidate.id),'{}'::uuid[])
    into candidate_ids
    from (
      select attempt.id,attempt.completed_at
        from public.notification_attempts as attempt
        join public.notification_jobs as notification
          on notification.id=attempt.notification_job_id
       where notification.organization_id=candidate_organization_id
         and notification.state in ('delivered','dead','cancelled')
         and attempt.completed_at<=transaction_timestamp()-interval '30 days'
       order by attempt.completed_at,attempt.id
       limit candidate_limit
    ) as candidate;

  delete from public.notification_attempts as attempt
   where attempt.id=any(candidate_ids);
  get diagnostics deleted_attempts=row_count;

  return jsonb_build_object(
    'jobType','log_retention',
    'deletedNotificationAttempts',deleted_attempts
  );
end
$$;

alter function public.boardagent_run_operational_retention(text,uuid,integer)
  owner to boardagent_migrator;
revoke all on function public.boardagent_run_operational_retention(text,uuid,integer) from public;
grant execute on function public.boardagent_run_operational_retention(text,uuid,integer)
  to boardagent_worker;
