-- Enumerate only stopped or expired, uncaptured export preparations. Runtime roles retain no
-- direct queue enumeration authority; the worker receives only locked request IDs.
create function public.boardagent_stopped_export_requests(candidate_organization_id uuid)
returns table(export_request_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or current_setting('transaction_isolation')<>'serializable' then
    raise exception 'stopped export reconciliation requires a serializable worker transaction'
      using errcode='25000';
  end if;
  if not exists (select 1 from public.system_instance
      where singleton_key and organization_id=candidate_organization_id) then
    raise exception 'export reconciliation instance mismatch' using errcode='22023';
  end if;
  -- Expired requests still need a terminal result after30-day operational job
  -- retention removed the old dead job. Never delete or relabel governance history.
  return query
  select request.id from public.export_requests as request
      where request.organization_id=candidate_organization_id and request.state='queued'
        and current_setting('boardagent.transaction_scope',true)='worker'
        and (request.expires_at<=transaction_timestamp() or exists (
          select 1 from public.jobs as job
            where job.organization_id=request.organization_id
              and job.job_type='export_build' and job.subject_type='export_request'
              and job.subject_id=request.id and job.state='dead'
        ))
        and not exists (
          select 1 from public.jobs as job
            where job.organization_id=request.organization_id
              and job.job_type='export_build' and job.subject_type='export_request'
              and job.subject_id=request.id and job.state in ('queued','retry','leased')
        )
        and not exists (
          select 1 from public.export_artifacts as artifact where artifact.export_request_id=request.id
        )
      order by request.created_at,request.id limit 100 for update of request skip locked;
end;
$$;
alter function public.boardagent_stopped_export_requests(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_stopped_export_requests(uuid) from public;
grant execute on function public.boardagent_stopped_export_requests(uuid) to boardagent_worker;
