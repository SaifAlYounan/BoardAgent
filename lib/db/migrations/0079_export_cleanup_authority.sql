-- BoardAgent Phase 4 / group 79: 24-hour export artifact TTL and crash-safe cleanup authority.

alter table public.export_artifacts
  add column expires_at timestamptz(6),
  add column cleanup_lease_token uuid,
  add column cleanup_lease_expires_at timestamptz(6);

update public.export_artifacts
   set expires_at=created_at+interval '24 hours';

alter table public.export_artifacts
  alter column expires_at set not null,
  alter column expires_at set default (transaction_timestamp()+interval '24 hours'),
  add constraint export_artifacts_exact_ttl_ck
    check (expires_at=created_at+interval '24 hours'),
  add constraint export_artifacts_cleanup_lease_ck check (
    (cleanup_lease_token is null and cleanup_lease_expires_at is null)
    or
    (cleanup_lease_token is not null and cleanup_lease_expires_at is not null)
  );

create index export_artifacts_cleanup_idx
  on public.export_artifacts(state,expires_at,id)
  where state in ('ready','quarantined','expired');

-- Cleanup metadata is owned by the protected worker functions, not by arbitrary role SQL.
revoke update on public.export_artifacts from boardagent_server,boardagent_worker;
grant update(state,deleted_at) on public.export_artifacts to boardagent_worker;

create policy boardagent_migrator_export_cleanup_artifacts
  on public.export_artifacts for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');

create function public.boardagent_claim_export_artifact_cleanup(
  candidate_organization_id uuid,
  candidate_mode text,
  candidate_cleanup_token uuid,
  candidate_lease_seconds integer
)
returns table(
  export_request_id uuid,
  artifact_id uuid,
  canonical_manifest bytea,
  stored_manifest_sha256 bytea,
  cleanup_reason text,
  cleanup_token uuid
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  candidate record;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_mode not in ('expiry','reconcile')
     or candidate_organization_id is null
     or candidate_cleanup_token is null
     or candidate_lease_seconds not between 30 and 300 then
    raise exception 'export cleanup claim requires one managed bounded worker request'
      using errcode='25000';
  end if;

  select request.id as request_id,request.state as request_state,
         artifact.id as artifact_id,artifact.state as artifact_state,
         artifact.manifest,artifact.manifest_sha256,
         case
           when artifact.state='ready' then 'ttl_expired'
           when artifact.state='expired' then 'deletion_requested'
           else 'quarantined_partial'
         end as reason
    into candidate
    from public.export_artifacts as artifact
    join public.export_requests as request on request.id=artifact.export_request_id
   where request.organization_id=candidate_organization_id
     and artifact.state in ('ready','quarantined','expired')
     and (
       artifact.cleanup_lease_token=candidate_cleanup_token
       or artifact.cleanup_lease_expires_at is null
       or artifact.cleanup_lease_expires_at<=transaction_timestamp()
     )
     and (
       (candidate_mode='expiry' and (
         (artifact.state='ready' and artifact.expires_at<=transaction_timestamp()
          and request.state='succeeded')
         or (artifact.state='expired' and request.state in ('expired','succeeded'))
         or (artifact.state='quarantined' and request.state in ('failed','cancelled'))
       ))
       or
       (candidate_mode='reconcile' and (
         (artifact.state='expired' and request.state in ('expired','succeeded'))
         or (artifact.state='quarantined' and request.state in ('failed','cancelled'))
       ))
     )
   order by
     case artifact.state when 'expired' then 0 when 'quarantined' then 1 else 2 end,
     artifact.expires_at,
     artifact.id
   for update of request,artifact skip locked
   limit 1;

  if candidate.artifact_id is null then
    return;
  end if;

  if candidate.artifact_state='ready' then
    update public.export_artifacts
       set state='expired'
     where id=candidate.artifact_id and state='ready';
    update public.export_requests
       set state='expired',row_version=row_version+1
     where id=candidate.request_id and state='succeeded';
  end if;

  update public.export_artifacts
     set cleanup_lease_token=candidate_cleanup_token,
         cleanup_lease_expires_at=transaction_timestamp()
           +make_interval(secs=>candidate_lease_seconds)
   where id=candidate.artifact_id;

  return query select
    candidate.request_id,
    candidate.artifact_id,
    candidate.manifest,
    candidate.manifest_sha256,
    candidate.reason,
    candidate_cleanup_token;
end
$$;

create function public.boardagent_complete_export_artifact_cleanup(
  candidate_organization_id uuid,
  candidate_export_request_id uuid,
  candidate_artifact_id uuid,
  candidate_cleanup_token uuid,
  candidate_storage_deleted boolean
)
returns table(
  export_request_id uuid,
  artifact_id uuid,
  organization_id uuid,
  board_id uuid,
  prior_artifact_state text,
  manifest_sha256 bytea,
  content_set_sha256 bytea
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  candidate record;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or not candidate_storage_deleted then
    raise exception 'export cleanup completion requires verified storage deletion'
      using errcode='25000';
  end if;
  select request.id as request_id,request.organization_id,request.board_id,
         request.state as request_state,artifact.id as artifact_id,
         artifact.state as artifact_state,artifact.manifest_sha256,
         artifact.content_set_sha256,artifact.cleanup_lease_token
    into strict candidate
    from public.export_requests as request
    join public.export_artifacts as artifact on artifact.export_request_id=request.id
   where request.id=candidate_export_request_id
     and request.organization_id=candidate_organization_id
     and artifact.id=candidate_artifact_id
   for update of request,artifact;
  if candidate.artifact_state not in ('expired','quarantined')
     or candidate.cleanup_lease_token is distinct from candidate_cleanup_token then
    raise exception 'export cleanup completion does not own the exact artifact'
      using errcode='55000';
  end if;

  update public.export_artifacts
     set state='deleted',deleted_at=transaction_timestamp(),
         cleanup_lease_token=null,cleanup_lease_expires_at=null
   where id=candidate.artifact_id;
  if candidate.request_state in ('succeeded','expired') then
    update public.export_requests
       set state='deleted',completed_at=coalesce(completed_at,transaction_timestamp()),
           row_version=row_version+1
     where id=candidate.request_id and state in ('succeeded','expired');
  end if;

  return query select
    candidate.request_id,candidate.artifact_id,candidate.organization_id,candidate.board_id,
    candidate.artifact_state,candidate.manifest_sha256,candidate.content_set_sha256;
exception
  when no_data_found then
    raise exception 'export cleanup target is unavailable' using errcode='P0002';
end
$$;

create function public.boardagent_release_export_artifact_cleanup(
  candidate_organization_id uuid,
  candidate_export_request_id uuid,
  candidate_artifact_id uuid,
  candidate_cleanup_token uuid
)
returns boolean
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  released integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'export cleanup release requires a managed worker request'
      using errcode='25000';
  end if;
  update public.export_artifacts as artifact
     set cleanup_lease_token=null,cleanup_lease_expires_at=null
    from public.export_requests as request
   where request.id=candidate_export_request_id
     and request.organization_id=candidate_organization_id
     and artifact.export_request_id=request.id
     and artifact.id=candidate_artifact_id
     and artifact.cleanup_lease_token=candidate_cleanup_token;
  get diagnostics released=row_count;
  return released=1;
end
$$;

create function public.boardagent_export_reconcile_target(
  candidate_organization_id uuid,
  candidate_export_request_id uuid
)
returns table(
  export_request_id uuid,
  request_state text,
  request_started_at text,
  artifact_id uuid,
  artifact_state text,
  canonical_manifest bytea,
  stored_manifest_sha256 bytea,
  active_export_build boolean,
  safe_to_fail_partial boolean
)
language plpgsql
stable
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'export reconciliation inspection requires a managed worker request'
      using errcode='25000';
  end if;
  return query
    select request.id,request.state,
           case when request.started_at is null then null else
             to_char(request.started_at at time zone 'UTC',
                     'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end,
           artifact.id,artifact.state,artifact.manifest,artifact.manifest_sha256,
           exists (
             select 1 from public.jobs as job
              where job.organization_id=request.organization_id
                and job.job_type='export_build'
                and job.subject_type='export_request'
                and job.subject_id=request.id
                and job.state='leased'
           ),
           request.state='running'
             and (
               request.expires_at<=transaction_timestamp()
               or (
                 request.started_at<=transaction_timestamp()-interval '5 minutes'
                 and not exists (
                   select 1 from public.jobs as job
                    where job.organization_id=request.organization_id
                      and job.job_type='export_build'
                      and job.subject_type='export_request'
                      and job.subject_id=request.id
                      and job.state='leased'
                 )
               )
             )
      from public.export_requests as request
      left join public.export_artifacts as artifact
        on artifact.export_request_id=request.id
     where request.organization_id=candidate_organization_id
       and request.id=candidate_export_request_id;
end
$$;

create function public.boardagent_settle_reconciled_export_build_jobs(
  candidate_organization_id uuid,
  candidate_export_request_id uuid
)
returns integer
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  settled integer;
  request_state text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'export build settlement requires a managed worker request'
      using errcode='25000';
  end if;
  select request.state into strict request_state
    from public.export_requests as request
   where request.id=candidate_export_request_id
     and request.organization_id=candidate_organization_id
   for update;
  if request_state not in ('succeeded','failed','cancelled','expired','deleted') then
    raise exception 'export build settlement requires a terminal reconciliation result'
      using errcode='55000';
  end if;
  update public.jobs
     set state='cancelled',completed_at=transaction_timestamp(),
         lease_owner=null,lease_token=null,lease_started_at=null,lease_expires_at=null
   where organization_id=candidate_organization_id
     and job_type='export_build'
     and subject_type='export_request'
     and subject_id=candidate_export_request_id
     and state in ('queued','retry');
  get diagnostics settled=row_count;
  return settled;
exception
  when no_data_found then
    raise exception 'export build settlement target is unavailable' using errcode='P0002';
end
$$;

do $export_cleanup_functions$
declare
  function_name regprocedure;
begin
  foreach function_name in array array[
    'public.boardagent_claim_export_artifact_cleanup(uuid,text,uuid,integer)'::regprocedure,
    'public.boardagent_complete_export_artifact_cleanup(uuid,uuid,uuid,uuid,boolean)'::regprocedure,
    'public.boardagent_release_export_artifact_cleanup(uuid,uuid,uuid,uuid)'::regprocedure,
    'public.boardagent_export_reconcile_target(uuid,uuid)'::regprocedure,
    'public.boardagent_settle_reconciled_export_build_jobs(uuid,uuid)'::regprocedure
  ]
  loop
    execute 'alter function '||function_name||' owner to boardagent_migrator';
    execute 'revoke all on function '||function_name||' from public';
    execute 'grant execute on function '||function_name||' to boardagent_worker';
  end loop;
end
$export_cleanup_functions$;
