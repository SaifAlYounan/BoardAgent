-- BoardAgent Phase 1 / group 30: typed transactional outbox and protected worker leases.

-- Runtime roles never mutate or enumerate the generic queue directly. The server and
-- worker enter through the narrowly granted functions below; the migrator owns the
-- implementation and remains subject to explicit FORCE-RLS policies.
revoke select, insert, update on public.jobs from boardagent_server;
revoke select, insert, update on public.jobs from boardagent_worker;

do $worker_job_column_revoke$
declare
  granted_column record;
begin
  for granted_column in
    select table_schema, table_name, column_name
      from information_schema.column_privileges
     where table_schema='public'
       and table_name='jobs'
       and grantee='boardagent_worker'
       and privilege_type='UPDATE'
  loop
    execute format(
      'revoke update (%I) on %I.%I from boardagent_worker',
      granted_column.column_name,
      granted_column.table_schema,
      granted_column.table_name
    );
  end loop;
end;
$worker_job_column_revoke$;

alter table public.jobs
  add column lease_token uuid,
  add column lease_started_at timestamptz(6),
  add constraint jobs_lease_projection_ck check (
    (state='leased'
      and lease_owner is not null
      and lease_owner ~ '^[A-Za-z0-9._:-]{1,128}$'
      and lease_token is not null
      and lease_started_at is not null
      and lease_expires_at is not null
      and lease_expires_at>lease_started_at
      and completed_at is null)
    or
    (state<>'leased'
      and lease_owner is null
      and lease_token is null
      and lease_started_at is null
      and lease_expires_at is null)
  ),
  add constraint jobs_terminal_projection_ck check (
    (state in ('succeeded','dead','cancelled') and completed_at is not null)
    or (state not in ('succeeded','dead','cancelled') and completed_at is null)
  );

create index jobs_expired_lease_idx
  on public.jobs(lease_expires_at,id) where state='leased';

create table public.job_attempt_results (
  job_id uuid not null references public.jobs(id) on delete restrict,
  attempt integer not null check (attempt between 1 and 100),
  lease_token uuid not null,
  lease_owner text not null check (lease_owner ~ '^[A-Za-z0-9._:-]{1,128}$'),
  result_class text not null check (
    result_class in ('succeeded','retryable_failure','permanent_failure','lease_expired')
  ),
  result_sha256 bytea not null check (public.boardagent_hash_is_sha256(result_sha256)),
  error_class text check (error_class is null or error_class ~ '^[a-z][a-z0-9_.-]{1,127}$'),
  resulting_state text not null check (resulting_state in ('succeeded','retry','dead')),
  started_at timestamptz(6) not null,
  completed_at timestamptz(6) not null,
  primary key (job_id,attempt),
  unique (job_id,lease_token),
  check (completed_at>=started_at),
  check ((result_class='succeeded' and error_class is null and resulting_state='succeeded')
      or (result_class<>'succeeded' and error_class is not null
          and resulting_state in ('retry','dead')))
);

alter table public.job_attempt_results enable row level security;
alter table public.job_attempt_results force row level security;
alter table public.job_attempt_results owner to boardagent_migrator;

grant select on
  organizations,
  boards,
  members,
  votes,
  notices,
  notification_jobs,
  export_requests,
  jobs,
  job_attempt_results
to boardagent_migrator;
grant insert, update on public.jobs to boardagent_migrator;
grant insert on public.job_attempt_results to boardagent_migrator;
grant select on public.job_attempt_results to boardagent_backup;

create policy boardagent_migrator_job_runtime_read on public.organizations
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_job_runtime_read on public.votes
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_job_runtime_read on public.notices
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_job_runtime_read on public.notification_jobs
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_job_runtime_read on public.export_requests
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_job_runtime_all on public.jobs
  for all to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_job_attempt_read on public.job_attempt_results
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_job_attempt_insert on public.job_attempt_results
  for insert to boardagent_migrator with check (true);
create policy boardagent_backup_read on public.job_attempt_results
  for select to boardagent_backup using (true);

create function public.boardagent_typed_job_types()
returns text[]
language sql
immutable
parallel safe
set search_path = pg_catalog
as $$
  select array[
    'action_due_scan',
    'action_stage_expiry',
    'audit_checkpoint',
    'audit_verify',
    'automatic_vote_close',
    'backup_receipt_verify',
    'backup_trigger',
    'certificate_recovery',
    'clock_health',
    'compatibility_alert',
    'dependency_compatibility_alert',
    'export_artifact_expiry',
    'export_build',
    'export_reconcile',
    'feed_consistency_check',
    'feed_reconcile',
    'job_lease_reaper',
    'job_retention',
    'key_compatibility_alert',
    'log_retention',
    'notice_fanout',
    'notification_dead_letter_alert',
    'notification_lease_reaper',
    'notification_retry',
    'oauth_ephemera_expiry',
    'protocol_compatibility_alert',
    'question_due_scan',
    'rate_bucket_retention',
    'refresh_session_revocation',
    'restore_due_alert',
    'task_due_scan',
    'vote_deadline_scan',
    'webhook_delivery',
    'wizard_expiry'
  ]::text[]
$$;

create function public.boardagent_guard_typed_job_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  payload jsonb;
  parameters jsonb;
begin
  begin
    payload := convert_from(new.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'typed job payload must be one strict UTF-8 JSON object'
      using errcode='23514';
  end;

  if jsonb_typeof(payload)<>'object'
     or not payload ?& array[
       'schemaVersion','organizationId','boardId','jobType','subjectType','subjectId','parameters'
     ]
     or payload-array[
       'schemaVersion','organizationId','boardId','jobType','subjectType','subjectId','parameters'
     ]::text[] <> '{}'::jsonb
     or jsonb_typeof(payload->'parameters')<>'object'
     or pg_catalog.sha256(new.canonical_payload) is distinct from new.payload_sha256
     or new.job_type<>all(public.boardagent_typed_job_types())
     or new.schema_version is distinct from 'boardagent.job.'||new.job_type||'.v1'
     or payload->>'schemaVersion' is distinct from new.schema_version
     or payload->>'organizationId' is distinct from new.organization_id::text
     or payload->>'jobType' is distinct from new.job_type
     or payload->>'subjectType' is distinct from new.subject_type
     or payload->>'subjectId' is distinct from new.subject_id::text
     or payload->'boardId' is distinct from (
       case when new.board_id is null then 'null'::jsonb else to_jsonb(new.board_id::text) end
     )
     or new.subject_id is null then
    raise exception 'typed job row, payload, hash, or closed type registry does not match'
      using errcode='23514';
  end if;

  parameters := payload->'parameters';

  if new.job_type in ('action_due_scan','question_due_scan','task_due_scan','vote_deadline_scan') then
    if new.subject_type<>'board'
       or new.board_id is null
       or new.subject_id<>new.board_id
       or not parameters ? 'through'
       or parameters-array['through']::text[]<>'{}'::jsonb
       or jsonb_typeof(parameters->'through')<>'string'
       or length(parameters->>'through') not between 20 and 35 then
      raise exception 'board scan job binding is invalid' using errcode='23514';
    end if;
    perform (parameters->>'through')::timestamptz;
  elsif new.job_type in ('automatic_vote_close','certificate_recovery') then
    if new.subject_type<>'vote'
       or new.board_id is null
       or parameters-array['voteId']::text[]<>'{}'::jsonb
       or parameters->>'voteId' is distinct from new.subject_id::text
       or not exists (
         select 1 from public.votes as vote
          where vote.id=new.subject_id
            and vote.organization_id=new.organization_id
            and vote.board_id=new.board_id
            and ((new.job_type='automatic_vote_close'
                  and vote.state='open'
                  and vote.close_mode='automatic'
                  and vote.current_decision_package_id is not null
                  and vote.deadline_at<=pg_catalog.clock_timestamp()
                  and coalesce((
                    select sample.healthy
                           and sample.valid_until>pg_catalog.clock_timestamp()
                      from public.clock_health_samples as sample
                     where sample.organization_id=vote.organization_id
                       and sample.measured_at<=pg_catalog.clock_timestamp()
                     order by sample.measured_at desc,sample.id desc
                     limit 1
                  ),false))
              or (new.job_type='certificate_recovery' and vote.state='closing'))
       ) then
      raise exception 'vote job does not bind an eligible vote on the exact board'
        using errcode='23514';
    end if;
  elsif new.job_type='notice_fanout' then
    if new.subject_type<>'notice'
       or new.board_id is null
       or parameters-array['noticeId']::text[]<>'{}'::jsonb
       or parameters->>'noticeId' is distinct from new.subject_id::text
       or not exists (
         select 1 from public.notices as notice
          where notice.id=new.subject_id
            and notice.organization_id=new.organization_id
            and notice.board_id=new.board_id
       ) then
      raise exception 'notice job does not bind a notice on the exact board'
        using errcode='23514';
    end if;
  elsif new.job_type in ('webhook_delivery','notification_retry','notification_dead_letter_alert') then
    if new.subject_type<>'notification_job'
       or new.board_id is null
       or parameters-array['notificationJobId']::text[]<>'{}'::jsonb
       or parameters->>'notificationJobId' is distinct from new.subject_id::text
       or not exists (
         select 1
           from public.notification_jobs as notification
           join public.notices as notice on notice.id=notification.notice_id
          where notification.id=new.subject_id
            and notification.organization_id=new.organization_id
            and notice.organization_id=new.organization_id
            and notice.board_id=new.board_id
       ) then
      raise exception 'notification job does not bind a notification on the exact board'
        using errcode='23514';
    end if;
  elsif new.job_type='export_build' then
    if new.subject_type<>'export_request'
       or parameters-array['exportRequestId']::text[]<>'{}'::jsonb
       or parameters->>'exportRequestId' is distinct from new.subject_id::text
       or not exists (
         select 1 from public.export_requests as export_request
          where export_request.id=new.subject_id
            and export_request.organization_id=new.organization_id
            and export_request.board_id is not distinct from new.board_id
            and export_request.state='queued'
       ) then
      raise exception 'export job does not bind an exact queued export request'
        using errcode='23514';
    end if;
  elsif new.job_type='feed_reconcile' then
    if new.subject_type<>'member'
       or new.board_id is null
       or parameters-array['memberId']::text[]<>'{}'::jsonb
       or parameters->>'memberId' is distinct from new.subject_id::text
       or not exists (
         select 1
           from public.members as member
           join public.board_memberships as membership
             on membership.organization_id=member.organization_id
            and membership.member_id=member.id
            and membership.board_id=new.board_id
          where member.id=new.subject_id
            and member.organization_id=new.organization_id
       ) then
      raise exception 'feed reconciliation job does not bind an exact organization member and board'
        using errcode='23514';
    end if;
  elsif new.job_type='audit_checkpoint' then
    if new.subject_type<>'organization'
       or new.board_id is not null
       or new.subject_id<>new.organization_id
       or not parameters ? 'throughSequence'
       or parameters-array['throughSequence']::text[]<>'{}'::jsonb
       or parameters->>'throughSequence' !~ '^[1-9][0-9]*$'
       or not exists (select 1 from public.organizations where id=new.organization_id) then
      raise exception 'audit checkpoint job binding is invalid' using errcode='23514';
    end if;
  else
    if new.subject_type<>'organization'
       or new.board_id is not null
       or new.subject_id<>new.organization_id
       or parameters<>'{}'::jsonb
       or not exists (select 1 from public.organizations where id=new.organization_id) then
      raise exception 'organization job binding is invalid' using errcode='23514';
    end if;
  end if;

  return new;
exception
  when invalid_text_representation or datetime_field_overflow then
    raise exception 'typed job contains an invalid typed identifier or timestamp'
      using errcode='23514';
end;
$$;

create trigger boardagent_typed_job_insert
before insert on public.jobs
for each row execute function public.boardagent_guard_typed_job_insert();

create function public.boardagent_enqueue_request_job(
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

create function public.boardagent_claim_typed_job(
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
       order by queued.available_at,queued.id
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

create function public.boardagent_heartbeat_typed_job(
  candidate_job_id uuid,
  candidate_lease_owner text,
  candidate_attempt integer,
  candidate_lease_token uuid,
  candidate_lease_seconds integer
)
returns timestamptz
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  now_at timestamptz(6);
  next_expiry timestamptz(6);
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'job heartbeat requires a managed worker transaction' using errcode='25000';
  end if;
  if candidate_lease_owner is null
     or candidate_lease_owner!~'^[A-Za-z0-9._:-]{1,128}$'
     or candidate_attempt not between 1 and 100
     or candidate_lease_token is null
     or candidate_lease_seconds not between 5 and 300 then
    raise exception 'job heartbeat inputs are invalid' using errcode='22023';
  end if;
  now_at := clock_timestamp();
  update public.jobs
     set lease_expires_at=greatest(
       lease_expires_at,
       now_at+make_interval(secs=>candidate_lease_seconds)
     )
   where id=candidate_job_id
     and state='leased'
     and attempts=candidate_attempt
     and lease_owner=candidate_lease_owner
     and lease_token=candidate_lease_token
     and lease_expires_at>now_at
  returning lease_expires_at into next_expiry;
  return next_expiry;
end;
$$;

create function public.boardagent_complete_typed_job(
  candidate_job_id uuid,
  candidate_lease_owner text,
  candidate_attempt integer,
  candidate_lease_token uuid,
  candidate_result_class text,
  candidate_result_sha256 bytea,
  candidate_error_class text
)
returns table(resulting_state text,replayed boolean)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  now_at timestamptz(6);
  job_row public.jobs%rowtype;
  prior public.job_attempt_results%rowtype;
  next_state text;
  delay_seconds integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'job completion requires a managed worker transaction' using errcode='25000';
  end if;
  if candidate_lease_owner is null
     or candidate_lease_owner!~'^[A-Za-z0-9._:-]{1,128}$'
     or candidate_attempt not between 1 and 100
     or candidate_lease_token is null
     or candidate_result_class not in ('succeeded','retryable_failure','permanent_failure')
     or not public.boardagent_hash_is_sha256(candidate_result_sha256)
     or (candidate_result_class='succeeded' and candidate_error_class is not null)
     or (candidate_result_class<>'succeeded'
         and (candidate_error_class is null
              or candidate_error_class!~'^[a-z][a-z0-9_.-]{1,127}$')) then
    raise exception 'job completion inputs are invalid' using errcode='22023';
  end if;

  select * into prior
    from public.job_attempt_results
   where job_id=candidate_job_id and attempt=candidate_attempt;
  if found then
    if prior.lease_owner is distinct from candidate_lease_owner
       or prior.lease_token is distinct from candidate_lease_token
       or prior.result_class is distinct from candidate_result_class
       or prior.result_sha256 is distinct from candidate_result_sha256
       or prior.error_class is distinct from candidate_error_class then
      raise exception 'job attempt result conflicts with immutable prior result'
        using errcode='23505';
    end if;
    resulting_state := prior.resulting_state;
    replayed := true;
    return next;
    return;
  end if;

  now_at := clock_timestamp();
  select * into job_row from public.jobs where id=candidate_job_id for update;
  if not found
     or job_row.state<>'leased'
     or job_row.attempts<>candidate_attempt
     or job_row.lease_owner is distinct from candidate_lease_owner
     or job_row.lease_token is distinct from candidate_lease_token
     or job_row.lease_expires_at<=now_at then
    return;
  end if;

  if candidate_result_class='succeeded' then
    next_state := 'succeeded';
  elsif candidate_result_class='permanent_failure' or candidate_attempt>=10 then
    next_state := 'dead';
  else
    next_state := 'retry';
  end if;
  delay_seconds := least(86400,(30*power(2,least(candidate_attempt-1,11)))::integer);

  insert into public.job_attempt_results(
    job_id,attempt,lease_token,lease_owner,result_class,result_sha256,error_class,
    resulting_state,started_at,completed_at
  ) values (
    candidate_job_id,candidate_attempt,candidate_lease_token,candidate_lease_owner,
    candidate_result_class,candidate_result_sha256,candidate_error_class,next_state,
    job_row.lease_started_at,now_at
  );

  update public.jobs
     set state=next_state,
         available_at=case when next_state='retry'
           then now_at+make_interval(secs=>delay_seconds) else available_at end,
         lease_owner=null,
         lease_token=null,
         lease_started_at=null,
         lease_expires_at=null,
         last_error_class=case when next_state='succeeded' then null else candidate_error_class end,
         completed_at=case when next_state in ('succeeded','dead') then now_at else null end
   where id=candidate_job_id;

  resulting_state := next_state;
  replayed := false;
  return next;
end;
$$;

create function public.boardagent_reap_expired_typed_jobs(candidate_limit integer default 100)
returns table(retried integer,dead integer)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  now_at timestamptz(6);
  expired public.jobs%rowtype;
  next_state text;
  delay_seconds integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'job lease reaper requires a managed worker transaction' using errcode='25000';
  end if;
  if candidate_limit not between 1 and 10000 then
    raise exception 'job lease reaper limit is invalid' using errcode='22023';
  end if;
  retried := 0;
  dead := 0;
  now_at := clock_timestamp();

  for expired in
    select * from public.jobs
     where state='leased' and lease_expires_at<=now_at
     order by lease_expires_at,id
     for update skip locked
     limit candidate_limit
  loop
    next_state := case when expired.attempts>=10 then 'dead' else 'retry' end;
    delay_seconds := least(86400,(30*power(2,least(expired.attempts-1,11)))::integer);
    insert into public.job_attempt_results(
      job_id,attempt,lease_token,lease_owner,result_class,result_sha256,error_class,
      resulting_state,started_at,completed_at
    ) values (
      expired.id,expired.attempts,expired.lease_token,expired.lease_owner,'lease_expired',
      pg_catalog.sha256(pg_catalog.convert_to(
        'boardagent.job.lease_expired.v1:'||expired.id::text||':'||expired.attempts::text,
        'UTF8'
      )),
      'lease_expired',next_state,expired.lease_started_at,now_at
    );
    update public.jobs
       set state=next_state,
           available_at=case when next_state='retry'
             then now_at+make_interval(secs=>delay_seconds) else available_at end,
           lease_owner=null,
           lease_token=null,
           lease_started_at=null,
           lease_expires_at=null,
           last_error_class='lease_expired',
           completed_at=case when next_state='dead' then now_at else null end
     where id=expired.id;
    if next_state='retry' then retried := retried+1; else dead := dead+1; end if;
  end loop;
  return next;
end;
$$;

alter function public.boardagent_typed_job_types() owner to boardagent_migrator;
alter function public.boardagent_guard_typed_job_insert() owner to boardagent_migrator;
alter function public.boardagent_enqueue_request_job(uuid,uuid,uuid,text,text,text,uuid,bytea,bytea,text,timestamptz)
  owner to boardagent_migrator;
alter function public.boardagent_claim_typed_job(text,integer) owner to boardagent_migrator;
alter function public.boardagent_heartbeat_typed_job(uuid,text,integer,uuid,integer)
  owner to boardagent_migrator;
alter function public.boardagent_complete_typed_job(uuid,text,integer,uuid,text,bytea,text)
  owner to boardagent_migrator;
alter function public.boardagent_reap_expired_typed_jobs(integer) owner to boardagent_migrator;

revoke all on function public.boardagent_typed_job_types() from public;
revoke all on function public.boardagent_guard_typed_job_insert() from public;
revoke all on function public.boardagent_enqueue_request_job(uuid,uuid,uuid,text,text,text,uuid,bytea,bytea,text,timestamptz)
  from public;
revoke all on function public.boardagent_claim_typed_job(text,integer) from public;
revoke all on function public.boardagent_heartbeat_typed_job(uuid,text,integer,uuid,integer) from public;
revoke all on function public.boardagent_complete_typed_job(uuid,text,integer,uuid,text,bytea,text)
  from public;
revoke all on function public.boardagent_reap_expired_typed_jobs(integer) from public;

grant execute on function public.boardagent_enqueue_request_job(uuid,uuid,uuid,text,text,text,uuid,bytea,bytea,text,timestamptz)
  to boardagent_server;
grant execute on function public.boardagent_claim_typed_job(text,integer)
  to boardagent_worker;
grant execute on function public.boardagent_heartbeat_typed_job(uuid,text,integer,uuid,integer)
  to boardagent_worker;
grant execute on function public.boardagent_complete_typed_job(uuid,text,integer,uuid,text,bytea,text)
  to boardagent_worker;
grant execute on function public.boardagent_reap_expired_typed_jobs(integer)
  to boardagent_worker;

create trigger boardagent_job_attempt_results_immutable
before update or delete on public.job_attempt_results
for each row execute function public.boardagent_reject_evidence_mutation();
