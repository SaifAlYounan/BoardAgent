-- BoardAgent Phase 4 / group 76: protected notification lease recovery and
-- durable dead-letter alert outbox authority. The worker never regains direct
-- table mutation or enumeration rights.

create function public.boardagent_notification_delivery_state(
  candidate_notification_job_id uuid
)
returns text
language plpgsql
stable
security definer
set search_path=pg_catalog,public
as $$
declare
  resolved_state text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_notification_job_id is null
     or not public.boardagent_is_uuid_v7(candidate_notification_job_id) then
    raise exception 'notification state lookup input is invalid' using errcode='22023';
  end if;
  select notification.state into resolved_state
    from public.notification_jobs as notification
   where notification.id=candidate_notification_job_id;
  return resolved_state;
end
$$;

create function public.boardagent_reap_expired_notification_leases(
  candidate_organization_id uuid,
  candidate_attempt_ids uuid[]
)
returns table(
  reaped integer,
  retried integer,
  dead integer,
  dead_notification_ids uuid[]
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  now_at timestamptz(6);
  expired public.notification_jobs%rowtype;
  next_state text;
  delay_seconds integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or candidate_attempt_ids is null
     or cardinality(candidate_attempt_ids) not between 1 and 100
     or exists (
       select 1 from unnest(candidate_attempt_ids) as candidate(id)
        where candidate.id is null or not public.boardagent_is_uuid_v7(candidate.id)
     )
     or (select count(distinct candidate.id) from unnest(candidate_attempt_ids) as candidate(id))
        <>cardinality(candidate_attempt_ids)
     or not exists (
       select 1 from public.organizations as organization
        where organization.id=candidate_organization_id
     ) then
    raise exception 'notification lease reaper input is invalid' using errcode='22023';
  end if;

  reaped := 0;
  retried := 0;
  dead := 0;
  dead_notification_ids := '{}'::uuid[];
  now_at := clock_timestamp();

  for expired in
    select candidate.*
      from public.notification_jobs as candidate
     where candidate.organization_id=candidate_organization_id
       and candidate.state='leased'
       and candidate.lease_expires_at<=now_at
     order by candidate.lease_expires_at,candidate.id
     for update skip locked
     limit cardinality(candidate_attempt_ids)
  loop
    reaped := reaped+1;
    next_state := case when expired.attempts>=10 then 'dead' else 'retry' end;
    delay_seconds := least(86400,(30*power(2,least(expired.attempts-1,11)))::integer);

    insert into public.notification_attempts(
      id,notification_job_id,attempt,request_sha256,result_class,error_class,
      http_status,response_sha256,started_at,completed_at
    ) values (
      candidate_attempt_ids[reaped],expired.id,expired.attempts,
      pg_catalog.sha256(pg_catalog.convert_to(
        'boardagent.notification.lease_expired.v1:'||expired.id::text||':'||
          expired.attempts::text,
        'UTF8'
      )),
      'retryable_failure','notification_lease_expired',null,null,
      expired.lease_started_at,now_at
    );

    update public.notification_jobs
       set state=next_state,
           available_at=case when next_state='retry'
             then now_at+make_interval(secs=>delay_seconds) else available_at end,
           lease_owner=null,
           lease_started_at=null,
           lease_expires_at=null
     where id=expired.id;

    if next_state='retry' then
      retried := retried+1;
    else
      dead := dead+1;
      dead_notification_ids := array_append(dead_notification_ids,expired.id);
    end if;
  end loop;
  return next;
end
$$;

create function public.boardagent_notification_dead_letter_target(
  candidate_notification_job_id uuid
)
returns table(
  notification_job_id uuid,
  organization_id uuid,
  board_id uuid,
  state text
)
language plpgsql
stable
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_notification_job_id is null
     or not public.boardagent_is_uuid_v7(candidate_notification_job_id) then
    raise exception 'notification dead-letter lookup input is invalid' using errcode='22023';
  end if;
  return query
    select notification.id,notification.organization_id,notice.board_id,notification.state
      from public.notification_jobs as notification
      join public.notices as notice
        on notice.id=notification.notice_id
       and notice.organization_id=notification.organization_id
     where notification.id=candidate_notification_job_id
       and notification.source_kind='notice'
       and notification.state='dead';
end
$$;

create function public.boardagent_enqueue_notification_dead_letter_alert(
  candidate_job_id uuid,
  candidate_notification_job_id uuid
)
returns table(job_id uuid,replayed boolean)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  target record;
  payload_bytes bytea;
  stored public.jobs%rowtype;
  target_key text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_job_id is null
     or not public.boardagent_is_uuid_v7(candidate_job_id)
     or candidate_notification_job_id is null
     or not public.boardagent_is_uuid_v7(candidate_notification_job_id) then
    raise exception 'notification dead-letter enqueue input is invalid' using errcode='22023';
  end if;

  select notification.organization_id,notice.board_id
    into target
    from public.notification_jobs as notification
    join public.notices as notice
      on notice.id=notification.notice_id
     and notice.organization_id=notification.organization_id
   where notification.id=candidate_notification_job_id
     and notification.source_kind='notice'
     and notification.state='dead'
   for update of notification;
  if not found then
    return;
  end if;

  payload_bytes := convert_to(
    '{"boardId":'||to_jsonb(target.board_id::text)::text||
    ',"jobType":"notification_dead_letter_alert"'||
    ',"organizationId":'||to_jsonb(target.organization_id::text)::text||
    ',"parameters":{"notificationJobId":'||
      to_jsonb(candidate_notification_job_id::text)::text||'}'||
    ',"schemaVersion":"boardagent.job.notification_dead_letter_alert.v1"'||
    ',"subjectId":'||to_jsonb(candidate_notification_job_id::text)::text||
    ',"subjectType":"notification_job"}',
    'UTF8'
  );
  target_key := 'notification-dead-letter:'||candidate_notification_job_id::text;

  insert into public.jobs(
    id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
    canonical_payload,payload_sha256,idempotency_key
  ) values (
    candidate_job_id,target.organization_id,target.board_id,
    'notification_dead_letter_alert',
    'boardagent.job.notification_dead_letter_alert.v1','notification_job',
    candidate_notification_job_id,payload_bytes,pg_catalog.sha256(payload_bytes),target_key
  ) on conflict (organization_id,job_type,idempotency_key) do nothing
  returning * into stored;

  if found then
    job_id := stored.id;
    replayed := false;
    return next;
    return;
  end if;

  select * into stored
    from public.jobs as candidate
   where candidate.organization_id=target.organization_id
     and candidate.job_type='notification_dead_letter_alert'
     and candidate.idempotency_key=target_key;
  if not found
     or stored.board_id is distinct from target.board_id
     or stored.subject_type<>'notification_job'
     or stored.subject_id is distinct from candidate_notification_job_id
     or stored.canonical_payload<>payload_bytes
     or stored.payload_sha256<>pg_catalog.sha256(payload_bytes) then
    raise exception 'notification dead-letter idempotency binding conflicts'
      using errcode='23505';
  end if;
  job_id := stored.id;
  replayed := true;
  return next;
end
$$;

alter function public.boardagent_notification_delivery_state(uuid)
  owner to boardagent_migrator;
alter function public.boardagent_reap_expired_notification_leases(uuid,uuid[])
  owner to boardagent_migrator;
alter function public.boardagent_notification_dead_letter_target(uuid)
  owner to boardagent_migrator;
alter function public.boardagent_enqueue_notification_dead_letter_alert(uuid,uuid)
  owner to boardagent_migrator;

revoke all on function public.boardagent_notification_delivery_state(uuid) from public;
revoke all on function public.boardagent_reap_expired_notification_leases(uuid,uuid[]) from public;
revoke all on function public.boardagent_notification_dead_letter_target(uuid) from public;
revoke all on function public.boardagent_enqueue_notification_dead_letter_alert(uuid,uuid) from public;

grant execute on function public.boardagent_notification_delivery_state(uuid)
  to boardagent_worker;
grant execute on function public.boardagent_reap_expired_notification_leases(uuid,uuid[])
  to boardagent_worker;
grant execute on function public.boardagent_notification_dead_letter_target(uuid)
  to boardagent_worker;
grant execute on function public.boardagent_enqueue_notification_dead_letter_alert(uuid,uuid)
  to boardagent_worker;
