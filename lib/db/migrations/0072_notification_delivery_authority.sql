-- BoardAgent Phase 4 / group 72: transactional notice fanout and contentless
-- webhook delivery leases. External network I/O remains outside every transaction.

alter table public.notification_jobs
  add column canonical_payload bytea,
  add column lease_started_at timestamptz(6);

update public.notification_jobs
   set canonical_payload=convert_to(
     '{"eventClass":'||to_jsonb(wake_class)::text||
     ',"occurredAt":'||to_jsonb(to_char(created_at at time zone 'UTC',
       'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text||
     ',"schemaVersion":"boardagent.webhook-wake.v1"'||
     ',"wakeId":'||to_jsonb(rtrim(translate(encode(random_wake_id,'base64'),'+/','-_'),'='))::text||'}',
     'UTF8'
   )
 where canonical_payload is null;

do $notification_payload_backfill$
begin
  if exists (
    select 1 from public.notification_jobs
     where canonical_payload is null
        or pg_catalog.sha256(canonical_payload)<>payload_sha256
  ) then
    raise exception 'legacy notification payload cannot be reconstructed exactly';
  end if;
end
$notification_payload_backfill$;

alter table public.notification_jobs
  alter column canonical_payload set not null,
  add constraint notification_jobs_canonical_payload_ck check (
    octet_length(canonical_payload) between 2 and 2048
    and pg_catalog.sha256(canonical_payload)=payload_sha256
  ),
  add constraint notification_jobs_lease_projection_v2_ck check (
    (state='leased'
      and lease_owner is not null
      and lease_owner~'^[A-Za-z0-9._:-]{1,128}$'
      and lease_started_at is not null
      and lease_expires_at is not null
      and lease_expires_at>lease_started_at)
    or
    (state<>'leased'
      and lease_owner is null
      and lease_started_at is null
      and lease_expires_at is null)
  );

alter table public.notification_attempts
  add column error_class text
    check (error_class is null or error_class~'^[a-z][a-z0-9_.-]{1,127}$'),
  add constraint notification_attempts_result_error_ck check (
    (result_class='delivered' and error_class is null)
    or (result_class<>'delivered' and error_class is not null)
  );

grant select on public.board_memberships,public.pending_action_feed to boardagent_migrator;
grant select,insert,update on public.notification_jobs to boardagent_migrator;
grant select,insert on public.notification_attempts to boardagent_migrator;

create policy boardagent_migrator_notification_membership_read
  on public.board_memberships for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_notification_feed_read
  on public.pending_action_feed for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_notification_jobs_all
  on public.notification_jobs for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true) in ('request','worker'))
  with check (current_setting('boardagent.transaction_scope',true) in ('request','worker'));
create policy boardagent_migrator_notification_attempts_read
  on public.notification_attempts for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_notification_attempts_insert
  on public.notification_attempts for insert to boardagent_migrator
  with check (current_setting('boardagent.transaction_scope',true)='worker');

create function public.boardagent_enqueue_notice_fanout(candidate_notice_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  notice public.notices%rowtype;
  payload_text text;
  payload_bytes bytea;
  stored public.jobs%rowtype;
begin
  select * into notice from public.notices where id=candidate_notice_id;
  if not found then
    raise exception 'notice fanout target is unavailable' using errcode='P0002';
  end if;
  payload_text :=
    '{"boardId":'||to_jsonb(notice.board_id::text)::text||
    ',"jobType":"notice_fanout"'||
    ',"organizationId":'||to_jsonb(notice.organization_id::text)::text||
    ',"parameters":{"noticeId":'||to_jsonb(notice.id::text)::text||'}'||
    ',"schemaVersion":"boardagent.job.notice_fanout.v1"'||
    ',"subjectId":'||to_jsonb(notice.id::text)::text||
    ',"subjectType":"notice"}';
  payload_bytes := convert_to(payload_text,'UTF8');
  insert into public.jobs(
    id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
    canonical_payload,payload_sha256,idempotency_key
  ) values (
    notice.id,notice.organization_id,notice.board_id,'notice_fanout',
    'boardagent.job.notice_fanout.v1','notice',notice.id,payload_bytes,
    pg_catalog.sha256(payload_bytes),'notice-fanout:'||notice.id::text
  ) on conflict (organization_id,job_type,idempotency_key) do nothing;

  select * into stored from public.jobs
   where organization_id=notice.organization_id and job_type='notice_fanout'
     and idempotency_key='notice-fanout:'||notice.id::text;
  if not found or stored.id<>notice.id or stored.board_id<>notice.board_id
     or stored.canonical_payload<>payload_bytes
     or stored.payload_sha256<>pg_catalog.sha256(payload_bytes) then
    raise exception 'notice fanout idempotency binding conflicts' using errcode='23505';
  end if;
end
$$;

create function public.boardagent_notice_fanout_trigger()
returns trigger
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  perform public.boardagent_enqueue_notice_fanout(new.id);
  return new;
end
$$;

create trigger boardagent_notice_fanout_outbox
after insert on public.notices
for each row execute function public.boardagent_notice_fanout_trigger();

do $backfill_notice_fanout$
declare
  notice_id uuid;
begin
  for notice_id in select id from public.notices order by id loop
    perform public.boardagent_enqueue_notice_fanout(notice_id);
  end loop;
end
$backfill_notice_fanout$;

create function public.boardagent_notice_webhook_targets(candidate_notice_id uuid)
returns table(
  organization_id uuid,
  board_id uuid,
  member_id uuid,
  webhook_id uuid,
  wake_class text
)
language plpgsql
stable
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'notice fanout requires a managed worker transaction' using errcode='25000';
  end if;
  return query
    select notice.organization_id,notice.board_id,notice.recipient_member_id,webhook.id,
           case when feed.state='pending' then 'pending_action'::text else 'notice'::text end
      from public.notices as notice
      join public.members as member
        on member.organization_id=notice.organization_id
       and member.id=notice.recipient_member_id and member.state='active'
      join public.board_memberships as membership
        on membership.organization_id=notice.organization_id
       and membership.board_id=notice.board_id
       and membership.member_id=notice.recipient_member_id
       and membership.state='active' and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
      join public.pending_action_feed as feed
        on feed.notice_id=notice.id and feed.organization_id=notice.organization_id
       and feed.board_id=notice.board_id and feed.member_id=notice.recipient_member_id
       and feed.entitlement_generation=membership.entitlement_generation
       and feed.state in ('pending','resolved')
      join public.member_webhooks as webhook
        on webhook.organization_id=notice.organization_id
       and webhook.member_id=notice.recipient_member_id and webhook.state='active'
     where notice.id=candidate_notice_id and notice.state in ('committed','delivered')
       and (case when feed.state='pending' then 'pending_action' else 'notice' end)
           =any(webhook.event_classes)
     order by webhook.id;
end
$$;

create function public.boardagent_create_notification_delivery(
  candidate_notification_id uuid,
  candidate_notice_id uuid,
  candidate_webhook_id uuid,
  candidate_wake_class text,
  candidate_random_wake_id bytea,
  candidate_canonical_payload bytea,
  candidate_payload_sha256 bytea
)
returns table(notification_job_id uuid,replayed boolean)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  target record;
  payload jsonb;
  expected_payload bytea;
  job_payload bytea;
  prior public.notification_jobs%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_notification_id is null
     or not public.boardagent_is_uuid_v7(candidate_notification_id)
     or candidate_wake_class not in ('pending_action','notice')
     or octet_length(candidate_random_wake_id)<>32
     or octet_length(candidate_canonical_payload) not between 2 and 2048
     or candidate_payload_sha256 is null
     or pg_catalog.sha256(candidate_canonical_payload)<>candidate_payload_sha256 then
    raise exception 'notification creation input is invalid' using errcode='22023';
  end if;
  begin
    payload := convert_from(candidate_canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'notification payload is invalid' using errcode='22023';
  end;
  expected_payload := convert_to(
    '{"eventClass":'||to_jsonb(payload->>'eventClass')::text||
    ',"occurredAt":'||to_jsonb(payload->>'occurredAt')::text||
    ',"schemaVersion":'||to_jsonb(payload->>'schemaVersion')::text||
    ',"wakeId":'||to_jsonb(payload->>'wakeId')::text||'}',
    'UTF8'
  );
  if not (payload ?& array['schemaVersion','eventClass','wakeId','occurredAt'])
     or payload-array['schemaVersion','eventClass','wakeId','occurredAt']::text[]<>'{}'::jsonb
     or candidate_canonical_payload<>expected_payload
     or payload->>'schemaVersion'<>'boardagent.webhook-wake.v1'
     or payload->>'eventClass'<>candidate_wake_class
     or payload->>'wakeId'<>rtrim(translate(encode(candidate_random_wake_id,'base64'),'+/','-_'),'=')
     or (payload->>'occurredAt')::timestamptz>clock_timestamp()+interval '1 second'
     or (payload->>'occurredAt')::timestamptz<clock_timestamp()-interval '5 minutes' then
    raise exception 'notification payload binding is invalid' using errcode='22023';
  end if;

  select * into prior from public.notification_jobs
   where notice_id=candidate_notice_id and webhook_id=candidate_webhook_id;
  if found then
    notification_job_id := prior.id;
    replayed := true;
    return next;
    return;
  end if;

  select * into target
    from public.boardagent_notice_webhook_targets(candidate_notice_id)
   where webhook_id=candidate_webhook_id and wake_class=candidate_wake_class;
  if not found then
    raise exception 'notification target is no longer entitled' using errcode='42501';
  end if;
  insert into public.notification_jobs(
    id,organization_id,notice_id,recipient_member_id,webhook_id,source_kind,wake_class,
    random_wake_id,canonical_payload,payload_sha256,state,created_at
  ) values (
    candidate_notification_id,target.organization_id,candidate_notice_id,target.member_id,
    candidate_webhook_id,'notice',candidate_wake_class,candidate_random_wake_id,
    candidate_canonical_payload,candidate_payload_sha256,'queued',
    (payload->>'occurredAt')::timestamptz
  );
  job_payload := convert_to(
    '{"boardId":'||to_jsonb(target.board_id::text)::text||
    ',"jobType":"webhook_delivery"'||
    ',"organizationId":'||to_jsonb(target.organization_id::text)::text||
    ',"parameters":{"notificationJobId":'||to_jsonb(candidate_notification_id::text)::text||'}'||
    ',"schemaVersion":"boardagent.job.webhook_delivery.v1"'||
    ',"subjectId":'||to_jsonb(candidate_notification_id::text)::text||
    ',"subjectType":"notification_job"}',
    'UTF8'
  );
  insert into public.jobs(
    id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
    canonical_payload,payload_sha256,idempotency_key
  ) values (
    candidate_notification_id,target.organization_id,target.board_id,'webhook_delivery',
    'boardagent.job.webhook_delivery.v1','notification_job',candidate_notification_id,
    job_payload,pg_catalog.sha256(job_payload),
    'webhook-delivery:'||candidate_notification_id::text
  );
  notification_job_id := candidate_notification_id;
  replayed := false;
  return next;
end
$$;

create function public.boardagent_claim_notification_delivery(
  candidate_notification_job_id uuid,
  candidate_lease_owner text,
  candidate_lease_seconds integer
)
returns table(
  notification_job_id uuid,
  organization_id uuid,
  board_id uuid,
  member_id uuid,
  webhook_id uuid,
  endpoint_ciphertext bytea,
  secret_ciphertext bytea,
  endpoint_sha256 bytea,
  secret_sha256 bytea,
  key_id uuid,
  webhook_generation bigint,
  source_kind text,
  wake_class text,
  random_wake_id bytea,
  canonical_payload bytea,
  payload_sha256 bytea,
  attempt integer,
  lease_expires_at timestamptz
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  notification public.notification_jobs%rowtype;
  webhook public.member_webhooks%rowtype;
  resolved_board_id uuid;
  eligible boolean;
  lease_start timestamptz;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_lease_owner!~'^[A-Za-z0-9._:-]{1,128}$'
     or candidate_lease_seconds not between 5 and 300 then
    raise exception 'notification lease input is invalid' using errcode='22023';
  end if;
  if candidate_notification_job_id is null then
    select * into notification from public.notification_jobs
     where source_kind='test' and state in ('queued','retry')
       and available_at<=clock_timestamp()
     order by available_at,id
     for update skip locked
     limit 1;
  else
    select * into notification from public.notification_jobs
     where id=candidate_notification_job_id for update;
  end if;
  if not found or notification.state not in ('queued','retry')
     or notification.available_at>clock_timestamp() then
    return;
  end if;
  select candidate.* into webhook from public.member_webhooks as candidate
   where candidate.id=notification.webhook_id
     and candidate.organization_id=notification.organization_id;
  if not found or webhook.member_id<>notification.recipient_member_id
     or webhook.state<>'active'
     or not (notification.wake_class=any(webhook.event_classes))
     or not exists (
       select 1 from public.members as member
        where member.id=notification.recipient_member_id
          and member.organization_id=notification.organization_id and member.state='active'
     ) then
    update public.notification_jobs
       set state='cancelled',lease_owner=null,lease_started_at=null,lease_expires_at=null
     where id=notification.id;
    return;
  end if;
  if notification.source_kind='notice' then
    select target.board_id is not null,target.board_id into eligible,resolved_board_id
      from public.boardagent_notice_webhook_targets(notification.notice_id) as target
     where target.webhook_id=notification.webhook_id
       and target.wake_class=notification.wake_class;
    if not coalesce(eligible,false) then
      update public.notification_jobs
         set state='cancelled',lease_owner=null,lease_started_at=null,lease_expires_at=null
       where id=notification.id;
      return;
    end if;
  else
    resolved_board_id := null;
  end if;
  if notification.attempts>=10 then
    update public.notification_jobs
       set state='dead',lease_owner=null,lease_started_at=null,lease_expires_at=null
     where id=notification.id;
    return;
  end if;
  lease_start := clock_timestamp();
  update public.notification_jobs
     set state='leased',attempts=attempts+1,lease_owner=candidate_lease_owner,
         lease_started_at=lease_start,
         lease_expires_at=lease_start+make_interval(secs=>candidate_lease_seconds)
   where id=notification.id
   returning * into notification;

  notification_job_id := notification.id;
  organization_id := notification.organization_id;
  board_id := resolved_board_id;
  member_id := notification.recipient_member_id;
  webhook_id := webhook.id;
  endpoint_ciphertext := webhook.endpoint_ciphertext;
  secret_ciphertext := webhook.secret_ciphertext;
  endpoint_sha256 := webhook.endpoint_sha256;
  secret_sha256 := webhook.secret_sha256;
  key_id := webhook.key_id;
  webhook_generation := webhook.generation;
  source_kind := notification.source_kind;
  wake_class := notification.wake_class;
  random_wake_id := notification.random_wake_id;
  canonical_payload := notification.canonical_payload;
  payload_sha256 := notification.payload_sha256;
  attempt := notification.attempts;
  lease_expires_at := notification.lease_expires_at;
  return next;
end
$$;

create function public.boardagent_complete_notification_delivery(
  candidate_attempt_id uuid,
  candidate_notification_job_id uuid,
  candidate_lease_owner text,
  candidate_attempt integer,
  candidate_request_sha256 bytea,
  candidate_result_class text,
  candidate_error_class text,
  candidate_http_status integer,
  candidate_response_sha256 bytea
)
returns table(
  organization_id uuid,
  board_id uuid,
  webhook_id uuid,
  resulting_state text,
  replayed boolean
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  notification public.notification_jobs%rowtype;
  prior public.notification_attempts%rowtype;
  next_state text;
  resolved_board_id uuid;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_attempt_id is null or not public.boardagent_is_uuid_v7(candidate_attempt_id)
     or candidate_lease_owner!~'^[A-Za-z0-9._:-]{1,128}$'
     or candidate_attempt not between 1 and 10
     or not public.boardagent_hash_is_sha256(candidate_request_sha256)
     or candidate_result_class not in ('delivered','retryable_failure','permanent_failure','cancelled')
     or (candidate_result_class='delivered' and candidate_error_class is not null)
     or (candidate_result_class<>'delivered'
         and (candidate_error_class is null
              or candidate_error_class!~'^[a-z][a-z0-9_.-]{1,127}$'))
     or (candidate_http_status is not null and candidate_http_status not between 100 and 599)
     or (candidate_response_sha256 is not null
         and not public.boardagent_hash_is_sha256(candidate_response_sha256)) then
    raise exception 'notification completion input is invalid' using errcode='22023';
  end if;
  select * into prior from public.notification_attempts
   where notification_job_id=candidate_notification_job_id and attempt=candidate_attempt;
  if found then
    if prior.request_sha256<>candidate_request_sha256
       or prior.result_class<>candidate_result_class
       or prior.error_class is distinct from candidate_error_class
       or prior.http_status is distinct from candidate_http_status
       or prior.response_sha256 is distinct from candidate_response_sha256 then
      raise exception 'notification attempt result conflicts' using errcode='23505';
    end if;
    select * into notification from public.notification_jobs
     where id=candidate_notification_job_id;
    select notice.board_id into resolved_board_id from public.notices as notice
     where notice.id=notification.notice_id;
    organization_id := notification.organization_id;
    board_id := resolved_board_id;
    webhook_id := notification.webhook_id;
    resulting_state := notification.state;
    replayed := true;
    return next;
    return;
  end if;

  select * into notification from public.notification_jobs
   where id=candidate_notification_job_id for update;
  if not found or notification.state<>'leased'
     or notification.attempts<>candidate_attempt
     or notification.lease_owner is distinct from candidate_lease_owner
     or notification.lease_expires_at<=clock_timestamp() then
    return;
  end if;
  next_state := case
    when candidate_result_class='delivered' then 'delivered'
    when candidate_result_class='cancelled' then 'cancelled'
    when candidate_result_class='permanent_failure' or candidate_attempt>=10 then 'dead'
    else 'retry'
  end;
  insert into public.notification_attempts(
    id,notification_job_id,attempt,request_sha256,result_class,error_class,http_status,
    response_sha256,started_at
  ) values (
    candidate_attempt_id,notification.id,candidate_attempt,candidate_request_sha256,
    candidate_result_class,candidate_error_class,candidate_http_status,candidate_response_sha256,
    notification.lease_started_at
  );
  update public.notification_jobs
     set state=next_state,
         available_at=case when next_state='retry' then
           clock_timestamp()+make_interval(
             secs=>least(86400,(30*power(2,least(candidate_attempt-1,11)))::integer)
           )
           else available_at end,
         lease_owner=null,lease_started_at=null,lease_expires_at=null,
         delivered_at=case when next_state='delivered' then transaction_timestamp() else null end
   where id=notification.id;
  select notice.board_id into resolved_board_id from public.notices as notice
   where notice.id=notification.notice_id;
  organization_id := notification.organization_id;
  board_id := resolved_board_id;
  webhook_id := notification.webhook_id;
  resulting_state := next_state;
  replayed := false;
  return next;
end
$$;

create function public.boardagent_cancel_disabled_webhook_notifications()
returns trigger
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  if old.state='active' and new.state in ('disabled','revoked') then
    update public.notification_jobs
       set state='cancelled',lease_owner=null,lease_started_at=null,lease_expires_at=null
     where webhook_id=new.id and state in ('queued','retry');
  end if;
  return new;
end
$$;

create trigger boardagent_disabled_webhook_notification_cancel
after update of state on public.member_webhooks
for each row execute function public.boardagent_cancel_disabled_webhook_notifications();

alter function public.boardagent_enqueue_notice_fanout(uuid) owner to boardagent_migrator;
alter function public.boardagent_notice_fanout_trigger() owner to boardagent_migrator;
alter function public.boardagent_notice_webhook_targets(uuid) owner to boardagent_migrator;
alter function public.boardagent_create_notification_delivery(uuid,uuid,uuid,text,bytea,bytea,bytea)
  owner to boardagent_migrator;
alter function public.boardagent_claim_notification_delivery(uuid,text,integer)
  owner to boardagent_migrator;
alter function public.boardagent_complete_notification_delivery(uuid,uuid,text,integer,bytea,text,text,integer,bytea)
  owner to boardagent_migrator;
alter function public.boardagent_cancel_disabled_webhook_notifications()
  owner to boardagent_migrator;

revoke all on function public.boardagent_enqueue_notice_fanout(uuid) from public;
revoke all on function public.boardagent_notice_fanout_trigger() from public;
revoke all on function public.boardagent_notice_webhook_targets(uuid) from public;
revoke all on function public.boardagent_create_notification_delivery(uuid,uuid,uuid,text,bytea,bytea,bytea)
  from public;
revoke all on function public.boardagent_claim_notification_delivery(uuid,text,integer) from public;
revoke all on function public.boardagent_complete_notification_delivery(uuid,uuid,text,integer,bytea,text,text,integer,bytea)
  from public;
revoke all on function public.boardagent_cancel_disabled_webhook_notifications() from public;
grant execute on function public.boardagent_notice_webhook_targets(uuid) to boardagent_worker;
grant execute on function public.boardagent_create_notification_delivery(uuid,uuid,uuid,text,bytea,bytea,bytea)
  to boardagent_worker;
grant execute on function public.boardagent_claim_notification_delivery(uuid,text,integer)
  to boardagent_worker;
grant execute on function public.boardagent_complete_notification_delivery(uuid,uuid,text,integer,bytea,text,text,integer,bytea)
  to boardagent_worker;
