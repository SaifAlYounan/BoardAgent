-- Refuse missing exact minutes versions before projection writes, require typed
-- checkpoint watermarks, and preserve the explicit expired-job batch bound.
-- Existing role grants, canonical evidence, histories and all other behavior remain.

CREATE OR REPLACE FUNCTION public.boardagent_apply_minutes_terminal_transition(candidate_minutes_id uuid, expected_row_version bigint, candidate_state text, candidate_consent_record_id uuid)
 RETURNS TABLE(next_row_version bigint, superseded_task_ids uuid[])
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  locked_minutes minutes%rowtype;
  current_version minutes_versions%rowtype;
  current_package minutes_signature_packages%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_state is null
     or candidate_state not in ('finalized','cancelled') then
    raise exception 'terminal minutes transition requires a managed request transaction'
      using errcode = '25000';
  end if;
  select minutes.* into locked_minutes
    from minutes
   where minutes.id=candidate_minutes_id
     and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(minutes.board_id)
 and not public.boardagent_member_record_recused('minutes',minutes.id,public.boardagent_context_uuid('boardagent.member_id'))
   for update of minutes;
  if not found or locked_minutes.row_version is distinct from expected_row_version then
    return;
  end if;
  select version.* into current_version
    from minutes_versions as version
   where version.id=locked_minutes.current_version_id
     and version.minutes_id=locked_minutes.id;
  if not found then
    return;
  end if;
  if locked_minutes.current_signature_package_id is not null then
    select package.* into current_package
      from minutes_signature_packages as package
     where package.id=locked_minutes.current_signature_package_id
       and package.minutes_id=locked_minutes.id
     for update of package;
    if not found then
      return;
    end if;
  end if;
  if not exists (
    select 1 from board_memberships as membership
     where membership.organization_id=locked_minutes.organization_id
       and membership.board_id=locked_minutes.board_id
       and membership.member_id=boardagent_context_uuid('boardagent.member_id')
       and membership.is_secretary
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
  ) then
    return;
  end if;
  if not exists (
    select 1
      from consent_records as consent
      join action_stages as stage on stage.id=consent.stage_id
      join input_required_attempts as attempt
        on attempt.id=consent.input_required_attempt_id
     where consent.id=candidate_consent_record_id
       and consent.organization_id=locked_minutes.organization_id
       and consent.board_id=locked_minutes.board_id
       and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
       and consent.client_id=boardagent_context_uuid('boardagent.client_id')
       and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
       and consent.action_code=case candidate_state
         when 'finalized' then 'finalize_minutes' else 'cancel_minutes' end
       and consent.target_type='minutes'
       and consent.target_id=locked_minutes.id
       and consent.package_sha256=case candidate_state
         when 'finalized' then current_package.package_sha256
         else current_version.canonical_sha256 end
       and stage.state='active'
       and stage.payload_sha256=consent.payload_sha256
       and stage.package_sha256=consent.package_sha256
       and attempt.stage_id=stage.id
       and attempt.state='prepared'
       and attempt.original_name=consent.action_code
  ) then
    return;
  end if;

  if candidate_state='finalized' then
    if locked_minutes.state<>'signature_ready'
       or locked_minutes.current_signature_package_id is null
       or current_package.state<>'current'
       or not exists (
         select 1 from minutes_action_declarations as declaration
          where declaration.minutes_id=locked_minutes.id
            and declaration.minutes_version_id=locked_minutes.current_version_id
       )
       or exists (
         select 1
           from minutes_signature_requirements as requirement
           left join minutes_signatures as signature
             on signature.package_id=requirement.package_id
            and signature.signer_member_id=requirement.member_id
          where requirement.package_id=locked_minutes.current_signature_package_id
            and requirement.requirement='required'
            and signature.id is null
       )
       or exists (
         select 1 from tasks as task
          where task.source_minutes_id=locked_minutes.id
            and task.source_minutes_version_id=locked_minutes.current_version_id
            and task.state='draft'
       ) then
      return;
    end if;
    update minutes_signature_packages
       set state='terminal'
     where id=locked_minutes.current_signature_package_id and state='current';
    update minutes_resign_requirements
       set state='resolved',resolution='package_terminal',resolved_at=transaction_timestamp()
     where minutes_id=locked_minutes.id and state='pending';
    superseded_task_ids:=array[]::uuid[];
    update minutes
       set state='finalized',finalized_at=transaction_timestamp(),row_version=row_version+1
     where id=locked_minutes.id and row_version=expected_row_version
    returning row_version into next_row_version;
  else
    if locked_minutes.state not in ('unpublished_draft','published_review','signature_ready') then
      return;
    end if;
    if locked_minutes.current_signature_package_id is not null then
      update minutes_signature_packages
         set state='terminal'
       where id=locked_minutes.current_signature_package_id and state='current';
    end if;
    update minutes_resign_requirements
       set state='resolved',resolution='package_terminal',resolved_at=transaction_timestamp()
     where minutes_id=locked_minutes.id and state='pending';
    with superseded as (
      update tasks
         set state='superseded',row_version=row_version+1
       where source_minutes_id=locked_minutes.id and state='draft'
      returning id
    )
    select coalesce(array_agg(id order by id),array[]::uuid[])
      into superseded_task_ids
      from superseded;
    update minutes
       set state='cancelled',cancelled_at=transaction_timestamp(),row_version=row_version+1
     where id=locked_minutes.id and row_version=expected_row_version
    returning row_version into next_row_version;
  end if;
  return next;
end
$function$
;

create or replace function public.boardagent_guard_typed_job_insert()
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
       or parameters-array['notificationJobId']::text[]<>'{}'::jsonb
       or parameters->>'notificationJobId' is distinct from new.subject_id::text
       or not exists (
         select 1 from public.notification_jobs as notification
           left join public.notices as notice on notice.id=notification.notice_id
          where notification.id=new.subject_id
            and notification.organization_id=new.organization_id
            and (
              (notification.source_kind='notice' and new.board_id is not null
               and notice.organization_id=new.organization_id and notice.board_id=new.board_id)
              or (new.job_type='webhook_delivery' and new.board_id is null
                and notification.source_kind='test' and notification.notice_id is null
                and notification.wake_class='security' and notification.state='queued'
                and new.id=notification.id
                and new.idempotency_key='webhook-delivery:'||notification.id::text
                and current_setting('boardagent.transaction_scope',true)='request'
                and exists (
                  select 1 from public.boardagent_resolve_access_token(
                    public.boardagent_context_uuid('boardagent.token_jti')
                  ) as actor
                  join public.member_webhooks as webhook on webhook.id=notification.webhook_id
                   where actor.organization_id=new.organization_id
                     and actor.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
                     and actor.member_id=notification.recipient_member_id
                     and actor.member_id=public.boardagent_context_uuid('boardagent.member_id')
                     and actor.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
                     and 'notifications:manage'=any(actor.scope_set)
                     and webhook.organization_id=actor.organization_id
                     and webhook.member_id=actor.member_id and webhook.state='active'
                     and 'security'=any(webhook.event_classes)
                )
              )
            )
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
       or jsonb_typeof(parameters->'throughSequence') is distinct from 'string'
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

create or replace function public.boardagent_reap_expired_typed_jobs(candidate_limit integer default 100)
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
  if candidate_limit is null or candidate_limit not between 1 and 10000 then
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
