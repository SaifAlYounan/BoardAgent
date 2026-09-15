-- Explicit contentless webhook tests get the same durable typed dispatch as notices.
-- Boardless dispatch is limited to the live owner's exact queued security test.
-- Existing board-bound notice jobs and all other typed-job bindings are unchanged.
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
