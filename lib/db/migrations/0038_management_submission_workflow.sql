-- BoardAgent Phase 4: complete the frozen management-to-secretariat submission
-- lifecycle. All writes remain behind request-scoped security-definer functions;
-- approval creates an inert wizard draft and never performs the proposed act.

alter table management_submission_threads
  add column last_audit_event_id uuid references audit_events(id)
    deferrable initially deferred;
alter table management_submission_versions
  add column audit_event_id uuid references audit_events(id)
    deferrable initially deferred;
alter table management_revision_requests
  add column audit_event_id uuid references audit_events(id)
    deferrable initially deferred;
alter table management_revision_replies
  add column audit_event_id uuid references audit_events(id)
    deferrable initially deferred;
alter table management_submission_dispositions
  add column audit_event_id uuid references audit_events(id)
    deferrable initially deferred;

grant select,insert,update on management_submission_threads to boardagent_migrator;
grant select,insert on management_submission_versions to boardagent_migrator;
grant select,insert on management_revision_requests to boardagent_migrator;
grant select,insert on management_revision_replies to boardagent_migrator;
grant select,insert on management_submission_dispositions to boardagent_migrator;

create policy boardagent_migrator_management_submission_threads_all
  on management_submission_threads for all to boardagent_migrator
  using (true) with check (true);
create policy boardagent_migrator_management_submission_versions_insert
  on management_submission_versions for insert to boardagent_migrator with check (true);
create policy boardagent_migrator_management_revision_requests_all
  on management_revision_requests for all to boardagent_migrator
  using (true) with check (true);
create policy boardagent_migrator_management_revision_replies_all
  on management_revision_replies for all to boardagent_migrator
  using (true) with check (true);
create policy boardagent_migrator_management_submission_dispositions_all
  on management_submission_dispositions for all to boardagent_migrator
  using (true) with check (true);

create function boardagent_management_actor_for_board(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select boardagent_actor_ready_for_board(candidate_board,'documents:contribute')
     and exists (
       select 1
         from members as actor
         join board_memberships as membership
           on membership.organization_id=actor.organization_id
          and membership.member_id=actor.id
          and membership.board_id=candidate_board
        where actor.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and actor.id=boardagent_context_uuid('boardagent.member_id')
          and actor.state='active'
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null
               or membership.active_until>transaction_timestamp())
          and membership.seat_role<>'observer'
          and (
            membership.seat_role='management'
            or exists (
              select 1 from organization_role_assignments as assignment
               where assignment.organization_id=membership.organization_id
                 and assignment.member_id=membership.member_id
                 and assignment.role='management'
                 and assignment.active_from<=transaction_timestamp()
                 and (assignment.active_until is null
                      or assignment.active_until>transaction_timestamp())
            )
          )
     )
$$;
alter function boardagent_management_actor_for_board(uuid) owner to boardagent_migrator;
revoke all on function boardagent_management_actor_for_board(uuid) from public;
grant execute on function boardagent_management_actor_for_board(uuid) to boardagent_server;

create function boardagent_secretary_member_ready(candidate_board uuid,candidate_member uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select boardagent_context_board_allowed(candidate_board)
     and exists (
       select 1
         from members as member
         join board_memberships as membership
           on membership.organization_id=member.organization_id
          and membership.member_id=member.id
          and membership.board_id=candidate_board
        where member.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and member.id=candidate_member
          and member.state='active'
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null
               or membership.active_until>transaction_timestamp())
          and (
            membership.is_secretary
            or exists (
              select 1 from organization_role_assignments as assignment
               where assignment.organization_id=membership.organization_id
                 and assignment.member_id=membership.member_id
                 and assignment.role in ('secretariat','admin')
                 and assignment.active_from<=transaction_timestamp()
                 and (assignment.active_until is null
                      or assignment.active_until>transaction_timestamp())
            )
          )
     )
$$;
alter function boardagent_secretary_member_ready(uuid,uuid) owner to boardagent_migrator;
revoke all on function boardagent_secretary_member_ready(uuid,uuid) from public;
grant execute on function boardagent_secretary_member_ready(uuid,uuid) to boardagent_server;

create function boardagent_create_management_submission(
  candidate_submission uuid,
  candidate_version uuid,
  candidate_board uuid,
  candidate_secretary uuid,
  candidate_payload bytea,
  candidate_references jsonb,
  candidate_payload_sha256 bytea,
  candidate_purpose text,
  candidate_idempotency uuid,
  candidate_audit_event uuid
)
returns table(
  submission_id uuid,
  submission_state text,
  result_row_version bigint,
  result_board_id uuid,
  result_version_id uuid
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare actor uuid := boardagent_context_uuid('boardagent.member_id');
begin
  perform 1
    from board_memberships as membership
   where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and membership.board_id=candidate_board
     and membership.member_id=candidate_secretary
   for update;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_management_actor_for_board(candidate_board)
     or not boardagent_secretary_member_ready(candidate_board,candidate_secretary)
     or not boardagent_management_submission_documents_valid(candidate_board,candidate_references)
     or not boardagent_idempotency_in_progress(
       candidate_idempotency,'submit_document_to_secretariat'
     )
     or not boardagent_hash_is_sha256(candidate_payload_sha256)
     or convert_from(candidate_payload,'UTF8')::jsonb is distinct from jsonb_build_object(
       'schemaVersion','boardagent.management-submission.v1',
       'submissionId',candidate_submission,
       'versionId',candidate_version,
       'version',1,
       'documentReferences',candidate_references,
       'purpose',candidate_purpose,
       'authorMemberId',actor
     ) then
    raise exception 'management submission creation is not authorized'
      using errcode='42501';
  end if;

  insert into management_submission_threads(
    id,organization_id,board_id,management_owner_ids,assigned_secretary_id,state,
    current_version_id,row_version,created_by,last_audit_event_id
  ) values (
    candidate_submission,boardagent_context_uuid('boardagent.organization_id'),candidate_board,
    array[actor],candidate_secretary,'submitted',candidate_version,1,actor,candidate_audit_event
  );
  insert into management_submission_versions(
    id,organization_id,board_id,thread_id,version,schema_version,canonical_payload,
    document_references,payload_sha256,author_member_id,change_reason,supersedes_id,
    audit_event_id
  ) values (
    candidate_version,boardagent_context_uuid('boardagent.organization_id'),candidate_board,
    candidate_submission,1,'boardagent.management-submission.v1',candidate_payload,
    candidate_references,candidate_payload_sha256,actor,candidate_purpose,null,
    candidate_audit_event
  );
  return query select candidate_submission,'submitted'::text,1::bigint,
                      candidate_board,candidate_version;
end
$$;

create function boardagent_request_management_revision(
  candidate_request uuid,
  candidate_submission uuid,
  candidate_reason text,
  candidate_reason_sha256 bytea,
  candidate_idempotency uuid,
  candidate_audit_event uuid
)
returns table(
  submission_id uuid,
  submission_state text,
  result_row_version bigint,
  result_board_id uuid,
  result_version_id uuid,
  result_request_id uuid
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare changed management_submission_threads%rowtype;
begin
  select * into changed
    from management_submission_threads as thread
   where thread.id=candidate_submission
   for update;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or changed.id is null
     or changed.state not in ('submitted','resubmitted')
     or changed.current_version_id is null
     or changed.assigned_secretary_id
          is distinct from boardagent_context_uuid('boardagent.member_id')
     or not boardagent_secretariat_for_board(changed.board_id)
     or not boardagent_idempotency_in_progress(
       candidate_idempotency,'request_management_revision'
     )
     or not boardagent_hash_is_sha256(candidate_reason_sha256)
     or length(candidate_reason) not between 1 and 65536 then
    raise exception 'management revision request is not authorized'
      using errcode='42501';
  end if;

  insert into management_revision_requests(
    id,organization_id,board_id,thread_id,submission_version_id,
    secretary_member_id,request_text,request_sha256,audit_event_id
  ) values (
    candidate_request,changed.organization_id,changed.board_id,changed.id,
    changed.current_version_id,boardagent_context_uuid('boardagent.member_id'),
    candidate_reason,candidate_reason_sha256,candidate_audit_event
  );
  update management_submission_threads as thread
     set state='revision_requested',row_version=thread.row_version+1,
         last_audit_event_id=candidate_audit_event
   where thread.id=changed.id
     and thread.row_version=changed.row_version
  returning thread.* into changed;
  if changed.state is distinct from 'revision_requested' then
    raise exception 'management submission changed during revision request'
      using errcode='40001';
  end if;
  return query select changed.id,changed.state,changed.row_version,changed.board_id,
                      changed.current_version_id,candidate_request;
end
$$;

create function boardagent_reply_management_revision(
  candidate_reply uuid,
  candidate_submission uuid,
  candidate_request uuid,
  candidate_reply_text text,
  candidate_reply_sha256 bytea,
  candidate_idempotency uuid,
  candidate_audit_event uuid
)
returns table(
  submission_id uuid,
  submission_state text,
  result_row_version bigint,
  result_board_id uuid,
  result_version_id uuid,
  result_request_id uuid,
  result_reply_id uuid
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare changed management_submission_threads%rowtype;
begin
  select * into changed
    from management_submission_threads as thread
   where thread.id=candidate_submission
   for update;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or changed.id is null
     or changed.state<>'revision_requested'
     or changed.current_version_id is null
     or not boardagent_management_submission_actor_allowed(changed.id)
     or not exists (
       select 1 from management_revision_requests as request
        where request.id=candidate_request
          and request.thread_id=changed.id
          and request.submission_version_id=changed.current_version_id
     )
     or exists (
       select 1 from management_revision_replies as reply
        where reply.request_id=candidate_request
          and reply.submission_version_id=changed.current_version_id
     )
     or not boardagent_idempotency_in_progress(
       candidate_idempotency,'reply_to_management_revision'
     )
     or not boardagent_hash_is_sha256(candidate_reply_sha256)
     or length(candidate_reply_text) not between 1 and 1048576 then
    raise exception 'management revision reply is not authorized'
      using errcode='42501';
  end if;

  insert into management_revision_replies(
    id,organization_id,board_id,request_id,submission_version_id,
    management_author_id,canonical_reply,reply_sha256,audit_event_id
  ) values (
    candidate_reply,changed.organization_id,changed.board_id,candidate_request,
    changed.current_version_id,boardagent_context_uuid('boardagent.member_id'),
    candidate_reply_text,candidate_reply_sha256,candidate_audit_event
  );
  update management_submission_threads as thread
     set row_version=thread.row_version+1,last_audit_event_id=candidate_audit_event
   where thread.id=changed.id and thread.row_version=changed.row_version
  returning thread.* into changed;
  return query select changed.id,changed.state,changed.row_version,changed.board_id,
                      changed.current_version_id,candidate_request,candidate_reply;
end
$$;

create function boardagent_dispose_management_submission(
  candidate_disposition_id uuid,
  candidate_submission uuid,
  candidate_version uuid,
  candidate_disposition text,
  candidate_reason text,
  candidate_draft_id uuid,
  candidate_signed_context bytea,
  candidate_context_sha256 bytea,
  candidate_idempotency uuid,
  candidate_audit_event uuid
)
returns table(
  submission_id uuid,
  submission_state text,
  result_row_version bigint,
  result_board_id uuid,
  result_version_id uuid,
  result_draft_id uuid
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare changed management_submission_threads%rowtype;
declare operation text;
begin
  select * into changed
    from management_submission_threads as thread
   where thread.id=candidate_submission
   for update;
  operation:=case candidate_disposition
    when 'approved_to_draft' then 'approve_management_submission'
    when 'rejected' then 'reject_management_submission'
    else null
  end;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or changed.id is null
     or changed.state not in ('submitted','resubmitted')
     or changed.current_version_id is distinct from candidate_version
     or changed.assigned_secretary_id
          is distinct from boardagent_context_uuid('boardagent.member_id')
     or not boardagent_secretariat_for_board(changed.board_id)
     or operation is null
     or not boardagent_idempotency_in_progress(candidate_idempotency,operation) then
    raise exception 'management submission disposition is not authorized'
      using errcode='42501';
  end if;

  if candidate_disposition='approved_to_draft' then
    if candidate_reason is not null
       or candidate_draft_id is null
       or candidate_signed_context is null
       or octet_length(candidate_signed_context) not between 32 and 1048576
       or not boardagent_hash_is_sha256(candidate_context_sha256) then
      raise exception 'management approval requires one exact inert draft'
        using errcode='22023';
    end if;
    insert into wizard_drafts(
      id,organization_id,board_id,draft_type,creator_member_id,signed_context,
      context_sha256,state,expires_at
    ) values (
      candidate_draft_id,changed.organization_id,changed.board_id,'proposal',
      boardagent_context_uuid('boardagent.member_id'),candidate_signed_context,
      candidate_context_sha256,'active',transaction_timestamp()+interval '7 days'
    );
  elsif candidate_reason is null
        or length(candidate_reason) not between 1 and 65536
        or candidate_draft_id is not null
        or candidate_signed_context is not null
        or candidate_context_sha256 is not null then
    raise exception 'management rejection requires only a reason'
      using errcode='22023';
  end if;

  insert into management_submission_dispositions(
    id,organization_id,board_id,thread_id,submission_version_id,disposition,
    secretary_member_id,reason,resulting_draft_id,audit_event_id
  ) values (
    candidate_disposition_id,changed.organization_id,changed.board_id,changed.id,
    candidate_version,candidate_disposition,
    boardagent_context_uuid('boardagent.member_id'),
    coalesce(candidate_reason,'Approved to confirmable draft; underlying act not executed.'),
    candidate_draft_id,candidate_audit_event
  );
  update management_submission_threads as thread
     set state=candidate_disposition,row_version=thread.row_version+1,
         last_audit_event_id=candidate_audit_event
   where thread.id=changed.id and thread.row_version=changed.row_version
  returning thread.* into changed;
  if changed.state is distinct from candidate_disposition then
    raise exception 'management submission is no longer awaiting disposition'
      using errcode='40001';
  end if;
  return query select changed.id,changed.state,changed.row_version,changed.board_id,
                      candidate_version,candidate_draft_id;
end
$$;

do $management_workflow_functions$
declare function_name text;
begin
  foreach function_name in array array[
    'boardagent_create_management_submission(uuid,uuid,uuid,uuid,bytea,jsonb,bytea,text,uuid,uuid)',
    'boardagent_request_management_revision(uuid,uuid,text,bytea,uuid,uuid)',
    'boardagent_reply_management_revision(uuid,uuid,uuid,text,bytea,uuid,uuid)',
    'boardagent_dispose_management_submission(uuid,uuid,uuid,text,text,uuid,bytea,bytea,uuid,uuid)'
  ]
  loop
    execute 'alter function ' || function_name || ' owner to boardagent_migrator';
    execute 'revoke all on function ' || function_name || ' from public';
    execute 'grant execute on function ' || function_name || ' to boardagent_server';
  end loop;
end
$management_workflow_functions$;

-- Migration 0035 guarded every submission update as if it were a resubmission. Narrow
-- that guard to the transition it owns so the rest of the frozen lifecycle can proceed.
drop trigger boardagent_management_submission_projection on management_submission_threads;
create trigger boardagent_management_submission_projection
  before update of state,current_version_id,queue_entered_at,row_version
  on management_submission_threads
  for each row
  when (new.state='resubmitted')
  execute function boardagent_management_submission_projection_integrity();

drop function boardagent_apply_management_resubmission(uuid,bigint,uuid,uuid);
create function boardagent_apply_management_resubmission(
  candidate_thread uuid,
  expected_row_version bigint,
  expected_prior_version uuid,
  candidate_version uuid,
  candidate_audit_event uuid
)
returns bigint
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare next_row_version bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request' then
    raise exception 'management resubmission requires a managed request transaction'
      using errcode='25000';
  end if;
  if not boardagent_management_submission_actor_allowed(candidate_thread) then
    return null;
  end if;
  update management_submission_threads as thread
     set state='resubmitted',current_version_id=candidate_version,
         queue_entered_at=transaction_timestamp(),row_version=thread.row_version+1,
         last_audit_event_id=candidate_audit_event
   where thread.id=candidate_thread
     and thread.state='revision_requested'
     and thread.current_version_id=expected_prior_version
     and thread.row_version=expected_row_version
  returning thread.row_version into next_row_version;
  return next_row_version;
end
$$;
alter function boardagent_apply_management_resubmission(uuid,bigint,uuid,uuid,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_management_resubmission(uuid,bigint,uuid,uuid,uuid)
  from public;
grant execute on function boardagent_apply_management_resubmission(uuid,bigint,uuid,uuid,uuid)
  to boardagent_server;

create function boardagent_verify_management_submission_audit()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public
as $$
declare candidate_event uuid;
declare candidate_object uuid;
declare candidate_board uuid;
declare candidate_organization uuid;
declare expected_event text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request' then
    return null;
  end if;
  candidate_organization:=new.organization_id;
  candidate_board:=new.board_id;
  if tg_table_name='management_submission_threads' then
    candidate_event:=new.last_audit_event_id;
    candidate_object:=new.id;
    expected_event:=case new.state
      when 'submitted' then 'management_submission_created'
      when 'revision_requested' then 'management_revision_requested'
      when 'resubmitted' then 'management_submission_version_created'
      when 'approved_to_draft' then 'management_submission_approved_to_draft'
      when 'rejected' then 'management_submission_rejected'
      else null
    end;
    if tg_op='UPDATE' and new.state=old.state then
      expected_event:='management_revision_replied';
    end if;
  elsif tg_table_name='management_submission_versions' then
    candidate_event:=new.audit_event_id;
    candidate_object:=new.thread_id;
    expected_event:=case when new.version=1 then 'management_submission_created'
                         else 'management_submission_version_created' end;
  elsif tg_table_name='management_revision_requests' then
    candidate_event:=new.audit_event_id;
    candidate_object:=new.thread_id;
    expected_event:='management_revision_requested';
  elsif tg_table_name='management_revision_replies' then
    candidate_event:=new.audit_event_id;
    select request.thread_id into candidate_object
      from management_revision_requests as request where request.id=new.request_id;
    expected_event:='management_revision_replied';
  else
    candidate_event:=new.audit_event_id;
    candidate_object:=new.thread_id;
    expected_event:=case new.disposition
      when 'approved_to_draft' then 'management_submission_approved_to_draft'
      else 'management_submission_rejected' end;
  end if;
  if candidate_event is null or expected_event is null or not exists (
    select 1 from audit_events as event
     where event.id=candidate_event
       and event.organization_id=candidate_organization
       and event.board_id=candidate_board
       and event.event_type=expected_event
       and event.object_type='management_submission'
       and event.object_id=candidate_object
       and event.actor_member_id=boardagent_context_uuid('boardagent.member_id')
       and event.client_id=boardagent_context_uuid('boardagent.client_id')
       and event.token_jti=boardagent_context_uuid('boardagent.token_jti')
  ) then
    raise exception 'management submission mutation lacks its exact audit event'
      using errcode='23503';
  end if;
  return null;
end
$$;
alter function boardagent_verify_management_submission_audit() owner to boardagent_migrator;
revoke all on function boardagent_verify_management_submission_audit() from public;

create constraint trigger boardagent_management_submission_threads_audit
  after insert or update on management_submission_threads
  deferrable initially deferred
  for each row execute function boardagent_verify_management_submission_audit();
create constraint trigger boardagent_management_submission_versions_audit
  after insert on management_submission_versions
  deferrable initially deferred
  for each row execute function boardagent_verify_management_submission_audit();
create constraint trigger boardagent_management_revision_requests_audit
  after insert on management_revision_requests
  deferrable initially deferred
  for each row execute function boardagent_verify_management_submission_audit();
create constraint trigger boardagent_management_revision_replies_audit
  after insert on management_revision_replies
  deferrable initially deferred
  for each row execute function boardagent_verify_management_submission_audit();
create constraint trigger boardagent_management_submission_dispositions_audit
  after insert on management_submission_dispositions
  deferrable initially deferred
  for each row execute function boardagent_verify_management_submission_audit();
