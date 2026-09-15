-- BoardAgent confirmed meeting, agenda, RSVP and attendance lifecycle authority.

alter table meeting_rsvps
  add column note text check (note is null or length(note) between 1 and 4096);

grant insert on
  agenda_items,
  agenda_versions,
  meeting_attendance,
  meeting_rsvps,
  meeting_versions,
  meetings
to boardagent_server;
grant update(is_current) on meeting_rsvps to boardagent_server;

-- Terminal/amendment projections are writable only through the guarded SECURITY
-- DEFINER transition below. FORCE RLS still applies to the non-login migrator owner,
-- so give that function only request-scoped visibility and the exact meeting columns.
grant select on
  action_stages,
  agenda_versions,
  consent_records,
  meeting_attendance,
  meeting_versions,
  meetings,
  notices
to boardagent_migrator;
grant update(
  title,
  state,
  scheduled_start,
  scheduled_end,
  current_version_id,
  current_agenda_version_id,
  row_version,
  completed_at,
  cancelled_at
) on meetings to boardagent_migrator;

do $migrator_meeting_transition_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'action_stages','agenda_versions','consent_records','meeting_attendance',
    'meeting_versions','meetings','notices'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_meeting_transition_read on %I for select to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=boardagent_context_uuid(''boardagent.organization_id'') and (board_id is null or boardagent_context_board_allowed(board_id)))',
      source_table
    );
  end loop;
end
$migrator_meeting_transition_read$;

create policy boardagent_migrator_meeting_transition_update
  on meetings for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  );

create function boardagent_meeting_actor_ready(candidate_board uuid,required_scope text)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select required_scope in ('governance:read','meeting:act','minutes:act','secretariat:admin')
     and boardagent_context_board_allowed(candidate_board)
     and exists (
       select 1
         from members as actor
         join board_memberships as membership
           on membership.organization_id=actor.organization_id
          and membership.member_id=actor.id
          and membership.board_id=candidate_board
         join access_token_records as token
           on token.organization_id=actor.organization_id
          and token.member_id=actor.id
          and token.client_id=boardagent_context_uuid('boardagent.client_id')
          and token.jti=boardagent_context_uuid('boardagent.token_jti')
         join oauth_clients as client on client.id=token.client_id
         join system_instance as instance
           on instance.organization_id=actor.organization_id
          and instance.canonical_resource_uri=token.resource_uri
        where actor.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and actor.id=boardagent_context_uuid('boardagent.member_id')
          and actor.state='active'
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null
               or membership.active_until>transaction_timestamp())
          and client.organization_id=actor.organization_id
          and client.state='active'
          and token.revoked_at is null
          and token.expires_at>transaction_timestamp()
          and required_scope=any(token.scope_set)
          and exists (
            select 1 from onboarding_attestations as attestation
             where attestation.organization_id=actor.organization_id
               and attestation.member_id=actor.id
               and attestation.board_id=candidate_board
               and attestation.terms_version_id=(
                 select terms.id from onboarding_terms_versions as terms
                  where terms.organization_id=actor.organization_id
                    and terms.seat_role=membership.seat_role
                    and terms.effective_at<=transaction_timestamp()
                  order by terms.effective_at desc,terms.version desc,terms.id desc limit 1
               )
               and attestation.support_version_id=(
                 select support.id from secretary_support_versions as support
                  where support.organization_id=actor.organization_id
                    and (support.board_id=candidate_board or support.board_id is null)
                    and support.effective_at<=transaction_timestamp()
                  order by (support.board_id=candidate_board) desc,support.effective_at desc,
                           support.version desc,support.id desc limit 1
               )
          )
     )
$$;
alter function boardagent_meeting_actor_ready(uuid,text) owner to boardagent_migrator;
revoke all on function boardagent_meeting_actor_ready(uuid,text) from public;
grant execute on function boardagent_meeting_actor_ready(uuid,text) to boardagent_server;

create function boardagent_meeting_secretary_for_board(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select boardagent_meeting_actor_ready(candidate_board,'secretariat:admin')
     and exists (
       select 1 from board_memberships as membership
        where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and membership.board_id=candidate_board
          and membership.member_id=boardagent_context_uuid('boardagent.member_id')
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
                 and assignment.role='secretariat'
                 and assignment.active_from<=transaction_timestamp()
                 and (assignment.active_until is null
                      or assignment.active_until>transaction_timestamp())
            )
          )
     )
$$;
alter function boardagent_meeting_secretary_for_board(uuid) owner to boardagent_migrator;
revoke all on function boardagent_meeting_secretary_for_board(uuid) from public;
grant execute on function boardagent_meeting_secretary_for_board(uuid) to boardagent_server;

create function boardagent_lock_meeting_recipients(
  candidate_board uuid,
  candidate_member_ids uuid[]
)
returns table(member_id uuid,entitlement_generation bigint)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_member_ids is null
     or cardinality(candidate_member_ids) not between 1 and 1000
     or exists (select 1 from unnest(candidate_member_ids) as requested(id) where id is null)
     or (select count(distinct id) from unnest(candidate_member_ids) as requested(id))
          <> cardinality(candidate_member_ids)
     or not boardagent_meeting_secretary_for_board(candidate_board) then
    raise exception 'meeting recipient lock requires exact secretary authority and recipients'
      using errcode='42501';
  end if;
  return query
    select membership.member_id,membership.entitlement_generation
      from boards as board
      join board_memberships as membership
        on membership.organization_id=board.organization_id
       and membership.board_id=board.id
      join members as member
        on member.organization_id=membership.organization_id
       and member.id=membership.member_id
     where board.id=candidate_board
       and board.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and board.state='active'
       and membership.member_id=any(candidate_member_ids)
       and member.state='active'
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null
            or membership.active_until>transaction_timestamp())
     order by membership.member_id
     for update of membership,member;
end
$$;
alter function boardagent_lock_meeting_recipients(uuid,uuid[]) owner to boardagent_migrator;
revoke all on function boardagent_lock_meeting_recipients(uuid,uuid[]) from public;
grant execute on function boardagent_lock_meeting_recipients(uuid,uuid[]) to boardagent_server;

drop policy boardagent_server_scope on meetings;
create policy boardagent_server_meetings_select on meetings for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (
      boardagent_meeting_actor_ready(board_id,'governance:read')
      or boardagent_meeting_actor_ready(board_id,'meeting:act')
      or boardagent_meeting_actor_ready(board_id,'minutes:act')
      or boardagent_meeting_secretary_for_board(board_id)
    )
  );
create policy boardagent_server_meetings_insert on meetings for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by=boardagent_context_uuid('boardagent.member_id')
    and state='called'
    and row_version=1
    and boardagent_meeting_secretary_for_board(board_id)
  );
create policy boardagent_server_meetings_update on meetings for update to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_meeting_secretary_for_board(board_id)
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_meeting_secretary_for_board(board_id)
  );

drop policy boardagent_server_scope on meeting_versions;
create policy boardagent_server_meeting_versions_select
  on meeting_versions for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (
      boardagent_meeting_actor_ready(board_id,'governance:read')
      or boardagent_meeting_actor_ready(board_id,'meeting:act')
      or boardagent_meeting_secretary_for_board(board_id)
    )
  );
create policy boardagent_server_meeting_versions_insert
  on meeting_versions for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by=boardagent_context_uuid('boardagent.member_id')
    and boardagent_meeting_secretary_for_board(board_id)
    and exists (
      select 1 from consent_records as consent
       where consent.id=consent_record_id
         and consent.organization_id=organization_id
         and consent.board_id=board_id
         and consent.actor_member_id=created_by
         and consent.action_code in ('create_meeting','amend_meeting')
         and consent.target_type='meeting'
         and consent.target_id=meeting_id
    )
  );

drop policy boardagent_server_scope on agenda_versions;
create policy boardagent_server_agenda_versions_select
  on agenda_versions for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (
      boardagent_meeting_actor_ready(board_id,'governance:read')
      or boardagent_meeting_actor_ready(board_id,'meeting:act')
      or boardagent_meeting_secretary_for_board(board_id)
    )
  );
create policy boardagent_server_agenda_versions_insert
  on agenda_versions for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by=boardagent_context_uuid('boardagent.member_id')
    and boardagent_meeting_secretary_for_board(board_id)
    and exists (
      select 1 from meeting_versions as meeting_version
       where meeting_version.id=meeting_version_id
         and meeting_version.meeting_id=meeting_id
         and meeting_version.board_id=board_id
         and meeting_version.organization_id=organization_id
    )
  );

create policy boardagent_server_agenda_items_select
  on agenda_items for select to boardagent_server
  using (
    exists (
      select 1 from agenda_versions as agenda
       where agenda.id=agenda_version_id
         and (
           boardagent_meeting_actor_ready(agenda.board_id,'governance:read')
           or boardagent_meeting_actor_ready(agenda.board_id,'meeting:act')
           or boardagent_meeting_secretary_for_board(agenda.board_id)
         )
    )
  );
create policy boardagent_server_agenda_items_insert
  on agenda_items for insert to boardagent_server
  with check (
    exists (
      select 1 from agenda_versions as agenda
       where agenda.id=agenda_version_id
         and boardagent_meeting_secretary_for_board(agenda.board_id)
         and (
           source_document_version_id is null
           or exists (
             select 1 from document_versions as document_version
             join documents as document on document.id=document_version.document_id
              where document_version.id=source_document_version_id
                and document.board_id=agenda.board_id
                and document.state<>'soft_deleted'
                and document_version.sha256=source_document_sha256
                and boardagent_document_permission(document.id,'read')
           )
         )
    )
  );

drop policy boardagent_server_scope on meeting_rsvps;
create policy boardagent_server_meeting_rsvps_select
  on meeting_rsvps for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (
      (member_id=boardagent_context_uuid('boardagent.member_id')
       and boardagent_meeting_actor_ready(board_id,'meeting:act'))
      or boardagent_meeting_secretary_for_board(board_id)
    )
  );
create policy boardagent_server_meeting_rsvps_insert
  on meeting_rsvps for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and member_id=boardagent_context_uuid('boardagent.member_id')
    and boardagent_meeting_actor_ready(board_id,'meeting:act')
    and exists (
      select 1 from board_memberships as membership
       where membership.organization_id=organization_id
         and membership.board_id=board_id
         and membership.member_id=member_id
         and membership.seat_role<>'observer'
    )
    and exists (select 1 from meetings as meeting where meeting.id=meeting_id and meeting.state='called')
  );
create policy boardagent_server_meeting_rsvps_update
  on meeting_rsvps for update to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and member_id=boardagent_context_uuid('boardagent.member_id')
    and boardagent_meeting_actor_ready(board_id,'meeting:act')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and member_id=boardagent_context_uuid('boardagent.member_id')
    and boardagent_meeting_actor_ready(board_id,'meeting:act')
  );

drop policy boardagent_server_scope on meeting_attendance;
create policy boardagent_server_meeting_attendance_select
  on meeting_attendance for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (
      boardagent_meeting_actor_ready(board_id,'governance:read')
      or boardagent_meeting_secretary_for_board(board_id)
    )
  );
create policy boardagent_server_meeting_attendance_insert
  on meeting_attendance for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and recorder_member_id=boardagent_context_uuid('boardagent.member_id')
    and boardagent_meeting_secretary_for_board(board_id)
    and exists (
      select 1 from meetings as meeting
       where meeting.id=meeting_attendance.meeting_id
         and meeting.board_id=meeting_attendance.board_id
         and meeting.state in ('called','completed')
    )
    and exists (
      select 1 from notices as notice
       where notice.object_type='meeting'
         and notice.object_id=meeting_attendance.meeting_id
         and notice.notice_type='meeting_called'
         and notice.recipient_member_id=meeting_attendance.member_id
    )
    and (
      (source='secretary_record' and corrects_id is null
       and correction_reason is null and consent_record_id is null)
      or
      (source='correction' and corrects_id is not null
       and correction_reason is not null and consent_record_id is not null
       and exists (
         select 1 from meeting_attendance as prior
          where prior.id=meeting_attendance.corrects_id
            and prior.meeting_id=meeting_attendance.meeting_id
            and prior.member_id=meeting_attendance.member_id
            and not exists (
              select 1 from meeting_attendance as later
               where later.corrects_id=prior.id
                 and later.id<>meeting_attendance.id
            )
       )
       and exists (
         select 1 from consent_records as consent
          where consent.id=meeting_attendance.consent_record_id
            and consent.organization_id=meeting_attendance.organization_id
            and consent.board_id=meeting_attendance.board_id
            and consent.actor_member_id=meeting_attendance.recorder_member_id
            and consent.action_code='correct_attendance'
            and consent.target_type='meeting_attendance'
            and consent.target_id=meeting_attendance.corrects_id
       ))
    )
  );

create function boardagent_apply_meeting_change(
  candidate_meeting_id uuid,
  expected_row_version bigint,
  candidate_action text,
  candidate_consent_record_id uuid,
  expected_payload_sha256 bytea,
  expected_package_sha256 bytea,
  candidate_meeting_version_id uuid,
  candidate_agenda_version_id uuid
)
returns bigint
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  changed_version bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_action not in ('amend_meeting','cancel_meeting','complete_meeting')
     or not boardagent_hash_is_sha256(expected_payload_sha256)
     or not boardagent_hash_is_sha256(expected_package_sha256)
     or not exists (
       select 1 from consent_records as consent
       join action_stages as stage on stage.id=consent.stage_id
       join meetings as meeting on meeting.id=candidate_meeting_id
        where consent.id=candidate_consent_record_id
          and consent.organization_id=meeting.organization_id
          and consent.board_id=meeting.board_id
          and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
          and consent.client_id=boardagent_context_uuid('boardagent.client_id')
          and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
          and consent.action_code=candidate_action
          and consent.target_type='meeting'
          and consent.target_id=meeting.id
          and consent.payload_sha256=expected_payload_sha256
          and stage.package_sha256=expected_package_sha256
          and meeting.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and boardagent_context_board_allowed(meeting.board_id)
          and boardagent_meeting_secretary_for_board(meeting.board_id)
          and (
            candidate_action<>'amend_meeting'
            or exists (
              select 1 from meeting_versions as meeting_version
              join agenda_versions as agenda
                on agenda.id=candidate_agenda_version_id
               and agenda.meeting_id=meeting_version.meeting_id
               and agenda.meeting_version_id=meeting_version.id
               where meeting_version.id=candidate_meeting_version_id
                 and meeting_version.meeting_id=meeting.id
                 and meeting_version.version=(
                   select current_version.version+1
                     from meeting_versions as current_version
                    where current_version.id=meeting.current_version_id
                 )
                 and meeting_version.consent_record_id=consent.id
                 and meeting_version.notice_package_sha256=expected_package_sha256
            )
          )
     ) then
    raise exception 'meeting transition lacks exact confirmed authority' using errcode='42501';
  end if;

  if candidate_action='amend_meeting' then
    update meetings as meeting
       set title=meeting_version.canonical_title,
           scheduled_start=meeting_version.scheduled_start,
           scheduled_end=meeting_version.scheduled_end,
           current_version_id=meeting_version.id,
           current_agenda_version_id=candidate_agenda_version_id,
           row_version=meeting.row_version+1
      from meeting_versions as meeting_version
     where meeting.id=candidate_meeting_id
       and meeting.row_version=expected_row_version
       and meeting.state='called'
       and meeting_version.id=candidate_meeting_version_id
     returning meeting.row_version into changed_version;
  elsif candidate_action='cancel_meeting' then
    update meetings
       set state='cancelled',cancelled_at=transaction_timestamp(),row_version=row_version+1
     where id=candidate_meeting_id
       and row_version=expected_row_version
       and state in ('draft','called')
     returning row_version into changed_version;
  else
    if exists (
      select 1 from notices as attendee
       where attendee.object_type='meeting'
         and attendee.object_id=candidate_meeting_id
         and attendee.notice_type='meeting_called'
         and not exists (
           select 1 from meeting_attendance as attendance
            where attendance.meeting_id=candidate_meeting_id
              and attendance.member_id=attendee.recipient_member_id
              and not exists (
                select 1 from meeting_attendance as later
                 where later.corrects_id=attendance.id
              )
         )
    ) then
      raise exception 'meeting attendance is incomplete' using errcode='23514';
    end if;
    update meetings
       set state='completed',completed_at=transaction_timestamp(),row_version=row_version+1
     where id=candidate_meeting_id
       and row_version=expected_row_version
       and state='called'
     returning row_version into changed_version;
  end if;
  if changed_version is null then
    raise exception 'meeting changed before confirmed transition' using errcode='40001';
  end if;
  return changed_version;
end
$$;
alter function boardagent_apply_meeting_change(uuid,bigint,text,uuid,bytea,bytea,uuid,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_meeting_change(uuid,bigint,text,uuid,bytea,bytea,uuid,uuid)
  from public;
grant execute on function boardagent_apply_meeting_change(uuid,bigint,text,uuid,bytea,bytea,uuid,uuid)
  to boardagent_server;
