-- BoardAgent transcript-annex lifecycle authority. BoardAgent accepts canonical text
-- only: it stores no recording and performs no transcription.

alter table meeting_transcript_versions
  add column coverage_statement text not null
  check (length(coverage_statement) between 1 and 1024);

alter table transcript_challenges
  add constraint transcript_challenges_exact_turn_fk
  foreign key (transcript_version_id,turn_id)
  references transcript_turns(transcript_version_id,id)
  on delete restrict;

alter table transcript_question_links
  add constraint transcript_question_links_first_turn_fk
  foreign key (transcript_version_id,first_turn_id)
  references transcript_turns(transcript_version_id,id)
  on delete restrict;
alter table transcript_question_links
  add constraint transcript_question_links_last_turn_fk
  foreign key (transcript_version_id,last_turn_id)
  references transcript_turns(transcript_version_id,id)
  on delete restrict;

create unique index transcript_challenges_one_member_turn_uq
  on transcript_challenges(transcript_version_id,turn_id,challenger_member_id);

grant insert on
  meeting_transcripts,
  meeting_transcript_versions,
  transcript_turns,
  transcript_verifications,
  transcript_challenges,
  transcript_challenge_dispositions,
  transcript_question_links
to boardagent_server;
grant update(state,current_version_id,row_version) on meeting_transcripts to boardagent_server;
grant update(state) on transcript_challenges to boardagent_server;

-- The original blanket transition permits verification but cannot express the reverse
-- projection caused by a new immutable successor. Replace it with an exact aggregate
-- guard while retaining the generic row-version trigger.
drop trigger boardagent_state_transition on meeting_transcripts;

create function boardagent_guard_transcript_projection()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog,public
as $$
begin
  if new.id is distinct from old.id
     or new.organization_id is distinct from old.organization_id
     or new.board_id is distinct from old.board_id
     or new.meeting_id is distinct from old.meeting_id
     or new.created_at is distinct from old.created_at
     or not boardagent_meeting_secretary_for_board(old.board_id) then
    raise exception 'transcript aggregate permits only an exact secretary projection change'
      using errcode='55000';
  end if;

  if new.current_version_id is distinct from old.current_version_id then
    if new.state<>'unverified'
       or not exists (
         select 1
           from meeting_transcript_versions as successor
           join meeting_transcript_versions as predecessor
             on predecessor.id=old.current_version_id
          where successor.id=new.current_version_id
            and successor.transcript_id=old.id
            and successor.supersedes_id=old.current_version_id
            and successor.version=predecessor.version+1
            and successor.verification_state='agent_prepared_unverified'
       ) then
      raise exception 'transcript successor projection is invalid' using errcode='55000';
    end if;
  elsif old.state='unverified' and new.state='secretary_verified' then
    if not exists (
      select 1
        from transcript_verifications as verification
       where verification.transcript_version_id=old.current_version_id
         and verification.secretary_member_id=boardagent_context_uuid('boardagent.member_id')
         and verification.status='secretary_verified'
    ) then
      raise exception 'transcript verification projection lacks exact evidence'
        using errcode='55000';
    end if;
  elsif new.state is distinct from old.state then
    raise exception 'invalid transcript state transition: % -> %',old.state,new.state
      using errcode='23514';
  end if;
  return new;
end
$$;
alter function boardagent_guard_transcript_projection() owner to boardagent_migrator;
revoke all on function boardagent_guard_transcript_projection() from public;
grant execute on function boardagent_guard_transcript_projection() to boardagent_server;
create trigger boardagent_transcript_projection
before update on meeting_transcripts
for each row execute function boardagent_guard_transcript_projection();

-- Replace the bootstrap-wide organization policies with object- and role-exact paths.
drop policy boardagent_server_scope on meeting_transcripts;
create policy boardagent_server_transcripts_select on meeting_transcripts
  for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (
      boardagent_meeting_actor_ready(board_id,'governance:read')
      or boardagent_meeting_secretary_for_board(board_id)
    )
  );
create policy boardagent_server_transcripts_insert on meeting_transcripts
  for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and state='unverified'
    and row_version=1
    and boardagent_meeting_secretary_for_board(board_id)
    and exists (
      select 1 from meetings as meeting
       where meeting.id=meeting_transcripts.meeting_id
         and meeting.board_id=meeting_transcripts.board_id
         and meeting.state in ('called','completed')
    )
  );
create policy boardagent_server_transcripts_update on meeting_transcripts
  for update to boardagent_server
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

drop policy boardagent_server_scope on meeting_transcript_versions;
create policy boardagent_server_transcript_versions_select on meeting_transcript_versions
  for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (
      boardagent_meeting_actor_ready(board_id,'governance:read')
      or boardagent_meeting_secretary_for_board(board_id)
    )
  );
create policy boardagent_server_transcript_versions_insert on meeting_transcript_versions
  for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by=boardagent_context_uuid('boardagent.member_id')
    and source_type='agent_prepared'
    and verification_state='agent_prepared_unverified'
    and boardagent_meeting_secretary_for_board(board_id)
    and exists (
      select 1 from meeting_transcripts as transcript
       where transcript.id=meeting_transcript_versions.transcript_id
         and transcript.board_id=meeting_transcript_versions.board_id
    )
  );

create policy boardagent_server_transcript_turns_select on transcript_turns
  for select to boardagent_server
  using (
    exists (
      select 1 from meeting_transcript_versions as version
       where version.id=transcript_turns.transcript_version_id
    )
  );
create policy boardagent_server_transcript_turns_insert on transcript_turns
  for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and exists (
      select 1
        from meeting_transcript_versions as version
       where version.id=transcript_turns.transcript_version_id
         and version.created_by=boardagent_context_uuid('boardagent.member_id')
         and boardagent_meeting_secretary_for_board(version.board_id)
         and (
           transcript_turns.speaker_member_id is null
           or exists (
             select 1
               from members as speaker
               join board_memberships as membership
                 on membership.organization_id=speaker.organization_id
                and membership.member_id=speaker.id
                and membership.board_id=version.board_id
              where speaker.organization_id=version.organization_id
                and speaker.id=transcript_turns.speaker_member_id
                and speaker.state='active'
                and membership.state='active'
                and membership.active_from<=transaction_timestamp()
                and (membership.active_until is null
                     or membership.active_until>transaction_timestamp())
           )
         )
    )
  );

drop policy boardagent_server_scope on transcript_verifications;
create policy boardagent_server_transcript_verifications_select on transcript_verifications
  for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and exists (
      select 1 from meeting_transcript_versions as version
       where version.id=transcript_verifications.transcript_version_id
    )
  );
create policy boardagent_server_transcript_verifications_insert on transcript_verifications
  for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and secretary_member_id=boardagent_context_uuid('boardagent.member_id')
    and status='secretary_verified'
    and exists (
      select 1
        from meeting_transcript_versions as version
        join meeting_transcripts as transcript on transcript.id=version.transcript_id
        join consent_records as consent on consent.id=transcript_verifications.consent_record_id
       where version.id=transcript_verifications.transcript_version_id
         and version.canonical_sha256=transcript_verifications.transcript_sha256
         and transcript.current_version_id=version.id
         and transcript.state='unverified'
         and boardagent_meeting_secretary_for_board(transcript.board_id)
         and consent.organization_id=transcript.organization_id
         and consent.board_id=transcript.board_id
         and consent.actor_member_id=transcript_verifications.secretary_member_id
         and consent.action_code='verify_meeting_transcript'
         and consent.target_type='meeting_transcript'
         and consent.target_id=transcript.id
         and consent.package_sha256=version.canonical_sha256
    )
  );

drop policy boardagent_server_scope on transcript_challenges;
create policy boardagent_server_transcript_challenges_select on transcript_challenges
  for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1 from meeting_transcript_versions as version
       where version.id=transcript_challenges.transcript_version_id
    )
  );
create policy boardagent_server_transcript_challenges_insert on transcript_challenges
  for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and challenger_member_id=boardagent_context_uuid('boardagent.member_id')
    and state='pending'
    and boardagent_communication_actor_ready(board_id,'secretariat:message')
    and exists (
      select 1
        from meeting_transcript_versions as version
        join meeting_transcripts as transcript on transcript.id=version.transcript_id
        join notices as attendee
          on attendee.object_type='meeting'
         and attendee.object_id=transcript.meeting_id
         and attendee.notice_type='meeting_called'
         and attendee.recipient_member_id=transcript_challenges.challenger_member_id
        join board_memberships as membership
          on membership.organization_id=transcript_challenges.organization_id
         and membership.board_id=transcript_challenges.board_id
         and membership.member_id=transcript_challenges.challenger_member_id
       where version.id=transcript_challenges.transcript_version_id
         and version.board_id=transcript_challenges.board_id
         and membership.state='active'
         and membership.seat_role<>'observer'
         and membership.active_from<=transaction_timestamp()
         and (membership.active_until is null
              or membership.active_until>transaction_timestamp())
    )
  );
create policy boardagent_server_transcript_challenges_update on transcript_challenges
  for update to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and state='pending'
    and boardagent_meeting_secretary_for_board(board_id)
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and state in ('accepted','rejected')
    and boardagent_meeting_secretary_for_board(board_id)
    and exists (
      select 1 from transcript_challenge_dispositions as disposition
       where disposition.challenge_id=transcript_challenges.id
         and disposition.decision=transcript_challenges.state
    )
  );

-- A disposition policy cannot join transcript_challenges directly while the challenge
-- UPDATE policy is checking for that disposition: PostgreSQL correctly detects that as
-- recursive RLS. Resolve only the board/organization visibility predicate through this
-- narrow owner-held lookup; it exposes no row data and preserves the request context.
grant select on transcript_challenges to boardagent_migrator;
create policy boardagent_migrator_transcript_challenge_read on transcript_challenges
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  );
create function boardagent_transcript_challenge_visible(candidate_challenge uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select exists (
    select 1
      from transcript_challenges as challenge
     where challenge.id=candidate_challenge
       and challenge.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(challenge.board_id)
  )
$$;
alter function boardagent_transcript_challenge_visible(uuid) owner to boardagent_migrator;
revoke all on function boardagent_transcript_challenge_visible(uuid) from public;
grant execute on function boardagent_transcript_challenge_visible(uuid) to boardagent_server;

drop policy boardagent_server_scope on transcript_challenge_dispositions;
create policy boardagent_server_transcript_dispositions_select
  on transcript_challenge_dispositions for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_transcript_challenge_visible(challenge_id)
  );
create policy boardagent_server_transcript_dispositions_insert
  on transcript_challenge_dispositions for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and secretary_member_id=boardagent_context_uuid('boardagent.member_id')
    and exists (
      select 1
        from transcript_challenges as challenge
        join meeting_transcript_versions as challenged_version
          on challenged_version.id=challenge.transcript_version_id
        join meeting_transcripts as transcript on transcript.id=challenged_version.transcript_id
        join consent_records as consent
          on consent.id=transcript_challenge_dispositions.consent_record_id
       where challenge.id=transcript_challenge_dispositions.challenge_id
         and challenge.state='pending'
         and boardagent_meeting_secretary_for_board(challenge.board_id)
         and consent.organization_id=challenge.organization_id
         and consent.board_id=challenge.board_id
         and consent.actor_member_id=transcript_challenge_dispositions.secretary_member_id
         and consent.action_code='resolve_transcript_challenge'
         and consent.target_type='transcript_challenge'
         and consent.target_id=challenge.id
         and (
           (transcript_challenge_dispositions.decision='rejected'
            and transcript_challenge_dispositions.corrected_transcript_version_id is null)
           or
           (transcript_challenge_dispositions.decision='accepted'
            and exists (
              select 1 from meeting_transcript_versions as corrected
               where corrected.id=
                 transcript_challenge_dispositions.corrected_transcript_version_id
                 and corrected.transcript_id=transcript.id
                 and corrected.supersedes_id=challenged_version.id
                 and transcript.current_version_id=corrected.id
            ))
         )
    )
  );

drop policy boardagent_server_scope on transcript_question_links;
create policy boardagent_server_transcript_question_links_select on transcript_question_links
  for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1 from meeting_transcript_versions as version
       where version.id=transcript_question_links.transcript_version_id
    )
    and boardagent_question_permission(management_question_id,'read')
  );
create policy boardagent_server_transcript_question_links_insert on transcript_question_links
  for insert to boardagent_server
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_meeting_secretary_for_board(board_id)
    and boardagent_question_permission(management_question_id,'read')
    and exists (
      select 1
        from meeting_transcript_versions as version
        join meeting_transcripts as transcript on transcript.id=version.transcript_id
        join consent_records as consent on consent.id=transcript_question_links.consent_record_id
       where version.id=transcript_question_links.transcript_version_id
         and version.board_id=transcript_question_links.board_id
         and transcript.current_version_id=version.id
         and consent.organization_id=transcript_question_links.organization_id
         and consent.board_id=transcript_question_links.board_id
         and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
         and consent.action_code='link_meeting_qna'
         and consent.target_type='meeting_transcript'
         and consent.target_id=transcript.id
         and consent.package_sha256=version.canonical_sha256
    )
  );
