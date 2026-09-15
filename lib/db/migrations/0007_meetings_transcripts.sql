-- BoardAgent Phase 1 / group 7: meetings, agendas, attendance, and transcript annexes.

create table meetings (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  title text not null check (length(title) between 1 and 512),
  state text not null default 'draft' check (state in ('draft', 'called', 'completed', 'cancelled')),
  scheduled_start timestamptz(6) not null,
  scheduled_end timestamptz(6) not null,
  current_version_id uuid,
  current_agenda_version_id uuid,
  current_minutes_id uuid,
  row_version bigint not null default 1 check (row_version > 0),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  completed_at timestamptz(6),
  cancelled_at timestamptz(6),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check (scheduled_end > scheduled_start),
  check ((state = 'completed' and completed_at is not null and cancelled_at is null)
    or (state = 'cancelled' and cancelled_at is not null and completed_at is null)
    or state in ('draft', 'called'))
);

create table meeting_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  meeting_id uuid not null,
  version integer not null check (version > 0),
  canonical_schema text not null check (canonical_schema = 'boardagent.meeting.v1'),
  canonical_title text not null check (length(canonical_title) between 1 and 512),
  scheduled_start timestamptz(6) not null,
  scheduled_end timestamptz(6) not null,
  notice_package bytea not null check (octet_length(notice_package) between 2 and 10485760),
  notice_package_sha256 bytea not null check (boardagent_hash_is_sha256(notice_package_sha256)),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  change_reason text not null check (length(change_reason) between 1 and 65536),
  consent_record_id uuid references consent_records(id) on delete restrict,
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (meeting_id, version),
  unique (meeting_id, id),
  foreign key (board_id, meeting_id) references meetings(board_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check (scheduled_end > scheduled_start)
);

alter table meetings
  add constraint meetings_current_version_fk
  foreign key (id, current_version_id) references meeting_versions(meeting_id, id)
  deferrable initially deferred;

create table agenda_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  meeting_id uuid not null,
  meeting_version_id uuid not null,
  version integer not null check (version > 0),
  schema_version text not null check (schema_version = 'boardagent.agenda.v1'),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 10485760),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (meeting_id, version),
  unique (meeting_id, id),
  foreign key (meeting_id, meeting_version_id) references meeting_versions(meeting_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict
);

alter table meetings
  add constraint meetings_current_agenda_fk
  foreign key (id, current_agenda_version_id) references agenda_versions(meeting_id, id)
  deferrable initially deferred;

create table agenda_items (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  agenda_version_id uuid not null references agenda_versions(id) on delete restrict,
  ordinal integer not null check (ordinal > 0),
  title text not null check (length(title) between 1 and 512),
  source_document_version_id uuid references document_versions(id) on delete restrict,
  source_document_sha256 bytea,
  item_sha256 bytea not null check (boardagent_hash_is_sha256(item_sha256)),
  unique (agenda_version_id, ordinal),
  check ((source_document_version_id is null and source_document_sha256 is null)
    or (source_document_version_id is not null and boardagent_hash_is_sha256(source_document_sha256)))
);

create table meeting_rsvps (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  meeting_id uuid not null,
  member_id uuid not null,
  version integer not null check (version > 0),
  response text not null check (response in ('attending', 'not_attending', 'tentative')),
  is_current boolean not null default true,
  idempotency_record_id uuid not null references idempotency_records(id) on delete restrict,
  recorded_at timestamptz(6) not null default transaction_timestamp(),
  unique (meeting_id, member_id, version),
  foreign key (board_id, meeting_id) references meetings(board_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict
);
create unique index meeting_rsvps_one_current_uq
  on meeting_rsvps(meeting_id, member_id) where is_current;

create table meeting_attendance (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  meeting_id uuid not null,
  member_id uuid not null,
  attendance_status text not null check (attendance_status in ('present', 'absent', 'excused', 'partial')),
  source text not null check (source in ('secretary_record', 'member_confirmation', 'correction')),
  recorder_member_id uuid not null,
  corrects_id uuid references meeting_attendance(id) on delete restrict,
  correction_reason text,
  consent_record_id uuid references consent_records(id) on delete restrict,
  recorded_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (board_id, meeting_id) references meetings(board_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, recorder_member_id) references members(organization_id, id) on delete restrict,
  check ((corrects_id is null and correction_reason is null)
    or (corrects_id is not null and correction_reason is not null and length(correction_reason) between 1 and 65536))
);
create unique index meeting_attendance_original_uq
  on meeting_attendance(meeting_id, member_id) where corrects_id is null;
create unique index meeting_attendance_one_correction_uq
  on meeting_attendance(corrects_id) where corrects_id is not null;

create table meeting_transcripts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  meeting_id uuid not null unique,
  state text not null default 'unverified' check (state in ('unverified', 'secretary_verified')),
  current_version_id uuid,
  row_version bigint not null default 1 check (row_version > 0),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (board_id, id),
  foreign key (board_id, meeting_id) references meetings(board_id, id) on delete restrict
);

create table meeting_transcript_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  transcript_id uuid not null,
  version integer not null check (version > 0),
  canonical_schema text not null check (canonical_schema in ('boardagent.transcript-markdown.v1', 'boardagent.transcript-turns.v1')),
  media_type text not null check (media_type in ('text/markdown; charset=utf-8', 'application/json')),
  canonical_bytes bytea not null check (octet_length(canonical_bytes) between 1 and 10485760),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  source_type text not null check (source_type in ('agent_prepared', 'secretary_prepared', 'imported_text')),
  coverage_start timestamptz(6),
  coverage_end timestamptz(6),
  verification_state text not null default 'agent_prepared_unverified'
    check (verification_state in ('agent_prepared_unverified', 'secretary_verified')),
  created_by uuid not null,
  supersedes_id uuid references meeting_transcript_versions(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (transcript_id, version),
  unique (transcript_id, id),
  foreign key (board_id, transcript_id) references meeting_transcripts(board_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check ((coverage_start is null and coverage_end is null)
    or (coverage_start is not null and coverage_end > coverage_start)),
  check ((media_type = 'application/json' and canonical_schema = 'boardagent.transcript-turns.v1')
    or (media_type = 'text/markdown; charset=utf-8' and canonical_schema = 'boardagent.transcript-markdown.v1'))
);

alter table meeting_transcripts
  add constraint meeting_transcripts_current_version_fk
  foreign key (id, current_version_id) references meeting_transcript_versions(transcript_id, id)
  deferrable initially deferred;

create table transcript_turns (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  transcript_version_id uuid not null references meeting_transcript_versions(id) on delete restrict,
  ordinal integer not null check (ordinal > 0),
  speaker_member_id uuid references members(id) on delete restrict,
  speaker_label text not null check (length(speaker_label) between 1 and 512),
  starts_at_ms bigint check (starts_at_ms is null or starts_at_ms >= 0),
  ends_at_ms bigint check (ends_at_ms is null or ends_at_ms >= 0),
  canonical_text text not null check (length(canonical_text) between 1 and 1048576),
  text_sha256 bytea not null check (boardagent_hash_is_sha256(text_sha256)),
  unique (transcript_version_id, ordinal),
  unique (transcript_version_id, id),
  check ((starts_at_ms is null and ends_at_ms is null)
    or (starts_at_ms is not null and ends_at_ms > starts_at_ms))
);

create table transcript_verifications (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  transcript_version_id uuid not null unique references meeting_transcript_versions(id) on delete restrict,
  transcript_sha256 bytea not null check (boardagent_hash_is_sha256(transcript_sha256)),
  secretary_member_id uuid not null,
  status text not null check (status = 'secretary_verified'),
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  verified_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict
);

create table transcript_challenges (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  transcript_version_id uuid not null references meeting_transcript_versions(id) on delete restrict,
  turn_id uuid not null references transcript_turns(id) on delete restrict,
  challenger_member_id uuid not null,
  canonical_comment text not null check (length(canonical_comment) between 1 and 1048576),
  comment_sha256 bytea not null check (boardagent_hash_is_sha256(comment_sha256)),
  state text not null default 'pending' check (state in ('pending', 'accepted', 'rejected')),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, challenger_member_id) references members(organization_id, id) on delete restrict
);

create table transcript_challenge_dispositions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  challenge_id uuid not null unique references transcript_challenges(id) on delete restrict,
  secretary_member_id uuid not null,
  decision text not null check (decision in ('accepted', 'rejected')),
  reason text not null check (length(reason) between 1 and 65536),
  corrected_transcript_version_id uuid,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  foreign key (corrected_transcript_version_id) references meeting_transcript_versions(id) on delete restrict,
  check ((decision = 'accepted' and corrected_transcript_version_id is not null)
    or (decision = 'rejected' and corrected_transcript_version_id is null))
);

create table transcript_question_links (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  transcript_version_id uuid not null references meeting_transcript_versions(id) on delete restrict,
  first_turn_id uuid not null references transcript_turns(id) on delete restrict,
  last_turn_id uuid not null references transcript_turns(id) on delete restrict,
  turns_sha256 bytea not null check (boardagent_hash_is_sha256(turns_sha256)),
  management_question_id uuid not null references management_questions(id) on delete restrict,
  management_question_sha256 bytea not null check (boardagent_hash_is_sha256(management_question_sha256)),
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (transcript_version_id, first_turn_id, last_turn_id, management_question_id)
);

create index meetings_board_schedule_idx on meetings(board_id, scheduled_start, id);
create index meeting_versions_meeting_idx on meeting_versions(meeting_id, version desc);
create index transcript_turns_version_idx on transcript_turns(transcript_version_id, ordinal);
create index transcript_challenges_pending_idx
  on transcript_challenges(board_id, created_at, id) where state = 'pending';
