-- BoardAgent Phase 1 / group 6: management submissions and permanent Q&A threads.

create table management_submission_threads (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  management_owner_ids uuid[] not null check (cardinality(management_owner_ids) between 1 and 1000),
  assigned_secretary_id uuid,
  state text not null default 'submitted'
    check (state in ('submitted', 'revision_requested', 'resubmitted', 'approved_to_draft', 'rejected')),
  current_version_id uuid,
  queue_entered_at timestamptz(6) not null default transaction_timestamp(),
  row_version bigint not null default 1 check (row_version > 0),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, assigned_secretary_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict
);

create table management_submission_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  thread_id uuid not null,
  version integer not null check (version > 0),
  schema_version text not null check (schema_version = 'boardagent.management-submission.v1'),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 10485760),
  document_references jsonb not null check (jsonb_typeof(document_references) = 'array'),
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  author_member_id uuid not null,
  change_reason text not null check (length(change_reason) between 1 and 65536),
  supersedes_id uuid references management_submission_versions(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (thread_id, version),
  unique (thread_id, id),
  foreign key (board_id, thread_id) references management_submission_threads(board_id, id) on delete restrict,
  foreign key (organization_id, author_member_id) references members(organization_id, id) on delete restrict
);

alter table management_submission_threads
  add constraint management_submission_threads_current_version_fk
  foreign key (id, current_version_id) references management_submission_versions(thread_id, id)
  deferrable initially deferred;

create table management_revision_requests (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  thread_id uuid not null,
  submission_version_id uuid not null,
  secretary_member_id uuid not null,
  request_text text not null check (length(request_text) between 1 and 1048576),
  request_sha256 bytea not null check (boardagent_hash_is_sha256(request_sha256)),
  consent_record_id uuid references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (thread_id, submission_version_id)
    references management_submission_versions(thread_id, id) on delete restrict,
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  unique (thread_id, submission_version_id, id)
);

create table management_revision_replies (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  request_id uuid not null references management_revision_requests(id) on delete restrict,
  submission_version_id uuid not null references management_submission_versions(id) on delete restrict,
  management_author_id uuid not null,
  canonical_reply text not null check (length(canonical_reply) between 1 and 1048576),
  reply_sha256 bytea not null check (boardagent_hash_is_sha256(reply_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, management_author_id) references members(organization_id, id) on delete restrict,
  unique (request_id, submission_version_id)
);

create table management_submission_dispositions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  thread_id uuid not null,
  submission_version_id uuid not null,
  disposition text not null check (disposition in ('approved_to_draft', 'rejected')),
  secretary_member_id uuid not null,
  reason text not null check (length(reason) between 1 and 65536),
  resulting_draft_id uuid,
  consent_record_id uuid references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (thread_id, submission_version_id)
    references management_submission_versions(thread_id, id) on delete restrict,
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  foreign key (resulting_draft_id) references wizard_drafts(id) on delete restrict,
  unique (submission_version_id),
  check ((disposition = 'approved_to_draft' and resulting_draft_id is not null)
    or (disposition = 'rejected' and resulting_draft_id is null))
);

create table management_questions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  asker_member_id uuid not null,
  assigned_owner_ids uuid[] not null check (cardinality(assigned_owner_ids) between 1 and 1000),
  due_at timestamptz(6) not null,
  acl_policy jsonb not null check (jsonb_typeof(acl_policy) = 'object'),
  state text not null default 'pending' check (state in ('pending', 'overdue', 'answered')),
  current_turn_id uuid,
  row_version bigint not null default 1 check (row_version > 0),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, asker_member_id) references members(organization_id, id) on delete restrict,
  check (due_at > created_at)
);

create table management_question_turns (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  question_id uuid not null,
  ordinal integer not null check (ordinal > 0),
  turn_kind text not null check (turn_kind in ('question', 'answer', 'follow_up')),
  author_member_id uuid not null,
  author_role text not null check (author_role in ('voting_member', 'management', 'observer', 'secretariat')),
  canonical_text text not null check (length(canonical_text) between 1 and 1048576),
  text_sha256 bytea not null check (boardagent_hash_is_sha256(text_sha256)),
  citation_snapshot jsonb not null check (jsonb_typeof(citation_snapshot) = 'array'),
  idempotency_record_id uuid not null references idempotency_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (question_id, ordinal),
  unique (question_id, id),
  foreign key (board_id, question_id) references management_questions(board_id, id) on delete restrict,
  foreign key (organization_id, author_member_id) references members(organization_id, id) on delete restrict
);

alter table management_questions
  add constraint management_questions_current_turn_fk
  foreign key (id, current_turn_id) references management_question_turns(question_id, id)
  deferrable initially deferred;

create table management_question_answers (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  question_id uuid not null references management_questions(id) on delete restrict,
  answer_turn_id uuid not null unique references management_question_turns(id) on delete restrict,
  management_author_id uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, management_author_id) references members(organization_id, id) on delete restrict,
  unique (question_id, id)
);

create table question_visibility (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  question_id uuid not null,
  inherited_document_id uuid,
  inherited_object_type text,
  inherited_object_id uuid,
  grantee_member_id uuid,
  grantee_seat_role text check (grantee_seat_role in ('voting_member', 'management', 'observer')),
  effect text not null check (effect in ('grant', 'exclude')),
  reason text not null check (length(reason) between 1 and 65536),
  active_from timestamptz(6) not null default transaction_timestamp(),
  active_until timestamptz(6),
  created_by uuid not null,
  foreign key (board_id, question_id) references management_questions(board_id, id) on delete restrict,
  foreign key (inherited_document_id) references documents(id) on delete restrict,
  foreign key (organization_id, grantee_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check (num_nonnulls(inherited_document_id, inherited_object_id) <= 1),
  check ((inherited_object_id is null and inherited_object_type is null)
    or (inherited_object_id is not null and inherited_object_type ~ '^[a-z][a-z0-9_]{1,63}$')),
  check (num_nonnulls(grantee_member_id, grantee_seat_role) = 1),
  check (active_until is null or active_until > active_from)
);
create unique index question_visibility_one_active_uq
  on question_visibility(question_id, grantee_member_id, grantee_seat_role, effect)
  nulls not distinct
  where active_until is null;

create table question_decision_links (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  question_id uuid not null,
  inclusive_turn_ordinal integer not null check (inclusive_turn_ordinal > 0),
  inclusive_turn_sha256 bytea not null check (boardagent_hash_is_sha256(inclusive_turn_sha256)),
  decision_package_id uuid not null,
  decision_package_version integer not null check (decision_package_version > 0),
  decision_package_sha256 bytea not null check (boardagent_hash_is_sha256(decision_package_sha256)),
  selected_by uuid not null,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (board_id, question_id) references management_questions(board_id, id) on delete restrict,
  foreign key (organization_id, selected_by) references members(organization_id, id) on delete restrict,
  unique (question_id, decision_package_id)
);

create index management_submission_queue_idx
  on management_submission_threads(board_id, state, queue_entered_at, id);
create index management_questions_due_idx
  on management_questions(board_id, state, due_at, id) where state in ('pending', 'overdue');
create index management_question_turns_read_idx
  on management_question_turns(question_id, ordinal);
