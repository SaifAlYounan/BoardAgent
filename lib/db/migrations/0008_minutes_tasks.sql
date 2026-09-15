-- BoardAgent Phase 1 / group 8: minutes review, signatures, and action-item evidence.

create table minutes (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  meeting_id uuid not null unique,
  state text not null default 'unpublished_draft'
    check (state in ('unpublished_draft', 'published_review', 'signature_ready', 'finalized', 'cancelled')),
  current_version_id uuid,
  current_signature_package_id uuid,
  correction_of_minutes_id uuid references minutes(id) on delete restrict,
  row_version bigint not null default 1 check (row_version > 0),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  finalized_at timestamptz(6),
  cancelled_at timestamptz(6),
  unique (board_id, id),
  unique (meeting_id, id),
  foreign key (board_id, meeting_id) references meetings(board_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check ((state = 'finalized' and finalized_at is not null and cancelled_at is null)
    or (state = 'cancelled' and cancelled_at is not null and finalized_at is null)
    or state in ('unpublished_draft', 'published_review', 'signature_ready'))
);

alter table meetings
  add constraint meetings_current_minutes_fk
  foreign key (id, current_minutes_id) references minutes(meeting_id, id)
  deferrable initially deferred;

create table minutes_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  minutes_id uuid not null,
  version integer not null check (version > 0),
  canonical_schema text not null check (canonical_schema = 'boardagent.minutes.v1'),
  canonical_text text not null check (length(canonical_text) between 1 and 10485760),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  package_base_sha256 bytea not null check (boardagent_hash_is_sha256(package_base_sha256)),
  transcript_version_id uuid references meeting_transcript_versions(id) on delete restrict,
  transcript_sha256 bytea,
  created_by uuid not null,
  supersedes_id uuid references minutes_versions(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (minutes_id, version),
  unique (minutes_id, id),
  foreign key (board_id, minutes_id) references minutes(board_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check ((transcript_version_id is null and transcript_sha256 is null)
    or (transcript_version_id is not null and boardagent_hash_is_sha256(transcript_sha256)))
);

alter table minutes
  add constraint minutes_current_version_fk
  foreign key (id, current_version_id) references minutes_versions(minutes_id, id)
  deferrable initially deferred;

create table minutes_review_items (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  minutes_id uuid not null,
  item_kind text not null check (item_kind in ('comment', 'redline')),
  schema_version text not null check (schema_version in ('boardagent.minutes-comment.v1', 'boardagent.minutes-redline.v1')),
  author_member_id uuid not null,
  author_seat_role text not null check (author_seat_role in ('voting_member', 'management', 'observer')),
  base_version_id uuid not null,
  base_sha256 bytea not null check (boardagent_hash_is_sha256(base_sha256)),
  exact_anchor jsonb not null check (jsonb_typeof(exact_anchor) = 'object'),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 1048576),
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  idempotency_record_id uuid not null references idempotency_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (minutes_id, base_version_id) references minutes_versions(minutes_id, id) on delete restrict,
  foreign key (organization_id, author_member_id) references members(organization_id, id) on delete restrict,
  check ((item_kind = 'comment' and schema_version = 'boardagent.minutes-comment.v1')
    or (item_kind = 'redline' and schema_version = 'boardagent.minutes-redline.v1'))
);

create table minutes_review_withdrawals (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  review_item_id uuid not null unique references minutes_review_items(id) on delete restrict,
  author_member_id uuid not null,
  current_minutes_version_id uuid not null references minutes_versions(id) on delete restrict,
  idempotency_record_id uuid not null references idempotency_records(id) on delete restrict,
  withdrawn_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, author_member_id) references members(organization_id, id) on delete restrict
);

create table minutes_diffs (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  minutes_id uuid not null references minutes(id) on delete restrict,
  base_version_id uuid not null,
  new_version_id uuid not null,
  operations jsonb not null check (jsonb_typeof(operations) = 'array'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (minutes_id, base_version_id) references minutes_versions(minutes_id, id) on delete restrict,
  foreign key (minutes_id, new_version_id) references minutes_versions(minutes_id, id) on delete restrict,
  unique (base_version_id, new_version_id),
  check (base_version_id <> new_version_id)
);

create table minutes_review_dispositions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  review_item_id uuid not null unique references minutes_review_items(id) on delete restrict,
  secretary_member_id uuid not null,
  decision text not null check (decision in ('accepted', 'rejected')),
  reason text not null check (length(reason) between 1 and 65536),
  resulting_minutes_version_id uuid references minutes_versions(id) on delete restrict,
  diff_id uuid references minutes_diffs(id) on delete restrict,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  check (decision = 'accepted' or (resulting_minutes_version_id is null and diff_id is null)),
  check (num_nonnulls(resulting_minutes_version_id, diff_id) in (0, 2))
);

create table minutes_correction_cycles (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  original_minutes_id uuid not null references minutes(id) on delete restrict,
  replacement_minutes_id uuid not null unique references minutes(id) on delete restrict,
  reason text not null check (length(reason) between 1 and 65536),
  secretary_member_id uuid not null,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  unique (original_minutes_id, replacement_minutes_id),
  check (original_minutes_id <> replacement_minutes_id)
);

create table minutes_action_declarations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  minutes_id uuid not null,
  minutes_version_id uuid not null,
  minutes_sha256 bytea not null check (boardagent_hash_is_sha256(minutes_sha256)),
  declaration text not null check (declaration in ('items_logged', 'no_action_items')),
  complete_manifest bytea not null check (octet_length(complete_manifest) between 2 and 10485760),
  manifest_sha256 bytea not null check (boardagent_hash_is_sha256(manifest_sha256)),
  secretary_member_id uuid not null,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  declared_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (minutes_id, minutes_version_id) references minutes_versions(minutes_id, id) on delete restrict,
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  unique (minutes_version_id)
);

create table tasks (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  source_meeting_id uuid,
  source_minutes_id uuid,
  source_minutes_version_id uuid,
  source_minutes_sha256 bytea,
  source_locator jsonb,
  owner_member_id uuid not null,
  due_at timestamptz(6) not null,
  description_schema text not null check (description_schema = 'boardagent.task.v1'),
  canonical_description text not null check (length(canonical_description) between 1 and 1048576),
  required_evidence jsonb not null check (jsonb_typeof(required_evidence) = 'object'),
  task_sha256 bytea not null check (boardagent_hash_is_sha256(task_sha256)),
  state text not null default 'open'
    check (state in ('draft', 'open', 'in_progress', 'evidence_submitted', 'completed', 'cancelled', 'superseded')),
  row_version bigint not null default 1 check (row_version > 0),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  completed_at timestamptz(6),
  cancelled_at timestamptz(6),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (board_id, source_meeting_id) references meetings(board_id, id) on delete restrict,
  foreign key (board_id, source_minutes_id) references minutes(board_id, id) on delete restrict,
  foreign key (source_minutes_id, source_minutes_version_id)
    references minutes_versions(minutes_id, id) on delete restrict,
  foreign key (organization_id, owner_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check ((source_minutes_id is null and source_meeting_id is null and source_minutes_version_id is null
      and source_minutes_sha256 is null and source_locator is null)
    or (source_minutes_id is not null and source_meeting_id is not null and source_minutes_version_id is not null
      and boardagent_hash_is_sha256(source_minutes_sha256) and jsonb_typeof(source_locator) = 'object')),
  check (state <> 'draft' or source_minutes_id is not null),
  check ((state = 'completed' and completed_at is not null and cancelled_at is null)
    or (state = 'cancelled' and cancelled_at is not null and completed_at is null)
    or state in ('draft', 'open', 'in_progress', 'evidence_submitted', 'superseded'))
);

create table minutes_action_item_dispositions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  task_id uuid not null unique references tasks(id) on delete restrict,
  stale_minutes_version_id uuid not null references minutes_versions(id) on delete restrict,
  replacement_minutes_version_id uuid not null references minutes_versions(id) on delete restrict,
  disposition text not null check (disposition = 'superseded'),
  reason text not null check (length(reason) between 1 and 65536),
  audit_event_id uuid,
  created_at timestamptz(6) not null default transaction_timestamp(),
  check (stale_minutes_version_id <> replacement_minutes_version_id)
);

create table task_evidence (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  task_id uuid not null,
  owner_member_id uuid not null,
  canonical_text text,
  document_references jsonb not null check (jsonb_typeof(document_references) = 'array'),
  resource_references jsonb not null check (jsonb_typeof(resource_references) = 'array'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  state text not null default 'submitted' check (state in ('submitted', 'accepted', 'rejected')),
  row_version bigint not null default 1 check (row_version > 0),
  submitted_at timestamptz(6) not null default transaction_timestamp(),
  unique (task_id, id),
  foreign key (board_id, task_id) references tasks(board_id, id) on delete restrict,
  foreign key (organization_id, owner_member_id) references members(organization_id, id) on delete restrict,
  check (canonical_text is not null or jsonb_array_length(document_references) > 0
    or jsonb_array_length(resource_references) > 0)
);

create table task_evidence_reviews (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  evidence_id uuid not null unique references task_evidence(id) on delete restrict,
  secretary_member_id uuid not null,
  decision text not null check (decision in ('accepted', 'rejected')),
  reason text not null check (length(reason) between 1 and 65536),
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  reviewed_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict
);

create table task_closures (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  task_id uuid not null unique,
  primary_evidence_id uuid not null,
  accepted_evidence_manifest jsonb not null check (
    jsonb_typeof(accepted_evidence_manifest) = 'array' and jsonb_array_length(accepted_evidence_manifest) > 0
  ),
  source_minutes_sha256 bytea,
  secretary_member_id uuid not null,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  closure_sha256 bytea not null unique check (boardagent_hash_is_sha256(closure_sha256)),
  closed_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (board_id, task_id) references tasks(board_id, id) on delete restrict,
  foreign key (task_id, primary_evidence_id) references task_evidence(task_id, id) on delete restrict,
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  check (source_minutes_sha256 is null or boardagent_hash_is_sha256(source_minutes_sha256))
);

create table task_correction_cycles (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  prior_task_id uuid not null unique references tasks(id) on delete restrict,
  prior_closure_id uuid not null unique references task_closures(id) on delete restrict,
  replacement_task_id uuid not null unique references tasks(id) on delete restrict,
  secretary_member_id uuid not null,
  reason text not null check (length(reason) between 1 and 65536),
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  check (prior_task_id <> replacement_task_id)
);

create table minutes_signature_packages (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  minutes_id uuid not null,
  minutes_version_id uuid not null,
  version integer not null check (version > 0),
  minutes_sha256 bytea not null check (boardagent_hash_is_sha256(minutes_sha256)),
  transcript_manifest_sha256 bytea not null check (boardagent_hash_is_sha256(transcript_manifest_sha256)),
  action_manifest_sha256 bytea not null check (boardagent_hash_is_sha256(action_manifest_sha256)),
  review_manifest_sha256 bytea not null check (boardagent_hash_is_sha256(review_manifest_sha256)),
  signer_manifest_sha256 bytea not null check (boardagent_hash_is_sha256(signer_manifest_sha256)),
  package_sha256 bytea not null unique check (boardagent_hash_is_sha256(package_sha256)),
  state text not null default 'current' check (state in ('current', 'superseded', 'terminal')),
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  issued_at timestamptz(6) not null default transaction_timestamp(),
  unique (minutes_id, version),
  unique (minutes_id, id),
  foreign key (minutes_id, minutes_version_id) references minutes_versions(minutes_id, id) on delete restrict
);
create unique index minutes_signature_packages_one_current_uq
  on minutes_signature_packages(minutes_id) where state = 'current';

alter table minutes
  add constraint minutes_current_signature_package_fk
  foreign key (id, current_signature_package_id) references minutes_signature_packages(minutes_id, id)
  deferrable initially deferred;

create table minutes_signature_requirements (
  package_id uuid not null references minutes_signature_packages(id) on delete restrict,
  member_id uuid not null references members(id) on delete restrict,
  seat_role text not null check (seat_role in ('voting_member', 'management', 'observer')),
  requirement text not null check (requirement in ('required', 'permitted')),
  member_snapshot_sha256 bytea not null check (boardagent_hash_is_sha256(member_snapshot_sha256)),
  primary key (package_id, member_id)
);

create table minutes_signatures (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  package_id uuid not null,
  minutes_version_id uuid not null references minutes_versions(id) on delete restrict,
  package_sha256 bytea not null check (boardagent_hash_is_sha256(package_sha256)),
  signer_member_id uuid not null,
  signer_seat_role text not null check (signer_seat_role in ('voting_member', 'management', 'observer')),
  reservation_sha256 bytea check (reservation_sha256 is null or boardagent_hash_is_sha256(reservation_sha256)),
  consent_record_id uuid not null unique references consent_records(id) on delete restrict,
  access_token_record_id uuid not null references access_token_records(id) on delete restrict,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  exact_origin text not null,
  staged_at timestamptz(6) not null,
  signed_at timestamptz(6) not null default transaction_timestamp(),
  signature_record_sha256 bytea not null unique check (boardagent_hash_is_sha256(signature_record_sha256)),
  foreign key (package_id, signer_member_id)
    references minutes_signature_requirements(package_id, member_id) on delete restrict,
  foreign key (organization_id, signer_member_id) references members(organization_id, id) on delete restrict,
  unique (package_id, signer_member_id),
  check (signed_at >= staged_at)
);

create table minutes_signature_supersessions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  old_signature_id uuid not null unique references minutes_signatures(id) on delete restrict,
  old_package_id uuid not null references minutes_signature_packages(id) on delete restrict,
  new_minutes_version_id uuid not null references minutes_versions(id) on delete restrict,
  new_package_id uuid not null references minutes_signature_packages(id) on delete restrict,
  reason text not null check (length(reason) between 1 and 65536),
  audit_event_id uuid,
  created_at timestamptz(6) not null default transaction_timestamp(),
  check (old_package_id <> new_package_id)
);

create table minutes_resign_requirements (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  minutes_id uuid not null references minutes(id) on delete restrict,
  signer_member_id uuid not null references members(id) on delete restrict,
  from_package_id uuid not null references minutes_signature_packages(id) on delete restrict,
  to_package_id uuid not null references minutes_signature_packages(id) on delete restrict,
  state text not null default 'pending' check (state in ('pending', 'resolved')),
  resolution text check (resolution in ('signed_current_package', 'package_superseded', 'package_terminal')),
  resolved_signature_id uuid references minutes_signatures(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  resolved_at timestamptz(6),
  check (from_package_id <> to_package_id),
  check ((state = 'pending' and resolution is null and resolved_at is null and resolved_signature_id is null)
    or (state = 'resolved' and resolution is not null and resolved_at is not null))
);
create unique index minutes_resign_requirements_one_pending_uq
  on minutes_resign_requirements(minutes_id, signer_member_id) where state = 'pending';

create index minutes_board_state_idx on minutes(board_id, state, id);
create index minutes_review_items_package_idx on minutes_review_items(minutes_id, base_version_id, created_at, id);
create index tasks_owner_state_due_idx on tasks(owner_member_id, state, due_at, id)
  where state in ('open', 'in_progress', 'evidence_submitted');
