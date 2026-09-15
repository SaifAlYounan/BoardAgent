-- BoardAgent Phase 1 / group 10: audit chain, member feed, outbox, jobs, exports, and backup proof.

create table audit_chain_head (
  singleton_key boolean primary key default true check (singleton_key),
  last_sequence bigint not null default 0 check (last_sequence >= 0),
  last_event_sha256 bytea not null default decode(repeat('00', 32), 'hex')
    check (boardagent_hash_is_sha256(last_event_sha256)),
  row_version bigint not null default 1 check (row_version > 0),
  check (last_sequence > 0 or last_event_sha256 = decode(repeat('00', 32), 'hex'))
);
insert into audit_chain_head(singleton_key) values (true);

create table audit_events (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  sequence bigint not null unique check (sequence > 0),
  organization_id uuid not null references organizations(id) on delete restrict,
  board_id uuid,
  event_type text not null check (event_type in (
    'context_read', 'client_registered', 'client_registration_rejected',
    'oauth_client_blocked', 'oauth_client_unblocked', 'token_issued', 'token_refreshed',
    'token_reuse_detected', 'session_revoked', 'enrollment_issued', 'enrollment_redeemed',
    'enrollment_revoked', 'member_activated', 'identity_recovery_started',
    'external_identity_linked', 'external_identity_unlinked', 'member_changed',
    'onboarding_stage_created', 'onboarding_attested', 'onboarding_stale',
    'authorization_denied', 'rate_limited', 'resource_fetch', 'notice_delivered',
    'document_version_created', 'document_circulated', 'document_access_changed',
    'document_archived', 'document_soft_deleted', 'recusal_changed',
    'management_submission_created', 'management_revision_requested',
    'management_revision_replied', 'management_submission_version_created',
    'management_submission_approved_to_draft', 'management_submission_rejected',
    'management_question_asked', 'management_question_answered',
    'management_question_followed_up', 'secretariat_request_created',
    'secretariat_request_replied', 'secretariat_request_closed', 'board_created',
    'board_amended', 'board_archived', 'governance_profile_activated', 'matter_evaluated',
    'ruleset_amended', 'rule_overridden', 'stage_created', 'stage_replaced',
    'elicitation_sent', 'consent_recorded', 'consent_rejected', 'ballot_cast',
    'ballot_superseded', 'proxy_granted', 'proxy_revoked', 'resolution_amended',
    'vote_opened', 'vote_source_update_pending', 'vote_source_excluded', 'vote_closing',
    'vote_closed', 'vote_cancelled', 'vote_superseded', 'vote_replaced', 'revote_required',
    'certificate_issued', 'certificate_corrected', 'meeting_called', 'meeting_amended',
    'meeting_rsvp_recorded', 'meeting_attendance_recorded', 'meeting_attendance_corrected',
    'meeting_completed', 'meeting_cancelled', 'transcript_version_created',
    'transcript_secretary_verified', 'transcript_qna_linked', 'transcript_turn_challenged',
    'transcript_challenge_resolved', 'minutes_version_created', 'minutes_published',
    'minutes_commented', 'minutes_review_withdrawn', 'minutes_redline_proposed',
    'minutes_review_dispositioned', 'minutes_package_corrected',
    'minutes_correction_cycle_created', 'minutes_action_items_declared',
    'minutes_action_item_draft_superseded', 'minutes_action_items_activated',
    'minutes_signature_package_issued', 'minutes_signed', 'minutes_signature_superseded',
    'minutes_resign_required', 'minutes_finalized', 'minutes_cancelled', 'task_created',
    'task_started', 'task_evidence_submitted', 'task_evidence_reviewed', 'task_completed',
    'task_correction_cycle_created', 'task_cancelled', 'proposal_submitted',
    'proposal_withdrawn', 'proposal_approved_to_draft', 'proposal_rejected',
    'draft_cancelled', 'draft_expired', 'export_requested', 'export_started',
    'export_performed', 'export_failed', 'export_cancelled', 'export_artifact_deleted',
    'webhook_configured', 'webhook_secret_rotated', 'webhook_disabled', 'webhook_tested',
    'webhook_delivery_attempted', 'audit_checkpoint_signed', 'audit_verification_failed',
    'migration_applied', 'backup_completed', 'restore_verified'
  )),
  schema_version text not null check (schema_version = 'boardagent.audit-event.v1'),
  actor_member_id uuid,
  acting_for_member_id uuid,
  client_id uuid references oauth_clients(id) on delete restrict,
  token_jti uuid,
  consent_record_id uuid references consent_records(id) on delete restrict,
  object_type text not null check (object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  object_id uuid,
  object_version bigint check (object_version is null or object_version > 0),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 10485760),
  previous_event_sha256 bytea not null check (boardagent_hash_is_sha256(previous_event_sha256)),
  event_sha256 bytea not null unique check (boardagent_hash_is_sha256(event_sha256)),
  occurred_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, acting_for_member_id) references members(organization_id, id) on delete restrict,
  check (sequence > 1 or previous_event_sha256 = decode(repeat('00', 32), 'hex'))
);

create table audit_checkpoints (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  first_sequence bigint not null check (first_sequence > 0),
  last_sequence bigint not null check (last_sequence >= first_sequence),
  first_event_sha256 bytea not null check (boardagent_hash_is_sha256(first_event_sha256)),
  last_event_sha256 bytea not null check (boardagent_hash_is_sha256(last_event_sha256)),
  canonical_manifest bytea not null check (octet_length(canonical_manifest) between 2 and 10485760),
  manifest_sha256 bytea not null unique check (boardagent_hash_is_sha256(manifest_sha256)),
  signature bytea not null check (octet_length(signature) = 64),
  signing_key_id uuid not null references crypto_key_registry(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (first_sequence, last_sequence)
);

alter table membership_versions
  add constraint membership_versions_audit_event_fk
  foreign key (audit_event_id) references audit_events(id) on delete restrict;
alter table rule_overrides
  add constraint rule_overrides_audit_event_fk
  foreign key (audit_event_id) references audit_events(id) on delete restrict;
alter table minutes_action_item_dispositions
  add constraint minutes_action_dispositions_audit_event_fk
  foreign key (audit_event_id) references audit_events(id) on delete restrict;
alter table minutes_signature_supersessions
  add constraint minutes_signature_supersessions_audit_event_fk
  foreign key (audit_event_id) references audit_events(id) on delete restrict;
alter table ballot_dispositions
  add constraint ballot_dispositions_audit_event_fk
  foreign key (audit_event_id) references audit_events(id) on delete restrict;

create table notices (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  notice_type text not null check (notice_type ~ '^[a-z][a-z0-9_]{1,127}$'),
  object_type text not null check (object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  object_id uuid not null,
  object_version bigint not null check (object_version > 0),
  recipient_member_id uuid not null,
  content_sha256 bytea not null check (boardagent_hash_is_sha256(content_sha256)),
  feed_sequence bigint not null check (feed_sequence > 0),
  state text not null default 'committed' check (state in ('committed', 'delivered', 'superseded', 'cancelled')),
  audit_event_id uuid not null references audit_events(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  delivered_at timestamptz(6),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, recipient_member_id) references members(organization_id, id) on delete restrict,
  unique (recipient_member_id, board_id, feed_sequence),
  unique (notice_type, object_type, object_id, object_version, recipient_member_id),
  check ((state = 'delivered' and delivered_at is not null) or state <> 'delivered')
);

create table pending_action_feed (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  member_id uuid not null,
  entitlement_generation bigint not null check (entitlement_generation > 0),
  feed_sequence bigint not null check (feed_sequence > 0),
  action_type text not null check (action_type ~ '^[a-z][a-z0-9_]{1,127}$'),
  object_type text not null check (object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  object_id uuid not null,
  object_version bigint not null check (object_version > 0),
  visibility_sha256 bytea not null check (boardagent_hash_is_sha256(visibility_sha256)),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 1048576),
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  state text not null default 'pending' check (state in ('pending', 'resolved', 'superseded')),
  notice_id uuid references notices(id) on delete restrict,
  audit_event_id uuid not null references audit_events(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  resolved_at timestamptz(6),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  unique (member_id, board_id, entitlement_generation, feed_sequence),
  check ((state = 'resolved' and resolved_at is not null) or state <> 'resolved')
);

create table feed_tombstones (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  member_id uuid not null,
  entitlement_generation bigint not null check (entitlement_generation > 0),
  feed_sequence bigint not null check (feed_sequence > 0),
  removed_feed_id uuid references pending_action_feed(id) on delete restrict,
  object_type text not null check (object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  object_id uuid not null,
  reason_class text not null check (reason_class in ('resolved', 'revoked', 'recused', 'superseded', 'hidden')),
  tombstone_sha256 bytea not null unique check (boardagent_hash_is_sha256(tombstone_sha256)),
  audit_event_id uuid not null references audit_events(id) on delete restrict,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  unique (member_id, board_id, entitlement_generation, feed_sequence)
);

alter table circulation_recipients
  add constraint circulation_recipients_notice_fk
  foreign key (notice_id) references notices(id) on delete restrict;

create table member_webhooks (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  endpoint_ciphertext bytea not null check (octet_length(endpoint_ciphertext) between 32 and 4096),
  endpoint_sha256 bytea not null check (boardagent_hash_is_sha256(endpoint_sha256)),
  secret_sha256 bytea not null check (boardagent_hash_is_sha256(secret_sha256)),
  key_id uuid not null references crypto_key_registry(id) on delete restrict,
  ssrf_validation_receipt_sha256 bytea not null check (boardagent_hash_is_sha256(ssrf_validation_receipt_sha256)),
  state text not null default 'active' check (state in ('active', 'disabled', 'revoked')),
  generation bigint not null default 1 check (generation > 0),
  created_at timestamptz(6) not null default transaction_timestamp(),
  disabled_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  unique (member_id, endpoint_sha256)
);

create table notification_jobs (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  notice_id uuid not null references notices(id) on delete restrict,
  recipient_member_id uuid not null,
  webhook_id uuid references member_webhooks(id) on delete restrict,
  wake_class text not null check (wake_class ~ '^[a-z][a-z0-9_]{1,63}$'),
  random_wake_id bytea not null unique check (octet_length(random_wake_id) = 32),
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  state text not null default 'queued'
    check (state in ('queued', 'leased', 'retry', 'delivered', 'dead', 'cancelled')),
  attempts integer not null default 0 check (attempts between 0 and 100),
  available_at timestamptz(6) not null default transaction_timestamp(),
  lease_owner text,
  lease_expires_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  delivered_at timestamptz(6),
  foreign key (organization_id, recipient_member_id) references members(organization_id, id) on delete restrict,
  unique (notice_id, recipient_member_id, webhook_id),
  check ((state = 'leased' and lease_owner is not null and lease_expires_at is not null)
    or state <> 'leased'),
  check ((state = 'delivered' and delivered_at is not null) or state <> 'delivered')
);

create table notification_attempts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  notification_job_id uuid not null references notification_jobs(id) on delete restrict,
  attempt integer not null check (attempt > 0),
  request_sha256 bytea not null check (boardagent_hash_is_sha256(request_sha256)),
  result_class text not null check (result_class in ('delivered', 'retryable_failure', 'permanent_failure', 'cancelled')),
  http_status integer check (http_status is null or http_status between 100 and 599),
  response_sha256 bytea check (response_sha256 is null or boardagent_hash_is_sha256(response_sha256)),
  started_at timestamptz(6) not null,
  completed_at timestamptz(6) not null default transaction_timestamp(),
  unique (notification_job_id, attempt),
  check (completed_at >= started_at)
);

create table jobs (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  board_id uuid,
  job_type text not null check (job_type ~ '^[a-z][a-z0-9_]{1,127}$'),
  schema_version text not null check (schema_version ~ '^boardagent\.job\.[a-z0-9_.-]+\.v[0-9]+$'),
  subject_type text not null check (subject_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  subject_id uuid,
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 1048576),
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  idempotency_key text not null check (length(idempotency_key) between 16 and 256),
  state text not null default 'queued'
    check (state in ('queued', 'leased', 'retry', 'succeeded', 'dead', 'cancelled')),
  attempts integer not null default 0 check (attempts between 0 and 100),
  available_at timestamptz(6) not null default transaction_timestamp(),
  lease_owner text,
  lease_expires_at timestamptz(6),
  last_error_class text,
  created_at timestamptz(6) not null default transaction_timestamp(),
  completed_at timestamptz(6),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  unique (organization_id, job_type, idempotency_key),
  check ((state = 'leased' and lease_owner is not null and lease_expires_at is not null)
    or state <> 'leased'),
  check ((state = 'succeeded' and completed_at is not null) or state <> 'succeeded')
);

create table export_requests (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  public_id bytea not null unique check (octet_length(public_id) = 32),
  organization_id uuid not null,
  board_id uuid,
  requester_member_id uuid not null,
  export_type text not null check (export_type in ('audit_chain', 'system_data')),
  scope_manifest bytea not null check (octet_length(scope_manifest) between 2 and 1048576),
  scope_sha256 bytea not null check (boardagent_hash_is_sha256(scope_sha256)),
  state text not null default 'staged'
    check (state in ('staged', 'confirmed', 'queued', 'running', 'succeeded', 'failed', 'expired', 'deleted', 'cancelled')),
  consent_record_id uuid references consent_records(id) on delete restrict,
  recent_auth_at timestamptz(6) not null,
  expires_at timestamptz(6) not null,
  row_version bigint not null default 1 check (row_version > 0),
  created_at timestamptz(6) not null default transaction_timestamp(),
  completed_at timestamptz(6),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, requester_member_id) references members(organization_id, id) on delete restrict,
  check (expires_at > created_at),
  check ((state in ('confirmed', 'queued', 'running', 'succeeded', 'failed', 'expired', 'deleted')
      and consent_record_id is not null)
    or state in ('staged', 'cancelled'))
);

create table export_artifacts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  export_request_id uuid not null unique references export_requests(id) on delete restrict,
  manifest bytea not null check (octet_length(manifest) between 2 and 10485760),
  manifest_sha256 bytea not null unique check (boardagent_hash_is_sha256(manifest_sha256)),
  content_set_sha256 bytea not null check (boardagent_hash_is_sha256(content_set_sha256)),
  encrypted_storage_locator text not null check (length(encrypted_storage_locator) between 1 and 4096),
  encryption_key_id uuid not null references crypto_key_registry(id) on delete restrict,
  byte_length bigint not null check (byte_length >= 0),
  state text not null default 'ready' check (state in ('ready', 'quarantined', 'deleted', 'expired')),
  created_at timestamptz(6) not null default transaction_timestamp(),
  deleted_at timestamptz(6)
);

create table export_chunks (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  artifact_id uuid not null references export_artifacts(id) on delete restrict,
  ordinal integer not null check (ordinal >= 0),
  byte_offset bigint not null check (byte_offset >= 0),
  byte_length integer not null check (byte_length between 1 and 10485760),
  chunk_sha256 bytea not null check (boardagent_hash_is_sha256(chunk_sha256)),
  storage_locator text not null check (length(storage_locator) between 1 and 4096),
  unique (artifact_id, ordinal),
  unique (artifact_id, byte_offset)
);

create table backup_receipts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  schema_version text not null check (schema_version = 'boardagent.backup-receipt.v1'),
  canonical_manifest bytea not null check (octet_length(canonical_manifest) between 2 and 10485760),
  manifest_sha256 bytea not null unique check (boardagent_hash_is_sha256(manifest_sha256)),
  snapshot_lsn pg_lsn not null,
  snapshot_at timestamptz(6) not null,
  content_set_sha256 bytea not null check (boardagent_hash_is_sha256(content_set_sha256)),
  encryption_key_id uuid not null references crypto_key_registry(id) on delete restrict,
  state text not null check (state in ('created', 'verified', 'failed')),
  verified_restore_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  check ((state = 'verified' and verified_restore_at is not null) or state <> 'verified')
);

create index audit_events_board_sequence_idx on audit_events(board_id, sequence);
create index pending_action_feed_member_idx
  on pending_action_feed(member_id, board_id, entitlement_generation, feed_sequence) where state = 'pending';
create index feed_tombstones_member_idx
  on feed_tombstones(member_id, board_id, entitlement_generation, feed_sequence);
create index notification_jobs_lease_idx
  on notification_jobs(state, available_at, id) where state in ('queued', 'retry');
create index jobs_lease_idx on jobs(state, available_at, id) where state in ('queued', 'retry');
create index export_requests_requester_idx on export_requests(requester_member_id, created_at desc, id);
