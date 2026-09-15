-- BoardAgent Phase 1 / group 5: staged consent, replay safety, and guided drafts.

create table action_stages (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid,
  actor_member_id uuid not null,
  acting_for_member_id uuid,
  action_code text not null check (action_code ~ '^[a-z][a-z0-9_]{1,127}$'),
  target_type text not null check (target_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  target_id uuid,
  canonical_schema text not null check (canonical_schema ~ '^boardagent\.[a-z0-9_.-]+\.v[0-9]+$'),
  canonicalization_version text not null check (canonicalization_version = 'RFC8785+NFC-LF-v1'),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 10485760),
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  package_sha256 bytea check (package_sha256 is null or boardagent_hash_is_sha256(package_sha256)),
  nonce_sha256 bytea not null unique check (boardagent_hash_is_sha256(nonce_sha256)),
  protected_code_sha256 bytea not null unique check (boardagent_hash_is_sha256(protected_code_sha256)),
  client_id uuid not null references oauth_clients(id) on delete restrict,
  access_token_record_id uuid not null references access_token_records(id) on delete restrict,
  token_jti uuid not null,
  exact_origin text not null check (exact_origin ~ '^https://[^/?#]+$'),
  context_sha256 bytea not null check (boardagent_hash_is_sha256(context_sha256)),
  state text not null default 'active'
    check (state in ('active', 'replaced', 'confirmed', 'rejected', 'expired', 'cancelled')),
  replaces_stage_id uuid references action_stages(id) on delete restrict,
  expires_at timestamptz(6) not null,
  confirmed_at timestamptz(6),
  rejected_at timestamptz(6),
  cancelled_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, acting_for_member_id) references members(organization_id, id) on delete restrict,
  check (expires_at <= created_at + interval '10 minutes'),
  check (expires_at > created_at),
  check ((state = 'confirmed' and confirmed_at is not null)
    or (state = 'rejected' and rejected_at is not null)
    or (state = 'cancelled' and cancelled_at is not null)
    or state in ('active', 'replaced', 'expired')),
  check (num_nonnulls(confirmed_at, rejected_at, cancelled_at) <= 1)
);
create unique index action_stages_one_active_key_uq
  on action_stages(actor_member_id, client_id, action_code, target_type, target_id)
  nulls not distinct
  where state = 'active';
create index action_stages_expiry_idx on action_stages(expires_at, id) where state = 'active';

create table input_required_attempts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  stage_id uuid not null references action_stages(id) on delete restrict,
  wizard_draft_id uuid,
  protocol_version text not null check (protocol_version = '2026-07-28'),
  protocol_header_version text not null check (protocol_header_version = '2026-07-28'),
  result_meta_version text not null check (result_meta_version = 'boardagent.mrtr.v1'),
  original_method text not null check (original_method = 'tools/call'),
  original_name text not null check (original_name ~ '^[a-z][a-z0-9_]{1,127}$'),
  original_arguments_sha256 bytea not null check (boardagent_hash_is_sha256(original_arguments_sha256)),
  capabilities_sha256 bytea not null check (boardagent_hash_is_sha256(capabilities_sha256)),
  embedded_form_sha256 bytea not null check (boardagent_hash_is_sha256(embedded_form_sha256)),
  embedded_result_sha256 bytea not null check (boardagent_hash_is_sha256(embedded_result_sha256)),
  request_state_bytes bytea not null check (octet_length(request_state_bytes) between 32 and 4096),
  request_state_sha256 bytea not null unique check (boardagent_hash_is_sha256(request_state_sha256)),
  prepared_request_id bytea not null check (octet_length(prepared_request_id) between 1 and 1024),
  retry_request_id bytea check (retry_request_id is null or octet_length(retry_request_id) between 1 and 1024),
  input_response_sha256 bytea check (input_response_sha256 is null or boardagent_hash_is_sha256(input_response_sha256)),
  response_action text check (response_action in ('accept', 'decline', 'cancel')),
  state text not null default 'prepared'
    check (state in ('prepared', 'retry_received', 'accepted', 'declined', 'cancelled', 'expired', 'confirmed')),
  prepared_at timestamptz(6) not null default transaction_timestamp(),
  retry_received_at timestamptz(6),
  completed_at timestamptz(6),
  unique (stage_id, prepared_request_id),
  foreign key (organization_id, stage_id) references action_stages(organization_id, id) on delete restrict,
  check ((state in ('accepted', 'declined', 'cancelled', 'confirmed')
      and retry_request_id is not null and input_response_sha256 is not null and response_action is not null)
    or state in ('prepared', 'retry_received', 'expired')),
  check ((state in ('declined', 'cancelled') and completed_at is not null)
    or state not in ('declined', 'cancelled'))
);

create table consent_records (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid,
  stage_id uuid not null unique references action_stages(id) on delete restrict,
  input_required_attempt_id uuid not null unique references input_required_attempts(id) on delete restrict,
  actor_member_id uuid not null,
  acting_for_member_id uuid,
  action_code text not null,
  target_type text not null,
  target_id uuid,
  canonical_schema text not null check (canonical_schema = 'boardagent.consent-record.v1'),
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  package_sha256 bytea check (package_sha256 is null or boardagent_hash_is_sha256(package_sha256)),
  protected_code_record_sha256 bytea not null check (boardagent_hash_is_sha256(protected_code_record_sha256)),
  access_token_record_id uuid not null references access_token_records(id) on delete restrict,
  token_jti uuid not null,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  exact_origin text not null,
  staged_at timestamptz(6) not null,
  confirmed_at timestamptz(6) not null default transaction_timestamp(),
  record_sha256 bytea not null unique check (boardagent_hash_is_sha256(record_sha256)),
  unique (organization_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, acting_for_member_id) references members(organization_id, id) on delete restrict,
  check (confirmed_at >= staged_at)
);

create table idempotency_records (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  actor_member_id uuid not null,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  operation text not null check (operation ~ '^[a-z][a-z0-9_]{1,127}$'),
  idempotency_key text not null check (length(idempotency_key) between 16 and 256),
  request_sha256 bytea not null check (boardagent_hash_is_sha256(request_sha256)),
  state text not null check (state in ('in_progress', 'succeeded', 'failed', 'expired')),
  safe_response_type text check (safe_response_type is null or safe_response_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  safe_response_id uuid,
  safe_response_sha256 bytea check (safe_response_sha256 is null or boardagent_hash_is_sha256(safe_response_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  completed_at timestamptz(6),
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  unique (actor_member_id, client_id, operation, idempotency_key),
  check (expires_at > created_at),
  check (num_nonnulls(safe_response_type, safe_response_id, safe_response_sha256) in (0, 3)),
  check ((state in ('succeeded', 'failed') and completed_at is not null) or state in ('in_progress', 'expired'))
);

create table wizard_drafts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  draft_type text not null check (draft_type in ('meeting', 'vote', 'minutes', 'task', 'proposal')),
  creator_member_id uuid not null,
  current_step integer not null default 0 check (current_step >= 0),
  signed_context bytea not null check (octet_length(signed_context) between 32 and 1048576),
  context_sha256 bytea not null check (boardagent_hash_is_sha256(context_sha256)),
  state text not null default 'active'
    check (state in ('active', 'ready_to_confirm', 'posted', 'expired', 'cancelled')),
  ruleset_id uuid references rulesets(id) on delete restrict,
  package_sha256 bytea check (package_sha256 is null or boardagent_hash_is_sha256(package_sha256)),
  row_version bigint not null default 1 check (row_version > 0),
  expires_at timestamptz(6) not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  posted_at timestamptz(6),
  unique (organization_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, creator_member_id) references members(organization_id, id) on delete restrict,
  check (expires_at > created_at),
  check ((state = 'posted' and posted_at is not null) or state <> 'posted')
);

alter table input_required_attempts
  add constraint input_required_attempts_wizard_fk
  foreign key (wizard_draft_id) references wizard_drafts(id) on delete restrict;

create table wizard_steps (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  draft_id uuid not null references wizard_drafts(id) on delete restrict,
  ordinal integer not null check (ordinal >= 0),
  question_code text not null check (question_code ~ '^[a-z][a-z0-9_]{1,127}$'),
  value_schema text not null check (value_schema ~ '^boardagent\.[a-z0-9_.-]+\.v[0-9]+$'),
  canonical_value bytea not null check (octet_length(canonical_value) between 1 and 1048576),
  value_sha256 bytea not null check (boardagent_hash_is_sha256(value_sha256)),
  recommended_rule_id uuid references ruleset_rules(id) on delete restrict,
  citation_snapshot jsonb not null check (jsonb_typeof(citation_snapshot) = 'array'),
  override_selected boolean not null default false,
  override_reason text,
  attempt integer not null check (attempt > 0),
  recorded_at timestamptz(6) not null default transaction_timestamp(),
  unique (draft_id, ordinal, attempt),
  check ((override_selected and override_reason is not null and length(override_reason) between 1 and 65536)
    or (not override_selected and override_reason is null))
);

create table rule_overrides (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  evaluation_id uuid not null references matter_evaluations(id) on delete restrict,
  wizard_draft_id uuid not null references wizard_drafts(id) on delete restrict,
  final_object_type text not null check (final_object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  final_object_id uuid not null,
  recommended_rule_id uuid references ruleset_rules(id) on delete restrict,
  selected_rule_id uuid not null references ruleset_rules(id) on delete restrict,
  reason text not null check (length(reason) between 1 and 65536),
  citation_snapshot jsonb not null check (jsonb_typeof(citation_snapshot) = 'array'),
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  audit_event_id uuid,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  unique (evaluation_id, wizard_draft_id, final_object_type, final_object_id)
);

alter table organization_role_assignments
  add constraint organization_role_assignments_consent_fk
  foreign key (consent_record_id) references consent_records(id) on delete restrict;
alter table membership_versions
  add constraint membership_versions_consent_fk
  foreign key (consent_record_id) references consent_records(id) on delete restrict;
alter table onboarding_attestations
  add constraint onboarding_attestations_consent_fk
  foreign key (consent_record_id) references consent_records(id) on delete restrict;
alter table document_circulations
  add constraint document_circulations_consent_fk
  foreign key (consent_record_id) references consent_records(id) on delete restrict;
alter table governance_profiles
  add constraint governance_profiles_activation_consent_fk
  foreign key (activation_consent_record_id) references consent_records(id) on delete restrict;
alter table rulesets
  add constraint rulesets_activation_consent_fk
  foreign key (activation_consent_record_id) references consent_records(id) on delete restrict;
