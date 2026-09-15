-- BoardAgent Phase 1 / group 9: frozen decision packages, votes, proxies, and certificates.

create table votes (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  title text not null check (length(title) between 1 and 512),
  state text not null default 'draft'
    check (state in ('draft', 'open', 'source_update_pending', 'closing', 'closed', 'superseded', 'cancelled')),
  current_resolution_version_id uuid,
  current_decision_package_id uuid,
  approval_rule_id uuid not null references approval_rules(id) on delete restrict,
  governance_profile_id uuid not null references governance_profiles(id) on delete restrict,
  ruleset_id uuid not null references rulesets(id) on delete restrict,
  electorate_sha256 bytea check (electorate_sha256 is null or boardagent_hash_is_sha256(electorate_sha256)),
  close_mode text not null check (close_mode in ('automatic', 'secretariat_confirmed')),
  deadline_at timestamptz(6),
  row_version bigint not null default 1 check (row_version > 0),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  opened_at timestamptz(6),
  closed_at timestamptz(6),
  cancelled_at timestamptz(6),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check ((state in ('open', 'source_update_pending', 'closing', 'closed', 'superseded')
      and opened_at is not null and deadline_at is not null and electorate_sha256 is not null)
    or state in ('draft', 'cancelled')),
  check ((state = 'closed' and closed_at is not null and cancelled_at is null)
    or (state = 'cancelled' and cancelled_at is not null and closed_at is null)
    or state in ('draft', 'open', 'source_update_pending', 'closing', 'superseded')),
  check (deadline_at is null or deadline_at > created_at)
);

create table resolution_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null,
  version integer not null check (version > 0),
  canonical_schema text not null check (canonical_schema = 'boardagent.resolution.v1'),
  canonical_text text not null check (length(canonical_text) between 1 and 1048576),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  supersedes_id uuid references resolution_versions(id) on delete restrict,
  author_member_id uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (vote_id, version),
  unique (vote_id, id),
  foreign key (board_id, vote_id) references votes(board_id, id) on delete restrict,
  foreign key (organization_id, author_member_id) references members(organization_id, id) on delete restrict
);

alter table votes
  add constraint votes_current_resolution_fk
  foreign key (id, current_resolution_version_id) references resolution_versions(vote_id, id)
  deferrable initially deferred;

create table decision_packages (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null,
  version integer not null check (version > 0),
  schema_version text not null check (schema_version = 'boardagent.decision-package.v1'),
  resolution_version_id uuid not null,
  resolution_sha256 bytea not null check (boardagent_hash_is_sha256(resolution_sha256)),
  submission_manifest jsonb not null check (jsonb_typeof(submission_manifest) = 'array'),
  submission_manifest_sha256 bytea not null check (boardagent_hash_is_sha256(submission_manifest_sha256)),
  document_manifest jsonb not null check (jsonb_typeof(document_manifest) = 'array'),
  document_manifest_sha256 bytea not null check (boardagent_hash_is_sha256(document_manifest_sha256)),
  question_cutoff_manifest jsonb not null check (jsonb_typeof(question_cutoff_manifest) = 'array'),
  question_cutoff_sha256 bytea not null check (boardagent_hash_is_sha256(question_cutoff_sha256)),
  approval_rule_id uuid not null references approval_rules(id) on delete restrict,
  approval_rule_sha256 bytea not null check (boardagent_hash_is_sha256(approval_rule_sha256)),
  governance_profile_id uuid not null references governance_profiles(id) on delete restrict,
  governance_profile_sha256 bytea not null check (boardagent_hash_is_sha256(governance_profile_sha256)),
  ruleset_id uuid not null references rulesets(id) on delete restrict,
  ruleset_sha256 bytea not null check (boardagent_hash_is_sha256(ruleset_sha256)),
  electorate_sha256 bytea not null check (boardagent_hash_is_sha256(electorate_sha256)),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 10485760),
  package_sha256 bytea not null unique check (boardagent_hash_is_sha256(package_sha256)),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (vote_id, version),
  unique (vote_id, id),
  foreign key (vote_id, resolution_version_id) references resolution_versions(vote_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict
);

alter table votes
  add constraint votes_current_package_fk
  foreign key (id, current_decision_package_id) references decision_packages(vote_id, id)
  deferrable initially deferred;

alter table question_decision_links
  add constraint question_decision_links_package_fk
  foreign key (decision_package_id) references decision_packages(id) on delete restrict;

create table decision_package_components (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  decision_package_id uuid not null references decision_packages(id) on delete restrict,
  component_class text not null check (component_class in (
    'resolution', 'submission', 'document', 'question_cutoff', 'approval_rule',
    'governance_profile', 'ruleset', 'electorate'
  )),
  ordinal integer not null check (ordinal >= 0),
  object_type text not null check (object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  object_id uuid,
  object_version bigint check (object_version is null or object_version > 0),
  object_sha256 bytea not null check (boardagent_hash_is_sha256(object_sha256)),
  unique (decision_package_id, component_class, ordinal),
  unique (decision_package_id, id)
);

create table vote_electorate (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null,
  member_id uuid not null,
  membership_version_id uuid not null references membership_versions(id) on delete restrict,
  seat_role text not null check (seat_role = 'voting_member'),
  voting_weight bigint not null check (voting_weight between 1 and 1000000000),
  eligibility_snapshot jsonb not null check (jsonb_typeof(eligibility_snapshot) = 'object'),
  eligibility_sha256 bytea not null check (boardagent_hash_is_sha256(eligibility_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (board_id, vote_id) references votes(board_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  unique (vote_id, member_id),
  unique (vote_id, member_id, id)
);

create table vote_exclusions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null,
  member_id uuid not null,
  version integer not null check (version > 0),
  state text not null check (state in ('excluded', 'lifted')),
  reason text not null check (length(reason) between 1 and 65536),
  actor_member_id uuid not null,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  effective_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (board_id, vote_id) references votes(board_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  unique (vote_id, member_id, version)
);
create unique index vote_exclusions_one_live_uq
  on vote_exclusions(vote_id, member_id) where state = 'excluded';

create table proxy_grants (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null,
  principal_member_id uuid not null,
  holder_member_id uuid not null,
  policy text not null check (policy in ('principal_supersedes_proxy', 'first_ballot_final')),
  consent_record_id uuid not null unique references consent_records(id) on delete restrict,
  granted_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6),
  foreign key (vote_id, principal_member_id) references vote_electorate(vote_id, member_id) on delete restrict,
  foreign key (vote_id, holder_member_id) references vote_electorate(vote_id, member_id) on delete restrict,
  foreign key (organization_id, principal_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, holder_member_id) references members(organization_id, id) on delete restrict,
  unique (vote_id, principal_member_id),
  check (principal_member_id <> holder_member_id),
  check (expires_at is null or expires_at > granted_at)
);

create table proxy_revocations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  grant_id uuid not null unique references proxy_grants(id) on delete restrict,
  revoker_member_id uuid not null,
  reason text not null check (length(reason) between 1 and 65536),
  effect text not null check (effect in ('revoked', 'expired', 'superseded')),
  consent_record_id uuid references consent_records(id) on delete restrict,
  revoked_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, revoker_member_id) references members(organization_id, id) on delete restrict
);

create table ballots (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null,
  decision_package_id uuid not null,
  principal_member_id uuid not null,
  caster_member_id uuid not null,
  choice text not null check (choice in ('yes', 'no', 'abstain')),
  statement_sha256 bytea check (statement_sha256 is null or boardagent_hash_is_sha256(statement_sha256)),
  voting_weight bigint not null check (voting_weight between 1 and 1000000000),
  ballot_source text not null check (ballot_source in ('own', 'proxy')),
  proxy_grant_id uuid references proxy_grants(id) on delete restrict,
  consent_record_id uuid not null unique references consent_records(id) on delete restrict,
  cast_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (vote_id, decision_package_id) references decision_packages(vote_id, id) on delete restrict,
  foreign key (vote_id, principal_member_id) references vote_electorate(vote_id, member_id) on delete restrict,
  foreign key (organization_id, caster_member_id) references members(organization_id, id) on delete restrict,
  unique (vote_id, id),
  check ((ballot_source = 'own' and principal_member_id = caster_member_id and proxy_grant_id is null)
    or (ballot_source = 'proxy' and principal_member_id <> caster_member_id and proxy_grant_id is not null))
);

create table ballot_dispositions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  prior_ballot_id uuid not null unique references ballots(id) on delete restrict,
  superseding_ballot_id uuid references ballots(id) on delete restrict,
  replacement_vote_id uuid references votes(id) on delete restrict,
  reason text not null check (length(reason) between 1 and 65536),
  effect text not null check (effect in ('superseded', 'invalidated_by_recusal', 'invalidated_by_vote_replacement')),
  audit_event_id uuid,
  created_at timestamptz(6) not null default transaction_timestamp(),
  check (num_nonnulls(superseding_ballot_id, replacement_vote_id) <= 1),
  check (superseding_ballot_id is null or superseding_ballot_id <> prior_ballot_id)
);

create table vote_outcomes (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null unique,
  decision_package_id uuid not null,
  electorate_sha256 bytea not null check (boardagent_hash_is_sha256(electorate_sha256)),
  approval_rule_id uuid not null references approval_rules(id) on delete restrict,
  canonical_tally jsonb not null check (jsonb_typeof(canonical_tally) = 'object'),
  tally_sha256 bytea not null check (boardagent_hash_is_sha256(tally_sha256)),
  outcome text not null check (outcome in ('approved', 'rejected', 'quorum_not_met')),
  finalized_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (board_id, vote_id) references votes(board_id, id) on delete restrict,
  foreign key (vote_id, decision_package_id) references decision_packages(vote_id, id) on delete restrict
);

create table vote_certificates (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null unique references votes(id) on delete restrict,
  outcome_id uuid not null unique references vote_outcomes(id) on delete restrict,
  public_id bytea not null unique check (octet_length(public_id) = 32),
  schema_version text not null check (schema_version = 'boardagent.vote-certificate.v1'),
  canonical_payload bytea not null check (octet_length(canonical_payload) between 2 and 10485760),
  payload_sha256 bytea not null unique check (boardagent_hash_is_sha256(payload_sha256)),
  signature bytea not null check (octet_length(signature) = 64),
  signing_key_id uuid not null references crypto_key_registry(id) on delete restrict,
  state text not null default 'current' check (state in ('current', 'superseded', 'compromised')),
  supersedes_id uuid references vote_certificates(id) on delete restrict,
  issued_at timestamptz(6) not null default transaction_timestamp()
);

create table vote_supersessions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  old_vote_id uuid not null unique references votes(id) on delete restrict,
  new_vote_id uuid not null unique references votes(id) on delete restrict,
  changed_component_classes text[] not null check (cardinality(changed_component_classes) between 1 and 8),
  old_package_sha256 bytea not null check (boardagent_hash_is_sha256(old_package_sha256)),
  new_package_sha256 bytea not null check (boardagent_hash_is_sha256(new_package_sha256)),
  secretary_member_id uuid not null,
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  reason text not null check (length(reason) between 1 and 65536),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, secretary_member_id) references members(organization_id, id) on delete restrict,
  check (old_vote_id <> new_vote_id),
  check (old_package_sha256 <> new_package_sha256)
);

create index votes_board_state_deadline_idx on votes(board_id, state, deadline_at, id);
create index ballots_vote_principal_idx on ballots(vote_id, principal_member_id, cast_at, id);
create index vote_exclusions_live_member_idx on vote_exclusions(member_id, vote_id)
  where state = 'excluded';
