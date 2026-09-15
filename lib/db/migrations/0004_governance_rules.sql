-- BoardAgent Phase 1 / group 4: governance profiles, exact rules, and persisted evaluation.

create table approval_rules (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  schema_version text not null check (schema_version = 'boardagent.approval-rule.v1'),
  threshold_numerator bigint not null check (threshold_numerator >= 0),
  threshold_denominator bigint not null check (threshold_denominator > 0),
  quorum_numerator bigint not null check (quorum_numerator >= 0),
  quorum_denominator bigint not null check (quorum_denominator > 0),
  approval_denominator text not null check (approval_denominator in ('eligible', 'participating', 'yes_no')),
  abstentions_count_for_quorum boolean not null,
  tie_behavior text not null check (tie_behavior in ('reject', 'chair_casting_vote')),
  proxy_policy text not null check (proxy_policy in ('principal_supersedes_proxy', 'first_ballot_final')),
  close_mode text not null check (close_mode in ('automatic', 'secretariat_confirmed')),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (board_id, id),
  unique (board_id, canonical_sha256),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check (threshold_numerator <= threshold_denominator),
  check (quorum_numerator <= quorum_denominator)
);

create table governance_profiles (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  version integer not null check (version > 0),
  state text not null check (state in ('draft', 'active', 'superseded')),
  schema_version text not null check (schema_version = 'boardagent.governance-profile.v1'),
  canonical_payload jsonb not null check (jsonb_typeof(canonical_payload) = 'object'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  source_agreement_references jsonb not null check (jsonb_typeof(source_agreement_references) = 'array'),
  activation_consent_record_id uuid,
  supersedes_id uuid,
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  activated_at timestamptz(6),
  unique (board_id, version),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  foreign key (supersedes_id) references governance_profiles(id) on delete restrict,
  check ((state = 'active' and activation_consent_record_id is not null and activated_at is not null)
    or state <> 'active')
);
create unique index governance_profiles_one_active_uq on governance_profiles(board_id)
  where state = 'active';

create table governance_seat_rules (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  profile_id uuid not null references governance_profiles(id) on delete restrict,
  seat_class text not null check (seat_class in ('voting_member', 'management', 'observer')),
  minimum_weight bigint not null check (minimum_weight >= 0),
  maximum_weight bigint not null check (maximum_weight between 0 and 1000000000),
  eligibility_constraints jsonb not null check (jsonb_typeof(eligibility_constraints) = 'object'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  unique (profile_id, seat_class),
  check (minimum_weight <= maximum_weight),
  check ((seat_class = 'voting_member' and minimum_weight > 0)
    or (seat_class <> 'voting_member' and minimum_weight = 0 and maximum_weight = 0))
);

create table governance_rule_templates (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  profile_id uuid not null references governance_profiles(id) on delete restrict,
  code text not null check (code ~ '^[a-z][a-z0-9_]{0,127}$'),
  approval_rule_id uuid not null references approval_rules(id) on delete restrict,
  exact_rule_payload jsonb not null check (jsonb_typeof(exact_rule_payload) = 'object'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  unique (profile_id, code),
  unique (profile_id, canonical_sha256)
);

create table governance_citations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  profile_id uuid not null references governance_profiles(id) on delete restrict,
  rule_template_id uuid references governance_rule_templates(id) on delete restrict,
  source_document_version_id uuid not null references document_versions(id) on delete restrict,
  source_document_sha256 bytea not null check (boardagent_hash_is_sha256(source_document_sha256)),
  clause text not null check (length(clause) between 1 and 512),
  locator text not null check (length(locator) between 1 and 1024),
  unique (profile_id, rule_template_id, source_document_version_id, clause, locator)
);

create table rulesets (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  profile_id uuid not null references governance_profiles(id) on delete restrict,
  version integer not null check (version > 0),
  state text not null check (state in ('draft', 'active', 'superseded')),
  schema_version text not null check (schema_version = 'boardagent.ruleset.v1'),
  canonical_payload jsonb not null check (jsonb_typeof(canonical_payload) = 'object'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  activation_consent_record_id uuid,
  supersedes_id uuid,
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  activated_at timestamptz(6),
  unique (board_id, version),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  foreign key (supersedes_id) references rulesets(id) on delete restrict,
  check ((state = 'active' and activation_consent_record_id is not null and activated_at is not null)
    or state <> 'active')
);
create unique index rulesets_one_active_uq on rulesets(board_id) where state = 'active';

alter table boards
  add constraint boards_current_profile_fk foreign key (id, current_governance_profile_id)
    references governance_profiles(board_id, id) deferrable initially deferred,
  add constraint boards_current_ruleset_fk foreign key (id, current_ruleset_id)
    references rulesets(board_id, id) deferrable initially deferred;

create table matter_types (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  ruleset_id uuid not null references rulesets(id) on delete restrict,
  code text not null check (code ~ '^[a-z][a-z0-9_]{0,127}$'),
  name text not null check (length(name) between 1 and 512),
  strict_fact_schema jsonb not null check (jsonb_typeof(strict_fact_schema) = 'object'),
  schema_sha256 bytea not null check (boardagent_hash_is_sha256(schema_sha256)),
  unique (ruleset_id, code)
);

create table ruleset_rules (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  ruleset_id uuid not null references rulesets(id) on delete restrict,
  matter_type_id uuid not null references matter_types(id) on delete restrict,
  priority integer not null check (priority between 0 and 1000000),
  specificity integer not null check (specificity between 0 and 1000000),
  condition_tree jsonb not null check (jsonb_typeof(condition_tree) = 'object'),
  approval_rule_id uuid not null references approval_rules(id) on delete restrict,
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  unique (ruleset_id, id)
);
create index ruleset_rules_evaluation_idx
  on ruleset_rules(ruleset_id, matter_type_id, priority desc, specificity desc, id);

create table rule_citations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  rule_id uuid not null references ruleset_rules(id) on delete restrict,
  source_document_version_id uuid not null references document_versions(id) on delete restrict,
  source_document_sha256 bytea not null check (boardagent_hash_is_sha256(source_document_sha256)),
  clause text not null check (length(clause) between 1 and 512),
  locator text not null check (length(locator) between 1 and 1024),
  unique (rule_id, source_document_version_id, clause, locator)
);

create table matter_evaluations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  requester_member_id uuid not null,
  profile_id uuid not null references governance_profiles(id) on delete restrict,
  ruleset_id uuid not null references rulesets(id) on delete restrict,
  matter_type_id uuid not null references matter_types(id) on delete restrict,
  engine_version text not null check (engine_version = 'boardagent.rules-engine.v1'),
  canonical_facts jsonb not null check (jsonb_typeof(canonical_facts) = 'object'),
  facts_sha256 bytea not null check (boardagent_hash_is_sha256(facts_sha256)),
  result text not null check (result in ('matched', 'ambiguous', 'missing', 'no_match')),
  matched_rule_id uuid references ruleset_rules(id) on delete restrict,
  candidate_rule_ids uuid[] not null default '{}',
  citation_snapshot jsonb not null check (jsonb_typeof(citation_snapshot) = 'array'),
  result_sha256 bytea not null check (boardagent_hash_is_sha256(result_sha256)),
  evaluated_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, requester_member_id) references members(organization_id, id) on delete restrict,
  check ((result = 'matched' and matched_rule_id is not null and cardinality(candidate_rule_ids) = 1)
    or (result <> 'matched' and matched_rule_id is null))
);
