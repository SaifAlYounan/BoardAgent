-- BoardAgent Phase 1 / group 2: people, authority, onboarding, OAuth, and credentials.

create table accountable_principals (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  legal_name text not null check (length(legal_name) between 1 and 512),
  reference text check (reference is null or length(reference) between 1 and 1024),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, id)
);

create table members (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  member_kind text not null check (member_kind in ('human', 'ai_system')),
  legal_name text not null check (length(legal_name) between 1 and 512),
  display_name text not null check (length(display_name) between 1 and 512),
  state text not null default 'invited'
    check (state in ('invited', 'enrollment_pending', 'pending_activation', 'active', 'suspended', 'removed')),
  accountable_principal_id uuid,
  identity_generation bigint not null default 1 check (identity_generation > 0),
  onboarding_generation bigint not null default 1 check (onboarding_generation > 0),
  row_version bigint not null default 1 check (row_version > 0),
  hidden_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, id),
  foreign key (organization_id, accountable_principal_id)
    references accountable_principals(organization_id, id) on delete restrict,
  check ((member_kind = 'ai_system' and accountable_principal_id is not null)
    or (member_kind = 'human' and accountable_principal_id is null))
);

alter table board_versions
  add constraint board_versions_created_by_fk
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict;

create table organization_role_assignments (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  role text not null check (role in ('admin', 'secretariat', 'management')),
  active_from timestamptz(6) not null default transaction_timestamp(),
  active_until timestamptz(6),
  change_reason text not null check (length(change_reason) between 1 and 65536),
  consent_record_id uuid,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (active_until is null or active_until > active_from)
);
create unique index organization_roles_one_active_uq
  on organization_role_assignments(organization_id, member_id, role)
  where active_until is null;

create table board_memberships (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  member_id uuid not null,
  seat_role text not null check (seat_role in ('voting_member', 'management', 'observer')),
  is_secretary boolean not null default false,
  voting_weight bigint not null default 0,
  state text not null default 'active' check (state in ('active', 'suspended', 'ended')),
  entitlement_generation bigint not null default 1 check (entitlement_generation > 0),
  active_from timestamptz(6) not null default transaction_timestamp(),
  active_until timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, board_id, member_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (active_until is null or active_until > active_from),
  check ((seat_role = 'voting_member' and voting_weight between 1 and 1000000000)
    or (seat_role <> 'voting_member' and voting_weight = 0)),
  check (seat_role <> 'observer' or not is_secretary)
);
create unique index board_memberships_one_active_uq
  on board_memberships(board_id, member_id)
  where active_until is null and state = 'active';
create index board_memberships_member_active_idx
  on board_memberships(member_id, board_id, entitlement_generation)
  where active_until is null and state = 'active';

create table membership_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  member_id uuid not null,
  membership_id uuid not null,
  version integer not null check (version > 0),
  seat_role text not null check (seat_role in ('voting_member', 'management', 'observer')),
  is_secretary boolean not null,
  voting_weight bigint not null,
  authority_snapshot jsonb not null check (jsonb_typeof(authority_snapshot) = 'object'),
  snapshot_sha256 bytea not null check (boardagent_hash_is_sha256(snapshot_sha256)),
  change_reason text not null check (length(change_reason) between 1 and 65536),
  actor_member_id uuid not null,
  consent_record_id uuid,
  audit_event_id uuid,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (membership_id, version),
  foreign key (organization_id, board_id, member_id, membership_id)
    references board_memberships(organization_id, board_id, member_id, id) on delete restrict,
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  check ((seat_role = 'voting_member' and voting_weight between 1 and 1000000000)
    or (seat_role <> 'voting_member' and voting_weight = 0)),
  check (seat_role <> 'observer' or not is_secretary)
);

create table external_identity_links (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  issuer text not null check (issuer ~ '^https://[^?#]+$'),
  subject text not null check (length(subject) between 1 and 1024),
  state text not null check (state in ('pending', 'active', 'revoked')),
  invitation_id uuid,
  confirmed_by uuid,
  confirmed_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (issuer, subject),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, confirmed_by) references members(organization_id, id) on delete restrict,
  check ((state = 'active' and confirmed_by is not null and confirmed_at is not null)
    or state <> 'active')
);

create table secretary_support_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  board_id uuid,
  version integer not null check (version > 0),
  support_name text not null check (length(support_name) between 1 and 512),
  contact_methods jsonb not null check (jsonb_typeof(contact_methods) = 'array'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  effective_at timestamptz(6) not null,
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  unique (organization_id, board_id, version)
);

create table onboarding_terms_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  seat_role text not null check (seat_role in ('voting_member', 'management', 'observer')),
  version integer not null check (version > 0),
  schema_version text not null check (schema_version = 'boardagent.onboarding-terms.v1'),
  canonical_text text not null check (length(canonical_text) between 1 and 1048576),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  material_change boolean not null,
  effective_at timestamptz(6) not null,
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  unique (organization_id, seat_role, version)
);

create table onboarding_attestations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  board_id uuid not null,
  terms_version_id uuid not null references onboarding_terms_versions(id) on delete restrict,
  support_version_id uuid not null references secretary_support_versions(id) on delete restrict,
  presentation_choice text not null check (length(presentation_choice) between 1 and 2048),
  local_memory_choice text not null check (length(local_memory_choice) between 1 and 2048),
  consent_record_id uuid not null,
  attested_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  unique (member_id, board_id, terms_version_id)
);

create table member_contact_points (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  kind text not null check (kind in ('verified_number', 'in_person_reference', 'operator_reference')),
  protected_value bytea not null check (octet_length(protected_value) between 16 and 4096),
  key_id uuid not null references crypto_key_registry(id) on delete restrict,
  verified_at timestamptz(6) not null,
  state text not null check (state in ('active', 'revoked')),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict
);

create table oauth_clients (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  protocol_id_kind text not null check (protocol_id_kind in ('verified_cimd_url', 'dcr_opaque', 'preregistered')),
  protocol_id_value text not null check (length(protocol_id_value) between 1 and 2048),
  safe_metadata jsonb not null check (jsonb_typeof(safe_metadata) = 'object'),
  metadata_sha256 bytea not null check (boardagent_hash_is_sha256(metadata_sha256)),
  state text not null check (state in ('active', 'suspended', 'revoked')),
  registered_by uuid,
  registered_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, id),
  unique (protocol_id_kind, protocol_id_value),
  foreign key (organization_id, registered_by) references members(organization_id, id) on delete restrict
);

create table oauth_client_redirect_uris (
  client_id uuid not null references oauth_clients(id) on delete restrict,
  redirect_uri text not null check (length(redirect_uri) between 1 and 2048),
  redirect_uri_sha256 bytea not null check (boardagent_hash_is_sha256(redirect_uri_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  primary key (client_id, redirect_uri_sha256)
);

create table oauth_client_grants (
  client_id uuid not null references oauth_clients(id) on delete restrict,
  grant_type text not null check (grant_type in ('authorization_code', 'refresh_token')),
  scope text not null check (scope ~ '^[a-z][a-z0-9:_-]{0,127}$'),
  created_at timestamptz(6) not null default transaction_timestamp(),
  primary key (client_id, grant_type, scope)
);

create table auth_sessions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  opaque_session_sha256 bytea not null unique check (boardagent_hash_is_sha256(opaque_session_sha256)),
  member_id uuid,
  client_id uuid references oauth_clients(id) on delete restrict,
  state text not null check (state in ('anonymous', 'authenticated', 'revoked', 'expired')),
  exact_origin text not null check (exact_origin ~ '^https://[^/?#]+$'),
  created_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  last_authenticated_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (expires_at > created_at)
);

create table oauth_authorization_requests (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  resource_uri text not null,
  redirect_uri text not null,
  scope_set text[] not null check (cardinality(scope_set) between 1 and 128),
  member_id uuid,
  session_id uuid not null references auth_sessions(id) on delete restrict,
  state_hash bytea not null check (boardagent_hash_is_sha256(state_hash)),
  request_state text not null check (request_state in ('pending', 'approved', 'denied', 'consumed', 'expired')),
  expires_at timestamptz(6) not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (resource_uri ~ '^https://[^?#]+/mcp$'),
  check (expires_at > created_at)
);

create table oauth_authorization_codes (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  code_sha256 bytea not null unique check (boardagent_hash_is_sha256(code_sha256)),
  authorization_request_id uuid not null unique references oauth_authorization_requests(id) on delete cascade,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  member_id uuid not null,
  redirect_uri text not null,
  resource_uri text not null,
  scope_set text[] not null,
  pkce_s256_challenge text not null check (pkce_s256_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  issued_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  consumed_at timestamptz(6),
  revoked_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (expires_at <= issued_at + interval '60 seconds'),
  check (num_nonnulls(consumed_at, revoked_at) <= 1)
);

create table oauth_consents (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  resource_uri text not null,
  scope_set text[] not null,
  granted_at timestamptz(6) not null default transaction_timestamp(),
  revoked_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict
);
create unique index oauth_consents_active_uq
  on oauth_consents(member_id, client_id, resource_uri, scope_set)
  where revoked_at is null;

create table refresh_families (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  resource_uri text not null,
  generation bigint not null default 0 check (generation >= 0),
  state text not null check (state in ('active', 'revoked', 'compromised', 'expired')),
  issued_at timestamptz(6) not null default transaction_timestamp(),
  last_used_at timestamptz(6) not null default transaction_timestamp(),
  idle_expires_at timestamptz(6) not null,
  absolute_expires_at timestamptz(6) not null,
  revoked_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (idle_expires_at <= last_used_at + interval '30 days'),
  check (absolute_expires_at <= issued_at + interval '90 days')
);

create table refresh_tokens (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  family_id uuid not null references refresh_families(id) on delete cascade,
  generation bigint not null check (generation > 0),
  token_sha256 bytea not null unique check (boardagent_hash_is_sha256(token_sha256)),
  issued_at timestamptz(6) not null default transaction_timestamp(),
  used_at timestamptz(6),
  replaced_by_id uuid,
  revoked_at timestamptz(6),
  unique (family_id, generation),
  foreign key (replaced_by_id) references refresh_tokens(id) deferrable initially deferred,
  check (num_nonnulls(used_at, revoked_at) <= 1)
);
create unique index refresh_tokens_one_active_uq on refresh_tokens(family_id)
  where used_at is null and revoked_at is null;

create table access_token_records (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  jti uuid not null unique check (boardagent_is_uuid_v7(jti)),
  member_id uuid not null,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  resource_uri text not null,
  scope_set text[] not null,
  session_id uuid references auth_sessions(id) on delete restrict,
  refresh_family_id uuid references refresh_families(id) on delete restrict,
  signing_key_id uuid not null references crypto_key_registry(id) on delete restrict,
  issued_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  revoked_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (expires_at <= issued_at + interval '15 minutes')
);

create table webauthn_credentials (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  credential_id bytea not null unique check (octet_length(credential_id) between 16 and 1024),
  public_key bytea not null check (octet_length(public_key) between 32 and 4096),
  signature_counter bigint not null default 0 check (signature_counter >= 0),
  transports text[] not null default '{}',
  backup_eligible boolean not null,
  backup_state boolean not null,
  state text not null check (state in ('active', 'suspect', 'revoked')),
  created_at timestamptz(6) not null default transaction_timestamp(),
  last_used_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict
);

create table webauthn_challenges (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  challenge_sha256 bytea not null unique check (boardagent_hash_is_sha256(challenge_sha256)),
  session_id uuid references auth_sessions(id) on delete cascade,
  member_id uuid,
  purpose text not null check (purpose in ('enrollment', 'authentication', 'recent_auth', 'recovery')),
  rp_id text not null check (length(rp_id) between 1 and 253),
  exact_origin text not null,
  issued_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  consumed_at timestamptz(6),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  check (expires_at > issued_at)
);

create table totp_credentials (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  encrypted_secret bytea not null check (octet_length(encrypted_secret) between 32 and 4096),
  key_id uuid not null references crypto_key_registry(id) on delete restrict,
  state text not null check (state in ('active', 'locked', 'revoked')),
  failed_attempts integer not null default 0 check (failed_attempts between 0 and 1000),
  locked_until timestamptz(6),
  last_accepted_step bigint,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict
);

create table enrollment_invitations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  token_sha256 bytea not null unique check (boardagent_hash_is_sha256(token_sha256)),
  issued_by uuid not null,
  handoff_method text not null check (length(handoff_method) between 1 and 512),
  issued_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  consumed_at timestamptz(6),
  revoked_at timestamptz(6),
  pending_activation_member_id uuid,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, issued_by) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, pending_activation_member_id) references members(organization_id, id) on delete restrict,
  check (expires_at <= issued_at + interval '24 hours'),
  check (num_nonnulls(consumed_at, revoked_at) <= 1)
);

alter table external_identity_links
  add constraint external_identity_invitation_fk
  foreign key (invitation_id) references enrollment_invitations(id) on delete restrict;

create table enrollment_activation_challenges (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  invitation_id uuid not null references enrollment_invitations(id) on delete restrict,
  protected_code bytea not null check (octet_length(protected_code) between 32 and 4096),
  proofing_method text not null check (length(proofing_method) between 1 and 1024),
  attempt_count integer not null default 0 check (attempt_count between 0 and 20),
  state text not null check (state in ('issued', 'consumed', 'expired', 'revoked')),
  issued_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  consumed_at timestamptz(6),
  confirmed_by uuid,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, confirmed_by) references members(organization_id, id) on delete restrict,
  check (expires_at <= issued_at + interval '10 minutes')
);

create table oidc_login_transactions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  exact_issuer text not null check (exact_issuer ~ '^https://[^?#]+$'),
  state_sha256 bytea not null unique check (boardagent_hash_is_sha256(state_sha256)),
  nonce_sha256 bytea not null unique check (boardagent_hash_is_sha256(nonce_sha256)),
  session_id uuid not null references auth_sessions(id) on delete cascade,
  client_id uuid not null references oauth_clients(id) on delete restrict,
  resource_uri text not null,
  issued_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  consumed_at timestamptz(6),
  check (expires_at > issued_at)
);

create table rate_limit_buckets (
  bucket_class text not null check (bucket_class in ('ip', 'client', 'member', 'token', 'registration')),
  subject_sha256 bytea not null check (boardagent_hash_is_sha256(subject_sha256)),
  window_started_at timestamptz(6) not null,
  window_seconds integer not null check (window_seconds between 1 and 86400),
  request_count integer not null check (request_count >= 0),
  blocked_until timestamptz(6),
  primary key (bucket_class, subject_sha256, window_started_at)
);

create index access_tokens_active_jti_idx on access_token_records(jti, expires_at)
  where revoked_at is null;
create index auth_sessions_member_active_idx on auth_sessions(member_id, expires_at)
  where state = 'authenticated';
create index enrollment_invitations_member_idx on enrollment_invitations(member_id, expires_at)
  where consumed_at is null and revoked_at is null;
