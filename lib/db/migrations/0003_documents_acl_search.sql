-- BoardAgent Phase 1 / group 3: canonical documents, deny-wins ACL, search, and retention.

create table documents (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  title text not null check (length(title) between 1 and 512),
  state text not null default 'active' check (state in ('active', 'archived', 'soft_deleted')),
  current_version_id uuid,
  created_by uuid not null,
  row_version bigint not null default 1 check (row_version > 0),
  hidden_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict
);

create table document_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  document_id uuid not null,
  version integer not null check (version > 0),
  media_type text not null check (media_type in (
    'text/markdown; charset=utf-8',
    'text/plain; charset=utf-8',
    'application/json'
  )),
  document_schema text,
  canonicalization_version text not null check (canonicalization_version = 'RFC8785+NFC-LF-v1'),
  canonical_bytes bytea not null check (octet_length(canonical_bytes) between 1 and 10485760),
  byte_length integer not null check (byte_length between 1 and 10485760),
  sha256 bytea not null check (boardagent_hash_is_sha256(sha256)),
  canonical_metadata jsonb not null check (jsonb_typeof(canonical_metadata) = 'object'),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (document_id, version),
  unique (document_id, id),
  foreign key (board_id, document_id) references documents(board_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  check (byte_length = octet_length(canonical_bytes)),
  check ((media_type = 'application/json' and document_schema is not null)
    or (media_type <> 'application/json' and document_schema is null))
);

alter table documents
  add constraint documents_current_version_fk
  foreign key (id, current_version_id) references document_versions(document_id, id)
  deferrable initially deferred;

create table document_validation_attempts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid,
  actor_member_id uuid not null,
  offered_media_type text not null check (length(offered_media_type) between 1 and 255),
  offered_name text check (offered_name is null or length(offered_name) between 1 and 1024),
  offered_length bigint check (offered_length is null or offered_length >= 0),
  offered_sha256 bytea check (offered_sha256 is null or boardagent_hash_is_sha256(offered_sha256)),
  result text not null check (result in ('accepted', 'rejected')),
  result_code text not null check (result_code ~ '^[a-z][a-z0-9_]{1,63}$'),
  remediation text not null check (length(remediation) between 1 and 2048),
  accepted_document_version_id uuid references document_versions(id) on delete restrict,
  attempted_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  check ((result = 'accepted' and accepted_document_version_id is not null)
    or (result = 'rejected' and accepted_document_version_id is null))
);

create table document_search (
  document_id uuid primary key references documents(id) on delete restrict,
  board_id uuid not null,
  current_version_id uuid not null references document_versions(id) on delete restrict,
  canonical_text_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_text_sha256)),
  search_text text not null,
  search_vector tsvector generated always as (to_tsvector('simple', search_text)) stored,
  indexed_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (board_id, document_id) references documents(board_id, id) on delete restrict
);
create index document_search_vector_idx on document_search using gin(search_vector);

create table document_access_grants (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  document_id uuid not null,
  grantee_member_id uuid,
  grantee_seat_role text check (grantee_seat_role in ('voting_member', 'management', 'observer')),
  permission text not null check (permission in ('read', 'contribute', 'circulate')),
  active_from timestamptz(6) not null default transaction_timestamp(),
  active_until timestamptz(6),
  granted_by uuid not null,
  foreign key (board_id, document_id) references documents(board_id, id) on delete restrict,
  foreign key (organization_id, grantee_member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, granted_by) references members(organization_id, id) on delete restrict,
  check (num_nonnulls(grantee_member_id, grantee_seat_role) = 1),
  check (active_until is null or active_until > active_from)
);
create unique index document_access_grants_active_member_uq
  on document_access_grants(document_id, grantee_member_id, permission)
  where grantee_member_id is not null and active_until is null;
create unique index document_access_grants_active_role_uq
  on document_access_grants(document_id, grantee_seat_role, permission)
  where grantee_seat_role is not null and active_until is null;

create table document_exclusions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  document_id uuid not null,
  member_id uuid not null,
  version integer not null check (version > 0),
  reason text not null check (length(reason) between 1 and 65536),
  active_from timestamptz(6) not null default transaction_timestamp(),
  active_until timestamptz(6),
  created_by uuid not null,
  foreign key (board_id, document_id) references documents(board_id, id) on delete restrict,
  foreign key (organization_id, member_id) references members(organization_id, id) on delete restrict,
  foreign key (organization_id, created_by) references members(organization_id, id) on delete restrict,
  unique (document_id, member_id, version),
  check (active_until is null or active_until > active_from)
);
create unique index document_exclusions_one_active_uq
  on document_exclusions(document_id, member_id)
  where active_until is null;

create table document_circulations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  document_id uuid not null,
  document_version_id uuid not null,
  document_sha256 bytea not null check (boardagent_hash_is_sha256(document_sha256)),
  recipient_policy jsonb not null check (jsonb_typeof(recipient_policy) = 'object'),
  package_sha256 bytea not null check (boardagent_hash_is_sha256(package_sha256)),
  consent_record_id uuid not null,
  circulated_by uuid not null,
  circulated_at timestamptz(6) not null default transaction_timestamp(),
  state text not null check (state in ('committed', 'superseded')),
  foreign key (board_id, document_id) references documents(board_id, id) on delete restrict,
  foreign key (document_id, document_version_id) references document_versions(document_id, id) on delete restrict,
  foreign key (organization_id, circulated_by) references members(organization_id, id) on delete restrict
);

create table circulation_recipients (
  circulation_id uuid not null references document_circulations(id) on delete restrict,
  member_id uuid not null references members(id) on delete restrict,
  document_version_id uuid not null references document_versions(id) on delete restrict,
  entitlement_snapshot_sha256 bytea not null check (boardagent_hash_is_sha256(entitlement_snapshot_sha256)),
  notice_id uuid,
  feed_sequence bigint,
  created_at timestamptz(6) not null default transaction_timestamp(),
  primary key (circulation_id, member_id),
  unique (member_id, document_version_id, circulation_id)
);

create table retention_snapshots (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  board_id uuid,
  object_type text not null check (object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  object_id uuid not null,
  object_version bigint not null check (object_version > 0),
  canonical_schema text not null check (length(canonical_schema) between 1 and 128),
  canonical_payload bytea not null,
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  content_references jsonb not null check (jsonb_typeof(content_references) = 'array'),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  unique (object_type, object_id, object_version)
);

create table deletion_tombstones (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  board_id uuid,
  object_type text not null check (object_type ~ '^[a-z][a-z0-9_]{1,63}$'),
  object_id uuid not null,
  snapshot_id uuid not null references retention_snapshots(id) on delete restrict,
  actor_member_id uuid not null,
  reason text not null check (length(reason) between 1 and 65536),
  hidden_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, actor_member_id) references members(organization_id, id) on delete restrict,
  unique (object_type, object_id)
);

create index documents_board_state_idx on documents(board_id, state, id);
create index document_versions_document_idx on document_versions(document_id, version desc);
create index document_exclusions_member_idx on document_exclusions(member_id, document_id)
  where active_until is null;
