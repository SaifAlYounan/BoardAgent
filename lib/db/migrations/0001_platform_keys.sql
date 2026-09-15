-- BoardAgent Phase 1 / group 1: platform, immutable configuration, and public keys.
-- Hand-reviewed SQL is authoritative; Drizzle declarations are a typed query mirror.

create function boardagent_is_uuid_v7(value uuid)
returns boolean
language sql
immutable
strict
as $$
  select substring(value::text from 15 for 1) = '7'
     and substring(value::text from 20 for 1) in ('8', '9', 'a', 'b')
$$;

create function boardagent_hash_is_sha256(value bytea)
returns boolean
language sql
immutable
strict
as $$ select octet_length(value) = 32 $$;

create table organizations (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  legal_name text not null check (length(legal_name) between 1 and 512),
  display_name text not null check (length(display_name) between 1 and 512),
  slug text not null unique check (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$'),
  timezone text not null check (length(timezone) between 1 and 128),
  state text not null default 'active' check (state in ('active', 'archived')),
  created_at timestamptz(6) not null default transaction_timestamp()
);

create table system_instance (
  singleton_key boolean primary key default true check (singleton_key),
  instance_id uuid not null unique check (boardagent_is_uuid_v7(instance_id)),
  organization_id uuid not null unique references organizations(id) on delete restrict,
  canonical_resource_uri text not null unique,
  bootstrapped_at timestamptz(6) not null default transaction_timestamp(),
  constraint system_instance_resource_ck check (
    canonical_resource_uri = lower(canonical_resource_uri)
    and canonical_resource_uri ~ '^https://[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/mcp$'
    and canonical_resource_uri !~ '[?#]'
  )
);

create table boards (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  slug text not null check (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$'),
  name text not null check (length(name) between 1 and 512),
  timezone text not null check (length(timezone) between 1 and 128),
  state text not null default 'active' check (state in ('active', 'archived')),
  current_version_id uuid,
  current_governance_profile_id uuid,
  current_ruleset_id uuid,
  row_version bigint not null default 1 check (row_version > 0),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, slug),
  unique (organization_id, id)
);

create table board_versions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  version integer not null check (version > 0),
  canonical_schema text not null check (canonical_schema = 'boardagent.board.v1'),
  canonical_payload jsonb not null check (jsonb_typeof(canonical_payload) = 'object'),
  canonical_sha256 bytea not null check (boardagent_hash_is_sha256(canonical_sha256)),
  change_reason text not null check (length(change_reason) between 1 and 65536),
  created_by uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (board_id, version),
  unique (board_id, id),
  foreign key (organization_id, board_id) references boards(organization_id, id) on delete restrict
);

alter table boards
  add constraint boards_current_version_fk
  foreign key (id, current_version_id) references board_versions(board_id, id)
  deferrable initially deferred;

create table crypto_key_registry (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  kid text not null check (kid ~ '^[A-Za-z0-9._-]{1,128}$'),
  purpose text not null check (purpose in ('oauth_signing', 'evidence_signing', 'browser_session', 'data_kek')),
  algorithm text not null check (algorithm in ('EdDSA', 'ES256', 'A256GCM', 'HMAC-SHA256')),
  public_jwk jsonb,
  nonsecret_locator text not null check (length(nonsecret_locator) between 1 and 2048),
  activated_at timestamptz(6) not null,
  retired_at timestamptz(6),
  compromised_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, kid),
  check (retired_at is null or retired_at >= activated_at),
  check (compromised_at is null or compromised_at >= activated_at),
  check ((purpose in ('oauth_signing', 'evidence_signing') and public_jwk is not null)
    or (purpose not in ('oauth_signing', 'evidence_signing') and public_jwk is null))
);

create table config_receipts (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null references organizations(id) on delete restrict,
  effective_config_sha256 bytea not null check (boardagent_hash_is_sha256(effective_config_sha256)),
  app_build text not null check (length(app_build) between 1 and 256),
  schema_version integer not null check (schema_version > 0),
  protocol_version text not null check (length(protocol_version) between 1 and 64),
  started_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id, effective_config_sha256, started_at)
);

create index boards_organization_state_idx on boards(organization_id, state, id);
create index crypto_key_registry_active_idx
  on crypto_key_registry(organization_id, purpose, activated_at desc)
  where retired_at is null and compromised_at is null;
