-- Durable, non-secret material needed to resume a confirmed MCP vote close after
-- the recoverable database -> Ed25519 signer boundary.

create table vote_close_stage_material (
  stage_id uuid primary key references action_stages(id) on delete restrict,
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null,
  outcome_id uuid not null unique check (boardagent_is_uuid_v7(outcome_id)),
  certificate_id uuid not null unique check (boardagent_is_uuid_v7(certificate_id)),
  certificate_public_id bytea not null unique check (octet_length(certificate_public_id) = 32),
  certificate_public_id_sha256 bytea not null unique
    check (boardagent_hash_is_sha256(certificate_public_id_sha256)),
  signing_key_id uuid not null references crypto_key_registry(id) on delete restrict,
  close_consent_record_id uuid not null unique check (boardagent_is_uuid_v7(close_consent_record_id)),
  closing_audit_event_id uuid not null unique check (boardagent_is_uuid_v7(closing_audit_event_id)),
  expected_tally_sha256 bytea not null check (boardagent_hash_is_sha256(expected_tally_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, stage_id)
    references action_stages(organization_id, id) on delete restrict,
  foreign key (board_id, vote_id) references votes(board_id, id) on delete restrict,
  check (outcome_id <> certificate_id),
  check (close_consent_record_id <> closing_audit_event_id)
);

create index vote_close_stage_material_vote_idx
  on vote_close_stage_material(vote_id, stage_id);

alter table vote_close_stage_material enable row level security;
alter table vote_close_stage_material force row level security;

grant select, insert on vote_close_stage_material to boardagent_server;
grant select on vote_close_stage_material to boardagent_worker, boardagent_backup;

create policy boardagent_server_vote_close_stage_material_select
  on vote_close_stage_material for select to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1
        from action_stages as stage
       where stage.id = vote_close_stage_material.stage_id
         and stage.organization_id = vote_close_stage_material.organization_id
         and stage.board_id = vote_close_stage_material.board_id
         and stage.actor_member_id = boardagent_context_uuid('boardagent.member_id')
         and stage.client_id = boardagent_context_uuid('boardagent.client_id')
         and stage.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and stage.action_code = 'close_vote'
         and stage.target_type = 'vote'
         and stage.target_id = vote_close_stage_material.vote_id
    )
  );

create policy boardagent_server_vote_close_stage_material_insert
  on vote_close_stage_material for insert to boardagent_server
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1
        from action_stages as stage
       where stage.id = vote_close_stage_material.stage_id
         and stage.organization_id = vote_close_stage_material.organization_id
         and stage.board_id = vote_close_stage_material.board_id
         and stage.actor_member_id = boardagent_context_uuid('boardagent.member_id')
         and stage.client_id = boardagent_context_uuid('boardagent.client_id')
         and stage.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and stage.action_code = 'close_vote'
         and stage.target_type = 'vote'
         and stage.target_id = vote_close_stage_material.vote_id
         and stage.state = 'active'
    )
  );

create policy boardagent_worker_vote_close_stage_material_select
  on vote_close_stage_material for select to boardagent_worker
  using (current_setting('boardagent.transaction_scope', true) = 'worker');

create policy boardagent_backup_vote_close_stage_material_select
  on vote_close_stage_material for select to boardagent_backup using (true);

create trigger boardagent_immutable
  before update or delete on vote_close_stage_material
  for each row execute function boardagent_reject_evidence_mutation();

revoke update, delete, truncate, references, trigger on vote_close_stage_material
  from boardagent_server, boardagent_worker, boardagent_backup;
