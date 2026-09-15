-- Durable preparation material and an exact secretary-only snapshot for the
-- confirmed open-vote replacement MCP surface.

create function boardagent_lock_vote_replacement_surface(candidate_vote uuid)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_state text,
  vote_row_version bigint,
  vote_title text,
  resolution_version_id uuid,
  resolution_version integer,
  resolution_text text,
  resolution_sha256 bytea,
  package_payload bytea,
  package_sha256 bytea,
  actor_ready boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement preparation requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.state,
           vote.row_version,
           vote.title,
           resolution.id,
           resolution.version,
           resolution.canonical_text,
           resolution.canonical_sha256,
           package.canonical_payload,
           package.package_sha256,
           boardagent_vote_actor_ready(vote.board_id)
      from votes as vote
      join resolution_versions as resolution
        on resolution.id = vote.current_resolution_version_id
       and resolution.vote_id = vote.id
      join decision_packages as package
        on package.id = vote.current_decision_package_id
       and package.vote_id = vote.id
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(vote.board_id)
     for update of vote
     for share of resolution, package;
end
$$;
alter function boardagent_lock_vote_replacement_surface(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_replacement_surface(uuid) from public;
grant execute on function boardagent_lock_vote_replacement_surface(uuid) to boardagent_server;

create table vote_replacement_stage_material (
  stage_id uuid primary key references action_stages(id) on delete restrict,
  organization_id uuid not null,
  board_id uuid not null,
  old_vote_id uuid not null references votes(id) on delete restrict,
  new_vote_id uuid not null check (boardagent_is_uuid_v7(new_vote_id)),
  consent_record_id uuid not null unique check (boardagent_is_uuid_v7(consent_record_id)),
  canonical_material bytea not null,
  material_sha256 bytea not null check (boardagent_hash_is_sha256(material_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, stage_id)
    references action_stages(organization_id, id) on delete restrict,
  foreign key (organization_id, board_id)
    references boards(organization_id, id) on delete restrict,
  foreign key (board_id, old_vote_id)
    references votes(board_id, id) on delete restrict,
  check (old_vote_id <> new_vote_id),
  check (octet_length(canonical_material) between 2 and 1048576)
);

create index vote_replacement_stage_material_vote_idx
  on vote_replacement_stage_material(old_vote_id, new_vote_id, stage_id);

alter table vote_replacement_stage_material enable row level security;
alter table vote_replacement_stage_material force row level security;

grant select, insert on vote_replacement_stage_material to boardagent_server;
grant select on vote_replacement_stage_material to boardagent_backup;

create policy boardagent_server_vote_replacement_stage_material_select
  on vote_replacement_stage_material for select to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1
        from action_stages as stage
       where stage.id = vote_replacement_stage_material.stage_id
         and stage.organization_id = vote_replacement_stage_material.organization_id
         and stage.board_id = vote_replacement_stage_material.board_id
         and stage.actor_member_id = boardagent_context_uuid('boardagent.member_id')
         and stage.client_id = boardagent_context_uuid('boardagent.client_id')
         and stage.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and stage.action_code in ('replace_open_vote', 'amend_resolution_text', 'extend_vote_deadline')
         and stage.target_type = 'vote'
         and stage.target_id = vote_replacement_stage_material.old_vote_id
    )
  );

create policy boardagent_server_vote_replacement_stage_material_insert
  on vote_replacement_stage_material for insert to boardagent_server
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1
        from action_stages as stage
       where stage.id = vote_replacement_stage_material.stage_id
         and stage.organization_id = vote_replacement_stage_material.organization_id
         and stage.board_id = vote_replacement_stage_material.board_id
         and stage.actor_member_id = boardagent_context_uuid('boardagent.member_id')
         and stage.client_id = boardagent_context_uuid('boardagent.client_id')
         and stage.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and stage.action_code in ('replace_open_vote', 'amend_resolution_text', 'extend_vote_deadline')
         and stage.target_type = 'vote'
         and stage.target_id = vote_replacement_stage_material.old_vote_id
         and stage.state = 'active'
    )
  );

create policy boardagent_backup_vote_replacement_stage_material_select
  on vote_replacement_stage_material for select to boardagent_backup using (true);

create trigger boardagent_immutable
  before update or delete on vote_replacement_stage_material
  for each row execute function boardagent_reject_evidence_mutation();

revoke update, delete, truncate, references, trigger on vote_replacement_stage_material
  from boardagent_server, boardagent_backup;
