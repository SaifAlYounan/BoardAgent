-- Guided vote creation: read-only current electorate/recipient snapshots plus the
-- durable, non-secret identifiers needed to resume one exact MRTR confirmation.

grant insert on wizard_drafts, wizard_steps to boardagent_server;
grant update(state, row_version, posted_at) on wizard_drafts to boardagent_server;

create function boardagent_lock_vote_creation_electorate(candidate_board uuid)
returns table(
  member_id uuid,
  membership_version_id uuid,
  is_chair boolean,
  voting_weight bigint,
  authority_snapshot jsonb,
  authority_snapshot_sha256 bytea
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board) then
    raise exception 'vote creation electorate requires the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           version.id,
           membership.is_chair,
           membership.voting_weight,
           version.authority_snapshot,
           version.snapshot_sha256
      from boards as board
      join board_memberships as membership
        on membership.organization_id = board.organization_id
       and membership.board_id = board.id
      join lateral (
        select candidate.id,
               candidate.seat_role,
               candidate.is_chair,
               candidate.voting_weight,
               candidate.authority_snapshot,
               candidate.snapshot_sha256
          from membership_versions as candidate
         where candidate.membership_id = membership.id
         order by candidate.version desc, candidate.id desc
         limit 1
      ) as version on true
     where board.id = candidate_board
       and board.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and board.state = 'active'
       and boardagent_vote_actor_ready(board.id)
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role = 'voting_member'
       and version.seat_role = membership.seat_role
       and version.is_chair = membership.is_chair
       and version.voting_weight = membership.voting_weight
     order by membership.member_id
     for update of membership
     for share of version;
end
$$;
alter function boardagent_lock_vote_creation_electorate(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_creation_electorate(uuid) from public;
grant execute on function boardagent_lock_vote_creation_electorate(uuid) to boardagent_server;

create function boardagent_lock_vote_creation_recipients(candidate_board uuid)
returns table(member_id uuid, seat_role text, entitlement_generation bigint)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board) then
    raise exception 'vote creation recipients require the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.seat_role,
           membership.entitlement_generation
      from boards as board
      join board_memberships as membership
        on membership.organization_id = board.organization_id
       and membership.board_id = board.id
      join members as recipient
        on recipient.organization_id = membership.organization_id
       and recipient.id = membership.member_id
     where board.id = candidate_board
       and board.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and board.state = 'active'
       and boardagent_vote_actor_ready(board.id)
       and recipient.state = 'active'
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and exists (
         select 1
           from onboarding_attestations as attestation
          where attestation.organization_id = membership.organization_id
            and attestation.member_id = membership.member_id
            and attestation.board_id = membership.board_id
            and attestation.terms_version_id = (
              select terms.id
                from onboarding_terms_versions as terms
               where terms.organization_id = membership.organization_id
                 and terms.seat_role = membership.seat_role
                 and terms.effective_at <= transaction_timestamp()
               order by terms.effective_at desc, terms.version desc, terms.id desc
               limit 1
            )
            and attestation.support_version_id = (
              select support.id
                from secretary_support_versions as support
               where support.organization_id = membership.organization_id
                 and (support.board_id = membership.board_id or support.board_id is null)
                 and support.effective_at <= transaction_timestamp()
               order by (support.board_id = membership.board_id) desc,
                        support.effective_at desc,
                        support.version desc,
                        support.id desc
               limit 1
            )
       )
     order by membership.member_id
     for update of membership
     for share of recipient;
end
$$;
alter function boardagent_lock_vote_creation_recipients(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_creation_recipients(uuid) from public;
grant execute on function boardagent_lock_vote_creation_recipients(uuid) to boardagent_server;

create table vote_creation_stage_material (
  stage_id uuid primary key references action_stages(id) on delete restrict,
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null check (boardagent_is_uuid_v7(vote_id)),
  wizard_draft_id uuid not null unique references wizard_drafts(id) on delete restrict,
  wizard_step_id uuid not null unique check (boardagent_is_uuid_v7(wizard_step_id)),
  resolution_version_id uuid not null unique check (boardagent_is_uuid_v7(resolution_version_id)),
  decision_package_id uuid not null unique check (boardagent_is_uuid_v7(decision_package_id)),
  consent_record_id uuid not null unique check (boardagent_is_uuid_v7(consent_record_id)),
  vote_opened_audit_event_id uuid not null unique
    check (boardagent_is_uuid_v7(vote_opened_audit_event_id)),
  idempotency_record_id uuid not null unique check (boardagent_is_uuid_v7(idempotency_record_id)),
  rule_override_id uuid unique check (boardagent_is_uuid_v7(rule_override_id)),
  rule_override_audit_event_id uuid unique
    check (boardagent_is_uuid_v7(rule_override_audit_event_id)),
  rule_override_idempotency_record_id uuid unique
    check (boardagent_is_uuid_v7(rule_override_idempotency_record_id)),
  decision_package_component_ids uuid[] not null
    check (cardinality(decision_package_component_ids) between 7 and 10007),
  question_decision_link_ids uuid[] not null
    check (cardinality(question_decision_link_ids) between 0 and 10000),
  electorate_entry_ids uuid[] not null
    check (cardinality(electorate_entry_ids) between 1 and 1000),
  delivery_member_ids uuid[] not null
    check (cardinality(delivery_member_ids) between 1 and 1000),
  delivery_notice_ids uuid[] not null,
  delivery_feed_ids uuid[] not null,
  delivery_audit_event_ids uuid[] not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, stage_id)
    references action_stages(organization_id, id) on delete restrict,
  foreign key (organization_id, board_id)
    references boards(organization_id, id) on delete restrict,
  foreign key (organization_id, wizard_draft_id)
    references wizard_drafts(organization_id, id) on delete restrict,
  check (cardinality(delivery_notice_ids) = cardinality(delivery_member_ids)),
  check (cardinality(delivery_feed_ids) = cardinality(delivery_member_ids)),
  check (cardinality(delivery_audit_event_ids) = cardinality(delivery_member_ids)),
  check (
    (rule_override_id is null
      and rule_override_audit_event_id is null
      and rule_override_idempotency_record_id is null)
    or
    (rule_override_id is not null
      and rule_override_audit_event_id is not null
      and rule_override_idempotency_record_id is not null)
  )
);

create index vote_creation_stage_material_vote_idx
  on vote_creation_stage_material(vote_id, stage_id);

alter table vote_creation_stage_material enable row level security;
alter table vote_creation_stage_material force row level security;

grant select, insert on vote_creation_stage_material to boardagent_server;
grant select on vote_creation_stage_material to boardagent_backup;

create policy boardagent_server_vote_creation_stage_material_select
  on vote_creation_stage_material for select to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1
        from action_stages as stage
       where stage.id = vote_creation_stage_material.stage_id
         and stage.organization_id = vote_creation_stage_material.organization_id
         and stage.board_id = vote_creation_stage_material.board_id
         and stage.actor_member_id = boardagent_context_uuid('boardagent.member_id')
         and stage.client_id = boardagent_context_uuid('boardagent.client_id')
         and stage.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and stage.action_code = 'create_vote'
         and stage.target_type = 'vote'
         and stage.target_id = vote_creation_stage_material.vote_id
    )
  );

create policy boardagent_server_vote_creation_stage_material_insert
  on vote_creation_stage_material for insert to boardagent_server
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (
      select 1
        from action_stages as stage
       where stage.id = vote_creation_stage_material.stage_id
         and stage.organization_id = vote_creation_stage_material.organization_id
         and stage.board_id = vote_creation_stage_material.board_id
         and stage.actor_member_id = boardagent_context_uuid('boardagent.member_id')
         and stage.client_id = boardagent_context_uuid('boardagent.client_id')
         and stage.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and stage.action_code = 'create_vote'
         and stage.target_type = 'vote'
         and stage.target_id = vote_creation_stage_material.vote_id
         and stage.state = 'active'
    )
  );

create policy boardagent_backup_vote_creation_stage_material_select
  on vote_creation_stage_material for select to boardagent_backup using (true);

create trigger boardagent_immutable
  before update or delete on vote_creation_stage_material
  for each row execute function boardagent_reject_evidence_mutation();

revoke update, delete, truncate, references, trigger on vote_creation_stage_material
  from boardagent_server, boardagent_backup;
