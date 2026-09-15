-- BoardAgent Phase 1 / group 24: fail closed from the bootstrap-wide runtime grants.
-- Later phases may add only the exact table/column/function authority introduced by
-- their verified transaction boundary; this migration is the Phase-1 baseline.

revoke insert, update on all tables in schema public
  from boardagent_server, boardagent_worker;

-- Table-level REVOKE does not remove older column-level grants. Clear every inherited
-- runtime UPDATE grant before rebuilding the exact projection allowlist below; otherwise
-- migrations 0013/0014/0016 leave effective write paths that are invisible in
-- information_schema.role_table_grants.
do $runtime_column_revoke$
declare
  granted_column record;
begin
  for granted_column in
    select grantee, table_schema, table_name, column_name
      from information_schema.column_privileges
     where table_schema = 'public'
       and grantee in ('boardagent_server', 'boardagent_worker')
       and privilege_type = 'UPDATE'
  loop
    execute format(
      'revoke update (%I) on %I.%I from %I',
      granted_column.column_name,
      granted_column.table_schema,
      granted_column.table_name,
      granted_column.grantee
    );
  end loop;
end
$runtime_column_revoke$;

grant insert on
  action_stages,
  audit_events,
  ballot_dispositions,
  ballots,
  consent_records,
  decision_package_components,
  decision_packages,
  document_search,
  document_validation_attempts,
  document_versions,
  documents,
  feed_tombstones,
  idempotency_records,
  input_required_attempts,
  management_question_answers,
  management_question_turns,
  management_questions,
  matter_evaluations,
  notices,
  pending_action_feed,
  proxy_grants,
  proxy_revocations,
  question_decision_links,
  question_visibility,
  resolution_versions,
  rule_overrides,
  vote_electorate,
  vote_exclusions,
  vote_source_update_causes,
  vote_source_update_dispositions,
  vote_supersessions,
  votes
to boardagent_server;

-- UPDATE is column-scoped to the projections advanced by implemented repositories.
-- Binding inputs, identities, payloads, expiry and immutable evidence are never writable
-- through the raw request role.
grant update(state, confirmed_at, rejected_at, cancelled_at)
  on action_stages to boardagent_server;
grant update(current_version_id, canonical_text_sha256, search_text, indexed_at)
  on document_search to boardagent_server;
grant update(current_version_id, row_version)
  on documents to boardagent_server;
grant update(state, safe_response_type, safe_response_id, safe_response_sha256, completed_at)
  on idempotency_records to boardagent_server;
grant update(
  retry_request_id,
  input_response_sha256,
  response_action,
  retry_received_at,
  completed_at,
  state
) on input_required_attempts to boardagent_server;
grant update(state, resolved_at)
  on pending_action_feed to boardagent_server;
grant update(
  state,
  row_version,
  current_resolution_version_id,
  current_decision_package_id,
  electorate_sha256,
  close_mode,
  deadline_at,
  matter_evaluation_id,
  selected_ruleset_rule_id,
  rule_override_id,
  rule_override_sha256,
  opened_at
) on votes to boardagent_server;

create function boardagent_guard_action_stage_binding()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if tg_op = 'INSERT' then
    if new.state <> 'active'
       or new.created_at is distinct from transaction_timestamp()
       or new.expires_at is distinct from new.created_at + interval '10 minutes'
       or num_nonnulls(new.confirmed_at,new.rejected_at,new.cancelled_at) <> 0 then
      raise exception 'action stage insert must use the database clock and exact ten-minute lifetime'
        using errcode = '23514';
    end if;
    return new;
  end if;

  if row(
       new.id,new.organization_id,new.board_id,new.actor_member_id,new.acting_for_member_id,
       new.action_code,new.target_type,new.target_id,new.canonical_schema,
       new.canonicalization_version,new.canonical_payload,new.payload_sha256,
       new.package_sha256,new.nonce_sha256,new.protected_code_sha256,new.client_id,
       new.access_token_record_id,new.token_jti,new.exact_origin,new.context_sha256,
       new.replaces_stage_id,new.expires_at,new.created_at
     ) is distinct from row(
       old.id,old.organization_id,old.board_id,old.actor_member_id,old.acting_for_member_id,
       old.action_code,old.target_type,old.target_id,old.canonical_schema,
       old.canonicalization_version,old.canonical_payload,old.payload_sha256,
       old.package_sha256,old.nonce_sha256,old.protected_code_sha256,old.client_id,
       old.access_token_record_id,old.token_jti,old.exact_origin,old.context_sha256,
       old.replaces_stage_id,old.expires_at,old.created_at
     ) then
    raise exception 'action stage binding fields are immutable' using errcode = '55000';
  end if;
  if old.state <> 'active' or new.state = old.state then
    raise exception 'action stage update requires one terminal transition from active'
      using errcode = '55000';
  end if;
  if new.state = 'confirmed' then
    if new.confirmed_at is distinct from transaction_timestamp()
       or new.rejected_at is not null or new.cancelled_at is not null then
      raise exception 'confirmed action stage requires the exact transaction timestamp'
        using errcode = '23514';
    end if;
  elsif new.state = 'rejected' then
    if new.rejected_at is distinct from transaction_timestamp()
       or new.confirmed_at is not null or new.cancelled_at is not null then
      raise exception 'rejected action stage requires the exact transaction timestamp'
        using errcode = '23514';
    end if;
  elsif new.state = 'cancelled' then
    if new.cancelled_at is distinct from transaction_timestamp()
       or new.confirmed_at is not null or new.rejected_at is not null then
      raise exception 'cancelled action stage requires the exact transaction timestamp'
        using errcode = '23514';
    end if;
  elsif new.state in ('replaced','expired') then
    if num_nonnulls(new.confirmed_at,new.rejected_at,new.cancelled_at) <> 0 then
      raise exception 'replaced or expired action stage cannot carry a terminal act timestamp'
        using errcode = '23514';
    end if;
  else
    raise exception 'unsupported action stage terminal transition' using errcode = '23514';
  end if;
  return new;
end
$$;
revoke all on function boardagent_guard_action_stage_binding() from public;
create trigger boardagent_action_stage_binding_guard
before insert or update on action_stages
for each row execute function boardagent_guard_action_stage_binding();

create function boardagent_lock_board_members(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_member_ids uuid[]
)
returns table(
  member_id uuid,
  entitlement_generation bigint,
  seat_role text,
  is_secretary boolean,
  voting_weight bigint,
  member_state text,
  membership_state text,
  active_now boolean,
  has_management_role boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_organization_id
          is distinct from boardagent_context_uuid('boardagent.organization_id')
     or not boardagent_context_board_allowed(candidate_board_id) then
    raise exception 'membership lock requires the managed request board context'
      using errcode = '25000';
  end if;
  if candidate_member_ids is null
     or cardinality(candidate_member_ids) not between 1 and 1000
     or exists (select 1 from unnest(candidate_member_ids) as requested(id) where id is null)
     or (select count(distinct id) from unnest(candidate_member_ids) as requested(id))
          <> cardinality(candidate_member_ids) then
    raise exception 'membership lock requires one through 1000 distinct member IDs'
      using errcode = '22023';
  end if;
  return query
    select membership.member_id,
           membership.entitlement_generation,
           membership.seat_role,
           membership.is_secretary,
           membership.voting_weight,
           member.state,
           membership.state,
           member.state='active'
             and membership.state='active'
             and membership.active_from<=transaction_timestamp()
             and (membership.active_until is null
                  or membership.active_until>transaction_timestamp()),
           exists (
             select 1 from organization_role_assignments as role_assignment
              where role_assignment.organization_id=membership.organization_id
                and role_assignment.member_id=membership.member_id
                and role_assignment.role='management'
                and role_assignment.active_from<=transaction_timestamp()
                and (role_assignment.active_until is null
                     or role_assignment.active_until>transaction_timestamp())
           )
      from board_memberships as membership
      join members as member
        on member.organization_id=membership.organization_id
       and member.id=membership.member_id
     where membership.organization_id=candidate_organization_id
       and membership.board_id=candidate_board_id
       and membership.member_id=any(candidate_member_ids)
     order by membership.member_id
       for update of membership,member;
end
$$;
alter function boardagent_lock_board_members(uuid,uuid,uuid[])
  owner to boardagent_migrator;
revoke all on function boardagent_lock_board_members(uuid,uuid,uuid[]) from public;
grant execute on function boardagent_lock_board_members(uuid,uuid,uuid[])
  to boardagent_server;

create function boardagent_lock_board_root(candidate_board_id uuid)
returns table(
  organization_id uuid,
  state text,
  current_governance_profile_id uuid,
  current_ruleset_id uuid,
  actor_ready boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board_id) then
    raise exception 'board root lock requires the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select board.organization_id,
           board.state,
           board.current_governance_profile_id,
           board.current_ruleset_id,
           boardagent_vote_actor_ready(board.id)
      from boards as board
     where board.id=candidate_board_id
       and board.organization_id=boardagent_context_uuid('boardagent.organization_id')
     for update of board;
end
$$;
alter function boardagent_lock_board_root(uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_board_root(uuid) from public;
grant execute on function boardagent_lock_board_root(uuid)
  to boardagent_server;

create policy boardagent_migrator_wizard_lock
  on wizard_drafts for update to boardagent_migrator
  using (true) with check (true);

create function boardagent_lock_wizard_draft(
  candidate_wizard_id uuid,
  candidate_board_id uuid
)
returns table(
  creator_member_id uuid,
  draft_type text,
  state text,
  ruleset_id uuid,
  package_sha256 bytea,
  unexpired boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board_id) then
    raise exception 'wizard lock requires the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select wizard.creator_member_id,
           wizard.draft_type,
           wizard.state,
           wizard.ruleset_id,
           wizard.package_sha256,
           wizard.expires_at>transaction_timestamp()
      from wizard_drafts as wizard
     where wizard.id=candidate_wizard_id
       and wizard.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and wizard.board_id=candidate_board_id
     for update of wizard;
end
$$;
alter function boardagent_lock_wizard_draft(uuid,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_wizard_draft(uuid,uuid) from public;
grant execute on function boardagent_lock_wizard_draft(uuid,uuid)
  to boardagent_server;

-- The current worker mutates product state only through SECURITY DEFINER functions.
-- Audit append remains a direct, trigger-serialized insert so worker attribution is
-- retained in the same caller-owned transaction.
grant insert on audit_events to boardagent_worker;
