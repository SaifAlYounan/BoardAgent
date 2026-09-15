-- BoardAgent Phase 1 / group 18: close vote-replacement source and feed lineage.

alter table vote_supersessions
  drop constraint vote_supersessions_changed_component_classes_check;
alter table vote_supersessions
  add constraint vote_supersessions_changed_component_classes_check
  check (cardinality(changed_component_classes) between 1 and 10);

-- Until consent-bound matter-evaluation/override evidence is implemented, a
-- replacement must preserve the exact governance tuple.  Same-board and
-- same-close-mode alone are not constitutional authorization for another rule.
create or replace function boardagent_lock_vote_for_replacement(
  candidate_old_vote uuid,
  candidate_consent uuid,
  candidate_payload_sha256 bytea,
  candidate_new_package_sha256 bytea,
  candidate_approval_rule uuid,
  candidate_governance_profile uuid,
  candidate_ruleset uuid,
  candidate_close_mode text
)
returns table(
  organization_id uuid,
  board_id uuid,
  vote_state text,
  vote_row_version bigint,
  old_package_payload bytea,
  old_package_sha256 bytea,
  approval_rule_sha256 bytea,
  governance_profile_version integer,
  governance_profile_sha256 bytea,
  ruleset_version integer,
  ruleset_sha256 bytea,
  actor_ready boolean,
  binding_valid boolean,
  consent_valid boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_payload_sha256 is null
     or octet_length(candidate_payload_sha256) <> 32
     or candidate_new_package_sha256 is null
     or octet_length(candidate_new_package_sha256) <> 32 then
    raise exception 'replacement confirmation hash is invalid' using errcode = '22023';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.state,
           vote.row_version,
           package.canonical_payload,
           package.package_sha256,
           rule.canonical_sha256,
           profile.version,
           profile.canonical_sha256,
           ruleset.version,
           ruleset.canonical_sha256,
           boardagent_vote_actor_ready(vote.board_id),
           (
             board.state = 'active'
             and board.current_governance_profile_id = profile.id
             and board.current_ruleset_id = ruleset.id
             and profile.state = 'active'
             and profile.organization_id = vote.organization_id
             and profile.board_id = vote.board_id
             and ruleset.state = 'active'
             and ruleset.organization_id = vote.organization_id
             and ruleset.board_id = vote.board_id
             and ruleset.profile_id = profile.id
             and rule.organization_id = vote.organization_id
             and rule.board_id = vote.board_id
             and rule.close_mode = candidate_close_mode
             and candidate_approval_rule = vote.approval_rule_id
             and candidate_governance_profile = vote.governance_profile_id
             and candidate_ruleset = vote.ruleset_id
             and candidate_close_mode = vote.close_mode
           ),
           exists (
             select 1
               from consent_records as consent
               join action_stages as stage on stage.id = consent.stage_id
               join input_required_attempts as attempt
                 on attempt.id = consent.input_required_attempt_id
              where consent.id = candidate_consent
                and consent.organization_id = vote.organization_id
                and consent.board_id = vote.board_id
                and consent.actor_member_id = boardagent_context_uuid('boardagent.member_id')
                and consent.client_id = boardagent_context_uuid('boardagent.client_id')
                and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
                and consent.action_code = 'replace_open_vote'
                and consent.target_type = 'vote'
                and consent.target_id = vote.id
                and consent.payload_sha256 = candidate_payload_sha256
                and consent.package_sha256 = candidate_new_package_sha256
                and stage.organization_id = consent.organization_id
                and stage.board_id = consent.board_id
                and stage.actor_member_id = consent.actor_member_id
                and stage.client_id = consent.client_id
                and stage.token_jti = consent.token_jti
                and stage.action_code = consent.action_code
                and stage.target_type = consent.target_type
                and stage.target_id = consent.target_id
                and stage.payload_sha256 = consent.payload_sha256
                and stage.package_sha256 = consent.package_sha256
                and stage.state = 'confirmed'
                and stage.confirmed_at is not null
                and attempt.organization_id = consent.organization_id
                and attempt.stage_id = stage.id
                and attempt.original_method = 'tools/call'
                and attempt.original_name = 'replace_open_vote'
                and attempt.response_action = 'accept'
                and attempt.state = 'confirmed'
           )
      from votes as vote
      join decision_packages as package
        on package.id = vote.current_decision_package_id
       and package.vote_id = vote.id
      join boards as board on board.id = vote.board_id
      join approval_rules as rule on rule.id = candidate_approval_rule
      join governance_profiles as profile on profile.id = candidate_governance_profile
      join rulesets as ruleset on ruleset.id = candidate_ruleset
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(vote.board_id)
     for update of vote
     for share of package, board, rule, profile, ruleset;
end
$$;

drop policy boardagent_server_question_links_insert on question_decision_links;
create policy boardagent_server_question_links_insert on question_decision_links
  for insert to boardagent_server
  with check (
    question_decision_links.organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(question_decision_links.board_id)
    and question_decision_links.selected_by = boardagent_context_uuid('boardagent.member_id')
    and boardagent_vote_actor_ready(question_decision_links.board_id)
    and exists (
      select 1
        from decision_packages as package
        join votes as vote on vote.id = package.vote_id
        join consent_records as consent
          on consent.id = question_decision_links.consent_record_id
       where package.id = question_decision_links.decision_package_id
         and package.organization_id = question_decision_links.organization_id
         and package.board_id = question_decision_links.board_id
         and package.version = question_decision_links.decision_package_version
         and package.package_sha256 = question_decision_links.decision_package_sha256
         and consent.organization_id = question_decision_links.organization_id
         and consent.board_id = question_decision_links.board_id
         and consent.actor_member_id = question_decision_links.selected_by
         and consent.client_id = boardagent_context_uuid('boardagent.client_id')
         and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
         and consent.target_type = 'vote'
         and consent.package_sha256 = package.package_sha256
         and (
           (consent.action_code = 'create_vote' and consent.target_id = vote.id)
           or (
             consent.action_code = 'replace_open_vote'
             and exists (
               select 1
                 from vote_supersessions as supersession
                where supersession.old_vote_id = consent.target_id
                  and supersession.new_vote_id = vote.id
                  and supersession.consent_record_id = consent.id
                  and supersession.new_package_sha256 = package.package_sha256
             )
           )
         )
    )
  );

create table vote_source_update_causes (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  vote_id uuid not null references votes(id) on delete restrict,
  source_class text not null
    check (source_class in ('management_submission', 'document', 'question_cutoff')),
  source_id uuid not null,
  source_version integer not null check (source_version > 0),
  source_sha256 bytea not null check (boardagent_hash_is_sha256(source_sha256)),
  trigger_audit_event_id uuid not null
    references audit_events(id) on delete restrict deferrable initially deferred,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id)
    on delete restrict,
  unique (vote_id, source_class, source_id, source_version, source_sha256)
);

create table vote_source_update_dispositions (
  id uuid primary key check (boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  cause_id uuid not null unique references vote_source_update_causes(id) on delete restrict,
  source_vote_id uuid not null references votes(id) on delete restrict,
  replacement_vote_id uuid references votes(id) on delete restrict,
  effect text not null check (effect in ('incorporated', 'excluded')),
  consent_record_id uuid not null references consent_records(id) on delete restrict,
  reason text not null check (length(reason) between 1 and 65536),
  audit_event_id uuid not null
    references audit_events(id) on delete restrict deferrable initially deferred,
  created_at timestamptz(6) not null default transaction_timestamp(),
  foreign key (organization_id, board_id) references boards(organization_id, id)
    on delete restrict,
  check (
    (effect = 'incorporated' and replacement_vote_id is not null)
    or (effect = 'excluded' and replacement_vote_id is null)
  )
);

create index vote_source_update_causes_pending_idx
  on vote_source_update_causes(vote_id, source_class, source_id, source_version, id);
create index vote_source_update_dispositions_replacement_idx
  on vote_source_update_dispositions(replacement_vote_id, cause_id)
  where replacement_vote_id is not null;

grant select, insert on vote_source_update_causes, vote_source_update_dispositions
  to boardagent_server;
grant select on vote_source_update_causes, vote_source_update_dispositions
  to boardagent_backup;
grant select, update on vote_source_update_causes to boardagent_migrator;
grant select on vote_source_update_dispositions to boardagent_migrator;

alter table vote_source_update_causes enable row level security;
alter table vote_source_update_causes force row level security;
alter table vote_source_update_dispositions enable row level security;
alter table vote_source_update_dispositions force row level security;

create policy boardagent_backup_read on vote_source_update_causes
  for select to boardagent_backup using (true);
create policy boardagent_backup_read on vote_source_update_dispositions
  for select to boardagent_backup using (true);
create policy boardagent_server_scope on vote_source_update_causes
  for all to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  )
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  );
create policy boardagent_server_scope on vote_source_update_dispositions
  for all to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  )
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  );
create policy boardagent_migrator_vote_source_cause_lock on vote_source_update_causes
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_vote_source_cause_read on vote_source_update_causes
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_vote_source_disposition_read
  on vote_source_update_dispositions
  for select to boardagent_migrator using (true);

create trigger boardagent_immutable
  before update or delete on vote_source_update_causes
  for each row execute function boardagent_reject_evidence_mutation();
create trigger boardagent_immutable
  before update or delete on vote_source_update_dispositions
  for each row execute function boardagent_reject_evidence_mutation();
revoke update, delete on vote_source_update_causes, vote_source_update_dispositions
  from boardagent_server, boardagent_worker;

create function boardagent_lock_vote_source_causes(candidate_vote uuid)
returns table(
  cause_id uuid,
  source_class text,
  source_id uuid,
  source_version integer,
  source_sha256 bytea
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote source-cause lock requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select cause.id,
           cause.source_class,
           cause.source_id,
           cause.source_version,
           cause.source_sha256
      from vote_source_update_causes as cause
      join votes as vote on vote.id = cause.vote_id
     where cause.vote_id = candidate_vote
       and cause.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(cause.board_id)
       and vote.organization_id = cause.organization_id
       and vote.board_id = cause.board_id
       and not exists (
         select 1
           from vote_source_update_dispositions as disposition
          where disposition.cause_id = cause.id
       )
     order by cause.id
     for update of cause;
end
$$;
alter function boardagent_lock_vote_source_causes(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_vote_source_causes(uuid) from public;
grant execute on function boardagent_lock_vote_source_causes(uuid) to boardagent_server;
