-- BoardAgent Phase 1 / group 22: package-bound evaluation, selected rule and override evidence.

alter table rule_overrides
  add column canonical_sha256 bytea not null
    check (boardagent_hash_is_sha256(canonical_sha256));
alter table rule_overrides alter column audit_event_id set not null;

create trigger boardagent_immutable
  before update or delete on rule_overrides
  for each row execute function boardagent_reject_evidence_mutation();
revoke update, delete on rule_overrides from boardagent_server, boardagent_worker;

alter table votes
  add column matter_evaluation_id uuid references matter_evaluations(id) on delete restrict,
  add column selected_ruleset_rule_id uuid references ruleset_rules(id) on delete restrict,
  add column rule_override_id uuid references rule_overrides(id) on delete restrict,
  add column rule_override_sha256 bytea
    check (rule_override_sha256 is null or boardagent_hash_is_sha256(rule_override_sha256)),
  add constraint votes_rule_override_pair_check
    check (num_nonnulls(rule_override_id, rule_override_sha256) in (0, 2)),
  add constraint votes_open_rule_selection_check
    check (
      state in ('draft', 'cancelled')
      or (matter_evaluation_id is not null and selected_ruleset_rule_id is not null)
    );

alter table decision_packages
  add column matter_evaluation_id uuid not null
    references matter_evaluations(id) on delete restrict,
  add column matter_evaluation_result_sha256 bytea not null
    check (boardagent_hash_is_sha256(matter_evaluation_result_sha256)),
  add column selected_ruleset_rule_id uuid not null
    references ruleset_rules(id) on delete restrict,
  add column selected_ruleset_rule_sha256 bytea not null
    check (boardagent_hash_is_sha256(selected_ruleset_rule_sha256)),
  add column rule_override_id uuid references rule_overrides(id) on delete restrict,
  add column rule_override_sha256 bytea
    check (rule_override_sha256 is null or boardagent_hash_is_sha256(rule_override_sha256)),
  add constraint decision_packages_rule_override_pair_check
    check (num_nonnulls(rule_override_id, rule_override_sha256) in (0, 2));

alter table decision_package_components
  drop constraint decision_package_components_component_class_check;
alter table decision_package_components
  add constraint decision_package_components_component_class_check
  check (component_class in (
    'resolution', 'submission', 'document', 'question_cutoff', 'approval_rule',
    'governance_profile', 'ruleset', 'electorate', 'matter_evaluation', 'ruleset_rule'
  ));

create function boardagent_guard_vote_rule_selection()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if new.state not in ('draft', 'cancelled')
     and (new.matter_evaluation_id is null or new.selected_ruleset_rule_id is null) then
    raise exception 'opened vote requires exact matter evaluation and selected ruleset rule'
      using errcode = '23514';
  end if;
  if num_nonnulls(new.rule_override_id, new.rule_override_sha256) not in (0, 2) then
    raise exception 'vote rule override reference and hash must move together'
      using errcode = '23514';
  end if;
  if tg_op = 'UPDATE' and old.state <> 'draft' and (
    new.matter_evaluation_id is distinct from old.matter_evaluation_id
    or new.selected_ruleset_rule_id is distinct from old.selected_ruleset_rule_id
    or new.rule_override_id is distinct from old.rule_override_id
    or new.rule_override_sha256 is distinct from old.rule_override_sha256
  ) then
    raise exception 'opened vote rule-selection evidence is immutable'
      using errcode = '55000';
  end if;
  return new;
end
$$;
create trigger boardagent_vote_rule_selection_guard
  before insert or update on votes
  for each row execute function boardagent_guard_vote_rule_selection();

grant select on matter_evaluations, wizard_drafts, rule_overrides, audit_events
  to boardagent_migrator;
create policy boardagent_migrator_rule_selection_read on matter_evaluations
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_rule_selection_read on wizard_drafts
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_rule_selection_read on rule_overrides
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_rule_selection_read on audit_events
  for select to boardagent_migrator using (true);

create function boardagent_rule_selection_evidence(
  candidate_board uuid,
  candidate_profile uuid,
  candidate_ruleset uuid,
  candidate_approval_rule uuid,
  candidate_evaluation uuid,
  candidate_selected_rule uuid
)
returns table(
  organization_id uuid,
  board_id uuid,
  evaluation_id uuid,
  evaluation_result text,
  evaluation_result_details jsonb,
  evaluation_result_sha256 bytea,
  recommended_rule_id uuid,
  evaluation_candidate_rule_ids uuid[],
  selected_rule_id uuid,
  selected_rule_sha256 bytea,
  selected_approval_rule_id uuid,
  selected_approval_rule_sha256 bytea,
  selected_template_payload jsonb,
  selected_template_sha256 bytea,
  citation_snapshot jsonb,
  evidence_valid boolean
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'rule selection requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select evaluation.organization_id,
           evaluation.board_id,
           evaluation.id,
           evaluation.result,
           evaluation.result_details,
           evaluation.result_sha256,
           evaluation.matched_rule_id,
           evaluation.candidate_rule_ids,
           selected_rule.id,
           selected_rule.canonical_sha256,
           selected_rule.approval_rule_id,
           approval.canonical_sha256,
           template.exact_rule_payload,
           template.canonical_sha256,
           coalesce(
             (
               select jsonb_agg(
                        jsonb_build_object(
                          'ruleId', citation.rule_id,
                          'sourceDocumentVersionId', citation.source_document_version_id,
                          'sourceDocumentSha256', encode(citation.source_document_sha256, 'hex'),
                          'clause', citation.clause,
                          'locator', citation.locator
                        )
                        order by citation.source_document_version_id,
                                 citation.clause,
                                 citation.locator,
                                 citation.id
                      )
                 from rule_citations as citation
                where citation.rule_id = selected_rule.id
             ),
             '[]'::jsonb
           ),
           (
             board.state = 'active'
             and board.current_governance_profile_id = candidate_profile
             and board.current_ruleset_id = candidate_ruleset
             and profile.state = 'active'
             and ruleset.state = 'active'
             and ruleset.profile_id = profile.id
             and evaluation.profile_id = profile.id
             and evaluation.ruleset_id = ruleset.id
             and selected_rule.ruleset_id = ruleset.id
             and selected_rule.matter_type_id = evaluation.matter_type_id
             and selected_rule.approval_rule_id = candidate_approval_rule
             and approval.organization_id = evaluation.organization_id
             and approval.board_id = evaluation.board_id
             and template.exact_rule_payload->>'schemaVersion' =
                 'boardagent.governance-rule-template.v1'
             and template.exact_rule_payload->>'approvalRuleSha256' =
                 encode(approval.canonical_sha256, 'hex')
             and template.exact_rule_payload->>'overridePolicy' in
                 ('forbidden', 'reasoned_within_bounds')
             and exists (
               select 1 from rule_citations as citation
                where citation.rule_id = selected_rule.id
             )
             and not exists (
               select 1
                 from rule_citations as citation
                 left join document_versions as source_version
                   on source_version.id = citation.source_document_version_id
                where citation.rule_id = selected_rule.id
                  and (
                    source_version.id is null
                    or source_version.organization_id <> evaluation.organization_id
                    or source_version.board_id <> evaluation.board_id
                    or source_version.sha256 <> citation.source_document_sha256
                  )
             )
             and boardagent_vote_actor_ready(evaluation.board_id)
           )
      from matter_evaluations as evaluation
      join boards as board
        on board.id = evaluation.board_id
       and board.organization_id = evaluation.organization_id
      join governance_profiles as profile on profile.id = candidate_profile
      join rulesets as ruleset on ruleset.id = candidate_ruleset
      join ruleset_rules as selected_rule on selected_rule.id = candidate_selected_rule
      join approval_rules as approval on approval.id = candidate_approval_rule
      join governance_rule_templates as template
        on template.profile_id = profile.id
       and template.approval_rule_id = selected_rule.approval_rule_id
     where evaluation.id = candidate_evaluation
       and evaluation.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and evaluation.board_id = candidate_board
       and boardagent_context_board_allowed(evaluation.board_id);
end
$$;
alter function boardagent_rule_selection_evidence(uuid, uuid, uuid, uuid, uuid, uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_rule_selection_evidence(uuid, uuid, uuid, uuid, uuid, uuid)
  from public;
grant execute on function boardagent_rule_selection_evidence(uuid, uuid, uuid, uuid, uuid, uuid)
  to boardagent_server;
