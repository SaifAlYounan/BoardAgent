-- BoardAgent Phase 1 / group 21: reproducible, persisted matter evaluation.

alter table matter_evaluations
  add column result_details jsonb not null default '{}'::jsonb
    check (jsonb_typeof(result_details) = 'object');

grant select on
  approval_rules,
  governance_profiles,
  governance_rule_templates,
  rulesets,
  matter_types,
  ruleset_rules,
  rule_citations
to boardagent_migrator;
grant update on governance_profiles, rulesets, matter_types to boardagent_migrator;

do $migrator_matter_evaluation_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'approval_rules', 'governance_profiles', 'governance_rule_templates', 'rulesets',
    'matter_types', 'ruleset_rules', 'rule_citations'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_matter_evaluation_read on %I for select to boardagent_migrator using (true)',
      source_table
    );
  end loop;
end
$migrator_matter_evaluation_read$;

create policy boardagent_migrator_matter_evaluation_lock on governance_profiles
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_matter_evaluation_lock on rulesets
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_matter_evaluation_lock on matter_types
  for update to boardagent_migrator using (true) with check (true);

create function boardagent_lock_matter_evaluation_snapshot(
  candidate_board uuid,
  candidate_matter_type text
)
returns table(
  organization_id uuid,
  board_id uuid,
  profile_id uuid,
  profile_version integer,
  profile_sha256 bytea,
  ruleset_id uuid,
  ruleset_version integer,
  ruleset_sha256 bytea,
  matter_type_id uuid,
  matter_type_schema_sha256 bytea,
  matter_definitions jsonb,
  rule_definitions jsonb,
  snapshot_valid boolean
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  selected_organization_id uuid;
  selected_profile_id uuid;
  selected_profile_version integer;
  selected_profile_sha256 bytea;
  selected_ruleset_id uuid;
  selected_ruleset_version integer;
  selected_ruleset_sha256 bytea;
  selected_matter_type_id uuid;
  selected_matter_schema_sha256 bytea;
  selected_matter_definitions jsonb;
  selected_rule_definitions jsonb;
  selected_snapshot_valid boolean;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'matter evaluation requires a managed request transaction'
      using errcode = '25000';
  end if;

  select board.organization_id,
         profile.id,
         profile.version,
         profile.canonical_sha256,
         ruleset.id,
         ruleset.version,
         ruleset.canonical_sha256
    into selected_organization_id,
         selected_profile_id,
         selected_profile_version,
         selected_profile_sha256,
         selected_ruleset_id,
         selected_ruleset_version,
         selected_ruleset_sha256
    from boards as board
    join governance_profiles as profile
      on profile.id = board.current_governance_profile_id
     and profile.board_id = board.id
     and profile.organization_id = board.organization_id
     and profile.state = 'active'
    join rulesets as ruleset
      on ruleset.id = board.current_ruleset_id
     and ruleset.board_id = board.id
     and ruleset.organization_id = board.organization_id
     and ruleset.profile_id = profile.id
     and ruleset.state = 'active'
   where board.id = candidate_board
     and board.organization_id = boardagent_context_uuid('boardagent.organization_id')
     and board.state = 'active'
     and boardagent_vote_actor_ready(board.id)
   for update of board, profile, ruleset;

  if not found then
    return;
  end if;

  select matter.id, matter.schema_sha256
    into selected_matter_type_id, selected_matter_schema_sha256
    from matter_types as matter
   where matter.ruleset_id = selected_ruleset_id
     and matter.code = candidate_matter_type
   for update of matter;

  if not found then
    return;
  end if;

  -- Lock every typed fact definition used by this exact ruleset version. Rule and
  -- citation rows are already append-only evidence under the immutable wall.
  perform 1
    from matter_types as matter
   where matter.ruleset_id = selected_ruleset_id
   order by matter.code, matter.id
   for update of matter;

  select coalesce(
           jsonb_agg(
             jsonb_build_object(
               'definition', matter.strict_fact_schema,
               'schemaSha256', encode(matter.schema_sha256, 'hex')
             )
             order by matter.code, matter.id
           ),
           '[]'::jsonb
         )
    into selected_matter_definitions
    from matter_types as matter
   where matter.ruleset_id = selected_ruleset_id;

  select coalesce(
           jsonb_agg(
             jsonb_build_object(
               'id', rule.id,
               'matterType', matter.code,
               'priority', rule.priority,
               'specificity', rule.specificity,
               'condition', rule.condition_tree,
               'approvalRuleId', rule.approval_rule_id,
               'citations', coalesce(
                 (
                   select jsonb_agg(
                            jsonb_build_object(
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
                    where citation.rule_id = rule.id
                 ),
                 '[]'::jsonb
               )
             )
             order by rule.priority desc, rule.specificity desc, rule.id
           ),
           '[]'::jsonb
         )
    into selected_rule_definitions
    from ruleset_rules as rule
    join matter_types as matter
      on matter.id = rule.matter_type_id
     and matter.ruleset_id = selected_ruleset_id
   where rule.ruleset_id = selected_ruleset_id;

  select not exists (
           select 1
             from ruleset_rules as rule
             left join matter_types as matter
               on matter.id = rule.matter_type_id
              and matter.ruleset_id = selected_ruleset_id
             left join approval_rules as approval
               on approval.id = rule.approval_rule_id
              and approval.organization_id = selected_organization_id
              and approval.board_id = candidate_board
            where rule.ruleset_id = selected_ruleset_id
              and (
                matter.id is null
                or approval.id is null
                or not exists (
                  select 1
                    from governance_rule_templates as template
                   where template.profile_id = selected_profile_id
                     and template.approval_rule_id = rule.approval_rule_id
                )
                or not exists (
                  select 1 from rule_citations as citation where citation.rule_id = rule.id
                )
                or exists (
                  select 1
                    from rule_citations as citation
                    left join document_versions as source_version
                      on source_version.id = citation.source_document_version_id
                   where citation.rule_id = rule.id
                     and (
                       source_version.id is null
                       or source_version.organization_id <> selected_organization_id
                       or source_version.board_id <> candidate_board
                       or source_version.sha256 <> citation.source_document_sha256
                     )
                )
              )
         )
    into selected_snapshot_valid;

  organization_id := selected_organization_id;
  board_id := candidate_board;
  profile_id := selected_profile_id;
  profile_version := selected_profile_version;
  profile_sha256 := selected_profile_sha256;
  ruleset_id := selected_ruleset_id;
  ruleset_version := selected_ruleset_version;
  ruleset_sha256 := selected_ruleset_sha256;
  matter_type_id := selected_matter_type_id;
  matter_type_schema_sha256 := selected_matter_schema_sha256;
  matter_definitions := selected_matter_definitions;
  rule_definitions := selected_rule_definitions;
  snapshot_valid := selected_snapshot_valid;
  return next;
end
$$;

alter function boardagent_lock_matter_evaluation_snapshot(uuid, text)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_matter_evaluation_snapshot(uuid, text) from public;
grant execute on function boardagent_lock_matter_evaluation_snapshot(uuid, text)
  to boardagent_server;
