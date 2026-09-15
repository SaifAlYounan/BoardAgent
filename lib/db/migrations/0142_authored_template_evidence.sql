-- Accept the immutable authoring format only when it equals the exact profile
-- template and selected approval fields. Return original payload/hash unchanged:
-- TypeScript validates both original hashes before deriving its strict runtime view.
-- Existing runtime schema/hash/citation/authority checks remain intact.
create or replace function public.boardagent_rule_selection_evidence(
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
set search_path = pg_catalog, public, pg_temp
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
             and (
               (
                 template.exact_rule_payload->>'schemaVersion' =
                   'boardagent.governance-rule-template.v1'
                 and template.exact_rule_payload->>'approvalRuleSha256' =
                   encode(approval.canonical_sha256, 'hex')
                 and template.exact_rule_payload->>'overridePolicy' in
                   ('forbidden', 'reasoned_within_bounds')
               )
               or (
                 not (template.exact_rule_payload ? 'schemaVersion')
                 and template.exact_rule_payload->>'id'=template.id::text
                 and template.exact_rule_payload->>'code'=template.code
                 and template.exact_rule_payload->>'overridePolicy' in
                   ('forbidden','strengthen_only')
                 and exists (
                   select 1 from jsonb_array_elements(profile.canonical_payload->'templates')
                     as authored(value)
                    where authored.value=template.exact_rule_payload
                 )
                 and template.exact_rule_payload @> jsonb_build_object(
                   'approval',jsonb_build_object(
                     'numerator',approval.threshold_numerator::text,
                     'denominator',approval.threshold_denominator::text),
                   'quorum',jsonb_build_object(
                     'numerator',approval.quorum_numerator::text,
                     'denominator',approval.quorum_denominator::text),
                   'approvalDenominator',approval.approval_denominator,
                   'abstentionsCountForQuorum',approval.abstentions_count_for_quorum,
                   'tieBehavior',approval.tie_behavior,'proxyPolicy',approval.proxy_policy,
                   'closeMode',approval.close_mode
                 )
               )
             )
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
