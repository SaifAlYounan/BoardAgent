-- BoardAgent Phase 4 / group 68: fail-closed organization, board and member export isolation.

create or replace function public.boardagent_export_system_table_rows(
  candidate_request_id uuid,
  candidate_class text,
  candidate_table text
)
returns table(table_rows jsonb, row_count bigint)
language plpgsql
stable
security definer
set search_path=pg_catalog,public
as $$
declare
  request_row public.export_requests%rowtype;
  scope jsonb;
  scope_kind text;
  scope_member_id uuid;
  allowed boolean := false;
  has_organization_id boolean := false;
  has_board_id boolean := false;
  member_predicate text;
  row_predicate text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or current_setting('transaction_isolation')<>'repeatable read' then
    raise exception 'system export reads require a managed repeatable-read worker transaction'
      using errcode='25000';
  end if;
  select request.* into strict request_row
    from public.export_requests as request where request.id=candidate_request_id;
  scope := convert_from(request_row.scope_manifest,'UTF8')::jsonb;
  scope_kind := scope->>'scope';
  scope_member_id := nullif(scope->>'memberId','')::uuid;
  if request_row.state<>'queued'
     or request_row.export_type<>'system_data'
     or scope_kind not in ('organization','board','member_portability')
     or (scope_kind='organization' and (request_row.board_id is not null or scope_member_id is not null))
     or (scope_kind='board' and (request_row.board_id is null or scope_member_id is not null))
     or (scope_kind='member_portability' and (request_row.board_id is not null or scope_member_id is null))
     or not exists (
       select 1 from jsonb_array_elements_text(scope->'dataClasses') as class(value)
        where class.value=candidate_class
     ) then
    raise exception 'system export component is outside the frozen request scope'
      using errcode='42501';
  end if;

  allowed := case candidate_class
    when 'identity_authority' then candidate_table=any(array[
      'accountable_principals','members','organization_role_assignments','board_memberships',
      'membership_versions','onboarding_terms_versions','onboarding_attestations',
      'secretary_support_versions'
    ])
    when 'governance' then candidate_table=any(array[
      'organizations','system_instance','boards','board_versions','governance_profiles',
      'governance_seat_rules','governance_rule_templates','governance_citations','rulesets',
      'matter_types','ruleset_rules','rule_citations','rule_overrides','matter_evaluations'
    ])
    when 'documents' then candidate_table=any(array[
      'documents','document_versions','document_access_grants','document_circulations',
      'circulation_recipients','document_exclusions','document_validation_attempts'
    ])
    when 'management' then candidate_table=any(array[
      'management_submission_threads','management_submission_versions',
      'management_revision_requests','management_revision_replies',
      'management_submission_dispositions','management_questions',
      'management_question_turns','management_question_answers','question_visibility',
      'question_decision_links'
    ])
    when 'meetings' then candidate_table=any(array[
      'meetings','meeting_versions','agenda_versions','agenda_items','meeting_rsvps',
      'meeting_attendance','meeting_transcripts','meeting_transcript_versions',
      'transcript_turns','transcript_verifications','transcript_question_links',
      'transcript_challenges','transcript_challenge_dispositions'
    ])
    when 'minutes_tasks' then candidate_table=any(array[
      'minutes','minutes_versions','minutes_diffs','minutes_review_items',
      'minutes_review_withdrawals','minutes_review_dispositions',
      'minutes_action_declarations','minutes_action_item_dispositions',
      'minutes_signature_packages','minutes_signature_requirements','minutes_signatures',
      'minutes_signature_supersessions','minutes_resign_requirements',
      'minutes_correction_cycles','tasks','task_evidence','task_evidence_reviews',
      'task_closures','task_correction_cycles'
    ])
    when 'decisions' then candidate_table=any(array[
      'approval_rules','resolution_versions','decision_packages',
      'decision_package_components','votes','vote_electorate','vote_exclusions',
      'vote_source_update_causes','vote_source_update_dispositions','ballots',
      'ballot_dispositions','proxy_grants','proxy_revocations','vote_outcomes',
      'vote_certificates','vote_supersessions'
    ])
    when 'audit' then candidate_table='audit_checkpoints'
    when 'operations' then candidate_table=any(array[
      'config_receipts','clock_health_samples','retention_snapshots','deletion_tombstones',
      'notices','pending_action_feed','feed_tombstones'
    ])
    else false
  end;
  if not allowed then
    raise exception 'system export table is not on the secret-free allowlist'
      using errcode='42501';
  end if;

  select exists (
    select 1 from information_schema.columns as column_definition
     where column_definition.table_schema='public'
       and column_definition.table_name=candidate_table
       and column_definition.column_name='organization_id'
  ) into has_organization_id;
  select exists (
    select 1 from information_schema.columns as column_definition
     where column_definition.table_schema='public'
       and column_definition.table_name=candidate_table
       and column_definition.column_name='board_id'
  ) into has_board_id;

  if scope_kind='organization' then
    if has_organization_id then
      row_predicate := 'source_row.organization_id=$1';
    elsif candidate_table='organizations' then
      row_predicate := 'source_row.id=$1';
    else
      row_predicate := case candidate_table
        when 'agenda_items' then
          'exists (select 1 from public.agenda_versions as parent where parent.id=source_row.agenda_version_id and parent.organization_id=$1)'
        when 'circulation_recipients' then
          'exists (select 1 from public.document_versions as parent where parent.id=source_row.document_version_id and parent.organization_id=$1)'
        when 'decision_package_components' then
          'exists (select 1 from public.decision_packages as parent where parent.id=source_row.decision_package_id and parent.organization_id=$1)'
        when 'ballot_dispositions' then
          'exists (select 1 from public.ballots as parent where parent.id=source_row.prior_ballot_id and parent.organization_id=$1)'
        when 'document_search' then
          'exists (select 1 from public.documents as parent where parent.id=source_row.document_id and parent.organization_id=$1)'
        when 'governance_seat_rules' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.organization_id=$1)'
        when 'governance_rule_templates' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.organization_id=$1)'
        when 'governance_citations' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.organization_id=$1)'
        when 'matter_types' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.organization_id=$1)'
        when 'ruleset_rules' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.organization_id=$1)'
        when 'rule_citations' then
          'exists (select 1 from public.ruleset_rules as rule join public.rulesets as parent on parent.id=rule.ruleset_id where rule.id=source_row.rule_id and parent.organization_id=$1)'
        when 'transcript_turns' then
          'exists (select 1 from public.meeting_transcript_versions as parent where parent.id=source_row.transcript_version_id and parent.organization_id=$1)'
        when 'minutes_diffs' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.organization_id=$1)'
        when 'minutes_action_item_dispositions' then
          'exists (select 1 from public.tasks as parent where parent.id=source_row.task_id and parent.organization_id=$1)'
        when 'minutes_signature_requirements' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.package_id and parent.organization_id=$1)'
        when 'minutes_signature_supersessions' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.old_package_id and parent.organization_id=$1)'
        when 'minutes_resign_requirements' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.organization_id=$1)'
        else null
      end;
    end if;
  elsif scope_kind='board' then
    if has_board_id then
      row_predicate := 'source_row.board_id=$2';
    elsif candidate_table='boards' then
      row_predicate := 'source_row.id=$2 and source_row.organization_id=$1';
    elsif candidate_table='organizations' then
      row_predicate := 'source_row.id=$1';
    elsif candidate_table='system_instance' then
      row_predicate := 'source_row.organization_id=$1';
    elsif candidate_table='members' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.board_memberships as membership where membership.board_id=$2 and membership.member_id=source_row.id)';
    elsif candidate_table='accountable_principals' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.members as member join public.board_memberships as membership on membership.member_id=member.id where member.accountable_principal_id=source_row.id and membership.board_id=$2)';
    elsif candidate_table='onboarding_terms_versions' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.onboarding_attestations as attestation where attestation.board_id=$2 and attestation.terms_version_id=source_row.id)';
    else
      row_predicate := case candidate_table
        when 'agenda_items' then
          'exists (select 1 from public.agenda_versions as parent where parent.id=source_row.agenda_version_id and parent.board_id=$2)'
        when 'circulation_recipients' then
          'exists (select 1 from public.document_versions as parent where parent.id=source_row.document_version_id and parent.board_id=$2)'
        when 'decision_package_components' then
          'exists (select 1 from public.decision_packages as parent where parent.id=source_row.decision_package_id and parent.board_id=$2)'
        when 'ballot_dispositions' then
          'exists (select 1 from public.ballots as parent where parent.id=source_row.prior_ballot_id and parent.board_id=$2)'
        when 'document_search' then
          'source_row.board_id=$2'
        when 'governance_seat_rules' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.board_id=$2)'
        when 'governance_rule_templates' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.board_id=$2)'
        when 'governance_citations' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.board_id=$2)'
        when 'matter_types' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.board_id=$2)'
        when 'ruleset_rules' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.board_id=$2)'
        when 'rule_citations' then
          'exists (select 1 from public.ruleset_rules as rule join public.rulesets as parent on parent.id=rule.ruleset_id where rule.id=source_row.rule_id and parent.board_id=$2)'
        when 'transcript_turns' then
          'exists (select 1 from public.meeting_transcript_versions as parent where parent.id=source_row.transcript_version_id and parent.board_id=$2)'
        when 'minutes_diffs' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.board_id=$2)'
        when 'minutes_action_item_dispositions' then
          'exists (select 1 from public.tasks as parent where parent.id=source_row.task_id and parent.board_id=$2)'
        when 'minutes_signature_requirements' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.package_id and parent.board_id=$2)'
        when 'minutes_signature_supersessions' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.old_package_id and parent.board_id=$2)'
        when 'minutes_resign_requirements' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.board_id=$2)'
        else null
      end;
    end if;
  else
    select string_agg(format('source_row.%I=$2',column_definition.column_name),' or '
                      order by column_definition.ordinal_position)
      into member_predicate
      from information_schema.columns as column_definition
     where column_definition.table_schema='public'
       and column_definition.table_name=candidate_table
       and column_definition.column_name=any(array[
         'member_id','actor_member_id','acting_for_member_id','author_member_id',
         'proposer_member_id','requester_member_id','owner_member_id',
         'principal_member_id','caster_member_id','holder_member_id','revoker_member_id',
         'recipient_member_id','grantee_member_id','signer_member_id','secretary_member_id',
         'management_author_id','recorder_member_id','challenger_member_id',
         'close_actor_member_id','selected_by','requested_by','issued_by','confirmed_by',
         'authorized_by','created_by'
       ]);
    if candidate_table='organizations' then
      row_predicate := 'source_row.id=$1';
    elsif candidate_table='members' then
      row_predicate := 'source_row.organization_id=$1 and source_row.id=$2';
    elsif candidate_table='boards' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.board_memberships as membership where membership.board_id=source_row.id and membership.member_id=$2)';
    elsif candidate_table='accountable_principals' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.members as member where member.accountable_principal_id=source_row.id and member.id=$2)';
    elsif member_predicate is not null then
      row_predicate := case when has_organization_id
        then format('source_row.organization_id=$1 and (%s)',member_predicate)
        else format('(%s)',member_predicate)
      end;
    end if;
  end if;

  if row_predicate is null then
    return query select '[]'::jsonb,0::bigint;
    return;
  end if;
  return query execute format(
    'select coalesce(jsonb_agg(normalized.row_value order by normalized.row_value::text),''[]''::jsonb),count(*)::bigint
       from public.%I as source_row
       cross join lateral (
         select jsonb_object_agg(item.key,item.value order by item.key) as row_value
           from jsonb_each_text(to_jsonb(source_row)) as item(key,value)
       ) as normalized
      where %s',
    candidate_table,row_predicate
  ) using request_row.organization_id,
          case when scope_kind='board' then request_row.board_id else scope_member_id end;
end
$$;
alter function public.boardagent_export_system_table_rows(uuid,text,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_export_system_table_rows(uuid,text,text) from public;
grant execute on function public.boardagent_export_system_table_rows(uuid,text,text)
  to boardagent_worker;

create or replace function public.boardagent_export_audit_event_rows(candidate_request_id uuid)
returns table(table_rows jsonb,row_count bigint)
language plpgsql
stable
security definer
set search_path=pg_catalog,public
as $$
declare
  request_row public.export_requests%rowtype;
  scope jsonb;
  range_first bigint;
  range_last bigint;
  scope_kind text;
  scope_member_id uuid;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or current_setting('transaction_isolation')<>'repeatable read' then
    raise exception 'audit export reads require a managed repeatable-read worker transaction'
      using errcode='25000';
  end if;
  select request.* into strict request_row
    from public.export_requests as request where request.id=candidate_request_id;
  scope := convert_from(request_row.scope_manifest,'UTF8')::jsonb;
  scope_kind := scope->>'scope';
  scope_member_id := nullif(scope->>'memberId','')::uuid;
  if request_row.state<>'queued'
     or (request_row.export_type='system_data' and not exists (
       select 1 from jsonb_array_elements_text(scope->'dataClasses') as class(value)
        where class.value='audit'
     )) then
    raise exception 'audit component is outside the frozen request scope' using errcode='42501';
  end if;
  if request_row.export_type='audit_chain' then
    range_first := (scope->>'firstSequence')::bigint;
    range_last := (scope->>'lastSequence')::bigint;
  else
    range_first := 1;
    select head.last_sequence into range_last
      from public.audit_chain_head as head where head.singleton_key;
  end if;

  return query
    select coalesce(jsonb_agg(
      case
        when request_row.export_type='audit_chain'
             and (request_row.board_id is null or event.board_id=request_row.board_id)
          then normalized.row_value
        when request_row.export_type='system_data' and scope_kind='organization'
          then normalized.row_value
        when request_row.export_type='system_data' and scope_kind='board'
             and event.board_id=request_row.board_id
          then normalized.row_value
        when request_row.export_type='system_data' and scope_kind='member_portability'
             and (event.actor_member_id=scope_member_id
                  or event.acting_for_member_id=scope_member_id
                  or (event.object_type='member' and event.object_id=scope_member_id))
          then normalized.row_value
        else jsonb_build_object(
          'sequence',event.sequence::text,
          'previous_event_sha256',encode(event.previous_event_sha256,'hex'),
          'event_sha256',encode(event.event_sha256,'hex'),
          'redacted','true'
        )
      end order by event.sequence
    ),'[]'::jsonb),count(*)::bigint
      from public.audit_events as event
      cross join lateral (
        select jsonb_object_agg(item.key,item.value order by item.key) as row_value
          from jsonb_each_text(to_jsonb(event)) as item(key,value)
      ) as normalized
     where event.organization_id=request_row.organization_id
       and event.sequence between range_first and range_last;
end
$$;
alter function public.boardagent_export_audit_event_rows(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_export_audit_event_rows(uuid) from public;
grant execute on function public.boardagent_export_audit_event_rows(uuid) to boardagent_worker;

create function public.boardagent_resolve_audit_export_range(
  candidate_board_id uuid,
  candidate_first_sequence text,
  candidate_last_sequence text,
  candidate_exact_origin text
)
returns table(first_sequence text,last_sequence text)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  resolved_first bigint;
  resolved_last bigint;
begin
  perform 1 from public.boardagent_assert_export_authority(
    'audit_chain',candidate_board_id,candidate_exact_origin
  );
  if candidate_first_sequence is null
     or candidate_first_sequence!~'^(0|[1-9][0-9]*)$'
     or (candidate_last_sequence is not null
         and candidate_last_sequence!~'^[1-9][0-9]*$') then
    raise exception 'audit export range is invalid' using errcode='22023';
  end if;
  resolved_first := greatest(candidate_first_sequence::bigint,1);
  if candidate_last_sequence is null then
    select head.last_sequence into strict resolved_last
      from public.audit_chain_head as head where head.singleton_key;
  else
    resolved_last := candidate_last_sequence::bigint;
  end if;
  if resolved_last<resolved_first or resolved_last-resolved_first>=1000000 then
    raise exception 'audit export range is empty, inverted or too large' using errcode='22023';
  end if;
  return query select resolved_first::text,resolved_last::text;
end
$$;
alter function public.boardagent_resolve_audit_export_range(uuid,text,text,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_resolve_audit_export_range(uuid,text,text,text)
  from public;
grant execute on function public.boardagent_resolve_audit_export_range(uuid,text,text,text)
  to boardagent_server;
