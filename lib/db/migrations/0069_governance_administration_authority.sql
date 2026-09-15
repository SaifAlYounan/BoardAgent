-- BoardAgent Phase 4 / group 69: confirmed board, charter-profile and ruleset authority.
-- Complex writes remain behind one SECURITY DEFINER aggregate boundary and exact consent.

alter table public.boards drop constraint if exists boards_slug_check;
alter table public.boards add constraint boards_slug_check
  check (length(slug) between 1 and 80 and slug~'^[a-z0-9]+(?:-[a-z0-9]+)*$');

alter table public.approval_rules
  drop constraint if exists approval_rules_proxy_policy_check;
alter table public.approval_rules
  add constraint approval_rules_proxy_policy_check
  check (proxy_policy in ('principal_supersedes_proxy','first_ballot_final','forbidden'));

grant select,insert,update on public.boards,public.board_versions,public.approval_rules,
  public.governance_profiles,public.governance_seat_rules,public.governance_rule_templates,
  public.governance_citations,public.rulesets,public.matter_types,public.ruleset_rules,
  public.rule_citations to boardagent_migrator;
grant select on public.document_versions,public.board_memberships,public.votes,public.meetings,
  public.minutes,public.tasks,public.action_stages to boardagent_migrator;

create policy boardagent_migrator_governance_admin_boards
  on public.boards for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

do $governance_admin_root_policies$
declare
  table_name text;
begin
  foreach table_name in array array[
    'board_versions','approval_rules','governance_profiles','rulesets'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_governance_admin on public.%I for all to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id'')) with check (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id''))',
      table_name
    );
  end loop;
end
$governance_admin_root_policies$;

create policy boardagent_migrator_governance_admin_seat_rules
  on public.governance_seat_rules for all to boardagent_migrator
  using (exists (
    select 1 from public.governance_profiles as profile
     where profile.id=governance_seat_rules.profile_id
       and profile.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ))
  with check (exists (
    select 1 from public.governance_profiles as profile
     where profile.id=governance_seat_rules.profile_id
       and profile.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ));
create policy boardagent_migrator_governance_admin_templates
  on public.governance_rule_templates for all to boardagent_migrator
  using (exists (
    select 1 from public.governance_profiles as profile
     where profile.id=governance_rule_templates.profile_id
       and profile.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ))
  with check (exists (
    select 1 from public.governance_profiles as profile
     where profile.id=governance_rule_templates.profile_id
       and profile.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ));
create policy boardagent_migrator_governance_admin_citations
  on public.governance_citations for all to boardagent_migrator
  using (exists (
    select 1 from public.governance_profiles as profile
     where profile.id=governance_citations.profile_id
       and profile.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ))
  with check (exists (
    select 1 from public.governance_profiles as profile
     where profile.id=governance_citations.profile_id
       and profile.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ));
create policy boardagent_migrator_governance_admin_matter_types
  on public.matter_types for all to boardagent_migrator
  using (exists (
    select 1 from public.rulesets as ruleset
     where ruleset.id=matter_types.ruleset_id
       and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ))
  with check (exists (
    select 1 from public.rulesets as ruleset
     where ruleset.id=matter_types.ruleset_id
       and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ));
create policy boardagent_migrator_governance_admin_rules
  on public.ruleset_rules for all to boardagent_migrator
  using (exists (
    select 1 from public.rulesets as ruleset
     where ruleset.id=ruleset_rules.ruleset_id
       and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ))
  with check (exists (
    select 1 from public.rulesets as ruleset
     where ruleset.id=ruleset_rules.ruleset_id
       and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ));
create policy boardagent_migrator_governance_admin_rule_citations
  on public.rule_citations for all to boardagent_migrator
  using (exists (
    select 1 from public.ruleset_rules as rule
    join public.rulesets as ruleset on ruleset.id=rule.ruleset_id
     where rule.id=rule_citations.rule_id
       and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ))
  with check (exists (
    select 1 from public.ruleset_rules as rule
    join public.rulesets as ruleset on ruleset.id=rule.ruleset_id
     where rule.id=rule_citations.rule_id
       and ruleset.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  ));

create function public.boardagent_governance_admin_snapshot(
  candidate_action text,
  candidate_board_id uuid,
  candidate_request jsonb
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  context_organization uuid;
  context_member uuid;
  context_client uuid;
  context_token uuid;
  board_row public.boards%rowtype;
  profile_row public.governance_profiles%rowtype;
  ruleset_row public.rulesets%rowtype;
  current_version integer;
  open_actions bigint;
  profile_seats integer;
  live_seats integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_action not in (
       'create_board','update_board','archive_board','configure_board_governance','manage_ruleset'
     )
     or candidate_board_id is null
     or not public.boardagent_is_uuid_v7(candidate_board_id)
     or jsonb_typeof(candidate_request)<>'object'
     or candidate_request->>'actionCode' is distinct from candidate_action
     or (candidate_request->>'boardId')::uuid is distinct from candidate_board_id then
    raise exception 'governance administration requires one managed exact action'
      using errcode='25000';
  end if;
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  context_client := public.boardagent_context_uuid('boardagent.client_id');
  context_token := public.boardagent_context_uuid('boardagent.token_jti');
  if not exists (
    select 1 from public.access_token_records as token
    join public.oauth_clients as client on client.id=token.client_id
    join public.members as actor
      on actor.id=token.member_id and actor.organization_id=token.organization_id
     where token.organization_id=context_organization
       and token.member_id=context_member and token.client_id=context_client
       and token.jti=context_token and token.revoked_at is null
       and token.expires_at>transaction_timestamp()
       and 'secretariat:admin'=any(token.scope_set)
       and client.state='active' and actor.state='active'
  ) or not exists (
    select 1 from public.organization_role_assignments as assignment
     where assignment.organization_id=context_organization
       and assignment.member_id=context_member and assignment.role='admin'
       and assignment.active_from<=transaction_timestamp()
       and (assignment.active_until is null or assignment.active_until>transaction_timestamp())
  ) or exists (
    select 1 from public.board_memberships as observer
     where observer.organization_id=context_organization and observer.member_id=context_member
       and observer.seat_role='observer' and observer.state='active'
       and observer.active_from<=transaction_timestamp()
       and (observer.active_until is null or observer.active_until>transaction_timestamp())
  ) then
    raise exception 'governance administration requires a live nonobserver administrator'
      using errcode='42501';
  end if;

  if candidate_action='create_board' then
    perform 1 from public.organizations as organization
     where organization.id=context_organization for share;
    if exists (
         select 1 from public.boards as existing
          where existing.id=candidate_board_id
             or (existing.organization_id=context_organization
                 and existing.slug=candidate_request->>'slug')
       ) or not exists (
         select 1 from public.members as secretary
          where secretary.id=(candidate_request->>'secretaryMemberId')::uuid
            and secretary.organization_id=context_organization and secretary.state='active'
       ) then
      raise exception 'new board identity, slug or secretary is unavailable' using errcode='55000';
    end if;
    return jsonb_build_object(
      'organizationId',context_organization,'boardId',candidate_board_id,
      'boardAbsent',true,'slug',candidate_request->>'slug',
      'secretaryMemberId',candidate_request->>'secretaryMemberId'
    );
  end if;

  select board.* into board_row from public.boards as board
   where board.id=candidate_board_id and board.organization_id=context_organization
   for update;
  if board_row.id is null or board_row.state<>'active' then
    raise exception 'active board is unavailable' using errcode='P0002';
  end if;
  select coalesce(max(version),0)::integer into current_version
    from public.board_versions where board_id=board_row.id;

  if candidate_action='update_board' then
    if board_row.row_version<>(candidate_request->>'expectedRowVersion')::bigint then
      raise exception 'board row version changed' using errcode='40001';
    end if;
  elsif candidate_action='archive_board' then
    select
      (select count(*) from public.votes
        where board_id=board_row.id and state not in ('closed','cancelled'))+
      (select count(*) from public.meetings
        where board_id=board_row.id and state not in ('completed','cancelled'))+
      (select count(*) from public.minutes
        where board_id=board_row.id and state not in ('finalized','cancelled'))+
      (select count(*) from public.tasks
        where board_id=board_row.id and state not in ('completed','cancelled'))+
      (select count(*) from public.action_stages
        where board_id=board_row.id and state='active'
          and not (
            action_code='archive_board' and target_type='board' and target_id=board_row.id
            and actor_member_id=context_member and client_id=context_client
          ))
      into open_actions;
    if open_actions<>0 then
      raise exception 'board has unfinished governance actions' using errcode='55000';
    end if;
  elsif candidate_action='configure_board_governance' then
    if board_row.current_governance_profile_id is distinct from
         nullif(candidate_request->>'expectedProfileId','')::uuid
       or (candidate_request->'profile'->>'boardId')::uuid<>board_row.id
       or (candidate_request->'profile'->>'id')::uuid=
          coalesce(board_row.current_governance_profile_id,'00000000-0000-0000-0000-000000000000')::uuid
       or (candidate_request->'profile'->>'version')::integer<>
          coalesce((select version+1 from public.governance_profiles
                     where id=board_row.current_governance_profile_id),1)
       or nullif(candidate_request->'profile'->>'supersedesId','')::uuid
          is distinct from board_row.current_governance_profile_id then
      raise exception 'governance profile does not supersede the exact active profile'
        using errcode='40001';
    end if;
    select jsonb_array_length(candidate_request->'profile'->'seats') into profile_seats;
    select count(*)::integer into live_seats from public.board_memberships as membership
     where membership.board_id=board_row.id and membership.organization_id=context_organization
       and membership.state='active' and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp());
    if profile_seats<>live_seats or exists (
      select 1 from jsonb_array_elements(candidate_request->'profile'->'seats') as seat(value)
      left join public.board_memberships as membership
        on membership.board_id=board_row.id
       and membership.member_id=(seat.value->>'memberId')::uuid
       and membership.state='active' and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
       and membership.seat_role=seat.value->>'role'
       and membership.voting_weight=(seat.value->>'weight')::bigint
       and membership.is_chair=(seat.value->>'chair')::boolean
      where membership.id is null
    ) then
      raise exception 'governance profile seats do not match live board authority'
        using errcode='42501';
    end if;
    if exists (
      select 1 from jsonb_array_elements(candidate_request->'citationMaterial') as item(value)
      left join public.document_versions as version
        on version.id=(item.value->'citation'->>'documentVersionId')::uuid
       and version.board_id=board_row.id
       and version.sha256=decode(item.value->'citation'->>'sourceDocumentSha256','hex')
      where version.id is null
    ) then
      raise exception 'governance profile citation source is unavailable' using errcode='42501';
    end if;
  elsif candidate_action='manage_ruleset' then
    select profile.* into profile_row from public.governance_profiles as profile
     where profile.id=board_row.current_governance_profile_id
       and profile.board_id=board_row.id and profile.state='active';
    if profile_row.id is null
       or board_row.current_ruleset_id is distinct from
          nullif(candidate_request->>'expectedRulesetId','')::uuid
       or (candidate_request->'ruleset'->>'boardId')::uuid<>board_row.id
       or (candidate_request->'ruleset'->>'version')::integer<>
          coalesce((select version+1 from public.rulesets
                     where id=board_row.current_ruleset_id),1)
       or (candidate_request->'ruleset'->>'id')::uuid=
          coalesce(board_row.current_ruleset_id,'00000000-0000-0000-0000-000000000000')::uuid then
      raise exception 'ruleset does not supersede the exact active ruleset/profile'
        using errcode='40001';
    end if;
    if exists (
      select 1 from jsonb_array_elements(candidate_request->'ruleset'->'rules') as item(value)
      where not exists (
        select 1 from public.governance_rule_templates as template
         where template.profile_id=profile_row.id
           and template.approval_rule_id=(item.value->>'approvalRuleId')::uuid
      )
    ) then
      raise exception 'ruleset references an approval rule outside the active profile'
        using errcode='42501';
    end if;
    if exists (
      select 1 from jsonb_array_elements(candidate_request->'citationMaterial') as item(value)
      left join public.document_versions as version
        on version.id=(item.value->'citation'->>'documentVersionId')::uuid
       and version.board_id=board_row.id
       and version.sha256=decode(item.value->'citation'->>'sourceDocumentSha256','hex')
      where version.id is null
    ) then
      raise exception 'ruleset citation source is unavailable' using errcode='42501';
    end if;
  end if;

  return jsonb_build_object(
    'organizationId',context_organization,'boardId',board_row.id,'state',board_row.state,
    'rowVersion',board_row.row_version::text,'currentBoardVersion',current_version,
    'currentGovernanceProfileId',board_row.current_governance_profile_id,
    'currentRulesetId',board_row.current_ruleset_id,
    'openActionCount',coalesce(open_actions,0)::text
  );
end
$$;

create function public.boardagent_apply_governance_admin_action(
  candidate_action text,
  candidate_board_id uuid,
  candidate_payload jsonb,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  context_organization uuid;
  context_member uuid;
  request jsonb;
  live_snapshot jsonb;
  bound_target_id uuid;
  bound_target_type text;
  prior_profile_id uuid;
  prior_ruleset_id uuid;
  next_version integer;
  template_item jsonb;
  template_payload jsonb;
  approval_payload jsonb;
  seat_item jsonb;
  citation_item jsonb;
  matter_item jsonb;
  matter_payload jsonb;
  rule_item jsonb;
  rule_payload jsonb;
begin
  if candidate_payload->>'schemaVersion' is distinct from 'boardagent.governance-administration.v1'
     or candidate_payload->>'actionCode' is distinct from candidate_action
     or (candidate_payload->>'boardId')::uuid is distinct from candidate_board_id
     or not public.boardagent_hash_is_sha256(candidate_payload_sha256) then
    raise exception 'governance administration payload is invalid' using errcode='22023';
  end if;
  request := candidate_payload->'request';
  bound_target_id := (candidate_payload->>'targetId')::uuid;
  bound_target_type := candidate_payload->>'targetType';
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  live_snapshot := public.boardagent_governance_admin_snapshot(
    candidate_action,candidate_board_id,request
  );
  if live_snapshot is distinct from candidate_payload->'current'
     or not exists (
       select 1 from public.consent_records as consent
        where consent.id=candidate_consent_record_id
          and consent.organization_id=context_organization
          and consent.actor_member_id=context_member
          and consent.action_code=candidate_action
          and consent.target_type=bound_target_type
          and consent.target_id=bound_target_id
          and consent.payload_sha256=candidate_payload_sha256
          and consent.package_sha256 is not distinct from case
            when candidate_action='configure_board_governance'
              then decode(request->>'profileSha256','hex')
            when candidate_action='manage_ruleset'
              then decode(request->>'rulesetSha256','hex')
            else null
          end
     ) then
    raise exception 'governance administration consent or state binding is invalid'
      using errcode='42501';
  end if;

  if candidate_action='create_board' then
    insert into public.boards(id,organization_id,slug,name,timezone,current_version_id)
    values (
      candidate_board_id,context_organization,request->>'slug',request->>'name',
      request->>'timezone',(request->>'boardVersionId')::uuid
    );
    insert into public.board_versions(
      id,organization_id,board_id,version,canonical_schema,canonical_payload,
      canonical_sha256,change_reason,created_by
    ) values (
      (request->>'boardVersionId')::uuid,context_organization,candidate_board_id,1,
      'boardagent.board.v1',jsonb_build_object(
        'schemaVersion','boardagent.board.v1','boardId',candidate_board_id,
        'slug',request->>'slug','name',request->>'name','timezone',request->>'timezone',
        'settings',request->'initialSettings','secretaryMemberId',request->>'secretaryMemberId'
      ),decode(request->>'boardVersionSha256','hex'),'Initial board creation',context_member
    );
    return jsonb_build_object(
      'boardId',candidate_board_id,'state','active','rowVersion','1',
      'version',1,'versionId',request->>'boardVersionId',
      'versionSha256',request->>'boardVersionSha256','implicitSeatsCreated',false
    );
  elsif candidate_action='update_board' then
    select coalesce(max(version),0)+1 into next_version
      from public.board_versions where board_id=candidate_board_id;
    insert into public.board_versions(
      id,organization_id,board_id,version,canonical_schema,canonical_payload,
      canonical_sha256,change_reason,created_by
    ) values (
      (request->>'boardVersionId')::uuid,context_organization,candidate_board_id,next_version,
      'boardagent.board.v1',jsonb_build_object(
        'schemaVersion','boardagent.board.v1','boardId',candidate_board_id,
        'slug',null,'name',request->>'name','timezone',request->>'timezone',
        'settings',request->'settings','secretaryMemberId',null
      ),decode(request->>'boardVersionSha256','hex'),request->>'reason',context_member
    );
    update public.boards set name=request->>'name',timezone=request->>'timezone',
      current_version_id=(request->>'boardVersionId')::uuid,row_version=row_version+1
     where id=candidate_board_id
       and row_version=(request->>'expectedRowVersion')::bigint and state='active';
    return jsonb_build_object(
      'boardId',candidate_board_id,'state','active',
      'rowVersion',((request->>'expectedRowVersion')::bigint+1)::text,
      'version',next_version,'versionId',request->>'boardVersionId',
      'versionSha256',request->>'boardVersionSha256'
    );
  elsif candidate_action='archive_board' then
    update public.boards set state='archived',row_version=row_version+1
     where id=candidate_board_id and state='active';
    return jsonb_build_object(
      'boardId',candidate_board_id,'state','archived',
      'rowVersion',((live_snapshot->>'rowVersion')::bigint+1)::text,
      'reason',request->>'reason'
    );
  elsif candidate_action='configure_board_governance' then
    prior_profile_id := nullif(request->>'expectedProfileId','')::uuid;
    if prior_profile_id is not null then
      update public.governance_profiles set state='superseded'
       where id=prior_profile_id and state='active';
    end if;
    insert into public.governance_profiles(
      id,organization_id,board_id,version,state,schema_version,canonical_payload,
      canonical_sha256,source_agreement_references,activation_consent_record_id,
      supersedes_id,created_by,activated_at
    ) values (
      (request->'profile'->>'id')::uuid,context_organization,candidate_board_id,
      (request->'profile'->>'version')::integer,'active','boardagent.governance-profile.v1',
      request->'profile',decode(request->>'profileSha256','hex'),
      request->'profile'->'sourceAgreements',candidate_consent_record_id,
      prior_profile_id,context_member,transaction_timestamp()
    );
    for seat_item in select value from jsonb_array_elements(request->'seatMaterial') as item(value)
    loop
      insert into public.governance_seat_rules(
        id,profile_id,seat_class,minimum_weight,maximum_weight,
        eligibility_constraints,canonical_sha256
      ) values (
        (seat_item->>'id')::uuid,(request->'profile'->>'id')::uuid,
        seat_item->>'seatClass',(seat_item->>'minimumWeight')::bigint,
        (seat_item->>'maximumWeight')::bigint,'{}'::jsonb,
        decode(seat_item->>'canonicalSha256','hex')
      );
    end loop;
    for template_item in
      select value from jsonb_array_elements(request->'templateMaterial') as item(value)
    loop
      select value into strict template_payload
        from jsonb_array_elements(request->'profile'->'templates') as item(value)
       where (value->>'id')::uuid=(template_item->>'templateId')::uuid;
      approval_payload := jsonb_build_object(
        'schemaVersion','boardagent.approval-rule.v1',
        'approval',template_payload->'approval','quorum',template_payload->'quorum',
        'approvalDenominator',template_payload->>'approvalDenominator',
        'abstentionsCountForQuorum',(template_payload->>'abstentionsCountForQuorum')::boolean,
        'tieBehavior',template_payload->>'tieBehavior','proxyPolicy',template_payload->>'proxyPolicy',
        'closeMode',template_payload->>'closeMode'
      );
      insert into public.approval_rules(
        id,organization_id,board_id,schema_version,threshold_numerator,threshold_denominator,
        quorum_numerator,quorum_denominator,approval_denominator,
        abstentions_count_for_quorum,tie_behavior,proxy_policy,close_mode,
        canonical_sha256,created_by
      ) values (
        (template_item->>'approvalRuleId')::uuid,context_organization,candidate_board_id,
        'boardagent.approval-rule.v1',(template_payload->'approval'->>'numerator')::bigint,
        (template_payload->'approval'->>'denominator')::bigint,
        (template_payload->'quorum'->>'numerator')::bigint,
        (template_payload->'quorum'->>'denominator')::bigint,
        template_payload->>'approvalDenominator',
        (template_payload->>'abstentionsCountForQuorum')::boolean,
        template_payload->>'tieBehavior',template_payload->>'proxyPolicy',
        template_payload->>'closeMode',decode(template_item->>'approvalRuleSha256','hex'),
        context_member
      );
      insert into public.governance_rule_templates(
        id,profile_id,code,approval_rule_id,exact_rule_payload,canonical_sha256
      ) values (
        (template_item->>'templateId')::uuid,(request->'profile'->>'id')::uuid,
        template_payload->>'code',(template_item->>'approvalRuleId')::uuid,
        template_payload,decode(template_item->>'templateSha256','hex')
      );
    end loop;
    for citation_item in
      select value from jsonb_array_elements(request->'citationMaterial') as item(value)
    loop
      insert into public.governance_citations(
        id,profile_id,rule_template_id,source_document_version_id,
        source_document_sha256,clause,locator
      ) values (
        (citation_item->>'id')::uuid,(request->'profile'->>'id')::uuid,
        nullif(citation_item->>'ruleTemplateId','')::uuid,
        (citation_item->'citation'->>'documentVersionId')::uuid,
        decode(citation_item->'citation'->>'sourceDocumentSha256','hex'),
        citation_item->'citation'->>'clause',citation_item->'citation'->>'locator'
      );
    end loop;
    update public.boards set current_governance_profile_id=(request->'profile'->>'id')::uuid,
      row_version=row_version+1 where id=candidate_board_id and state='active';
    return jsonb_build_object(
      'boardId',candidate_board_id,'profileId',request->'profile'->>'id',
      'profileVersion',(request->'profile'->>'version')::integer,
      'profileSha256',request->>'profileSha256','state','active'
    );
  else
    prior_ruleset_id := nullif(request->>'expectedRulesetId','')::uuid;
    if prior_ruleset_id is not null then
      update public.rulesets set state='superseded'
       where id=prior_ruleset_id and state='active';
    end if;
    insert into public.rulesets(
      id,organization_id,board_id,profile_id,version,state,schema_version,
      canonical_payload,canonical_sha256,activation_consent_record_id,supersedes_id,
      created_by,activated_at
    ) values (
      (request->'ruleset'->>'id')::uuid,context_organization,candidate_board_id,
      (live_snapshot->>'currentGovernanceProfileId')::uuid,
      (request->'ruleset'->>'version')::integer,'active','boardagent.ruleset.v1',
      (request->'ruleset') - 'canonicalHash'::text,decode(request->>'rulesetSha256','hex'),
      candidate_consent_record_id,prior_ruleset_id,context_member,transaction_timestamp()
    );
    for matter_item in
      select value from jsonb_array_elements(request->'matterTypeMaterial') as item(value)
    loop
      select value into strict matter_payload
        from jsonb_array_elements(request->'ruleset'->'matterTypes') as item(value)
       where value->>'code'=matter_item->>'code';
      insert into public.matter_types(
        id,ruleset_id,code,name,strict_fact_schema,schema_sha256
      ) values (
        (matter_item->>'id')::uuid,(request->'ruleset'->>'id')::uuid,
        matter_payload->>'code',initcap(replace(matter_payload->>'code','_',' ')),
        matter_payload,decode(matter_item->>'schemaSha256','hex')
      );
    end loop;
    for rule_item in select value from jsonb_array_elements(request->'ruleMaterial') as item(value)
    loop
      select value into strict rule_payload
        from jsonb_array_elements(request->'ruleset'->'rules') as item(value)
       where (value->>'id')::uuid=(rule_item->>'ruleId')::uuid;
      select value into strict matter_item
        from jsonb_array_elements(request->'matterTypeMaterial') as item(value)
       where value->>'code'=rule_payload->>'matterType';
      insert into public.ruleset_rules(
        id,ruleset_id,matter_type_id,priority,specificity,condition_tree,
        approval_rule_id,canonical_sha256
      ) values (
        (rule_payload->>'id')::uuid,(request->'ruleset'->>'id')::uuid,
        (matter_item->>'id')::uuid,(rule_payload->>'priority')::integer,
        (rule_payload->>'specificity')::integer,rule_payload->'condition',
        (rule_payload->>'approvalRuleId')::uuid,decode(rule_item->>'canonicalSha256','hex')
      );
    end loop;
    for citation_item in
      select value from jsonb_array_elements(request->'citationMaterial') as item(value)
    loop
      insert into public.rule_citations(
        id,rule_id,source_document_version_id,source_document_sha256,clause,locator
      ) values (
        (citation_item->>'id')::uuid,(citation_item->>'ruleId')::uuid,
        (citation_item->'citation'->>'documentVersionId')::uuid,
        decode(citation_item->'citation'->>'sourceDocumentSha256','hex'),
        citation_item->'citation'->>'clause',citation_item->'citation'->>'locator'
      );
    end loop;
    update public.boards set current_ruleset_id=(request->'ruleset'->>'id')::uuid,
      row_version=row_version+1 where id=candidate_board_id and state='active';
    return jsonb_build_object(
      'boardId',candidate_board_id,'rulesetId',request->'ruleset'->>'id',
      'rulesetVersion',(request->'ruleset'->>'version')::integer,
      'rulesetSha256',request->>'rulesetSha256','state','active',
      'profileId',live_snapshot->>'currentGovernanceProfileId'
    );
  end if;
end
$$;

do $governance_admin_functions$
declare
  function_name regprocedure;
begin
  foreach function_name in array array[
    'public.boardagent_governance_admin_snapshot(text,uuid,jsonb)'::regprocedure,
    'public.boardagent_apply_governance_admin_action(text,uuid,jsonb,bytea,uuid)'::regprocedure
  ]
  loop
    execute 'alter function '||function_name||' owner to boardagent_migrator';
    execute 'revoke all on function '||function_name||' from public';
    execute 'grant execute on function '||function_name||' to boardagent_server';
  end loop;
end
$governance_admin_functions$;
