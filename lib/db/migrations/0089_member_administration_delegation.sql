-- Exact-board authority is a capability record, never an organization role.
create function public.boardagent_administrative_citations(candidate_board uuid,candidate_evidence jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare citation jsonb; source record; version_ids uuid[];
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or jsonb_typeof(candidate_evidence) is distinct from 'array'
    or jsonb_array_length(candidate_evidence) not between 1 and 8 then
    raise exception 'administrative evidence is invalid' using errcode='22023';
  end if;
  if (select count(distinct value) from jsonb_array_elements(candidate_evidence))<>jsonb_array_length(candidate_evidence) then
    raise exception 'administrative evidence is duplicated' using errcode='22023';
  end if;
  for citation in select value from jsonb_array_elements(candidate_evidence) loop
    if jsonb_typeof(citation) is distinct from 'object' or citation-array['document_version_id','sha256','clause','locator']<>'{}'::jsonb
      or not(citation ?& array['document_version_id','sha256','clause','locator'])
      or jsonb_typeof(citation->'document_version_id') is distinct from 'string'
      or not public.boardagent_is_uuid_v7((citation->>'document_version_id')::uuid)
      or jsonb_typeof(citation->'sha256') is distinct from 'string' or coalesce(citation->>'sha256','')!~'^[0-9a-f]{64}$'
      or jsonb_typeof(citation->'clause') is distinct from 'string' or length(citation->>'clause') not between 1 and 1024
      or jsonb_typeof(citation->'locator') is distinct from 'string' or length(citation->>'locator') not between 1 and 1024
      or position(chr(13) in (citation->>'clause')||(citation->>'locator'))>0
      or normalize(citation->>'clause',NFC) is distinct from citation->>'clause'
      or normalize(citation->>'locator',NFC) is distinct from citation->>'locator' then
      raise exception 'administrative citation is invalid' using errcode='22023';
    end if;
  end loop;
  select array_agg(distinct (value->>'document_version_id')::uuid order by (value->>'document_version_id')::uuid)
    into version_ids from jsonb_array_elements(candidate_evidence);
  -- Reuse the existing ACL/exclusion/onboarding/scope check and document locking.
  for source in select * from public.boardagent_lock_visible_question_citations(version_ids) loop
    if source.board_id is distinct from candidate_board or exists(select 1 from jsonb_array_elements(candidate_evidence) c
      where (c.value->>'document_version_id')::uuid=source.id and decode(c.value->>'sha256','hex')<>source.sha256) then
      raise exception 'administrative evidence is unavailable' using errcode='42501';
    end if;
    version_ids := array_remove(version_ids,source.id);
  end loop;
  if cardinality(version_ids)<>0 then raise exception 'administrative evidence is unavailable' using errcode='42501'; end if;
  return candidate_evidence;
end
$$;
alter function public.boardagent_administrative_citations(uuid,jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_administrative_citations(uuid,jsonb) from public;

create function public.boardagent_member_admin_delegation_effective(candidate_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public
as $$
  select current_setting('boardagent.transaction_scope',true)='request' and exists(
    select 1 from public.member_admin_delegations d
    join public.members m on m.organization_id=d.organization_id and m.id=d.member_id
    join public.boards b on b.organization_id=d.organization_id and b.id=d.board_id
    join public.board_memberships s on s.organization_id=d.organization_id and s.board_id=d.board_id
      and s.member_id=d.member_id and s.id=d.secretary_membership_id
    where d.organization_id=public.boardagent_context_uuid('boardagent.organization_id') and d.id=candidate_id
      and d.state='active' and d.expires_at>transaction_timestamp() and b.state='active'
      and m.state='active' and m.member_kind='human' and s.state='active' and s.is_secretary
      and s.seat_role<>'observer' and s.active_from<=transaction_timestamp()
      and (s.active_until is null or s.active_until>transaction_timestamp())
      and not exists(select 1 from public.membership_versions v where v.organization_id=d.organization_id
        and v.membership_id=d.secretary_membership_id and v.version>d.secretary_membership_version
        and (not v.is_secretary or v.seat_role='observer'
          or coalesce(v.authority_snapshot->'after'->>'state','active')<>'active'
          or coalesce(v.authority_snapshot->'memberAfter'->>'state','active')<>'active'))
  )
$$;
alter function public.boardagent_member_admin_delegation_effective(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_member_admin_delegation_effective(uuid) from public;

create function public.boardagent_member_admin_delegation_snapshot(candidate_request jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  change jsonb := candidate_request->'change';
  action text := change->>'operation';
  fields text[]; field text;
  board uuid; identifier uuid; target_id uuid; expires timestamptz;
  actor_member public.members%rowtype; target_member public.members%rowtype;
  seat public.board_memberships%rowtype; seat_version integer;
  existing public.member_admin_delegations%rowtype;
  evidence jsonb; before_record jsonb := null; after_record jsonb; record_version bigint := 1;
  admin_after boolean;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable' or org is null or actor is null then
    raise exception 'delegation requires a managed serializable request' using errcode='25000';
  end if;
  if jsonb_typeof(candidate_request) is distinct from 'object'
    or candidate_request-array['schema_version','idempotency_key','change']<>'{}'::jsonb
    or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
    or jsonb_typeof(candidate_request->'idempotency_key') is distinct from 'string'
    or coalesce(candidate_request->>'idempotency_key','')!~'^[A-Za-z0-9._~-]{16,200}$'
    or jsonb_typeof(change) is distinct from 'object' or coalesce(action,'') not in ('grant','revoke')
    or jsonb_typeof(change->'reason') is distinct from 'string' or coalesce(length(change->>'reason'),0) not between 1 and 2000
    or position(chr(13) in change->>'reason')>0 or normalize(change->>'reason',NFC) is distinct from change->>'reason' then
    raise exception 'delegation input is invalid' using errcode='22023';
  end if;
  fields := case action when 'grant' then array['operation','delegation_id','member_id','board_id','expected_member_version','expires_at','reason','authority_evidence']
    else array['operation','delegation_id','board_id','expected_delegation_version','reason'] end;
  if change-fields<>'{}'::jsonb or not(change ?& fields) then raise exception 'delegation fields are invalid' using errcode='22023'; end if;
  foreach field in array fields loop
    if field like '%_id' and (jsonb_typeof(change->field) is distinct from 'string' or not public.boardagent_is_uuid_v7((change->>field)::uuid)) then
      raise exception 'delegation identifier is invalid' using errcode='22023';
    elsif field like 'expected_%_version' then
      if jsonb_typeof(change->field) is distinct from 'number' or coalesce(change->>field,'')!~'^[1-9][0-9]{0,15}$'
        or (change->>field)::numeric>9007199254740991 then raise exception 'delegation version is invalid' using errcode='22023'; end if;
    end if;
  end loop;
  board := (change->>'board_id')::uuid; identifier := (change->>'delegation_id')::uuid;
  perform pg_advisory_xact_lock(hashtextextended(org::text,424286));
  if not exists(select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
    where t.organization_id=org and t.member_id=actor and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
      and 'secretariat:admin'=any(t.scope_set) and 'admin'=any(t.roles))
    or not public.boardagent_administrative_member_eligible(actor) then
    raise exception 'administrative delegation is unavailable' using errcode='42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(board::text,424251));
  perform 1 from public.boards b where b.organization_id=org and b.id=board and b.state='active' for update;
  if not found then raise exception 'administrative delegation is unavailable' using errcode='42501'; end if;
  if action='grant' then
    target_id := (change->>'member_id')::uuid;
    if jsonb_typeof(change->'expires_at') is distinct from 'string'
      or coalesce(change->>'expires_at','')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$' then
      raise exception 'delegation deadline is invalid' using errcode='22023';
    end if;
    expires := (change->>'expires_at')::timestamptz;
    if expires<=transaction_timestamp() or expires>transaction_timestamp()+interval '90 days' then
      raise exception 'delegation deadline is invalid' using errcode='22023';
    end if;
    if exists(select 1 from public.member_admin_delegations d where d.organization_id=org and d.id=identifier) then
      raise exception 'administrative delegation is unavailable' using errcode='42501';
    end if;
  else
    select d.* into existing from public.member_admin_delegations d where d.organization_id=org and d.board_id=board and d.id=identifier for update;
    if existing.id is null or existing.state<>'active' or existing.row_version<>(change->>'expected_delegation_version')::bigint then
      raise exception 'administrative delegation is unavailable' using errcode='42501';
    end if;
    target_id := existing.member_id; expires := existing.expires_at; evidence := existing.authority_evidence;
  end if;
  perform 1 from public.members m where m.organization_id=org and m.id=any(array[actor,target_id]) order by m.id for update;
  select m.* into actor_member from public.members m where m.organization_id=org and m.id=actor;
  select m.* into target_member from public.members m where m.organization_id=org and m.id=target_id;
  if target_member.id is null then raise exception 'administrative delegation is unavailable' using errcode='42501'; end if;
  if action='grant' then
    select s.* into seat from public.board_memberships s where s.organization_id=org and s.board_id=board and s.member_id=target_id
      and s.state='active' and s.is_secretary and s.seat_role<>'observer' and s.active_from<=transaction_timestamp()
      and (s.active_until is null or s.active_until>transaction_timestamp()) order by s.id limit 1 for update;
    select max(v.version) into seat_version from public.membership_versions v where v.organization_id=org and v.membership_id=seat.id;
    if target_member.row_version<>(change->>'expected_member_version')::bigint or not public.boardagent_administrative_member_eligible(target_id)
      or seat.id is null or seat_version is null or exists(select 1 from public.member_admin_delegations d
        where d.organization_id=org and d.board_id=board and d.member_id=target_id and public.boardagent_member_admin_delegation_effective(d.id)) then
      raise exception 'administrative delegation is unavailable' using errcode='42501';
    end if;
    evidence := public.boardagent_administrative_citations(board,change->'authority_evidence');
    after_record := jsonb_build_object('delegationId',identifier,'boardId',board,'memberId',target_id,'issuerMemberId',actor,
      'secretaryMembershipId',seat.id,'secretaryMembershipVersion',seat_version,'state','active','rowVersion','1',
      'expiresAt',expires,'authorityEvidence',evidence,'powers',jsonb_build_array('manage_ordinary_voting_directors'));
  else
    record_version := 2;
    -- Revocation must remain possible after source access is withdrawn. Do not disclose
    -- retained source citations in this confirmation; their original evidence remains.
    before_record := jsonb_build_object('delegationId',identifier,'boardId',board,'memberId',target_id,'issuerMemberId',existing.issuer_member_id,
      'secretaryMembershipId',existing.secretary_membership_id,'secretaryMembershipVersion',existing.secretary_membership_version,
      'state','active','rowVersion','1','expiresAt',expires,'powers',jsonb_build_array('manage_ordinary_voting_directors'));
    after_record := before_record||jsonb_build_object('state','revoked','rowVersion','2','powers','[]'::jsonb);
  end if;
  admin_after := exists(select 1 from public.organization_role_assignments a where a.organization_id=org and a.member_id=target_id
    and a.role='admin' and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp()));
  return jsonb_build_object('operation',action,'recordType','member_admin_delegation','recordId',identifier,'recordVersion',record_version::text,
    'boardId',board,'actorMemberId',actor,'actorDisplayName',actor_member.display_name,'actorIdentityGeneration',actor_member.identity_generation::text,
    'targetMemberId',target_id,'targetDisplayName',target_member.display_name,'targetIdentityGeneration',target_member.identity_generation::text,
    'targetMemberVersion',target_member.row_version::text,'issuerMemberId',actor,'issuerIdentityGeneration',actor_member.identity_generation::text,
    'before',before_record,'after',after_record,'eventType',case action when 'grant' then 'member_admin_delegation_granted' else 'member_admin_delegation_revoked' end,
    'affectedMemberIds',jsonb_build_array(target_id),'memberChanges',jsonb_build_array(jsonb_build_object('memberId',target_id,'displayName',target_member.display_name,
      'beforeIdentityGeneration',target_member.identity_generation::text,'afterIdentityGeneration',(target_member.identity_generation+1)::text,
      'beforeRowVersion',target_member.row_version::text,'afterRowVersion',(target_member.row_version+1)::text,'adminAfter',admin_after)));
end
$$;
alter function public.boardagent_member_admin_delegation_snapshot(jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_member_admin_delegation_snapshot(jsonb) from public;
grant execute on function public.boardagent_member_admin_delegation_snapshot(jsonb) to boardagent_server;
