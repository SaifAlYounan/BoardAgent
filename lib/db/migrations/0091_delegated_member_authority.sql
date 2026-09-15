-- One live capability projection for both member-invite and member-lifecycle paths.
create function public.boardagent_member_administration_authority(candidate_request jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  change jsonb := candidate_request->'change'; action text := change->>'operation';
  selected_board uuid; target_id uuid; board_record record; actor_is_admin boolean;
  actor_generation bigint; target public.members%rowtype; seat public.board_memberships%rowtype;
  delegation public.member_admin_delegations%rowtype; evidence jsonb; fields text[];
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable' or org is null or actor is null then
    raise exception 'member administration requires a managed serializable request' using errcode='25000';
  end if;
  if jsonb_typeof(candidate_request) is distinct from 'object'
    or candidate_request-array['schema_version','change','idempotency_key','authority_evidence']<>'{}'::jsonb
    or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
    or jsonb_typeof(candidate_request->'idempotency_key') is distinct from 'string'
    or coalesce(candidate_request->>'idempotency_key','')!~'^[A-Za-z0-9._~-]{16,200}$'
    or jsonb_typeof(change) is distinct from 'object' or coalesce(action,'') not in ('invite','suspend','remove','reactivate','change_seat') then
    raise exception 'member administrative input is invalid' using errcode='22023';
  end if;
  fields := case action when 'invite' then array['operation','member_id','board_id','member_kind','seat_role','legal_name','display_name','voting_weight','accountable_principal_id']
    when 'change_seat' then array['operation','member_id','board_id','reason','seat_role','voting_weight','is_secretary']
    else array['operation','member_id','board_id','reason'] end;
  if change-(fields||case when action='invite' then array['reason'] else array[]::text[] end)<>'{}'::jsonb or not(change ?& fields)
    or jsonb_typeof(change->'member_id') is distinct from 'string'
    or not public.boardagent_is_uuid_v7((change->>'member_id')::uuid)
    or jsonb_typeof(change->'board_id') not in ('string','null') then
    raise exception 'member administrative fields are invalid' using errcode='22023';
  end if;
  selected_board := (change->>'board_id')::uuid; target_id := (change->>'member_id')::uuid;
  if (selected_board is not null and not public.boardagent_is_uuid_v7(selected_board))
    or (action in ('invite','change_seat') and selected_board is null)
    or (change ? 'reason' and (jsonb_typeof(change->'reason') is distinct from 'string'
      or coalesce(length(change->>'reason'),0) not between 1 and case when action='invite' then 2000 else 65536 end
      or position(chr(13) in change->>'reason')>0 or normalize(change->>'reason',NFC) is distinct from change->>'reason')) then
    raise exception 'member administrative reason or board is invalid' using errcode='22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(org::text,424286));
  select 'admin'=any(t.roles) into actor_is_admin from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
    where t.organization_id=org and t.member_id=actor and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
      and 'secretariat:admin'=any(t.scope_set);
  if actor_is_admin is null or not public.boardagent_administrative_member_eligible(actor) then
    raise exception 'member administration is unavailable' using errcode='42501';
  end if;
  for board_record in select b.id,b.state from public.boards b where b.organization_id=org
    and (b.id=selected_board or (selected_board is null and exists(select 1 from public.board_memberships s
      where s.organization_id=org and s.member_id=target_id and s.board_id=b.id))) order by b.id loop
    perform pg_advisory_xact_lock(hashtextextended(board_record.id::text,424251));
    perform 1 from public.boards b where b.organization_id=org and b.id=board_record.id for update;
  end loop;
  perform pg_advisory_xact_lock(hashtextextended(target_id::text,424252));
  select m.* into target from public.members m where m.organization_id=org and m.id=target_id for update;
  if actor_is_admin then
    if candidate_request ? 'authority_evidence' then
      evidence := public.boardagent_administrative_citations(selected_board,candidate_request->'authority_evidence');
      select identity_generation into actor_generation from public.members where organization_id=org and id=actor;
      return jsonb_build_object('mode','company_admin','actorMemberId',actor,'actorIdentityGeneration',actor_generation::text,
        'boardId',selected_board,'appointmentEvidence',evidence);
    end if;
    return null;
  end if;
  if selected_board is null or target_id=actor or not(candidate_request ? 'authority_evidence')
    or jsonb_typeof(change->'reason') is distinct from 'string' or coalesce(length(change->>'reason'),0) not between 1 and 2000 then
    raise exception 'member administration is unavailable' using errcode='42501';
  end if;
  select d.* into delegation from public.member_admin_delegations d where d.organization_id=org and d.member_id=actor
    and d.board_id=selected_board and public.boardagent_member_admin_delegation_effective(d.id) order by d.created_at,d.id limit 1 for update;
  if delegation.id is null then raise exception 'member administration is unavailable' using errcode='42501'; end if;
  if action='invite' then
    if target.id is not null or change->>'member_kind' is distinct from 'human' or change->>'seat_role' is distinct from 'voting_member'
      or change->'accountable_principal_id' is distinct from 'null'::jsonb then
      raise exception 'member administration is unavailable' using errcode='42501';
    end if;
  else
    select s.* into seat from public.board_memberships s where s.organization_id=org and s.board_id=selected_board and s.member_id=target_id
      order by s.created_at desc,s.id desc limit 1 for update;
    if target.id is null or target.state<>'active' or target.member_kind<>'human' or seat.id is null
      or seat.seat_role<>'voting_member' or seat.is_secretary
      or (action='change_seat' and (change->>'seat_role' is distinct from 'voting_member' or change->'is_secretary' is distinct from 'false'::jsonb))
      or exists(select 1 from public.organization_role_assignments a where a.organization_id=org and a.member_id=target_id and a.role='admin'
        and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp()))
      or exists(select 1 from public.board_memberships s where s.organization_id=org and s.member_id=target_id and s.is_secretary
        and s.state='active' and s.active_from<=transaction_timestamp() and (s.active_until is null or s.active_until>transaction_timestamp()))
      or exists(select 1 from public.member_admin_delegations d where d.organization_id=org and d.member_id=target_id
        and d.state='active' and d.expires_at>transaction_timestamp()) then
      raise exception 'member administration is unavailable' using errcode='42501';
    end if;
  end if;
  evidence := public.boardagent_administrative_citations(selected_board,candidate_request->'authority_evidence');
  select identity_generation into actor_generation from public.members where organization_id=org and id=actor;
  return jsonb_build_object('mode','delegated','actorMemberId',actor,'actorIdentityGeneration',actor_generation::text,
    'boardId',selected_board,'delegationId',delegation.id,'delegationVersion',delegation.row_version::text,
    'secretaryMembershipId',delegation.secretary_membership_id,'secretaryMembershipVersion',delegation.secretary_membership_version,
    'expiresAt',delegation.expires_at,'appointmentEvidence',evidence);
end
$$;
alter function public.boardagent_member_administration_authority(jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_member_administration_authority(jsonb) from public;
grant execute on function public.boardagent_member_administration_authority(jsonb) to boardagent_server;

-- Organization-admin citations may span readable boards; delegated calls always bind one board.
create or replace function public.boardagent_administrative_citations(candidate_board uuid,candidate_evidence jsonb)
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
    if (candidate_board is not null and source.board_id is distinct from candidate_board) or exists(select 1 from jsonb_array_elements(candidate_evidence) c
      where (c.value->>'document_version_id')::uuid=source.id and decode(c.value->>'sha256','hex')<>source.sha256) then
      raise exception 'administrative evidence is unavailable' using errcode='42501';
    end if;
    version_ids := array_remove(version_ids,source.id);
  end loop;
  if cardinality(version_ids)<>0 then raise exception 'administrative evidence is unavailable' using errcode='42501'; end if;
  return candidate_evidence;
end
$$;

-- Replaces the original function while retaining its state/history rules.
create or replace function public.boardagent_member_lifecycle_snapshot(candidate_request jsonb)
returns jsonb language plpgsql volatile security definer
set search_path=pg_catalog,public
as $$
declare
  administrative_authority jsonb;
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  change jsonb := candidate_request->'change';
  operation text := change->>'operation';
  target_member_id uuid;
  selected_board_id uuid;
  target public.members%rowtype;
  seat public.board_memberships%rowtype;
  board_record record;
  before_seats jsonb := '[]';
  after_seats jsonb := '[]';
  before_member jsonb;
  after_member jsonb;
  item jsonb;
  next_item jsonb;
  next_state text;
  next_secretary boolean;
  next_role text;
  next_weight bigint;
  next_chair boolean;
  next_member_state text;
  seat_count integer := 0;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or org is null or actor is null then
    raise exception 'member lifecycle requires a managed serializable request' using errcode='25000';
  end if;
  if coalesce(jsonb_typeof(candidate_request),'')<>'object'
     or candidate_request - array['schema_version','change','idempotency_key','authority_evidence']<>'{}'::jsonb
     or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
     or coalesce(candidate_request->>'idempotency_key','') !~ '^[A-Za-z0-9._~-]{16,200}$'
     or coalesce(jsonb_typeof(change),'')<>'object'
     or coalesce(operation,'') not in ('suspend','remove','reactivate','change_seat')
     or not (change ?& array['operation','member_id','board_id','reason'])
     or coalesce(length(change->>'reason'),0) not between 1 and 65536 then
    raise exception 'member lifecycle input is invalid' using errcode='22023';
  end if;
  if operation='change_seat' then
    if change - array['operation','member_id','board_id','reason','seat_role','voting_weight','is_secretary']<>'{}'::jsonb
       or not (change ?& array['seat_role','voting_weight','is_secretary'])
       or jsonb_typeof(change->'is_secretary') is distinct from 'boolean'
       or jsonb_typeof(change->'voting_weight') is distinct from 'number'
       or coalesce(change->>'seat_role','') not in ('voting_member','management','observer') then
      raise exception 'member seat input is invalid' using errcode='22023';
    end if;
    next_role := change->>'seat_role';
    next_weight := (change->>'voting_weight')::bigint;
    next_secretary := (change->>'is_secretary')::boolean;
    if (change->>'voting_weight')::numeric<>next_weight
       or (next_role='voting_member' and next_weight not between 1 and 1000000000)
       or (next_role<>'voting_member' and next_weight<>0)
       or (next_role='observer' and next_secretary) then
      raise exception 'member seat authority is invalid' using errcode='22023';
    end if;
  elsif change - array['operation','member_id','board_id','reason']<>'{}'::jsonb then
    raise exception 'member lifecycle input has unknown fields' using errcode='22023';
  end if;
  target_member_id := (change->>'member_id')::uuid;
  selected_board_id := (change->>'board_id')::uuid;
  if target_member_id is null or not public.boardagent_is_uuid_v7(target_member_id)
     or (selected_board_id is not null and not public.boardagent_is_uuid_v7(selected_board_id))
     or (operation='change_seat' and selected_board_id is null) then
    raise exception 'member lifecycle target is invalid' using errcode='22023';
  end if;

  -- Serialize administrators' final-seat checks, then use the existing board/member
  -- aggregate lock order. PostgreSQL serializable retry handles concurrent other flows.
  perform pg_advisory_xact_lock(hashtextextended(org::text,424286));
  administrative_authority := public.boardagent_member_administration_authority(candidate_request);
  for board_record in
    select b.id,b.state from public.boards b where b.organization_id=org
      and (b.id=selected_board_id or (selected_board_id is null and exists (
        select 1 from public.board_memberships m where m.organization_id=org
          and m.member_id=target_member_id and m.board_id=b.id))) order by b.id
  loop
    perform pg_advisory_xact_lock(hashtextextended(board_record.id::text,424251));
    perform 1 from public.boards b where b.id=board_record.id for update;
    if selected_board_id is not null and board_record.state<>'active' then
      raise exception 'member board is unavailable' using errcode='P0002';
    end if;
  end loop;
  perform pg_advisory_xact_lock(hashtextextended(target_member_id::text,424252));
  select m.* into target from public.members m where m.organization_id=org and m.id=target_member_id for update;
  if target.id is null or target.state not in ('active','suspended','removed') then
    raise exception 'member lifecycle target is unavailable' using errcode='P0002';
  end if;
  if selected_board_id is not null and target.state<>'active' then
    raise exception 'reactivate the person before changing board authority' using errcode='23514';
  end if;
  next_member_state := target.state;
  if selected_board_id is null then
    if (operation='suspend' and target.state<>'active')
       or (operation='remove' and target.state not in ('active','suspended'))
       or (operation='reactivate' and target.state not in ('suspended','removed')) then
      raise exception 'member lifecycle transition is invalid' using errcode='23514';
    end if;
    next_member_state := case operation when 'suspend' then 'suspended' when 'remove' then 'removed' else 'active' end;
    if next_member_state<>'active' and exists (
      select 1 from public.organization_role_assignments a where a.organization_id=org
        and a.member_id=target_member_id and a.role='admin' and a.active_from<=transaction_timestamp()
        and (a.active_until is null or a.active_until>transaction_timestamp())
    ) and not exists (
      select 1 from public.organization_role_assignments a join public.members m on m.organization_id=a.organization_id and m.id=a.member_id
       where a.organization_id=org and a.member_id<>target_member_id and a.role='admin'
         and m.state='active' and a.active_from<=transaction_timestamp()
         and (a.active_until is null or a.active_until>transaction_timestamp())
    ) then
      raise exception 'cannot disable the final active administrator' using errcode='23514';
    end if;
  end if;
  before_member := jsonb_build_object('memberId',target.id,'displayName',target.display_name,
    'memberKind',target.member_kind,'state',target.state,'identityGeneration',target.identity_generation::text,
    'rowVersion',target.row_version::text,'organizationRoles',to_jsonb(array(
      select distinct a.role from public.organization_role_assignments a where a.organization_id=org and a.member_id=target_member_id
       and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp()) order by a.role)));
  after_member := before_member||jsonb_build_object('state',next_member_state,
    'identityGeneration',(target.identity_generation+1)::text,'rowVersion',(target.row_version+1)::text);
  for seat in
    select m.* from public.board_memberships m where m.organization_id=org and m.member_id=target_member_id
      and (selected_board_id is null or m.board_id=selected_board_id)
      and m.id=(select latest.id from public.board_memberships latest
        where latest.organization_id=org and latest.member_id=target_member_id and latest.board_id=m.board_id
        order by latest.created_at desc,latest.id desc limit 1)
      order by m.board_id,m.id for update
  loop
    seat_count := seat_count+1;
    next_state := seat.state;
    if selected_board_id is not null then
      if (operation in ('suspend','change_seat') and seat.state<>'active')
         or (operation='remove' and seat.state not in ('active','suspended'))
         or (operation='reactivate' and seat.state not in ('suspended','ended')) then
        raise exception 'board membership transition is invalid' using errcode='23514';
      end if;
      next_state := case operation when 'suspend' then 'suspended' when 'remove' then 'ended' else 'active' end;
    elsif operation='remove' then
      next_state := 'ended';
    end if;
    if operation<>'change_seat' then
      next_role := seat.seat_role; next_weight := seat.voting_weight; next_secretary := seat.is_secretary;
    end if;
    if target.member_kind='ai_system' and (next_role<>'observer' or next_secretary) then
      raise exception 'AI members must remain observers' using errcode='23514';
    end if;
    next_chair := seat.is_chair and next_role='voting_member';
    if seat.is_secretary and seat.state='active'
       and (next_member_state<>'active' or next_state<>'active' or not next_secretary)
       and exists(select 1 from public.boards b where b.id=seat.board_id and b.state='active')
       and not exists (
        select 1 from public.board_memberships other join public.members m on m.organization_id=other.organization_id and m.id=other.member_id
         where other.organization_id=org and other.board_id=seat.board_id and other.member_id<>target_member_id
           and other.state='active' and other.is_secretary and m.state='active'
           and other.active_from<=transaction_timestamp() and (other.active_until is null or other.active_until>transaction_timestamp())
       ) then
      raise exception 'cannot disable the final active board secretary' using errcode='23514';
    end if;
    item := jsonb_build_object('membershipId',seat.id,'boardId',seat.board_id,'seatRole',seat.seat_role,
      'isSecretary',seat.is_secretary,'isChair',seat.is_chair,'votingWeight',seat.voting_weight::text,
      'state',seat.state,'entitlementGeneration',seat.entitlement_generation::text);
    next_item := item||jsonb_build_object('seatRole',next_role,'isSecretary',next_secretary,
      'isChair',next_chair,'votingWeight',next_weight::text,'state',next_state,
      'entitlementGeneration',(seat.entitlement_generation+1)::text);
    if operation='change_seat' and item - 'entitlementGeneration'=next_item - 'entitlementGeneration' then
      raise exception 'member seat change has no effect' using errcode='23514';
    end if;
    before_seats := before_seats||jsonb_build_array(item);
    after_seats := after_seats||jsonb_build_array(next_item);
  end loop;
  if selected_board_id is not null and seat_count<>1 then
    raise exception 'member board is unavailable' using errcode='P0002';
  end if;
  return jsonb_build_object('memberBefore',before_member,'memberAfter',after_member,
    'seatsBefore',before_seats,'seatsAfter',after_seats,
    'connectionEffect','All existing sessions, access tokens, refresh families and unused authorization codes are revoked. Sign in again.')
    ||case when administrative_authority is null then '{}'::jsonb else jsonb_build_object('administrativeAuthority',administrative_authority) end;
end
$$;


create or replace function public.boardagent_finalize_member_lifecycle(
  candidate_request jsonb,candidate_payload_sha256 bytea,candidate_consent_id uuid,
  candidate_audit_id uuid,candidate_versions jsonb,candidate_idempotency_id uuid,
  candidate_request_sha256 bytea
)
returns void language plpgsql volatile security definer
set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  target_member_id uuid := (candidate_request->'change'->>'member_id')::uuid;
  selected_board_id uuid := (candidate_request->'change'->>'board_id')::uuid;
  snapshot jsonb;
  payload jsonb;
  consent public.consent_records%rowtype;
  stage public.action_stages%rowtype;
  next_seat jsonb;
  old_seat jsonb;
  version jsonb;
  version_bytes bytea;
  expected_version jsonb;
  feed record;
  tombstone_payload text;
  next_version integer;
  retained_snapshot_id uuid;
begin
  snapshot := public.boardagent_member_lifecycle_snapshot(candidate_request);
  payload := jsonb_build_object('schemaVersion','boardagent.member-lifecycle.v1','request',candidate_request,'current',snapshot);
  select c.* into consent from public.consent_records c
   where c.id=candidate_consent_id and c.organization_id=org and c.actor_member_id=actor
     and c.client_id=public.boardagent_context_uuid('boardagent.client_id')
     and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
     and c.board_id is not distinct from selected_board_id and c.action_code='manage_member'
     and c.target_type='member' and c.target_id=target_member_id
     and c.payload_sha256=candidate_payload_sha256 and c.confirmed_at=transaction_timestamp();
  select s.* into stage from public.action_stages s where s.id=consent.stage_id
    and s.state='active' and s.payload_sha256=candidate_payload_sha256;
  if consent.id is null or stage.id is null or pg_catalog.sha256(stage.canonical_payload)<>candidate_payload_sha256
     or convert_from(stage.canonical_payload,'UTF8')::jsonb<>payload then
    raise exception 'member lifecycle requires its exact fresh unchanged consent' using errcode='42501';
  end if;
  if not exists(select 1 from public.audit_events a where a.id=candidate_audit_id and a.organization_id=org
    and a.actor_member_id=actor and a.consent_record_id=candidate_consent_id
    and a.event_type='member_changed' and a.object_type='member' and a.object_id=target_member_id
    and a.board_id is not distinct from selected_board_id
    and a.client_id=consent.client_id and a.token_jti=consent.token_jti
    and a.object_version=(snapshot->'memberAfter'->>'rowVersion')::bigint
    and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'=jsonb_build_object(
      'operation',candidate_request->'change'->>'operation','payloadSha256',encode(candidate_payload_sha256,'hex'),
      'before',snapshot->'memberBefore','after',snapshot->'memberAfter','seatsBefore',snapshot->'seatsBefore','seatsAfter',snapshot->'seatsAfter')
      ||case when snapshot ? 'administrativeAuthority' then jsonb_build_object('administrativeAuthority',snapshot->'administrativeAuthority') else '{}'::jsonb end) then
    raise exception 'member lifecycle requires its appended audit' using errcode='42501';
  end if;
  if not exists(select 1 from public.input_required_attempts attempt where attempt.id=consent.input_required_attempt_id
      and attempt.stage_id=stage.id and attempt.original_arguments_sha256=candidate_request_sha256) then
    raise exception 'member lifecycle idempotency request binding is invalid' using errcode='42501';
  end if;
  -- The stage retry path supplies safe one-use retry semantics. Reusing the application
  -- idempotency key in a new ceremony must never apply a later authority change again.
  insert into public.idempotency_records(id,organization_id,actor_member_id,client_id,operation,
    idempotency_key,request_sha256,state,expires_at,completed_at,safe_response_type,safe_response_id,safe_response_sha256)
   values(candidate_idempotency_id,org,actor,consent.client_id,'manage_member',candidate_request->>'idempotency_key',
    candidate_request_sha256,'succeeded',transaction_timestamp()+interval '24 hours',transaction_timestamp(),
    'member',target_member_id,candidate_payload_sha256);
  if coalesce(jsonb_typeof(candidate_versions),'')<>'array'
     or jsonb_array_length(candidate_versions)<>jsonb_array_length(snapshot->'seatsAfter') then
    raise exception 'membership version set is incomplete' using errcode='23514';
  end if;
  for next_seat in select value from jsonb_array_elements(snapshot->'seatsAfter') loop
    select value into old_seat from jsonb_array_elements(snapshot->'seatsBefore') where value->>'membershipId'=next_seat->>'membershipId';
    if (select count(*) from jsonb_array_elements(candidate_versions) where value->>'membershipId'=next_seat->>'membershipId')<>1 then
      raise exception 'membership version is missing or duplicated' using errcode='23514';
    end if;
    select value into version from jsonb_array_elements(candidate_versions) where value->>'membershipId'=next_seat->>'membershipId';
    version_bytes := decode(version->>'canonicalHex','hex');
    expected_version := jsonb_build_object('schemaVersion','boardagent.membership-lifecycle-authority.v1',
      'operation',candidate_request->'change'->>'operation','memberBefore',snapshot->'memberBefore',
      'memberAfter',snapshot->'memberAfter','before',old_seat,'after',next_seat)
      ||case when snapshot ? 'administrativeAuthority' then jsonb_build_object('administrativeAuthority',snapshot->'administrativeAuthority') else '{}'::jsonb end;
    if convert_from(version_bytes,'UTF8')::jsonb<>expected_version then
      raise exception 'membership authority snapshot is invalid' using errcode='23514';
    end if;
    update public.board_memberships m set state=next_seat->>'state',seat_role=next_seat->>'seatRole',
      is_secretary=(next_seat->>'isSecretary')::boolean,is_chair=(next_seat->>'isChair')::boolean,
      voting_weight=(next_seat->>'votingWeight')::bigint,entitlement_generation=(next_seat->>'entitlementGeneration')::bigint,
      active_from=case when m.state='ended' and next_seat->>'state'='active' then transaction_timestamp() else m.active_from end,
      -- Preserve any existing access deadline for a changed or suspended seat.
      -- Only explicit reactivation of an ended seat starts a fresh active window.
      active_until=case when next_seat->>'state'='ended' then coalesce(m.active_until,greatest(transaction_timestamp(),m.active_from+interval '1 microsecond'))
        when m.state='ended' and next_seat->>'state'='active' then null else m.active_until end
     where m.id=(next_seat->>'membershipId')::uuid and m.organization_id=org;
    select coalesce(max(v.version),0)+1 into next_version from public.membership_versions v where v.membership_id=(next_seat->>'membershipId')::uuid;
    insert into public.membership_versions(id,organization_id,board_id,member_id,membership_id,version,
      seat_role,is_secretary,voting_weight,authority_snapshot,snapshot_sha256,change_reason,actor_member_id,consent_record_id,audit_event_id)
     values((version->>'id')::uuid,org,(next_seat->>'boardId')::uuid,target_member_id,(next_seat->>'membershipId')::uuid,next_version,
      next_seat->>'seatRole',(next_seat->>'isSecretary')::boolean,(next_seat->>'votingWeight')::bigint,
      expected_version,pg_catalog.sha256(version_bytes),candidate_request->'change'->>'reason',actor,candidate_consent_id,candidate_audit_id);
    if candidate_request->'change'->>'operation'='remove' then
      retained_snapshot_id := pg_catalog.uuidv7();
      insert into public.retention_snapshots(id,organization_id,board_id,object_type,object_id,object_version,canonical_schema,canonical_payload,canonical_sha256,content_references)
       values(retained_snapshot_id,org,(next_seat->>'boardId')::uuid,'board_membership',(next_seat->>'membershipId')::uuid,
         (snapshot->'memberAfter'->>'rowVersion')::bigint,'boardagent.member-lifecycle.v1',stage.canonical_payload,stage.payload_sha256,'[]');
      insert into public.deletion_tombstones(id,organization_id,board_id,object_type,object_id,snapshot_id,actor_member_id,reason)
       values(pg_catalog.uuidv7(),org,(next_seat->>'boardId')::uuid,'board_membership',(next_seat->>'membershipId')::uuid,
         retained_snapshot_id,actor,candidate_request->'change'->>'reason') on conflict (object_type,object_id) do nothing;
    end if;
    -- Current entitlement is checked synchronously on reads. Also remove stale pending
    -- projections in this same transaction, preserving the source audit association.
    for feed in select f.* from public.pending_action_feed f where f.organization_id=org and f.member_id=target_member_id
      and f.board_id=(next_seat->>'boardId')::uuid and f.state='pending' order by f.feed_sequence,f.id for update loop
      -- All substituted values have UUID, integer-string or restricted enum syntax;
      -- this is canonical JSON with sorted keys, matching the existing tombstone schema.
      tombstone_payload := format('{"boardId":"%s","entitlementGeneration":"%s","feedSequence":"%s","memberId":"%s","objectId":"%s","objectType":"%s","priorEntitlementGeneration":"%s","reasonClass":"revoked","removedFeedId":"%s","schemaVersion":"boardagent.feed-tombstone.v1","source":"member_lifecycle"}',
        feed.board_id,next_seat->>'entitlementGeneration',feed.feed_sequence,target_member_id,feed.object_id,feed.object_type,feed.entitlement_generation,feed.id);
      update public.pending_action_feed set state='superseded',resolved_at=transaction_timestamp() where id=feed.id;
      insert into public.feed_tombstones(id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
        removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id)
       values(pg_catalog.uuidv7(),org,feed.board_id,target_member_id,(next_seat->>'entitlementGeneration')::bigint,feed.feed_sequence,
         feed.id,feed.object_type,feed.object_id,'revoked',pg_catalog.sha256(convert_to(tombstone_payload,'UTF8')),feed.audit_event_id);
    end loop;
  end loop;
  if candidate_request->'change'->>'operation'='remove' and selected_board_id is null then
    retained_snapshot_id := pg_catalog.uuidv7();
    insert into public.retention_snapshots(id,organization_id,board_id,object_type,object_id,object_version,canonical_schema,canonical_payload,canonical_sha256,content_references)
     values(retained_snapshot_id,org,null,'member',target_member_id,(snapshot->'memberAfter'->>'rowVersion')::bigint,
       'boardagent.member-lifecycle.v1',stage.canonical_payload,stage.payload_sha256,'[]');
    insert into public.deletion_tombstones(id,organization_id,board_id,object_type,object_id,snapshot_id,actor_member_id,reason)
     values(pg_catalog.uuidv7(),org,null,'member',target_member_id,retained_snapshot_id,actor,candidate_request->'change'->>'reason')
     on conflict (object_type,object_id) do nothing;
  end if;
  update public.members set state=snapshot->'memberAfter'->>'state',
    identity_generation=(snapshot->'memberAfter'->>'identityGeneration')::bigint,
    row_version=(snapshot->'memberAfter'->>'rowVersion')::bigint,
    hidden_at=case when snapshot->'memberAfter'->>'state'='removed' then transaction_timestamp() else null end
   where id=target_member_id and organization_id=org;
  update public.auth_sessions set state='revoked' where organization_id=org and member_id=target_member_id and state in ('anonymous','authenticated','expired');
  update public.refresh_families set state='revoked',revoked_at=transaction_timestamp() where organization_id=org and member_id=target_member_id and state='active';
  update public.access_token_records set revoked_at=transaction_timestamp() where organization_id=org and member_id=target_member_id and revoked_at is null;
  update public.oauth_authorization_codes set revoked_at=transaction_timestamp() where organization_id=org and member_id=target_member_id and consumed_at is null and revoked_at is null;
  update public.enrollment_invitations set revoked_at=transaction_timestamp() where organization_id=org and member_id=target_member_id and consumed_at is null and revoked_at is null;
  update public.action_stages set state='replaced' where organization_id=org and actor_member_id=target_member_id and state='active' and id<>stage.id;
end
$$;


-- Bare preparation is read-only; finalization additionally checks the entire cited request.
create or replace function public.boardagent_prepare_member_invite(
  candidate_board_id uuid,
  candidate_member_id uuid,
  candidate_member_kind text,
  candidate_seat_role text,
  candidate_voting_weight bigint,
  candidate_accountable_principal_id uuid
)
returns table(
  result_status text,
  result_board_name text,
  result_board_row_version bigint,
  result_persisted_member_kind text,
  result_accountable_principal_name text
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  context_organization_id uuid;
  context_actor_id uuid;
  target_board public.boards%rowtype;
  persisted_kind text;
  principal_name text;
  actor_ready boolean;
begin
  context_organization_id := public.boardagent_context_uuid('boardagent.organization_id');
  context_actor_id := public.boardagent_context_uuid('boardagent.member_id');
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or context_organization_id is null
     or context_actor_id is null then
    raise exception 'member invitation requires a managed serializable request transaction'
      using errcode='25000';
  end if;
  if candidate_board_id is null
     or candidate_member_id is null
     or not public.boardagent_is_uuid_v7(candidate_member_id)
     or candidate_member_kind not in ('human','ai_observer')
     or candidate_seat_role not in ('voting_member','management','observer')
     or candidate_voting_weight is null
     or candidate_voting_weight not between 0 and 1000000000 then
    raise exception 'member invitation inputs are invalid' using errcode='22023';
  end if;
  persisted_kind := case candidate_member_kind
    when 'human' then 'human'
    when 'ai_observer' then 'ai_system'
  end;

  perform pg_advisory_xact_lock(hashtextextended(context_organization_id::text,424286));
  -- Board first, then the not-yet-existing member identifier. This is the same stable
  -- aggregate order used by stage persistence and confirmation.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(candidate_board_id::text,424251::bigint)
  );
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(candidate_member_id::text,424252::bigint)
  );
  select board.* into target_board
    from public.boards as board
   where board.organization_id=context_organization_id
     and board.id=candidate_board_id
   for update;

  if candidate_accountable_principal_id is not null then
    select principal.legal_name into principal_name
      from public.accountable_principals as principal
     where principal.organization_id=context_organization_id
       and principal.id=candidate_accountable_principal_id;
  end if;
  select exists(select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
    where t.organization_id=context_organization_id and t.member_id=context_actor_id
      and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id') and 'secretariat:admin'=any(t.scope_set)
      and public.boardagent_administrative_member_eligible(context_actor_id)
      and ('admin'=any(t.roles) or (candidate_member_kind='human' and candidate_seat_role='voting_member'
        and candidate_member_id<>context_actor_id and candidate_accountable_principal_id is null
        and exists(select 1 from public.member_admin_delegations d where d.organization_id=context_organization_id
          and d.member_id=context_actor_id and d.board_id=candidate_board_id and public.boardagent_member_admin_delegation_effective(d.id))))) into actor_ready;

  if target_board.id is null
     or target_board.state<>'active'
     or not actor_ready
     or exists (
       select 1 from public.members as member
        where member.organization_id=context_organization_id
          and member.id=candidate_member_id
     )
     or (candidate_member_kind='human' and candidate_accountable_principal_id is not null)
     or (candidate_member_kind='ai_observer' and (
       candidate_accountable_principal_id is null
       or principal_name is null
       or candidate_seat_role<>'observer'
     ))
     or (candidate_seat_role='voting_member' and candidate_voting_weight<1)
     or (candidate_seat_role<>'voting_member' and candidate_voting_weight<>0) then
    return query select 'unavailable'::text,null::text,null::bigint,null::text,null::text;
    return;
  end if;
  return query select 'ready'::text,target_board.name,target_board.row_version,
    persisted_kind,principal_name;
end
$$;


-- The original internal signature accepted a claimed snapshot/response digest
-- without the corresponding bytes. Remove it so runtime callers cannot bypass
-- actual-byte verification. External manage_member arguments remain unchanged.
drop function public.boardagent_finalize_member_invite(
  uuid,uuid,text,text,text,text,bigint,uuid,text,bytea,bytea,uuid,uuid,uuid,uuid,
  uuid,jsonb,bytea,bytea
);
create function public.boardagent_finalize_member_invite(
  candidate_board_id uuid,
  candidate_member_id uuid,
  candidate_member_kind text,
  candidate_legal_name text,
  candidate_display_name text,
  candidate_seat_role text,
  candidate_voting_weight bigint,
  candidate_accountable_principal_id uuid,
  candidate_idempotency_key text,
  candidate_request_sha256 bytea,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid,
  candidate_idempotency_record_id uuid,
  candidate_membership_id uuid,
  candidate_membership_version_id uuid,
  candidate_audit_event_id uuid,
  candidate_authority_snapshot jsonb,
  candidate_authority_snapshot_sha256 bytea,
  candidate_safe_response_sha256 bytea,
  candidate_authority_snapshot_bytes bytea,
  candidate_safe_response_bytes bytea
)
returns table(
  result_status text,
  result_member_id uuid,
  result_membership_id uuid,
  result_member_row_version bigint,
  result_safe_response_sha256 bytea
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  administrative_authority jsonb;
  prepared record;
  consent public.consent_records%rowtype;
  stage public.action_stages%rowtype;
  audit public.audit_events%rowtype;
  idempotency public.idempotency_records%rowtype;
  inserted_idempotency_id uuid;
  stage_payload jsonb;
  expected_payload jsonb;
  audit_payload jsonb;
  expected_details jsonb;
  expected_snapshot jsonb;
  context_organization_id uuid;
  context_actor_id uuid;
  context_client_id uuid;
  context_token_jti uuid;
begin
  context_organization_id := public.boardagent_context_uuid('boardagent.organization_id');
  context_actor_id := public.boardagent_context_uuid('boardagent.member_id');
  context_client_id := public.boardagent_context_uuid('boardagent.client_id');
  context_token_jti := public.boardagent_context_uuid('boardagent.token_jti');
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or current_setting('transaction_isolation') is distinct from 'serializable' then
    raise exception 'member invitation requires a managed serializable request transaction'
      using errcode='25000';
  end if;
  if candidate_legal_name is null or length(candidate_legal_name) not between 1 and 512
     or candidate_display_name is null or length(candidate_display_name) not between 1 and 512
     or candidate_idempotency_key is null
     or length(candidate_idempotency_key) not between 16 and 200
     or candidate_idempotency_key !~ '^[A-Za-z0-9._~-]+$'
     or candidate_request_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_request_sha256)
     or candidate_payload_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_payload_sha256)
     or candidate_consent_record_id is null
     or candidate_idempotency_record_id is null
     or not public.boardagent_is_uuid_v7(candidate_idempotency_record_id)
     or candidate_membership_id is null
     or not public.boardagent_is_uuid_v7(candidate_membership_id)
     or candidate_membership_version_id is null
     or not public.boardagent_is_uuid_v7(candidate_membership_version_id)
     or candidate_audit_event_id is null
     or not public.boardagent_is_uuid_v7(candidate_audit_event_id)
     or candidate_authority_snapshot is null
     or jsonb_typeof(candidate_authority_snapshot)<>'object'
     or candidate_authority_snapshot_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_authority_snapshot_sha256)
     or candidate_safe_response_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_safe_response_sha256)
     or candidate_authority_snapshot_bytes is null
     or candidate_safe_response_bytes is null
     or octet_length(candidate_authority_snapshot_bytes) not between 2 and 65536
     or octet_length(candidate_safe_response_bytes) not between 2 and 4096
     or sha256(candidate_authority_snapshot_bytes)<>candidate_authority_snapshot_sha256
     or sha256(candidate_safe_response_bytes)<>candidate_safe_response_sha256 then
    raise exception 'member invitation finalization inputs are invalid' using errcode='22023';
  end if;

  select * into strict prepared
    from public.boardagent_prepare_member_invite(
      candidate_board_id,candidate_member_id,candidate_member_kind,candidate_seat_role,
      candidate_voting_weight,candidate_accountable_principal_id
    );
  if prepared.result_status is distinct from 'ready' then
    return query select 'unavailable'::text,null::uuid,null::uuid,null::bigint,null::bytea;
    return;
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      context_actor_id::text || chr(1) || context_client_id::text || chr(1) ||
        candidate_idempotency_key,
      424253::bigint
    )
  );
  insert into public.idempotency_records(
    id,organization_id,actor_member_id,client_id,operation,idempotency_key,
    request_sha256,state,expires_at
  ) values (
    candidate_idempotency_record_id,context_organization_id,context_actor_id,
    context_client_id,'manage_member',candidate_idempotency_key,
    candidate_request_sha256,'in_progress',transaction_timestamp()+interval '24 hours'
  )
  on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing
  returning id into inserted_idempotency_id;
  select record.* into idempotency
    from public.idempotency_records as record
   where record.actor_member_id=context_actor_id
     and record.client_id=context_client_id
     and record.operation='manage_member'
     and record.idempotency_key=candidate_idempotency_key
   for update;
  if idempotency.id is null then
    raise exception 'member invitation idempotency record is unavailable' using errcode='55000';
  end if;
  if not public.boardagent_constant_time_sha256_equal(
       idempotency.request_sha256,candidate_request_sha256
     ) then
    return query select 'idempotency_conflict'::text,null::uuid,null::uuid,
      null::bigint,null::bytea;
    return;
  end if;
  if inserted_idempotency_id is null then
    if idempotency.state='succeeded'
       and idempotency.safe_response_type='member'
       and idempotency.safe_response_id is not null
       and idempotency.safe_response_sha256 is not null then
      return query
        select 'replayed'::text,idempotency.safe_response_id,membership.id,
               member.row_version,idempotency.safe_response_sha256
          from public.members as member
          join public.board_memberships as membership
            on membership.organization_id=member.organization_id
           and membership.member_id=member.id
           and membership.board_id=candidate_board_id
         where member.organization_id=context_organization_id
           and member.id=idempotency.safe_response_id;
      if not found then
        raise exception 'member invitation safe response target is unavailable'
          using errcode='55000';
      end if;
      return;
    end if;
    return query select 'unavailable'::text,null::uuid,null::uuid,null::bigint,null::bytea;
    return;
  end if;

  select candidate.* into consent
    from public.consent_records as candidate
   where candidate.id=candidate_consent_record_id
     and candidate.organization_id=context_organization_id
     and candidate.board_id=candidate_board_id
     and candidate.actor_member_id=context_actor_id
     and candidate.client_id=context_client_id
     and candidate.token_jti=context_token_jti
     and candidate.action_code='manage_member'
     and candidate.target_type='member'
     and candidate.target_id=candidate_member_id
     and candidate.payload_sha256=candidate_payload_sha256
     and candidate.confirmed_at=transaction_timestamp();
  select candidate.* into stage
    from public.action_stages as candidate
   where candidate.id=consent.stage_id
     and candidate.organization_id=context_organization_id
     and candidate.board_id=candidate_board_id
     and candidate.state='active'
     and candidate.action_code='manage_member'
     and candidate.target_type='member'
     and candidate.target_id=candidate_member_id
     and candidate.payload_sha256=candidate_payload_sha256;
  if consent.id is null or stage.id is null then
    raise exception 'member invitation requires its exact fresh consent stage'
      using errcode='55000';
  end if;

  begin
    stage_payload := convert_from(stage.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'member invitation stage payload is invalid' using errcode='23514';
  end;
  administrative_authority := public.boardagent_member_administration_authority(stage_payload->'request');
  if pg_catalog.sha256(stage.canonical_payload)<>candidate_payload_sha256 or not exists(
    select 1 from public.input_required_attempts a where a.id=consent.input_required_attempt_id
      and a.stage_id=stage.id and a.original_arguments_sha256=candidate_request_sha256) then
    raise exception 'member invitation request bytes are not bound' using errcode='42501';
  end if;
  expected_payload := jsonb_build_object(
    'schemaVersion','boardagent.member-invite.v1',
    'request',jsonb_build_object(
      'schema_version','boardagent.tool-input.v1',
      'change',jsonb_build_object(
        'operation','invite',
        'member_id',candidate_member_id::text,
        'board_id',candidate_board_id::text,
        'member_kind',candidate_member_kind,
        'seat_role',candidate_seat_role,
        'legal_name',candidate_legal_name,
        'display_name',candidate_display_name,
        'voting_weight',candidate_voting_weight,
        'accountable_principal_id',candidate_accountable_principal_id
      ),
      'idempotency_key',candidate_idempotency_key
    ),
    'board',jsonb_build_object(
      'boardId',candidate_board_id::text,
      'boardName',prepared.result_board_name,
      'boardState','active',
      'boardRowVersion',prepared.result_board_row_version::text
    ),
    'member',jsonb_build_object(
      'memberId',candidate_member_id::text,
      'memberKind',candidate_member_kind,
      'persistedMemberKind',prepared.result_persisted_member_kind,
      'legalName',candidate_legal_name,
      'displayName',candidate_display_name,
      'accountablePrincipalId',candidate_accountable_principal_id,
      'accountablePrincipalName',prepared.result_accountable_principal_name
    ),
    'seat',jsonb_build_object(
      'seatRole',candidate_seat_role,
      'isSecretary',false,
      'votingWeight',candidate_voting_weight::text
    )
  );
  if (((stage_payload->'request')-'authority_evidence')||jsonb_build_object('change',(stage_payload->'request'->'change')-'reason'))<>expected_payload->'request' then
    raise exception 'member invitation request differs from the selected target' using errcode='42501';
  end if;
  expected_payload := jsonb_set(expected_payload,'{request}',stage_payload->'request');
  if administrative_authority is not null then expected_payload := expected_payload||jsonb_build_object('administrativeAuthority',administrative_authority); end if;
  if stage_payload<>expected_payload then
    raise exception 'member invitation canonical payload is stale or malformed'
      using errcode='55000';
  end if;

  expected_snapshot := jsonb_build_object(
    'schemaVersion','boardagent.membership-authority.v1',
    'memberId',candidate_member_id::text,
    'boardId',candidate_board_id::text,
    'seatRole',candidate_seat_role,
    'isSecretary',false,
    'votingWeight',candidate_voting_weight
  );
  if administrative_authority is not null then expected_snapshot := expected_snapshot||jsonb_build_object('administrativeAuthority',administrative_authority); end if;
  -- lib/contracts remains the canonical-byte producer. PostgreSQL verifies
  -- those exact bytes and their meaning; jsonb::text is never used as a hash.
  if candidate_authority_snapshot<>expected_snapshot
     or convert_from(candidate_authority_snapshot_bytes,'UTF8')::jsonb<>expected_snapshot
     or convert_from(candidate_safe_response_bytes,'UTF8')::jsonb<>jsonb_build_object(
       'schemaVersion','boardagent.member-safe-response.v1',
       'memberId',candidate_member_id::text,
       'membershipId',candidate_membership_id::text,
       'boardId',candidate_board_id::text
     ) then
    raise exception 'member invitation authority snapshot is invalid' using errcode='23514';
  end if;
  expected_details := jsonb_build_object(
    'operation','invite',
    'memberId',candidate_member_id::text,
    'boardId',candidate_board_id::text,
    'memberKind',candidate_member_kind,
    'persistedMemberKind',prepared.result_persisted_member_kind,
    'membershipId',candidate_membership_id::text,
    'membershipVersionId',candidate_membership_version_id::text,
    'seatRole',candidate_seat_role,
    'isSecretary',false,
    'votingWeight',candidate_voting_weight::text,
    'accountablePrincipalId',candidate_accountable_principal_id,
    'authoritySnapshotSha256',encode(candidate_authority_snapshot_sha256,'hex')
  );
  select event.* into audit
    from public.audit_events as event
   where event.id=candidate_audit_event_id
     and event.organization_id=context_organization_id
     and event.board_id=candidate_board_id
     and event.event_type='member_changed'
     and event.actor_member_id=context_actor_id
     and event.client_id=context_client_id
     and event.token_jti=context_token_jti
     and event.consent_record_id=candidate_consent_record_id
     and event.object_type='member'
     and event.object_id=candidate_member_id
     and event.object_version=1;
  if audit.id is null then
    raise exception 'member invitation audit evidence is missing' using errcode='55000';
  end if;
  begin
    audit_payload := convert_from(audit.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'member invitation audit payload is invalid' using errcode='23514';
  end;
  if audit_payload->>'eventId' is distinct from candidate_audit_event_id::text
     or audit_payload->>'eventType'<>'member_changed'
     or audit_payload->>'actorMemberId' is distinct from context_actor_id::text
     or audit_payload->>'actorClientId' is distinct from context_client_id::text
     or audit_payload->>'tokenJti' is distinct from context_token_jti::text
     or audit_payload->>'entityType'<>'member'
     or audit_payload->>'entityId' is distinct from candidate_member_id::text
     or audit_payload->>'boardId' is distinct from candidate_board_id::text
     or audit_payload->>'origin'<>'mcp'
     or audit_payload->>'schemaVersion'<>'1'
     or audit_payload->'details'<>expected_details then
    raise exception 'member invitation audit evidence does not match its projection'
      using errcode='23514';
  end if;

  insert into public.members(
    id,organization_id,member_kind,legal_name,display_name,state,
    accountable_principal_id
  ) values (
    candidate_member_id,context_organization_id,prepared.result_persisted_member_kind,
    candidate_legal_name,candidate_display_name,'invited',candidate_accountable_principal_id
  );
  insert into public.board_memberships(
    id,organization_id,board_id,member_id,seat_role,is_secretary,voting_weight,state
  ) values (
    candidate_membership_id,context_organization_id,candidate_board_id,
    candidate_member_id,candidate_seat_role,false,candidate_voting_weight,'active'
  );
  insert into public.membership_versions(
    id,organization_id,board_id,member_id,membership_id,version,seat_role,is_secretary,
    voting_weight,authority_snapshot,snapshot_sha256,change_reason,actor_member_id,
    consent_record_id,audit_event_id
  ) values (
    candidate_membership_version_id,context_organization_id,candidate_board_id,
    candidate_member_id,candidate_membership_id,1,candidate_seat_role,false,
    candidate_voting_weight,candidate_authority_snapshot,
    candidate_authority_snapshot_sha256,coalesce(stage_payload->'request'->'change'->>'reason','initial member invitation'),context_actor_id,
    candidate_consent_record_id,candidate_audit_event_id
  );
  update public.idempotency_records as changed
     set state='succeeded',safe_response_type='member',safe_response_id=candidate_member_id,
         safe_response_sha256=candidate_safe_response_sha256,
         completed_at=transaction_timestamp()
   where changed.id=candidate_idempotency_record_id
     and changed.state='in_progress';
  if not found then
    raise exception 'member invitation idempotency finalization failed' using errcode='40001';
  end if;
  return query select 'created'::text,candidate_member_id,candidate_membership_id,
    1::bigint,candidate_safe_response_sha256;
end
$$;

alter function public.boardagent_finalize_member_invite(
  uuid,uuid,text,text,text,text,bigint,uuid,text,bytea,bytea,uuid,uuid,uuid,uuid,
  uuid,jsonb,bytea,bytea,bytea,bytea
) owner to boardagent_migrator;
revoke all on function public.boardagent_finalize_member_invite(
  uuid,uuid,text,text,text,text,bigint,uuid,text,bytea,bytea,uuid,uuid,uuid,uuid,
  uuid,jsonb,bytea,bytea,bytea,bytea
) from public;
grant execute on function public.boardagent_finalize_member_invite(
  uuid,uuid,text,text,text,text,bigint,uuid,text,bytea,bytea,uuid,uuid,uuid,uuid,
  uuid,jsonb,bytea,bytea,bytea,bytea
) to boardagent_server;
