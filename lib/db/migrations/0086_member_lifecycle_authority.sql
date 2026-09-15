-- Complete the frozen manage_member lifecycle. No new request-role table writes.
-- The canonical before/after projection, consent, audit, history, revocation and feed
-- removals commit together. Existing voting snapshots are deliberately never updated.
grant select,update on public.board_memberships to boardagent_migrator;
grant select,insert on public.membership_versions to boardagent_migrator;
grant select,update on public.oauth_authorization_codes,public.action_stages,
  public.pending_action_feed to boardagent_migrator;
grant select,insert on public.feed_tombstones,public.retention_snapshots,public.deletion_tombstones to boardagent_migrator;

do $policies$
declare table_name text;
begin
  foreach table_name in array array['board_memberships','membership_versions',
    'oauth_authorization_codes','action_stages','pending_action_feed','feed_tombstones','retention_snapshots','deletion_tombstones'] loop
    execute format('create policy boardagent_migrator_member_lifecycle on public.%I for all to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id'')) with check (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id''))',table_name);
  end loop;
end
$policies$;

create function public.boardagent_member_lifecycle_snapshot(candidate_request jsonb)
returns jsonb language plpgsql volatile security definer
set search_path=pg_catalog,public
as $$
declare
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
     or candidate_request - array['schema_version','change','idempotency_key']<>'{}'::jsonb
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
  if not exists (
    select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) as token
     where token.organization_id=org and token.member_id=actor
       and token.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
       and 'secretariat:admin'=any(token.scope_set) and 'admin'=any(token.roles)
  ) then
    raise exception 'member lifecycle requires a current scoped administrator' using errcode='42501';
  end if;
  if not exists(select 1 from public.members m where m.organization_id=org and m.id=actor and m.member_kind='human')
     or exists(select 1 from public.board_memberships m where m.organization_id=org and m.member_id=actor
       and m.state='active' and m.active_from<=transaction_timestamp() and (m.active_until is null or m.active_until>transaction_timestamp())
       and not public.boardagent_communication_actor_ready(m.board_id,'secretariat:admin')) then
    raise exception 'member administrator onboarding is not current' using errcode='42501';
  end if;
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
    'connectionEffect','All existing sessions, access tokens, refresh families and unused authorization codes are revoked. Sign in again.');
end
$$;

create function public.boardagent_finalize_member_lifecycle(
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
      'before',snapshot->'memberBefore','after',snapshot->'memberAfter','seatsBefore',snapshot->'seatsBefore','seatsAfter',snapshot->'seatsAfter')) then
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
      'memberAfter',snapshot->'memberAfter','before',old_seat,'after',next_seat);
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

alter function public.boardagent_member_lifecycle_snapshot(jsonb) owner to boardagent_migrator;
alter function public.boardagent_finalize_member_lifecycle(jsonb,bytea,uuid,uuid,jsonb,uuid,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_member_lifecycle_snapshot(jsonb) from public;
revoke all on function public.boardagent_finalize_member_lifecycle(jsonb,bytea,uuid,uuid,jsonb,uuid,bytea) from public;
grant execute on function public.boardagent_member_lifecycle_snapshot(jsonb) to boardagent_server;
grant execute on function public.boardagent_finalize_member_lifecycle(jsonb,bytea,uuid,uuid,jsonb,uuid,bytea) to boardagent_server;

-- Preserve the original member transitions; add only exact, current, audited reactivation
-- of a removed person. The shared transition guards for every other aggregate stay intact.
create function public.boardagent_guard_member_lifecycle_transition()
returns trigger language plpgsql security invoker set search_path=pg_catalog,public
as $$
begin
  if new.state=old.state
     or (old.state='invited' and new.state in ('enrollment_pending','removed'))
     or (old.state='enrollment_pending' and new.state in ('pending_activation','removed'))
     or (old.state='pending_activation' and new.state in ('active','removed'))
     or (old.state='active' and new.state in ('suspended','removed'))
     or (old.state='suspended' and new.state in ('active','removed')) then return new; end if;
  if old.state='removed' and new.state='active'
     and current_user='boardagent_migrator' and current_setting('boardagent.transaction_scope',true)='request'
     and new.identity_generation=old.identity_generation+1
     and row(new.id,new.organization_id,new.legal_name,new.display_name,new.member_kind,new.accountable_principal_id,new.created_at,new.onboarding_generation)
       is not distinct from row(old.id,old.organization_id,old.legal_name,old.display_name,old.member_kind,old.accountable_principal_id,old.created_at,old.onboarding_generation)
     and exists (
       select 1 from public.consent_records c join public.action_stages s on s.id=c.stage_id
        join public.audit_events a on a.consent_record_id=c.id and a.event_type='member_changed' and a.object_type='member' and a.object_id=old.id
        where c.organization_id=old.organization_id and c.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
          and c.client_id=public.boardagent_context_uuid('boardagent.client_id') and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
          and c.action_code='manage_member' and c.target_type='member' and c.target_id=old.id and c.board_id is null
          and c.confirmed_at=transaction_timestamp() and s.state='active' and c.payload_sha256=s.payload_sha256
          and pg_catalog.sha256(s.canonical_payload)=s.payload_sha256
          and convert_from(s.canonical_payload,'UTF8')::jsonb->'request'->'change'->>'operation'='reactivate'
          and convert_from(s.canonical_payload,'UTF8')::jsonb->'current'->'memberBefore'->>'state'='removed'
          and convert_from(s.canonical_payload,'UTF8')::jsonb->'current'->'memberBefore'->>'rowVersion'=old.row_version::text
          and convert_from(s.canonical_payload,'UTF8')::jsonb->'current'->'memberAfter'->>'rowVersion'=new.row_version::text
     ) then return new; end if;
  raise exception 'illegal members state transition: % -> %',old.state,new.state using errcode='23514';
end
$$;
revoke all on function public.boardagent_guard_member_lifecycle_transition() from public;
drop trigger boardagent_state_transition on public.members;
create trigger boardagent_state_transition before update of state on public.members
  for each row execute function public.boardagent_guard_member_lifecycle_transition();
