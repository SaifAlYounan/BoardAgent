-- Current human eligibility and administrator proposal preparation. Every mutation
-- must separately consume fresh exact consent in the administrative finalizer.
create function public.boardagent_administrative_member_eligible(candidate_member uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public
as $$
  select current_setting('boardagent.transaction_scope',true)='request'
    and exists(select 1 from public.members m where m.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and m.id=candidate_member and m.state='active' and m.member_kind='human')
    and not exists(select 1 from public.board_memberships s where s.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and s.member_id=candidate_member and s.state='active' and s.active_from<=transaction_timestamp()
      and (s.active_until is null or s.active_until>transaction_timestamp()) and s.seat_role='observer')
    and not exists(select 1 from public.board_memberships s where s.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and s.member_id=candidate_member and s.state='active' and s.active_from<=transaction_timestamp()
      and (s.active_until is null or s.active_until>transaction_timestamp())
      and not exists(select 1 from public.onboarding_attestations a where a.organization_id=s.organization_id
        and a.member_id=s.member_id and a.board_id=s.board_id
        and a.terms_version_id=(select t.id from public.onboarding_terms_versions t
          where t.organization_id=s.organization_id and t.seat_role=s.seat_role and t.effective_at<=transaction_timestamp()
          order by t.effective_at desc,t.version desc,t.id desc limit 1)
        and a.support_version_id=(select v.id from public.secretary_support_versions v
          where v.organization_id=s.organization_id and (v.board_id=s.board_id or v.board_id is null)
          and v.effective_at<=transaction_timestamp()
          order by (v.board_id=s.board_id) desc,v.effective_at desc,v.version desc,v.id desc limit 1)))
$$;
alter function public.boardagent_administrative_member_eligible(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_administrative_member_eligible(uuid) from public;

create function public.boardagent_company_admin_snapshot(candidate_request jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  change jsonb := candidate_request->'change';
  operation text := change->>'operation';
  field text;
  fields text[];
  identifier uuid;
  target_id uuid;
  issuer_id uuid;
  proposal public.company_admin_proposals%rowtype;
  assignment public.organization_role_assignments%rowtype;
  actor_assignment public.organization_role_assignments%rowtype;
  actor_member public.members%rowtype;
  target_member public.members%rowtype;
  issuer_member public.members%rowtype;
  before_record jsonb := null;
  after_record jsonb;
  record_type text := 'company_admin_proposal';
  record_version bigint := 1;
  event_type text;
  effects jsonb := '[]';
  member_changes jsonb := '[]';
  gains_admin boolean := false;
  transfers_admin boolean := false;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable' or org is null or actor is null then
    raise exception 'administrative authority requires a managed serializable request' using errcode='25000';
  end if;
  if jsonb_typeof(candidate_request) is distinct from 'object'
    or candidate_request-array['schema_version','idempotency_key','change']<>'{}'::jsonb
    or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
    or jsonb_typeof(candidate_request->'idempotency_key') is distinct from 'string'
    or coalesce(candidate_request->>'idempotency_key','') !~ '^[A-Za-z0-9._~-]{16,200}$'
    or jsonb_typeof(change) is distinct from 'object'
    or coalesce(operation,'') not in ('grant','transfer','accept','decline','cancel','revoke')
    or jsonb_typeof(change->'reason') is distinct from 'string'
    or coalesce(length(change->>'reason'),0) not between 1 and 2000
    or position(chr(13) in change->>'reason')>0
    or normalize(change->>'reason',NFC) is distinct from change->>'reason' then
    raise exception 'administrative input is invalid' using errcode='22023';
  end if;
  fields := case when operation in ('grant','transfer') then array['operation','proposal_id','member_id','expected_member_version','reason']
    when operation='revoke' then array['operation','assignment_id','member_id','expected_member_version','reason']
    else array['operation','proposal_id','expected_proposal_version','reason'] end;
  if change-fields<>'{}'::jsonb or not(change ?& fields) then
    raise exception 'administrative input fields are invalid' using errcode='22023';
  end if;
  foreach field in array fields loop
    if field like '%_id' then
      if jsonb_typeof(change->field) is distinct from 'string'
        or not public.boardagent_is_uuid_v7((change->>field)::uuid) then
        raise exception 'administrative identifier is invalid' using errcode='22023';
      end if;
    elsif field like 'expected_%_version' then
      if jsonb_typeof(change->field) is distinct from 'number'
        or (change->>field) !~ '^[1-9][0-9]{0,15}$'
        or (change->>field)::numeric>9007199254740991 then
        raise exception 'administrative version is invalid' using errcode='22023';
      end if;
    end if;
  end loop;
  -- Shared with the original member lifecycle; do not replace this with a private lock.
  perform pg_advisory_xact_lock(hashtextextended(org::text,424286));
  if not exists(select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
    where t.organization_id=org and t.member_id=actor
      and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
      and 'secretariat:admin'=any(t.scope_set)) or not public.boardagent_administrative_member_eligible(actor) then
    raise exception 'administrative action is unavailable' using errcode='42501';
  end if;
  select a.* into actor_assignment from public.organization_role_assignments a
    where a.organization_id=org and a.member_id=actor and a.role='admin' and a.active_from<=transaction_timestamp()
      and (a.active_until is null or a.active_until>transaction_timestamp()) order by a.active_from,a.id limit 1;
  if operation in ('grant','transfer','revoke') and actor_assignment.id is null then
    raise exception 'administrative action is unavailable' using errcode='42501';
  end if;
  if operation='transfer' and (select count(*) from public.organization_role_assignments a where a.organization_id=org
    and a.member_id=actor and a.role='admin' and a.active_from<=transaction_timestamp()
    and (a.active_until is null or a.active_until>transaction_timestamp()))<>1 then
    raise exception 'administrative action is unavailable' using errcode='42501';
  end if;
  if operation in ('grant','transfer') then
    identifier := (change->>'proposal_id')::uuid; target_id := (change->>'member_id')::uuid; issuer_id := actor;
    if target_id=actor or exists(select 1 from public.company_admin_proposals p where p.organization_id=org and p.id=identifier)
      or exists(select 1 from public.organization_role_assignments a where a.organization_id=org and a.id=identifier) then
      raise exception 'administrative action is unavailable' using errcode='42501';
    end if;
  elsif operation='revoke' then
    identifier := (change->>'assignment_id')::uuid; target_id := (change->>'member_id')::uuid; issuer_id := actor;
    select a.* into assignment from public.organization_role_assignments a where a.organization_id=org and a.id=identifier
      and a.member_id=target_id and a.role='admin' and a.active_from<=transaction_timestamp()
      and (a.active_until is null or a.active_until>transaction_timestamp());
    if assignment.id is null or (select count(*) from public.organization_role_assignments a where a.organization_id=org
      and a.member_id=target_id and a.role='admin' and a.active_from<=transaction_timestamp()
      and (a.active_until is null or a.active_until>transaction_timestamp()))<>1 then
      raise exception 'administrative action is unavailable' using errcode='42501';
    end if;
  else
    identifier := (change->>'proposal_id')::uuid;
    select p.* into proposal from public.company_admin_proposals p where p.organization_id=org and p.id=identifier for update;
    if proposal.id is null or proposal.state<>'pending' or proposal.row_version<>(change->>'expected_proposal_version')::bigint
      or (operation in ('accept','decline') and actor<>proposal.target_member_id)
      or (operation='cancel' and actor<>proposal.issuer_member_id and actor_assignment.id is null) then
      raise exception 'administrative action is unavailable' using errcode='42501';
    end if;
    target_id := proposal.target_member_id; issuer_id := proposal.issuer_member_id;
    before_record := jsonb_build_object('proposalId',proposal.id,'operation',proposal.operation,'issuerMemberId',issuer_id,
      'issuerAssignmentId',proposal.issuer_assignment_id,'targetMemberId',target_id,'state',proposal.state,
      'rowVersion',proposal.row_version::text,'expiresAt',proposal.expires_at,'grantedAssignmentId',proposal.granted_assignment_id);
  end if;
  -- Deterministic member lock ordering also covers transfer's two identity effects.
  perform 1 from public.members m where m.organization_id=org and m.id=any(array[actor,target_id,issuer_id]) order by m.id for update;
  select m.* into actor_member from public.members m where m.organization_id=org and m.id=actor;
  select m.* into target_member from public.members m where m.organization_id=org and m.id=target_id;
  select m.* into issuer_member from public.members m where m.organization_id=org and m.id=issuer_id;
  if target_member.id is null or issuer_member.id is null then
    raise exception 'administrative action is unavailable' using errcode='42501';
  end if;
  if operation in ('grant','transfer','revoke') and target_member.row_version<>(change->>'expected_member_version')::bigint then
    raise exception 'administrative action is unavailable' using errcode='42501';
  end if;
  if operation in ('grant','transfer','accept') then
    if not public.boardagent_administrative_member_eligible(target_id)
      or exists(select 1 from public.organization_role_assignments a where a.organization_id=org and a.member_id=target_id
        and a.role='admin' and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp())) then
      raise exception 'administrative action is unavailable' using errcode='42501';
    end if;
  end if;
  if operation in ('grant','transfer') then
    after_record := jsonb_build_object('proposalId',identifier,'operation',operation,'issuerMemberId',actor,
      'issuerAssignmentId',actor_assignment.id,'targetMemberId',target_id,'state','pending','rowVersion','1',
      'expiresAt',null,'validForSeconds',86400,'grantedAssignmentId',null);
    event_type := 'company_admin_proposed';
  elsif operation='accept' then
    if proposal.expires_at<=transaction_timestamp() or issuer_member.identity_generation<>proposal.issuer_identity_generation
      or target_member.identity_generation<>proposal.target_identity_generation or target_member.row_version<>proposal.target_member_version
      or not public.boardagent_administrative_member_eligible(issuer_id)
      or not exists(select 1 from public.organization_role_assignments a where a.organization_id=org and a.id=proposal.issuer_assignment_id
        and a.member_id=issuer_id and a.role='admin' and a.active_from<=transaction_timestamp()
        and (a.active_until is null or a.active_until>transaction_timestamp())) then
      raise exception 'administrative action is unavailable' using errcode='42501';
    end if;
    gains_admin := true; transfers_admin := proposal.operation='transfer'; record_version := 2;
    if transfers_admin and (select count(*) from public.organization_role_assignments a where a.organization_id=org
      and a.member_id=issuer_id and a.role='admin' and a.active_from<=transaction_timestamp()
      and (a.active_until is null or a.active_until>transaction_timestamp()))<>1 then
      raise exception 'administrative action is unavailable' using errcode='42501';
    end if;
    after_record := before_record||jsonb_build_object('state','accepted','rowVersion','2','grantedAssignmentId',identifier);
    event_type := case when transfers_admin then 'company_admin_transferred' else 'company_admin_granted' end;
  elsif operation in ('decline','cancel') then
    record_version := 2;
    after_record := before_record||jsonb_build_object('state',case operation when 'decline' then 'declined' else 'cancelled' end,'rowVersion','2');
    event_type := case operation when 'decline' then 'company_admin_proposal_declined' else 'company_admin_proposal_cancelled' end;
  else
    if not exists(select 1 from public.organization_role_assignments a join public.members m on m.id=a.member_id and m.organization_id=a.organization_id
      where a.organization_id=org and a.member_id<>target_id and a.role='admin' and m.state='active' and m.member_kind='human'
        and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp())
        and not exists(select 1 from public.board_memberships s where s.organization_id=org and s.member_id=m.id and s.state='active'
          and s.seat_role='observer' and s.active_from<=transaction_timestamp() and (s.active_until is null or s.active_until>transaction_timestamp()))) then
      raise exception 'cannot revoke the final active human administrator' using errcode='23514';
    end if;
    record_type := 'company_admin_assignment'; record_version := target_member.row_version+1;
    before_record := jsonb_build_object('assignmentId',identifier,'memberId',target_id,'active',true);
    after_record := before_record||jsonb_build_object('active',false); event_type := 'company_admin_revoked';
  end if;
  if gains_admin or operation='revoke' then
    effects := jsonb_build_array(target_id);
    member_changes := jsonb_build_array(jsonb_build_object('memberId',target_id,'displayName',target_member.display_name,
      'beforeIdentityGeneration',target_member.identity_generation::text,'afterIdentityGeneration',(target_member.identity_generation+1)::text,
      'beforeRowVersion',target_member.row_version::text,'afterRowVersion',(target_member.row_version+1)::text,'adminAfter',gains_admin));
    if transfers_admin then
      effects := effects||jsonb_build_array(issuer_id);
      member_changes := member_changes||jsonb_build_array(jsonb_build_object('memberId',issuer_id,'displayName',issuer_member.display_name,
        'beforeIdentityGeneration',issuer_member.identity_generation::text,'afterIdentityGeneration',(issuer_member.identity_generation+1)::text,
        'beforeRowVersion',issuer_member.row_version::text,'afterRowVersion',(issuer_member.row_version+1)::text,'adminAfter',false));
    end if;
  end if;
  return jsonb_build_object('operation',operation,'recordType',record_type,'recordId',identifier,'recordVersion',record_version::text,
    'boardId',null,'actorMemberId',actor,'actorDisplayName',actor_member.display_name,'actorIdentityGeneration',actor_member.identity_generation::text,
    'targetMemberId',target_id,'targetDisplayName',target_member.display_name,'targetIdentityGeneration',target_member.identity_generation::text,
    'targetMemberVersion',target_member.row_version::text,'issuerMemberId',issuer_id,'issuerIdentityGeneration',issuer_member.identity_generation::text,
    'before',before_record,'after',after_record,'eventType',event_type,'affectedMemberIds',effects,'memberChanges',member_changes);
end
$$;
alter function public.boardagent_company_admin_snapshot(jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_company_admin_snapshot(jsonb) from public;
grant execute on function public.boardagent_company_admin_snapshot(jsonb) to boardagent_server;

create policy boardagent_migrator_company_admin_idempotency on public.idempotency_records
  for insert to boardagent_migrator with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='manage_company_admin'
  );

grant select,insert,update on public.organization_role_assignments to boardagent_migrator;
create policy boardagent_migrator_admin_assignment_request on public.organization_role_assignments
  for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='request' and organization_id=public.boardagent_context_uuid('boardagent.organization_id'))
  with check (current_setting('boardagent.transaction_scope',true)='request' and organization_id=public.boardagent_context_uuid('boardagent.organization_id'));

create function public.boardagent_guard_company_admin_proposal()
returns trigger language plpgsql security invoker set search_path=pg_catalog,public
as $$
begin
  if current_user<>'boardagent_migrator' or current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or old.state<>'pending' or new.state not in ('accepted','cancelled','declined') or new.row_version<>old.row_version+1
    or row(new.id,new.organization_id,new.operation,new.issuer_member_id,new.issuer_assignment_id,new.target_member_id,
      new.issuer_identity_generation,new.target_identity_generation,new.target_member_version,new.reason,new.created_at,
      new.expires_at,new.creation_consent_id,new.creation_audit_id)
      is distinct from row(old.id,old.organization_id,old.operation,old.issuer_member_id,old.issuer_assignment_id,old.target_member_id,
      old.issuer_identity_generation,old.target_identity_generation,old.target_member_version,old.reason,old.created_at,
      old.expires_at,old.creation_consent_id,old.creation_audit_id) then
    raise exception 'administrator proposal history is immutable' using errcode='23514';
  end if;
  return new;
end
$$;
revoke all on function public.boardagent_guard_company_admin_proposal() from public;
create trigger boardagent_company_admin_proposal_transition before update on public.company_admin_proposals
  for each row execute function public.boardagent_guard_company_admin_proposal();

create function public.boardagent_finalize_company_admin(
  candidate_request jsonb,candidate_payload_sha256 bytea,candidate_consent_id uuid,
  candidate_audit_id uuid,candidate_change_id uuid,candidate_idempotency_id uuid,candidate_request_sha256 bytea
)
returns void language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  snapshot jsonb;
  payload jsonb;
  consent public.consent_records%rowtype;
  stage public.action_stages%rowtype;
  proposal public.company_admin_proposals%rowtype;
  operation text := candidate_request->'change'->>'operation';
  record_id uuid;
  affected_id uuid;
  issuer_id uuid;
  effect jsonb;
begin
  snapshot := public.boardagent_company_admin_snapshot(candidate_request);
  record_id := (snapshot->>'recordId')::uuid; affected_id := (snapshot->>'targetMemberId')::uuid;
  issuer_id := (snapshot->>'issuerMemberId')::uuid;
  payload := jsonb_build_object('schemaVersion','boardagent.administrative-authority.v1','tool','manage_company_admin',
    'request',candidate_request,'snapshot',snapshot);
  select c.* into consent from public.consent_records c
    where c.id=candidate_consent_id and c.organization_id=org and c.actor_member_id=actor
      and c.client_id=public.boardagent_context_uuid('boardagent.client_id') and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
      and c.board_id is null and c.action_code='manage_company_admin' and c.target_type=snapshot->>'recordType'
      and c.target_id=record_id and c.payload_sha256=candidate_payload_sha256 and c.confirmed_at=transaction_timestamp();
  select s.* into stage from public.action_stages s where s.id=consent.stage_id and s.organization_id=org
    and s.state='active' and s.payload_sha256=candidate_payload_sha256;
  if consent.id is null or stage.id is null or pg_catalog.sha256(stage.canonical_payload)<>candidate_payload_sha256
    or convert_from(stage.canonical_payload,'UTF8')::jsonb<>payload then
    raise exception 'administrator change requires exact fresh unchanged consent' using errcode='42501';
  end if;
  if not exists(select 1 from public.audit_events a where a.id=candidate_audit_id and a.organization_id=org
    and a.actor_member_id=actor and a.consent_record_id=candidate_consent_id and a.event_type=snapshot->>'eventType'
    and a.object_type=snapshot->>'recordType' and a.object_id=record_id and a.board_id is null
    and a.client_id=consent.client_id and a.token_jti=consent.token_jti and a.object_version=(snapshot->>'recordVersion')::bigint
    and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'=jsonb_build_object('operation',operation,
      'administrativeRecordId',record_id,'payloadSha256',encode(candidate_payload_sha256,'hex'),
      'before',snapshot->'before','after',snapshot->'after','affectedMemberIds',snapshot->'affectedMemberIds','memberChanges',snapshot->'memberChanges')) then
    raise exception 'administrator change requires its appended audit' using errcode='42501';
  end if;
  if not exists(select 1 from public.input_required_attempts a where a.id=consent.input_required_attempt_id
    and a.stage_id=stage.id and a.original_arguments_sha256=candidate_request_sha256)
    or not public.boardagent_is_uuid_v7(candidate_change_id) or not public.boardagent_is_uuid_v7(candidate_idempotency_id) then
    raise exception 'administrator request binding is invalid' using errcode='42501';
  end if;
  insert into public.idempotency_records(id,organization_id,actor_member_id,client_id,operation,idempotency_key,
    request_sha256,state,expires_at,completed_at,safe_response_type,safe_response_id,safe_response_sha256)
    values(candidate_idempotency_id,org,actor,consent.client_id,'manage_company_admin',candidate_request->>'idempotency_key',
      candidate_request_sha256,'succeeded',transaction_timestamp()+interval '24 hours',transaction_timestamp(),
      snapshot->>'recordType',record_id,candidate_payload_sha256);
  insert into public.administrative_authority_changes(id,organization_id,board_id,record_type,record_id,record_version,
    actor_member_id,action_code,operation,consent_record_id,audit_event_id,canonical_payload,payload_sha256)
    values(candidate_change_id,org,null,snapshot->>'recordType',record_id,(snapshot->>'recordVersion')::bigint,
      actor,'manage_company_admin',operation,candidate_consent_id,candidate_audit_id,stage.canonical_payload,candidate_payload_sha256);
  if operation in ('grant','transfer') then
    insert into public.company_admin_proposals(id,organization_id,operation,issuer_member_id,issuer_assignment_id,target_member_id,
      issuer_identity_generation,target_identity_generation,target_member_version,reason,expires_at,creation_consent_id,creation_audit_id)
      values(record_id,org,operation,actor,(snapshot->'after'->>'issuerAssignmentId')::uuid,affected_id,
        (snapshot->>'issuerIdentityGeneration')::bigint,(snapshot->>'targetIdentityGeneration')::bigint,
        (snapshot->>'targetMemberVersion')::bigint,candidate_request->'change'->>'reason',transaction_timestamp()+interval '24 hours',
        candidate_consent_id,candidate_audit_id);
  elsif operation in ('accept','decline','cancel') then
    select p.* into proposal from public.company_admin_proposals p where p.organization_id=org and p.id=record_id;
    if operation='accept' then
      insert into public.organization_role_assignments(id,organization_id,member_id,role,change_reason,consent_record_id)
        values(record_id,org,affected_id,'admin',candidate_request->'change'->>'reason',candidate_consent_id);
      if proposal.operation='transfer' then
        update public.organization_role_assignments a set active_until=greatest(transaction_timestamp(),a.active_from+interval '1 microsecond')
          where a.organization_id=org and a.id=proposal.issuer_assignment_id;
      end if;
    end if;
    update public.company_admin_proposals set state=snapshot->'after'->>'state',row_version=2,
      completed_at=transaction_timestamp(),completion_consent_id=candidate_consent_id,completion_audit_id=candidate_audit_id,
      granted_assignment_id=case when candidate_request->'change'->>'operation'='accept' then record_id else null end
      where organization_id=org and id=record_id;
  else
    update public.organization_role_assignments a set active_until=greatest(transaction_timestamp(),a.active_from+interval '1 microsecond')
      where a.organization_id=org and a.id=record_id;
  end if;
  for effect in select value from jsonb_array_elements(snapshot->'memberChanges') loop
    affected_id := (effect->>'memberId')::uuid;
    update public.members set identity_generation=(effect->>'afterIdentityGeneration')::bigint,
      row_version=(effect->>'afterRowVersion')::bigint where organization_id=org and id=affected_id;
    update public.auth_sessions set state='revoked' where organization_id=org and member_id=affected_id and state in ('anonymous','authenticated','expired');
    update public.refresh_families set state='revoked',revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and state='active';
    update public.access_token_records set revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and revoked_at is null;
    update public.oauth_authorization_codes set revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and consumed_at is null and revoked_at is null;
    update public.enrollment_invitations set revoked_at=transaction_timestamp() where organization_id=org and member_id=affected_id and consumed_at is null and revoked_at is null;
    update public.action_stages set state='replaced' where organization_id=org and actor_member_id=affected_id and state='active' and id<>stage.id;
  end loop;
end
$$;
alter function public.boardagent_finalize_company_admin(jsonb,bytea,uuid,uuid,uuid,uuid,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_finalize_company_admin(jsonb,bytea,uuid,uuid,uuid,uuid,bytea) from public;
grant execute on function public.boardagent_finalize_company_admin(jsonb,bytea,uuid,uuid,uuid,uuid,bytea) to boardagent_server;

-- A retained role on an observer or inactive identity cannot preserve human H
-- administration. Cover old member/seat transitions and new role revocation at the
-- database boundary. Transfer inserts the accepted successor before ending its issuer.
create function public.boardagent_guard_effective_company_administrator()
returns trigger language plpgsql security invoker set search_path=pg_catalog,public
as $$
declare
  authority_org uuid := old.organization_id;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request' then return new; end if;
  -- Enrollment, recovery and unrelated members must not be turned into admin-only
  -- operations. This guard runs only when this row can reduce existing admin ability.
  if tg_table_name='members' then
    if old.state<>'active' or old.member_kind<>'human' or (new.state='active' and new.member_kind='human') then return new; end if;
    if not exists(select 1 from public.organization_role_assignments a where a.organization_id=authority_org
      and a.member_id=old.id and a.role='admin' and a.active_from<=transaction_timestamp()
      and (a.active_until is null or a.active_until>transaction_timestamp())) then return new; end if;
  elsif tg_table_name='board_memberships' then
    if new.state<>'active' or new.seat_role<>'observer' or new.active_from>transaction_timestamp()
      or (new.active_until is not null and new.active_until<=transaction_timestamp()) then return new; end if;
    if not exists(select 1 from public.organization_role_assignments a where a.organization_id=authority_org
      and a.member_id=old.member_id and a.role='admin' and a.active_from<=transaction_timestamp()
      and (a.active_until is null or a.active_until>transaction_timestamp())) then return new; end if;
  end if;
  if current_user<>'boardagent_migrator'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or authority_org is distinct from public.boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'administrative authority transition requires its managed transaction' using errcode='42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(authority_org::text,424286));
  if not exists(select 1 from public.organization_role_assignments a
    join public.members m on m.organization_id=a.organization_id and m.id=a.member_id
    where a.organization_id=authority_org and a.role='admin' and a.active_from<=transaction_timestamp()
      and (a.active_until is null or a.active_until>transaction_timestamp())
      and m.state='active' and m.member_kind='human'
      and not exists(select 1 from public.board_memberships s where s.organization_id=authority_org
        and s.member_id=m.id and s.state='active' and s.seat_role='observer' and s.active_from<=transaction_timestamp()
        and (s.active_until is null or s.active_until>transaction_timestamp()))) then
    raise exception 'cannot lose the final active human administrator' using errcode='23514';
  end if;
  return new;
end
$$;
revoke all on function public.boardagent_guard_effective_company_administrator() from public;
create trigger boardagent_preserve_effective_admin_member after update of state,member_kind on public.members
  for each row when (old.state is distinct from new.state or old.member_kind is distinct from new.member_kind)
  execute function public.boardagent_guard_effective_company_administrator();
create trigger boardagent_preserve_effective_admin_seat after update of state,seat_role,active_from,active_until on public.board_memberships
  for each row when (old.state is distinct from new.state or old.seat_role is distinct from new.seat_role
    or old.active_from is distinct from new.active_from or old.active_until is distinct from new.active_until)
  execute function public.boardagent_guard_effective_company_administrator();
create trigger boardagent_preserve_effective_admin_assignment after update of active_from,active_until,role,member_id on public.organization_role_assignments
  for each row when (old.role='admin' and (old.active_from is distinct from new.active_from or old.active_until is distinct from new.active_until
    or old.role is distinct from new.role or old.member_id is distinct from new.member_id))
  execute function public.boardagent_guard_effective_company_administrator();
