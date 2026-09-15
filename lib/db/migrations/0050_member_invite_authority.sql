-- BoardAgent Phase 2: exact confirmed creation of a member and one pre-enrollment seat.
-- Only an active organization admin with current onboarding and secretariat:admin can
-- use this request-scoped definer. Audit evidence exists before the FK-linked immutable
-- membership version is finalized.

grant select,insert on public.members,public.board_memberships,public.membership_versions
  to boardagent_migrator;
grant select on public.accountable_principals,public.action_stages,
  public.consent_records,public.audit_events to boardagent_migrator;
grant select,insert,update on public.idempotency_records to boardagent_migrator;

create policy boardagent_migrator_member_invite_member_insert
  on public.members for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and state='invited'
  );
create policy boardagent_migrator_member_invite_membership_insert
  on public.board_memberships for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and state='active'
  );
create policy boardagent_migrator_member_invite_version_insert
  on public.membership_versions for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and version=1
  );
create policy boardagent_migrator_member_invite_audit_read
  on public.audit_events for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_member_invite_principal_read
  on public.accountable_principals for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_member_invite_idempotency_insert
  on public.idempotency_records for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='manage_member'
  );
create policy boardagent_migrator_member_invite_idempotency_update
  on public.idempotency_records for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='manage_member'
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='manage_member'
  );

create function public.boardagent_prepare_member_invite(
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
  select exists (
    select 1
      from public.members as actor
      join public.access_token_records as token
        on token.organization_id=actor.organization_id
       and token.member_id=actor.id
       and token.client_id=public.boardagent_context_uuid('boardagent.client_id')
       and token.jti=public.boardagent_context_uuid('boardagent.token_jti')
      join public.oauth_clients as oauth_client
        on oauth_client.id=token.client_id
       and oauth_client.organization_id=token.organization_id
      join public.system_instance as instance
        on instance.organization_id=token.organization_id
       and instance.canonical_resource_uri=token.resource_uri
     where actor.organization_id=context_organization_id
       and actor.id=context_actor_id
       and actor.state='active'
       and oauth_client.state='active'
       and token.revoked_at is null
       and token.expires_at>transaction_timestamp()
       and 'secretariat:admin'=any(token.scope_set)
       and exists (
         select 1
           from public.organization_role_assignments as assignment
          where assignment.organization_id=actor.organization_id
            and assignment.member_id=actor.id
            and assignment.role='admin'
            and assignment.active_from<=transaction_timestamp()
            and (assignment.active_until is null
                 or assignment.active_until>transaction_timestamp())
       )
       and not exists (
         select 1
           from public.board_memberships as actor_membership
          where actor_membership.organization_id=actor.organization_id
            and actor_membership.member_id=actor.id
            and actor_membership.state='active'
            and actor_membership.active_from<=transaction_timestamp()
            and (actor_membership.active_until is null
                 or actor_membership.active_until>transaction_timestamp())
            and not exists (
              select 1
                from public.onboarding_attestations as attestation
               where attestation.organization_id=actor.organization_id
                 and attestation.member_id=actor.id
                 and attestation.board_id=actor_membership.board_id
                 and attestation.terms_version_id=(
                   select terms.id
                     from public.onboarding_terms_versions as terms
                    where terms.organization_id=actor.organization_id
                      and terms.seat_role=actor_membership.seat_role
                      and terms.effective_at<=transaction_timestamp()
                    order by terms.version desc,terms.id desc limit 1
                 )
                 and attestation.support_version_id=(
                   select support.id
                     from public.secretary_support_versions as support
                    where support.organization_id=actor.organization_id
                      and support.board_id=actor_membership.board_id
                      and support.effective_at<=transaction_timestamp()
                    order by support.version desc,support.id desc limit 1
                 )
            )
       )
  ) into actor_ready;

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
  candidate_safe_response_sha256 bytea
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
     or not public.boardagent_hash_is_sha256(candidate_safe_response_sha256) then
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
  if candidate_authority_snapshot<>expected_snapshot then
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
    candidate_authority_snapshot_sha256,'initial member invitation',context_actor_id,
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

alter function public.boardagent_prepare_member_invite(uuid,uuid,text,text,bigint,uuid)
  owner to boardagent_migrator;
alter function public.boardagent_finalize_member_invite(
  uuid,uuid,text,text,text,text,bigint,uuid,text,bytea,bytea,uuid,uuid,uuid,uuid,
  uuid,jsonb,bytea,bytea
) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_member_invite(
  uuid,uuid,text,text,bigint,uuid
) from public;
revoke all on function public.boardagent_finalize_member_invite(
  uuid,uuid,text,text,text,text,bigint,uuid,text,bytea,bytea,uuid,uuid,uuid,uuid,
  uuid,jsonb,bytea,bytea
) from public;
grant execute on function public.boardagent_prepare_member_invite(
  uuid,uuid,text,text,bigint,uuid
) to boardagent_server;
grant execute on function public.boardagent_finalize_member_invite(
  uuid,uuid,text,text,text,text,bigint,uuid,text,bytea,bytea,uuid,uuid,uuid,uuid,
  uuid,jsonb,bytea,bytea
) to boardagent_server;
