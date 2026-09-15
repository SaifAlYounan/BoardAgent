-- BoardAgent Phase 2: confirmed, secret-once enrollment invitation issuance.
-- The runtime role keeps no raw INSERT authority on enrollment_invitations. These
-- functions bind a live secretary/admin token, the exact staged consent payload,
-- a 24-hour idempotency record and one precreated seat before storing only a hash.

grant select,insert on public.enrollment_invitations to boardagent_migrator;
grant select on public.consent_records to boardagent_migrator;
grant select,insert,update on public.idempotency_records to boardagent_migrator;

create policy boardagent_migrator_enrollment_issue_invitation_read
  on public.enrollment_invitations for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_enrollment_issue_invitation_insert
  on public.enrollment_invitations for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and issued_by=public.boardagent_context_uuid('boardagent.member_id')
  );
create policy boardagent_migrator_enrollment_issue_consent_read
  on public.consent_records for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and token_jti=public.boardagent_context_uuid('boardagent.token_jti')
  );
create policy boardagent_migrator_enrollment_issue_idempotency_read
  on public.idempotency_records for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
  );
create policy boardagent_migrator_enrollment_issue_idempotency_insert
  on public.idempotency_records for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='issue_enrollment'
  );
create policy boardagent_migrator_enrollment_issue_idempotency_update
  on public.idempotency_records for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='issue_enrollment'
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='issue_enrollment'
  );

create function public.boardagent_prepare_enrollment_issuance(candidate_member_id uuid)
returns table(
  result_status text,
  result_member_display_name text,
  result_member_kind text,
  result_member_state text,
  result_member_row_version bigint,
  result_seats jsonb
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  context_organization_id uuid;
  context_actor_id uuid;
  target public.members%rowtype;
  seats jsonb;
  actor_ready boolean;
begin
  context_organization_id := public.boardagent_context_uuid('boardagent.organization_id');
  context_actor_id := public.boardagent_context_uuid('boardagent.member_id');
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or context_organization_id is null
     or context_actor_id is null then
    raise exception 'enrollment issuance requires a managed serializable request transaction'
      using errcode='25000';
  end if;
  if candidate_member_id is null then
    raise exception 'enrollment issuance member is invalid' using errcode='22023';
  end if;

  -- One member-scoped transaction lock serializes different secretaries/clients without
  -- granting the request role UPDATE merely to obtain a row lock.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(candidate_member_id::text,424249::bigint)
  );

  select member.* into target
    from public.members as member
   where member.organization_id=context_organization_id
     and member.id=candidate_member_id;
  select jsonb_agg(
           jsonb_build_object(
             'boardId',board.id::text,
             'boardName',board.name,
             'seatRole',membership.seat_role,
             'isSecretary',membership.is_secretary,
             'votingWeight',membership.voting_weight::text,
             'entitlementGeneration',membership.entitlement_generation::text
           ) order by board.id,membership.id
         ) into seats
    from public.board_memberships as membership
    join public.boards as board
      on board.organization_id=membership.organization_id
     and board.id=membership.board_id
     and board.state='active'
   where membership.organization_id=context_organization_id
     and membership.member_id=candidate_member_id
     and membership.state='active'
     and membership.active_from<=transaction_timestamp()
     and (membership.active_until is null
          or membership.active_until>transaction_timestamp());

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
                    order by terms.version desc,terms.id desc
                    limit 1
                 )
                 and attestation.support_version_id=(
                   select support.id
                     from public.secretary_support_versions as support
                    where support.organization_id=actor.organization_id
                      and support.board_id=actor_membership.board_id
                      and support.effective_at<=transaction_timestamp()
                    order by support.version desc,support.id desc
                    limit 1
                 )
            )
       )
       and (
         exists (
           select 1
             from public.organization_role_assignments as assignment
            where assignment.organization_id=actor.organization_id
              and assignment.member_id=actor.id
              and assignment.role in ('admin','secretariat')
              and assignment.active_from<=transaction_timestamp()
              and (assignment.active_until is null
                   or assignment.active_until>transaction_timestamp())
         )
         or not exists (
           select 1
             from public.board_memberships as target_membership
            where target_membership.organization_id=context_organization_id
              and target_membership.member_id=candidate_member_id
              and target_membership.state='active'
              and target_membership.active_from<=transaction_timestamp()
              and (target_membership.active_until is null
                   or target_membership.active_until>transaction_timestamp())
              and not (
                public.boardagent_context_board_allowed(target_membership.board_id)
                and exists (
                  select 1
                    from public.board_memberships as secretary_membership
                   where secretary_membership.organization_id=actor.organization_id
                     and secretary_membership.board_id=target_membership.board_id
                     and secretary_membership.member_id=actor.id
                     and secretary_membership.is_secretary
                     and secretary_membership.state='active'
                     and secretary_membership.active_from<=transaction_timestamp()
                     and (secretary_membership.active_until is null
                          or secretary_membership.active_until>transaction_timestamp())
                )
              )
         )
       )
  ) into actor_ready;

  if target.id is null
     or target.state<>'invited'
     or seats is null
     or jsonb_array_length(seats) not between 1 and 25
     or not actor_ready
     or exists (
       select 1 from public.enrollment_invitations as invitation
        where invitation.organization_id=context_organization_id
          and invitation.member_id=candidate_member_id
          and invitation.consumed_at is null
          and invitation.revoked_at is null
          and invitation.expires_at>transaction_timestamp()
     )
     or exists (
       select 1 from public.webauthn_credentials as credential
        where credential.organization_id=context_organization_id
          and credential.member_id=candidate_member_id
          and credential.state='active'
     )
     or exists (
       select 1 from public.enrollment_activation_challenges as challenge
        where challenge.organization_id=context_organization_id
          and challenge.member_id=candidate_member_id
          and challenge.state='issued'
          and challenge.expires_at>transaction_timestamp()
     ) then
    return query select 'unavailable'::text,null::text,null::text,null::text,
      null::bigint,null::jsonb;
    return;
  end if;

  return query select 'ready'::text,target.display_name,target.member_kind,target.state,
    target.row_version,seats;
end
$$;

create function public.boardagent_finalize_enrollment_issuance(
  candidate_member_id uuid,
  candidate_handoff_method text,
  candidate_expires_in_seconds integer,
  candidate_idempotency_key text,
  candidate_request_sha256 bytea,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid,
  candidate_invitation_id uuid,
  candidate_invitation_token_sha256 bytea,
  candidate_idempotency_record_id uuid,
  candidate_safe_response_sha256 bytea
)
returns table(
  result_status text,
  result_invitation_id uuid,
  result_expires_at text,
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
  stage_payload jsonb;
  expected_payload jsonb;
  idempotency public.idempotency_records%rowtype;
  inserted_idempotency_id uuid;
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
    raise exception 'enrollment issuance requires a managed serializable request transaction'
      using errcode='25000';
  end if;
  if candidate_member_id is null
     or candidate_handoff_method not in ('operator_display','operator_qr')
     or candidate_expires_in_seconds not between 60 and 86400
     or candidate_idempotency_key is null
     or length(candidate_idempotency_key) not between 16 and 200
     or candidate_idempotency_key !~ '^[A-Za-z0-9._~-]+$'
     or candidate_request_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_request_sha256)
     or candidate_payload_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_payload_sha256)
     or candidate_consent_record_id is null
     or candidate_invitation_id is null
     or not public.boardagent_is_uuid_v7(candidate_invitation_id)
     or candidate_invitation_token_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_invitation_token_sha256)
     or candidate_idempotency_record_id is null
     or not public.boardagent_is_uuid_v7(candidate_idempotency_record_id)
     or candidate_safe_response_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_safe_response_sha256) then
    raise exception 'enrollment issuance inputs are invalid' using errcode='22023';
  end if;

  select * into strict prepared
    from public.boardagent_prepare_enrollment_issuance(candidate_member_id);
  if prepared.result_status is distinct from 'ready' then
    return query select 'unavailable'::text,null::uuid,null::text,null::bytea;
    return;
  end if;

  -- A second lock namespace makes the same actor/client/idempotency key serialize
  -- even if a malformed retry changes the target member.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      context_actor_id::text || chr(1) || context_client_id::text || chr(1) ||
        candidate_idempotency_key,
      424250::bigint
    )
  );

  insert into public.idempotency_records(
    id,organization_id,actor_member_id,client_id,operation,idempotency_key,
    request_sha256,state,expires_at
  ) values (
    candidate_idempotency_record_id,context_organization_id,context_actor_id,
    context_client_id,'issue_enrollment',candidate_idempotency_key,
    candidate_request_sha256,'in_progress',transaction_timestamp()+interval '24 hours'
  )
  on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing
  returning id into inserted_idempotency_id;

  select record.* into idempotency
    from public.idempotency_records as record
   where record.actor_member_id=context_actor_id
     and record.client_id=context_client_id
     and record.operation='issue_enrollment'
     and record.idempotency_key=candidate_idempotency_key
   for update;
  if idempotency.id is null then
    raise exception 'enrollment issuance idempotency record is unavailable' using errcode='55000';
  end if;
  if not public.boardagent_constant_time_sha256_equal(
       idempotency.request_sha256,candidate_request_sha256
     ) then
    return query select 'idempotency_conflict'::text,null::uuid,null::text,null::bytea;
    return;
  end if;
  if inserted_idempotency_id is null then
    if idempotency.state='succeeded'
       and idempotency.safe_response_type='enrollment_invitation'
       and idempotency.safe_response_id is not null
       and idempotency.safe_response_sha256 is not null then
      return query
        select 'replayed'::text,idempotency.safe_response_id,
               to_char(invitation.expires_at at time zone 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
               idempotency.safe_response_sha256
          from public.enrollment_invitations as invitation
         where invitation.organization_id=context_organization_id
           and invitation.id=idempotency.safe_response_id;
      if not found then
        raise exception 'enrollment issuance safe response target is unavailable'
          using errcode='55000';
      end if;
      return;
    end if;
    return query select 'unavailable'::text,null::uuid,null::text,null::bytea;
    return;
  end if;

  select candidate.* into consent
    from public.consent_records as candidate
   where candidate.id=candidate_consent_record_id
     and candidate.organization_id=context_organization_id
     and candidate.actor_member_id=context_actor_id
     and candidate.client_id=context_client_id
     and candidate.token_jti=context_token_jti
     and candidate.action_code='issue_enrollment'
     and candidate.target_type='member'
     and candidate.target_id=candidate_member_id
     and candidate.payload_sha256=candidate_payload_sha256
     and candidate.confirmed_at=transaction_timestamp();
  if consent.id is null then
    raise exception 'enrollment issuance requires its exact fresh consent record'
      using errcode='55000';
  end if;
  select candidate.* into stage
    from public.action_stages as candidate
   where candidate.id=consent.stage_id
     and candidate.organization_id=context_organization_id
     and candidate.state='active'
     and candidate.action_code='issue_enrollment'
     and candidate.target_type='member'
     and candidate.target_id=candidate_member_id
     and candidate.payload_sha256=candidate_payload_sha256;
  if stage.id is null then
    raise exception 'enrollment issuance stage is unavailable' using errcode='55000';
  end if;
  begin
    stage_payload := convert_from(stage.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'enrollment issuance stage payload is invalid' using errcode='23514';
  end;
  expected_payload := jsonb_build_object(
    'schemaVersion','boardagent.enrollment-issuance.v1',
    'request',jsonb_build_object(
      'schema_version','boardagent.tool-input.v1',
      'member_id',candidate_member_id::text,
      'handoff_method',candidate_handoff_method,
      'expires_in_seconds',candidate_expires_in_seconds,
      'idempotency_key',candidate_idempotency_key
    ),
    'member',jsonb_build_object(
      'memberId',candidate_member_id::text,
      'memberDisplayName',prepared.result_member_display_name,
      'memberKind',prepared.result_member_kind,
      'memberState',prepared.result_member_state,
      'memberRowVersion',prepared.result_member_row_version::text
    ),
    'seats',prepared.result_seats
  );
  if stage_payload<>expected_payload then
    raise exception 'enrollment issuance canonical payload is stale or malformed'
      using errcode='55000';
  end if;

  insert into public.enrollment_invitations(
    id,organization_id,member_id,token_sha256,issued_by,handoff_method,expires_at
  ) values (
    candidate_invitation_id,context_organization_id,candidate_member_id,
    candidate_invitation_token_sha256,context_actor_id,candidate_handoff_method,
    transaction_timestamp()+make_interval(secs=>candidate_expires_in_seconds)
  );
  update public.idempotency_records as changed
     set state='succeeded',safe_response_type='enrollment_invitation',
         safe_response_id=candidate_invitation_id,
         safe_response_sha256=candidate_safe_response_sha256,
         completed_at=transaction_timestamp()
   where changed.id=candidate_idempotency_record_id
     and changed.state='in_progress';
  if not found then
    raise exception 'enrollment issuance idempotency finalization failed' using errcode='40001';
  end if;

  return query
    select 'issued'::text,invitation.id,
           to_char(invitation.expires_at at time zone 'UTC',
                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           candidate_safe_response_sha256
      from public.enrollment_invitations as invitation
     where invitation.id=candidate_invitation_id;
end
$$;

alter function public.boardagent_prepare_enrollment_issuance(uuid)
  owner to boardagent_migrator;
alter function public.boardagent_finalize_enrollment_issuance(
  uuid,text,integer,text,bytea,bytea,uuid,uuid,bytea,uuid,bytea
) owner to boardagent_migrator;

revoke all on function public.boardagent_prepare_enrollment_issuance(uuid) from public;
revoke all on function public.boardagent_finalize_enrollment_issuance(
  uuid,text,integer,text,bytea,bytea,uuid,uuid,bytea,uuid,bytea
) from public;
grant execute on function public.boardagent_prepare_enrollment_issuance(uuid)
  to boardagent_server;
grant execute on function public.boardagent_finalize_enrollment_issuance(
  uuid,text,integer,text,bytea,bytea,uuid,uuid,bytea,uuid,bytea
) to boardagent_server;
