-- BoardAgent Phase 2: secretary-confirmed MCP enrollment activation.
-- The human code is persisted only as SHA-256. Preparation deliberately does not
-- reveal whether it matches; only an exact fresh consent may plan one attempt.

grant select on public.members,public.enrollment_invitations,
  public.enrollment_activation_challenges,public.webauthn_credentials,
  public.auth_sessions,public.organization_role_assignments,public.board_memberships,
  public.boards,public.access_token_records,public.oauth_clients,public.system_instance,
  public.onboarding_attestations,public.onboarding_terms_versions,
  public.secretary_support_versions,public.consent_records,public.action_stages,
  public.audit_events,public.pending_action_feed to boardagent_migrator;
grant update(state,row_version) on public.members to boardagent_migrator;
grant update(id) on public.enrollment_invitations,public.board_memberships
  to boardagent_migrator;
grant update(state,attempt_count,consumed_at,confirmed_by)
  on public.enrollment_activation_challenges to boardagent_migrator;
grant select,insert,update on public.idempotency_records to boardagent_migrator;

create policy boardagent_migrator_confirm_activation_member_read
  on public.members for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_confirm_activation_member_update
  on public.members for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_confirm_activation_challenge_read
  on public.enrollment_activation_challenges for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_confirm_activation_challenge_update
  on public.enrollment_activation_challenges for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_confirm_activation_invitation_lock
  on public.enrollment_invitations for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_confirm_activation_membership_lock
  on public.board_memberships for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

do $policies$
declare
  relation_name text;
begin
  foreach relation_name in array array[
    'enrollment_invitations','webauthn_credentials','auth_sessions',
    'organization_role_assignments','board_memberships','access_token_records',
    'oauth_clients','onboarding_attestations','onboarding_terms_versions',
    'secretary_support_versions','consent_records','action_stages','audit_events',
    'pending_action_feed','idempotency_records'
  ] loop
    execute format(
      'create policy boardagent_migrator_confirm_activation_read on public.%I for select to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id''))',
      relation_name
    );
  end loop;
end
$policies$;
create policy boardagent_migrator_confirm_activation_board_read
  on public.boards for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_confirm_activation_instance_read
  on public.system_instance for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_confirm_activation_idempotency_insert
  on public.idempotency_records for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='confirm_enrollment_activation'
  );
create policy boardagent_migrator_confirm_activation_idempotency_update
  on public.idempotency_records for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='confirm_enrollment_activation'
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and client_id=public.boardagent_context_uuid('boardagent.client_id')
    and operation='confirm_enrollment_activation'
  );

create function public.boardagent_prepare_confirmed_enrollment_activation(
  candidate_member_id uuid,
  candidate_invitation_id uuid,
  candidate_challenge_id uuid,
  candidate_protected_code_sha256 bytea,
  candidate_proofing_method text
)
returns table(
  result_status text,
  result_member_display_name text,
  result_member_state text,
  result_member_row_version bigint,
  result_challenge_expires_at text,
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
  context_client_id uuid;
  context_token_jti uuid;
  invitation public.enrollment_invitations%rowtype;
  target public.members%rowtype;
  challenge public.enrollment_activation_challenges%rowtype;
  seats jsonb;
  actor_ready boolean;
begin
  context_organization_id := public.boardagent_context_uuid('boardagent.organization_id');
  context_actor_id := public.boardagent_context_uuid('boardagent.member_id');
  context_client_id := public.boardagent_context_uuid('boardagent.client_id');
  context_token_jti := public.boardagent_context_uuid('boardagent.token_jti');
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or context_organization_id is null
     or context_actor_id is null
     or context_client_id is null
     or context_token_jti is null then
    raise exception 'confirmed enrollment activation requires a managed request transaction'
      using errcode='25000';
  end if;
  if candidate_member_id is null
     or candidate_invitation_id is null
     or candidate_challenge_id is null
     or candidate_protected_code_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_protected_code_sha256)
     or candidate_proofing_method not in ('in_person','verified_number_call') then
    raise exception 'confirmed enrollment activation inputs are invalid' using errcode='22023';
  end if;

  -- Match the existing identity-activation lock order so browser and MCP paths cannot
  -- deadlock: invitation, target member, challenge, then target memberships.
  select candidate.* into invitation
    from public.enrollment_invitations as candidate
   where candidate.id=candidate_invitation_id
     and candidate.organization_id=context_organization_id
   for update;
  select member.* into target
    from public.members as member
   where member.id=candidate_member_id
     and member.organization_id=context_organization_id
   for update;
  select candidate.* into challenge
    from public.enrollment_activation_challenges as candidate
   where candidate.id=candidate_challenge_id
     and candidate.organization_id=context_organization_id
   for update;
  perform membership.id
    from public.board_memberships as membership
   where membership.organization_id=context_organization_id
     and membership.member_id=candidate_member_id
     and membership.state='active'
     and membership.active_from<=transaction_timestamp()
     and (membership.active_until is null
          or membership.active_until>transaction_timestamp())
   order by membership.board_id,membership.id
   for update;

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
       and token.client_id=context_client_id
       and token.jti=context_token_jti
      join public.auth_sessions as session
        on session.id=token.session_id
       and session.organization_id=token.organization_id
       and session.member_id=token.member_id
       and session.client_id=token.client_id
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
       and session.state='authenticated'
       and session.expires_at>transaction_timestamp()
       and session.last_authenticated_at>=transaction_timestamp()-interval '10 minutes'
       and not exists (
         select 1
           from public.board_memberships as target_membership
          where target_membership.organization_id=context_organization_id
            and target_membership.member_id=candidate_member_id
            and target_membership.state='active'
            and target_membership.active_from<=transaction_timestamp()
            and (target_membership.active_until is null
                 or target_membership.active_until>transaction_timestamp())
            and not public.boardagent_context_board_allowed(target_membership.board_id)
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
              and not exists (
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
  ) into actor_ready;

  if invitation.id is null
     or target.id is null
     or challenge.id is null
     or target.state<>'pending_activation'
     or invitation.member_id<>candidate_member_id
     or invitation.pending_activation_member_id is distinct from candidate_member_id
     or invitation.consumed_at is null
     or invitation.consumed_at>invitation.expires_at
     or invitation.consumed_at>transaction_timestamp()
     or invitation.revoked_at is not null
     or challenge.member_id<>candidate_member_id
     or challenge.invitation_id<>candidate_invitation_id
     or challenge.state<>'issued'
     or challenge.expires_at<=transaction_timestamp()
     or challenge.attempt_count>=20
     or challenge.proofing_method<>candidate_proofing_method
     or not exists (
       select 1 from public.webauthn_credentials as credential
        where credential.organization_id=context_organization_id
          and credential.member_id=candidate_member_id
          and credential.state='active'
     )
     or seats is null
     or jsonb_array_length(seats) not between 1 and 25
     or not actor_ready then
    return query select 'unavailable'::text,null::text,null::text,null::bigint,
      null::text,null::jsonb;
    return;
  end if;

  return query select 'ready'::text,target.display_name,target.state,target.row_version,
    to_char(challenge.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),seats;
end
$$;

create function public.boardagent_plan_confirmed_enrollment_activation(
  candidate_member_id uuid,
  candidate_invitation_id uuid,
  candidate_challenge_id uuid,
  candidate_protected_code_sha256 bytea,
  candidate_proofing_method text,
  candidate_idempotency_key text,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid
)
returns table(
  result_status text,
  result_challenge_state text,
  result_attempt_count integer,
  result_member_row_version bigint
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
  challenge public.enrollment_activation_challenges%rowtype;
  stage_payload jsonb;
  expected_payload jsonb;
begin
  if candidate_idempotency_key is null
     or length(candidate_idempotency_key) not between 16 and 200
     or candidate_idempotency_key !~ '^[A-Za-z0-9._~-]+$'
     or candidate_payload_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_payload_sha256)
     or candidate_consent_record_id is null then
    raise exception 'confirmed activation plan inputs are invalid' using errcode='22023';
  end if;
  select * into strict prepared
    from public.boardagent_prepare_confirmed_enrollment_activation(
      candidate_member_id,candidate_invitation_id,candidate_challenge_id,
      candidate_protected_code_sha256,candidate_proofing_method
    );
  if prepared.result_status is distinct from 'ready' then
    return query select 'unavailable'::text,null::text,null::integer,null::bigint;
    return;
  end if;
  select candidate.* into consent
    from public.consent_records as candidate
   where candidate.id=candidate_consent_record_id
     and candidate.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
     and candidate.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
     and candidate.client_id=public.boardagent_context_uuid('boardagent.client_id')
     and candidate.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
     and candidate.action_code='confirm_enrollment_activation'
     and candidate.target_type='member'
     and candidate.target_id=candidate_member_id
     and candidate.payload_sha256=candidate_payload_sha256
     and candidate.confirmed_at=transaction_timestamp();
  select candidate.* into stage
    from public.action_stages as candidate
   where candidate.id=consent.stage_id
     and candidate.organization_id=consent.organization_id
     and candidate.state='active'
     and candidate.action_code='confirm_enrollment_activation'
     and candidate.target_type='member'
     and candidate.target_id=candidate_member_id
     and candidate.payload_sha256=candidate_payload_sha256;
  if consent.id is null or stage.id is null then
    raise exception 'confirmed activation requires its exact fresh consent stage'
      using errcode='55000';
  end if;
  begin
    stage_payload := convert_from(stage.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'confirmed activation stage payload is invalid' using errcode='23514';
  end;
  expected_payload := jsonb_build_object(
    'schemaVersion','boardagent.enrollment-activation.v1',
    'request',jsonb_build_object(
      'schema_version','boardagent.tool-input.v1',
      'member_id',candidate_member_id::text,
      'invitation_id',candidate_invitation_id::text,
      'challenge_id',candidate_challenge_id::text,
      'confirmation_code_sha256',encode(candidate_protected_code_sha256,'hex'),
      'proofing_method',candidate_proofing_method,
      'idempotency_key',candidate_idempotency_key
    ),
    'member',jsonb_build_object(
      'memberId',candidate_member_id::text,
      'memberDisplayName',prepared.result_member_display_name,
      'memberState',prepared.result_member_state,
      'memberRowVersion',prepared.result_member_row_version::text
    ),
    'challenge',jsonb_build_object(
      'invitationId',candidate_invitation_id::text,
      'challengeId',candidate_challenge_id::text,
      'expiresAt',prepared.result_challenge_expires_at,
      'proofingMethod',candidate_proofing_method
    ),
    'seats',prepared.result_seats
  );
  if stage_payload<>expected_payload then
    raise exception 'confirmed activation canonical payload is stale or malformed'
      using errcode='55000';
  end if;
  select candidate.* into strict challenge
    from public.enrollment_activation_challenges as candidate
   where candidate.id=candidate_challenge_id;
  if public.boardagent_constant_time_sha256_equal(
       challenge.protected_code,candidate_protected_code_sha256
     ) then
    return query select 'activated'::text,'consumed'::text,challenge.attempt_count,
      prepared.result_member_row_version+1;
  else
    return query select 'code_mismatch'::text,
      case when challenge.attempt_count+1>=20 then 'revoked'::text else 'issued'::text end,
      challenge.attempt_count+1,null::bigint;
  end if;
end
$$;

create function public.boardagent_finalize_confirmed_enrollment_activation(
  candidate_member_id uuid,
  candidate_invitation_id uuid,
  candidate_challenge_id uuid,
  candidate_protected_code_sha256 bytea,
  candidate_proofing_method text,
  candidate_idempotency_key text,
  candidate_request_sha256 bytea,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid,
  candidate_idempotency_record_id uuid,
  candidate_audit_event_id uuid,
  candidate_feed_ids uuid[],
  candidate_safe_response_sha256 bytea
)
returns table(
  result_status text,
  result_challenge_state text,
  result_attempt_count integer,
  result_member_row_version bigint,
  result_safe_response_sha256 bytea
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  planned record;
  audit public.audit_events%rowtype;
  audit_payload jsonb;
  expected_details jsonb;
  feed public.pending_action_feed%rowtype;
  feed_payload jsonb;
  expected_board_ids uuid[];
  expected_generation bigint;
  feed_position integer;
  context_organization_id uuid;
  context_actor_id uuid;
  context_client_id uuid;
  context_token_jti uuid;
  idempotency public.idempotency_records%rowtype;
  inserted_idempotency_id uuid;
begin
  context_organization_id := public.boardagent_context_uuid('boardagent.organization_id');
  context_actor_id := public.boardagent_context_uuid('boardagent.member_id');
  context_client_id := public.boardagent_context_uuid('boardagent.client_id');
  context_token_jti := public.boardagent_context_uuid('boardagent.token_jti');
  if candidate_request_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_request_sha256)
     or candidate_idempotency_record_id is null
     or not public.boardagent_is_uuid_v7(candidate_idempotency_record_id)
     or candidate_audit_event_id is null
     or not public.boardagent_is_uuid_v7(candidate_audit_event_id)
     or candidate_feed_ids is null
     or array_position(candidate_feed_ids,null) is not null
     or cardinality(candidate_feed_ids)<>(
       select count(distinct requested.feed_id)::integer
         from unnest(candidate_feed_ids) as requested(feed_id)
     )
     or candidate_safe_response_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_safe_response_sha256) then
    raise exception 'confirmed activation finalization inputs are invalid' using errcode='22023';
  end if;
  select * into strict planned
    from public.boardagent_plan_confirmed_enrollment_activation(
      candidate_member_id,candidate_invitation_id,candidate_challenge_id,
      candidate_protected_code_sha256,candidate_proofing_method,candidate_idempotency_key,
      candidate_payload_sha256,candidate_consent_record_id
    );
  if planned.result_status not in ('activated','code_mismatch') then
    return query select 'unavailable'::text,null::text,null::integer,null::bigint,null::bytea;
    return;
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      context_actor_id::text || chr(1) || context_client_id::text || chr(1) ||
        candidate_idempotency_key,
      424256::bigint
    )
  );
  insert into public.idempotency_records(
    id,organization_id,actor_member_id,client_id,operation,idempotency_key,
    request_sha256,state,expires_at
  ) values (
    candidate_idempotency_record_id,context_organization_id,context_actor_id,
    context_client_id,'confirm_enrollment_activation',candidate_idempotency_key,
    candidate_request_sha256,'in_progress',transaction_timestamp()+interval '24 hours'
  )
  on conflict (actor_member_id,client_id,operation,idempotency_key) do nothing
  returning id into inserted_idempotency_id;
  select record.* into idempotency
    from public.idempotency_records as record
   where record.actor_member_id=context_actor_id
     and record.client_id=context_client_id
     and record.operation='confirm_enrollment_activation'
     and record.idempotency_key=candidate_idempotency_key
   for update;
  if idempotency.id is null then
    raise exception 'confirmed activation idempotency record is unavailable' using errcode='55000';
  end if;
  if not public.boardagent_constant_time_sha256_equal(
       idempotency.request_sha256,candidate_request_sha256
     ) then
    return query select 'idempotency_conflict'::text,null::text,null::integer,
      null::bigint,null::bytea;
    return;
  end if;
  if inserted_idempotency_id is null then
    return query select 'unavailable'::text,null::text,null::integer,null::bigint,null::bytea;
    return;
  end if;

  select event.* into audit
    from public.audit_events as event
   where event.id=candidate_audit_event_id
     and event.organization_id=context_organization_id
     and event.consent_record_id=candidate_consent_record_id
     and event.actor_member_id=context_actor_id
     and event.client_id=context_client_id
     and event.token_jti=context_token_jti
     and event.board_id is null;
  if audit.id is null then
    raise exception 'confirmed activation audit evidence is missing' using errcode='55000';
  end if;
  begin
    audit_payload := convert_from(audit.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'confirmed activation audit payload is invalid' using errcode='23514';
  end;
  if jsonb_typeof(audit_payload)<>'object'
     or not audit_payload ?& array[
       'eventId','eventType','actorMemberId','actorClientId','tokenJti','entityType',
       'entityId','boardId','occurredAt','origin','details','schemaVersion'
     ]
     or audit_payload-array[
       'eventId','eventType','actorMemberId','actorClientId','tokenJti','entityType',
       'entityId','boardId','occurredAt','origin','details','schemaVersion'
     ]::text[]<>'{}'::jsonb
     or jsonb_typeof(audit_payload->'details')<>'object'
     or audit_payload->>'eventId' is distinct from audit.id::text
     or audit_payload->>'actorMemberId' is distinct from context_actor_id::text
     or audit_payload->>'actorClientId' is distinct from context_client_id::text
     or audit_payload->>'tokenJti' is distinct from context_token_jti::text
     or audit_payload->'boardId'<>'null'::jsonb
     or audit_payload->>'origin'<>'mcp'
     or audit_payload->>'schemaVersion'<>'1'
     or (audit_payload->>'occurredAt')::timestamptz is distinct from audit.occurred_at then
    raise exception 'confirmed activation audit context does not match' using errcode='23514';
  end if;

  select coalesce(array_agg(membership.board_id order by membership.board_id),'{}'::uuid[])
    into expected_board_ids
    from public.board_memberships as membership
   where membership.organization_id=context_organization_id
     and membership.member_id=candidate_member_id
     and membership.state='active'
     and membership.active_from<=transaction_timestamp()
     and (membership.active_until is null
          or membership.active_until>transaction_timestamp());

  if planned.result_status='code_mismatch' then
    expected_details := jsonb_build_object(
      'reason','code_mismatch',
      'memberId',candidate_member_id::text,
      'invitationId',candidate_invitation_id::text,
      'attemptCount',planned.result_attempt_count,
      'challengeState',planned.result_challenge_state
    );
    if cardinality(candidate_feed_ids)<>0
       or audit.event_type<>'authorization_denied'
       or audit.object_type<>'enrollment_activation'
       or audit.object_id<>candidate_challenge_id
       or audit.object_version is not null
       or audit_payload->>'eventType'<>'authorization_denied'
       or audit_payload->>'entityType'<>'enrollment_activation'
       or audit_payload->>'entityId' is distinct from candidate_challenge_id::text
       or audit_payload->'details'<>expected_details
       or exists (
         select 1 from public.pending_action_feed as existing
          where existing.audit_event_id=audit.id
       ) then
      raise exception 'confirmed activation denial evidence is invalid' using errcode='23514';
    end if;
    update public.enrollment_activation_challenges as changed
       set attempt_count=planned.result_attempt_count,state=planned.result_challenge_state
     where changed.id=candidate_challenge_id
       and changed.organization_id=context_organization_id
       and changed.state='issued'
       and changed.attempt_count=planned.result_attempt_count-1;
    if not found then
      raise exception 'activation challenge changed during denial finalization'
        using errcode='40001';
    end if;
  else
    expected_details := jsonb_build_object(
      'invitationId',candidate_invitation_id::text,
      'challengeId',candidate_challenge_id::text,
      'proofingMethod',candidate_proofing_method,
      'passkeyEnrolled',true,
      'feedBoardCount',cardinality(expected_board_ids)
    );
    if cardinality(candidate_feed_ids)<>cardinality(expected_board_ids)
       or audit.event_type<>'member_activated'
       or audit.object_type<>'member'
       or audit.object_id<>candidate_member_id
       or audit.object_version<>planned.result_member_row_version
       or audit_payload->>'eventType'<>'member_activated'
       or audit_payload->>'entityType'<>'member'
       or audit_payload->>'entityId' is distinct from candidate_member_id::text
       or audit_payload->'details'<>expected_details then
      raise exception 'confirmed member activation evidence is invalid' using errcode='23514';
    end if;
    for feed_position in 1..cardinality(expected_board_ids) loop
      select membership.entitlement_generation into expected_generation
        from public.board_memberships as membership
       where membership.organization_id=context_organization_id
         and membership.member_id=candidate_member_id
         and membership.board_id=expected_board_ids[feed_position]
         and membership.state='active';
      select entry.* into feed
        from public.pending_action_feed as entry
       where entry.id=candidate_feed_ids[feed_position];
      if feed.id is null
         or feed.organization_id<>context_organization_id
         or feed.board_id<>expected_board_ids[feed_position]
         or feed.member_id<>candidate_member_id
         or feed.entitlement_generation<>expected_generation
         or feed.action_type<>'complete_onboarding'
         or feed.object_type<>'member'
         or feed.object_id<>candidate_member_id
         or feed.object_version<>planned.result_member_row_version
         or feed.state<>'pending'
         or feed.audit_event_id<>audit.id
         or pg_catalog.sha256(feed.canonical_payload)<>feed.payload_sha256
         or exists (
           select 1 from public.pending_action_feed as later
            where later.member_id=feed.member_id
              and later.board_id=feed.board_id
              and later.entitlement_generation=feed.entitlement_generation
              and later.feed_sequence>feed.feed_sequence
         ) then
        raise exception 'confirmed activation feed evidence is invalid' using errcode='23514';
      end if;
      begin
        feed_payload := convert_from(feed.canonical_payload,'UTF8')::jsonb;
      exception when others then
        raise exception 'confirmed activation feed payload is invalid' using errcode='23514';
      end;
      if feed_payload<>jsonb_build_object(
           'schemaVersion','boardagent.pending-action.v1',
           'actionType','complete_onboarding',
           'memberId',candidate_member_id::text,
           'boardId',expected_board_ids[feed_position]::text,
           'objectType','member',
           'objectId',candidate_member_id::text,
           'objectVersion',planned.result_member_row_version::text
         ) then
        raise exception 'confirmed activation feed payload does not match' using errcode='23514';
      end if;
    end loop;
    if (
      select count(*) from public.pending_action_feed as linked
       where linked.audit_event_id=audit.id
    )<>cardinality(candidate_feed_ids) then
      raise exception 'confirmed activation audit has an unexpected feed count'
        using errcode='23514';
    end if;
    update public.enrollment_activation_challenges as changed
       set state='consumed',consumed_at=transaction_timestamp(),confirmed_by=context_actor_id
     where changed.id=candidate_challenge_id
       and changed.organization_id=context_organization_id
       and changed.state='issued'
       and changed.attempt_count=planned.result_attempt_count;
    if not found then
      raise exception 'activation challenge changed during finalization' using errcode='40001';
    end if;
    update public.members as changed
       set state='active',row_version=changed.row_version+1
     where changed.id=candidate_member_id
       and changed.organization_id=context_organization_id
       and changed.state='pending_activation'
       and changed.row_version=planned.result_member_row_version-1;
    if not found then
      raise exception 'member changed during activation finalization' using errcode='40001';
    end if;
  end if;

  update public.idempotency_records as changed
     set state='succeeded',
         safe_response_type=case when planned.result_status='activated'
           then 'member' else 'enrollment_activation' end,
         safe_response_id=case when planned.result_status='activated'
           then candidate_member_id else candidate_challenge_id end,
         safe_response_sha256=candidate_safe_response_sha256,
         completed_at=transaction_timestamp()
   where changed.id=candidate_idempotency_record_id and changed.state='in_progress';
  if not found then
    raise exception 'activation idempotency finalization failed' using errcode='40001';
  end if;
  return query select planned.result_status,planned.result_challenge_state,
    planned.result_attempt_count,planned.result_member_row_version,
    candidate_safe_response_sha256;
end
$$;

alter function public.boardagent_prepare_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text
) owner to boardagent_migrator;
alter function public.boardagent_plan_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text,text,bytea,uuid
) owner to boardagent_migrator;
alter function public.boardagent_finalize_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text,text,bytea,bytea,uuid,uuid,uuid,uuid[],bytea
) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text
) from public;
revoke all on function public.boardagent_plan_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text,text,bytea,uuid
) from public;
revoke all on function public.boardagent_finalize_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text,text,bytea,bytea,uuid,uuid,uuid,uuid[],bytea
) from public;
grant execute on function public.boardagent_prepare_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text
) to boardagent_server;
grant execute on function public.boardagent_plan_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text,text,bytea,uuid
) to boardagent_server;
grant execute on function public.boardagent_finalize_confirmed_enrollment_activation(
  uuid,uuid,uuid,bytea,text,text,bytea,bytea,uuid,uuid,uuid,uuid[],bytea
) to boardagent_server;
