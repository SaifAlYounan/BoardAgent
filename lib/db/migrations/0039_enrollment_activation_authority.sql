-- BoardAgent Phase 1 / group 39: exact enrollment activation authority.

-- The request role may observe identity projections, but it cannot mutate the
-- activation challenge or member projection directly. A protected prepare/finalize
-- pair keeps canonical audit/feed construction in the repository while making the
-- state transition impossible to commit without its exact evidence.
revoke update(state,attempt_count,consumed_at,confirmed_by)
  on public.enrollment_activation_challenges from boardagent_server;

grant select on
  public.members,
  public.enrollment_invitations,
  public.enrollment_activation_challenges,
  public.webauthn_credentials,
  public.auth_sessions,
  public.organization_role_assignments,
  public.board_memberships,
  public.audit_events,
  public.pending_action_feed
to boardagent_migrator;
grant update(state,row_version) on public.members to boardagent_migrator;
grant update(id) on public.enrollment_invitations to boardagent_migrator;
grant update(state,attempt_count,consumed_at,confirmed_by)
  on public.enrollment_activation_challenges to boardagent_migrator;
grant update(id) on public.auth_sessions,public.organization_role_assignments
  to boardagent_migrator;

-- Every relation used by the definer has an explicit identity-scope policy. Some
-- earlier transaction migrations also grant broader migrator visibility; these
-- policies make this function's intended RLS dependencies auditable in one place.
create policy boardagent_migrator_identity_member_read on public.members
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_member_update on public.members
  for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_invitation_read on public.enrollment_invitations
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_invitation_lock on public.enrollment_invitations
  for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_challenge_read
  on public.enrollment_activation_challenges
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_challenge_update
  on public.enrollment_activation_challenges
  for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_webauthn_read on public.webauthn_credentials
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_session_read on public.auth_sessions
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_session_lock on public.auth_sessions
  for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_role_read on public.organization_role_assignments
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_role_lock on public.organization_role_assignments
  for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_membership_read on public.board_memberships
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_membership_lock on public.board_memberships
  for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_audit_read on public.audit_events
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_feed_read on public.pending_action_feed
  for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

create function public.boardagent_constant_time_sha256_equal(left_value bytea,right_value bytea)
returns boolean
language plpgsql
immutable
strict
parallel safe
set search_path=pg_catalog
as $$
declare
  difference integer := 0;
  position integer;
begin
  if octet_length(left_value)<>32 or octet_length(right_value)<>32 then
    return false;
  end if;
  for position in 0..31 loop
    difference := difference | (get_byte(left_value,position) # get_byte(right_value,position));
  end loop;
  return difference=0;
end
$$;

create function public.boardagent_prepare_enrollment_activation(
  candidate_organization_id uuid,
  candidate_member_id uuid,
  candidate_invitation_id uuid,
  candidate_challenge_id uuid,
  candidate_protected_code_sha256 bytea,
  candidate_proofing_method text,
  candidate_secretary_member_id uuid,
  candidate_secretary_session_id uuid,
  candidate_feed_board_ids uuid[]
)
returns table(
  result_status text,
  result_challenge_state text,
  result_attempt_count integer,
  result_member_row_version bigint,
  result_secretary_client_id uuid,
  result_board_ids uuid[]
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  invitation public.enrollment_invitations%rowtype;
  target public.members%rowtype;
  challenge public.enrollment_activation_challenges%rowtype;
  expected_board_ids uuid[];
  supplied_board_ids uuid[];
  context_board_ids uuid[];
  has_organization_authority boolean;
  has_all_board_authority boolean;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or candidate_organization_id is distinct from
       public.boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'enrollment activation requires a managed serializable identity transaction'
      using errcode='25000';
  end if;
  if candidate_member_id is null
     or candidate_invitation_id is null
     or candidate_challenge_id is null
     or candidate_secretary_member_id is null
     or candidate_secretary_session_id is null
     or candidate_protected_code_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_protected_code_sha256)
     or candidate_proofing_method is null
     or length(candidate_proofing_method) not between 1 and 1024
     or candidate_feed_board_ids is null
     or cardinality(candidate_feed_board_ids) not between 1 and 25
     or array_position(candidate_feed_board_ids,null) is not null
     or cardinality(candidate_feed_board_ids)<>(
       select count(distinct requested.board_id)::integer
         from unnest(candidate_feed_board_ids) as requested(board_id)
     ) then
    raise exception 'enrollment activation inputs are invalid' using errcode='22023';
  end if;

  -- Stable lock order: invitation, target member, challenge, target memberships,
  -- secretary session/actor, then current secretary authority rows. Audit is locked
  -- later by the repository only after every aggregate lock has been taken.
  select candidate.* into invitation
    from public.enrollment_invitations as candidate
   where candidate.id=candidate_invitation_id
     and candidate.organization_id=candidate_organization_id
   for update;
  select member.* into target
    from public.members as member
   where member.id=candidate_member_id
     and member.organization_id=candidate_organization_id
   for update;
  select candidate.* into challenge
    from public.enrollment_activation_challenges as candidate
   where candidate.id=candidate_challenge_id
     and candidate.organization_id=candidate_organization_id
   for update;

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
     or octet_length(challenge.protected_code)<>32
     or not exists (
       select 1
         from public.webauthn_credentials as credential
        where credential.organization_id=candidate_organization_id
          and credential.member_id=candidate_member_id
          and credential.state='active'
     ) then
    return query
      select 'unavailable'::text,null::text,null::integer,null::bigint,null::uuid,null::uuid[];
    return;
  end if;

  perform membership.id
    from public.board_memberships as membership
   where membership.organization_id=candidate_organization_id
     and membership.member_id=candidate_member_id
     and membership.state='active'
     and membership.active_from<=transaction_timestamp()
     and (membership.active_until is null or membership.active_until>transaction_timestamp())
   order by membership.board_id,membership.id
   for update;
  select coalesce(array_agg(membership.board_id order by membership.board_id),'{}'::uuid[])
    into expected_board_ids
    from public.board_memberships as membership
   where membership.organization_id=candidate_organization_id
     and membership.member_id=candidate_member_id
     and membership.state='active'
     and membership.active_from<=transaction_timestamp()
     and (membership.active_until is null or membership.active_until>transaction_timestamp());
  select coalesce(array_agg(requested.board_id order by requested.board_id),'{}'::uuid[])
    into supplied_board_ids
    from unnest(candidate_feed_board_ids) as requested(board_id);
  begin
    select coalesce(array_agg(context_value.board_id order by context_value.board_id),'{}'::uuid[])
      into context_board_ids
      from (
        select distinct allowed.value::uuid as board_id
          from jsonb_array_elements_text(
            current_setting('boardagent.board_ids',true)::jsonb
          ) as allowed(value)
      ) as context_value;
  exception when others then
    raise exception 'identity board context is invalid' using errcode='25000';
  end;
  if cardinality(expected_board_ids) not between 1 and 25
     or expected_board_ids<>supplied_board_ids
     or expected_board_ids<>context_board_ids then
    return query
      select 'unavailable'::text,null::text,null::integer,null::bigint,null::uuid,null::uuid[];
    return;
  end if;

  perform session.id
    from public.auth_sessions as session
   where session.id=candidate_secretary_session_id
     and session.organization_id=candidate_organization_id
     and session.member_id=candidate_secretary_member_id
   for update;
  perform actor.id
    from public.members as actor
   where actor.id=candidate_secretary_member_id
     and actor.organization_id=candidate_organization_id
   for update;
  select session.client_id into result_secretary_client_id
    from public.auth_sessions as session
    join public.members as actor
      on actor.id=session.member_id and actor.organization_id=session.organization_id
   where session.id=candidate_secretary_session_id
     and session.organization_id=candidate_organization_id
     and session.member_id=candidate_secretary_member_id
     and session.state='authenticated'
     and session.expires_at>transaction_timestamp()
     and session.last_authenticated_at>=transaction_timestamp()-interval '10 minutes'
     and actor.state='active'
   limit 1;
  if not found then
    return query
      select 'secretary_invalid'::text,null::text,null::integer,null::bigint,null::uuid,
             expected_board_ids;
    return;
  end if;

  perform role_assignment.id
    from public.organization_role_assignments as role_assignment
   where role_assignment.organization_id=candidate_organization_id
     and role_assignment.member_id=candidate_secretary_member_id
     and role_assignment.role in ('admin','secretariat')
     and role_assignment.active_from<=transaction_timestamp()
     and (role_assignment.active_until is null
          or role_assignment.active_until>transaction_timestamp())
   order by role_assignment.id
   for update;
  select exists (
    select 1
      from public.organization_role_assignments as role_assignment
     where role_assignment.organization_id=candidate_organization_id
       and role_assignment.member_id=candidate_secretary_member_id
       and role_assignment.role in ('admin','secretariat')
       and role_assignment.active_from<=transaction_timestamp()
       and (role_assignment.active_until is null
            or role_assignment.active_until>transaction_timestamp())
  ) into has_organization_authority;

  perform secretary_membership.id
    from public.board_memberships as secretary_membership
   where secretary_membership.organization_id=candidate_organization_id
     and secretary_membership.member_id=candidate_secretary_member_id
     and secretary_membership.board_id=any(expected_board_ids)
     and secretary_membership.is_secretary
     and secretary_membership.state='active'
     and secretary_membership.active_from<=transaction_timestamp()
     and (secretary_membership.active_until is null
          or secretary_membership.active_until>transaction_timestamp())
   order by secretary_membership.board_id,secretary_membership.id
   for update;
  select not exists (
    select 1
      from unnest(expected_board_ids) as expected(board_id)
     where not exists (
       select 1
         from public.board_memberships as secretary_membership
        where secretary_membership.organization_id=candidate_organization_id
          and secretary_membership.member_id=candidate_secretary_member_id
          and secretary_membership.board_id=expected.board_id
          and secretary_membership.is_secretary
          and secretary_membership.state='active'
          and secretary_membership.active_from<=transaction_timestamp()
          and (secretary_membership.active_until is null
               or secretary_membership.active_until>transaction_timestamp())
     )
  ) into has_all_board_authority;
  if not has_organization_authority and not has_all_board_authority then
    return query
      select 'secretary_invalid'::text,null::text,null::integer,null::bigint,null::uuid,
             expected_board_ids;
    return;
  end if;

  result_board_ids := expected_board_ids;
  if public.boardagent_constant_time_sha256_equal(
       challenge.protected_code,candidate_protected_code_sha256
     ) then
    result_status := 'activated';
    result_challenge_state := 'consumed';
    result_attempt_count := challenge.attempt_count;
    result_member_row_version := target.row_version+1;
  else
    result_status := 'code_mismatch';
    result_attempt_count := challenge.attempt_count+1;
    result_challenge_state := case
      when result_attempt_count>=20 then 'revoked' else 'issued' end;
    result_member_row_version := null;
  end if;
  return next;
end
$$;

create function public.boardagent_finalize_enrollment_activation(
  candidate_organization_id uuid,
  candidate_member_id uuid,
  candidate_invitation_id uuid,
  candidate_challenge_id uuid,
  candidate_protected_code_sha256 bytea,
  candidate_proofing_method text,
  candidate_secretary_member_id uuid,
  candidate_secretary_session_id uuid,
  candidate_feed_board_ids uuid[],
  candidate_audit_event_id uuid,
  candidate_feed_ids uuid[]
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
  audit public.audit_events%rowtype;
  audit_payload jsonb;
  audit_details jsonb;
  feed public.pending_action_feed%rowtype;
  feed_payload jsonb;
  expected_generation bigint;
  feed_position integer;
begin
  if candidate_audit_event_id is null
     or candidate_feed_ids is null
     or array_position(candidate_feed_ids,null) is not null
     or cardinality(candidate_feed_ids)<>(
       select count(distinct requested.feed_id)::integer
         from unnest(candidate_feed_ids) as requested(feed_id)
     ) then
    raise exception 'enrollment finalization evidence identifiers are invalid'
      using errcode='22023';
  end if;
  select * into strict prepared
    from public.boardagent_prepare_enrollment_activation(
      candidate_organization_id,candidate_member_id,candidate_invitation_id,
      candidate_challenge_id,candidate_protected_code_sha256,candidate_proofing_method,
      candidate_secretary_member_id,candidate_secretary_session_id,candidate_feed_board_ids
    );
  if prepared.result_status not in ('activated','code_mismatch') then
    raise exception 'enrollment activation is no longer eligible for finalization'
      using errcode='55000';
  end if;

  select event.* into audit
    from public.audit_events as event
   where event.id=candidate_audit_event_id
     and event.organization_id=candidate_organization_id;
  if audit.id is null then
    raise exception 'enrollment activation audit evidence is missing' using errcode='55000';
  end if;
  begin
    audit_payload := convert_from(audit.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'enrollment activation audit payload is invalid' using errcode='23514';
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
     or audit_payload->>'eventId' is distinct from candidate_audit_event_id::text
     or audit_payload->>'actorMemberId' is distinct from candidate_secretary_member_id::text
     or audit_payload->'actorClientId' is distinct from (
       case when prepared.result_secretary_client_id is null then 'null'::jsonb
            else to_jsonb(prepared.result_secretary_client_id::text) end
     )
     or audit_payload->'tokenJti'<>'null'::jsonb
     or audit_payload->'boardId'<>'null'::jsonb
     or audit_payload->>'origin'<>'browser'
     or audit_payload->>'schemaVersion'<>'1'
     or (audit_payload->>'occurredAt')::timestamptz is distinct from audit.occurred_at
     or audit.actor_member_id is distinct from candidate_secretary_member_id
     or audit.client_id is distinct from prepared.result_secretary_client_id
     or audit.token_jti is not null
     or audit.board_id is not null then
    raise exception 'enrollment activation audit evidence does not match its projection'
      using errcode='23514';
  end if;
  audit_details := audit_payload->'details';

  if prepared.result_status='code_mismatch' then
    if cardinality(candidate_feed_ids)<>0
       or audit.event_type<>'authorization_denied'
       or audit.object_type<>'enrollment_activation'
       or audit.object_id is distinct from candidate_challenge_id
       or audit.object_version is not null
       or audit_payload->>'eventType'<>'authorization_denied'
       or audit_payload->>'entityType'<>'enrollment_activation'
       or audit_payload->>'entityId' is distinct from candidate_challenge_id::text
       or audit_details<>jsonb_build_object(
         'reason','code_mismatch',
         'memberId',candidate_member_id::text,
         'invitationId',candidate_invitation_id::text,
         'attemptCount',prepared.result_attempt_count,
         'challengeState',prepared.result_challenge_state
       )
       or exists (
         select 1 from public.pending_action_feed as existing
          where existing.audit_event_id=candidate_audit_event_id
       ) then
      raise exception 'enrollment mismatch audit evidence is incomplete or conflicting'
        using errcode='23514';
    end if;
    update public.enrollment_activation_challenges as changed
       set attempt_count=prepared.result_attempt_count,
           state=prepared.result_challenge_state
     where changed.id=candidate_challenge_id
       and changed.organization_id=candidate_organization_id
       and changed.state='issued'
       and changed.attempt_count=prepared.result_attempt_count-1
    returning changed.state,changed.attempt_count
      into result_challenge_state,result_attempt_count;
    if not found then
      raise exception 'enrollment challenge changed during mismatch finalization'
        using errcode='40001';
    end if;
    result_status := 'code_mismatch';
    result_member_row_version := null;
    return next;
    return;
  end if;

  if cardinality(candidate_feed_ids)<>cardinality(prepared.result_board_ids)
     or audit.event_type<>'member_activated'
     or audit.object_type<>'member'
     or audit.object_id is distinct from candidate_member_id
     or audit.object_version is distinct from prepared.result_member_row_version
     or audit_payload->>'eventType'<>'member_activated'
     or audit_payload->>'entityType'<>'member'
     or audit_payload->>'entityId' is distinct from candidate_member_id::text
     or audit_details<>jsonb_build_object(
       'invitationId',candidate_invitation_id::text,
       'challengeId',candidate_challenge_id::text,
       'proofingMethod',candidate_proofing_method,
       'passkeyEnrolled',true,
       'feedBoardCount',cardinality(prepared.result_board_ids)
     ) then
    raise exception 'member activation audit evidence is incomplete or conflicting'
      using errcode='23514';
  end if;

  for feed_position in 1..cardinality(prepared.result_board_ids) loop
    select membership.entitlement_generation into expected_generation
      from public.board_memberships as membership
     where membership.organization_id=candidate_organization_id
       and membership.member_id=candidate_member_id
       and membership.board_id=prepared.result_board_ids[feed_position]
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null
            or membership.active_until>transaction_timestamp());
    select entry.* into feed
      from public.pending_action_feed as entry
     where entry.id=candidate_feed_ids[feed_position];
    if expected_generation is null
       or feed.id is null
       or feed.organization_id<>candidate_organization_id
       or feed.board_id<>prepared.result_board_ids[feed_position]
       or feed.member_id<>candidate_member_id
       or feed.entitlement_generation<>expected_generation
       or feed.action_type<>'complete_onboarding'
       or feed.object_type<>'member'
       or feed.object_id<>candidate_member_id
       or feed.object_version<>prepared.result_member_row_version
       or feed.state<>'pending'
       or feed.audit_event_id<>candidate_audit_event_id
       or pg_catalog.sha256(feed.canonical_payload)<>feed.payload_sha256
       or exists (
         select 1
           from public.pending_action_feed as later
          where later.member_id=feed.member_id
            and later.board_id=feed.board_id
            and later.entitlement_generation=feed.entitlement_generation
            and later.feed_sequence>feed.feed_sequence
       ) then
      raise exception 'member activation feed evidence is incomplete or conflicting'
        using errcode='23514';
    end if;
    begin
      feed_payload := convert_from(feed.canonical_payload,'UTF8')::jsonb;
    exception when others then
      raise exception 'member activation feed payload is invalid' using errcode='23514';
    end;
    if feed_payload<>jsonb_build_object(
         'schemaVersion','boardagent.pending-action.v1',
         'actionType','complete_onboarding',
         'memberId',candidate_member_id::text,
         'boardId',prepared.result_board_ids[feed_position]::text,
         'objectType','member',
         'objectId',candidate_member_id::text,
         'objectVersion',prepared.result_member_row_version::text
       ) then
      raise exception 'member activation feed payload does not match its projection'
        using errcode='23514';
    end if;
  end loop;
  if (
    select count(*) from public.pending_action_feed as linked
     where linked.audit_event_id=candidate_audit_event_id
  )<>cardinality(candidate_feed_ids) then
    raise exception 'member activation audit has an unexpected feed evidence count'
      using errcode='23514';
  end if;

  update public.enrollment_activation_challenges as changed
     set state='consumed',consumed_at=transaction_timestamp(),
         confirmed_by=candidate_secretary_member_id
   where changed.id=candidate_challenge_id
     and changed.organization_id=candidate_organization_id
     and changed.state='issued'
     and changed.attempt_count=prepared.result_attempt_count;
  if not found then
    raise exception 'enrollment challenge changed during activation finalization'
      using errcode='40001';
  end if;
  update public.members as changed
     set state='active',row_version=changed.row_version+1
   where changed.id=candidate_member_id
     and changed.organization_id=candidate_organization_id
     and changed.state='pending_activation'
     and changed.row_version=prepared.result_member_row_version-1
  returning changed.row_version into result_member_row_version;
  if not found or result_member_row_version<>prepared.result_member_row_version then
    raise exception 'member projection changed during activation finalization'
      using errcode='40001';
  end if;
  result_status := 'activated';
  result_challenge_state := 'consumed';
  result_attempt_count := prepared.result_attempt_count;
  return next;
end
$$;

alter function public.boardagent_constant_time_sha256_equal(bytea,bytea)
  owner to boardagent_migrator;
alter function public.boardagent_prepare_enrollment_activation(
  uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[]
) owner to boardagent_migrator;
alter function public.boardagent_finalize_enrollment_activation(
  uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[],uuid,uuid[]
) owner to boardagent_migrator;

revoke all on function public.boardagent_constant_time_sha256_equal(bytea,bytea) from public;
revoke all on function public.boardagent_prepare_enrollment_activation(
  uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[]
) from public;
revoke all on function public.boardagent_finalize_enrollment_activation(
  uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[],uuid,uuid[]
) from public;
grant execute on function public.boardagent_prepare_enrollment_activation(
  uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[]
) to boardagent_server;
grant execute on function public.boardagent_finalize_enrollment_activation(
  uuid,uuid,uuid,uuid,bytea,text,uuid,uuid,uuid[],uuid,uuid[]
) to boardagent_server;
