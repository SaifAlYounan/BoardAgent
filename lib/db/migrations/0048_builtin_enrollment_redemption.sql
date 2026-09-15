-- BoardAgent Phase 2 / group 48: builtin invitation redemption authority.
-- A valid invitation may start a UV WebAuthn ceremony, but only this audited
-- prepare/finalize boundary may atomically bind the resulting credential, consume
-- the invitation, create the ten-minute human-code challenge, and leave the seat
-- pending activation. Link possession never makes the member active.

revoke update(consumed_at,pending_activation_member_id)
  on public.enrollment_invitations from boardagent_server;
revoke insert on public.enrollment_activation_challenges from boardagent_server;

grant select on
  public.organizations,
  public.boards,
  public.members,
  public.board_memberships,
  public.enrollment_invitations,
  public.webauthn_challenges,
  public.webauthn_credentials,
  public.audit_events
to boardagent_migrator;
grant update(state,row_version) on public.members to boardagent_migrator;
grant update(consumed_at,pending_activation_member_id)
  on public.enrollment_invitations to boardagent_migrator;
grant update(consumed_at) on public.webauthn_challenges to boardagent_migrator;
grant insert on public.webauthn_credentials,public.enrollment_activation_challenges
  to boardagent_migrator;

create policy boardagent_migrator_builtin_enrollment_organization_read
  on public.organizations for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_builtin_enrollment_board_read
  on public.boards for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_builtin_enrollment_webauthn_challenge_read
  on public.webauthn_challenges for select to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_builtin_enrollment_webauthn_challenge_update
  on public.webauthn_challenges for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_builtin_enrollment_webauthn_credential_insert
  on public.webauthn_credentials for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_builtin_enrollment_activation_insert
  on public.enrollment_activation_challenges for insert to boardagent_migrator
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

create function public.boardagent_lookup_builtin_enrollment(
  candidate_organization_id uuid,
  candidate_invitation_token_sha256 bytea
)
returns table(
  result_status text,
  result_invitation_id uuid,
  result_member_id uuid,
  result_organization_display_name text,
  result_member_display_name text,
  result_handoff_method text,
  result_seats jsonb
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  invitation public.enrollment_invitations%rowtype;
  target public.members%rowtype;
  organization_display_name text;
  seats jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or candidate_organization_id is distinct from
       public.boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'builtin enrollment lookup requires a managed identity transaction'
      using errcode='25000';
  end if;
  if candidate_invitation_token_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_invitation_token_sha256) then
    raise exception 'builtin enrollment lookup inputs are invalid' using errcode='22023';
  end if;

  select candidate.* into invitation
    from public.enrollment_invitations as candidate
   where candidate.organization_id=candidate_organization_id
     and public.boardagent_constant_time_sha256_equal(
       candidate.token_sha256,candidate_invitation_token_sha256
     )
   limit 1;
  if invitation.id is null
     or invitation.consumed_at is not null
     or invitation.revoked_at is not null
     or invitation.expires_at<=transaction_timestamp() then
    return query select 'unavailable'::text,null::uuid,null::uuid,null::text,
      null::text,null::text,null::jsonb;
    return;
  end if;

  select member.* into target
    from public.members as member
   where member.organization_id=candidate_organization_id
     and member.id=invitation.member_id
     and member.state='invited';
  select organization.display_name into organization_display_name
    from public.organizations as organization
   where organization.id=candidate_organization_id;
  select jsonb_agg(
           jsonb_build_object(
             'boardId',board.id::text,
             'boardName',board.name,
             'seatRole',membership.seat_role
           ) order by board.id,membership.id
         ) into seats
    from public.board_memberships as membership
    join public.boards as board
      on board.organization_id=membership.organization_id
     and board.id=membership.board_id
   where membership.organization_id=candidate_organization_id
     and membership.member_id=invitation.member_id
     and membership.state='active'
     and membership.active_from<=transaction_timestamp()
     and (membership.active_until is null
          or membership.active_until>transaction_timestamp());
  if target.id is null
     or organization_display_name is null
     or seats is null
     or jsonb_array_length(seats) not between 1 and 25 then
    return query select 'unavailable'::text,null::uuid,null::uuid,null::text,
      null::text,null::text,null::jsonb;
    return;
  end if;
  return query select 'available'::text,invitation.id,target.id,
    organization_display_name,target.display_name,invitation.handoff_method,seats;
end
$$;

create function public.boardagent_prepare_builtin_enrollment_redemption(
  candidate_organization_id uuid,
  candidate_member_id uuid,
  candidate_invitation_token_sha256 bytea,
  candidate_webauthn_challenge_id uuid,
  candidate_expected_challenge_sha256 bytea,
  candidate_credential_id uuid,
  candidate_raw_credential_id bytea,
  candidate_public_key bytea,
  candidate_signature_counter bigint,
  candidate_transports text[],
  candidate_backup_eligible boolean,
  candidate_backup_state boolean,
  candidate_activation_challenge_id uuid,
  candidate_activation_code_sha256 bytea,
  candidate_proofing_method text
)
returns table(
  result_status text,
  result_invitation_id uuid,
  result_member_row_version bigint,
  result_issued_by uuid,
  result_handoff_method text,
  result_rp_id text,
  result_exact_origin text
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  invitation public.enrollment_invitations%rowtype;
  target public.members%rowtype;
  challenge public.webauthn_challenges%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or current_setting('transaction_isolation') is distinct from 'serializable'
     or candidate_organization_id is distinct from
       public.boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'builtin enrollment redemption requires a managed serializable identity transaction'
      using errcode='25000';
  end if;
  if candidate_member_id is null
     or candidate_invitation_token_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_invitation_token_sha256)
     or candidate_webauthn_challenge_id is null
     or candidate_expected_challenge_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_expected_challenge_sha256)
     or candidate_credential_id is null
     or candidate_raw_credential_id is null
     or octet_length(candidate_raw_credential_id) not between 16 and 1024
     or candidate_public_key is null
     or octet_length(candidate_public_key) not between 32 and 4096
     or candidate_signature_counter is null
     or candidate_signature_counter not between 0 and 4294967295
     or candidate_transports is null
     or cardinality(candidate_transports)>16
     or array_position(candidate_transports,null) is not null
     or exists (
       select 1 from unnest(candidate_transports) as supplied(transport)
        where supplied.transport not in
          ('ble','cable','hybrid','internal','nfc','smart-card','usb')
     )
     or cardinality(candidate_transports)<>(
       select count(distinct supplied.transport)::integer
         from unnest(candidate_transports) as supplied(transport)
     )
     or candidate_backup_eligible is null
     or candidate_backup_state is null
     or (not candidate_backup_eligible and candidate_backup_state)
     or candidate_activation_challenge_id is null
     or candidate_activation_code_sha256 is null
     or not public.boardagent_hash_is_sha256(candidate_activation_code_sha256)
     or candidate_proofing_method not in ('in_person','verified_number_call') then
    raise exception 'builtin enrollment redemption inputs are invalid' using errcode='22023';
  end if;

  -- Stable order: invitation, member, WebAuthn challenge, then the global audit
  -- head acquired by the repository before finalization.
  select candidate.* into invitation
    from public.enrollment_invitations as candidate
   where candidate.organization_id=candidate_organization_id
     and public.boardagent_constant_time_sha256_equal(
       candidate.token_sha256,candidate_invitation_token_sha256
     )
   for update;
  if invitation.id is null then
    return query select 'unavailable'::text,null::uuid,null::bigint,null::uuid,
      null::text,null::text,null::text;
    return;
  end if;
  select member.* into target
    from public.members as member
   where member.organization_id=candidate_organization_id
     and member.id=candidate_member_id
   for update;
  select candidate.* into challenge
    from public.webauthn_challenges as candidate
   where candidate.organization_id=candidate_organization_id
     and candidate.id=candidate_webauthn_challenge_id
   for update;

  if target.id is null
     or challenge.id is null
     or invitation.member_id<>candidate_member_id
     or invitation.consumed_at is not null
     or invitation.revoked_at is not null
     or invitation.expires_at<=transaction_timestamp()
     or target.state<>'invited'
     or challenge.member_id is distinct from candidate_member_id
     or challenge.session_id is not null
     or challenge.purpose<>'enrollment'
     or challenge.consumed_at is not null
     or challenge.expires_at<=transaction_timestamp()
     or not public.boardagent_constant_time_sha256_equal(
       challenge.challenge_sha256,candidate_expected_challenge_sha256
     )
     or exists (
       select 1 from public.webauthn_credentials as credential
        where credential.id=candidate_credential_id
           or credential.credential_id=candidate_raw_credential_id
           or (credential.organization_id=candidate_organization_id
               and credential.member_id=candidate_member_id
               and credential.state='active')
     )
     or exists (
       select 1 from public.enrollment_activation_challenges as activation
        where activation.id=candidate_activation_challenge_id
     ) then
    return query select 'unavailable'::text,null::uuid,null::bigint,null::uuid,
      null::text,null::text,null::text;
    return;
  end if;

  return query select 'ready'::text,invitation.id,target.row_version,
    invitation.issued_by,invitation.handoff_method,challenge.rp_id,challenge.exact_origin;
end
$$;

create function public.boardagent_finalize_builtin_enrollment_redemption(
  candidate_organization_id uuid,
  candidate_member_id uuid,
  candidate_invitation_token_sha256 bytea,
  candidate_webauthn_challenge_id uuid,
  candidate_expected_challenge_sha256 bytea,
  candidate_credential_id uuid,
  candidate_raw_credential_id bytea,
  candidate_public_key bytea,
  candidate_signature_counter bigint,
  candidate_transports text[],
  candidate_backup_eligible boolean,
  candidate_backup_state boolean,
  candidate_activation_challenge_id uuid,
  candidate_activation_code_sha256 bytea,
  candidate_proofing_method text,
  candidate_audit_event_id uuid
)
returns table(
  result_status text,
  result_invitation_id uuid,
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
  inserted_id uuid;
  intermediate_row_version bigint;
begin
  select candidate.* into prepared
    from public.boardagent_prepare_builtin_enrollment_redemption(
      candidate_organization_id,
      candidate_member_id,
      candidate_invitation_token_sha256,
      candidate_webauthn_challenge_id,
      candidate_expected_challenge_sha256,
      candidate_credential_id,
      candidate_raw_credential_id,
      candidate_public_key,
      candidate_signature_counter,
      candidate_transports,
      candidate_backup_eligible,
      candidate_backup_state,
      candidate_activation_challenge_id,
      candidate_activation_code_sha256,
      candidate_proofing_method
    ) as candidate;
  if prepared.result_status is distinct from 'ready' then
    return query select 'unavailable'::text,null::uuid,null::bigint;
    return;
  end if;

  select event.* into audit
    from public.audit_events as event
   where event.id=candidate_audit_event_id
     and event.organization_id=candidate_organization_id;
  if audit.id is null then
    raise exception 'builtin enrollment redemption requires its audit event'
      using errcode='55000';
  end if;
  begin
    audit_payload := convert_from(audit.canonical_payload,'UTF8')::jsonb;
  exception when others then
    raise exception 'builtin enrollment redemption audit payload is invalid'
      using errcode='23514';
  end;
  audit_details := audit_payload->'details';
  if audit.event_type<>'enrollment_redeemed'
     or audit.object_type<>'enrollment_invitation'
     or audit.object_id is distinct from prepared.result_invitation_id
     or audit.object_version is not null
     or audit.actor_member_id is not null
     or audit.client_id is not null
     or audit.token_jti is not null
     or audit.board_id is not null
     or audit_payload->>'eventId' is distinct from candidate_audit_event_id::text
     or audit_payload->>'eventType'<>'enrollment_redeemed'
     or audit_payload->'actorMemberId'<>'null'::jsonb
     or audit_payload->'actorClientId'<>'null'::jsonb
     or audit_payload->'tokenJti'<>'null'::jsonb
     or audit_payload->>'entityType'<>'enrollment_invitation'
     or audit_payload->>'entityId' is distinct from prepared.result_invitation_id::text
     or audit_payload->'boardId'<>'null'::jsonb
     or audit_payload->>'origin'<>'browser'
     or audit_payload->>'schemaVersion'<>'1'
     or (audit_payload->>'occurredAt')::timestamptz is distinct from audit.occurred_at
     or audit_details<>jsonb_build_object(
       'memberId',candidate_member_id::text,
       'invitationId',prepared.result_invitation_id::text,
       'issuedBy',prepared.result_issued_by::text,
       'handoffMethod',prepared.result_handoff_method,
       'credentialId',candidate_credential_id::text,
       'activationChallengeId',candidate_activation_challenge_id::text,
       'proofingMethod',candidate_proofing_method,
       'rpId',prepared.result_rp_id,
       'exactOrigin',prepared.result_exact_origin,
       'passkeyUserVerified',true
     ) then
    raise exception 'builtin enrollment redemption audit evidence is incomplete or conflicting'
      using errcode='23514';
  end if;

  insert into public.webauthn_credentials(
    id,organization_id,member_id,credential_id,public_key,signature_counter,
    transports,backup_eligible,backup_state,state
  ) values (
    candidate_credential_id,candidate_organization_id,candidate_member_id,
    candidate_raw_credential_id,candidate_public_key,candidate_signature_counter,
    candidate_transports,candidate_backup_eligible,candidate_backup_state,'active'
  )
  returning id into inserted_id;
  if inserted_id is distinct from candidate_credential_id then
    raise exception 'builtin enrollment credential insertion failed' using errcode='40001';
  end if;

  update public.webauthn_challenges as changed
     set consumed_at=transaction_timestamp()
   where changed.id=candidate_webauthn_challenge_id
     and changed.organization_id=candidate_organization_id
     and changed.consumed_at is null;
  if not found then
    raise exception 'builtin enrollment WebAuthn challenge changed during finalization'
      using errcode='40001';
  end if;
  update public.enrollment_invitations as changed
     set consumed_at=transaction_timestamp(),
         pending_activation_member_id=candidate_member_id
   where changed.id=prepared.result_invitation_id
     and changed.organization_id=candidate_organization_id
     and changed.consumed_at is null
     and changed.revoked_at is null;
  if not found then
    raise exception 'builtin enrollment invitation changed during finalization'
      using errcode='40001';
  end if;

  update public.members as changed
     set state='enrollment_pending',row_version=changed.row_version+1
   where changed.id=candidate_member_id
     and changed.organization_id=candidate_organization_id
     and changed.state='invited'
     and changed.row_version=prepared.result_member_row_version
  returning changed.row_version into intermediate_row_version;
  if not found then
    raise exception 'builtin enrollment member changed before pending transition'
      using errcode='40001';
  end if;
  update public.members as changed
     set state='pending_activation',row_version=changed.row_version+1
   where changed.id=candidate_member_id
     and changed.organization_id=candidate_organization_id
     and changed.state='enrollment_pending'
     and changed.row_version=intermediate_row_version
  returning changed.row_version into result_member_row_version;
  if not found then
    raise exception 'builtin enrollment member changed before activation-pending transition'
      using errcode='40001';
  end if;

  insert into public.enrollment_activation_challenges(
    id,organization_id,member_id,invitation_id,protected_code,proofing_method,
    state,expires_at
  ) values (
    candidate_activation_challenge_id,candidate_organization_id,candidate_member_id,
    prepared.result_invitation_id,candidate_activation_code_sha256,
    candidate_proofing_method,'issued',transaction_timestamp()+interval '10 minutes'
  );

  result_status := 'completed';
  result_invitation_id := prepared.result_invitation_id;
  return next;
end
$$;

alter function public.boardagent_lookup_builtin_enrollment(uuid,bytea)
  owner to boardagent_migrator;
alter function public.boardagent_prepare_builtin_enrollment_redemption(
  uuid,uuid,bytea,uuid,bytea,uuid,bytea,bytea,bigint,text[],boolean,boolean,uuid,bytea,text
) owner to boardagent_migrator;
alter function public.boardagent_finalize_builtin_enrollment_redemption(
  uuid,uuid,bytea,uuid,bytea,uuid,bytea,bytea,bigint,text[],boolean,boolean,uuid,bytea,text,uuid
) owner to boardagent_migrator;

revoke all on function public.boardagent_lookup_builtin_enrollment(uuid,bytea) from public;
revoke all on function public.boardagent_prepare_builtin_enrollment_redemption(
  uuid,uuid,bytea,uuid,bytea,uuid,bytea,bytea,bigint,text[],boolean,boolean,uuid,bytea,text
) from public;
revoke all on function public.boardagent_finalize_builtin_enrollment_redemption(
  uuid,uuid,bytea,uuid,bytea,uuid,bytea,bytea,bigint,text[],boolean,boolean,uuid,bytea,text,uuid
) from public;
grant execute on function public.boardagent_lookup_builtin_enrollment(uuid,bytea)
  to boardagent_server;
grant execute on function public.boardagent_prepare_builtin_enrollment_redemption(
  uuid,uuid,bytea,uuid,bytea,uuid,bytea,bytea,bigint,text[],boolean,boolean,uuid,bytea,text
) to boardagent_server;
grant execute on function public.boardagent_finalize_builtin_enrollment_redemption(
  uuid,uuid,bytea,uuid,bytea,uuid,bytea,bytea,bigint,text[],boolean,boolean,uuid,bytea,text,uuid
) to boardagent_server;
