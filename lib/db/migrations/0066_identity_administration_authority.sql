-- BoardAgent Phase 4 / group 66: confirmed identity-administration authority.
-- All mutations remain behind the one-use MCP consent record and a SECURITY DEFINER
-- aggregate lock; the request role receives no raw identity-table write privilege.

create table public.identity_recovery_requests (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  requested_by uuid not null,
  reason text not null check (length(reason) between 1 and 65536),
  proofing_method text not null check (length(proofing_method) between 1 and 2048),
  credential_disposition text not null
    check (credential_disposition in ('revoke_all','preserve_named')),
  preserved_credential_ids uuid[] not null default '{}',
  prior_identity_generation bigint not null check (prior_identity_generation >= 0),
  consent_record_id uuid not null references public.consent_records(id) on delete restrict,
  state text not null default 'initiated' check (state in ('initiated','completed','cancelled')),
  created_at timestamptz(6) not null default transaction_timestamp(),
  completed_at timestamptz(6),
  foreign key (organization_id,member_id)
    references public.members(organization_id,id) on delete restrict,
  foreign key (organization_id,requested_by)
    references public.members(organization_id,id) on delete restrict,
  check (
    (credential_disposition='revoke_all' and cardinality(preserved_credential_ids)=0)
    or
    (credential_disposition='preserve_named' and cardinality(preserved_credential_ids)>0)
  ),
  check (completed_at is null or state='completed')
);

alter table public.identity_recovery_requests enable row level security;
alter table public.identity_recovery_requests force row level security;
grant select on public.identity_recovery_requests to boardagent_server,boardagent_worker;
create policy boardagent_server_identity_recovery_read
  on public.identity_recovery_requests for select to boardagent_server
  using (
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and (
      member_id=public.boardagent_context_uuid('boardagent.member_id')
      or exists (
        select 1 from public.organization_role_assignments as assignment
         where assignment.organization_id=identity_recovery_requests.organization_id
           and assignment.member_id=public.boardagent_context_uuid('boardagent.member_id')
           and assignment.role in ('admin','secretariat')
           and assignment.active_from<=transaction_timestamp()
           and (assignment.active_until is null or assignment.active_until>transaction_timestamp())
      )
    )
  );
create policy boardagent_worker_identity_recovery_read
  on public.identity_recovery_requests for select to boardagent_worker using (true);

grant select,insert,update on public.identity_recovery_requests to boardagent_migrator;
grant select,update on public.enrollment_invitations,public.members,public.auth_sessions,
  public.oauth_clients,public.oauth_consents,public.refresh_families,
  public.access_token_records,public.webauthn_credentials,public.totp_credentials,
  public.external_identity_links,public.oidc_login_transactions,public.member_contact_points
  to boardagent_migrator;

create policy boardagent_migrator_identity_admin_recovery
  on public.identity_recovery_requests for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

do $identity_admin_policies$
declare
  identity_table text;
begin
  foreach identity_table in array array[
    'enrollment_invitations','members','auth_sessions','oauth_clients','oauth_consents',
    'refresh_families','access_token_records','webauthn_credentials','totp_credentials',
    'external_identity_links','oidc_login_transactions','member_contact_points'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_identity_admin on public.%I for all to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id'')) with check (current_setting(''boardagent.transaction_scope'',true)=''request'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id''))',
      identity_table
    );
  end loop;
end
$identity_admin_policies$;

create function public.boardagent_identity_admin_snapshot(
  candidate_action text,
  candidate_target uuid,
  candidate_arguments jsonb
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
  required_role text;
  invitation public.enrollment_invitations%rowtype;
  target_member public.members%rowtype;
  target_session public.auth_sessions%rowtype;
  target_client public.oauth_clients%rowtype;
  identity_link public.external_identity_links%rowtype;
  oidc_proof public.oidc_login_transactions%rowtype;
  proof_sha bytea;
  preserved_ids uuid[];
  credential_count integer;
  recovery_paths integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_action not in (
       'revoke_enrollment','initiate_identity_recovery','revoke_my_session',
       'block_oauth_client','unblock_oauth_client','link_external_identity',
       'unlink_external_identity'
     )
     or candidate_target is null
     or not public.boardagent_is_uuid_v7(candidate_target)
     or jsonb_typeof(candidate_arguments)<>'object' then
    raise exception 'identity administration requires one managed exact action'
      using errcode='25000';
  end if;
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  context_client := public.boardagent_context_uuid('boardagent.client_id');
  context_token := public.boardagent_context_uuid('boardagent.token_jti');

  if not exists (
    select 1
      from public.access_token_records as token
      join public.oauth_clients as client on client.id=token.client_id
      join public.members as actor
        on actor.id=token.member_id and actor.organization_id=token.organization_id
     where token.organization_id=context_organization
       and token.member_id=context_member
       and token.client_id=context_client
       and token.jti=context_token
       and token.revoked_at is null and token.expires_at>transaction_timestamp()
       and client.state='active' and actor.state='active'
       and (candidate_action='revoke_my_session' or 'secretariat:admin'=any(token.scope_set))
  ) then
    raise exception 'identity administration requires a live scoped principal'
      using errcode='42501';
  end if;

  if candidate_action<>'revoke_my_session' then
    required_role := case
      when candidate_action in ('revoke_enrollment','initiate_identity_recovery')
        then 'secretariat_or_admin'
      else 'admin'
    end;
    if not exists (
      select 1 from public.organization_role_assignments as assignment
       where assignment.organization_id=context_organization
         and assignment.member_id=context_member
         and (
           (required_role='admin' and assignment.role='admin')
           or
           (required_role='secretariat_or_admin' and assignment.role in ('admin','secretariat'))
         )
         and assignment.active_from<=transaction_timestamp()
         and (assignment.active_until is null or assignment.active_until>transaction_timestamp())
    ) then
      raise exception 'identity administration role is unavailable' using errcode='42501';
    end if;
  end if;

  if candidate_action='revoke_enrollment' then
    select value.* into invitation
      from public.enrollment_invitations as value
     where value.id=candidate_target and value.organization_id=context_organization
     for update;
    if invitation.id is null or invitation.consumed_at is not null
       or invitation.revoked_at is not null or invitation.expires_at<=transaction_timestamp() then
      raise exception 'live enrollment invitation is unavailable' using errcode='P0002';
    end if;
    return jsonb_build_object(
      'invitationId',invitation.id,'memberId',invitation.member_id,
      'issuedBy',invitation.issued_by,
      'expiresAt',to_char(invitation.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    );
  elsif candidate_action='initiate_identity_recovery' then
    select value.* into target_member from public.members as value
     where value.id=candidate_target and value.organization_id=context_organization
       and value.state in ('active','pending_activation')
     for update;
    if target_member.id is null then
      raise exception 'recoverable member is unavailable' using errcode='P0002';
    end if;
    if candidate_arguments->>'credentialDisposition' not in ('revoke_all','preserve_named')
       or jsonb_typeof(candidate_arguments->'preservedCredentialIds')<>'array' then
      raise exception 'identity recovery credential disposition is invalid' using errcode='22023';
    end if;
    begin
      select coalesce(array_agg(value::uuid order by value::uuid),'{}'::uuid[])
        into preserved_ids
        from jsonb_array_elements_text(candidate_arguments->'preservedCredentialIds') as item(value);
    exception when others then
      raise exception 'identity recovery credential identifiers are invalid' using errcode='22023';
    end;
    if cardinality(preserved_ids)<>(
         select count(distinct value)::integer
           from unnest(preserved_ids) as item(value)
       )
       or (candidate_arguments->>'credentialDisposition'='revoke_all'
           and cardinality(preserved_ids)<>0)
       or (candidate_arguments->>'credentialDisposition'='preserve_named'
           and cardinality(preserved_ids)=0) then
      raise exception 'identity recovery preserved credentials are invalid' using errcode='22023';
    end if;
    select count(*)::integer into credential_count
      from (
        select id from public.webauthn_credentials
         where organization_id=context_organization and member_id=target_member.id
           and state='active' and id=any(preserved_ids)
        union all
        select id from public.totp_credentials
         where organization_id=context_organization and member_id=target_member.id
           and state in ('active','locked') and id=any(preserved_ids)
      ) as credential;
    if candidate_arguments->>'credentialDisposition'='preserve_named'
       and credential_count<>cardinality(preserved_ids) then
      raise exception 'named recovery credentials are unavailable' using errcode='P0002';
    end if;
    return jsonb_build_object(
      'memberId',target_member.id,'memberState',target_member.state,
      'identityGeneration',target_member.identity_generation::text,
      'credentialDisposition',candidate_arguments->>'credentialDisposition',
      'preservedCredentialIds',to_jsonb(preserved_ids)
    );
  elsif candidate_action='revoke_my_session' then
    begin
      proof_sha := decode(candidate_arguments->>'recentAuthProofSha256','hex');
    exception when others then
      raise exception 'recent authentication proof is invalid' using errcode='22023';
    end;
    select value.* into target_session from public.auth_sessions as value
     where value.id=candidate_target and value.organization_id=context_organization
       and value.member_id=context_member and value.state='authenticated'
       and value.expires_at>transaction_timestamp()
       and value.last_authenticated_at>=transaction_timestamp()-interval '15 minutes'
       and public.boardagent_constant_time_sha256_equal(value.opaque_session_sha256,proof_sha)
     for update;
    if target_session.id is null then
      raise exception 'own recently authenticated session is unavailable' using errcode='P0002';
    end if;
    return jsonb_build_object(
      'sessionId',target_session.id,'clientId',target_session.client_id,
      'exactOrigin',target_session.exact_origin,
      'expiresAt',to_char(target_session.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'recentAuthProofSha256',encode(proof_sha,'hex')
    );
  elsif candidate_action in ('block_oauth_client','unblock_oauth_client') then
    select value.* into target_client from public.oauth_clients as value
     where value.id=candidate_target and value.organization_id=context_organization
     for update;
    if target_client.id is null
       or (candidate_action='block_oauth_client' and target_client.state<>'active')
       or (candidate_action='unblock_oauth_client' and target_client.state<>'suspended') then
      raise exception 'OAuth client transition is unavailable (target %, state %)',
        target_client.id,target_client.state using errcode='P0002';
    end if;
    return jsonb_build_object(
      'clientId',target_client.id,'priorState',target_client.state,
      'protocolIdKind',target_client.protocol_id_kind,
      'metadataSha256',encode(target_client.metadata_sha256,'hex')
    );
  elsif candidate_action='link_external_identity' then
    begin
      proof_sha := decode(candidate_arguments->>'browserProofSha256','hex');
    exception when others then
      raise exception 'browser subject proof is invalid' using errcode='22023';
    end;
    select value.* into target_member from public.members as value
     where value.id=candidate_target and value.organization_id=context_organization
       and value.state in ('invited','pending_activation','active')
     for update;
    if target_member.id is null then
      raise exception 'identity-link member is unavailable' using errcode='P0002';
    end if;
    select link.* into identity_link
      from public.external_identity_links as link
     where link.organization_id=context_organization
       and link.member_id=target_member.id
       and link.issuer=candidate_arguments->>'issuer'
       and link.subject=candidate_arguments->>'subject'
       and link.state='pending'
     for update;
    if identity_link.id is null then
      raise exception 'pending browser-proved identity link is unavailable' using errcode='P0002';
    end if;
    select login.* into oidc_proof
      from public.oidc_login_transactions as login
      join public.enrollment_invitations as enrollment
        on enrollment.id=identity_link.invitation_id
       and enrollment.token_sha256=login.invitation_token_sha256
     where login.organization_id=context_organization
       and login.exact_issuer=identity_link.issuer
       and login.failure_code='pending_link'
       and login.consumed_at is not null
       and login.consumed_at>=transaction_timestamp()-interval '15 minutes'
       and public.boardagent_constant_time_sha256_equal(login.state_sha256,proof_sha)
     order by login.consumed_at desc limit 1 for update of login;
    if oidc_proof.id is null then
      raise exception 'browser subject proof does not bind the pending identity' using errcode='42501';
    end if;
    return jsonb_build_object(
      'identityLinkId',identity_link.id,'memberId',identity_link.member_id,
      'issuer',identity_link.issuer,'subjectSha256',encode(pg_catalog.sha256(convert_to(identity_link.subject,'UTF8')),'hex'),
      'oidcTransactionId',oidc_proof.id,'browserProofSha256',encode(proof_sha,'hex')
    );
  else
    select link.* into identity_link from public.external_identity_links as link
     where link.id=candidate_target and link.organization_id=context_organization
       and link.state='active' for update;
    if identity_link.id is null then
      raise exception 'active external identity link is unavailable' using errcode='P0002';
    end if;
    select
      (select count(*) from public.external_identity_links as other
        where other.organization_id=context_organization and other.member_id=identity_link.member_id
          and other.state='active' and other.id<>identity_link.id)
      +(select count(*) from public.webauthn_credentials as credential
        where credential.organization_id=context_organization
          and credential.member_id=identity_link.member_id and credential.state='active')
      +(select count(*) from public.totp_credentials as credential
        where credential.organization_id=context_organization
          and credential.member_id=identity_link.member_id and credential.state in ('active','locked'))
      +(select count(*) from public.member_contact_points as record
        where record.organization_id=context_organization
          and record.member_id=identity_link.member_id and record.state='active')
      into recovery_paths;
    if recovery_paths<1 then
      raise exception 'unlink would remove the last recovery path' using errcode='23514';
    end if;
    return jsonb_build_object(
      'identityLinkId',identity_link.id,'memberId',identity_link.member_id,
      'issuer',identity_link.issuer,
      'subjectSha256',encode(pg_catalog.sha256(convert_to(identity_link.subject,'UTF8')),'hex'),
      'remainingRecoveryPaths',recovery_paths
    );
  end if;
end
$$;

create function public.boardagent_apply_identity_admin_action(
  candidate_action text,
  candidate_target uuid,
  candidate_arguments jsonb,
  candidate_payload_sha256 bytea,
  candidate_consent_record_id uuid,
  candidate_recovery_request_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  snapshot jsonb;
  context_organization uuid;
  context_member uuid;
  preserved_ids uuid[];
  target_member_id uuid;
  identity_link_id uuid;
  recovery_generation bigint;
  affected_sessions integer;
begin
  snapshot := public.boardagent_identity_admin_snapshot(
    candidate_action,candidate_target,candidate_arguments
  );
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  if not public.boardagent_hash_is_sha256(candidate_payload_sha256)
     or not exists (
       select 1 from public.consent_records as consent
        where consent.id=candidate_consent_record_id
          and consent.organization_id=context_organization
          and consent.actor_member_id=context_member
          and consent.action_code=candidate_action
          and consent.target_id is not distinct from candidate_target
          and consent.payload_sha256=candidate_payload_sha256
     ) then
    raise exception 'identity administration consent binding is invalid' using errcode='42501';
  end if;

  if candidate_action='revoke_enrollment' then
    update public.enrollment_invitations set revoked_at=transaction_timestamp()
     where id=candidate_target and revoked_at is null and consumed_at is null;
    return snapshot||jsonb_build_object('state','revoked');
  elsif candidate_action='initiate_identity_recovery' then
    begin
      select coalesce(array_agg(value::uuid order by value::uuid),'{}'::uuid[])
        into preserved_ids
        from jsonb_array_elements_text(candidate_arguments->'preservedCredentialIds') as item(value);
    exception when others then
      raise exception 'identity recovery credential identifiers are invalid' using errcode='22023';
    end;
    target_member_id := candidate_target;
    recovery_generation := (snapshot->>'identityGeneration')::bigint;
    update public.auth_sessions set state='revoked'
     where organization_id=context_organization and member_id=target_member_id
       and state in ('anonymous','authenticated');
    get diagnostics affected_sessions = row_count;
    update public.refresh_families set state='revoked',revoked_at=transaction_timestamp()
     where organization_id=context_organization and member_id=target_member_id
       and state='active';
    update public.access_token_records set revoked_at=transaction_timestamp()
     where organization_id=context_organization and member_id=target_member_id
       and revoked_at is null;
    update public.webauthn_credentials set state='revoked'
     where organization_id=context_organization and member_id=target_member_id
       and state in ('active','suspect') and not (id=any(preserved_ids));
    update public.totp_credentials set state='revoked'
     where organization_id=context_organization and member_id=target_member_id
       and state in ('active','locked') and not (id=any(preserved_ids));
    update public.members
       set identity_generation=identity_generation+1,row_version=row_version+1
     where id=target_member_id and organization_id=context_organization
       and identity_generation=recovery_generation;
    insert into public.identity_recovery_requests(
      id,organization_id,member_id,requested_by,reason,proofing_method,
      credential_disposition,preserved_credential_ids,prior_identity_generation,
      consent_record_id
    ) values (
      candidate_recovery_request_id,context_organization,target_member_id,context_member,
      candidate_arguments->>'reason',candidate_arguments->>'proofingMethod',
      candidate_arguments->>'credentialDisposition',preserved_ids,recovery_generation,
      candidate_consent_record_id
    );
    return snapshot||jsonb_build_object(
      'recoveryRequestId',candidate_recovery_request_id,'state','initiated',
      'revokedSessionCount',affected_sessions,
      'newIdentityGeneration',(recovery_generation+1)::text
    );
  elsif candidate_action='revoke_my_session' then
    update public.refresh_families set state='revoked',revoked_at=transaction_timestamp()
     where id in (
       select token.refresh_family_id from public.access_token_records as token
        where token.session_id=candidate_target and token.refresh_family_id is not null
     ) and state='active';
    update public.access_token_records set revoked_at=transaction_timestamp()
     where session_id=candidate_target and revoked_at is null;
    update public.auth_sessions set state='revoked'
     where id=candidate_target and state='authenticated';
    return snapshot||jsonb_build_object('state','revoked');
  elsif candidate_action='block_oauth_client' then
    update public.oauth_clients set state='suspended' where id=candidate_target and state='active';
    update public.oauth_consents set revoked_at=transaction_timestamp()
     where client_id=candidate_target and revoked_at is null;
    update public.refresh_families set state='revoked',revoked_at=transaction_timestamp()
     where client_id=candidate_target and state='active';
    update public.access_token_records set revoked_at=transaction_timestamp()
     where client_id=candidate_target and revoked_at is null;
    update public.auth_sessions set state='revoked'
     where client_id=candidate_target and state in ('anonymous','authenticated');
    return snapshot||jsonb_build_object('state','suspended');
  elsif candidate_action='unblock_oauth_client' then
    update public.oauth_clients set state='active' where id=candidate_target and state='suspended';
    return snapshot||jsonb_build_object('state','active','grantsRestored',false);
  elsif candidate_action='link_external_identity' then
    identity_link_id := (snapshot->>'identityLinkId')::uuid;
    update public.external_identity_links
       set state='active',confirmed_by=context_member,confirmed_at=transaction_timestamp()
     where id=identity_link_id and state='pending';
    return snapshot||jsonb_build_object('state','active');
  else
    target_member_id := (snapshot->>'memberId')::uuid;
    update public.external_identity_links set state='revoked'
     where id=candidate_target and state='active';
    update public.refresh_families set state='revoked',revoked_at=transaction_timestamp()
     where organization_id=context_organization and member_id=target_member_id
       and state='active';
    update public.access_token_records set revoked_at=transaction_timestamp()
     where organization_id=context_organization and member_id=target_member_id
       and revoked_at is null;
    update public.auth_sessions set state='revoked'
     where organization_id=context_organization and member_id=target_member_id
       and state in ('anonymous','authenticated');
    return snapshot||jsonb_build_object('state','revoked','sessionsRevoked',true);
  end if;
end
$$;

do $identity_admin_functions$
declare
  function_name regprocedure;
begin
  foreach function_name in array array[
    'public.boardagent_identity_admin_snapshot(text,uuid,jsonb)'::regprocedure,
    'public.boardagent_apply_identity_admin_action(text,uuid,jsonb,bytea,uuid,uuid)'::regprocedure
  ]
  loop
    execute 'alter function '||function_name||' owner to boardagent_migrator';
    execute 'revoke all on function '||function_name||' from public';
    execute 'grant execute on function '||function_name||' to boardagent_server';
  end loop;
end
$identity_admin_functions$;
