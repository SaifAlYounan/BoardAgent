-- Audit P07: safe own-session reads and a reference to existing recent authentication.
-- The reference is not a cookie, bearer secret, authentication grant or standing act.
-- Its possession cannot replace the independently rechecked current token and 15-minute
-- authentication boundary. Binding actions still require the existing exact confirmation.

create function public.boardagent_recent_auth_context()
returns table(session_id uuid,proof_reference text,proof_sha256 bytea,
              authenticated_at timestamptz,expires_at timestamptz)
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  with current_auth as (
    select session.id,session.last_authenticated_at,
           least(token.expires_at,session.expires_at,
                 session.last_authenticated_at+interval '15 minutes') as expires_at,
           pg_catalog.sha256(convert_to(
             'boardagent.recent-auth-reference.v1:'||session.id::text||':'||token.jti::text||':'||
             to_char(session.last_authenticated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
             'UTF8'
           )) as reference_bytes
      from public.access_token_records as token
      join public.auth_sessions as session on session.id=token.session_id
      join public.boardagent_resolve_access_token(
        public.boardagent_context_uuid('boardagent.token_jti')
      ) as active on active.token_record_id=token.id
     where current_setting('boardagent.transaction_scope',true)='request'
       and token.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
       and token.member_id=public.boardagent_context_uuid('boardagent.member_id')
       and token.client_id=public.boardagent_context_uuid('boardagent.client_id')
       and session.state='authenticated' and session.expires_at>transaction_timestamp()
       and session.last_authenticated_at>transaction_timestamp()-interval '15 minutes'
       and session.last_authenticated_at<=transaction_timestamp()
  )
  select id,rtrim(translate(encode(reference_bytes,'base64'),'+/','-_'),'='),
         pg_catalog.sha256(reference_bytes),last_authenticated_at,expires_at
    from current_auth
$$;
alter function public.boardagent_recent_auth_context() owner to boardagent_migrator;
revoke all on function public.boardagent_recent_auth_context() from public;
grant execute on function public.boardagent_recent_auth_context() to boardagent_server;

create index auth_sessions_own_page_idx
  on public.auth_sessions(organization_id,member_id,created_at desc,id desc);

create function public.boardagent_own_session_page(
  candidate_after_at timestamptz,candidate_after_id uuid,candidate_limit integer
)
returns table(item jsonb,cursor_at text,cursor_id text)
language plpgsql
stable
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_limit is null or candidate_limit not between 1 and 501
     or (candidate_after_at is null)<>(candidate_after_id is null) then
    raise exception 'own session page requires a bounded managed request' using errcode='25000';
  end if;
  if not exists (
    select 1 from public.boardagent_resolve_access_token(
      public.boardagent_context_uuid('boardagent.token_jti')
    ) as token
     where token.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
       and token.member_id=public.boardagent_context_uuid('boardagent.member_id')
       and token.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
  ) then
    raise exception 'own session principal is unavailable' using errcode='42501';
  end if;
  return query
    select jsonb_build_object(
      'session_id',session.id,'client_id',session.client_id,'state',session.state,
      'origin',session.exact_origin,
      'created_at',to_char(session.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'expires_at',to_char(session.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'last_authenticated_at',case when session.last_authenticated_at is null then null else
        to_char(session.last_authenticated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
    ),to_char(session.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),session.id::text
    from public.auth_sessions as session
   where session.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
     and session.member_id=public.boardagent_context_uuid('boardagent.member_id')
     and (candidate_after_at is null or (session.created_at,session.id)<(candidate_after_at,candidate_after_id))
   order by session.created_at desc,session.id desc limit candidate_limit;
end
$$;
alter function public.boardagent_own_session_page(timestamptz,uuid,integer) owner to boardagent_migrator;
revoke all on function public.boardagent_own_session_page(timestamptz,uuid,integer) from public;
grant execute on function public.boardagent_own_session_page(timestamptz,uuid,integer) to boardagent_server;

create or replace function public.boardagent_identity_admin_snapshot(
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
    -- Recent authentication belongs to the caller; the named owned connection
    -- may be older or browser-expired. The confirmation still binds that target.
    perform 1 from public.boardagent_recent_auth_context() as proof
     where public.boardagent_constant_time_sha256_equal(proof.proof_sha256,proof_sha);
    if not found then
      raise exception 'recent same-client authentication proof is unavailable' using errcode='P0002';
    end if;
    select value.* into target_session from public.auth_sessions as value
     where value.id=candidate_target and value.organization_id=context_organization
       and value.member_id=context_member and value.state in ('authenticated','expired')
       and value.last_authenticated_at is not null
     for update;
    if target_session.id is null then
      raise exception 'owned session is unavailable' using errcode='P0002';
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
