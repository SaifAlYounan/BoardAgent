-- Audit P03: separate bounded browser sessions from rotating agent authority.
-- Browser reads continue to require authenticated state and their original expiry.
-- This private predicate is reused by bearer resolution and ordinary webhook actions.

grant select on public.refresh_families to boardagent_migrator;
create policy boardagent_migrator_refresh_authority_read on public.refresh_families
  for select to boardagent_migrator using (true);

create function public.boardagent_access_session_current(candidate_token_id uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select exists (
    select 1 from public.access_token_records as token
    join public.auth_sessions as session
      on session.id=token.session_id
     and session.organization_id=token.organization_id
     and session.member_id=token.member_id
     and session.client_id=token.client_id
     and session.state in ('authenticated','expired')
     and session.last_authenticated_at is not null
    left join public.refresh_families as family
      on family.id=token.refresh_family_id
     and family.organization_id=token.organization_id
     and family.member_id=token.member_id
     and family.client_id=token.client_id
     and family.resource_uri=token.resource_uri
     and family.state='active' and family.revoked_at is null
     and family.idle_expires_at>transaction_timestamp()
     and family.absolute_expires_at>transaction_timestamp()
    where token.id=candidate_token_id
      and token.revoked_at is null and token.expires_at>transaction_timestamp()
      and (
        (token.refresh_family_id is not null and family.id is not null)
        or (token.refresh_family_id is null and session.state='authenticated'
            and session.expires_at>transaction_timestamp())
      )
  )
$$;
alter function public.boardagent_access_session_current(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_access_session_current(uuid) from public;

create or replace function boardagent_resolve_access_token(candidate_jti uuid)
returns table(
  token_record_id uuid,
  organization_id uuid,
  member_id uuid,
  internal_client_id uuid,
  protocol_client_id text,
  resource_uri text,
  scope_set text[],
  expires_at_epoch bigint,
  signing_key_kid text,
  roles text[],
  board_ids text[]
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select token.id,
         token.organization_id,
         token.member_id,
         token.client_id,
         oauth_client.protocol_id_value,
         token.resource_uri,
         token.scope_set,
         floor(extract(epoch from token.expires_at))::bigint,
         signing_key.kid,
         coalesce(
           array(
             select distinct role_name
               from (
                 select assignment.role as role_name
                   from organization_role_assignments as assignment
                  where assignment.organization_id=token.organization_id
                    and assignment.member_id=token.member_id
                    and assignment.active_from<=transaction_timestamp()
                    and (assignment.active_until is null
                         or assignment.active_until>transaction_timestamp())
                 union all
                 select case membership.seat_role
                          when 'voting_member' then 'member'
                          when 'management' then 'management'
                          when 'observer' then 'observer'
                        end as role_name
                   from board_memberships as membership
                  where membership.organization_id=token.organization_id
                    and membership.member_id=token.member_id
                    and membership.state='active'
                    and membership.active_from<=transaction_timestamp()
                    and (membership.active_until is null
                         or membership.active_until>transaction_timestamp())
                 union all
                 select 'secretariat' as role_name
                   from board_memberships as membership
                  where membership.organization_id=token.organization_id
                    and membership.member_id=token.member_id
                    and membership.is_secretary
                    and membership.state='active'
                    and membership.active_from<=transaction_timestamp()
                    and (membership.active_until is null
                         or membership.active_until>transaction_timestamp())
               ) as live_roles
              where role_name is not null
              order by role_name
           ),
           array[]::text[]
         ) as roles,
         coalesce(
           array(
             select distinct membership.board_id::text
               from board_memberships as membership
              where membership.organization_id=token.organization_id
                and membership.member_id=token.member_id
                and membership.state='active'
                and membership.active_from<=transaction_timestamp()
                and (membership.active_until is null
                     or membership.active_until>transaction_timestamp())
              order by membership.board_id::text
           ),
           array[]::text[]
         ) as board_ids
    from access_token_records as token
    join members as member
      on member.id=token.member_id
     and member.organization_id=token.organization_id
     and member.state='active'
    join oauth_clients as oauth_client
      on oauth_client.id=token.client_id
     and oauth_client.organization_id=token.organization_id
     and oauth_client.state='active'
    join crypto_key_registry as signing_key
      on signing_key.id=token.signing_key_id
     and signing_key.organization_id=token.organization_id
     and signing_key.purpose='oauth_signing'
     and signing_key.algorithm='ES256'
     and signing_key.public_jwk is not null
     and signing_key.compromised_at is null
    join system_instance as instance
      on instance.organization_id=token.organization_id
     and instance.canonical_resource_uri=token.resource_uri
   where token.jti=candidate_jti
     and public.boardagent_access_session_current(token.id)
     and token.revoked_at is null
     and token.expires_at>transaction_timestamp()
$$;

alter function boardagent_resolve_access_token(uuid) owner to boardagent_migrator;
revoke all on function boardagent_resolve_access_token(uuid) from public;
grant execute on function boardagent_resolve_access_token(uuid) to boardagent_server;

create or replace function public.boardagent_webhook_snapshot(
  candidate_action text,
  candidate_webhook_id uuid,
  candidate_key_id uuid,
  candidate_exact_origin text
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
  webhook public.member_webhooks%rowtype;
  resolved_key_id uuid;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_action not in ('configure_webhook','rotate_webhook_secret','disable_webhook','test_webhook')
     or candidate_webhook_id is null or not public.boardagent_is_uuid_v7(candidate_webhook_id)
     or candidate_exact_origin !~ '^https://[^/?#]+$' then
    raise exception 'webhook authority requires one managed exact action' using errcode='25000';
  end if;
  context_organization := public.boardagent_context_uuid('boardagent.organization_id');
  context_member := public.boardagent_context_uuid('boardagent.member_id');
  context_client := public.boardagent_context_uuid('boardagent.client_id');
  context_token := public.boardagent_context_uuid('boardagent.token_jti');

  perform 1
    from public.access_token_records as token
    join public.oauth_clients as oauth_client on oauth_client.id=token.client_id
    join public.auth_sessions as session on session.id=token.session_id
    join public.members as actor
      on actor.id=token.member_id and actor.organization_id=token.organization_id
    join public.system_instance as instance on instance.organization_id=token.organization_id
   where token.organization_id=context_organization and token.member_id=context_member
     and token.client_id=context_client and token.jti=context_token
     and token.revoked_at is null and token.expires_at>transaction_timestamp()
     and 'notifications:manage'=any(token.scope_set)
     and oauth_client.state='active' and actor.state='active'
     and instance.canonical_resource_uri=token.resource_uri
     and session.organization_id=token.organization_id and session.member_id=token.member_id
     and session.client_id=token.client_id
     and public.boardagent_access_session_current(token.id)
     and session.exact_origin=candidate_exact_origin
     and (
       candidate_action not in ('configure_webhook','rotate_webhook_secret')
       or session.last_authenticated_at>=transaction_timestamp()-interval '15 minutes'
     )
   for update of token,session;
  if not found then
    raise exception 'webhook authority is unavailable' using errcode='42501';
  end if;

  select candidate.* into webhook from public.member_webhooks as candidate
   where candidate.id=candidate_webhook_id
     and candidate.organization_id=context_organization and candidate.member_id=context_member
   for update;

  if candidate_action='configure_webhook' then
    if webhook.id is not null or candidate_key_id is null then
      raise exception 'new webhook identity is unavailable' using errcode='55000';
    end if;
    resolved_key_id := candidate_key_id;
  else
    if webhook.id is null or webhook.state<>'active' then
      raise exception 'active owned webhook is unavailable' using errcode='P0002';
    end if;
    resolved_key_id := webhook.key_id;
    if candidate_key_id is not null and candidate_key_id<>resolved_key_id then
      raise exception 'webhook key binding changed' using errcode='40001';
    end if;
  end if;

  if candidate_action in ('configure_webhook','rotate_webhook_secret') and not exists (
    select 1 from public.crypto_key_registry as key
     where key.id=resolved_key_id and key.organization_id=context_organization
       and key.purpose='data_kek' and key.algorithm='A256GCM' and key.public_jwk is null
       and key.activated_at<=transaction_timestamp() and key.retired_at is null
       and key.compromised_at is null
  ) then
    raise exception 'active webhook encryption key is unavailable' using errcode='55000';
  end if;

  if candidate_action='configure_webhook' then
    return jsonb_build_object(
      'organizationId',context_organization,'memberId',context_member,
      'webhookId',candidate_webhook_id,'state','absent','generation','0',
      'endpointSha256',null,'keyId',resolved_key_id
    );
  end if;
  return jsonb_build_object(
    'organizationId',context_organization,'memberId',context_member,
    'webhookId',webhook.id,'state',webhook.state,'generation',webhook.generation::text,
    'endpointSha256',encode(webhook.endpoint_sha256,'hex'),'keyId',webhook.key_id,
    'eventClasses',to_jsonb(webhook.event_classes)
  );
end
$$;

create or replace function boardagent_guard_auth_session_state()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if new.member_id is distinct from old.member_id or new.client_id is distinct from old.client_id then
    raise exception 'auth session principal/client binding is immutable'
      using errcode='23514';
  end if;
  -- An expired browser may still anchor a live refresh grant. Explicitly revoke
  -- that anchor without changing its authentication, secret or time boundaries.
  if old.state='expired' and new.state='revoked' and row(
       new.opaque_session_sha256,new.expires_at,new.last_authenticated_at,new.exact_origin,new.created_at
     ) is not distinct from row(
       old.opaque_session_sha256,old.expires_at,old.last_authenticated_at,old.exact_origin,old.created_at
     ) then
    return new;
  end if;
  if old.state in ('revoked','expired') and row(
       new.opaque_session_sha256,new.expires_at,new.last_authenticated_at,new.state
     ) is distinct from row(
       old.opaque_session_sha256,old.expires_at,old.last_authenticated_at,old.state
     ) then
    raise exception 'terminal auth session is immutable' using errcode='23514';
  end if;
  if new.state=old.state then
    if new.state='authenticated' and (
      new.expires_at>old.created_at+interval '8 hours'
      or new.last_authenticated_at is null
      or new.last_authenticated_at>transaction_timestamp()
    ) then
      raise exception 'authenticated session rotation exceeded its frozen lifetime'
        using errcode='23514';
    end if;
    return new;
  end if;
  if (old.state='anonymous' and new.state in ('authenticated','revoked','expired'))
     or (old.state='authenticated' and new.state in ('revoked','expired')) then
    return new;
  end if;
  raise exception 'illegal auth session transition: % -> %',old.state,new.state
    using errcode='23514';
end
$$;

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
    perform 1 from public.auth_sessions as proof
     where proof.organization_id=context_organization and proof.member_id=context_member
       and proof.client_id=context_client and proof.state='authenticated'
       and proof.expires_at>transaction_timestamp()
       and proof.last_authenticated_at>=transaction_timestamp()-interval '15 minutes'
       and public.boardagent_constant_time_sha256_equal(proof.opaque_session_sha256,proof_sha)
     for update;
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

create or replace function public.boardagent_apply_identity_admin_action(
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
     where id=candidate_target and state in ('authenticated','expired');
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
