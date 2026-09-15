-- BoardAgent Phase 2 / group 47: exact prelinked upstream OIDC identity authority.
-- Raw state, nonce, PKCE verifier, authorization code and upstream tokens never enter
-- relational storage. PostgreSQL binds only their hashes/challenge and a one-use local
-- completion capability to the existing BoardAgent authorization request.

alter table public.oidc_login_transactions
  add column provider_id text not null
    check (provider_id ~ '^[a-z][a-z0-9_-]{0,31}$'),
  add column provider_kind text not null
    check (provider_kind in ('generic','uae_pass')),
  add column interaction_uid text not null
    check (
      length(interaction_uid) between 16 and 256
      and interaction_uid ~ '^[A-Za-z0-9_-]+$'
    ),
  add column authorization_request_id uuid not null
    references public.oauth_authorization_requests(id) on delete cascade,
  add column callback_uri text not null
    check (callback_uri ~ '^https://[^?#]+/auth/oidc/callback/[a-z][a-z0-9_-]{0,31}$'),
  add column pkce_s256_challenge text not null
    check (pkce_s256_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  add column invitation_token_sha256 bytea
    check (invitation_token_sha256 is null or public.boardagent_hash_is_sha256(invitation_token_sha256)),
  add column linked_identity_link_id uuid
    references public.external_identity_links(id) on delete restrict,
  add column linked_member_id uuid,
  add column completion_sha256 bytea
    check (completion_sha256 is null or public.boardagent_hash_is_sha256(completion_sha256)),
  add column completion_consumed_at timestamptz(6),
  add column failure_code text
    check (failure_code in ('binding_refused','protocol_refused','unknown_subject','pending_link')),
  add foreign key (organization_id,linked_member_id)
    references public.members(organization_id,id) on delete restrict,
  add check (expires_at<=issued_at+interval '10 minutes'),
  add check (provider_kind='uae_pass' or invitation_token_sha256 is null),
  add check (
    (consumed_at is null
      and linked_identity_link_id is null
      and linked_member_id is null
      and completion_sha256 is null
      and completion_consumed_at is null
      and failure_code is null)
    or
    (consumed_at is not null and (
      (linked_identity_link_id is not null
        and linked_member_id is not null
        and completion_sha256 is not null
        and failure_code is null)
      or
      (linked_identity_link_id is null
        and linked_member_id is null
        and completion_sha256 is null
        and completion_consumed_at is null
        and failure_code is not null)
    ))
  ),
  add check (completion_consumed_at is null or completion_sha256 is not null);

create unique index oidc_login_transactions_one_live_request_uq
  on public.oidc_login_transactions(authorization_request_id)
  where consumed_at is null;
create unique index oidc_login_transactions_completion_uq
  on public.oidc_login_transactions(completion_sha256)
  where completion_sha256 is not null;

revoke insert,update on public.oidc_login_transactions from boardagent_server;
revoke insert,update on public.external_identity_links from boardagent_server;

drop policy boardagent_server_scope on public.oidc_login_transactions;
create policy boardagent_server_identity_oidc_login_transactions
  on public.oidc_login_transactions for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

create policy boardagent_migrator_identity_oidc_login_transactions
  on public.oidc_login_transactions for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_migrator_identity_external_links
  on public.external_identity_links for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

do $oidc_federation_migrator_read$
declare
  identity_table text;
begin
  foreach identity_table in array array[
    'members','enrollment_invitations','oauth_authorization_requests','auth_sessions'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_oidc_read on public.%I for select to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''identity'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id''))',
      identity_table
    );
  end loop;
end
$oidc_federation_migrator_read$;

create policy boardagent_migrator_oidc_authorization_request_lock
  on public.oauth_authorization_requests for update to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

create function public.boardagent_begin_oidc_login(
  candidate_organization_id uuid,
  candidate_transaction_id uuid,
  candidate_provider_id text,
  candidate_provider_kind text,
  candidate_exact_issuer text,
  candidate_interaction_uid text,
  candidate_authorization_request_id uuid,
  candidate_session_id uuid,
  candidate_client_id uuid,
  candidate_resource_uri text,
  candidate_callback_uri text,
  candidate_state_sha256 bytea,
  candidate_nonce_sha256 bytea,
  candidate_pkce_s256_challenge text,
  candidate_invitation_token_sha256 bytea
)
returns table(result_transaction_id uuid,result_expires_at timestamptz)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  authorization_request public.oauth_authorization_requests%rowtype;
  browser_session public.auth_sessions%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or candidate_organization_id
          is distinct from public.boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'OIDC federation requires the managed identity context'
      using errcode='25000';
  end if;
  if not public.boardagent_is_uuid_v7(candidate_transaction_id)
     or candidate_provider_id is null
     or candidate_provider_id !~ '^[a-z][a-z0-9_-]{0,31}$'
     or candidate_provider_kind is null
     or candidate_provider_kind not in ('generic','uae_pass')
     or candidate_exact_issuer is null
     or candidate_exact_issuer !~ '^https://[^?#]+$'
     or candidate_interaction_uid is null
     or length(candidate_interaction_uid) not between 16 and 256
     or candidate_interaction_uid !~ '^[A-Za-z0-9_-]+$'
     or candidate_resource_uri is null
     or candidate_resource_uri !~ '^https://[^/?#]+/mcp$'
     or candidate_callback_uri is null
     or candidate_callback_uri !~ '^https://[^?#]+/auth/oidc/callback/[a-z][a-z0-9_-]{0,31}$'
     or right(candidate_resource_uri,4)<>'/mcp'
     or candidate_callback_uri <> left(candidate_resource_uri,length(candidate_resource_uri)-4)
          || '/auth/oidc/callback/' || candidate_provider_id
     or not public.boardagent_hash_is_sha256(candidate_state_sha256)
     or not public.boardagent_hash_is_sha256(candidate_nonce_sha256)
     or candidate_pkce_s256_challenge !~ '^[A-Za-z0-9_-]{43}$'
     or (candidate_provider_kind='generic' and candidate_invitation_token_sha256 is not null)
     or (candidate_invitation_token_sha256 is not null
          and not public.boardagent_hash_is_sha256(candidate_invitation_token_sha256)) then
    raise exception 'invalid OIDC federation transaction binding' using errcode='22023';
  end if;

  select request.* into authorization_request
    from public.oauth_authorization_requests as request
   where request.id=candidate_authorization_request_id
     and request.organization_id=candidate_organization_id
   for update;
  select session.* into browser_session
    from public.auth_sessions as session
   where session.id=candidate_session_id
     and session.organization_id=candidate_organization_id
   for update;
  if authorization_request.id is null
     or browser_session.id is null
     or authorization_request.session_id<>candidate_session_id
     or authorization_request.client_id<>candidate_client_id
     or authorization_request.resource_uri<>candidate_resource_uri
     or authorization_request.request_state<>'pending'
     or authorization_request.member_id is not null
     or authorization_request.expires_at<=transaction_timestamp()
     or browser_session.client_id<>candidate_client_id
     or browser_session.state<>'anonymous'
     or browser_session.member_id is not null
     or browser_session.expires_at<=transaction_timestamp()
     or browser_session.exact_origin||'/mcp'<>candidate_resource_uri then
    raise exception 'OIDC federation authorization binding is unavailable' using errcode='28000';
  end if;

  insert into public.oidc_login_transactions(
    id,organization_id,provider_id,provider_kind,exact_issuer,interaction_uid,
    authorization_request_id,state_sha256,nonce_sha256,session_id,client_id,
    resource_uri,callback_uri,pkce_s256_challenge,invitation_token_sha256,expires_at
  ) values (
    candidate_transaction_id,candidate_organization_id,candidate_provider_id,
    candidate_provider_kind,candidate_exact_issuer,candidate_interaction_uid,
    candidate_authorization_request_id,candidate_state_sha256,candidate_nonce_sha256,
    candidate_session_id,candidate_client_id,candidate_resource_uri,candidate_callback_uri,
    candidate_pkce_s256_challenge,candidate_invitation_token_sha256,
    transaction_timestamp()+interval '10 minutes'
  );
  return query
    select candidate_transaction_id,transaction_timestamp()+interval '10 minutes';
end
$$;

create function public.boardagent_complete_oidc_login(
  candidate_organization_id uuid,
  candidate_transaction_id uuid,
  candidate_provider_id text,
  candidate_provider_kind text,
  candidate_exact_issuer text,
  candidate_state_sha256 bytea,
  candidate_nonce_sha256 bytea,
  candidate_pkce_s256_challenge text,
  candidate_subject text,
  candidate_completion_sha256 bytea,
  candidate_pending_link_id uuid
)
returns table(result_status text,result_interaction_uid text,result_member_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  login_transaction public.oidc_login_transactions%rowtype;
  authorization_request public.oauth_authorization_requests%rowtype;
  browser_session public.auth_sessions%rowtype;
  linked_member uuid;
  linked_identity_link uuid;
  pending_invitation public.enrollment_invitations%rowtype;
  existing_link public.external_identity_links%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or candidate_organization_id
          is distinct from public.boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'OIDC federation requires the managed identity context'
      using errcode='25000';
  end if;
  if not public.boardagent_is_uuid_v7(candidate_transaction_id)
     or candidate_provider_id is null
     or candidate_provider_id !~ '^[a-z][a-z0-9_-]{0,31}$'
     or candidate_provider_kind is null
     or candidate_provider_kind not in ('generic','uae_pass')
     or candidate_exact_issuer is null
     or candidate_exact_issuer !~ '^https://[^?#]+$'
     or candidate_subject is null
     or length(candidate_subject) not between 1 and 1024
     or octet_length(candidate_subject) not between 1 and 4096
     or candidate_subject ~ '[[:cntrl:]]'
     or not public.boardagent_hash_is_sha256(candidate_state_sha256)
     or not public.boardagent_hash_is_sha256(candidate_nonce_sha256)
     or candidate_pkce_s256_challenge !~ '^[A-Za-z0-9_-]{43}$'
     or not public.boardagent_hash_is_sha256(candidate_completion_sha256)
     or not public.boardagent_is_uuid_v7(candidate_pending_link_id) then
    raise exception 'invalid OIDC federation completion' using errcode='22023';
  end if;

  select candidate.* into login_transaction
    from public.oidc_login_transactions as candidate
   where candidate.id=candidate_transaction_id
     and candidate.organization_id=candidate_organization_id
   for update;
  if login_transaction.id is null or login_transaction.consumed_at is not null then
    return query select 'unavailable'::text,null::text,null::uuid;
    return;
  end if;

  select request.* into authorization_request
    from public.oauth_authorization_requests as request
   where request.id=login_transaction.authorization_request_id
     and request.organization_id=candidate_organization_id
   for update;
  select session.* into browser_session
    from public.auth_sessions as session
   where session.id=login_transaction.session_id
     and session.organization_id=candidate_organization_id
   for update;
  if login_transaction.provider_id is distinct from candidate_provider_id
     or login_transaction.provider_kind is distinct from candidate_provider_kind
     or login_transaction.exact_issuer is distinct from candidate_exact_issuer
     or login_transaction.state_sha256 is distinct from candidate_state_sha256
     or login_transaction.nonce_sha256 is distinct from candidate_nonce_sha256
     or login_transaction.pkce_s256_challenge is distinct from candidate_pkce_s256_challenge
     or login_transaction.expires_at<=transaction_timestamp()
     or authorization_request.id is null
     or authorization_request.session_id<>login_transaction.session_id
     or authorization_request.client_id<>login_transaction.client_id
     or authorization_request.resource_uri<>login_transaction.resource_uri
     or authorization_request.request_state<>'pending'
     or authorization_request.member_id is not null
     or authorization_request.expires_at<=transaction_timestamp()
     or browser_session.id is null
     or browser_session.client_id<>login_transaction.client_id
     or browser_session.state<>'anonymous'
     or browser_session.member_id is not null
     or browser_session.expires_at<=transaction_timestamp() then
    update public.oidc_login_transactions
       set consumed_at=transaction_timestamp(),failure_code='binding_refused'
     where id=login_transaction.id;
    return query
      select 'unavailable'::text,login_transaction.interaction_uid,null::uuid;
    return;
  end if;

  select link.id,link.member_id into linked_identity_link,linked_member
    from public.external_identity_links as link
    join public.members as member
      on member.id=link.member_id
     and member.organization_id=link.organization_id
     and member.state='active'
   where link.organization_id=candidate_organization_id
     and link.issuer=candidate_exact_issuer
     and link.subject=candidate_subject
     and link.state='active';
  if linked_member is not null then
    update public.oidc_login_transactions
       set consumed_at=transaction_timestamp(),
           linked_identity_link_id=linked_identity_link,linked_member_id=linked_member,
           completion_sha256=candidate_completion_sha256
     where id=login_transaction.id;
    return query
      select 'authenticated'::text,login_transaction.interaction_uid,linked_member;
    return;
  end if;

  if candidate_provider_kind='uae_pass'
     and login_transaction.invitation_token_sha256 is not null then
    select invitation.* into pending_invitation
      from public.enrollment_invitations as invitation
      join public.members as invited_member
        on invited_member.id=invitation.member_id
       and invited_member.organization_id=invitation.organization_id
       and invited_member.state='invited'
     where invitation.organization_id=candidate_organization_id
       and invitation.token_sha256=login_transaction.invitation_token_sha256
       and invitation.consumed_at is null
       and invitation.revoked_at is null
       and invitation.expires_at>transaction_timestamp()
     for update of invitation;
    if pending_invitation.id is not null then
      select link.* into existing_link
        from public.external_identity_links as link
       where link.issuer=candidate_exact_issuer and link.subject=candidate_subject
       for update;
      if existing_link.id is null then
        insert into public.external_identity_links(
          id,organization_id,member_id,issuer,subject,state,invitation_id
        ) values (
          candidate_pending_link_id,candidate_organization_id,pending_invitation.member_id,
          candidate_exact_issuer,candidate_subject,'pending',pending_invitation.id
        );
      elsif existing_link.organization_id<>candidate_organization_id
         or existing_link.member_id<>pending_invitation.member_id
         or existing_link.state<>'pending'
         or existing_link.invitation_id is distinct from pending_invitation.id then
        update public.oidc_login_transactions
           set consumed_at=transaction_timestamp(),failure_code='unknown_subject'
         where id=login_transaction.id;
        return query
          select 'unknown_subject'::text,login_transaction.interaction_uid,null::uuid;
        return;
      end if;
      update public.oidc_login_transactions
         set consumed_at=transaction_timestamp(),failure_code='pending_link'
       where id=login_transaction.id;
      return query
        select 'pending_link'::text,login_transaction.interaction_uid,null::uuid;
      return;
    end if;
  end if;

  update public.oidc_login_transactions
     set consumed_at=transaction_timestamp(),failure_code='unknown_subject'
   where id=login_transaction.id;
  return query
    select 'unknown_subject'::text,login_transaction.interaction_uid,null::uuid;
end
$$;

create function public.boardagent_reject_oidc_login(
  candidate_organization_id uuid,
  candidate_transaction_id uuid,
  candidate_failure_code text
)
returns boolean
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  changed integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or candidate_organization_id
          is distinct from public.boardagent_context_uuid('boardagent.organization_id')
     or not public.boardagent_is_uuid_v7(candidate_transaction_id)
     or candidate_failure_code is null
     or candidate_failure_code not in ('binding_refused','protocol_refused') then
    raise exception 'invalid OIDC federation rejection' using errcode='25000';
  end if;
  update public.oidc_login_transactions
     set consumed_at=transaction_timestamp(),failure_code=candidate_failure_code
   where id=candidate_transaction_id
     and organization_id=candidate_organization_id
     and consumed_at is null;
  get diagnostics changed=row_count;
  return changed=1;
end
$$;

create function public.boardagent_consume_oidc_completion(
  candidate_organization_id uuid,
  candidate_interaction_uid text,
  candidate_completion_sha256 bytea
)
returns uuid
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  login_transaction public.oidc_login_transactions%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or candidate_organization_id
          is distinct from public.boardagent_context_uuid('boardagent.organization_id')
     or candidate_interaction_uid is null
     or length(candidate_interaction_uid) not between 16 and 256
     or candidate_interaction_uid !~ '^[A-Za-z0-9_-]+$'
     or not public.boardagent_hash_is_sha256(candidate_completion_sha256) then
    raise exception 'invalid OIDC federation completion consumption' using errcode='25000';
  end if;
  select candidate.* into login_transaction
    from public.oidc_login_transactions as candidate
   where candidate.organization_id=candidate_organization_id
     and candidate.interaction_uid=candidate_interaction_uid
     and candidate.completion_sha256=candidate_completion_sha256
   for update;
  if login_transaction.id is null
     or login_transaction.consumed_at is null
     or login_transaction.completion_consumed_at is not null
     or login_transaction.failure_code is not null
     or login_transaction.linked_member_id is null
     or login_transaction.expires_at<=transaction_timestamp()
     or not exists (
       select 1
         from public.oauth_authorization_requests as request
         join public.auth_sessions as session
           on session.id=request.session_id
          and session.organization_id=request.organization_id
          and session.state='anonymous'
          and session.member_id is null
          and session.client_id=request.client_id
          and session.expires_at>transaction_timestamp()
         join public.members as member
           on member.id=login_transaction.linked_member_id
          and member.organization_id=login_transaction.organization_id
          and member.state='active'
         join public.external_identity_links as link
           on link.id=login_transaction.linked_identity_link_id
          and link.organization_id=login_transaction.organization_id
          and link.member_id=member.id
          and link.issuer=login_transaction.exact_issuer
          and link.state='active'
        where request.id=login_transaction.authorization_request_id
          and request.organization_id=login_transaction.organization_id
          and request.client_id=login_transaction.client_id
          and request.resource_uri=login_transaction.resource_uri
          and request.request_state='pending'
          and request.member_id is null
          and request.expires_at>transaction_timestamp()
     ) then
    return null;
  end if;
  update public.oidc_login_transactions
     set completion_consumed_at=transaction_timestamp()
   where id=login_transaction.id;
  return login_transaction.linked_member_id;
end
$$;

do $oidc_federation_functions$
declare
  function_name regprocedure;
begin
  foreach function_name in array array[
    'public.boardagent_begin_oidc_login(uuid,uuid,text,text,text,text,uuid,uuid,uuid,text,text,bytea,bytea,text,bytea)'::regprocedure,
    'public.boardagent_complete_oidc_login(uuid,uuid,text,text,text,bytea,bytea,text,text,bytea,uuid)'::regprocedure,
    'public.boardagent_reject_oidc_login(uuid,uuid,text)'::regprocedure,
    'public.boardagent_consume_oidc_completion(uuid,text,bytea)'::regprocedure
  ]
  loop
    execute 'alter function '||function_name||' owner to boardagent_migrator';
    execute 'revoke all on function '||function_name||' from public';
    execute 'grant execute on function '||function_name||' to boardagent_server';
  end loop;
end
$oidc_federation_functions$;
