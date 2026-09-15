-- BoardAgent Phase 2 / group 44: normalized oidc-provider authorization authority.
-- Raw OAuth state and bearer/code/session values remain outside relational storage;
-- PostgreSQL retains only hashes plus the frozen typed request/session/consent/code rows.

grant insert on
  public.auth_sessions,
  public.oauth_authorization_requests,
  public.oauth_authorization_codes,
  public.oauth_consents
to boardagent_server;

grant update(
  opaque_session_sha256,
  member_id,
  client_id,
  state,
  expires_at,
  last_authenticated_at
) on public.auth_sessions to boardagent_server;
grant update(member_id,session_id,request_state)
  on public.oauth_authorization_requests to boardagent_server;
grant update(consumed_at,revoked_at)
  on public.oauth_authorization_codes to boardagent_server;
grant update(revoked_at)
  on public.oauth_consents to boardagent_server;

do $oauth_identity_policies$
declare
  identity_table text;
begin
  foreach identity_table in array array[
    'auth_sessions',
    'oauth_authorization_requests',
    'oauth_authorization_codes',
    'oauth_consents'
  ]
  loop
    execute format('drop policy boardagent_server_scope on public.%I',identity_table);
    execute format(
      'create policy boardagent_server_identity_scope on public.%I for all to boardagent_server using (current_setting(''boardagent.transaction_scope'',true)=''identity'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id'')) with check (current_setting(''boardagent.transaction_scope'',true)=''identity'' and organization_id=public.boardagent_context_uuid(''boardagent.organization_id''))',
      identity_table
    );
  end loop;
end
$oauth_identity_policies$;

create function boardagent_guard_oauth_request_state()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if old.member_id is not null and new.member_id is distinct from old.member_id then
    raise exception 'OAuth request member binding is immutable once established'
      using errcode='23514';
  end if;
  if new.member_id is distinct from old.member_id and old.request_state<>'pending' then
    raise exception 'OAuth request member binding requires a pending request'
      using errcode='23514';
  end if;
  if new.session_id is distinct from old.session_id then
    if old.request_state<>'pending' or new.member_id is null or not exists (
      select 1
        from public.auth_sessions as old_session
        join public.auth_sessions as new_session
          on new_session.id=new.session_id
         and new_session.organization_id=old.organization_id
         and new_session.client_id=old.client_id
         and new_session.member_id=new.member_id
         and new_session.state='authenticated'
       where old_session.id=old.session_id
         and old_session.organization_id=old.organization_id
         and old_session.state='anonymous'
    ) then
      raise exception 'OAuth request session replacement is not an authenticated continuation'
        using errcode='23514';
    end if;
  end if;
  if new.request_state=old.request_state then return new; end if;
  if (old.request_state='pending' and new.request_state in ('approved','denied','expired'))
     or (old.request_state='approved' and new.request_state='consumed') then
    return new;
  end if;
  raise exception 'illegal OAuth request transition: % -> %',old.request_state,new.request_state
    using errcode='23514';
end
$$;
create trigger boardagent_oauth_request_state
  before update on public.oauth_authorization_requests
  for each row execute function boardagent_guard_oauth_request_state();

create function boardagent_guard_auth_session_state()
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
create trigger boardagent_auth_session_state
  before update on public.auth_sessions
  for each row execute function boardagent_guard_auth_session_state();

create function boardagent_guard_oauth_code_terminal_time()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if old.consumed_at is not null or old.revoked_at is not null then
    raise exception 'terminal OAuth code is immutable' using errcode='23514';
  end if;
  if (new.consumed_at is not distinct from transaction_timestamp() and new.revoked_at is null)
     or (new.revoked_at is not distinct from transaction_timestamp() and new.consumed_at is null) then
    return new;
  end if;
  raise exception 'OAuth code terminality requires the database transaction time'
    using errcode='23514';
end
$$;
create trigger boardagent_oauth_code_terminal_time
  before update of consumed_at,revoked_at on public.oauth_authorization_codes
  for each row execute function boardagent_guard_oauth_code_terminal_time();

create function boardagent_guard_oauth_consent_revocation_time()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if old.revoked_at is null and new.revoked_at is not distinct from transaction_timestamp() then
    return new;
  end if;
  raise exception 'OAuth consent revocation requires one database-timed transition'
    using errcode='23514';
end
$$;
create trigger boardagent_oauth_consent_revocation_time
  before update of revoked_at on public.oauth_consents
  for each row execute function boardagent_guard_oauth_consent_revocation_time();
