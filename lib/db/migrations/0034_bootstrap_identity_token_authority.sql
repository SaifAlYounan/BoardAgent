-- BoardAgent Phase 1 / group 34: exact bootstrap, activation and OAuth token authority.

create or replace function boardagent_lock_audit_head()
returns table(last_sequence bigint, last_event_sha256 bytea, occurred_at text)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if coalesce(current_setting('boardagent.transaction_scope', true),'')
       not in ('request','migration','worker','bootstrap','identity') then
    raise exception 'audit append requires a managed request transaction, migration transaction, worker transaction, bootstrap transaction, or identity transaction'
      using errcode = '25000';
  end if;
  return query
    select head.last_sequence,
           head.last_event_sha256,
           to_char(transaction_timestamp() at time zone 'UTC',
                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      from audit_chain_head as head
     where head.singleton_key
       for update;
  if not found then
    raise exception 'audit chain head is unavailable' using errcode = '55000';
  end if;
end
$$;
alter function boardagent_lock_audit_head() owner to boardagent_migrator;
revoke all on function boardagent_lock_audit_head() from public;
grant execute on function boardagent_lock_audit_head()
  to boardagent_server, boardagent_worker, boardagent_migrator;

grant insert on access_token_records, refresh_families, refresh_tokens to boardagent_server;
grant update(consumed_at) on oauth_authorization_codes to boardagent_server;
grant update(request_state) on oauth_authorization_requests to boardagent_server;
grant update(state,attempt_count,consumed_at,confirmed_by) on enrollment_activation_challenges
  to boardagent_server;
grant update(consumed_at,revoked_at,pending_activation_member_id) on enrollment_invitations
  to boardagent_server;
grant update(generation,state,last_used_at,idle_expires_at,revoked_at) on refresh_families
  to boardagent_server;
grant update(used_at,replaced_by_id,revoked_at) on refresh_tokens to boardagent_server;
grant update(revoked_at) on access_token_records to boardagent_server;
grant update(state) on auth_sessions to boardagent_server;

do $bootstrap_policies$
declare
  bootstrap_table text;
begin
  foreach bootstrap_table in array array[
    'organizations','system_instance','members','boards','board_versions',
    'organization_role_assignments','board_memberships','membership_versions',
    'secretary_support_versions','onboarding_terms_versions','enrollment_invitations'
  ]
  loop
    execute format('grant select,insert on %I to boardagent_migrator',bootstrap_table);
    execute format(
      'create policy boardagent_migrator_bootstrap on %I for all to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''bootstrap'') with check (current_setting(''boardagent.transaction_scope'',true)=''bootstrap'')',
      bootstrap_table
    );
  end loop;
end
$bootstrap_policies$;

create policy boardagent_server_identity_refresh_tokens on refresh_tokens
  for all to boardagent_server
  using (
    exists (
      select 1 from refresh_families as family
       where family.id=refresh_tokens.family_id
         and family.organization_id=boardagent_context_uuid('boardagent.organization_id')
    )
  )
  with check (
    exists (
      select 1 from refresh_families as family
       where family.id=refresh_tokens.family_id
         and family.organization_id=boardagent_context_uuid('boardagent.organization_id')
    )
  );

create policy boardagent_server_identity_client_grants on oauth_client_grants
  for select to boardagent_server
  using (
    exists (
      select 1 from oauth_clients as client
       where client.id=oauth_client_grants.client_id
         and client.organization_id=boardagent_context_uuid('boardagent.organization_id')
    )
  );
create policy boardagent_server_identity_client_redirects on oauth_client_redirect_uris
  for select to boardagent_server
  using (
    exists (
      select 1 from oauth_clients as client
       where client.id=oauth_client_redirect_uris.client_id
         and client.organization_id=boardagent_context_uuid('boardagent.organization_id')
    )
  );

create function boardagent_identity_member_onboarding_current(
  candidate_organization_id uuid,
  candidate_member_id uuid,
  requested_scopes text[]
)
returns boolean
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or candidate_organization_id
       is distinct from boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'onboarding readiness requires a managed identity transaction'
      using errcode='25000';
  end if;
  if requested_scopes <@ array['onboarding:read']::text[] then
    return true;
  end if;
  return not exists (
    select 1
      from board_memberships as membership
     where membership.organization_id=candidate_organization_id
       and membership.member_id=candidate_member_id
       and membership.state='active' and membership.active_until is null
       and not exists (
         select 1
           from lateral (
             select terms.id
               from onboarding_terms_versions as terms
              where terms.organization_id=membership.organization_id
                and terms.seat_role=membership.seat_role
                and terms.effective_at<=transaction_timestamp()
              order by terms.effective_at desc,terms.version desc,terms.id desc
              limit 1
           ) as current_terms
           cross join lateral (
             select support.id
               from secretary_support_versions as support
              where support.organization_id=membership.organization_id
                and (support.board_id=membership.board_id or support.board_id is null)
                and support.effective_at<=transaction_timestamp()
              order by (support.board_id=membership.board_id) desc,
                       support.effective_at desc,support.version desc,support.id desc
              limit 1
           ) as current_support
           join onboarding_attestations as attestation
             on attestation.organization_id=membership.organization_id
            and attestation.member_id=membership.member_id
            and attestation.board_id=membership.board_id
            and attestation.terms_version_id=current_terms.id
            and attestation.support_version_id=current_support.id
       )
  );
end
$$;
alter function boardagent_identity_member_onboarding_current(uuid,uuid,text[])
  owner to boardagent_migrator;
revoke all on function boardagent_identity_member_onboarding_current(uuid,uuid,text[])
  from public;
grant execute on function boardagent_identity_member_onboarding_current(uuid,uuid,text[])
  to boardagent_server;

create function boardagent_guard_consumable_state()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if new.state=old.state then return new; end if;
  if old.state<>'issued' or new.state not in ('consumed','expired','revoked') then
    raise exception 'illegal % state transition: % -> %',tg_table_name,old.state,new.state
      using errcode='23514';
  end if;
  return new;
end
$$;
create trigger boardagent_enrollment_challenge_state
  before update of state on enrollment_activation_challenges
  for each row execute function boardagent_guard_consumable_state();

create function boardagent_guard_refresh_family_state()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if new.state=old.state then return new; end if;
  if old.state<>'active' or new.state not in ('revoked','compromised','expired') then
    raise exception 'illegal refresh family state transition: % -> %',old.state,new.state
      using errcode='23514';
  end if;
  return new;
end
$$;
create trigger boardagent_refresh_family_state
  before update of state on refresh_families
  for each row execute function boardagent_guard_refresh_family_state();
