-- BoardAgent Phase 2 / group 45: encrypted, explicit TOTP fallback authority.
-- The pre-0045 table had never been executable. Refuse unknown legacy rows instead of
-- silently inventing a lookup handle or blessing an unverified seed.

do $legacy_totp_guard$
begin
  if exists (select 1 from public.totp_credentials) then
    raise exception 'unmanaged pre-0045 TOTP credentials require explicit recovery'
      using errcode='55000';
  end if;
end
$legacy_totp_guard$;

alter table public.totp_credentials
  add column fallback_handle_sha256 bytea not null
    check (public.boardagent_hash_is_sha256(fallback_handle_sha256)),
  add column authorized_by uuid not null,
  add column max_failed_attempts smallint not null
    check (max_failed_attempts between 3 and 10),
  add column lockout_seconds integer not null
    check (lockout_seconds between 60 and 86400),
  add column activated_at timestamptz(6),
  add column terminal_at timestamptz(6),
  add constraint totp_credentials_authorized_by_fk
    foreign key (organization_id,authorized_by)
    references public.members(organization_id,id) on delete restrict;

alter table public.totp_credentials
  drop constraint totp_credentials_state_check,
  drop constraint totp_credentials_failed_attempts_check,
  add constraint totp_credentials_state_check
    check (state in ('pending_verification','active','replaced','disabled','compromised')),
  add constraint totp_credentials_failed_attempts_check
    check (failed_attempts between 0 and max_failed_attempts),
  add constraint totp_credentials_last_step_check
    check (last_accepted_step is null or last_accepted_step>=0),
  add constraint totp_credentials_lifecycle_check check (
    (state='pending_verification' and activated_at is null and terminal_at is null)
    or (state='active' and activated_at is not null and terminal_at is null)
    or (state in ('replaced','disabled','compromised') and terminal_at is not null)
  ),
  add constraint totp_credentials_terminal_lock_check check (
    state not in ('replaced','disabled','compromised')
    or (failed_attempts=0 and locked_until is null)
  );

create unique index totp_credentials_fallback_handle_uq
  on public.totp_credentials(fallback_handle_sha256);
create unique index totp_credentials_one_pending_uq
  on public.totp_credentials(organization_id,member_id)
  where state='pending_verification';
create unique index totp_credentials_one_active_uq
  on public.totp_credentials(organization_id,member_id)
  where state='active';

grant insert on public.totp_credentials to boardagent_server;
grant update(
  state,failed_attempts,locked_until,last_accepted_step,activated_at,terminal_at
) on public.totp_credentials to boardagent_server;

drop policy boardagent_server_scope on public.totp_credentials;
create policy boardagent_server_identity_totp_credentials
  on public.totp_credentials
  for all to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

create function public.boardagent_guard_totp_credential()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
declare
  transaction_time constant timestamptz := transaction_timestamp();
  base_failures integer;
  expected_failures integer;
begin
  if tg_op='INSERT' then
    if new.state<>'pending_verification'
       or new.failed_attempts<>0
       or new.locked_until is not null
       or new.last_accepted_step is not null
       or new.activated_at is not null
       or new.terminal_at is not null
       or new.created_at is distinct from transaction_time then
      raise exception 'TOTP enrollment must begin as a database-timed unverified credential'
        using errcode='23514';
    end if;
    if not exists (
      select 1
        from public.members as actor
        join public.organization_role_assignments as assignment
          on assignment.organization_id=actor.organization_id
         and assignment.member_id=actor.id
       where actor.organization_id=new.organization_id
         and actor.id=new.authorized_by
         and actor.state='active'
         and assignment.role in ('secretariat','admin')
         and assignment.active_from<=transaction_time
         and (assignment.active_until is null or assignment.active_until>transaction_time)
    ) or not exists (
      select 1
        from public.members as target
       where target.organization_id=new.organization_id
         and target.id=new.member_id
         and target.state in ('pending_activation','active')
    ) then
      raise exception 'TOTP enrollment requires a live secretariat and eligible member'
        using errcode='42501';
    end if;
    if not exists (
      select 1
        from public.crypto_key_registry as key
       where key.organization_id=new.organization_id
         and key.id=new.key_id
         and key.purpose='data_kek'
         and key.algorithm='A256GCM'
         and key.activated_at<=transaction_time
         and key.retired_at is null
         and key.compromised_at is null
    ) then
      raise exception 'TOTP enrollment requires the active data encryption key'
        using errcode='55000';
    end if;
    return new;
  end if;

  if row(
       new.id,new.organization_id,new.member_id,new.encrypted_secret,new.key_id,
       new.fallback_handle_sha256,new.authorized_by,new.max_failed_attempts,
       new.lockout_seconds,new.created_at
     ) is distinct from row(
       old.id,old.organization_id,old.member_id,old.encrypted_secret,old.key_id,
       old.fallback_handle_sha256,old.authorized_by,old.max_failed_attempts,
       old.lockout_seconds,old.created_at
     ) then
    raise exception 'TOTP credential binding and ciphertext are immutable'
      using errcode='55000';
  end if;

  if new.state=old.state then
    if old.state not in ('pending_verification','active')
       or new.activated_at is distinct from old.activated_at
       or new.terminal_at is distinct from old.terminal_at
       or (old.locked_until is not null and old.locked_until>transaction_time) then
      raise exception 'TOTP credential cannot change in its current lifecycle state'
        using errcode='23514';
    end if;
    if new.last_accepted_step is distinct from old.last_accepted_step then
      if old.state<>'active'
         or new.last_accepted_step is null
         or (old.last_accepted_step is not null
             and new.last_accepted_step<=old.last_accepted_step)
         or new.failed_attempts<>0
         or new.locked_until is not null then
        raise exception 'TOTP success must advance one active credential replay step'
          using errcode='23514';
      end if;
      return new;
    end if;

    base_failures := case
      when old.locked_until is not null and old.locked_until<=transaction_time then 0
      else old.failed_attempts
    end;
    expected_failures := least(base_failures+1,old.max_failed_attempts);
    if new.failed_attempts<>expected_failures
       or (
         expected_failures<old.max_failed_attempts
         and new.locked_until is not null
       )
       or (
         expected_failures=old.max_failed_attempts
         and new.locked_until is distinct from
           transaction_time+make_interval(secs=>old.lockout_seconds)
       ) then
      raise exception 'TOTP failure counter or lockout is not the exact bounded transition'
        using errcode='23514';
    end if;
    return new;
  end if;

  if old.state='pending_verification' and new.state='active' then
    if new.activated_at is distinct from transaction_time
       or new.terminal_at is not null
       or new.last_accepted_step is null
       or new.failed_attempts<>0
       or new.locked_until is not null
       or (old.locked_until is not null and old.locked_until>transaction_time)
       or not exists (
         select 1
           from public.members as actor
           join public.organization_role_assignments as assignment
             on assignment.organization_id=actor.organization_id
            and assignment.member_id=actor.id
          where actor.organization_id=old.organization_id
            and actor.id=old.authorized_by
            and actor.state='active'
            and assignment.role in ('secretariat','admin')
            and assignment.active_from<=transaction_time
            and (assignment.active_until is null or assignment.active_until>transaction_time)
       )
       or not exists (
         select 1 from public.members as target
          where target.organization_id=old.organization_id
            and target.id=old.member_id
            and target.state in ('pending_activation','active')
       ) then
      raise exception 'TOTP activation requires first-code proof and continuing authority'
        using errcode='23514';
    end if;
    return new;
  end if;

  if old.state in ('pending_verification','active')
     and new.state in ('replaced','disabled','compromised')
     and new.activated_at is not distinct from old.activated_at
     and new.terminal_at is not distinct from transaction_time
     and new.last_accepted_step is not distinct from old.last_accepted_step
     and new.failed_attempts=0
     and new.locked_until is null then
    return new;
  end if;

  raise exception 'illegal TOTP credential lifecycle transition: % -> %',old.state,new.state
    using errcode='23514';
end
$$;

revoke all on function public.boardagent_guard_totp_credential() from public;
create trigger boardagent_totp_credential_guard
  before insert or update on public.totp_credentials
  for each row execute function public.boardagent_guard_totp_credential();
