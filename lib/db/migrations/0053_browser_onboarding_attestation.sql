-- BoardAgent Phase 2 / group 53: one-use browser/passkey onboarding attestation.
-- The MCP tool prepares a browser ceremony but cannot itself attest. Only a recent,
-- user-verified passkey ceremony may complete the immutable attestation.

create table public.onboarding_browser_stages (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  member_id uuid not null,
  session_id uuid not null references public.auth_sessions(id) on delete restrict,
  client_id uuid not null references public.oauth_clients(id) on delete restrict,
  access_token_record_id uuid not null references public.access_token_records(id) on delete restrict,
  token_jti uuid not null,
  terms_version_id uuid not null references public.onboarding_terms_versions(id) on delete restrict,
  support_version_id uuid not null references public.secretary_support_versions(id) on delete restrict,
  presentation_choice text not null check (length(presentation_choice) between 1 and 2048),
  local_memory_choice text not null check (length(local_memory_choice) between 1 and 2048),
  request_sha256 bytea not null check (public.boardagent_hash_is_sha256(request_sha256)),
  stage_token_sha256 bytea not null unique
    check (public.boardagent_hash_is_sha256(stage_token_sha256)),
  safe_response_sha256 bytea not null
    check (public.boardagent_hash_is_sha256(safe_response_sha256)),
  idempotency_record_id uuid not null unique
    references public.idempotency_records(id) on delete restrict,
  exact_origin text not null check (exact_origin ~ '^https://[^/?#]+$'),
  state text not null default 'active' check (state in ('active','completed','expired')),
  expires_at timestamptz(6) not null,
  created_audit_event_id uuid not null unique
    references public.audit_events(id) on delete restrict,
  attested_audit_event_id uuid unique references public.audit_events(id) on delete restrict,
  completed_at timestamptz(6),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (organization_id,id),
  foreign key (organization_id,board_id)
    references public.boards(organization_id,id) on delete restrict,
  foreign key (organization_id,member_id)
    references public.members(organization_id,id) on delete restrict,
  check (expires_at=created_at+interval '10 minutes'),
  check (
    (state='completed' and completed_at is not null and attested_audit_event_id is not null)
    or (state in ('active','expired') and completed_at is null and attested_audit_event_id is null)
  )
);

create unique index onboarding_browser_stages_one_active_uq
  on public.onboarding_browser_stages(member_id,client_id,board_id)
  where state='active';
create index onboarding_browser_stages_expiry_idx
  on public.onboarding_browser_stages(expires_at,id) where state='active';

alter table public.onboarding_attestations
  drop constraint onboarding_attestations_member_id_board_id_terms_version_id_key,
  alter column consent_record_id drop not null,
  add column onboarding_browser_stage_id uuid unique
    references public.onboarding_browser_stages(id) on delete restrict,
  add constraint onboarding_attestations_current_versions_uq
    unique (member_id,board_id,terms_version_id,support_version_id),
  add constraint onboarding_attestations_one_ceremony_ck
    check (num_nonnulls(consent_record_id,onboarding_browser_stage_id)=1);

create function public.boardagent_guard_onboarding_browser_stage()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if tg_op='INSERT' then
    if new.state<>'active'
       or new.created_at is distinct from transaction_timestamp()
       or new.expires_at is distinct from new.created_at+interval '10 minutes'
       or new.completed_at is not null
       or new.attested_audit_event_id is not null then
      raise exception 'onboarding browser stage must start active for exactly ten minutes'
        using errcode='23514';
    end if;
    return new;
  end if;
  if row(
       new.id,new.organization_id,new.board_id,new.member_id,new.session_id,new.client_id,
       new.access_token_record_id,new.token_jti,new.terms_version_id,new.support_version_id,
       new.presentation_choice,new.local_memory_choice,new.request_sha256,
       new.stage_token_sha256,new.safe_response_sha256,new.idempotency_record_id,
       new.exact_origin,new.expires_at,new.created_audit_event_id,new.created_at
     ) is distinct from row(
       old.id,old.organization_id,old.board_id,old.member_id,old.session_id,old.client_id,
       old.access_token_record_id,old.token_jti,old.terms_version_id,old.support_version_id,
       old.presentation_choice,old.local_memory_choice,old.request_sha256,
       old.stage_token_sha256,old.safe_response_sha256,old.idempotency_record_id,
       old.exact_origin,old.expires_at,old.created_audit_event_id,old.created_at
     ) then
    raise exception 'onboarding browser stage binding is immutable' using errcode='55000';
  end if;
  if old.state<>'active' or new.state not in ('completed','expired') then
    raise exception 'illegal onboarding browser stage transition: % -> %',old.state,new.state
      using errcode='23514';
  end if;
  if (new.state='completed' and
      (new.completed_at is distinct from transaction_timestamp()
       or new.attested_audit_event_id is null))
     or (new.state='expired' and
         (old.expires_at>transaction_timestamp()
          or new.completed_at is not null or new.attested_audit_event_id is not null)) then
    raise exception 'onboarding browser stage terminal evidence is invalid' using errcode='23514';
  end if;
  return new;
end
$$;

create trigger boardagent_onboarding_browser_stage_guard
before insert or update on public.onboarding_browser_stages
for each row execute function public.boardagent_guard_onboarding_browser_stage();

alter table public.onboarding_browser_stages enable row level security;
alter table public.onboarding_browser_stages force row level security;

create policy boardagent_backup_read on public.onboarding_browser_stages
  for select to boardagent_backup using (true);
create policy boardagent_server_onboarding_stage_request
  on public.onboarding_browser_stages for all to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and member_id=public.boardagent_context_uuid('boardagent.member_id')
    and public.boardagent_context_board_allowed(board_id)
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and member_id=public.boardagent_context_uuid('boardagent.member_id')
    and public.boardagent_context_board_allowed(board_id)
  );
create policy boardagent_server_onboarding_stage_identity_read
  on public.onboarding_browser_stages for select to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );
create policy boardagent_server_onboarding_stage_identity_update
  on public.onboarding_browser_stages for update to boardagent_server
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and public.boardagent_context_board_allowed(board_id)
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and public.boardagent_context_board_allowed(board_id)
  );

grant select,insert on public.onboarding_browser_stages to boardagent_server;
grant update(state,attested_audit_event_id,completed_at)
  on public.onboarding_browser_stages to boardagent_server;
grant select on public.onboarding_browser_stages to boardagent_backup;
grant insert on public.onboarding_attestations to boardagent_server;

revoke all on function public.boardagent_guard_onboarding_browser_stage() from public;
