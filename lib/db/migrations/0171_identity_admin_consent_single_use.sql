-- MR-IDENTITY-001 (readiness finding frozen as a failing test in
-- tests/protocol/administrative-recovery.postgres.test.ts on 13 September 2026). A
-- completed human consent authorizes exactly one identity administration effect. The
-- protected helper only matched the consent's fields and never recorded that the consent
-- had been spent, so the same consent id could drive the helper again at the server-role
-- SQL boundary, with the original or with substituted arguments. Every identity
-- administration consent is now spent exactly once, in the same transaction as its single
-- effect. Additive: one append-only ledger and a re-creation of the helper that differs
-- from SQL0095 only by the guard; function ownership and grants are unchanged.
create table public.identity_admin_consent_uses (
  consent_record_id uuid primary key references public.consent_records(id),
  organization_id uuid not null,
  action_code text not null,
  used_at timestamptz(6) not null default transaction_timestamp()
);
alter table public.identity_admin_consent_uses enable row level security;
alter table public.identity_admin_consent_uses force row level security;
grant select,insert on public.identity_admin_consent_uses to boardagent_migrator;
grant select on public.identity_admin_consent_uses to boardagent_backup;
create policy boardagent_identity_admin_consent_use_migrator on public.identity_admin_consent_uses
  for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true) in ('request','identity')
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id'))
  with check (current_setting('boardagent.transaction_scope',true) in ('request','identity')
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id'));
create policy boardagent_identity_admin_consent_use_backup on public.identity_admin_consent_uses
  for select to boardagent_backup using (current_setting('boardagent.transaction_scope',true)='backup');

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
set search_path=pg_catalog,public,pg_temp
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
  -- One consent, one effect: spend the consent before any mutation. A repeat with the
  -- same consent id, whatever its arguments, stops here and changes nothing.
  insert into public.identity_admin_consent_uses(consent_record_id,organization_id,action_code)
  values (candidate_consent_record_id,context_organization,candidate_action)
  on conflict (consent_record_id) do nothing;
  if not found then
    raise exception 'identity administration consent was already used' using errcode='42501';
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
    update public.totp_credentials
       set state='disabled',failed_attempts=0,locked_until=null,
           terminal_at=transaction_timestamp()
     where organization_id=context_organization and member_id=target_member_id
       and state in ('pending_verification','active') and not (id=any(preserved_ids));
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
