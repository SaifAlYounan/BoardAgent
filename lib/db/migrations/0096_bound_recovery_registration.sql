-- Complete the existing verified-person recovery ceremony. This private grant
-- conveys only replacement-passkey registration for one existing OTHER human.
-- It cannot appoint a member, change a seat or promote an administrator.
create table public.recovery_registration_grants (
  recovery_request_id uuid primary key references public.identity_recovery_requests(id),
  organization_id uuid not null,
  member_id uuid not null,
  issued_by uuid not null,
  issuer_identity_generation bigint not null check (issuer_identity_generation>0),
  target_identity_generation bigint not null check (target_identity_generation>0),
  token_sha256 bytea not null unique check (public.boardagent_hash_is_sha256(token_sha256)),
  created_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  consumed_at timestamptz(6),
  credential_id uuid,
  pending_credential jsonb,
  activation_challenge_id uuid unique,
  activation_code_sha256 bytea,
  activation_expires_at timestamptz(6),
  attempt_count integer not null default 0 check (attempt_count between 0 and 20),
  activated_at timestamptz(6),
  activation_audit_id uuid references public.audit_events(id),
  audit_event_id uuid references public.audit_events(id),
  foreign key (organization_id,member_id) references public.members(organization_id,id),
  foreign key (organization_id,issued_by) references public.members(organization_id,id),
  unique(recovery_request_id,organization_id,member_id),
  check (member_id<>issued_by),
  check ((consumed_at is null and pending_credential is null and activation_challenge_id is null
      and activation_code_sha256 is null and activation_expires_at is null and attempt_count=0)
    or (consumed_at is not null and pending_credential is not null and activation_challenge_id is not null
      and public.boardagent_is_uuid_v7(activation_challenge_id) and activation_code_sha256 is not null
      and public.boardagent_hash_is_sha256(activation_code_sha256) and activation_expires_at is not null
      and activation_expires_at=consumed_at+interval '10 minutes')),
  check ((activated_at is null and activation_audit_id is null)
    or (activated_at is not null and activation_audit_id is not null and consumed_at is not null
      and activated_at>=consumed_at and activated_at<activation_expires_at and attempt_count<20)),
  check (expires_at=created_at+interval '10 minutes'),
  check ((consumed_at is null and credential_id is null and audit_event_id is null)
    or (consumed_at is not null and credential_id is not null and audit_event_id is not null
      and consumed_at>=created_at and consumed_at<expires_at))
);
alter table public.recovery_registration_grants enable row level security;
alter table public.recovery_registration_grants force row level security;
grant select,insert,update on public.recovery_registration_grants to boardagent_migrator;
grant select on public.recovery_registration_grants to boardagent_backup;
create policy boardagent_recovery_grant_migrator on public.recovery_registration_grants
  for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true) in ('request','identity')
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id'))
  with check (current_setting('boardagent.transaction_scope',true) in ('request','identity')
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id'));
create policy boardagent_recovery_grant_backup on public.recovery_registration_grants
  for select to boardagent_backup using (current_setting('boardagent.transaction_scope',true)='backup');
create policy boardagent_recovery_registration_identity on public.identity_recovery_requests
  for all to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id'))
  with check (current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id'));

alter table public.webauthn_challenges add column recovery_request_id uuid;
alter table public.webauthn_challenges add constraint boardagent_recovery_challenge_binding
  foreign key(recovery_request_id,organization_id,member_id)
  references public.recovery_registration_grants(recovery_request_id,organization_id,member_id);
alter table public.webauthn_challenges add constraint boardagent_recovery_challenge_kind
  check(recovery_request_id is null or (purpose='recovery' and member_id is not null and session_id is null));

create function public.boardagent_issue_recovery_registration(candidate_recovery uuid,candidate_token_sha256 bytea)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  recovery public.identity_recovery_requests%rowtype;
  issuer_generation bigint;
  target_generation bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or not coalesce(public.boardagent_hash_is_sha256(candidate_token_sha256),false) then
    raise exception 'recovery registration requires exact confirmed authority' using errcode='42501';
  end if;
  select r.* into recovery from public.identity_recovery_requests r
    join public.consent_records c on c.id=r.consent_record_id and c.organization_id=r.organization_id
    join public.action_stages s on s.id=c.stage_id and s.organization_id=c.organization_id
    where r.id=candidate_recovery and r.organization_id=org and r.requested_by=actor
      and r.created_at=transaction_timestamp() and r.state='initiated'
      and c.actor_member_id=actor and c.client_id=public.boardagent_context_uuid('boardagent.client_id')
      and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
      and c.action_code='initiate_identity_recovery' and c.target_id=r.member_id
      and c.confirmed_at=transaction_timestamp()
      and (convert_from(s.canonical_payload,'UTF8')::jsonb)->'replacementRegistration'=jsonb_build_object(
        'schemaVersion','boardagent.recovery-registration-policy.v1',
        'eligibility','other-active-human-with-in-person-or-verified-number-proof',
        'handoffExpiresInSeconds',600,'activationCodeExpiresInSeconds',600,
        'activation','fresh-original-issuer-confirmation-of-human-code-and-exact-credential',
        'changesRolesOrSeats',false)
      and exists(select 1 from public.audit_events a where a.organization_id=org
        and a.consent_record_id=c.id and a.event_type='identity_recovery_started')
    for update of r;
  if recovery.id is null then
    raise exception 'fresh recovery consent is unavailable' using errcode='42501';
  end if;
  -- Self-containment and other proof descriptions retain their existing behavior;
  -- neither silently becomes an emergency credential-issuance path.
  if recovery.member_id=actor or recovery.proofing_method not in ('in_person','verified_number_call') then
    return null;
  end if;
  if not exists(select 1 from public.boardagent_resolve_access_token(
    public.boardagent_context_uuid('boardagent.token_jti')) t where t.organization_id=org
      and t.member_id=actor and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
      and 'secretariat:admin'=any(t.scope_set))
    or not public.boardagent_administrative_member_eligible(actor)
    or not exists(select 1 from public.organization_role_assignments a where a.organization_id=org
      and a.member_id=actor and a.role in ('admin','secretariat')
      and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp())) then
    raise exception 'current recovery issuer is unavailable' using errcode='42501';
  end if;
  select m.identity_generation into issuer_generation from public.members m where m.organization_id=org and m.id=actor;
  select m.identity_generation into target_generation from public.members m where m.organization_id=org
    and m.id=recovery.member_id and m.member_kind='human' and m.state='active';
  if target_generation is distinct from recovery.prior_identity_generation+1 then return null; end if;
  insert into public.recovery_registration_grants(recovery_request_id,organization_id,member_id,
    issued_by,issuer_identity_generation,target_identity_generation,token_sha256,expires_at)
  values(recovery.id,org,recovery.member_id,actor,issuer_generation,target_generation,
    candidate_token_sha256,transaction_timestamp()+interval '10 minutes');
  return jsonb_build_object('expires_at',to_char((transaction_timestamp()+interval '10 minutes')
    at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
end
$$;

create function public.boardagent_recovery_issuer_eligible(candidate_member uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public
as $$
  select current_setting('boardagent.transaction_scope',true)='identity'
    and exists(select 1 from public.members m where m.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and m.id=candidate_member and m.state='active' and m.member_kind='human')
    and not exists(select 1 from public.board_memberships s where s.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and s.member_id=candidate_member and s.state='active' and s.active_from<=transaction_timestamp()
      and (s.active_until is null or s.active_until>transaction_timestamp()) and s.seat_role='observer')
    and not exists(select 1 from public.board_memberships s where s.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and s.member_id=candidate_member and s.state='active' and s.active_from<=transaction_timestamp()
      and (s.active_until is null or s.active_until>transaction_timestamp())
      and not exists(select 1 from public.onboarding_attestations a where a.organization_id=s.organization_id
        and a.member_id=s.member_id and a.board_id=s.board_id
        and a.terms_version_id=(select t.id from public.onboarding_terms_versions t
          where t.organization_id=s.organization_id and t.seat_role=s.seat_role and t.effective_at<=transaction_timestamp()
          order by t.effective_at desc,t.version desc,t.id desc limit 1)
        and a.support_version_id=(select v.id from public.secretary_support_versions v
          where v.organization_id=s.organization_id and (v.board_id=s.board_id or v.board_id is null)
          and v.effective_at<=transaction_timestamp()
          order by (v.board_id=s.board_id) desc,v.effective_at desc,v.version desc,v.id desc limit 1)))
$$;
alter function public.boardagent_recovery_issuer_eligible(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_recovery_issuer_eligible(uuid) from public;

create function public.boardagent_lookup_recovery_registration(candidate_token_sha256 bytea)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  candidate jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity' or org is null
    or not coalesce(public.boardagent_hash_is_sha256(candidate_token_sha256),false) then
    raise exception 'recovery registration requires a managed identity transaction' using errcode='42501';
  end if;
  select jsonb_build_object('recoveryRequestId',g.recovery_request_id,'memberId',m.id,
    'memberDisplayName',m.display_name,'organizationDisplayName',o.display_name,'proofingMethod',r.proofing_method)
    into candidate from public.recovery_registration_grants g
    join public.identity_recovery_requests r on r.id=g.recovery_request_id and r.organization_id=g.organization_id
    join public.members m on m.organization_id=g.organization_id and m.id=g.member_id
    join public.members issuer on issuer.organization_id=g.organization_id and issuer.id=g.issued_by
    join public.organizations o on o.id=g.organization_id
    where g.organization_id=org and g.token_sha256=candidate_token_sha256
      and g.consumed_at is null and g.created_at<=transaction_timestamp() and g.expires_at>transaction_timestamp() and r.state='initiated'
      and m.state='active' and m.member_kind='human' and m.identity_generation=g.target_identity_generation
      and issuer.identity_generation=g.issuer_identity_generation
      and public.boardagent_recovery_issuer_eligible(issuer.id)
      and exists(select 1 from public.organization_role_assignments a where a.organization_id=org
        and a.member_id=issuer.id and a.role in ('admin','secretariat') and a.active_from<=transaction_timestamp()
        and (a.active_until is null or a.active_until>transaction_timestamp()));
  return candidate;
end
$$;

create function public.boardagent_prepare_recovery_registration(
  candidate_token_sha256 bytea,candidate_challenge_id uuid,candidate_challenge_sha256 bytea
)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  candidate jsonb;
  grant_row public.recovery_registration_grants%rowtype;
begin
  if current_setting('transaction_isolation') is distinct from 'serializable' then
    raise exception 'recovery registration requires serializable authority' using errcode='42501';
  end if;
  candidate := public.boardagent_lookup_recovery_registration(candidate_token_sha256);
  if candidate is null then return null; end if;
  select * into grant_row from public.recovery_registration_grants g
    where g.organization_id=org and g.recovery_request_id=(candidate->>'recoveryRequestId')::uuid;
  perform 1 from public.members m where m.organization_id=org
    and m.id=any(array[grant_row.member_id,grant_row.issued_by]) order by m.id for update;
  perform 1 from public.recovery_registration_grants g where g.recovery_request_id=grant_row.recovery_request_id for update;
  perform 1 from public.webauthn_challenges c where c.organization_id=org
    and c.id=candidate_challenge_id and c.member_id=grant_row.member_id and c.session_id is null
    and c.purpose='recovery' and c.recovery_request_id=grant_row.recovery_request_id and c.challenge_sha256=candidate_challenge_sha256
    and c.expires_at>transaction_timestamp() and c.consumed_at is null for update;
  if not found then return null; end if;
  return public.boardagent_lookup_recovery_registration(candidate_token_sha256);
end
$$;
alter function public.boardagent_prepare_recovery_registration(bytea,uuid,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_recovery_registration(bytea,uuid,bytea) from public;
grant execute on function public.boardagent_prepare_recovery_registration(bytea,uuid,bytea) to boardagent_server;

create function public.boardagent_complete_recovery_registration(
  candidate_token_sha256 bytea,candidate_challenge_id uuid,candidate_challenge_sha256 bytea,
  candidate_credential jsonb,candidate_audit_id uuid,
  candidate_activation_id uuid,candidate_activation_code_sha256 bytea
)
returns boolean language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  candidate jsonb;
  grant_row public.recovery_registration_grants%rowtype;
  replacement_credential_id uuid;
  raw_id bytea;
  key_bytes bytea;
begin
  if current_setting('transaction_isolation') is distinct from 'serializable' then
    raise exception 'recovery registration requires serializable authority' using errcode='42501';
  end if;
  candidate := public.boardagent_prepare_recovery_registration(candidate_token_sha256,candidate_challenge_id,candidate_challenge_sha256);
  if candidate is null then return false; end if;
  select * into grant_row from public.recovery_registration_grants g
    where g.organization_id=org and g.recovery_request_id=(candidate->>'recoveryRequestId')::uuid for update;
  if grant_row.consumed_at is not null then return false; end if;
  perform 1 from public.webauthn_challenges c where c.organization_id=org
    and c.id=candidate_challenge_id and c.member_id=grant_row.member_id and c.session_id is null
    and c.purpose='recovery' and c.recovery_request_id=grant_row.recovery_request_id and c.challenge_sha256=candidate_challenge_sha256
    and c.expires_at>transaction_timestamp() and c.consumed_at is null for update;
  if not found then return false; end if;
  if jsonb_typeof(candidate_credential) is distinct from 'object'
    or (select array_agg(k order by k) from jsonb_object_keys(candidate_credential) k)
      is distinct from array['backupEligible','backupState','counter','id','memberId','publicKey','rawId','transports']
    or not coalesce(candidate_credential->>'rawId' ~ '^[0-9a-f]+$',false)
    or not coalesce(candidate_credential->>'publicKey' ~ '^[0-9a-f]+$',false)
    or jsonb_typeof(candidate_credential->'counter') is distinct from 'number'
    or not coalesce(candidate_credential->>'counter' ~ '^[0-9]{1,10}$',false)
    or (candidate_credential->>'counter')::bigint>4294967295
    or jsonb_typeof(candidate_credential->'backupEligible') is distinct from 'boolean'
    or jsonb_typeof(candidate_credential->'backupState') is distinct from 'boolean'
    or (candidate_credential->>'backupEligible'='false' and candidate_credential->>'backupState'='true')
    or jsonb_typeof(candidate_credential->'transports') is distinct from 'array' then
    raise exception 'replacement credential is malformed' using errcode='22023';
  end if;
  if jsonb_array_length(candidate_credential->'transports')>7
    or exists(select 1 from jsonb_array_elements_text(candidate_credential->'transports') t(value)
      where value is null or value not in ('ble','cable','hybrid','internal','nfc','smart-card','usb')) then
    raise exception 'replacement transports are invalid' using errcode='22023';
  end if;
  replacement_credential_id := (candidate_credential->>'id')::uuid;
  raw_id := decode(candidate_credential->>'rawId','hex');
  key_bytes := decode(candidate_credential->>'publicKey','hex');
  if not coalesce(public.boardagent_is_uuid_v7(replacement_credential_id),false)
    or octet_length(raw_id) not between 16 and 1024 or octet_length(key_bytes) not between 32 and 4096
    or (candidate_credential->>'memberId')::uuid is distinct from grant_row.member_id
    or not exists(select 1 from public.audit_events a where a.id=candidate_audit_id
      and a.organization_id=org and a.event_type='enrollment_redeemed'
      and a.object_id=grant_row.recovery_request_id and a.object_type='identity_recovery'
      and a.occurred_at=transaction_timestamp()
      and a.actor_member_id is null and a.client_id is null and a.token_jti is null and a.board_id is null
      and (convert_from(a.canonical_payload,'UTF8')::jsonb)->>'origin'='browser'
      and (convert_from(a.canonical_payload,'UTF8')::jsonb)->'details'=jsonb_build_object(
        'recoveryRequestId',grant_row.recovery_request_id,'memberId',grant_row.member_id,
        'credentialId',replacement_credential_id,'publicKeySha256',encode(sha256(key_bytes),'hex'),
        'passkeyUserVerified',true,'activationChallengeId',candidate_activation_id,
        'activationCodeSha256',encode(candidate_activation_code_sha256,'hex'),'state','pending_activation')) then
    raise exception 'replacement credential lacks its exact verified audit' using errcode='42501';
  end if;
  -- Registration records a candidate only. No credential can authenticate until
  -- the issuer freshly confirms the code supplied by the verified human.
  if not coalesce(public.boardagent_is_uuid_v7(candidate_activation_id),false)
    or not coalesce(public.boardagent_hash_is_sha256(candidate_activation_code_sha256),false) then
    raise exception 'replacement activation binding is invalid' using errcode='22023';
  end if;
  update public.webauthn_challenges set consumed_at=transaction_timestamp() where id=candidate_challenge_id;
  update public.recovery_registration_grants set consumed_at=transaction_timestamp(),
    credential_id=replacement_credential_id,audit_event_id=candidate_audit_id,
    pending_credential=candidate_credential,activation_challenge_id=candidate_activation_id,
    activation_code_sha256=candidate_activation_code_sha256,
    activation_expires_at=transaction_timestamp()+interval '10 minutes'
    where recovery_request_id=grant_row.recovery_request_id;
  return true;
end
$$;

alter function public.boardagent_issue_recovery_registration(uuid,bytea) owner to boardagent_migrator;
alter function public.boardagent_lookup_recovery_registration(bytea) owner to boardagent_migrator;
alter function public.boardagent_complete_recovery_registration(bytea,uuid,bytea,jsonb,uuid,uuid,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_issue_recovery_registration(uuid,bytea) from public;
revoke all on function public.boardagent_lookup_recovery_registration(bytea) from public;
revoke all on function public.boardagent_complete_recovery_registration(bytea,uuid,bytea,jsonb,uuid,uuid,bytea) from public;
grant execute on function public.boardagent_issue_recovery_registration(uuid,bytea),
  public.boardagent_lookup_recovery_registration(bytea),
  public.boardagent_complete_recovery_registration(bytea,uuid,bytea,jsonb,uuid,uuid,bytea) to boardagent_server;


create function public.boardagent_guard_recovery_registration_grant()
returns trigger language plpgsql security invoker set search_path=pg_catalog,public
as $$
begin
  if tg_op='INSERT' then
    if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
      or new.created_at is distinct from transaction_timestamp() or new.consumed_at is not null
      or new.credential_id is not null or new.audit_event_id is not null
      or new.pending_credential is not null or new.activation_challenge_id is not null
      or new.activation_code_sha256 is not null or new.activation_expires_at is not null
      or new.attempt_count<>0 or new.activated_at is not null or new.activation_audit_id is not null then
      raise exception 'replacement grant requires fresh confirmed issuance' using errcode='23514';
    end if;
  else
    if row(new.recovery_request_id,new.organization_id,new.member_id,new.issued_by,
      new.issuer_identity_generation,new.target_identity_generation,new.token_sha256,new.created_at,new.expires_at)
      is distinct from row(old.recovery_request_id,old.organization_id,old.member_id,old.issued_by,
      old.issuer_identity_generation,old.target_identity_generation,old.token_sha256,old.created_at,old.expires_at) then
      raise exception 'replacement grant authority is immutable' using errcode='23514';
    end if;
    if old.consumed_at is null then
      if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
        or new.consumed_at is distinct from transaction_timestamp() or new.credential_id is null
        or new.audit_event_id is null or new.pending_credential is null
        or new.activation_challenge_id is null or new.activation_code_sha256 is null
        or not public.boardagent_hash_is_sha256(new.activation_code_sha256)
        or new.activation_expires_at is distinct from transaction_timestamp()+interval '10 minutes'
        or new.attempt_count<>0 or new.activated_at is not null or new.activation_audit_id is not null then
        raise exception 'replacement candidate requires verified registration' using errcode='23514';
      end if;
    else
      if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
        or row(new.consumed_at,new.credential_id,new.audit_event_id,new.pending_credential,
          new.activation_challenge_id,new.activation_code_sha256,new.activation_expires_at)
        is distinct from row(old.consumed_at,old.credential_id,old.audit_event_id,old.pending_credential,
          old.activation_challenge_id,old.activation_code_sha256,old.activation_expires_at)
        or old.activated_at is not null or old.attempt_count>=20 or old.activation_expires_at<=transaction_timestamp()
        or not coalesce(((new.activated_at=transaction_timestamp() and new.activation_audit_id is not null and new.attempt_count=old.attempt_count)
          or (new.activated_at is null and new.activation_audit_id is null and new.attempt_count=old.attempt_count+1)),false) then
        raise exception 'replacement activation is immutable and single-use' using errcode='23514';
      end if;
    end if;
  end if;
  return new;
end
$$;
revoke all on function public.boardagent_guard_recovery_registration_grant() from public;
create trigger boardagent_recovery_registration_grant_transition before insert or update
  on public.recovery_registration_grants for each row execute function public.boardagent_guard_recovery_registration_grant();

-- The existing confirm_enrollment_activation H ceremony also completes a recovery
-- candidate. Its UUID invitation field identifies the recovery request; it never
-- changes the member, their seats, role grants or onboarding records.
create function public.boardagent_prepare_recovery_activation(candidate_request jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  g public.recovery_registration_grants%rowtype;
  target public.members%rowtype;
  recovery public.identity_recovery_requests%rowtype;
  seats jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable' or org is null or actor is null then
    raise exception 'recovery activation requires managed request authority' using errcode='42501';
  end if;
  select * into g from public.recovery_registration_grants where organization_id=org
    and recovery_request_id=(candidate_request->>'invitation_id')::uuid;
  if g.recovery_request_id is null then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(org::text,424286));
  perform 1 from public.members m where m.organization_id=org
    and m.id=any(array[g.member_id,g.issued_by]) order by m.id for update;
  select * into g from public.recovery_registration_grants where recovery_request_id=g.recovery_request_id for update;
  select * into target from public.members where organization_id=org and id=g.member_id;
  select * into recovery from public.identity_recovery_requests where organization_id=org and id=g.recovery_request_id;
  if g.issued_by is distinct from actor or g.member_id is distinct from (candidate_request->>'member_id')::uuid
    or g.activation_challenge_id is distinct from (candidate_request->>'challenge_id')::uuid
    or recovery.proofing_method is distinct from candidate_request->>'proofing_method'
    or recovery.state is distinct from 'initiated' or g.consumed_at is null or g.consumed_at>transaction_timestamp()
    or g.activation_expires_at<=transaction_timestamp() or g.activated_at is not null or g.attempt_count>=20
    or target.state is distinct from 'active' or target.member_kind is distinct from 'human'
    or target.identity_generation is distinct from g.target_identity_generation
    or not public.boardagent_administrative_member_eligible(actor)
    or not exists(select 1 from public.members where organization_id=org and id=actor and identity_generation=g.issuer_identity_generation)
    or not exists(select 1 from public.organization_role_assignments where organization_id=org and member_id=actor
      and role in ('admin','secretariat') and active_from<=transaction_timestamp()
      and (active_until is null or active_until>transaction_timestamp()))
    or not exists(select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
      where t.organization_id=org and t.member_id=actor
      and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id') and 'secretariat:admin'=any(t.scope_set)) then
    return null;
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('boardId',b.id,'boardName',b.name,
    'seatRole',s.seat_role,'isSecretary',s.is_secretary,'votingWeight',s.voting_weight::text,
    'entitlementGeneration',s.entitlement_generation::text) order by b.id),'[]'::jsonb)
    into seats from public.board_memberships s join public.boards b on b.id=s.board_id and b.organization_id=s.organization_id
    where s.organization_id=org and s.member_id=g.member_id and s.state='active'
      and s.active_from<=transaction_timestamp() and (s.active_until is null or s.active_until>transaction_timestamp());
  return jsonb_build_object('schemaVersion','boardagent.enrollment-activation.v1',
    'request',candidate_request,
    'member',jsonb_build_object('memberId',target.id,'memberDisplayName',target.display_name,
      'memberState',target.state,'memberRowVersion',target.row_version::text),
    'challenge',jsonb_build_object('invitationId',g.recovery_request_id,'challengeId',g.activation_challenge_id,
      'expiresAt',to_char(g.activation_expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'proofingMethod',recovery.proofing_method),
    'seats',seats,'recovery',jsonb_build_object('credentialId',g.credential_id,
      'credentialSha256',encode(sha256(convert_to(g.pending_credential::text,'UTF8')),'hex')));
end
$$;

create function public.boardagent_plan_recovery_activation(candidate_request jsonb,candidate_payload_sha256 bytea,candidate_consent_id uuid)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  prepared jsonb;
  g public.recovery_registration_grants%rowtype;
  matched boolean;
begin
  if not coalesce(public.boardagent_hash_is_sha256(candidate_payload_sha256),false)
    or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
    or not coalesce(candidate_request->>'confirmation_code_sha256' ~ '^[0-9a-f]{64}$',false)
    or not coalesce(length(candidate_request->>'idempotency_key') between 16 and 200,false)
    or (select array_agg(k order by k) from jsonb_object_keys(candidate_request) k)
      is distinct from array['challenge_id','confirmation_code_sha256','idempotency_key','invitation_id','member_id','proofing_method','schema_version'] then
    raise exception 'recovery activation request is malformed' using errcode='22023';
  end if;
  prepared := public.boardagent_prepare_recovery_activation(candidate_request);
  if prepared is null then return null; end if;
  if not exists(select 1 from public.consent_records c join public.action_stages s on s.id=c.stage_id and s.organization_id=c.organization_id
    where c.id=candidate_consent_id and c.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and c.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
      and c.client_id=public.boardagent_context_uuid('boardagent.client_id') and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
      and c.action_code='confirm_enrollment_activation' and c.target_type='member'
      and c.target_id=(candidate_request->>'member_id')::uuid and c.payload_sha256=candidate_payload_sha256
      and c.confirmed_at=transaction_timestamp() and s.state='active'
      and s.action_code=c.action_code and s.target_type=c.target_type and s.target_id=c.target_id
      and s.payload_sha256=c.payload_sha256 and convert_from(s.canonical_payload,'UTF8')::jsonb=prepared) then
    raise exception 'recovery activation lacks its exact fresh consent' using errcode='42501';
  end if;
  select * into strict g from public.recovery_registration_grants where recovery_request_id=(candidate_request->>'invitation_id')::uuid;
  matched := public.boardagent_constant_time_sha256_equal(g.activation_code_sha256,decode(candidate_request->>'confirmation_code_sha256','hex'));
  return jsonb_build_object('outcome',case when matched then 'activated' else 'code_mismatch' end,
    'challengeState',case when matched then 'consumed' when g.attempt_count+1>=20 then 'revoked' else 'issued' end,
    'attemptCount',g.attempt_count+case when matched then 0 else 1 end,
    'memberRowVersion',case when matched then prepared->'member'->>'memberRowVersion' else null end);
end
$$;

create function public.boardagent_finalize_recovery_activation(
  candidate_request jsonb,candidate_payload_sha256 bytea,candidate_consent_id uuid,candidate_audit_id uuid,
  candidate_idempotency_id uuid,candidate_request_sha256 bytea,candidate_safe_response_sha256 bytea
)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  ctx_client_id uuid := public.boardagent_context_uuid('boardagent.client_id');
  planned jsonb;
  g public.recovery_registration_grants%rowtype;
  credential jsonb;
  expected_details jsonb;
  audit public.audit_events%rowtype;
  audit_payload jsonb;
  inserted uuid;
begin
  planned := public.boardagent_plan_recovery_activation(candidate_request,candidate_payload_sha256,candidate_consent_id);
  if planned is null then return null; end if;
  if not coalesce(public.boardagent_hash_is_sha256(candidate_request_sha256),false)
    or not coalesce(public.boardagent_hash_is_sha256(candidate_safe_response_sha256),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_idempotency_id),false) then
    raise exception 'recovery activation result binding is invalid' using errcode='22023';
  end if;
  select * into strict g from public.recovery_registration_grants where recovery_request_id=(candidate_request->>'invitation_id')::uuid;
  credential := g.pending_credential;
  expected_details := jsonb_build_object('recoveryRequestId',g.recovery_request_id,'memberId',g.member_id,
    'credentialId',g.credential_id,'challengeId',g.activation_challenge_id,
    'proofingMethod',candidate_request->>'proofing_method','outcome',planned->>'outcome',
    'attemptCount',(planned->>'attemptCount')::integer);
  select * into audit from public.audit_events a where a.id=candidate_audit_id and a.organization_id=org
    and a.consent_record_id=candidate_consent_id and a.actor_member_id=actor and a.client_id=ctx_client_id
    and a.token_jti=public.boardagent_context_uuid('boardagent.token_jti') and a.board_id is null
    and a.object_id=g.recovery_request_id and a.object_type='identity_recovery'
    and a.occurred_at=transaction_timestamp()
    and a.event_type=case when planned->>'outcome'='activated' then 'enrollment_redeemed' else 'authorization_denied' end;
  audit_payload := convert_from(audit.canonical_payload,'UTF8')::jsonb;
  if audit.id is null or audit_payload->'details' is distinct from expected_details
    or audit_payload->>'origin' is distinct from 'mcp' then
    raise exception 'recovery activation lacks exact audit evidence' using errcode='42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(actor::text||chr(1)||ctx_client_id::text||chr(1)||
    (candidate_request->>'idempotency_key'),424256));
  insert into public.idempotency_records(id,organization_id,actor_member_id,client_id,operation,idempotency_key,request_sha256,state,expires_at)
    values(candidate_idempotency_id,org,actor,ctx_client_id,'confirm_enrollment_activation',candidate_request->>'idempotency_key',
      candidate_request_sha256,'in_progress',transaction_timestamp()+interval '24 hours')
    on conflict(actor_member_id,client_id,operation,idempotency_key) do nothing returning id into inserted;
  if inserted is null then raise exception 'recovery activation idempotency key was used' using errcode='42501'; end if;
  if planned->>'outcome'='activated' then
    insert into public.webauthn_credentials(id,organization_id,member_id,credential_id,public_key,
      signature_counter,transports,backup_eligible,backup_state,state)
    values(g.credential_id,org,g.member_id,decode(credential->>'rawId','hex'),decode(credential->>'publicKey','hex'),
      (credential->>'counter')::bigint,array(select jsonb_array_elements_text(credential->'transports')),
      (credential->>'backupEligible')::boolean,(credential->>'backupState')::boolean,'active');
    update public.recovery_registration_grants set activated_at=transaction_timestamp(),activation_audit_id=candidate_audit_id
      where recovery_request_id=g.recovery_request_id;
    update public.identity_recovery_requests set state='completed',completed_at=transaction_timestamp() where id=g.recovery_request_id;
  else
    update public.recovery_registration_grants set attempt_count=(planned->>'attemptCount')::integer where recovery_request_id=g.recovery_request_id;
  end if;
  update public.idempotency_records set state='succeeded',safe_response_sha256=candidate_safe_response_sha256,
    safe_response_type=case when planned->>'outcome'='activated' then 'member' else 'enrollment_activation' end,
    safe_response_id=case when planned->>'outcome'='activated' then g.member_id else g.activation_challenge_id end,
    completed_at=transaction_timestamp() where id=candidate_idempotency_id;
  return planned||jsonb_build_object('safeResponseSha256',encode(candidate_safe_response_sha256,'hex'));
end
$$;

create policy boardagent_recovery_activation_request_credential on public.webauthn_credentials
  for insert to boardagent_migrator with check(current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id'));
alter function public.boardagent_prepare_recovery_activation(jsonb) owner to boardagent_migrator;
alter function public.boardagent_plan_recovery_activation(jsonb,bytea,uuid) owner to boardagent_migrator;
alter function public.boardagent_finalize_recovery_activation(jsonb,bytea,uuid,uuid,uuid,bytea,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_recovery_activation(jsonb) from public;
revoke all on function public.boardagent_plan_recovery_activation(jsonb,bytea,uuid) from public;
revoke all on function public.boardagent_finalize_recovery_activation(jsonb,bytea,uuid,uuid,uuid,bytea,bytea) from public;
grant execute on function public.boardagent_prepare_recovery_activation(jsonb),public.boardagent_plan_recovery_activation(jsonb,bytea,uuid),
  public.boardagent_finalize_recovery_activation(jsonb,bytea,uuid,uuid,uuid,bytea,bytea) to boardagent_server;

-- Remove the older unbound credential insertion path. Authentication retains only
-- its existing counter/backup/last-used column updates.
revoke insert on public.webauthn_credentials from boardagent_server;
