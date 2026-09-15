-- Pending-activation restart (docs/decisions/activation-restart-proposal-2026-09-13.md,
-- approved 13 September 2026). A person who registered a passkey but let the ten-minute
-- activation code expire or exhaust was stuck in pending_activation forever. This
-- private one-use handoff lets the company administrator or the current board secretary
-- (or, for the singleton first administrator, the local operator) restart activation:
-- the stale challenge ends revoked, a user-verified assertion with the ALREADY registered
-- passkey mints a fresh ten-minute code, and confirm_enrollment_activation proceeds
-- exactly as before. It never activates anyone, registers no passkey, creates no
-- invitation, and changes no role, seat or scope. Append-only history throughout.
create table public.activation_restart_grants (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  member_id uuid not null,
  issued_by uuid,
  issuer_kind text not null check (issuer_kind in ('member','operator')),
  proofing_method text not null check (proofing_method in ('in_person','verified_number_call')),
  token_sha256 bytea not null unique check (public.boardagent_hash_is_sha256(token_sha256)),
  stale_challenge_id uuid not null unique references public.enrollment_activation_challenges(id),
  created_at timestamptz(6) not null default transaction_timestamp(),
  expires_at timestamptz(6) not null,
  consumed_at timestamptz(6),
  fresh_challenge_id uuid unique references public.enrollment_activation_challenges(id),
  issued_audit_event_id uuid not null references public.audit_events(id),
  completed_audit_event_id uuid references public.audit_events(id),
  foreign key (organization_id,member_id) references public.members(organization_id,id),
  foreign key (organization_id,issued_by) references public.members(organization_id,id),
  check (member_id is distinct from issued_by),
  check ((issuer_kind='member' and issued_by is not null) or (issuer_kind='operator' and issued_by is null)),
  check (expires_at=created_at+interval '10 minutes'),
  check ((consumed_at is null and fresh_challenge_id is null and completed_audit_event_id is null)
    or (consumed_at is not null and fresh_challenge_id is not null and completed_audit_event_id is not null
      and consumed_at>=created_at and consumed_at<expires_at))
);
alter table public.activation_restart_grants enable row level security;
alter table public.activation_restart_grants force row level security;
grant select,insert,update on public.activation_restart_grants to boardagent_migrator;
grant select on public.activation_restart_grants to boardagent_backup;
create policy boardagent_activation_restart_grant_migrator on public.activation_restart_grants
  for all to boardagent_migrator
  using ((current_setting('boardagent.transaction_scope',true) in ('request','identity')
      and organization_id=public.boardagent_context_uuid('boardagent.organization_id'))
    or current_setting('boardagent.transaction_scope',true)='bootstrap')
  with check ((current_setting('boardagent.transaction_scope',true) in ('request','identity')
      and organization_id=public.boardagent_context_uuid('boardagent.organization_id'))
    or current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_activation_restart_grant_backup on public.activation_restart_grants
  for select to boardagent_backup using (current_setting('boardagent.transaction_scope',true)='backup');

-- The restart assertion is a WebAuthn authentication with no browser session, bound to
-- exactly one live handoff (the same shape SQL0096 gave recovery registration).
alter table public.webauthn_challenges add column activation_restart_grant_id uuid
  references public.activation_restart_grants(id);
alter table public.webauthn_challenges add constraint boardagent_activation_restart_challenge_kind
  check (activation_restart_grant_id is null
    or (purpose='activation_restart' and member_id is not null and session_id is null));
alter table public.webauthn_challenges drop constraint webauthn_challenges_purpose_check;
alter table public.webauthn_challenges add constraint webauthn_challenges_purpose_check
  check (purpose in ('enrollment','authentication','recent_auth','recovery','activation_restart'));

-- Row guard: a grant is born unconsumed by a confirmed issuer (request) or the operator
-- (bootstrap), is immutable in its authority columns, and is consumed exactly once by
-- the identity ceremony that minted the fresh code.
create function public.boardagent_guard_activation_restart_grant()
returns trigger language plpgsql security invoker set search_path=pg_catalog,public,pg_temp
as $$
declare
  scope text := current_setting('boardagent.transaction_scope',true);
begin
  if tg_op='INSERT' then
    if new.created_at is distinct from transaction_timestamp()
      or new.consumed_at is not null or new.fresh_challenge_id is not null
      or new.completed_audit_event_id is not null
      or not ((scope='request' and new.issuer_kind='member'
          and new.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
          and new.issued_by=public.boardagent_context_uuid('boardagent.member_id'))
        or (scope='bootstrap' and new.issuer_kind='operator' and new.issued_by is null)) then
      raise exception 'activation restart grant requires fresh confirmed issuance' using errcode='23514';
    end if;
  else
    if row(new.id,new.organization_id,new.member_id,new.issued_by,new.issuer_kind,new.proofing_method,
        new.token_sha256,new.stale_challenge_id,new.created_at,new.expires_at,new.issued_audit_event_id)
      is distinct from row(old.id,old.organization_id,old.member_id,old.issued_by,old.issuer_kind,old.proofing_method,
        old.token_sha256,old.stale_challenge_id,old.created_at,old.expires_at,old.issued_audit_event_id) then
      raise exception 'activation restart grant authority is immutable' using errcode='23514';
    end if;
    if old.consumed_at is not null then
      raise exception 'activation restart grant is single-use' using errcode='23514';
    end if;
    if scope is distinct from 'identity'
      or new.consumed_at is distinct from transaction_timestamp()
      or old.expires_at<=transaction_timestamp()
      or new.fresh_challenge_id is null or not public.boardagent_is_uuid_v7(new.fresh_challenge_id)
      or new.completed_audit_event_id is null then
      raise exception 'activation restart grant requires a verified live completion' using errcode='23514';
    end if;
  end if;
  return new;
end
$$;
revoke all on function public.boardagent_guard_activation_restart_grant() from public;
create trigger boardagent_activation_restart_grant_transition before insert or update
  on public.activation_restart_grants for each row
  execute function public.boardagent_guard_activation_restart_grant();

-- The issuer must hold the authority issue_enrollment requires for that member: the
-- company administrator, or the current secretary of a board where the member holds a
-- seat; always with secretariat:admin on the live token and current onboarding; never
-- the member themselves.
create function public.boardagent_activation_restart_issuer_authorized(candidate_member_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
as $$
  select current_setting('boardagent.transaction_scope',true)='request'
    and candidate_member_id is not null
    and public.boardagent_context_uuid('boardagent.member_id') is not null
    and candidate_member_id<>public.boardagent_context_uuid('boardagent.member_id')
    and exists(select 1 from public.boardagent_resolve_access_token(
        public.boardagent_context_uuid('boardagent.token_jti')) t
      where t.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
        and t.member_id=public.boardagent_context_uuid('boardagent.member_id')
        and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
        and 'secretariat:admin'=any(t.scope_set))
    and public.boardagent_administrative_member_eligible(public.boardagent_context_uuid('boardagent.member_id'))
    and (exists(select 1 from public.organization_role_assignments a
        where a.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
          and a.member_id=public.boardagent_context_uuid('boardagent.member_id') and a.role='admin'
          and a.active_from<=transaction_timestamp()
          and (a.active_until is null or a.active_until>transaction_timestamp()))
      or exists(select 1 from public.board_memberships secretary
        join public.board_memberships seat
          on seat.organization_id=secretary.organization_id and seat.board_id=secretary.board_id
        where secretary.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
          and secretary.member_id=public.boardagent_context_uuid('boardagent.member_id')
          and secretary.is_secretary and secretary.state='active'
          and secretary.active_from<=transaction_timestamp()
          and (secretary.active_until is null or secretary.active_until>transaction_timestamp())
          and seat.member_id=candidate_member_id and seat.state='active'
          and seat.active_from<=transaction_timestamp()
          and (seat.active_until is null or seat.active_until>transaction_timestamp())))
$$;
alter function public.boardagent_activation_restart_issuer_authorized(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_activation_restart_issuer_authorized(uuid) from public;

-- The member-side eligibility every path shares: one same-organization human in
-- pending_activation with an active registered passkey, whose LATEST activation
-- challenge is the named one and is expired or exhausted but never consumed, no live
-- code anywhere, one consumed invitation, and no live handoff. Locks invitation,
-- member, then challenges (the ordinary activation lock order). Returns null when
-- unavailable so callers choose between 'unavailable' and raising.
create function public.boardagent_activation_restart_candidate(
  candidate_organization_id uuid,candidate_member_id uuid,candidate_challenge_id uuid,candidate_proofing_method text
)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
  invitation public.enrollment_invitations%rowtype;
  target public.members%rowtype;
  stale public.enrollment_activation_challenges%rowtype;
  seats jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) not in ('request','bootstrap')
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or candidate_organization_id is null then
    raise exception 'activation restart requires a managed serializable transaction' using errcode='25000';
  end if;
  if candidate_member_id is null or candidate_challenge_id is null
    or candidate_proofing_method is null
    or candidate_proofing_method not in ('in_person','verified_number_call') then
    raise exception 'activation restart inputs are invalid' using errcode='22023';
  end if;
  select i.* into invitation from public.enrollment_invitations i
    where i.organization_id=candidate_organization_id and i.member_id=candidate_member_id
      and i.pending_activation_member_id=candidate_member_id
      and i.consumed_at is not null and i.revoked_at is null
    for update;
  if invitation.id is null or (select count(*) from public.enrollment_invitations i
      where i.organization_id=candidate_organization_id and i.member_id=candidate_member_id
        and i.pending_activation_member_id=candidate_member_id
        and i.consumed_at is not null and i.revoked_at is null)<>1 then
    return null;
  end if;
  select m.* into target from public.members m
    where m.organization_id=candidate_organization_id and m.id=candidate_member_id for update;
  if target.id is null or target.state<>'pending_activation' or target.member_kind<>'human' then
    return null;
  end if;
  perform 1 from public.enrollment_activation_challenges c
    where c.organization_id=candidate_organization_id and c.member_id=candidate_member_id
    order by c.issued_at,c.id for update;
  select c.* into stale from public.enrollment_activation_challenges c
    where c.organization_id=candidate_organization_id and c.member_id=candidate_member_id
    order by c.issued_at desc,c.id desc limit 1;
  if stale.id is null or stale.id<>candidate_challenge_id
    or stale.invitation_id<>invitation.id
    or stale.state not in ('issued','expired')
    or not (stale.state='expired' or stale.expires_at<=transaction_timestamp() or stale.attempt_count>=20)
    or stale.proofing_method<>candidate_proofing_method then
    return null;
  end if;
  if exists(select 1 from public.enrollment_activation_challenges c
      where c.organization_id=candidate_organization_id and c.member_id=candidate_member_id
        and (c.state='consumed'
          or (c.state='issued' and c.expires_at>transaction_timestamp() and c.attempt_count<20)))
    or not exists(select 1 from public.webauthn_credentials w
      where w.organization_id=candidate_organization_id and w.member_id=candidate_member_id and w.state='active')
    or exists(select 1 from public.activation_restart_grants g
      where g.organization_id=candidate_organization_id and g.member_id=candidate_member_id
        and g.consumed_at is null and g.expires_at>transaction_timestamp()) then
    return null;
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('board_id',b.id,'board_name',b.name,
      'seat_role',s.seat_role,'is_secretary',s.is_secretary,'voting_weight',s.voting_weight::text)
      order by b.id),'[]'::jsonb)
    into seats from public.board_memberships s
    join public.boards b on b.organization_id=s.organization_id and b.id=s.board_id
    where s.organization_id=candidate_organization_id and s.member_id=candidate_member_id and s.state='active'
      and s.active_from<=transaction_timestamp() and (s.active_until is null or s.active_until>transaction_timestamp());
  return jsonb_build_object(
    'member_id',target.id,'member_display_name',target.display_name,'member_state',target.state,
    'member_row_version',target.row_version::text,
    'stale_challenge_id',stale.id,'stale_challenge_state',stale.state,
    'stale_expires_at',to_char(stale.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'attempt_count',stale.attempt_count,'proofing_method',stale.proofing_method,
    'invitation_id',invitation.id,'seats',seats);
end
$$;
alter function public.boardagent_activation_restart_candidate(uuid,uuid,uuid,text) owner to boardagent_migrator;
revoke all on function public.boardagent_activation_restart_candidate(uuid,uuid,uuid,text) from public;

-- Exact canonical projection the confirmed stage must carry (compared as jsonb against
-- the stage bytes whose SHA-256 the consent record binds).
create function public.boardagent_activation_restart_payload(candidate_request jsonb,candidate jsonb)
returns jsonb language sql immutable security invoker set search_path=pg_catalog,public,pg_temp
as $$
  select jsonb_build_object(
    'schemaVersion','boardagent.activation-restart.v1',
    'request',candidate_request,
    'member',jsonb_build_object('memberId',candidate->>'member_id','memberDisplayName',candidate->>'member_display_name',
      'memberState',candidate->>'member_state','memberRowVersion',candidate->>'member_row_version'),
    'staleChallenge',jsonb_build_object('challengeId',candidate->>'stale_challenge_id','state',candidate->>'stale_challenge_state',
      'expiresAt',candidate->>'stale_expires_at','attemptCount',candidate->'attempt_count',
      'proofingMethod',candidate->>'proofing_method','invitationId',candidate->>'invitation_id'),
    'seats',(select coalesce(jsonb_agg(jsonb_build_object('boardId',seat->>'board_id','boardName',seat->>'board_name',
      'seatRole',seat->>'seat_role','isSecretary',seat->'is_secretary','votingWeight',seat->>'voting_weight')
      order by ordinality),'[]'::jsonb)
      from jsonb_array_elements(candidate->'seats') with ordinality as s(seat,ordinality)))
$$;
revoke all on function public.boardagent_activation_restart_payload(jsonb,jsonb) from public;

-- Read-only prepare half of the human-confirmed reissue_activation tool.
create function public.boardagent_prepare_activation_restart(
  candidate_member_id uuid,candidate_challenge_id uuid,candidate_proofing_method text
)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  candidate jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or org is null or public.boardagent_context_uuid('boardagent.member_id') is null
    or public.boardagent_context_uuid('boardagent.client_id') is null
    or public.boardagent_context_uuid('boardagent.token_jti') is null then
    raise exception 'activation restart requires a managed serializable request transaction' using errcode='25000';
  end if;
  if candidate_member_id is null or candidate_challenge_id is null
    or candidate_proofing_method not in ('in_person','verified_number_call') then
    raise exception 'activation restart inputs are invalid' using errcode='22023';
  end if;
  if not public.boardagent_activation_restart_issuer_authorized(candidate_member_id) then
    return jsonb_build_object('result_status','unavailable');
  end if;
  candidate := public.boardagent_activation_restart_candidate(org,candidate_member_id,candidate_challenge_id,candidate_proofing_method);
  if candidate is null then
    return jsonb_build_object('result_status','unavailable');
  end if;
  return jsonb_build_object('result_status','ready')||candidate;
end
$$;
alter function public.boardagent_prepare_activation_restart(uuid,uuid,text) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_activation_restart(uuid,uuid,text) from public;
grant execute on function public.boardagent_prepare_activation_restart(uuid,uuid,text) to boardagent_server;

-- Commit half: fresh exact consent, the pre-appended issuance audit, the stale challenge
-- revoked, one grant recorded. Only the token's SHA-256 ever reaches the database.
create function public.boardagent_issue_activation_restart(
  candidate_request jsonb,candidate_expected_payload_sha256 bytea,candidate_grant_id uuid,
  candidate_token_sha256 bytea,candidate_consent_record_id uuid,candidate_audit_event_id uuid
)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  target_member_id uuid;
  stale_challenge_id uuid;
  candidate jsonb;
  prepared jsonb;
  grant_expires_at timestamptz(6) := transaction_timestamp()+interval '10 minutes';
  grant_expires_text text := to_char((transaction_timestamp()+interval '10 minutes') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or org is null or actor is null
    or public.boardagent_context_uuid('boardagent.client_id') is null
    or public.boardagent_context_uuid('boardagent.token_jti') is null then
    raise exception 'activation restart requires a managed serializable request transaction' using errcode='25000';
  end if;
  if jsonb_typeof(candidate_request) is distinct from 'object'
    or (select array_agg(k order by k) from jsonb_object_keys(candidate_request) k)
      is distinct from array['challenge_id','idempotency_key','member_id','proofing_method','schema_version']
    or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
    or not coalesce(candidate_request->>'member_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',false)
    or not coalesce(candidate_request->>'challenge_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',false)
    or candidate_request->>'proofing_method' not in ('in_person','verified_number_call')
    or not coalesce(length(candidate_request->>'idempotency_key') between 16 and 200,false)
    or not coalesce(public.boardagent_hash_is_sha256(candidate_expected_payload_sha256),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_grant_id),false)
    or not coalesce(public.boardagent_hash_is_sha256(candidate_token_sha256),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_consent_record_id),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_audit_event_id),false) then
    raise exception 'activation restart request is malformed' using errcode='22023';
  end if;
  target_member_id := (candidate_request->>'member_id')::uuid;
  if target_member_id=actor then
    raise exception 'activation restart cannot be issued to oneself' using errcode='42501';
  end if;
  if not public.boardagent_activation_restart_issuer_authorized(target_member_id) then
    raise exception 'current activation restart issuer is unavailable' using errcode='42501';
  end if;
  candidate := public.boardagent_activation_restart_candidate(org,target_member_id,
    (candidate_request->>'challenge_id')::uuid,candidate_request->>'proofing_method');
  if candidate is null then
    raise exception 'activation restart target is unavailable' using errcode='42501';
  end if;
  stale_challenge_id := (candidate->>'stale_challenge_id')::uuid;
  prepared := public.boardagent_activation_restart_payload(candidate_request,candidate);
  if not exists(select 1 from public.consent_records c
      join public.action_stages s on s.id=c.stage_id and s.organization_id=c.organization_id
      where c.id=candidate_consent_record_id and c.organization_id=org
        and c.actor_member_id=actor and c.client_id=public.boardagent_context_uuid('boardagent.client_id')
        and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
        and c.action_code='reissue_activation' and c.target_type='member' and c.target_id=target_member_id
        and c.board_id is null and c.payload_sha256=candidate_expected_payload_sha256
        and c.confirmed_at=transaction_timestamp()
        and s.state='active' and s.action_code=c.action_code and s.target_type=c.target_type
        and s.target_id=c.target_id and s.payload_sha256=c.payload_sha256
        and s.canonical_schema='boardagent.activation-restart.v1'
        and pg_catalog.sha256(s.canonical_payload)=s.payload_sha256
        and convert_from(s.canonical_payload,'UTF8')::jsonb=prepared) then
    raise exception 'activation restart lacks its exact fresh consent' using errcode='42501';
  end if;
  if not exists(select 1 from public.audit_events a
      where a.id=candidate_audit_event_id and a.organization_id=org
        and a.event_type='activation_restart_issued'
        and a.actor_member_id=actor and a.client_id=public.boardagent_context_uuid('boardagent.client_id')
        and a.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
        and a.consent_record_id=candidate_consent_record_id
        and a.object_type='activation_restart_grant' and a.object_id=candidate_grant_id
        and a.board_id is null and a.occurred_at=transaction_timestamp()
        and (convert_from(a.canonical_payload,'UTF8')::jsonb)->>'origin'='mcp'
        and (convert_from(a.canonical_payload,'UTF8')::jsonb)->'details'=jsonb_build_object(
          'memberId',target_member_id,'staleChallengeId',stale_challenge_id,'grantId',candidate_grant_id,
          'proofingMethod',candidate_request->>'proofing_method','expiresAt',grant_expires_text)) then
    raise exception 'activation restart lacks its exact issuance audit' using errcode='42501';
  end if;
  -- issued -> revoked is the only legal move; an already expired challenge stays expired.
  update public.enrollment_activation_challenges set state='revoked'
    where id=stale_challenge_id and organization_id=org and state='issued';
  insert into public.activation_restart_grants(id,organization_id,member_id,issued_by,issuer_kind,
      proofing_method,token_sha256,stale_challenge_id,expires_at,issued_audit_event_id)
    values(candidate_grant_id,org,target_member_id,actor,'member',candidate_request->>'proofing_method',
      candidate_token_sha256,stale_challenge_id,grant_expires_at,candidate_audit_event_id);
  return jsonb_build_object('grantId',candidate_grant_id,'staleChallengeId',stale_challenge_id,
    'memberDisplayName',candidate->>'member_display_name','expiresAt',grant_expires_text);
end
$$;
alter function public.boardagent_issue_activation_restart(jsonb,bytea,uuid,bytea,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_issue_activation_restart(jsonb,bytea,uuid,bytea,uuid,uuid) from public;
grant execute on function public.boardagent_issue_activation_restart(jsonb,bytea,uuid,bytea,uuid,uuid) to boardagent_server;

-- Operator path: only the singleton first administrator, who has no issuer yet.
create function public.boardagent_issue_first_activation_restart(
  candidate_token_sha256 bytea,candidate_grant_id uuid,candidate_audit_event_id uuid,candidate_proofing_method text
)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
  org uuid;
  first_member public.members%rowtype;
  candidate jsonb;
  stale_challenge_id uuid;
  grant_expires_at timestamptz(6) := transaction_timestamp()+interval '10 minutes';
  grant_expires_text text := to_char((transaction_timestamp()+interval '10 minutes') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or current_user<>'boardagent_migrator' then
    raise exception 'first activation restart requires a managed serializable bootstrap transaction' using errcode='25000';
  end if;
  if not coalesce(public.boardagent_hash_is_sha256(candidate_token_sha256),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_grant_id),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_audit_event_id),false)
    or candidate_proofing_method not in ('in_person','verified_number_call') then
    raise exception 'first activation restart inputs are invalid' using errcode='22023';
  end if;
  select instance.organization_id into org from public.system_instance instance where instance.singleton_key;
  if org is null or (select count(*) from public.members m where m.organization_id=org)<>1 then
    raise exception 'first activation restart is unavailable' using errcode='42501';
  end if;
  select m.* into first_member from public.members m where m.organization_id=org for update;
  if first_member.state<>'pending_activation' or first_member.member_kind<>'human'
    or (select count(distinct a.role) from public.organization_role_assignments a
        where a.organization_id=org and a.member_id=first_member.id and a.role in ('admin','secretariat')
          and a.active_from<=transaction_timestamp()
          and (a.active_until is null or a.active_until>transaction_timestamp()))<>2 then
    raise exception 'first activation restart is unavailable' using errcode='42501';
  end if;
  select c.id into stale_challenge_id from public.enrollment_activation_challenges c
    where c.organization_id=org and c.member_id=first_member.id order by c.issued_at desc,c.id desc limit 1;
  candidate := public.boardagent_activation_restart_candidate(org,first_member.id,stale_challenge_id,candidate_proofing_method);
  if candidate is null then
    raise exception 'first activation restart is unavailable' using errcode='42501';
  end if;
  if not exists(select 1 from public.audit_events a
      where a.id=candidate_audit_event_id and a.organization_id=org
        and a.event_type='activation_restart_issued'
        and a.actor_member_id is null and a.client_id is null and a.token_jti is null
        and a.consent_record_id is null
        and a.object_type='activation_restart_grant' and a.object_id=candidate_grant_id
        and a.occurred_at=transaction_timestamp()
        and (convert_from(a.canonical_payload,'UTF8')::jsonb)->>'origin'='cli'
        and (convert_from(a.canonical_payload,'UTF8')::jsonb)->'details' @> jsonb_build_object(
          'bootstrap',true,'memberId',first_member.id,'staleChallengeId',stale_challenge_id,
          'grantId',candidate_grant_id,'proofingMethod',candidate_proofing_method,'expiresAt',grant_expires_text)) then
    raise exception 'first activation restart lacks its exact issuance audit' using errcode='42501';
  end if;
  update public.enrollment_activation_challenges set state='revoked'
    where id=stale_challenge_id and organization_id=org and state='issued';
  insert into public.activation_restart_grants(id,organization_id,member_id,issued_by,issuer_kind,
      proofing_method,token_sha256,stale_challenge_id,expires_at,issued_audit_event_id)
    values(candidate_grant_id,org,first_member.id,null,'operator',candidate_proofing_method,
      candidate_token_sha256,stale_challenge_id,grant_expires_at,candidate_audit_event_id);
  return jsonb_build_object('grantId',candidate_grant_id,'memberId',first_member.id,
    'staleChallengeId',stale_challenge_id,'memberDisplayName',first_member.display_name,
    'expiresAt',grant_expires_text);
end
$$;
alter function public.boardagent_issue_first_activation_restart(bytea,uuid,uuid,text) owner to boardagent_migrator;
revoke all on function public.boardagent_issue_first_activation_restart(bytea,uuid,uuid,text) from public;

-- Browser lookup: the handoff is visible only while live and the person is still pending.
create function public.boardagent_lookup_activation_restart(candidate_token_sha256 bytea)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  candidate jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity' or org is null
    or not coalesce(public.boardagent_hash_is_sha256(candidate_token_sha256),false) then
    raise exception 'activation restart requires a managed identity transaction' using errcode='42501';
  end if;
  select jsonb_build_object('grantId',g.id,'organizationId',g.organization_id,'memberId',m.id,
      'memberDisplayName',m.display_name,'organizationDisplayName',o.display_name,
      'proofingMethod',g.proofing_method,'staleChallengeId',g.stale_challenge_id,
      'expiresAt',to_char(g.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    into candidate from public.activation_restart_grants g
    join public.members m on m.organization_id=g.organization_id and m.id=g.member_id
    join public.organizations o on o.id=g.organization_id
    where g.organization_id=org and g.token_sha256=candidate_token_sha256
      and g.consumed_at is null and g.created_at<=transaction_timestamp() and g.expires_at>transaction_timestamp()
      and m.state='pending_activation' and m.member_kind='human'
      and exists(select 1 from public.webauthn_credentials w
        where w.organization_id=g.organization_id and w.member_id=g.member_id and w.state='active');
  return candidate;
end
$$;
alter function public.boardagent_lookup_activation_restart(bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_lookup_activation_restart(bytea) from public;
grant execute on function public.boardagent_lookup_activation_restart(bytea) to boardagent_server;

-- Completion, inside the store's authentication commit after the assertion challenge
-- was consumed: the fresh ten-minute code is a NEW linked challenge on the same
-- consumed invitation; the handoff is consumed exactly once. The raw code never
-- arrives here, only its SHA-256.
create function public.boardagent_complete_activation_restart(
  candidate_token_sha256 bytea,candidate_webauthn_challenge_id uuid,candidate_credential_id uuid,
  candidate_fresh_challenge_id uuid,candidate_activation_code_sha256 bytea,candidate_audit_event_id uuid
)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  candidate jsonb;
  grant_row public.activation_restart_grants%rowtype;
  consumed_invitation_id uuid;
  fresh_expires_at timestamptz(6) := transaction_timestamp()+interval '10 minutes';
  fresh_expires_text text := to_char((transaction_timestamp()+interval '10 minutes') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity' or org is null
    or current_setting('transaction_isolation') is distinct from 'serializable' then
    raise exception 'activation restart completion requires a managed serializable identity transaction' using errcode='42501';
  end if;
  if not coalesce(public.boardagent_hash_is_sha256(candidate_token_sha256),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_webauthn_challenge_id),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_credential_id),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_fresh_challenge_id),false)
    or not coalesce(public.boardagent_hash_is_sha256(candidate_activation_code_sha256),false)
    or not coalesce(public.boardagent_is_uuid_v7(candidate_audit_event_id),false) then
    raise exception 'activation restart completion inputs are invalid' using errcode='22023';
  end if;
  candidate := public.boardagent_lookup_activation_restart(candidate_token_sha256);
  if candidate is null then
    raise exception 'activation restart handoff is unavailable' using errcode='42501';
  end if;
  perform 1 from public.members m where m.organization_id=org and m.id=(candidate->>'memberId')::uuid for update;
  select g.* into grant_row from public.activation_restart_grants g
    where g.organization_id=org and g.id=(candidate->>'grantId')::uuid for update;
  if grant_row.id is null or grant_row.consumed_at is not null or grant_row.expires_at<=transaction_timestamp() then
    raise exception 'activation restart handoff is unavailable' using errcode='42501';
  end if;
  if not exists(select 1 from public.webauthn_challenges c
      where c.id=candidate_webauthn_challenge_id and c.organization_id=org
        and c.member_id=grant_row.member_id and c.session_id is null
        and c.purpose='activation_restart' and c.activation_restart_grant_id=grant_row.id
        and c.consumed_at=transaction_timestamp() and c.expires_at>transaction_timestamp()) then
    raise exception 'activation restart lacks its verified assertion challenge' using errcode='42501';
  end if;
  if not exists(select 1 from public.webauthn_credentials w
      where w.id=candidate_credential_id and w.organization_id=org
        and w.member_id=grant_row.member_id and w.state='active') then
    raise exception 'activation restart credential is not the member''s active passkey' using errcode='42501';
  end if;
  select i.id into consumed_invitation_id from public.enrollment_invitations i
    where i.organization_id=org and i.member_id=grant_row.member_id
      and i.pending_activation_member_id=grant_row.member_id
      and i.consumed_at is not null and i.revoked_at is null;
  if consumed_invitation_id is null
    or not exists(select 1 from public.enrollment_activation_challenges c
      where c.id=grant_row.stale_challenge_id and c.invitation_id=consumed_invitation_id
        and c.state in ('expired','revoked'))
    or exists(select 1 from public.enrollment_activation_challenges c
      where c.organization_id=org and c.member_id=grant_row.member_id
        and (c.state='consumed'
          or (c.state='issued' and c.expires_at>transaction_timestamp() and c.attempt_count<20))) then
    raise exception 'activation restart target is no longer eligible' using errcode='42501';
  end if;
  if not exists(select 1 from public.audit_events a
      where a.id=candidate_audit_event_id and a.organization_id=org
        and a.event_type='activation_restart_completed'
        and a.actor_member_id is null and a.client_id is null and a.token_jti is null
        and a.consent_record_id is null and a.board_id is null
        and a.object_type='activation_restart_grant' and a.object_id=grant_row.id
        and a.occurred_at=transaction_timestamp()
        and (convert_from(a.canonical_payload,'UTF8')::jsonb)->>'origin'='browser'
        and (convert_from(a.canonical_payload,'UTF8')::jsonb)->'details'=jsonb_build_object(
          'grantId',grant_row.id,'memberId',grant_row.member_id,'credentialId',candidate_credential_id,
          'staleChallengeId',grant_row.stale_challenge_id,'freshChallengeId',candidate_fresh_challenge_id,
          'proofingMethod',grant_row.proofing_method,'passkeyUserVerified',true,
          'expiresInSeconds',600,'expiresAt',fresh_expires_text)) then
    raise exception 'activation restart lacks its exact completion audit' using errcode='42501';
  end if;
  insert into public.enrollment_activation_challenges(id,organization_id,member_id,invitation_id,
      protected_code,proofing_method,state,expires_at)
    values(candidate_fresh_challenge_id,org,grant_row.member_id,consumed_invitation_id,
      candidate_activation_code_sha256,grant_row.proofing_method,'issued',fresh_expires_at);
  update public.activation_restart_grants set consumed_at=transaction_timestamp(),
      fresh_challenge_id=candidate_fresh_challenge_id,completed_audit_event_id=candidate_audit_event_id
    where id=grant_row.id;
  return jsonb_build_object('activationChallengeId',candidate_fresh_challenge_id,'memberId',grant_row.member_id,
    'invitationId',consumed_invitation_id,'expiresInSeconds',600,'expiresAt',fresh_expires_text);
end
$$;
alter function public.boardagent_complete_activation_restart(bytea,uuid,uuid,uuid,bytea,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_complete_activation_restart(bytea,uuid,uuid,uuid,bytea,uuid) from public;
grant execute on function public.boardagent_complete_activation_restart(bytea,uuid,uuid,uuid,bytea,uuid) to boardagent_server;

-- A restart audit claim cannot survive COMMIT without the grant it claims (the SQL0151
-- inverse-evidence pattern).
create function public.boardagent_guard_activation_restart_audit()
 returns trigger language plpgsql security definer set search_path=pg_catalog,public,pg_temp
as $$
begin
  if new.event_type='activation_restart_issued' then
    if not exists(select 1 from public.activation_restart_grants g
        where g.issued_audit_event_id=new.id and g.id=new.object_id
          and g.organization_id=new.organization_id and new.object_type='activation_restart_grant') then
      raise exception 'activation restart audit lacks its committed grant' using errcode='42501';
    end if;
  elsif new.event_type='activation_restart_completed' then
    if not exists(select 1 from public.activation_restart_grants g
        where g.completed_audit_event_id=new.id and g.id=new.object_id
          and g.organization_id=new.organization_id and new.object_type='activation_restart_grant') then
      raise exception 'activation restart audit lacks its committed completion' using errcode='42501';
    end if;
  end if;
  return new;
end
$$;
alter function public.boardagent_guard_activation_restart_audit() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_activation_restart_audit() from public;
create constraint trigger boardagent_activation_restart_audit_required
 after insert on public.audit_events deferrable initially deferred for each row
 when (new.event_type in ('activation_restart_issued','activation_restart_completed'))
 execute function public.boardagent_guard_activation_restart_audit();

-- Extend the closed event vocabulary by exactly the two pinned restart events, in
-- registry order.
alter table public.audit_events drop constraint audit_events_event_type_check;
alter table public.audit_events add constraint audit_events_event_type_check check (event_type in (
  'context_read',
  'client_registered',
  'client_registration_rejected',
  'oauth_client_blocked',
  'oauth_client_unblocked',
  'token_issued',
  'token_refreshed',
  'token_reuse_detected',
  'session_revoked',
  'enrollment_issued',
  'enrollment_redeemed',
  'enrollment_revoked',
  'member_activated',
  'identity_recovery_started',
  'external_identity_linked',
  'external_identity_unlinked',
  'member_changed',
  'onboarding_stage_created',
  'onboarding_attested',
  'onboarding_stale',
  'authorization_denied',
  'rate_limited',
  'resource_fetch',
  'notice_delivered',
  'document_version_created',
  'document_circulated',
  'document_access_changed',
  'document_archived',
  'document_soft_deleted',
  'recusal_changed',
  'management_submission_created',
  'management_revision_requested',
  'management_revision_replied',
  'management_submission_version_created',
  'management_submission_approved_to_draft',
  'management_submission_rejected',
  'management_question_asked',
  'management_question_answered',
  'management_question_followed_up',
  'secretariat_request_created',
  'secretariat_request_replied',
  'secretariat_request_closed',
  'board_created',
  'board_amended',
  'board_archived',
  'governance_profile_activated',
  'matter_evaluated',
  'ruleset_amended',
  'rule_overridden',
  'stage_created',
  'stage_replaced',
  'elicitation_sent',
  'consent_recorded',
  'consent_rejected',
  'ballot_cast',
  'ballot_superseded',
  'proxy_granted',
  'proxy_revoked',
  'resolution_amended',
  'vote_opened',
  'vote_source_update_pending',
  'vote_source_excluded',
  'vote_closing',
  'vote_closed',
  'vote_cancelled',
  'vote_superseded',
  'vote_replaced',
  'revote_required',
  'certificate_issued',
  'certificate_corrected',
  'meeting_called',
  'meeting_amended',
  'meeting_rsvp_recorded',
  'meeting_attendance_recorded',
  'meeting_attendance_corrected',
  'meeting_completed',
  'meeting_cancelled',
  'transcript_version_created',
  'transcript_secretary_verified',
  'transcript_qna_linked',
  'transcript_turn_challenged',
  'transcript_challenge_resolved',
  'minutes_version_created',
  'minutes_published',
  'minutes_commented',
  'minutes_review_withdrawn',
  'minutes_redline_proposed',
  'minutes_review_dispositioned',
  'minutes_package_corrected',
  'minutes_correction_cycle_created',
  'minutes_action_items_declared',
  'minutes_action_item_draft_superseded',
  'minutes_action_items_activated',
  'minutes_signature_package_issued',
  'minutes_signed',
  'minutes_signature_superseded',
  'minutes_resign_required',
  'minutes_finalized',
  'minutes_cancelled',
  'task_created',
  'task_started',
  'task_evidence_submitted',
  'task_evidence_reviewed',
  'task_completed',
  'task_correction_cycle_created',
  'task_cancelled',
  'proposal_submitted',
  'proposal_withdrawn',
  'proposal_approved_to_draft',
  'proposal_rejected',
  'draft_cancelled',
  'draft_expired',
  'export_requested',
  'export_started',
  'export_performed',
  'export_failed',
  'export_cancelled',
  'export_artifact_deleted',
  'webhook_configured',
  'webhook_secret_rotated',
  'webhook_disabled',
  'webhook_tested',
  'webhook_delivery_attempted',
  'audit_checkpoint_signed',
  'audit_verification_failed',
  'migration_applied',
  'backup_completed',
  'restore_verified',
  'company_admin_proposed',
  'company_admin_proposal_cancelled',
  'company_admin_proposal_declined',
  'company_admin_granted',
  'company_admin_revoked',
  'company_admin_transferred',
  'member_admin_delegation_granted',
  'member_admin_delegation_revoked',
  'key_lifecycle_changed',
  'secretary_support_published',
  'onboarding_terms_published',
  'activation_restart_issued',
  'activation_restart_completed'
));
