-- Independent recusal causes share the existing effective vote-exclusion projection.
-- Historical rows and decision packages retain their original bytes.
alter table public.vote_exclusions
  add column cause_requested_state text check(cause_requested_state in ('excluded','lifted')),
  add column source_board_exclusion_id uuid;
alter table public.board_exclusions add unique(id,organization_id,board_id,member_id,consent_record_id);
alter table public.vote_exclusions add constraint vote_exclusions_board_cause_fk
  foreign key(source_board_exclusion_id,organization_id,board_id,member_id,consent_record_id)
  references public.board_exclusions(id,organization_id,board_id,member_id,consent_record_id)
  deferrable initially deferred;
create index vote_exclusions_manual_cause_idx on public.vote_exclusions(vote_id,member_id,version desc)
  where source_board_exclusion_id is null;

create or replace function public.boardagent_prepare_board_recusal(candidate_request jsonb)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare
  org uuid:=public.boardagent_context_uuid('boardagent.organization_id');
  b uuid; m uuid; board_version bigint; member_name text;
  prior public.board_exclusions%rowtype; affected_votes jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or jsonb_typeof(candidate_request) is distinct from 'object'
    or not candidate_request ?& array['boardId','memberId','operation','reason','idempotencyKey']
    or exists(select 1 from jsonb_object_keys(candidate_request) k where k not in ('boardId','memberId','operation','reason','idempotencyKey'))
    or candidate_request->>'operation' not in ('add','lift')
    or length(candidate_request->>'reason') not between 1 and 65536
    or length(candidate_request->>'idempotencyKey') not between 16 and 256 then
    raise exception 'board recusal is unavailable' using errcode='42501';
  end if;
  b:=(candidate_request->>'boardId')::uuid; m:=(candidate_request->>'memberId')::uuid;
  if not public.boardagent_secretariat_for_board(b) then
    raise exception 'board recusal is unavailable' using errcode='42501';
  end if;
  select row_version into board_version from public.boards
    where id=b and organization_id=org and state='active' for update;
  select member.display_name into member_name
    from public.members member join public.board_memberships membership
      on membership.organization_id=member.organization_id and membership.member_id=member.id
    where member.organization_id=org and member.id=m and member.state='active'
      and membership.board_id=b and membership.state='active'
      and membership.active_from<=transaction_timestamp()
      and (membership.active_until is null or membership.active_until>transaction_timestamp())
    for update of membership,member;
  if board_version is null or member_name is null then
    raise exception 'board recusal is unavailable' using errcode='42501';
  end if;
  -- Feed state triggers allocate positions; take that per-person lock before the audit head.
  perform 1 from public.member_feed_sync_counters where organization_id=org and member_id=m for update;
  select * into prior from public.board_exclusions
    where organization_id=org and board_id=b and member_id=m order by version desc limit 1;
  if (candidate_request->>'operation'='add' and prior.state='excluded')
    or (candidate_request->>'operation'='lift' and prior.state is distinct from 'excluded') then
    raise exception 'board recusal transition is unavailable' using errcode='42501';
  end if;
  -- Close freezes its outcome before entering closing. Only still-open votes change.
  -- Lock every candidate in deterministic order before producing the exact consent manifest.
  perform 1 from public.votes v join public.vote_electorate e on e.vote_id=v.id and e.member_id=m
    where v.organization_id=org and v.board_id=b and v.state in ('open','source_update_pending')
    order by v.id for update of v;
  select coalesce(jsonb_agg(jsonb_build_object('voteId',v.id,
      'packageSha256',encode(p.package_sha256,'hex')) order by v.id),'[]'::jsonb)
    into affected_votes from public.votes v
    join public.vote_electorate e on e.vote_id=v.id and e.member_id=m
    join public.decision_packages p on p.id=v.current_decision_package_id and p.vote_id=v.id
    where v.organization_id=org and v.board_id=b and v.state in ('open','source_update_pending');
  return jsonb_build_object('schemaVersion','boardagent.board-recusal-consent.v1',
    'request',candidate_request,'boardVersion',board_version::text,'memberDisplayName',member_name,
    'priorExclusionId',prior.id,'priorVersion',coalesce(prior.version,0),'affectedVotes',affected_votes);
end
$$;
alter function public.boardagent_prepare_board_recusal(jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_board_recusal(jsonb) from public;
grant execute on function public.boardagent_prepare_board_recusal(jsonb) to boardagent_server;


-- This returns evidence only for the current confirmed actor and transaction.
create function public.boardagent_confirmed_board_recusal(candidate_consent uuid,candidate_member uuid,candidate_vote uuid)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare c public.consent_records%rowtype; s public.action_stages%rowtype; payload jsonb;
begin
  select * into c from public.consent_records where id=candidate_consent;
  select * into s from public.action_stages where id=c.stage_id;
  if (current_setting('boardagent.transaction_scope',true)='request'
    and c.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and c.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and c.client_id=public.boardagent_context_uuid('boardagent.client_id')
    and c.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
    and c.confirmed_at=transaction_timestamp()
    and c.action_code='manage_recusal' and c.target_type='board' and c.target_id=c.board_id
    and c.package_sha256 is null and s.package_sha256 is null
    and s.state='confirmed' and s.confirmed_at=c.confirmed_at
    and s.organization_id=c.organization_id and s.board_id=c.board_id
    and s.actor_member_id=c.actor_member_id and s.client_id=c.client_id and s.token_jti=c.token_jti
    and s.action_code=c.action_code and s.target_type=c.target_type and s.target_id=c.target_id
    and s.payload_sha256=c.payload_sha256 and s.payload_sha256=pg_catalog.sha256(s.canonical_payload)
    and s.canonical_schema='boardagent.board-recusal-consent.v1'
    and exists(select 1 from public.input_required_attempts a where a.id=c.input_required_attempt_id
      and a.stage_id=s.id and a.organization_id=c.organization_id and a.state='confirmed'
      and a.response_action='accept' and a.original_method='tools/call' and a.original_name='manage_recusal')
    and public.boardagent_secretariat_for_board(c.board_id)) is distinct from true then return null; end if;
  payload:=convert_from(s.canonical_payload,'UTF8')::jsonb;
  if (payload->'request'->>'boardId'=c.board_id::text
    and payload->'request'->>'memberId'=candidate_member::text
    and payload->'request'->>'operation' in ('add','lift')
    and jsonb_typeof(payload->'affectedVotes')='array') is distinct from true then return null; end if;
  if candidate_vote is not null and not exists (
    select 1 from jsonb_array_elements(payload->'affectedVotes') entry
    join public.votes v on v.id=candidate_vote and v.organization_id=c.organization_id and v.board_id=c.board_id
    join public.decision_packages p on p.id=v.current_decision_package_id and p.vote_id=v.id
    where entry->>'voteId'=v.id::text and entry->>'packageSha256'=encode(p.package_sha256,'hex')
      and v.state in ('open','source_update_pending')) then return null; end if;
  return payload;
end $$;
alter function public.boardagent_confirmed_board_recusal(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_confirmed_board_recusal(uuid,uuid,uuid) from public;

CREATE OR REPLACE FUNCTION public.boardagent_lock_vote_for_recusal(candidate_vote uuid, candidate_member uuid, candidate_consent uuid, candidate_payload_sha256 bytea)
 RETURNS TABLE(organization_id uuid, board_id uuid, vote_state text, vote_row_version bigint, decision_package_id uuid, package_sha256 bytea, electorate_weight bigint, current_exclusion_id uuid, current_exclusion_version integer, current_exclusion_state text, actor_ready boolean, consent_valid boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote recusal requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_payload_sha256 is null or octet_length(candidate_payload_sha256) <> 32 then
    raise exception 'vote recusal payload hash is invalid' using errcode = '22023';
  end if;
  return query
    select vote.organization_id,
           vote.board_id,
           vote.state,
           vote.row_version,
           package.id,
           package.package_sha256,
           electorate.voting_weight,
           current_exclusion.id,
           current_exclusion.version,
           current_exclusion.state,
           boardagent_vote_actor_ready(vote.board_id),
           (exists (
             select 1
               from consent_records as consent
               join action_stages as stage on stage.id = consent.stage_id
               join input_required_attempts as attempt
                 on attempt.id = consent.input_required_attempt_id
              where consent.id = candidate_consent
                and consent.organization_id = vote.organization_id
                and consent.board_id = vote.board_id
                and consent.actor_member_id = boardagent_context_uuid('boardagent.member_id')
                and consent.client_id = boardagent_context_uuid('boardagent.client_id')
                and consent.token_jti = boardagent_context_uuid('boardagent.token_jti')
                and consent.action_code = 'manage_recusal'
                and consent.target_type = 'vote'
                and consent.target_id = vote.id
                and consent.payload_sha256 = candidate_payload_sha256
                and consent.package_sha256 = package.package_sha256
                and stage.organization_id = consent.organization_id
                and stage.board_id = consent.board_id
                and stage.actor_member_id = consent.actor_member_id
                and stage.client_id = consent.client_id
                and stage.token_jti = consent.token_jti
                and stage.action_code = consent.action_code
                and stage.target_type = consent.target_type
                and stage.target_id = consent.target_id
                and stage.payload_sha256 = consent.payload_sha256
                and stage.package_sha256 = consent.package_sha256
                and stage.state = 'confirmed'
                and stage.confirmed_at is not null
                and attempt.organization_id = consent.organization_id
                and attempt.stage_id = stage.id
                and attempt.original_method = 'tools/call'
                and attempt.original_name = 'manage_recusal'
                and attempt.response_action = 'accept'
                and attempt.state = 'confirmed'
           ) or exists (
             select 1 from public.consent_records c
             where c.id=candidate_consent and c.payload_sha256=candidate_payload_sha256
               and public.boardagent_confirmed_board_recusal(c.id,candidate_member,vote.id) is not null
           ))
      from votes as vote
      join decision_packages as package
        on package.id = vote.current_decision_package_id
       and package.vote_id = vote.id
      join vote_electorate as electorate
        on electorate.vote_id = vote.id
       and electorate.member_id = candidate_member
      join members as target_member
        on target_member.organization_id = vote.organization_id
       and target_member.id = electorate.member_id
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
       and membership.member_id = electorate.member_id
      left join lateral (
        select exclusion.id, exclusion.version, exclusion.state
          from vote_exclusions as exclusion
         where exclusion.vote_id = vote.id
           and exclusion.member_id = electorate.member_id
         order by exclusion.version desc, exclusion.id desc
         limit 1
      ) as current_exclusion on true
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(vote.board_id)
       and target_member.state = 'active'
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
     for update of vote, target_member, membership
     for share of package;
end
$function$
;

-- New writes always carry the requested cause separately from its effective result.
-- A board cause uses the real board confirmation, never a synthetic per-vote consent.
create function public.boardagent_validate_vote_recusal_cause(candidate public.vote_exclusions)
returns boolean language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare c public.consent_records%rowtype; s public.action_stages%rowtype; payload jsonb;
  locked record; prior public.vote_exclusions%rowtype; manual_state text; requested text; effective text; board_payload jsonb;
begin
  if (current_setting('boardagent.transaction_scope',true)='request'
    and candidate.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and candidate.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')) is distinct from true then return false; end if;
  select * into c from public.consent_records where id=candidate.consent_record_id;
  select * into s from public.action_stages where id=c.stage_id;
  select * into locked from public.boardagent_lock_vote_for_recusal(candidate.vote_id,candidate.member_id,c.id,c.payload_sha256);
  if (locked.consent_valid and locked.actor_ready and locked.board_id=candidate.board_id
      and locked.vote_state in ('open','source_update_pending')
      and not exists(select 1 from public.vote_exclusions e where e.vote_id=candidate.vote_id and e.consent_record_id=c.id)) is distinct from true then return false; end if;
  requested:=coalesce(candidate.cause_requested_state,candidate.state);
  if candidate.source_board_exclusion_id is null then
    payload:=convert_from(s.canonical_payload,'UTF8')::jsonb;
    if (c.target_type='vote' and payload->>'schemaVersion'='boardagent.vote-recusal-consent.v1'
      and payload->>'voteId'=candidate.vote_id::text and payload->>'memberId'=candidate.member_id::text
      and payload->>'state'=requested and payload->>'reason'=candidate.reason
      and payload->>'packageSha256'=encode(locked.package_sha256,'hex')
      and s.payload_sha256=pg_catalog.sha256(s.canonical_payload)) is distinct from true then return false; end if;
    select * into prior from public.vote_exclusions e where e.vote_id=candidate.vote_id and e.member_id=candidate.member_id
      and e.source_board_exclusion_id is null order by e.version desc limit 1;
    if (requested='excluded' and coalesce(prior.cause_requested_state,prior.state)='excluded')
      or (requested='lifted' and coalesce(prior.cause_requested_state,prior.state) is distinct from 'excluded') then return false; end if;
    effective:=case when requested='excluded' or public.boardagent_member_board_recused(candidate.board_id,candidate.member_id) then 'excluded' else 'lifted' end;
  else
    board_payload:=public.boardagent_confirmed_board_recusal(c.id,candidate.member_id,candidate.vote_id);
    if board_payload is null or candidate.cause_requested_state is null
      or requested<>(case board_payload->'request'->>'operation' when 'add' then 'excluded' else 'lifted' end)
      or candidate.reason is distinct from board_payload->'request'->>'reason' then return false; end if;
    select coalesce(e.cause_requested_state,e.state) into manual_state from public.vote_exclusions e
      where e.vote_id=candidate.vote_id and e.member_id=candidate.member_id and e.source_board_exclusion_id is null
      order by e.version desc limit 1;
    effective:=case when requested='excluded' or manual_state='excluded' then 'excluded' else 'lifted' end;
  end if;
  return candidate.state=effective and candidate.version=coalesce(locked.current_exclusion_version,0)+1;
end $$;
alter function public.boardagent_validate_vote_recusal_cause(public.vote_exclusions) owner to boardagent_migrator;
revoke all on function public.boardagent_validate_vote_recusal_cause(public.vote_exclusions) from public;
grant execute on function public.boardagent_validate_vote_recusal_cause(public.vote_exclusions) to boardagent_server;
create function public.boardagent_guard_vote_recusal_cause() returns trigger language plpgsql
set search_path=pg_catalog,public,pg_temp as $$
begin
  if current_user='boardagent_server' and public.boardagent_validate_vote_recusal_cause(new) is distinct from true then
    raise exception 'vote recusal lacks confirmed cause authority' using errcode='42501'; end if;
  return new;
end $$;
revoke all on function public.boardagent_guard_vote_recusal_cause() from public;
create trigger boardagent_vote_recusal_cause before insert on public.vote_exclusions
  for each row execute function public.boardagent_guard_vote_recusal_cause();

create or replace function public.boardagent_apply_board_recusal(candidate_consent uuid,candidate_exclusion uuid,candidate_audit uuid)
returns void language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare
  consent public.consent_records%rowtype;
  stage public.action_stages%rowtype;
  payload jsonb;
  snapshot jsonb;
  request jsonb;
begin
  select * into consent from public.consent_records c where c.id=candidate_consent;
  select * into stage from public.action_stages s where s.id=consent.stage_id;
  if (current_setting('boardagent.transaction_scope',true)='request'
    and consent.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and consent.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and consent.client_id=public.boardagent_context_uuid('boardagent.client_id')
    and consent.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
    and consent.confirmed_at=transaction_timestamp()
    and consent.action_code='manage_recusal' and consent.target_type='board'
    and consent.board_id=consent.target_id and consent.package_sha256 is null
    and stage.state='confirmed' and stage.confirmed_at=consent.confirmed_at
    and stage.action_code=consent.action_code and stage.target_type=consent.target_type
    and stage.target_id=consent.target_id and stage.board_id=consent.board_id
    and stage.actor_member_id=consent.actor_member_id and stage.client_id=consent.client_id
    and stage.token_jti=consent.token_jti and stage.payload_sha256=consent.payload_sha256
    and stage.payload_sha256=pg_catalog.sha256(stage.canonical_payload)
    and stage.canonical_schema='boardagent.board-recusal-consent.v1'
    and exists(select 1 from public.input_required_attempts a where a.id=consent.input_required_attempt_id
      and a.stage_id=stage.id and a.state='confirmed' and a.response_action='accept'
      and a.original_name='manage_recusal')
    and public.boardagent_is_uuid_v7(candidate_exclusion)) is distinct from true then
    raise exception 'board recusal lacks exact confirmed authority' using errcode='42501';
  end if;
  payload:=convert_from(stage.canonical_payload,'UTF8')::jsonb;
  request:=payload->'request';
  snapshot:=public.boardagent_prepare_board_recusal(request);
  if payload is distinct from snapshot or (request->>'boardId')::uuid<>consent.board_id
    or not exists(select 1 from public.audit_events a
      where a.id=candidate_audit and a.organization_id=consent.organization_id
        and a.board_id=consent.board_id and a.object_type='board' and a.object_id=consent.board_id
        and a.event_type='recusal_changed' and a.actor_member_id=consent.actor_member_id
        and a.client_id=consent.client_id and a.token_jti=consent.token_jti
        and a.consent_record_id=consent.id
        and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'->>'exclusionId'=candidate_exclusion::text
        and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'->'request'=request) then
    raise exception 'board recusal lacks exact confirmed evidence' using errcode='42501';
  end if;
  -- A raw application SQL caller cannot apply the board restriction while skipping
  -- one of the confirmed, currently open vote effects.
  if (select count(*) from public.vote_exclusions e where e.source_board_exclusion_id=candidate_exclusion
       and e.consent_record_id=consent.id)<>jsonb_array_length(payload->'affectedVotes')
    or exists(select 1 from jsonb_array_elements(payload->'affectedVotes') entry where not exists (
      select 1 from public.vote_exclusions e where e.vote_id=(entry->>'voteId')::uuid
        and e.member_id=(request->>'memberId')::uuid and e.source_board_exclusion_id=candidate_exclusion
        and e.consent_record_id=consent.id and e.cause_requested_state=
          case request->>'operation' when 'add' then 'excluded' else 'lifted' end)) then
    raise exception 'board recusal vote effects are incomplete' using errcode='42501';
  end if;
  if request->>'operation'='add' and (
    exists(select 1 from public.action_stages a where a.organization_id=consent.organization_id and a.board_id=consent.board_id
      and a.state='active' and (a.actor_member_id=(request->>'memberId')::uuid or a.acting_for_member_id=(request->>'memberId')::uuid))
    or exists(select 1 from public.pending_action_feed f where f.organization_id=consent.organization_id and f.board_id=consent.board_id
      and f.member_id=(request->>'memberId')::uuid and f.state='pending')
    or exists(select 1 from public.ballots ballot join public.votes v on v.id=ballot.vote_id
      where v.board_id=consent.board_id and v.organization_id=consent.organization_id and v.state in ('open','source_update_pending')
        and (ballot.principal_member_id=(request->>'memberId')::uuid or (ballot.ballot_source='proxy' and ballot.caster_member_id=(request->>'memberId')::uuid))
        and not exists(select 1 from public.ballot_dispositions d where d.prior_ballot_id=ballot.id))
    or exists(select 1 from public.proxy_grants p join public.votes v on v.id=p.vote_id
      where v.board_id=consent.board_id and v.organization_id=consent.organization_id and v.state in ('open','source_update_pending')
        and (p.principal_member_id=(request->>'memberId')::uuid or p.holder_member_id=(request->>'memberId')::uuid)
        and not exists(select 1 from public.proxy_revocations r where r.grant_id=p.id))) then
    raise exception 'board recusal active projections remain' using errcode='42501';
  end if;
  insert into public.board_exclusions(id,organization_id,board_id,member_id,version,state,reason,
    actor_member_id,consent_record_id,audit_event_id)
    values(candidate_exclusion,consent.organization_id,consent.board_id,(request->>'memberId')::uuid,
      (payload->>'priorVersion')::integer+1,case request->>'operation' when 'add' then 'excluded' else 'lifted' end,
      request->>'reason',consent.actor_member_id,consent.id,candidate_audit);
end
$$;
alter function public.boardagent_apply_board_recusal(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_apply_board_recusal(uuid,uuid,uuid) from public;
grant execute on function public.boardagent_apply_board_recusal(uuid,uuid,uuid) to boardagent_server;


-- A lifted recipient can receive fresh pending work in the same atomic transaction.
-- Commit checks the final authority; premature delivery without the lift is rejected.
drop trigger boardagent_recused_board_recipient on public.notices;
drop trigger boardagent_recused_board_recipient on public.pending_action_feed;
create constraint trigger boardagent_recused_board_recipient after insert on public.notices
  deferrable initially deferred for each row execute function public.boardagent_guard_recused_board_recipient();
create constraint trigger boardagent_recused_board_recipient after insert on public.pending_action_feed
  deferrable initially deferred for each row execute function public.boardagent_guard_recused_board_recipient();

-- Read/lock only; delivery writes still require the final authority at commit.
CREATE OR REPLACE FUNCTION public.boardagent_lock_vote_recusal_recipients(candidate_old_vote uuid,candidate_member uuid,candidate_state text,candidate_board_lift boolean)
 RETURNS TABLE(member_id uuid, seat_role text, entitlement_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement recipients require a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.seat_role,
           membership.entitlement_generation
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join members as recipient
        on recipient.organization_id = membership.organization_id
       and recipient.id = membership.member_id
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state in ('open', 'source_update_pending')
       and boardagent_vote_actor_ready(vote.board_id)
       and recipient.state = 'active'
       and membership.state = 'active'
       and (not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
         or (candidate_board_lift and membership.member_id=candidate_member))
       and (candidate_state='lifted' or membership.member_id<>candidate_member)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and exists (
         select 1
           from onboarding_attestations as attestation
          where attestation.organization_id = membership.organization_id
            and attestation.member_id = membership.member_id
            and attestation.board_id = membership.board_id
            and attestation.terms_version_id = (
              select terms.id
                from onboarding_terms_versions as terms
               where terms.organization_id = membership.organization_id
                 and terms.seat_role = membership.seat_role
                 and terms.effective_at <= transaction_timestamp()
               order by terms.effective_at desc, terms.version desc, terms.id desc
               limit 1
            )
            and attestation.support_version_id = (
              select support.id
                from secretary_support_versions as support
               where support.organization_id = membership.organization_id
                 and (support.board_id = membership.board_id or support.board_id is null)
                 and support.effective_at <= transaction_timestamp()
               order by (support.board_id = membership.board_id) desc,
                        support.effective_at desc,
                        support.version desc,
                        support.id desc
               limit 1
            )
       )
     order by membership.member_id
     for update of membership
     for share of recipient;
end
$function$
;
alter function public.boardagent_lock_vote_recusal_recipients(uuid,uuid,text,boolean) owner to boardagent_migrator;
revoke all on function public.boardagent_lock_vote_recusal_recipients(uuid,uuid,text,boolean) from public;
grant execute on function public.boardagent_lock_vote_recusal_recipients(uuid,uuid,text,boolean) to boardagent_server;
