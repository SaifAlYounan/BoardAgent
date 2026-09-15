-- D2-044 / SR-075: recover only the original safe invitation receipt on a new
-- exact request. The original creation guard still rejects existing members;
-- this reader neither consumes consent nor changes members or memberships.
create function public.boardagent_replay_member_invite(
  candidate_request jsonb,
  candidate_request_sha256 bytea,
  candidate_origin text,
  candidate_token_record uuid
) returns jsonb language plpgsql volatile security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  context_client uuid := public.boardagent_context_uuid('boardagent.client_id');
  token_id uuid := public.boardagent_context_uuid('boardagent.token_jti');
  change jsonb := candidate_request->'change';
  selected_board uuid;
  selected_member uuid;
  actor_is_admin boolean;
  actor_generation bigint;
  prior public.idempotency_records%rowtype;
  original record;
  original_payload jsonb;
  original_authority jsonb;
  current_authority jsonb;
  evidence jsonb;
  delegation public.member_admin_delegations%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or org is null or actor is null or context_client is null or token_id is null
    or jsonb_typeof(candidate_request) is distinct from 'object'
    or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
    or change->>'operation' is distinct from 'invite'
    or jsonb_typeof(change->'board_id') is distinct from 'string'
    or jsonb_typeof(change->'member_id') is distinct from 'string'
    or jsonb_typeof(candidate_request->'idempotency_key') is distinct from 'string'
    or coalesce(candidate_request->>'idempotency_key','')!~'^[A-Za-z0-9._~-]{16,200}$'
    or candidate_request_sha256 is null
    or not public.boardagent_hash_is_sha256(candidate_request_sha256) then
    raise exception 'completed invitation request is invalid' using errcode='22023';
  end if;
  selected_board := (change->>'board_id')::uuid;
  selected_member := (change->>'member_id')::uuid;
  if not public.boardagent_is_uuid_v7(selected_board)
    or not public.boardagent_is_uuid_v7(selected_member) then
    raise exception 'completed invitation target is invalid' using errcode='22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(org::text,424286));
  select 'admin'=any(t.roles) into actor_is_admin
    from public.boardagent_resolve_access_token(token_id) t
    where t.token_record_id=candidate_token_record and t.organization_id=org
      and t.member_id=actor and t.internal_client_id=context_client
      and t.resource_uri=candidate_origin||'/mcp'
      and 'secretariat:admin'=any(t.scope_set);
  if actor_is_admin is null or not public.boardagent_administrative_member_eligible(actor) then
    raise exception 'completed invitation request is unavailable' using errcode='42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(selected_board::text,424251));
  perform 1 from public.boards b where b.organization_id=org and b.id=selected_board
    and b.state='active' for update;
  if not found or public.boardagent_member_board_recused(selected_board,actor) then
    raise exception 'completed invitation board is unavailable' using errcode='42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(selected_member::text,424252));
  select r.* into prior from public.idempotency_records r
    where r.organization_id=org and r.actor_member_id=actor and r.client_id=context_client
      and r.operation='manage_member' and r.idempotency_key=candidate_request->>'idempotency_key';
  if prior.id is null then return null; end if;
  if prior.request_sha256 is distinct from candidate_request_sha256
    or prior.state is distinct from 'succeeded' or prior.safe_response_type is distinct from 'member'
    or prior.safe_response_id is distinct from selected_member
    or prior.safe_response_sha256 is null
    or not public.boardagent_hash_is_sha256(prior.safe_response_sha256) then
    raise exception 'completed invitation conflicts with its original result' using errcode='23514';
  end if;
  select s.canonical_payload,s.payload_sha256,v.membership_id into original
    from public.action_stages s
    join public.consent_records c on c.stage_id=s.id and c.organization_id=s.organization_id
      and c.actor_member_id=s.actor_member_id and c.client_id=s.client_id and c.token_jti=s.token_jti
      and c.action_code=s.action_code and c.target_type=s.target_type and c.target_id=s.target_id
      and c.board_id=s.board_id and c.payload_sha256=s.payload_sha256
    join public.input_required_attempts attempt on attempt.id=c.input_required_attempt_id
      and attempt.organization_id=c.organization_id and attempt.stage_id=s.id
      and attempt.original_name='manage_member' and attempt.original_arguments_sha256=prior.request_sha256
    join public.audit_events a on a.consent_record_id=c.id and a.organization_id=c.organization_id
      and a.actor_member_id=c.actor_member_id and a.client_id=c.client_id and a.token_jti=c.token_jti
      and a.event_type='member_changed' and a.object_type='member' and a.object_id=c.target_id
      and a.board_id=c.board_id and a.object_version=1
    join public.membership_versions v on v.consent_record_id=c.id and v.audit_event_id=a.id
      and v.organization_id=c.organization_id and v.board_id=c.board_id
      and v.member_id=c.target_id and v.version=1
    where s.organization_id=org and s.actor_member_id=actor and s.client_id=context_client
      and s.action_code='manage_member' and s.target_type='member' and s.target_id=selected_member
      and s.board_id=selected_board and s.state='confirmed' and s.exact_origin=candidate_origin
    order by s.created_at,s.id limit 1;
  if not found or pg_catalog.sha256(original.canonical_payload) is distinct from original.payload_sha256 then
    raise exception 'completed invitation evidence is unavailable' using errcode='42501';
  end if;
  original_payload := convert_from(original.canonical_payload,'UTF8')::jsonb;
  original_authority := original_payload->'administrativeAuthority';
  if original_payload->>'schemaVersion' is distinct from 'boardagent.member-invite.v1'
    or original_payload->'request' is distinct from candidate_request then
    raise exception 'completed invitation request differs from its evidence' using errcode='42501';
  end if;
  if actor_is_admin then
    -- The existing company-admin branch permits an existing target and rechecks
    -- the exact request shape and any supplied current appointment citations.
    current_authority := public.boardagent_member_administration_authority(candidate_request);
  else
    -- A saved invite is not a fresh attempt to create its now-existing member.
    -- Retain every delegated invite scope and the original live delegation;
    -- only the creation prerequisite (target absence) is inapplicable here.
    if selected_member=actor or change->>'member_kind' is distinct from 'human'
      or change->>'seat_role' is distinct from 'voting_member'
      or change->'accountable_principal_id' is distinct from 'null'::jsonb
      or original_authority->>'mode' is distinct from 'delegated'
      or not(candidate_request ? 'authority_evidence') then
      raise exception 'completed invitation authority is unavailable' using errcode='42501';
    end if;
    select d.* into delegation from public.member_admin_delegations d
      where d.organization_id=org and d.member_id=actor and d.board_id=selected_board
        and d.id=(original_authority->>'delegationId')::uuid
        and public.boardagent_member_admin_delegation_effective(d.id) for update;
    if delegation.id is null then
      raise exception 'completed invitation delegation is unavailable' using errcode='42501';
    end if;
    evidence := public.boardagent_administrative_citations(selected_board,candidate_request->'authority_evidence');
    select identity_generation into actor_generation from public.members where organization_id=org and id=actor;
    current_authority := jsonb_build_object('mode','delegated','actorMemberId',actor,
      'actorIdentityGeneration',actor_generation::text,'boardId',selected_board,
      'delegationId',delegation.id,'delegationVersion',delegation.row_version::text,
      'secretaryMembershipId',delegation.secretary_membership_id,
      'secretaryMembershipVersion',delegation.secretary_membership_version,
      'expiresAt',delegation.expires_at,'appointmentEvidence',evidence);
    if current_authority is distinct from original_authority then
      raise exception 'completed invitation authority changed' using errcode='42501';
    end if;
  end if;
  return jsonb_build_object('memberId',selected_member,'boardId',selected_board,
    'membershipId',original.membership_id,'safeResponseSha256',encode(prior.safe_response_sha256,'hex'));
end
$$;
alter function public.boardagent_replay_member_invite(jsonb,bytea,text,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_replay_member_invite(jsonb,bytea,text,uuid) from public;
grant execute on function public.boardagent_replay_member_invite(jsonb,bytea,text,uuid) to boardagent_server;
