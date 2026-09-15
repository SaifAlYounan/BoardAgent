-- MR-MEC-002 / SR-075/086: an exact completed member lifecycle request may return
-- its original safe result after normal token rotation. This is a narrow read;
-- it grants no raw stage, consent, audit, or business-record access and performs
-- no lifecycle mutation. Preserve0145's current-JTI raw-evidence RLS boundary.
create function public.boardagent_replay_member_lifecycle(
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
  actor_is_admin boolean;
  current_authority jsonb;
  prior public.idempotency_records%rowtype;
  original_stage public.action_stages%rowtype;
  original_payload jsonb;
  original_current jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or org is null or actor is null or context_client is null or token_id is null
    or coalesce(change->>'operation','') not in ('change_seat','suspend','remove','reactivate')
    or not public.boardagent_hash_is_sha256(candidate_request_sha256) then
    raise exception 'completed member request is invalid' using errcode='22023';
  end if;
  select 'admin'=any(t.roles) into actor_is_admin
    from public.boardagent_resolve_access_token(token_id) t
    where t.token_record_id=candidate_token_record and t.organization_id=org
      and t.member_id=actor and t.internal_client_id=context_client
      and t.resource_uri=candidate_origin||'/mcp'
      and 'secretariat:admin'=any(t.scope_set);
  if actor_is_admin is null then
    raise exception 'completed member request is unavailable' using errcode='42501';
  end if;
  -- This validates the exact existing request shape, live human/onboarding state,
  -- company-admin or cited current delegation, target restrictions, and lock order.
  -- It intentionally does not require applying the already completed transition.
  current_authority := public.boardagent_member_administration_authority(candidate_request);
  selected_board := (change->>'board_id')::uuid;
  if selected_board is not null and (not exists (
    select 1 from public.boards b where b.organization_id=org and b.id=selected_board
      and b.state='active'
  ) or public.boardagent_member_board_recused(selected_board,actor)) then
    raise exception 'completed member board is unavailable' using errcode='42501';
  end if;
  select r.* into prior from public.idempotency_records r
    where r.organization_id=org and r.actor_member_id=actor and r.client_id=context_client
      and r.operation='manage_member' and r.idempotency_key=candidate_request->>'idempotency_key';
  if prior.id is null then return null; end if;
  if prior.request_sha256 is distinct from candidate_request_sha256
    or prior.state<>'succeeded' or prior.safe_response_type is distinct from 'member'
    or prior.safe_response_id is distinct from (change->>'member_id')::uuid
    or not public.boardagent_hash_is_sha256(prior.safe_response_sha256) then
    raise exception 'completed member request conflicts with its original result' using errcode='23514';
  end if;
  select s.* into original_stage from public.action_stages s
    join public.consent_records c on c.stage_id=s.id and c.organization_id=s.organization_id
      and c.actor_member_id=s.actor_member_id and c.client_id=s.client_id and c.token_jti=s.token_jti
      and c.action_code=s.action_code and c.target_type=s.target_type and c.target_id=s.target_id
      and c.board_id is not distinct from s.board_id and c.payload_sha256=s.payload_sha256
    join public.audit_events a on a.consent_record_id=c.id and a.organization_id=c.organization_id
      and a.actor_member_id=c.actor_member_id and a.client_id=c.client_id and a.token_jti=c.token_jti
      and a.event_type='member_changed' and a.object_type='member' and a.object_id=c.target_id
      and a.board_id is not distinct from c.board_id
    where s.organization_id=org and s.actor_member_id=actor and s.client_id=context_client
      and s.action_code='manage_member' and s.target_type='member' and s.target_id=prior.safe_response_id
      and s.board_id is not distinct from selected_board and s.state='confirmed'
      and s.exact_origin=candidate_origin and s.payload_sha256=prior.safe_response_sha256
    order by s.created_at,s.id limit 1;
  if original_stage.id is null or pg_catalog.sha256(original_stage.canonical_payload)<>prior.safe_response_sha256 then
    raise exception 'completed member evidence is unavailable' using errcode='42501';
  end if;
  original_payload := convert_from(original_stage.canonical_payload,'UTF8')::jsonb;
  original_current := original_payload->'current';
  if original_payload->>'schemaVersion' is distinct from 'boardagent.member-lifecycle.v1'
    or original_payload->'request' is distinct from candidate_request
    or original_current->'memberAfter'->>'memberId' is distinct from change->>'member_id'
    or (not actor_is_admin and current_authority is distinct from original_current->'administrativeAuthority')
    or exists (select 1 from jsonb_array_elements(original_current->'seatsAfter') seat
      where public.boardagent_member_board_recused((seat->>'boardId')::uuid,actor)) then
    raise exception 'completed member result or current authority is unavailable' using errcode='42501';
  end if;
  -- Only the fields already present in the original public safe result escape.
  -- The historical token, consent, full request and audit payload stay internal.
  return jsonb_build_object('operation',change->>'operation','memberId',change->>'member_id',
    'boardId',selected_board,'memberAfter',original_current->'memberAfter',
    'seatsAfter',original_current->'seatsAfter');
end
$$;
alter function public.boardagent_replay_member_lifecycle(jsonb,bytea,text,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_replay_member_lifecycle(jsonb,bytea,text,uuid) from public;
grant execute on function public.boardagent_replay_member_lifecycle(jsonb,bytea,text,uuid) to boardagent_server;
