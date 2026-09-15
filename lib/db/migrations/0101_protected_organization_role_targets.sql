-- SR-097 / Fable L1: a voting seat does not make an organization-privileged
-- person an ordinary director. Reserve all active organization-role holders for
-- company administrators, both when preparing and finalizing delegated changes.
-- Retain the existing admin path, allowed voting weights, lock order, grants and
-- SQL98 trusted namespace. Historical migration bytes remain unchanged.

-- One live capability projection for both member-invite and member-lifecycle paths.
create or replace function public.boardagent_member_administration_authority(candidate_request jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
  org uuid := public.boardagent_context_uuid('boardagent.organization_id');
  actor uuid := public.boardagent_context_uuid('boardagent.member_id');
  change jsonb := candidate_request->'change'; action text := change->>'operation';
  selected_board uuid; target_id uuid; board_record record; actor_is_admin boolean;
  actor_generation bigint; target public.members%rowtype; seat public.board_memberships%rowtype;
  delegation public.member_admin_delegations%rowtype; evidence jsonb; fields text[];
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or current_setting('transaction_isolation') is distinct from 'serializable' or org is null or actor is null then
    raise exception 'member administration requires a managed serializable request' using errcode='25000';
  end if;
  if jsonb_typeof(candidate_request) is distinct from 'object'
    or candidate_request-array['schema_version','change','idempotency_key','authority_evidence']<>'{}'::jsonb
    or candidate_request->>'schema_version' is distinct from 'boardagent.tool-input.v1'
    or jsonb_typeof(candidate_request->'idempotency_key') is distinct from 'string'
    or coalesce(candidate_request->>'idempotency_key','')!~'^[A-Za-z0-9._~-]{16,200}$'
    or jsonb_typeof(change) is distinct from 'object' or coalesce(action,'') not in ('invite','suspend','remove','reactivate','change_seat') then
    raise exception 'member administrative input is invalid' using errcode='22023';
  end if;
  fields := case action when 'invite' then array['operation','member_id','board_id','member_kind','seat_role','legal_name','display_name','voting_weight','accountable_principal_id']
    when 'change_seat' then array['operation','member_id','board_id','reason','seat_role','voting_weight','is_secretary']
    else array['operation','member_id','board_id','reason'] end;
  if change-(fields||case when action='invite' then array['reason'] else array[]::text[] end)<>'{}'::jsonb or not(change ?& fields)
    or jsonb_typeof(change->'member_id') is distinct from 'string'
    or not public.boardagent_is_uuid_v7((change->>'member_id')::uuid)
    or jsonb_typeof(change->'board_id') not in ('string','null') then
    raise exception 'member administrative fields are invalid' using errcode='22023';
  end if;
  selected_board := (change->>'board_id')::uuid; target_id := (change->>'member_id')::uuid;
  if (selected_board is not null and not public.boardagent_is_uuid_v7(selected_board))
    or (action in ('invite','change_seat') and selected_board is null)
    or (change ? 'reason' and (jsonb_typeof(change->'reason') is distinct from 'string'
      or coalesce(length(change->>'reason'),0) not between 1 and case when action='invite' then 2000 else 65536 end
      or position(chr(13) in change->>'reason')>0 or normalize(change->>'reason',NFC) is distinct from change->>'reason')) then
    raise exception 'member administrative reason or board is invalid' using errcode='22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(org::text,424286));
  select 'admin'=any(t.roles) into actor_is_admin from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
    where t.organization_id=org and t.member_id=actor and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
      and 'secretariat:admin'=any(t.scope_set);
  if actor_is_admin is null or not public.boardagent_administrative_member_eligible(actor) then
    raise exception 'member administration is unavailable' using errcode='42501';
  end if;
  for board_record in select b.id,b.state from public.boards b where b.organization_id=org
    and (b.id=selected_board or (selected_board is null and exists(select 1 from public.board_memberships s
      where s.organization_id=org and s.member_id=target_id and s.board_id=b.id))) order by b.id loop
    perform pg_advisory_xact_lock(hashtextextended(board_record.id::text,424251));
    perform 1 from public.boards b where b.organization_id=org and b.id=board_record.id for update;
  end loop;
  perform pg_advisory_xact_lock(hashtextextended(target_id::text,424252));
  select m.* into target from public.members m where m.organization_id=org and m.id=target_id for update;
  if actor_is_admin then
    if candidate_request ? 'authority_evidence' then
      evidence := public.boardagent_administrative_citations(selected_board,candidate_request->'authority_evidence');
      select identity_generation into actor_generation from public.members where organization_id=org and id=actor;
      return jsonb_build_object('mode','company_admin','actorMemberId',actor,'actorIdentityGeneration',actor_generation::text,
        'boardId',selected_board,'appointmentEvidence',evidence);
    end if;
    return null;
  end if;
  if selected_board is null or target_id=actor or not(candidate_request ? 'authority_evidence')
    or jsonb_typeof(change->'reason') is distinct from 'string' or coalesce(length(change->>'reason'),0) not between 1 and 2000 then
    raise exception 'member administration is unavailable' using errcode='42501';
  end if;
  select d.* into delegation from public.member_admin_delegations d where d.organization_id=org and d.member_id=actor
    and d.board_id=selected_board and public.boardagent_member_admin_delegation_effective(d.id) order by d.created_at,d.id limit 1 for update;
  if delegation.id is null then raise exception 'member administration is unavailable' using errcode='42501'; end if;
  if action='invite' then
    if target.id is not null or change->>'member_kind' is distinct from 'human' or change->>'seat_role' is distinct from 'voting_member'
      or change->'accountable_principal_id' is distinct from 'null'::jsonb then
      raise exception 'member administration is unavailable' using errcode='42501';
    end if;
  else
    select s.* into seat from public.board_memberships s where s.organization_id=org and s.board_id=selected_board and s.member_id=target_id
      order by s.created_at desc,s.id desc limit 1 for update;
    if target.id is null or target.state<>'active' or target.member_kind<>'human' or seat.id is null
      or seat.seat_role<>'voting_member' or seat.is_secretary
      or (action='change_seat' and (change->>'seat_role' is distinct from 'voting_member' or change->'is_secretary' is distinct from 'false'::jsonb))
      or exists(select 1 from public.organization_role_assignments a where a.organization_id=org and a.member_id=target_id and a.role in ('admin','secretariat','management')
        and a.active_from<=transaction_timestamp() and (a.active_until is null or a.active_until>transaction_timestamp()))
      or exists(select 1 from public.board_memberships s where s.organization_id=org and s.member_id=target_id and s.is_secretary
        and s.state='active' and s.active_from<=transaction_timestamp() and (s.active_until is null or s.active_until>transaction_timestamp()))
      or exists(select 1 from public.member_admin_delegations d where d.organization_id=org and d.member_id=target_id
        and d.state='active' and d.expires_at>transaction_timestamp()) then
      raise exception 'member administration is unavailable' using errcode='42501';
    end if;
  end if;
  evidence := public.boardagent_administrative_citations(selected_board,candidate_request->'authority_evidence');
  select identity_generation into actor_generation from public.members where organization_id=org and id=actor;
  return jsonb_build_object('mode','delegated','actorMemberId',actor,'actorIdentityGeneration',actor_generation::text,
    'boardId',selected_board,'delegationId',delegation.id,'delegationVersion',delegation.row_version::text,
    'secretaryMembershipId',delegation.secretary_membership_id,'secretaryMembershipVersion',delegation.secretary_membership_version,
    'expiresAt',delegation.expires_at,'appointmentEvidence',evidence);
end
$$;
alter function public.boardagent_member_administration_authority(jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_member_administration_authority(jsonb) from public;
grant execute on function public.boardagent_member_administration_authority(jsonb) to boardagent_server;

