-- MR-COMM001: require an active board at both communication creation boundaries.
-- Current catalog definitions preserve the hardened search_path, owners and ACLs.
-- Shared entitlement predicates and exact successful retry behavior are unchanged.

CREATE OR REPLACE FUNCTION public.boardagent_create_proposal(candidate_id uuid, candidate_board uuid, candidate_type text, candidate_title text, candidate_payload bytea, candidate_payload_sha256 bytea, candidate_references jsonb, candidate_idempotency uuid, candidate_audit_event uuid)
 RETURNS TABLE(proposal_id uuid, proposal_state text, result_row_version bigint, result_board_id uuid)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_proposer_for_board(candidate_board)
     or not boardagent_idempotency_in_progress(candidate_idempotency,'propose_action') then
    raise exception 'proposal creation is not authorized' using errcode='42501';
  end if;
  -- Serialize new effects with the supported board-archive row update.
  -- Exact completed retries return before this creation function is invoked.
  perform 1 from public.boards as board
   where board.id=candidate_board
     and board.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
     and board.state='active'
   for share;
  if not found then
    raise exception 'active board is unavailable' using errcode='P0002';
  end if;
  insert into proposals(id,organization_id,board_id,proposer_member_id,proposal_type,title,
    schema_version,canonical_payload,payload_sha256,resource_references,
    idempotency_record_id,last_audit_event_id)
  values(candidate_id,boardagent_context_uuid('boardagent.organization_id'),candidate_board,
    boardagent_context_uuid('boardagent.member_id'),candidate_type,candidate_title,
    'boardagent.proposal.v1',candidate_payload,candidate_payload_sha256,candidate_references,
    candidate_idempotency,candidate_audit_event);
  return query select candidate_id,'pending'::text,1::bigint,candidate_board;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_create_secretariat_request(candidate_id uuid, candidate_turn_id uuid, candidate_board uuid, candidate_topic text, candidate_text text, candidate_text_sha256 bytea, candidate_references jsonb, candidate_idempotency uuid, candidate_audit_event uuid)
 RETURNS TABLE(request_id uuid, request_state text, result_row_version bigint, result_board_id uuid)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare seat text;
begin
  select membership.seat_role into seat from board_memberships as membership
   where membership.board_id=candidate_board
     and membership.member_id=boardagent_context_uuid('boardagent.member_id')
     and membership.state='active' and membership.active_from<=transaction_timestamp()
     and (membership.active_until is null or membership.active_until>transaction_timestamp())
   for update;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or seat is null or seat='observer'
     or not boardagent_communication_actor_ready(candidate_board,'secretariat:message')
     or not boardagent_idempotency_in_progress(candidate_idempotency,'ask_secretariat') then
    raise exception 'secretariat request is not authorized' using errcode='42501';
  end if;
  -- Serialize new effects with the supported board-archive row update.
  -- Exact completed retries return before this creation function is invoked.
  perform 1 from public.boards as board
   where board.id=candidate_board
     and board.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
     and board.state='active'
   for share;
  if not found then
    raise exception 'active board is unavailable' using errcode='P0002';
  end if;
  insert into secretariat_requests(id,organization_id,board_id,requester_member_id,topic,
    current_turn_id,idempotency_record_id,last_audit_event_id)
  values(candidate_id,boardagent_context_uuid('boardagent.organization_id'),candidate_board,
    boardagent_context_uuid('boardagent.member_id'),candidate_topic,candidate_turn_id,
    candidate_idempotency,candidate_audit_event);
  insert into secretariat_request_turns(id,organization_id,board_id,request_id,ordinal,
    turn_kind,author_member_id,author_role,canonical_text,text_sha256,resource_references,
    idempotency_record_id,audit_event_id)
  values(candidate_turn_id,boardagent_context_uuid('boardagent.organization_id'),candidate_board,
    candidate_id,1,'request',boardagent_context_uuid('boardagent.member_id'),seat,
    candidate_text,candidate_text_sha256,candidate_references,candidate_idempotency,candidate_audit_event);
  return query select candidate_id,'open'::text,1::bigint,candidate_board;
end
$function$
;
