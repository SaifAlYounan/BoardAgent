-- BoardAgent Phase 4: append-only proposals and secretariat request threads. These
-- records implement already-frozen MCP callables; they add no callable/event surface.

create table proposals (
  id uuid primary key,
  organization_id uuid not null references organizations(id),
  board_id uuid not null,
  proposer_member_id uuid not null,
  proposal_type text not null check (proposal_type in ('meeting','vote','document','minutes','task','other')),
  title text not null check (length(title) between 1 and 1024),
  schema_version text not null check (schema_version='boardagent.proposal.v1'),
  canonical_payload bytea not null,
  payload_sha256 bytea not null check (boardagent_hash_is_sha256(payload_sha256)),
  resource_references jsonb not null check (jsonb_typeof(resource_references)='array'),
  state text not null default 'pending'
    check (state in ('pending','withdrawn','approved_to_draft','rejected')),
  row_version bigint not null default 1 check (row_version>=1),
  idempotency_record_id uuid not null references idempotency_records(id),
  last_audit_event_id uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  closed_at timestamptz(6),
  unique (organization_id,id),
  foreign key (organization_id,board_id) references boards(organization_id,id),
  foreign key (organization_id,proposer_member_id) references members(organization_id,id),
  foreign key (last_audit_event_id) references audit_events(id) deferrable initially deferred,
  check ((state='pending' and closed_at is null) or (state<>'pending' and closed_at is not null))
);

create table proposal_dispositions (
  id uuid primary key,
  organization_id uuid not null references organizations(id),
  board_id uuid not null,
  proposal_id uuid not null,
  actor_member_id uuid not null,
  disposition text not null check (disposition in ('approved_to_draft','rejected')),
  reason text,
  resulting_draft_id uuid,
  idempotency_record_id uuid not null references idempotency_records(id),
  audit_event_id uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (proposal_id),
  foreign key (organization_id,proposal_id) references proposals(organization_id,id),
  foreign key (organization_id,board_id) references boards(organization_id,id),
  foreign key (organization_id,actor_member_id) references members(organization_id,id),
  foreign key (organization_id,resulting_draft_id)
    references wizard_drafts(organization_id,id),
  foreign key (audit_event_id) references audit_events(id) deferrable initially deferred,
  check (
    (disposition='approved_to_draft' and resulting_draft_id is not null and reason is null)
    or (disposition='rejected' and resulting_draft_id is null and length(reason)>0)
  )
);

create table secretariat_requests (
  id uuid primary key,
  organization_id uuid not null references organizations(id),
  board_id uuid not null,
  requester_member_id uuid not null,
  topic text not null check (length(topic) between 1 and 1024),
  state text not null default 'open' check (state in ('open','answered','closed')),
  current_turn_id uuid,
  row_version bigint not null default 1 check (row_version>=1),
  idempotency_record_id uuid not null references idempotency_records(id),
  last_audit_event_id uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  closed_at timestamptz(6),
  unique (organization_id,id),
  foreign key (organization_id,board_id) references boards(organization_id,id),
  foreign key (organization_id,requester_member_id) references members(organization_id,id),
  foreign key (last_audit_event_id) references audit_events(id) deferrable initially deferred,
  check ((state='closed' and closed_at is not null) or (state<>'closed' and closed_at is null))
);

create table secretariat_request_turns (
  id uuid primary key,
  organization_id uuid not null references organizations(id),
  board_id uuid not null,
  request_id uuid not null,
  ordinal integer not null check (ordinal>=1),
  turn_kind text not null check (turn_kind in ('request','reply')),
  author_member_id uuid not null,
  author_role text not null check (author_role in ('voting_member','management','secretariat')),
  canonical_text text not null check (length(canonical_text)>0),
  text_sha256 bytea not null check (boardagent_hash_is_sha256(text_sha256)),
  resource_references jsonb not null check (jsonb_typeof(resource_references)='array'),
  idempotency_record_id uuid not null references idempotency_records(id),
  audit_event_id uuid not null,
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique (request_id,ordinal),
  foreign key (organization_id,request_id) references secretariat_requests(organization_id,id),
  foreign key (organization_id,board_id) references boards(organization_id,id),
  foreign key (organization_id,author_member_id) references members(organization_id,id),
  foreign key (audit_event_id) references audit_events(id) deferrable initially deferred
);

alter table secretariat_requests
  add foreign key (current_turn_id) references secretariat_request_turns(id)
  deferrable initially deferred;

create index proposals_queue_idx on proposals(board_id,state,created_at desc,id desc);
create index proposals_owner_idx on proposals(proposer_member_id,created_at desc,id desc);
create index secretariat_requests_queue_idx
  on secretariat_requests(board_id,state,created_at desc,id desc);
create index secretariat_requests_owner_idx
  on secretariat_requests(requester_member_id,created_at desc,id desc);

alter table proposals enable row level security;
alter table proposals force row level security;
alter table proposal_dispositions enable row level security;
alter table proposal_dispositions force row level security;
alter table secretariat_requests enable row level security;
alter table secretariat_requests force row level security;
alter table secretariat_request_turns enable row level security;
alter table secretariat_request_turns force row level security;

grant select on proposals,proposal_dispositions,secretariat_requests,secretariat_request_turns
  to boardagent_server,boardagent_backup,boardagent_migrator;
grant insert,update on proposals,secretariat_requests to boardagent_migrator;
grant insert on proposal_dispositions,secretariat_request_turns to boardagent_migrator;

create policy boardagent_backup_read on proposals for select to boardagent_backup using (true);
create policy boardagent_backup_read on proposal_dispositions for select to boardagent_backup using (true);
create policy boardagent_backup_read on secretariat_requests for select to boardagent_backup using (true);
create policy boardagent_backup_read on secretariat_request_turns for select to boardagent_backup using (true);
create policy boardagent_migrator_all on proposals for all to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_all on proposal_dispositions for all to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_all on secretariat_requests for all to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_all on secretariat_request_turns for all to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_communication_idempotency on idempotency_records
  for select to boardagent_migrator using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=boardagent_context_uuid('boardagent.member_id')
    and client_id=boardagent_context_uuid('boardagent.client_id')
  );
create policy boardagent_migrator_proposal_draft_insert on wizard_drafts
  for insert to boardagent_migrator with check (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and creator_member_id=boardagent_context_uuid('boardagent.member_id')
    and boardagent_context_board_allowed(board_id)
  );

create function boardagent_communication_actor_ready(candidate_board uuid,required_scope text)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select required_scope in ('member:propose','secretariat:admin','secretariat:message')
     and boardagent_context_board_allowed(candidate_board)
     and exists (
       select 1
         from members as actor
         join board_memberships as membership
           on membership.organization_id=actor.organization_id
          and membership.member_id=actor.id and membership.board_id=candidate_board
         join access_token_records as token
           on token.organization_id=actor.organization_id and token.member_id=actor.id
          and token.client_id=boardagent_context_uuid('boardagent.client_id')
          and token.jti=boardagent_context_uuid('boardagent.token_jti')
         join oauth_clients as client on client.id=token.client_id
         join system_instance as instance
           on instance.organization_id=actor.organization_id
          and instance.canonical_resource_uri=token.resource_uri
        where actor.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and actor.id=boardagent_context_uuid('boardagent.member_id')
          and actor.state='active' and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null or membership.active_until>transaction_timestamp())
          and client.organization_id=actor.organization_id and client.state='active'
          and token.revoked_at is null and token.expires_at>transaction_timestamp()
          and required_scope=any(token.scope_set)
          and exists (
            select 1 from onboarding_attestations as attestation
             where attestation.organization_id=actor.organization_id
               and attestation.member_id=actor.id and attestation.board_id=candidate_board
               and attestation.terms_version_id=(
                 select terms.id from onboarding_terms_versions as terms
                  where terms.organization_id=actor.organization_id
                    and terms.seat_role=membership.seat_role
                    and terms.effective_at<=transaction_timestamp()
                  order by terms.effective_at desc,terms.version desc,terms.id desc limit 1
               )
               and attestation.support_version_id=(
                 select support.id from secretary_support_versions as support
                  where support.organization_id=actor.organization_id
                    and (support.board_id=candidate_board or support.board_id is null)
                    and support.effective_at<=transaction_timestamp()
                  order by (support.board_id=candidate_board) desc,support.effective_at desc,
                           support.version desc,support.id desc limit 1
               )
          )
     )
$$;
alter function boardagent_communication_actor_ready(uuid,text) owner to boardagent_migrator;
revoke all on function boardagent_communication_actor_ready(uuid,text) from public;
grant execute on function boardagent_communication_actor_ready(uuid,text) to boardagent_server;

create function boardagent_secretariat_for_board(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select boardagent_communication_actor_ready(candidate_board,'secretariat:admin')
     and exists (
       select 1 from board_memberships as membership
        where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and membership.board_id=candidate_board
          and membership.member_id=boardagent_context_uuid('boardagent.member_id')
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null or membership.active_until>transaction_timestamp())
          and (
            membership.is_secretary
            or exists (
              select 1 from organization_role_assignments as role_assignment
               where role_assignment.organization_id=membership.organization_id
                 and role_assignment.member_id=membership.member_id
                 and role_assignment.role in ('secretariat','admin')
                 and role_assignment.active_from<=transaction_timestamp()
                 and (role_assignment.active_until is null
                      or role_assignment.active_until>transaction_timestamp())
            )
          )
     )
$$;
alter function boardagent_secretariat_for_board(uuid) owner to boardagent_migrator;
revoke all on function boardagent_secretariat_for_board(uuid) from public;
grant execute on function boardagent_secretariat_for_board(uuid) to boardagent_server;

create function boardagent_proposer_for_board(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select boardagent_communication_actor_ready(candidate_board,'member:propose')
     and exists (
       select 1 from board_memberships as membership
        where membership.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and membership.board_id=candidate_board
          and membership.member_id=boardagent_context_uuid('boardagent.member_id')
          and membership.state='active' and membership.seat_role<>'observer'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null or membership.active_until>transaction_timestamp())
          and (membership.seat_role in ('voting_member','management') or exists (
            select 1 from organization_role_assignments as role_assignment
             where role_assignment.organization_id=membership.organization_id
               and role_assignment.member_id=membership.member_id
               and role_assignment.role in ('member','management')
               and role_assignment.active_from<=transaction_timestamp()
               and (role_assignment.active_until is null
                    or role_assignment.active_until>transaction_timestamp())
          ))
     )
$$;
alter function boardagent_proposer_for_board(uuid) owner to boardagent_migrator;
revoke all on function boardagent_proposer_for_board(uuid) from public;
grant execute on function boardagent_proposer_for_board(uuid) to boardagent_server;

create function boardagent_proposal_action_authorized(candidate_id uuid,candidate_operation text)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select coalesce((
    select case candidate_operation
      when 'withdraw_proposal' then
        proposal.proposer_member_id=boardagent_context_uuid('boardagent.member_id')
        and boardagent_proposer_for_board(proposal.board_id)
      when 'approve_proposal' then boardagent_secretariat_for_board(proposal.board_id)
      when 'reject_proposal' then boardagent_secretariat_for_board(proposal.board_id)
      else false
    end
      from proposals as proposal
     where proposal.id=candidate_id and proposal.state='pending'
  ),false)
$$;
alter function boardagent_proposal_action_authorized(uuid,text) owner to boardagent_migrator;
revoke all on function boardagent_proposal_action_authorized(uuid,text) from public;
grant execute on function boardagent_proposal_action_authorized(uuid,text) to boardagent_server;

create function boardagent_secretariat_request_action_authorized(
  candidate_id uuid,candidate_operation text
)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select coalesce((
    select case candidate_operation
      when 'reply_secretariat_request' then
        request.state<>'closed' and boardagent_secretariat_for_board(request.board_id)
      when 'close_secretariat_request' then
        request.state='answered' and (
          (request.requester_member_id=boardagent_context_uuid('boardagent.member_id')
           and boardagent_communication_actor_ready(request.board_id,'secretariat:message'))
          or boardagent_secretariat_for_board(request.board_id)
        )
      else false
    end
      from secretariat_requests as request where request.id=candidate_id
  ),false)
$$;
alter function boardagent_secretariat_request_action_authorized(uuid,text)
  owner to boardagent_migrator;
revoke all on function boardagent_secretariat_request_action_authorized(uuid,text) from public;
grant execute on function boardagent_secretariat_request_action_authorized(uuid,text)
  to boardagent_server;

create policy boardagent_server_proposals_select on proposals for select to boardagent_server
  using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_secretariat_for_board(board_id)
  );
create policy boardagent_server_proposal_dispositions_select on proposal_dispositions
  for select to boardagent_server using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_secretariat_for_board(board_id)
  );
create policy boardagent_server_secretariat_requests_select on secretariat_requests
  for select to boardagent_server using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and (requester_member_id=boardagent_context_uuid('boardagent.member_id')
         or boardagent_secretariat_for_board(board_id))
  );
create policy boardagent_server_secretariat_request_turns_select on secretariat_request_turns
  for select to boardagent_server using (
    organization_id=boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and exists (select 1 from secretariat_requests as request where request.id=request_id)
  );

create function boardagent_guard_communication_root()
returns trigger
language plpgsql
security invoker
set search_path=pg_catalog
as $$
begin
  if row(new.id,new.organization_id,new.board_id,new.created_at)
       is distinct from row(old.id,old.organization_id,old.board_id,old.created_at)
     or new.row_version<>old.row_version+1 then
    raise exception 'communication root identity is immutable and row version must advance once'
      using errcode='55000';
  end if;
  if tg_table_name='proposals' then
    if row(new.proposer_member_id,new.proposal_type,new.title,new.schema_version,
           new.canonical_payload,new.payload_sha256,new.resource_references,
           new.idempotency_record_id)
       is distinct from row(old.proposer_member_id,old.proposal_type,old.title,old.schema_version,
           old.canonical_payload,old.payload_sha256,old.resource_references,
           old.idempotency_record_id)
       or old.state<>'pending' or new.state not in ('withdrawn','approved_to_draft','rejected')
       or new.closed_at is distinct from transaction_timestamp() then
      raise exception 'invalid proposal transition' using errcode='55000';
    end if;
  else
    if row(new.requester_member_id,new.topic,new.idempotency_record_id)
       is distinct from row(old.requester_member_id,old.topic,old.idempotency_record_id)
       or (old.state='open' and new.state not in ('answered','closed'))
       or (old.state='answered' and new.state not in ('answered','closed'))
       or old.state='closed'
       or (new.state='closed' and new.closed_at is distinct from transaction_timestamp())
       or (new.state<>'closed' and new.closed_at is not null) then
      raise exception 'invalid secretariat request transition' using errcode='55000';
    end if;
  end if;
  return new;
end
$$;
create trigger boardagent_proposal_root_guard before update on proposals
  for each row execute function boardagent_guard_communication_root();
create trigger boardagent_secretariat_request_root_guard before update on secretariat_requests
  for each row execute function boardagent_guard_communication_root();
create trigger boardagent_proposal_dispositions_immutable before update or delete on proposal_dispositions
  for each row execute function boardagent_reject_evidence_mutation();
create trigger boardagent_secretariat_request_turns_immutable before update or delete on secretariat_request_turns
  for each row execute function boardagent_reject_evidence_mutation();

create function boardagent_idempotency_in_progress(candidate uuid,candidate_operation text)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public
as $$
  select exists (
    select 1 from idempotency_records as record
     where record.id=candidate
       and record.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and record.actor_member_id=boardagent_context_uuid('boardagent.member_id')
       and record.client_id=boardagent_context_uuid('boardagent.client_id')
       and record.operation=candidate_operation and record.state='in_progress'
  )
$$;
alter function boardagent_idempotency_in_progress(uuid,text) owner to boardagent_migrator;
revoke all on function boardagent_idempotency_in_progress(uuid,text) from public;
grant execute on function boardagent_idempotency_in_progress(uuid,text) to boardagent_server;

create function boardagent_create_proposal(
  candidate_id uuid,candidate_board uuid,candidate_type text,candidate_title text,
  candidate_payload bytea,candidate_payload_sha256 bytea,candidate_references jsonb,
  candidate_idempotency uuid,candidate_audit_event uuid
)
returns table(proposal_id uuid,proposal_state text,result_row_version bigint,result_board_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_proposer_for_board(candidate_board)
     or not boardagent_idempotency_in_progress(candidate_idempotency,'propose_action') then
    raise exception 'proposal creation is not authorized' using errcode='42501';
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
$$;

create function boardagent_withdraw_proposal(
  candidate_id uuid,candidate_idempotency uuid,candidate_audit_event uuid
)
returns table(proposal_id uuid,proposal_state text,result_row_version bigint,result_board_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare changed proposals%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_idempotency_in_progress(candidate_idempotency,'withdraw_proposal') then
    raise exception 'proposal withdrawal is not authorized' using errcode='42501';
  end if;
  select * into changed from proposals where id=candidate_id for update;
  if changed.id is null or changed.state<>'pending'
     or changed.proposer_member_id<>boardagent_context_uuid('boardagent.member_id')
     or not boardagent_proposer_for_board(changed.board_id) then
    raise exception 'proposal unavailable' using errcode='P0002';
  end if;
  update proposals as proposal set state='withdrawn',row_version=proposal.row_version+1,
         last_audit_event_id=candidate_audit_event,closed_at=transaction_timestamp()
   where proposal.id=candidate_id and proposal.state='pending' returning proposal.* into changed;
  if changed.id is null then raise exception 'proposal unavailable' using errcode='P0002'; end if;
  return query select changed.id,changed.state,changed.row_version,changed.board_id;
end
$$;

create function boardagent_dispose_proposal(
  candidate_disposition_id uuid,candidate_id uuid,candidate_disposition text,
  candidate_reason text,candidate_draft_id uuid,candidate_draft_type text,
  candidate_signed_context bytea,candidate_context_sha256 bytea,
  candidate_idempotency uuid,candidate_audit_event uuid
)
returns table(proposal_id uuid,proposal_state text,result_row_version bigint,result_board_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare changed proposals%rowtype;
begin
  select * into changed from proposals where id=candidate_id for update;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or changed.id is null or changed.state<>'pending'
     or not boardagent_secretariat_for_board(changed.board_id)
     or candidate_disposition not in ('approved_to_draft','rejected')
     or not boardagent_idempotency_in_progress(
       candidate_idempotency,
       case candidate_disposition when 'approved_to_draft' then 'approve_proposal' else 'reject_proposal' end
     ) then
    raise exception 'proposal disposition is not authorized' using errcode='42501';
  end if;
  if candidate_disposition='approved_to_draft' then
    if candidate_reason is not null or candidate_draft_id is null
       or candidate_draft_type not in ('meeting','vote','minutes','task','proposal')
       or candidate_signed_context is null
       or octet_length(candidate_signed_context) not between 32 and 1048576
       or not boardagent_hash_is_sha256(candidate_context_sha256) then
      raise exception 'approved proposal requires an exact resulting draft'
        using errcode='22023';
    end if;
    insert into wizard_drafts(
      id,organization_id,board_id,draft_type,creator_member_id,signed_context,
      context_sha256,state,expires_at
    ) values (
      candidate_draft_id,changed.organization_id,changed.board_id,candidate_draft_type,
      boardagent_context_uuid('boardagent.member_id'),candidate_signed_context,
      candidate_context_sha256,'active',transaction_timestamp()+interval '7 days'
    );
  elsif candidate_reason is null or length(candidate_reason)=0
        or candidate_draft_id is not null or candidate_draft_type is not null
        or candidate_signed_context is not null or candidate_context_sha256 is not null then
    raise exception 'rejected proposal requires only a reason' using errcode='22023';
  end if;
  insert into proposal_dispositions(id,organization_id,board_id,proposal_id,actor_member_id,
    disposition,reason,resulting_draft_id,idempotency_record_id,audit_event_id)
  values(candidate_disposition_id,changed.organization_id,changed.board_id,changed.id,
    boardagent_context_uuid('boardagent.member_id'),candidate_disposition,candidate_reason,
    candidate_draft_id,candidate_idempotency,candidate_audit_event);
  update proposals as proposal set state=candidate_disposition,
         row_version=proposal.row_version+1,
         last_audit_event_id=candidate_audit_event,closed_at=transaction_timestamp()
   where proposal.id=changed.id and proposal.state='pending' returning proposal.* into changed;
  if changed.state is distinct from candidate_disposition then
    raise exception 'proposal is no longer pending' using errcode='40001';
  end if;
  return query select changed.id,changed.state,changed.row_version,changed.board_id;
end
$$;

create function boardagent_create_secretariat_request(
  candidate_id uuid,candidate_turn_id uuid,candidate_board uuid,candidate_topic text,
  candidate_text text,candidate_text_sha256 bytea,candidate_references jsonb,
  candidate_idempotency uuid,candidate_audit_event uuid
)
returns table(request_id uuid,request_state text,result_row_version bigint,result_board_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
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
$$;

create function boardagent_reply_secretariat_request(
  candidate_turn_id uuid,candidate_request uuid,candidate_text text,candidate_text_sha256 bytea,
  candidate_idempotency uuid,candidate_audit_event uuid
)
returns table(request_id uuid,request_state text,result_row_version bigint,result_board_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare changed secretariat_requests%rowtype;
declare next_ordinal integer;
begin
  select * into changed from secretariat_requests where id=candidate_request for update;
  if changed.id is null or changed.state='closed'
     or not boardagent_secretariat_for_board(changed.board_id)
     or not boardagent_idempotency_in_progress(candidate_idempotency,'reply_secretariat_request') then
    raise exception 'secretariat reply is not authorized' using errcode='42501';
  end if;
  select coalesce(max(turn.ordinal),0)+1 into next_ordinal
    from secretariat_request_turns as turn where turn.request_id=changed.id;
  insert into secretariat_request_turns(id,organization_id,board_id,request_id,ordinal,
    turn_kind,author_member_id,author_role,canonical_text,text_sha256,resource_references,
    idempotency_record_id,audit_event_id)
  values(candidate_turn_id,changed.organization_id,changed.board_id,changed.id,next_ordinal,
    'reply',boardagent_context_uuid('boardagent.member_id'),'secretariat',candidate_text,
    candidate_text_sha256,'[]'::jsonb,candidate_idempotency,candidate_audit_event);
  update secretariat_requests as request
     set state='answered',current_turn_id=candidate_turn_id,
         row_version=request.row_version+1,last_audit_event_id=candidate_audit_event
   where request.id=changed.id returning request.* into changed;
  return query select changed.id,changed.state,changed.row_version,changed.board_id;
end
$$;

create function boardagent_close_secretariat_request(
  candidate_request uuid,candidate_idempotency uuid,candidate_audit_event uuid
)
returns table(request_id uuid,request_state text,result_row_version bigint,result_board_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare changed secretariat_requests%rowtype;
begin
  select * into changed from secretariat_requests where id=candidate_request for update;
  if changed.id is null or changed.state<>'answered'
     or not (
       (changed.requester_member_id=boardagent_context_uuid('boardagent.member_id')
        and boardagent_communication_actor_ready(changed.board_id,'secretariat:message'))
       or boardagent_secretariat_for_board(changed.board_id)
     )
     or not boardagent_idempotency_in_progress(candidate_idempotency,'close_secretariat_request') then
    raise exception 'secretariat request close is not authorized' using errcode='42501';
  end if;
  update secretariat_requests as request set state='closed',row_version=request.row_version+1,
         last_audit_event_id=candidate_audit_event,closed_at=transaction_timestamp()
   where request.id=changed.id returning request.* into changed;
  return query select changed.id,changed.state,changed.row_version,changed.board_id;
end
$$;

do $communication_functions$
declare function_name text;
begin
  foreach function_name in array array[
    'boardagent_create_proposal(uuid,uuid,text,text,bytea,bytea,jsonb,uuid,uuid)',
    'boardagent_withdraw_proposal(uuid,uuid,uuid)',
    'boardagent_dispose_proposal(uuid,uuid,text,text,uuid,text,bytea,bytea,uuid,uuid)',
    'boardagent_create_secretariat_request(uuid,uuid,uuid,text,text,bytea,jsonb,uuid,uuid)',
    'boardagent_reply_secretariat_request(uuid,uuid,text,bytea,uuid,uuid)',
    'boardagent_close_secretariat_request(uuid,uuid,uuid)'
  ]
  loop
    execute 'alter function ' || function_name || ' owner to boardagent_migrator';
    execute 'revoke all on function ' || function_name || ' from public';
    execute 'grant execute on function ' || function_name || ' to boardagent_server';
  end loop;
end
$communication_functions$;

create function boardagent_verify_communication_audit()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public
as $$
declare expected_event text;
declare candidate_event uuid;
declare candidate_object uuid;
begin
  if tg_table_name='proposals' then
    expected_event:=case new.state when 'pending' then 'proposal_submitted'
      when 'withdrawn' then 'proposal_withdrawn'
      when 'approved_to_draft' then 'proposal_approved_to_draft'
      else 'proposal_rejected' end;
    candidate_event:=new.last_audit_event_id; candidate_object:=new.id;
  elsif tg_table_name='proposal_dispositions' then
    expected_event:=case new.disposition when 'approved_to_draft' then 'proposal_approved_to_draft'
      else 'proposal_rejected' end;
    candidate_event:=new.audit_event_id; candidate_object:=new.proposal_id;
  elsif tg_table_name='secretariat_requests' then
    expected_event:=case new.state when 'open' then 'secretariat_request_created'
      when 'answered' then 'secretariat_request_replied' else 'secretariat_request_closed' end;
    candidate_event:=new.last_audit_event_id; candidate_object:=new.id;
  else
    expected_event:=case new.turn_kind when 'request' then 'secretariat_request_created'
      else 'secretariat_request_replied' end;
    candidate_event:=new.audit_event_id; candidate_object:=new.request_id;
  end if;
  if not exists (
    select 1 from audit_events as event where event.id=candidate_event
      and event.organization_id=new.organization_id and event.event_type=expected_event
      and event.object_id=candidate_object
  ) then
    raise exception 'communication mutation lacks its exact audit event' using errcode='23503';
  end if;
  return null;
end
$$;
alter function boardagent_verify_communication_audit() owner to boardagent_migrator;
revoke all on function boardagent_verify_communication_audit() from public;
create constraint trigger boardagent_proposals_audit
after insert or update on proposals deferrable initially deferred
for each row execute function boardagent_verify_communication_audit();
create constraint trigger boardagent_proposal_dispositions_audit
after insert on proposal_dispositions deferrable initially deferred
for each row execute function boardagent_verify_communication_audit();
create constraint trigger boardagent_secretariat_requests_audit
after insert or update on secretariat_requests deferrable initially deferred
for each row execute function boardagent_verify_communication_audit();
create constraint trigger boardagent_secretariat_request_turns_audit
after insert on secretariat_request_turns deferrable initially deferred
for each row execute function boardagent_verify_communication_audit();
