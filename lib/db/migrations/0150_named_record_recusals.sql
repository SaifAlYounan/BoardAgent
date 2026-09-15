-- Named recusals deny current access and prospective actions; immutable history is retained.
-- No recusal waives a required minutes signature or changes a signed package.

create table public.meeting_exclusions (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  meeting_id uuid not null,
  member_id uuid not null,
  version integer not null check (version>0),
  state text not null check (state in ('excluded','lifted')),
  reason text not null check (length(reason) between 1 and 65536),
  actor_member_id uuid not null,
  consent_record_id uuid not null unique references public.consent_records(id),
  audit_event_id uuid not null unique references public.audit_events(id),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique(meeting_id,member_id,version),
  foreign key(board_id,meeting_id) references public.meetings(board_id,id),
  foreign key(organization_id,board_id) references public.boards(organization_id,id),
  foreign key(organization_id,member_id) references public.members(organization_id,id),
  foreign key(organization_id,actor_member_id) references public.members(organization_id,id)
);
alter table public.meeting_exclusions enable row level security;
alter table public.meeting_exclusions force row level security;
grant select on public.meeting_exclusions to boardagent_server,boardagent_backup;
grant select,insert on public.meeting_exclusions to boardagent_migrator;
create policy boardagent_migrator_meeting_exclusions_read on public.meeting_exclusions
  for select to boardagent_migrator using(true);
create policy boardagent_migrator_meeting_exclusions_insert on public.meeting_exclusions
  for insert to boardagent_migrator with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id'));
create policy boardagent_backup_read on public.meeting_exclusions for select to boardagent_backup using(true);
-- An excluded person may read their own exclusion history; no governance content is returned.
create policy boardagent_server_meeting_exclusions_read on public.meeting_exclusions
  for select to boardagent_server using (
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and (member_id=public.boardagent_context_uuid('boardagent.member_id')
      or public.boardagent_secretariat_for_board(board_id)));

create trigger boardagent_immutable before update or delete on public.meeting_exclusions for each row execute function public.boardagent_reject_evidence_mutation();

create table public.minutes_exclusions (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  minutes_id uuid not null,
  member_id uuid not null,
  version integer not null check (version>0),
  state text not null check (state in ('excluded','lifted')),
  reason text not null check (length(reason) between 1 and 65536),
  actor_member_id uuid not null,
  consent_record_id uuid not null unique references public.consent_records(id),
  audit_event_id uuid not null unique references public.audit_events(id),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique(minutes_id,member_id,version),
  foreign key(board_id,minutes_id) references public.minutes(board_id,id),
  foreign key(organization_id,board_id) references public.boards(organization_id,id),
  foreign key(organization_id,member_id) references public.members(organization_id,id),
  foreign key(organization_id,actor_member_id) references public.members(organization_id,id)
);
alter table public.minutes_exclusions enable row level security;
alter table public.minutes_exclusions force row level security;
grant select on public.minutes_exclusions to boardagent_server,boardagent_backup;
grant select,insert on public.minutes_exclusions to boardagent_migrator;
create policy boardagent_migrator_minutes_exclusions_read on public.minutes_exclusions
  for select to boardagent_migrator using(true);
create policy boardagent_migrator_minutes_exclusions_insert on public.minutes_exclusions
  for insert to boardagent_migrator with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id'));
create policy boardagent_backup_read on public.minutes_exclusions for select to boardagent_backup using(true);
-- An excluded person may read their own exclusion history; no governance content is returned.
create policy boardagent_server_minutes_exclusions_read on public.minutes_exclusions
  for select to boardagent_server using (
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and (member_id=public.boardagent_context_uuid('boardagent.member_id')
      or public.boardagent_secretariat_for_board(board_id)));

create trigger boardagent_immutable before update or delete on public.minutes_exclusions for each row execute function public.boardagent_reject_evidence_mutation();

alter table public.question_visibility
 add column recusal_consent_record_id uuid unique references public.consent_records(id),
 add column recusal_audit_event_id uuid unique references public.audit_events(id),
 add column lift_consent_record_id uuid unique references public.consent_records(id),
 add column lift_audit_event_id uuid unique references public.audit_events(id);
grant insert,update on public.question_visibility to boardagent_migrator;
create policy boardagent_migrator_recusal_question_insert on public.question_visibility
 for insert to boardagent_migrator with check(current_setting('boardagent.transaction_scope',true)='request' and organization_id=public.boardagent_context_uuid('boardagent.organization_id') and effect='exclude');
create policy boardagent_migrator_recusal_question_update on public.question_visibility
 for update to boardagent_migrator using(organization_id=public.boardagent_context_uuid('boardagent.organization_id') and effect='exclude')
 with check(current_setting('boardagent.transaction_scope',true)='request' and organization_id=public.boardagent_context_uuid('boardagent.organization_id') and effect='exclude');
-- Authored question visibility grants cannot manufacture a confirmed exclusion.
create policy boardagent_server_question_grants_only on public.question_visibility
 as restrictive for insert to boardagent_server with check(effect='grant' and recusal_consent_record_id is null and lift_consent_record_id is null);

-- Worker jobs carry no human request context; the installed single tenant supplies their scope.
create function public.boardagent_recusal_organization() returns uuid language sql stable security definer
set search_path=pg_catalog,public,pg_temp as $$
 select case when current_setting('boardagent.transaction_scope',true)='worker'
  then (select organization_id from public.system_instance where singleton_key)
  else public.boardagent_context_uuid('boardagent.organization_id') end
$$;
alter function public.boardagent_recusal_organization() owner to boardagent_migrator;
revoke all on function public.boardagent_recusal_organization() from public;
create function public.boardagent_recusal_root(candidate_type text,candidate_id uuid)
returns table(board_id uuid,meeting_id uuid,minutes_id uuid,question_id uuid)
language plpgsql stable security definer set search_path=pg_catalog,public,pg_temp as $$
declare org uuid:=public.boardagent_recusal_organization();
begin
 case candidate_type
 when 'meeting' then return query select m.board_id,m.id,null::uuid,null::uuid from public.meetings m where m.id=candidate_id and m.organization_id=org;
 when 'minutes' then return query select m.board_id,m.meeting_id,m.id,null::uuid from public.minutes m where m.id=candidate_id and m.organization_id=org;
 when 'question' then return query select q.board_id,null::uuid,null::uuid,q.id from public.management_questions q where q.id=candidate_id and q.organization_id=org;
 when 'meeting_attendance' then return query select a.board_id,a.meeting_id,null::uuid,null::uuid from public.meeting_attendance a where a.id=candidate_id and a.organization_id=org;
 when 'meeting_transcript' then return query select t.board_id,t.meeting_id,null::uuid,null::uuid from public.meeting_transcripts t where t.id=candidate_id and t.organization_id=org;
 when 'transcript_challenge' then return query select t.board_id,t.meeting_id,null::uuid,null::uuid from public.transcript_challenges c join public.meeting_transcript_versions v on v.id=c.transcript_version_id join public.meeting_transcripts t on t.id=v.transcript_id where c.id=candidate_id and c.organization_id=org;
 when 'minutes_review_item' then return query select m.board_id,m.meeting_id,m.id,null::uuid from public.minutes_review_items r join public.minutes m on m.id=r.minutes_id where r.id=candidate_id and m.organization_id=org;
 when 'task' then return query select t.board_id,t.source_meeting_id,t.source_minutes_id,null::uuid from public.tasks t where t.id=candidate_id and t.organization_id=org;
 when 'task_evidence' then return query select t.board_id,t.source_meeting_id,t.source_minutes_id,null::uuid from public.task_evidence e join public.tasks t on t.id=e.task_id where e.id=candidate_id and t.organization_id=org;
 when 'agenda_version' then return query select r.* from public.agenda_versions p cross join lateral public.boardagent_recusal_root('meeting',p.meeting_id) r where p.id=candidate_id and p.organization_id=org;
 when 'transcript_version' then return query select r.* from public.meeting_transcript_versions p cross join lateral public.boardagent_recusal_root('meeting_transcript',p.transcript_id) r where p.id=candidate_id and p.organization_id=org;
 when 'minutes_package' then return query select r.* from public.minutes_signature_packages p cross join lateral public.boardagent_recusal_root('minutes',p.minutes_id) r where p.id=candidate_id and p.organization_id=org;
 else return;
 end case;
end $$;
alter function public.boardagent_recusal_root(text,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_recusal_root(text,uuid) from public;

create function public.boardagent_member_record_recused(candidate_type text,candidate_id uuid,candidate_member uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp as $$
 select exists(select 1 from public.boardagent_recusal_root(candidate_type,candidate_id) root where
   public.boardagent_member_board_recused(root.board_id,candidate_member)
   or coalesce((select e.state='excluded' from public.meeting_exclusions e where e.meeting_id=root.meeting_id and e.member_id=candidate_member order by version desc limit 1),false)
   or coalesce((select e.state='excluded' from public.minutes_exclusions e where e.minutes_id=root.minutes_id and e.member_id=candidate_member order by version desc limit 1),false)
   -- Deny includes every active cause; lifting a direct recusal never removes inherited/role exclusions.
   or exists(select 1 from public.question_visibility e where e.question_id=root.question_id and e.effect='exclude'
     and e.active_from<=transaction_timestamp() and (e.active_until is null or e.active_until>transaction_timestamp())
     and (e.grantee_member_id=candidate_member or exists(select 1 from public.board_memberships membership
       where membership.board_id=root.board_id and membership.member_id=candidate_member and membership.seat_role=e.grantee_seat_role)))
 )
$$;
alter function public.boardagent_member_record_recused(text,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_member_record_recused(text,uuid,uuid) from public;
grant execute on function public.boardagent_member_record_recused(text,uuid,uuid) to boardagent_server,boardagent_worker;

create function public.boardagent_recusal_covers(root_type text,root_id uuid,candidate_type text,candidate_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp as $$
 select (root_type=candidate_type and root_id=candidate_id) or exists(
 select 1 from public.boardagent_recusal_root(candidate_type,candidate_id) r
 where case root_type when 'meeting' then r.meeting_id=root_id when 'minutes' then r.minutes_id=root_id when 'question' then r.question_id=root_id else false end)
$$;
alter function public.boardagent_recusal_covers(text,uuid,text,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_recusal_covers(text,uuid,text,uuid) from public;
grant execute on function public.boardagent_recusal_covers(text,uuid,text,uuid) to boardagent_server;

create function public.boardagent_prepare_record_recusal(candidate_request jsonb)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare org uuid:=public.boardagent_context_uuid('boardagent.organization_id');
 b uuid; m uuid; o uuid; kind text; root_version bigint; member_name text; prior_id uuid; prior_version integer:=0; prior_state text;
begin
 if (current_setting('boardagent.transaction_scope',true)='request'
   and jsonb_typeof(candidate_request)='object'
   and candidate_request ?& array['boardId','objectType','objectId','memberId','operation','reason','idempotencyKey']
   and not exists(select 1 from jsonb_object_keys(candidate_request) k where k not in ('boardId','objectType','objectId','memberId','operation','reason','idempotencyKey'))
   and candidate_request->>'objectType' in ('question','meeting','minutes')
   and candidate_request->>'operation' in ('add','lift')
   and length(candidate_request->>'reason') between 1 and 65536
   and length(candidate_request->>'idempotencyKey') between 16 and 256) is distinct from true then
  raise exception 'record recusal is unavailable' using errcode='42501';
 end if;
 b:=(candidate_request->>'boardId')::uuid; m:=(candidate_request->>'memberId')::uuid;
 o:=(candidate_request->>'objectId')::uuid; kind:=candidate_request->>'objectType';
 if not public.boardagent_secretariat_for_board(b)
   or public.boardagent_member_record_recused(kind,o,public.boardagent_context_uuid('boardagent.member_id')) then
  raise exception 'record recusal is unavailable' using errcode='42501';
 end if;
 -- Same board/root/member lock order as ordinary mutations; serialize recusal cause versions.
 perform 1 from public.boards where id=b and organization_id=org and state='active' for update;
 if not found then raise exception 'record recusal is unavailable' using errcode='42501'; end if;
 if kind='meeting' then select row_version into root_version from public.meetings where id=o and board_id=b and organization_id=org for update;
 elsif kind='minutes' then select row_version into root_version from public.minutes where id=o and board_id=b and organization_id=org for update;
 else select row_version into root_version from public.management_questions where id=o and board_id=b and organization_id=org for update;
 end if;
 select member.display_name into member_name from public.members member join public.board_memberships membership
  on membership.organization_id=member.organization_id and membership.member_id=member.id
  where member.organization_id=org and member.id=m and member.state='active'
   and membership.board_id=b and membership.state='active' and membership.active_from<=transaction_timestamp()
   and (membership.active_until is null or membership.active_until>transaction_timestamp()) for update of member,membership;
 if root_version is null or member_name is null then raise exception 'record recusal is unavailable' using errcode='42501'; end if;
 perform 1 from public.member_feed_sync_counters where organization_id=org and member_id=m for update;
 if kind='question' then
  select id,case when active_until is null or active_until>transaction_timestamp() then 'excluded' else 'lifted' end
   into prior_id,prior_state from public.question_visibility where question_id=o and grantee_member_id=m and effect='exclude'
    and inherited_document_id is null and inherited_object_id is null
   order by active_from desc,id desc limit 1;
 else
  if kind='meeting' then select id,version,state into prior_id,prior_version,prior_state from public.meeting_exclusions where meeting_id=o and member_id=m order by version desc limit 1;
  else select id,version,state into prior_id,prior_version,prior_state from public.minutes_exclusions where minutes_id=o and member_id=m order by version desc limit 1; end if;
 end if;
 if (candidate_request->>'operation'='add' and prior_state='excluded') or (candidate_request->>'operation'='lift' and prior_state is distinct from 'excluded') then
  raise exception 'record recusal transition is unavailable' using errcode='42501'; end if;
 return jsonb_build_object('schemaVersion','boardagent.record-recusal-consent.v1','request',candidate_request,
  'rootVersion',root_version::text,'memberDisplayName',member_name,'priorExclusionId',prior_id,'priorVersion',coalesce(prior_version,0));
end $$;
alter function public.boardagent_prepare_record_recusal(jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_record_recusal(jsonb) from public;
grant execute on function public.boardagent_prepare_record_recusal(jsonb) to boardagent_server;

CREATE FUNCTION public.boardagent_apply_record_recusal(candidate_consent uuid, candidate_exclusion uuid, candidate_audit uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
    and consent.action_code='manage_recusal' and consent.target_type in ('question','meeting','minutes')
    and consent.package_sha256 is null
    and stage.state='confirmed' and stage.confirmed_at=consent.confirmed_at
    and stage.action_code=consent.action_code and stage.target_type=consent.target_type
    and stage.target_id=consent.target_id and stage.board_id=consent.board_id
    and stage.actor_member_id=consent.actor_member_id and stage.client_id=consent.client_id
    and stage.token_jti=consent.token_jti and stage.payload_sha256=consent.payload_sha256
    and stage.payload_sha256=pg_catalog.sha256(stage.canonical_payload)
    and stage.canonical_schema='boardagent.record-recusal-consent.v1'
    and exists(select 1 from public.input_required_attempts a where a.id=consent.input_required_attempt_id
      and a.stage_id=stage.id and a.state='confirmed' and a.response_action='accept'
      and a.original_name='manage_recusal')
    and public.boardagent_is_uuid_v7(candidate_exclusion)) is distinct from true then
    raise exception 'record recusal lacks exact confirmed authority' using errcode='42501';
  end if;
  payload:=convert_from(stage.canonical_payload,'UTF8')::jsonb;
  request:=payload->'request';
  snapshot:=public.boardagent_prepare_record_recusal(request);
  if payload is distinct from snapshot or (request->>'boardId')::uuid<>consent.board_id or request->>'objectType'<>consent.target_type or (request->>'objectId')::uuid<>consent.target_id
    or not exists(select 1 from public.audit_events a
      where a.id=candidate_audit and a.organization_id=consent.organization_id
        and a.board_id=consent.board_id and a.object_type=consent.target_type and a.object_id=consent.target_id
        and a.event_type='recusal_changed' and a.actor_member_id=consent.actor_member_id
        and a.client_id=consent.client_id and a.token_jti=consent.token_jti
        and a.consent_record_id=consent.id
        and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'->>'exclusionId'=candidate_exclusion::text
        and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'->'request'=request) then
    raise exception 'record recusal lacks exact confirmed evidence' using errcode='42501';
  end if;
  if request->>'operation'='add' and (
    exists(select 1 from public.action_stages a where a.organization_id=consent.organization_id and a.board_id=consent.board_id
      and a.state='active' and (a.actor_member_id=(request->>'memberId')::uuid or a.acting_for_member_id=(request->>'memberId')::uuid)
      and public.boardagent_recusal_covers(consent.target_type,consent.target_id,a.target_type,a.target_id))
    or exists(select 1 from public.pending_action_feed f where f.organization_id=consent.organization_id and f.board_id=consent.board_id
      and f.member_id=(request->>'memberId')::uuid and f.state='pending'
      and public.boardagent_recusal_covers(consent.target_type,consent.target_id,f.object_type,f.object_id))) then
    raise exception 'record recusal active projections remain' using errcode='42501';
  end if;
  if consent.target_type='question' then
    if request->>'operation'='add' then
      insert into public.question_visibility(id,organization_id,board_id,question_id,grantee_member_id,effect,reason,created_by,recusal_consent_record_id,recusal_audit_event_id)
       values(candidate_exclusion,consent.organization_id,consent.board_id,consent.target_id,(request->>'memberId')::uuid,'exclude',request->>'reason',consent.actor_member_id,consent.id,candidate_audit);
    else
      update public.question_visibility set active_until=transaction_timestamp(),lift_consent_record_id=consent.id,lift_audit_event_id=candidate_audit
       where id=(payload->>'priorExclusionId')::uuid and effect='exclude' and grantee_member_id=(request->>'memberId')::uuid;
    end if;
  elsif consent.target_type='meeting' then
    insert into public.meeting_exclusions(id,organization_id,board_id,meeting_id,member_id,version,state,reason,actor_member_id,consent_record_id,audit_event_id)
      values(candidate_exclusion,consent.organization_id,consent.board_id,consent.target_id,(request->>'memberId')::uuid,
        (payload->>'priorVersion')::integer+1,case request->>'operation' when 'add' then 'excluded' else 'lifted' end,request->>'reason',consent.actor_member_id,consent.id,candidate_audit);
  else
    insert into public.minutes_exclusions(id,organization_id,board_id,minutes_id,member_id,version,state,reason,actor_member_id,consent_record_id,audit_event_id)
      values(candidate_exclusion,consent.organization_id,consent.board_id,consent.target_id,(request->>'memberId')::uuid,
        (payload->>'priorVersion')::integer+1,case request->>'operation' when 'add' then 'excluded' else 'lifted' end,request->>'reason',consent.actor_member_id,consent.id,candidate_audit);
  end if;
end $function$;
alter function public.boardagent_apply_record_recusal(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_apply_record_recusal(uuid,uuid,uuid) from public;
grant execute on function public.boardagent_apply_record_recusal(uuid,uuid,uuid) to boardagent_server;

create policy boardagent_named_recusal_deny on public.meetings as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('meeting',id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('meeting',id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.meeting_versions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.agenda_versions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.meeting_rsvps as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.meeting_attendance as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.meeting_transcripts as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('meeting',meeting_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.tasks as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('task',id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('task',id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.agenda_items as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('agenda_version',agenda_version_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('agenda_version',agenda_version_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.meeting_transcript_versions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('meeting_transcript',transcript_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('meeting_transcript',transcript_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.transcript_turns as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.transcript_verifications as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.transcript_challenges as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.transcript_challenge_dispositions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('transcript_challenge',challenge_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('transcript_challenge',challenge_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.transcript_question_links as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('transcript_version',transcript_version_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_versions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_review_items as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_review_withdrawals as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes_review_item',review_item_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes_review_item',review_item_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_review_dispositions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes_review_item',review_item_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes_review_item',review_item_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_diffs as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_action_declarations as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_signature_packages as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_signature_requirements as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes_package',package_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes_package',package_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_signatures as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes_package',package_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes_package',package_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_signature_supersessions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes_package',old_package_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes_package',old_package_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_resign_requirements as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',minutes_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_action_item_dispositions as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('task',task_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('task',task_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.task_evidence as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('task',task_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('task',task_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.task_evidence_reviews as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('task_evidence',evidence_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('task_evidence',evidence_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.task_closures as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('task',task_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('task',task_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.minutes_correction_cycles as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('minutes',original_minutes_id,public.boardagent_context_uuid('boardagent.member_id')) and not public.boardagent_member_record_recused('minutes',replacement_minutes_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('minutes',original_minutes_id,public.boardagent_context_uuid('boardagent.member_id')) and not public.boardagent_member_record_recused('minutes',replacement_minutes_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.task_correction_cycles as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused('task',prior_task_id,public.boardagent_context_uuid('boardagent.member_id')) and not public.boardagent_member_record_recused('task',replacement_task_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused('task',prior_task_id,public.boardagent_context_uuid('boardagent.member_id')) and not public.boardagent_member_record_recused('task',replacement_task_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.notices as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused(object_type,object_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused(object_type,object_id,public.boardagent_context_uuid('boardagent.member_id')));

create policy boardagent_named_recusal_deny on public.pending_action_feed as restrictive for all to boardagent_server using(not public.boardagent_member_record_recused(object_type,object_id,public.boardagent_context_uuid('boardagent.member_id'))) with check(not public.boardagent_member_record_recused(object_type,object_id,public.boardagent_context_uuid('boardagent.member_id')));

CREATE OR REPLACE FUNCTION public.boardagent_apply_meeting_change(candidate_meeting_id uuid, expected_row_version bigint, candidate_action text, candidate_consent_record_id uuid, expected_payload_sha256 bytea, expected_package_sha256 bytea, candidate_meeting_version_id uuid, candidate_agenda_version_id uuid)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  changed_version bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_action not in ('amend_meeting','cancel_meeting','complete_meeting')
     or not boardagent_hash_is_sha256(expected_payload_sha256)
     or not boardagent_hash_is_sha256(expected_package_sha256)
     or not exists (
       select 1 from consent_records as consent
       join action_stages as stage on stage.id=consent.stage_id
       join meetings as meeting on meeting.id=candidate_meeting_id
        where consent.id=candidate_consent_record_id
          and consent.organization_id=meeting.organization_id
          and consent.board_id=meeting.board_id
          and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
          and consent.client_id=boardagent_context_uuid('boardagent.client_id')
          and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
          and consent.action_code=candidate_action
          and consent.target_type='meeting'
          and consent.target_id=meeting.id
          and consent.payload_sha256=expected_payload_sha256
          and stage.package_sha256=expected_package_sha256
          and meeting.organization_id=boardagent_context_uuid('boardagent.organization_id')
          and boardagent_context_board_allowed(meeting.board_id)
 and not public.boardagent_member_record_recused('meeting',meeting.id,public.boardagent_context_uuid('boardagent.member_id'))
          and boardagent_meeting_secretary_for_board(meeting.board_id)
          and (
            candidate_action<>'amend_meeting'
            or exists (
              select 1 from meeting_versions as meeting_version
              join agenda_versions as agenda
                on agenda.id=candidate_agenda_version_id
               and agenda.meeting_id=meeting_version.meeting_id
               and agenda.meeting_version_id=meeting_version.id
               where meeting_version.id=candidate_meeting_version_id
                 and meeting_version.meeting_id=meeting.id
                 and meeting_version.version=(
                   select current_version.version+1
                     from meeting_versions as current_version
                    where current_version.id=meeting.current_version_id
                 )
                 and meeting_version.consent_record_id=consent.id
                 and meeting_version.notice_package_sha256=expected_package_sha256
            )
          )
     ) then
    raise exception 'meeting transition lacks exact confirmed authority' using errcode='42501';
  end if;

  if candidate_action='amend_meeting' then
    update meetings as meeting
       set title=meeting_version.canonical_title,
           scheduled_start=meeting_version.scheduled_start,
           scheduled_end=meeting_version.scheduled_end,
           current_version_id=meeting_version.id,
           current_agenda_version_id=candidate_agenda_version_id,
           row_version=meeting.row_version+1
      from meeting_versions as meeting_version
     where meeting.id=candidate_meeting_id
       and meeting.row_version=expected_row_version
       and meeting.state='called'
       and meeting_version.id=candidate_meeting_version_id
     returning meeting.row_version into changed_version;
  elsif candidate_action='cancel_meeting' then
    update meetings
       set state='cancelled',cancelled_at=transaction_timestamp(),row_version=row_version+1
     where id=candidate_meeting_id
       and row_version=expected_row_version
       and state in ('draft','called')
     returning row_version into changed_version;
  else
    if exists (
      select 1 from notices as attendee
       where attendee.object_type='meeting'
         and attendee.object_id=candidate_meeting_id
         and attendee.notice_type='meeting_called'
         and not exists (
           select 1 from meeting_attendance as attendance
            where attendance.meeting_id=candidate_meeting_id
              and attendance.member_id=attendee.recipient_member_id
              and not exists (
                select 1 from meeting_attendance as later
                 where later.corrects_id=attendance.id
              )
         )
    ) then
      raise exception 'meeting attendance is incomplete' using errcode='23514';
    end if;
    update meetings
       set state='completed',completed_at=transaction_timestamp(),row_version=row_version+1
     where id=candidate_meeting_id
       and row_version=expected_row_version
       and state='called'
     returning row_version into changed_version;
  end if;
  if changed_version is null then
    raise exception 'meeting changed before confirmed transition' using errcode='40001';
  end if;
  return changed_version;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_apply_minutes_terminal_transition(candidate_minutes_id uuid, expected_row_version bigint, candidate_state text, candidate_consent_record_id uuid)
 RETURNS TABLE(next_row_version bigint, superseded_task_ids uuid[])
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  locked_minutes minutes%rowtype;
  current_version minutes_versions%rowtype;
  current_package minutes_signature_packages%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_state not in ('finalized','cancelled') then
    raise exception 'terminal minutes transition requires a managed request transaction'
      using errcode = '25000';
  end if;
  select minutes.* into locked_minutes
    from minutes
   where minutes.id=candidate_minutes_id
     and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(minutes.board_id)
 and not public.boardagent_member_record_recused('minutes',minutes.id,public.boardagent_context_uuid('boardagent.member_id'))
   for update of minutes;
  if not found or locked_minutes.row_version<>expected_row_version then
    return;
  end if;
  select version.* into current_version
    from minutes_versions as version
   where version.id=locked_minutes.current_version_id
     and version.minutes_id=locked_minutes.id;
  if not found then
    return;
  end if;
  if locked_minutes.current_signature_package_id is not null then
    select package.* into current_package
      from minutes_signature_packages as package
     where package.id=locked_minutes.current_signature_package_id
       and package.minutes_id=locked_minutes.id
     for update of package;
    if not found then
      return;
    end if;
  end if;
  if not exists (
    select 1 from board_memberships as membership
     where membership.organization_id=locked_minutes.organization_id
       and membership.board_id=locked_minutes.board_id
       and membership.member_id=boardagent_context_uuid('boardagent.member_id')
       and membership.is_secretary
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
  ) then
    return;
  end if;
  if not exists (
    select 1
      from consent_records as consent
      join action_stages as stage on stage.id=consent.stage_id
      join input_required_attempts as attempt
        on attempt.id=consent.input_required_attempt_id
     where consent.id=candidate_consent_record_id
       and consent.organization_id=locked_minutes.organization_id
       and consent.board_id=locked_minutes.board_id
       and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
       and consent.client_id=boardagent_context_uuid('boardagent.client_id')
       and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
       and consent.action_code=case candidate_state
         when 'finalized' then 'finalize_minutes' else 'cancel_minutes' end
       and consent.target_type='minutes'
       and consent.target_id=locked_minutes.id
       and consent.package_sha256=case candidate_state
         when 'finalized' then current_package.package_sha256
         else current_version.canonical_sha256 end
       and stage.state='active'
       and stage.payload_sha256=consent.payload_sha256
       and stage.package_sha256=consent.package_sha256
       and attempt.stage_id=stage.id
       and attempt.state='prepared'
       and attempt.original_name=consent.action_code
  ) then
    return;
  end if;

  if candidate_state='finalized' then
    if locked_minutes.state<>'signature_ready'
       or locked_minutes.current_signature_package_id is null
       or current_package.state<>'current'
       or not exists (
         select 1 from minutes_action_declarations as declaration
          where declaration.minutes_id=locked_minutes.id
            and declaration.minutes_version_id=locked_minutes.current_version_id
       )
       or exists (
         select 1
           from minutes_signature_requirements as requirement
           left join minutes_signatures as signature
             on signature.package_id=requirement.package_id
            and signature.signer_member_id=requirement.member_id
          where requirement.package_id=locked_minutes.current_signature_package_id
            and requirement.requirement='required'
            and signature.id is null
       )
       or exists (
         select 1 from tasks as task
          where task.source_minutes_id=locked_minutes.id
            and task.source_minutes_version_id=locked_minutes.current_version_id
            and task.state='draft'
       ) then
      return;
    end if;
    update minutes_signature_packages
       set state='terminal'
     where id=locked_minutes.current_signature_package_id and state='current';
    update minutes_resign_requirements
       set state='resolved',resolution='package_terminal',resolved_at=transaction_timestamp()
     where minutes_id=locked_minutes.id and state='pending';
    superseded_task_ids:=array[]::uuid[];
    update minutes
       set state='finalized',finalized_at=transaction_timestamp(),row_version=row_version+1
     where id=locked_minutes.id and row_version=expected_row_version
    returning row_version into next_row_version;
  else
    if locked_minutes.state not in ('unpublished_draft','published_review','signature_ready') then
      return;
    end if;
    if locked_minutes.current_signature_package_id is not null then
      update minutes_signature_packages
         set state='terminal'
       where id=locked_minutes.current_signature_package_id and state='current';
    end if;
    update minutes_resign_requirements
       set state='resolved',resolution='package_terminal',resolved_at=transaction_timestamp()
     where minutes_id=locked_minutes.id and state='pending';
    with superseded as (
      update tasks
         set state='superseded',row_version=row_version+1
       where source_minutes_id=locked_minutes.id and state='draft'
      returning id
    )
    select coalesce(array_agg(id order by id),array[]::uuid[])
      into superseded_task_ids
      from superseded;
    update minutes
       set state='cancelled',cancelled_at=transaction_timestamp(),row_version=row_version+1
     where id=locked_minutes.id and row_version=expected_row_version
    returning row_version into next_row_version;
  end if;
  return next;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_lock_task_source(candidate_board_id uuid, candidate_minutes_id uuid, candidate_minutes_version_id uuid)
 RETURNS TABLE(meeting_id uuid, minutes_sha256 bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board_id)
     or not boardagent_secretariat_for_board(candidate_board_id) then
    raise exception 'task source lock requires the managed secretariat request context'
      using errcode = '25000';
  end if;
  return query
    select minutes.meeting_id,version.canonical_sha256
      from minutes
      join minutes_versions as version
        on version.minutes_id=minutes.id
       and version.id=candidate_minutes_version_id
     where minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and minutes.board_id=candidate_board_id
       and minutes.id=candidate_minutes_id
 and not public.boardagent_member_record_recused('minutes',minutes.id,public.boardagent_context_uuid('boardagent.member_id'))
     -- The minutes version is immutable. Lock the mutable minutes root while reading the
     -- version hash; attempting to row-lock the immutable version would require an UPDATE
     -- policy that the request boundary deliberately does not possess.
     for key share of minutes;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_apply_task_terminal_transition(candidate_task_id uuid, expected_row_version bigint, candidate_state text, candidate_consent_record_id uuid)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  locked_task tasks%rowtype;
  closure_row task_closures%rowtype;
  next_row_version bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_state not in ('completed','cancelled') then
    raise exception 'terminal task transition requires a managed request transaction'
      using errcode = '25000';
  end if;
  select task.* into locked_task
    from tasks as task
   where task.id=candidate_task_id
     and task.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(task.board_id)
 and not public.boardagent_member_record_recused('task',task.id,public.boardagent_context_uuid('boardagent.member_id'))
   for update of task;
  if not found or locked_task.row_version<>expected_row_version then
    return null;
  end if;
  if not exists (
    select 1 from board_memberships as membership
     where membership.organization_id=locked_task.organization_id
       and membership.board_id=locked_task.board_id
       and membership.member_id=boardagent_context_uuid('boardagent.member_id')
       and membership.is_secretary
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
  ) then
    return null;
  end if;
  if not exists (
    select 1
      from consent_records as consent
      join action_stages as stage on stage.id=consent.stage_id
      join input_required_attempts as attempt
        on attempt.id=consent.input_required_attempt_id
     where consent.id=candidate_consent_record_id
       and consent.organization_id=locked_task.organization_id
       and consent.board_id=locked_task.board_id
       and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
       and consent.client_id=boardagent_context_uuid('boardagent.client_id')
       and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
       and consent.action_code=case candidate_state
         when 'completed' then 'complete_task' else 'cancel_task' end
       and consent.target_type='task'
       and consent.target_id=locked_task.id
       and consent.package_sha256=locked_task.task_sha256
       and stage.state='active'
       and attempt.state='prepared'
  ) then
    return null;
  end if;
  if candidate_state='completed' then
    if locked_task.state<>'evidence_submitted'
       or exists (
         select 1 from task_evidence as evidence
          where evidence.task_id=locked_task.id and evidence.state='submitted'
       ) then
      return null;
    end if;
    select closure.* into closure_row
      from task_closures as closure
     where closure.task_id=locked_task.id
       and closure.consent_record_id=candidate_consent_record_id
       and closure.secretary_member_id=boardagent_context_uuid('boardagent.member_id');
    if not found
       or jsonb_array_length(closure_row.accepted_evidence_manifest)=0
       or not exists (
         select 1 from task_evidence as primary_evidence
          where primary_evidence.id=closure_row.primary_evidence_id
            and primary_evidence.task_id=locked_task.id
            and primary_evidence.state='accepted'
       )
       or jsonb_array_length(closure_row.accepted_evidence_manifest)<>(
         select count(*) from task_evidence as evidence
          where evidence.task_id=locked_task.id and evidence.state='accepted'
       )
       or exists (
         select 1
           from task_evidence as evidence
           join task_evidence_reviews as review
             on review.evidence_id=evidence.id and review.decision='accepted'
          where evidence.task_id=locked_task.id and evidence.state='accepted'
            and not exists (
              select 1
                from jsonb_array_elements(closure_row.accepted_evidence_manifest) as item(value)
               where item.value->>'evidenceId'=evidence.id::text
                 and item.value->>'evidenceSha256'=encode(evidence.canonical_sha256,'hex')
                 and item.value->>'reviewId'=review.id::text
            )
       ) then
      return null;
    end if;
    update tasks as task
       set state='completed',completed_at=transaction_timestamp(),
           row_version=task.row_version+1
     where task.id=locked_task.id and task.row_version=expected_row_version
    returning task.row_version into next_row_version;
  else
    if locked_task.state not in ('draft','open','in_progress','evidence_submitted') then
      return null;
    end if;
    update tasks as task
       set state='cancelled',cancelled_at=transaction_timestamp(),
           row_version=task.row_version+1
     where task.id=locked_task.id and task.row_version=expected_row_version
    returning task.row_version into next_row_version;
  end if;
  return next_row_version;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_guard_recused_board_recipient()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare recipient uuid;
begin
  recipient:=(to_jsonb(new)->>case when tg_table_name='notices' then 'recipient_member_id' else 'member_id' end)::uuid;
  if current_user in ('boardagent_server','boardagent_worker','boardagent_migrator')
    and new.board_id is not null and (public.boardagent_member_board_recused(new.board_id,recipient) or public.boardagent_member_record_recused(new.object_type,new.object_id,recipient)) then
    raise exception 'board recipient is unavailable' using errcode='42501';
  end if;
  return new;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_member_board_recused(candidate_board uuid, candidate_member uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
  select coalesce((select exclusion.state='excluded' from public.board_exclusions exclusion
    where exclusion.organization_id=public.boardagent_recusal_organization()
      and exclusion.board_id=candidate_board and exclusion.member_id=candidate_member
    order by exclusion.version desc limit 1),false)
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_task_due_candidates(candidate_organization_id uuid, candidate_board_id uuid, candidate_through timestamp with time zone, candidate_limit integer, candidate_task_class text)
 RETURNS TABLE(task_id uuid, owner_member_id uuid, row_version bigint, due_at text, task_sha256 text, entitlement_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or candidate_board_id is null
     or not public.boardagent_is_uuid_v7(candidate_board_id)
     or candidate_through is null
     or candidate_through>transaction_timestamp()
     or candidate_limit is null
     or candidate_limit not between 1 and 1000
     or candidate_task_class is null
     or candidate_task_class not in ('minutes_action_item','standalone_task') then
    raise exception 'task due scan scope, watermark, limit, or class is invalid' using errcode='22023';
  end if;
  if not exists (
    select 1
      from public.system_instance as instance
      join public.boards as board
        on board.organization_id=instance.organization_id
       and board.id=candidate_board_id
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
       and board.state='active'
  ) then
    raise exception 'task due scan target is unavailable' using errcode='42501';
  end if;

  return query
    select task.id,
           task.owner_member_id,
           task.row_version,
           to_char(task.due_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           encode(task.task_sha256,'hex'),
           membership.entitlement_generation
      from public.tasks as task
      join public.members as member
        on member.organization_id=task.organization_id
       and member.id=task.owner_member_id
       and member.state='active'
      join public.board_memberships as membership
        on membership.organization_id=task.organization_id
       and membership.board_id=task.board_id
       and membership.member_id=task.owner_member_id
       and membership.state='active'
       and membership.active_until is null
       and membership.active_from<=transaction_timestamp()
     where task.organization_id=candidate_organization_id
       and task.board_id=candidate_board_id and not public.boardagent_member_record_recused('task',task.id,task.owner_member_id)
       and task.state in ('open','in_progress','evidence_submitted')
       and ((candidate_task_class='minutes_action_item' and task.source_minutes_id is not null)
         or (candidate_task_class='standalone_task' and task.source_minutes_id is null))
       and task.due_at<=candidate_through
       and not exists (
         select 1
           from public.notices as notice
          where notice.organization_id=task.organization_id
            and notice.board_id=task.board_id
            and notice.notice_type='task_due'
            and notice.object_type='task'
            and notice.object_id=task.id
            and notice.recipient_member_id=task.owner_member_id
       )
     order by task.due_at,task.id
     for update of task,membership skip locked
     limit candidate_limit;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_commit_task_due_projection(candidate_organization_id uuid, candidate_board_id uuid, candidate_task_id uuid, candidate_through timestamp with time zone, candidate_notice_id uuid, candidate_feed_id uuid, candidate_audit_event_id uuid, candidate_task_class text)
 RETURNS TABLE(task_id uuid, feed_sequence bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  target record;
  sequence_value bigint;
  created_at_value text;
  safe_refs_text text;
  notice_content_text text;
  feed_payload_text text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or candidate_board_id is null
     or not public.boardagent_is_uuid_v7(candidate_board_id)
     or candidate_task_id is null
     or not public.boardagent_is_uuid_v7(candidate_task_id)
     or candidate_through is null
     or candidate_through>transaction_timestamp()
     or candidate_notice_id is null
     or not public.boardagent_is_uuid_v7(candidate_notice_id)
     or candidate_feed_id is null
     or not public.boardagent_is_uuid_v7(candidate_feed_id)
     or candidate_audit_event_id is null
     or not public.boardagent_is_uuid_v7(candidate_audit_event_id)
     or candidate_notice_id=candidate_feed_id
     or candidate_notice_id=candidate_audit_event_id
     or candidate_feed_id=candidate_audit_event_id then
    raise exception 'task due projection input is invalid' using errcode='22023';
  end if;
  if candidate_task_class is null
     or candidate_task_class not in ('minutes_action_item','standalone_task') then
    raise exception 'task due projection class is invalid' using errcode='22023';
  end if;

  select task.id as task_id,
         task.owner_member_id,
         task.row_version,
         to_char(task.due_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as due_at,
         encode(task.task_sha256,'hex') as task_sha256,
         membership.entitlement_generation
    into target
    from public.tasks as task
    join public.boards as board
      on board.organization_id=task.organization_id
     and board.id=task.board_id
     and board.state='active'
    join public.members as member
      on member.organization_id=task.organization_id
     and member.id=task.owner_member_id
     and member.state='active'
    join public.board_memberships as membership
      on membership.organization_id=task.organization_id
     and membership.board_id=task.board_id
     and membership.member_id=task.owner_member_id
     and membership.state='active'
     and membership.active_until is null
     and membership.active_from<=transaction_timestamp()
   where task.id=candidate_task_id
     and task.organization_id=candidate_organization_id
     and task.board_id=candidate_board_id and not public.boardagent_member_record_recused('task',task.id,task.owner_member_id)
     and task.state in ('open','in_progress','evidence_submitted')
     and ((candidate_task_class='minutes_action_item' and task.source_minutes_id is not null)
       or (candidate_task_class='standalone_task' and task.source_minutes_id is null))
     and task.due_at<=candidate_through
     and not exists (
       select 1
         from public.notices as notice
        where notice.organization_id=task.organization_id
          and notice.board_id=task.board_id
          and notice.notice_type='task_due'
          and notice.object_type='task'
          and notice.object_id=task.id
          and notice.recipient_member_id=task.owner_member_id
     )
   for update of task,membership;
  if not found then
    return;
  end if;

  if not exists (
    select 1
      from public.audit_events as audit
     where audit.id=candidate_audit_event_id
       and audit.organization_id=candidate_organization_id
       and audit.board_id=candidate_board_id
       and audit.event_type='notice_delivered'
       and audit.object_type='task'
       and audit.object_id=candidate_task_id
       and audit.object_version=target.row_version
       and convert_from(audit.canonical_payload,'UTF8')::jsonb->>'origin'='worker'
  ) then
    raise exception 'task due projection audit binding is unavailable' using errcode='23503';
  end if;

  select greatest(
           coalesce((select max(notice.feed_sequence)
                       from public.notices as notice
                      where notice.board_id=candidate_board_id
                        and notice.recipient_member_id=target.owner_member_id),0),
           coalesce((select max(feed.feed_sequence)
                       from public.pending_action_feed as feed
                      where feed.board_id=candidate_board_id
                        and feed.member_id=target.owner_member_id),0),
           coalesce((select max(tombstone.feed_sequence)
                       from public.feed_tombstones as tombstone
                      where tombstone.board_id=candidate_board_id
                        and tombstone.member_id=target.owner_member_id),0)
         )+1
    into sequence_value;
  created_at_value := to_char(
    transaction_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
  );
  safe_refs_text :=
    '{"dueAt":'||to_jsonb(target.due_at)::text||
    ',"taskSha256":'||to_jsonb(target.task_sha256)::text||'}';
  notice_content_text :=
    '{"dueAt":'||to_jsonb(target.due_at)::text||
    ',"noticeType":"task_due"'||
    ',"recipientMemberId":'||to_jsonb(target.owner_member_id::text)::text||
    ',"taskId":'||to_jsonb(target.task_id::text)::text||
    ',"taskSha256":'||to_jsonb(target.task_sha256)::text||
    ',"taskVersion":'||target.row_version::text||'}';
  feed_payload_text :=
    '{"actionState":"pending"'||
    ',"createdAt":'||to_jsonb(created_at_value)::text||
    ',"deltaType":"task_due"'||
    ',"entitlementGeneration":'||target.entitlement_generation::text||
    ',"objectId":'||to_jsonb(target.task_id::text)::text||
    ',"objectType":"task"'||
    ',"objectVersion":'||target.row_version::text||
    ',"safeRefs":'||safe_refs_text||
    ',"schemaVersion":"boardagent.pending-action.v1"'||
    ',"sequence":'||to_jsonb(sequence_value::text)::text||'}';

  insert into public.notices(
    id,organization_id,board_id,notice_type,object_type,object_id,object_version,
    recipient_member_id,content_sha256,feed_sequence,audit_event_id
  ) values (
    candidate_notice_id,candidate_organization_id,candidate_board_id,
    'task_due','task',target.task_id,target.row_version,target.owner_member_id,
    pg_catalog.sha256(convert_to(notice_content_text,'UTF8')),sequence_value,
    candidate_audit_event_id
  );

  insert into public.pending_action_feed(
    id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
    action_type,object_type,object_id,object_version,visibility_sha256,
    canonical_payload,payload_sha256,notice_id,audit_event_id
  ) values (
    candidate_feed_id,candidate_organization_id,candidate_board_id,target.owner_member_id,
    target.entitlement_generation,sequence_value,'task_due','task',target.task_id,
    target.row_version,pg_catalog.sha256(convert_to(safe_refs_text,'UTF8')),
    convert_to(feed_payload_text,'UTF8'),pg_catalog.sha256(convert_to(feed_payload_text,'UTF8')),
    candidate_notice_id,candidate_audit_event_id
  );

  task_id := target.task_id;
  feed_sequence := sequence_value;
  return next;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_notice_webhook_targets(candidate_notice_id uuid)
 RETURNS TABLE(organization_id uuid, board_id uuid, member_id uuid, webhook_id uuid, wake_class text)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'notice fanout requires a managed worker transaction' using errcode='25000';
  end if;
  return query
    select notice.organization_id,notice.board_id,notice.recipient_member_id,webhook.id,
           case when feed.state='pending' then 'pending_action'::text else 'notice'::text end
      from public.notices as notice
      join public.members as member
        on member.organization_id=notice.organization_id
       and member.id=notice.recipient_member_id and member.state='active'
      join public.board_memberships as membership
        on membership.organization_id=notice.organization_id
       and membership.board_id=notice.board_id
       and membership.member_id=notice.recipient_member_id
       and membership.state='active' and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
      join public.pending_action_feed as feed
        on feed.notice_id=notice.id and feed.organization_id=notice.organization_id
       and feed.board_id=notice.board_id and feed.member_id=notice.recipient_member_id
       and feed.entitlement_generation=membership.entitlement_generation
       and feed.state in ('pending','resolved')
      join public.member_webhooks as webhook
        on webhook.organization_id=notice.organization_id
       and webhook.member_id=notice.recipient_member_id and webhook.state='active'
     where not public.boardagent_member_board_recused(notice.board_id,notice.recipient_member_id) and not public.boardagent_member_record_recused(notice.object_type,notice.object_id,notice.recipient_member_id) and notice.id=candidate_notice_id and notice.state in ('committed','delivered')
       and (case when feed.state='pending' then 'pending_action' else 'notice' end)
           =any(webhook.event_classes)
     order by webhook.id;
end
$function$
;

-- Retain new authority history in existing scoped system-data export classes.
CREATE OR REPLACE FUNCTION public.boardagent_export_system_table_rows(candidate_request_id uuid, candidate_class text, candidate_table text)
 RETURNS TABLE(table_rows jsonb, row_count bigint)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  request_row public.export_requests%rowtype;
  scope jsonb;
  scope_kind text;
  scope_member_id uuid;
  allowed boolean := false;
  has_organization_id boolean := false;
  has_board_id boolean := false;
  member_predicate text;
  row_predicate text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or current_setting('transaction_isolation')<>'repeatable read' then
    raise exception 'system export reads require a managed repeatable-read worker transaction'
      using errcode='25000';
  end if;
  select request.* into strict request_row
    from public.export_requests as request where request.id=candidate_request_id;
  scope := convert_from(request_row.scope_manifest,'UTF8')::jsonb;
  scope_kind := scope->>'scope';
  scope_member_id := nullif(scope->>'memberId','')::uuid;
  if request_row.state<>'queued'
     or request_row.export_type<>'system_data'
     or scope_kind not in ('organization','board','member_portability')
     or (scope_kind='organization' and (request_row.board_id is not null or scope_member_id is not null))
     or (scope_kind='board' and (request_row.board_id is null or scope_member_id is not null))
     or (scope_kind='member_portability' and (request_row.board_id is not null or scope_member_id is null))
     or not exists (
       select 1 from jsonb_array_elements_text(scope->'dataClasses') as class(value)
        where class.value=candidate_class
     ) then
    raise exception 'system export component is outside the frozen request scope'
      using errcode='42501';
  end if;

  allowed := case candidate_class
    when 'identity_authority' then candidate_table=any(array[
      'board_exclusions',
      'company_admin_proposals','member_admin_delegations','administrative_authority_changes',
      'accountable_principals','members','organization_role_assignments','board_memberships',
      'membership_versions','onboarding_terms_versions','onboarding_attestations',
      'secretary_support_versions'
    ])
    when 'governance' then candidate_table=any(array[
      'organizations','system_instance','boards','board_versions','governance_profiles',
      'governance_seat_rules','governance_rule_templates','governance_citations','rulesets',
      'matter_types','ruleset_rules','rule_citations','rule_overrides','matter_evaluations'
    ])
    when 'documents' then candidate_table=any(array[
      'documents','document_versions','document_access_grants','document_circulations',
      'circulation_recipients','document_exclusions','document_validation_attempts'
    ])
    when 'management' then candidate_table=any(array[
      'management_submission_threads','management_submission_versions',
      'management_revision_requests','management_revision_replies',
      'management_submission_dispositions','management_questions',
      'management_question_turns','management_question_answers','question_visibility',
      'question_decision_links'
    ])
    when 'meetings' then candidate_table=any(array[
      'meeting_exclusions',
      'meetings','meeting_versions','agenda_versions','agenda_items','meeting_rsvps',
      'meeting_attendance','meeting_transcripts','meeting_transcript_versions',
      'transcript_turns','transcript_verifications','transcript_question_links',
      'transcript_challenges','transcript_challenge_dispositions'
    ])
    when 'minutes_tasks' then candidate_table=any(array[
      'minutes_exclusions',
      'minutes','minutes_versions','minutes_diffs','minutes_review_items',
      'minutes_review_withdrawals','minutes_review_dispositions',
      'minutes_action_declarations','minutes_action_item_dispositions',
      'minutes_signature_packages','minutes_signature_requirements','minutes_signatures',
      'minutes_signature_supersessions','minutes_resign_requirements',
      'minutes_correction_cycles','tasks','task_evidence','task_evidence_reviews',
      'task_closures','task_correction_cycles'
    ])
    when 'decisions' then candidate_table=any(array[
      'approval_rules','resolution_versions','decision_packages',
      'decision_package_components','votes','vote_electorate','vote_exclusions',
      'vote_source_update_causes','vote_source_update_dispositions','ballots',
      'ballot_dispositions','proxy_grants','proxy_revocations','vote_outcomes',
      'vote_certificates','vote_supersessions'
    ])
    when 'audit' then candidate_table='audit_checkpoints'
    when 'operations' then candidate_table=any(array[
      'config_receipts','clock_health_samples','retention_snapshots','deletion_tombstones',
      'notices','pending_action_feed','feed_tombstones'
    ])
    else false
  end;
  if not allowed then
    raise exception 'system export table is not on the secret-free allowlist'
      using errcode='42501';
  end if;

  select exists (
    select 1 from information_schema.columns as column_definition
     where column_definition.table_schema='public'
       and column_definition.table_name=candidate_table
       and column_definition.column_name='organization_id'
  ) into has_organization_id;
  select exists (
    select 1 from information_schema.columns as column_definition
     where column_definition.table_schema='public'
       and column_definition.table_name=candidate_table
       and column_definition.column_name='board_id'
  ) into has_board_id;

  if scope_kind='organization' then
    if has_organization_id then
      row_predicate := 'source_row.organization_id=$1';
    elsif candidate_table='organizations' then
      row_predicate := 'source_row.id=$1';
    else
      row_predicate := case candidate_table
        when 'agenda_items' then
          'exists (select 1 from public.agenda_versions as parent where parent.id=source_row.agenda_version_id and parent.organization_id=$1)'
        when 'circulation_recipients' then
          'exists (select 1 from public.document_versions as parent where parent.id=source_row.document_version_id and parent.organization_id=$1)'
        when 'decision_package_components' then
          'exists (select 1 from public.decision_packages as parent where parent.id=source_row.decision_package_id and parent.organization_id=$1)'
        when 'ballot_dispositions' then
          'exists (select 1 from public.ballots as parent where parent.id=source_row.prior_ballot_id and parent.organization_id=$1)'
        when 'document_search' then
          'exists (select 1 from public.documents as parent where parent.id=source_row.document_id and parent.organization_id=$1)'
        when 'governance_seat_rules' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.organization_id=$1)'
        when 'governance_rule_templates' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.organization_id=$1)'
        when 'governance_citations' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.organization_id=$1)'
        when 'matter_types' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.organization_id=$1)'
        when 'ruleset_rules' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.organization_id=$1)'
        when 'rule_citations' then
          'exists (select 1 from public.ruleset_rules as rule join public.rulesets as parent on parent.id=rule.ruleset_id where rule.id=source_row.rule_id and parent.organization_id=$1)'
        when 'transcript_turns' then
          'exists (select 1 from public.meeting_transcript_versions as parent where parent.id=source_row.transcript_version_id and parent.organization_id=$1)'
        when 'minutes_diffs' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.organization_id=$1)'
        when 'minutes_action_item_dispositions' then
          'exists (select 1 from public.tasks as parent where parent.id=source_row.task_id and parent.organization_id=$1)'
        when 'minutes_signature_requirements' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.package_id and parent.organization_id=$1)'
        when 'minutes_signature_supersessions' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.old_package_id and parent.organization_id=$1)'
        when 'minutes_resign_requirements' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.organization_id=$1)'
        else null
      end;
    end if;
  elsif scope_kind='board' then
    if has_board_id then
      row_predicate := 'source_row.board_id=$2';
    elsif candidate_table='boards' then
      row_predicate := 'source_row.id=$2 and source_row.organization_id=$1';
    elsif candidate_table='organizations' then
      row_predicate := 'source_row.id=$1';
    elsif candidate_table='system_instance' then
      row_predicate := 'source_row.organization_id=$1';
    elsif candidate_table='members' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.board_memberships as membership where membership.board_id=$2 and membership.member_id=source_row.id)';
    elsif candidate_table='accountable_principals' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.members as member join public.board_memberships as membership on membership.member_id=member.id where member.accountable_principal_id=source_row.id and membership.board_id=$2)';
    elsif candidate_table='onboarding_terms_versions' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.onboarding_attestations as attestation where attestation.board_id=$2 and attestation.terms_version_id=source_row.id)';
    else
      row_predicate := case candidate_table
        when 'agenda_items' then
          'exists (select 1 from public.agenda_versions as parent where parent.id=source_row.agenda_version_id and parent.board_id=$2)'
        when 'circulation_recipients' then
          'exists (select 1 from public.document_versions as parent where parent.id=source_row.document_version_id and parent.board_id=$2)'
        when 'decision_package_components' then
          'exists (select 1 from public.decision_packages as parent where parent.id=source_row.decision_package_id and parent.board_id=$2)'
        when 'ballot_dispositions' then
          'exists (select 1 from public.ballots as parent where parent.id=source_row.prior_ballot_id and parent.board_id=$2)'
        when 'document_search' then
          'source_row.board_id=$2'
        when 'governance_seat_rules' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.board_id=$2)'
        when 'governance_rule_templates' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.board_id=$2)'
        when 'governance_citations' then
          'exists (select 1 from public.governance_profiles as parent where parent.id=source_row.profile_id and parent.board_id=$2)'
        when 'matter_types' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.board_id=$2)'
        when 'ruleset_rules' then
          'exists (select 1 from public.rulesets as parent where parent.id=source_row.ruleset_id and parent.board_id=$2)'
        when 'rule_citations' then
          'exists (select 1 from public.ruleset_rules as rule join public.rulesets as parent on parent.id=rule.ruleset_id where rule.id=source_row.rule_id and parent.board_id=$2)'
        when 'transcript_turns' then
          'exists (select 1 from public.meeting_transcript_versions as parent where parent.id=source_row.transcript_version_id and parent.board_id=$2)'
        when 'minutes_diffs' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.board_id=$2)'
        when 'minutes_action_item_dispositions' then
          'exists (select 1 from public.tasks as parent where parent.id=source_row.task_id and parent.board_id=$2)'
        when 'minutes_signature_requirements' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.package_id and parent.board_id=$2)'
        when 'minutes_signature_supersessions' then
          'exists (select 1 from public.minutes_signature_packages as parent where parent.id=source_row.old_package_id and parent.board_id=$2)'
        when 'minutes_resign_requirements' then
          'exists (select 1 from public.minutes as parent where parent.id=source_row.minutes_id and parent.board_id=$2)'
        else null
      end;
    end if;
  else
    select string_agg(format('source_row.%I=$2',column_definition.column_name),' or '
                      order by column_definition.ordinal_position)
      into member_predicate
      from information_schema.columns as column_definition
     where column_definition.table_schema='public'
       and column_definition.table_name=candidate_table
       and column_definition.column_name=any(array[
         'member_id','actor_member_id','acting_for_member_id','author_member_id',
         'proposer_member_id','requester_member_id','owner_member_id',
         'principal_member_id','caster_member_id','holder_member_id','revoker_member_id',
         'recipient_member_id','grantee_member_id','signer_member_id','secretary_member_id',
         'management_author_id','recorder_member_id','challenger_member_id',
         'close_actor_member_id','selected_by','requested_by','issued_by','confirmed_by',
         'authorized_by','created_by'
       ]);
    if candidate_table='organizations' then
      row_predicate := 'source_row.id=$1';
    elsif candidate_table='members' then
      row_predicate := 'source_row.organization_id=$1 and source_row.id=$2';
    elsif candidate_table='boards' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.board_memberships as membership where membership.board_id=source_row.id and membership.member_id=$2)';
    elsif candidate_table='accountable_principals' then
      row_predicate := 'source_row.organization_id=$1 and exists (select 1 from public.members as member where member.accountable_principal_id=source_row.id and member.id=$2)';
    elsif candidate_table='company_admin_proposals' then
      row_predicate := 'source_row.organization_id=$1 and (source_row.issuer_member_id=$2 or source_row.target_member_id=$2)';
    elsif candidate_table='member_admin_delegations' then
      row_predicate := 'source_row.organization_id=$1 and (source_row.member_id=$2 or source_row.issuer_member_id=$2)';
    elsif candidate_table='administrative_authority_changes' then
      row_predicate := 'source_row.organization_id=$1 and (
        source_row.actor_member_id=$2
        or (source_row.record_type=''company_admin_proposal'' and exists(
          select 1 from public.company_admin_proposals p where p.organization_id=$1 and p.id=source_row.record_id
            and (p.issuer_member_id=$2 or p.target_member_id=$2)))
        or (source_row.record_type=''company_admin_assignment'' and exists(
          select 1 from public.organization_role_assignments a where a.organization_id=$1 and a.id=source_row.record_id and a.member_id=$2))
        or (source_row.record_type=''member_admin_delegation'' and exists(
          select 1 from public.member_admin_delegations d where d.organization_id=$1 and d.id=source_row.record_id
            and (d.member_id=$2 or d.issuer_member_id=$2))))';
    elsif member_predicate is not null then
      row_predicate := case when has_organization_id
        then format('source_row.organization_id=$1 and (%s)',member_predicate)
        else format('(%s)',member_predicate)
      end;
    end if;
  end if;

  if row_predicate is null then
    return query select '[]'::jsonb,0::bigint;
    return;
  end if;
  return query execute format(
    'select coalesce(jsonb_agg(normalized.row_value order by normalized.row_value::text),''[]''::jsonb),count(*)::bigint
       from public.%I as source_row
       cross join lateral (
         select jsonb_object_agg(item.key,item.value order by item.key) as row_value
           from jsonb_each_text(to_jsonb(source_row)) as item(key,value)
       ) as normalized
      where %s',
    candidate_table,row_predicate
  ) using request_row.organization_id,
          case when scope_kind='board' then request_row.board_id else scope_member_id end;
end
$function$
;
