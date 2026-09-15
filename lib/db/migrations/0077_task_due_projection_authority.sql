-- BoardAgent Phase 4 / group 77: bounded task-due candidate locking and
-- content-safe reminder projection. This authority never advances task state.

grant select on
  public.boards,
  public.members,
  public.board_memberships,
  public.tasks,
  public.notices,
  public.pending_action_feed,
  public.feed_tombstones,
  public.audit_events
to boardagent_migrator;
grant insert on public.notices,public.pending_action_feed to boardagent_migrator;

create policy boardagent_migrator_task_due_board_read on public.boards
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_member_read on public.members
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_membership_read on public.board_memberships
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_task_read on public.tasks
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_notice_read on public.notices
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_notice_insert on public.notices
  for insert to boardagent_migrator
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_feed_read on public.pending_action_feed
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_feed_insert on public.pending_action_feed
  for insert to boardagent_migrator
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_tombstone_read on public.feed_tombstones
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_task_due_audit_read on public.audit_events
  for select to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');

create function public.boardagent_task_due_candidates(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_through timestamptz,
  candidate_limit integer,
  candidate_task_class text
)
returns table(
  task_id uuid,
  owner_member_id uuid,
  row_version bigint,
  due_at text,
  task_sha256 text,
  entitlement_generation bigint
)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
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
       and task.board_id=candidate_board_id
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
$$;

create function public.boardagent_commit_task_due_projection(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_task_id uuid,
  candidate_through timestamptz,
  candidate_notice_id uuid,
  candidate_feed_id uuid,
  candidate_audit_event_id uuid,
  candidate_task_class text
)
returns table(task_id uuid,feed_sequence bigint)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
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
     and task.board_id=candidate_board_id
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
$$;

alter function public.boardagent_task_due_candidates(uuid,uuid,timestamptz,integer,text)
  owner to boardagent_migrator;
alter function public.boardagent_commit_task_due_projection(uuid,uuid,uuid,timestamptz,uuid,uuid,uuid,text)
  owner to boardagent_migrator;

revoke all on function public.boardagent_task_due_candidates(uuid,uuid,timestamptz,integer,text)
  from public;
revoke all on function public.boardagent_commit_task_due_projection(uuid,uuid,uuid,timestamptz,uuid,uuid,uuid,text)
  from public;

grant execute on function public.boardagent_task_due_candidates(uuid,uuid,timestamptz,integer,text)
  to boardagent_worker;
grant execute on function public.boardagent_commit_task_due_projection(uuid,uuid,uuid,timestamptz,uuid,uuid,uuid,text)
  to boardagent_worker;
