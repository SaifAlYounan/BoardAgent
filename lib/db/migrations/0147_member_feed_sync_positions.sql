-- Cursor positions describe changes to the live feed projection, independently of
-- immutable source/notice feed_sequence and canonical payloads. A transactional
-- counter per person serializes allocation through commit across all their boards.
-- This is derived metadata; it confers no object authority and stores no content.
lock table public.pending_action_feed,public.feed_tombstones in share row exclusive mode;
create table public.member_feed_sync_counters (
  organization_id uuid not null,
  member_id uuid not null,
  last_sequence bigint not null check(last_sequence>0),
  primary key (organization_id,member_id),
  foreign key (organization_id,member_id) references public.members(organization_id,id)
);
create table public.member_feed_sync_positions (
  organization_id uuid not null,
  board_id uuid not null,
  member_id uuid not null,
  entry_kind text not null check(entry_kind in ('feed','tombstone')),
  entry_id uuid not null,
  feed_id uuid references public.pending_action_feed(id),
  tombstone_id uuid references public.feed_tombstones(id),
  change_sequence bigint not null check(change_sequence>0),
  primary key(entry_kind,entry_id),
  unique(organization_id,member_id,change_sequence),
  foreign key(organization_id,board_id) references public.boards(organization_id,id),
  foreign key(organization_id,member_id) references public.members(organization_id,id),
  check((entry_kind='feed' and feed_id=entry_id and feed_id is not null and tombstone_id is null)
     or (entry_kind='tombstone' and tombstone_id=entry_id and tombstone_id is not null and feed_id is null))
);
create unique index member_feed_sync_source_feed on public.member_feed_sync_positions(feed_id)
  where feed_id is not null;
create unique index member_feed_sync_source_tombstone on public.member_feed_sync_positions(tombstone_id)
  where tombstone_id is not null;

-- The migration runs before runtime resumes. Retain every existing source row and
-- hash; legacy cursor positions are explicitly resynchronized by the v2 reader.
-- FORCE RLS also applies to the migration owner. These read-only policies exist
-- only inside this migration transaction and are removed after the backfill.
create policy boardagent_feed_sync_migration_read on public.pending_action_feed
  for select to boardagent_migrator using(true);
create policy boardagent_tombstone_sync_migration_read on public.feed_tombstones
  for select to boardagent_migrator using(true);
insert into public.member_feed_sync_positions(
  organization_id,board_id,member_id,entry_kind,entry_id,feed_id,tombstone_id,change_sequence
)
select organization_id,board_id,member_id,entry_kind,entry_id,feed_id,tombstone_id,
       row_number() over(partition by organization_id,member_id
                        order by feed_sequence,board_id,entry_kind,entry_id)
from (
  select organization_id,board_id,member_id,'feed'::text as entry_kind,id as entry_id,
         id as feed_id,null::uuid as tombstone_id,feed_sequence
    from public.pending_action_feed
  union all
  select organization_id,board_id,member_id,'tombstone',id,null::uuid,id,feed_sequence
    from public.feed_tombstones
) as existing;
insert into public.member_feed_sync_counters(organization_id,member_id,last_sequence)
select organization_id,member_id,max(change_sequence)
  from public.member_feed_sync_positions group by organization_id,member_id;
drop policy boardagent_feed_sync_migration_read on public.pending_action_feed;
drop policy boardagent_tombstone_sync_migration_read on public.feed_tombstones;

alter table public.member_feed_sync_counters enable row level security;
alter table public.member_feed_sync_counters force row level security;
alter table public.member_feed_sync_positions enable row level security;
alter table public.member_feed_sync_positions force row level security;
revoke all on public.member_feed_sync_counters,public.member_feed_sync_positions
  from public,boardagent_server,boardagent_worker,boardagent_backup;
grant select,insert,update on public.member_feed_sync_counters,public.member_feed_sync_positions
  to boardagent_migrator;
create policy member_feed_sync_counter_internal on public.member_feed_sync_counters
  to boardagent_migrator using(true) with check(true);
create policy member_feed_sync_position_internal on public.member_feed_sync_positions
  to boardagent_migrator using(true) with check(true);
grant select on public.member_feed_sync_counters,public.member_feed_sync_positions to boardagent_backup;
create policy member_feed_sync_counter_backup on public.member_feed_sync_counters
  for select to boardagent_backup using(true);
create policy member_feed_sync_position_backup on public.member_feed_sync_positions
  for select to boardagent_backup using(true);
grant select on public.member_feed_sync_positions to boardagent_server;
create policy member_feed_sync_position_read on public.member_feed_sync_positions
  for select to boardagent_server using(
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and member_id=public.boardagent_context_uuid('boardagent.member_id')
    and ((entry_kind='feed' and exists(
      select 1 from public.pending_action_feed as source
       where source.id=feed_id and source.organization_id=member_feed_sync_positions.organization_id
         and source.board_id=member_feed_sync_positions.board_id
         and source.member_id=member_feed_sync_positions.member_id
    )) or (entry_kind='tombstone' and exists(
      select 1 from public.feed_tombstones as source
       where source.id=tombstone_id and source.organization_id=member_feed_sync_positions.organization_id
         and source.board_id=member_feed_sync_positions.board_id
         and source.member_id=member_feed_sync_positions.member_id
    )))
  );

create function public.boardagent_track_feed_sync_position()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  kind text;
  next_sequence bigint;
begin
  if tg_table_schema<>'public' or tg_table_name not in ('pending_action_feed','feed_tombstones') then
    raise exception 'invalid feed projection trigger target' using errcode='23514';
  end if;
  if tg_op='UPDATE' then
    if new.id<>old.id or new.organization_id<>old.organization_id
       or new.board_id<>old.board_id or new.member_id<>old.member_id then
      raise exception 'feed projection identity is immutable' using errcode='23514';
    end if;
    if new.state is not distinct from old.state
       and new.resolved_at is not distinct from old.resolved_at then return null; end if;
  end if;
  kind:=case when tg_table_name='pending_action_feed' then 'feed' else 'tombstone' end;
  insert into public.member_feed_sync_counters(organization_id,member_id,last_sequence)
    values(new.organization_id,new.member_id,1)
    on conflict(organization_id,member_id) do update
      set last_sequence=public.member_feed_sync_counters.last_sequence+1
    returning last_sequence into next_sequence;
  insert into public.member_feed_sync_positions(
    organization_id,board_id,member_id,entry_kind,entry_id,feed_id,tombstone_id,change_sequence
  ) values(new.organization_id,new.board_id,new.member_id,kind,new.id,
           case when kind='feed' then new.id end,
           case when kind='tombstone' then new.id end,next_sequence)
    on conflict(entry_kind,entry_id) do update set change_sequence=excluded.change_sequence;
  return null;
end
$$;
alter function public.boardagent_track_feed_sync_position() owner to boardagent_migrator;
revoke all on function public.boardagent_track_feed_sync_position()
  from public,boardagent_server,boardagent_worker,boardagent_backup;
create trigger boardagent_feed_sync_position after insert or update on public.pending_action_feed
  for each row execute function public.boardagent_track_feed_sync_position();
create trigger boardagent_tombstone_sync_position after insert on public.feed_tombstones
  for each row execute function public.boardagent_track_feed_sync_position();
