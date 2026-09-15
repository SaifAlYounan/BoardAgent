-- A late signature must not turn a valid-but-lagged chain into permanently invalid
-- persisted evidence. Preserve the actual history; never redate or reseal the outage.
create function public.boardagent_guard_checkpoint_cadence()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public
as $$
declare
  oldest_at timestamptz;
begin
  select event.occurred_at into strict oldest_at from public.audit_events as event
    where event.sequence=new.first_sequence and event.organization_id=new.organization_id;
  if new.created_at<oldest_at or new.created_at-oldest_at>interval '15 minutes' then
    raise exception 'checkpoint cannot satisfy the historical signing time window'
      using errcode='23514';
  end if;
  return new;
end;
$$;
alter function public.boardagent_guard_checkpoint_cadence() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_checkpoint_cadence() from public;
create trigger boardagent_audit_checkpoint_cadence_guard
  before insert on public.audit_checkpoints
  for each row execute function public.boardagent_guard_checkpoint_cadence();
