-- Concurrent appends must not create a backlog larger than the frozen signing window.
-- Roll back the whole originating transaction; a real checkpoint releases capacity.
-- Checkpoint insertion precedes its audit event, so signing a full window remains possible.
create function public.boardagent_guard_audit_checkpoint_capacity()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public
as $$
declare
  current_head bigint;
  checkpoint_head bigint;
begin
  select head.last_sequence into strict current_head from public.audit_chain_head as head
    where head.singleton_key for update;
  select coalesce(max(checkpoint.last_sequence),0) into checkpoint_head
    from public.audit_checkpoints as checkpoint;
  if current_head-checkpoint_head>=1000 then
    raise exception 'audit checkpoint capacity exhausted; retry after a signed checkpoint'
      using errcode='55000';
  end if;
  return new;
end;
$$;
alter function public.boardagent_guard_audit_checkpoint_capacity() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_checkpoint_capacity() from public;
create trigger boardagent_audit_capacity_guard
  before insert on public.audit_events
  for each row execute function public.boardagent_guard_audit_checkpoint_capacity();
