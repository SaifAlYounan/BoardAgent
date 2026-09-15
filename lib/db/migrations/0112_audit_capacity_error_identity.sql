-- Identify only the capacity refusal, so clients never retry unrelated55000 integrity failures.
-- The guard,1000-event bound, rollback behavior and authority are unchanged.
create or replace function public.boardagent_guard_audit_checkpoint_capacity()
returns trigger
language plpgsql
security definer
set search_path=pg_catalog,public,pg_temp
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
      using errcode='55000',constraint='boardagent_audit_checkpoint_capacity';
  end if;
  return new;
end;
$$;
alter function public.boardagent_guard_audit_checkpoint_capacity() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_audit_checkpoint_capacity() from public;
