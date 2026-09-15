-- Exact completed retries return before INSERT and remain inspectable with new processes live.
-- A new operation must exclude both lifetime service leases and in-flight service transactions.
create function public.boardagent_require_runtime_maintenance_exclusion()
returns trigger language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'key maintenance requires a serializable operator transaction' using errcode='25000';
  end if;
  if not pg_try_advisory_xact_lock(424248,1) then
    raise exception 'stop server and worker before key maintenance' using errcode='55000';
  end if;
  return new;
end;
$$;
alter function public.boardagent_require_runtime_maintenance_exclusion() owner to boardagent_migrator;
revoke all on function public.boardagent_require_runtime_maintenance_exclusion() from public;
create trigger boardagent_000_runtime_maintenance_exclusion before insert on public.key_lifecycle_operations
  for each row execute function public.boardagent_require_runtime_maintenance_exclusion();
