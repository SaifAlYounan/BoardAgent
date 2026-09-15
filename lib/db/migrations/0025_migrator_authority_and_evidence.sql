-- BoardAgent Phase 1 / group 25: the schema owner is the non-login migrator role,
-- and every later boot migration can append an evidence event when bootstrapped.

do $membership$
begin
  execute format('grant boardagent_migrator to %I', session_user);
end
$membership$;

grant usage, create on schema public to boardagent_migrator;

do $ownership$
declare
  candidate record;
begin
  for candidate in
    select c.oid::regclass as object_name, c.relkind
      from pg_class as c
      join pg_namespace as n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('r', 'p', 'S', 'v', 'm')
     order by c.oid
  loop
    if candidate.relkind = 'S' then
      execute format('alter sequence %s owner to boardagent_migrator', candidate.object_name);
    elsif candidate.relkind = 'v' then
      execute format('alter view %s owner to boardagent_migrator', candidate.object_name);
    elsif candidate.relkind = 'm' then
      execute format('alter materialized view %s owner to boardagent_migrator', candidate.object_name);
    else
      execute format('alter table %s owner to boardagent_migrator', candidate.object_name);
    end if;
  end loop;
  for candidate in
    select p.oid::regprocedure as object_name
      from pg_proc as p
      join pg_namespace as n on n.oid = p.pronamespace
     where n.nspname = 'public'
     order by p.oid
  loop
    execute format('alter function %s owner to boardagent_migrator', candidate.object_name);
  end loop;
end
$ownership$;

alter schema public owner to boardagent_migrator;

grant select on system_instance to boardagent_migrator;
grant select, insert on audit_events to boardagent_migrator;
grant select, update on audit_chain_head to boardagent_migrator;

create policy boardagent_migrator_system_instance_read on system_instance
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_audit_event_insert on audit_events
  for insert to boardagent_migrator with check (true);

create or replace function boardagent_lock_audit_head()
returns table(last_sequence bigint, last_event_sha256 bytea, occurred_at text)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) not in ('request', 'migration') then
    raise exception 'audit append requires a managed request or migration transaction'
      using errcode = '25000';
  end if;
  return query
    select head.last_sequence,
           head.last_event_sha256,
           to_char(
             transaction_timestamp() at time zone 'UTC',
             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
           )
      from audit_chain_head as head
     where head.singleton_key
       for update;
  if not found then
    raise exception 'audit chain head is unavailable' using errcode = '55000';
  end if;
end
$$;
alter function boardagent_lock_audit_head() owner to boardagent_migrator;
revoke all on function boardagent_lock_audit_head() from public;
grant execute on function boardagent_lock_audit_head()
  to boardagent_server, boardagent_worker;
