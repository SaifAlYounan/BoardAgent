-- BoardAgent Phase 1 / group 12: least-privilege primitives for mandatory transactions.

-- The application must know the current audit predecessor before it can construct the
-- canonical event hash. Keep the singleton hidden from runtime roles and expose only a
-- transaction-scoped, row-locking read through this SECURITY DEFINER capability.
grant select, update on audit_chain_head to boardagent_migrator;
create policy boardagent_migrator_audit_chain_head on audit_chain_head
  for all to boardagent_migrator using (true) with check (true);

alter function boardagent_advance_audit_head() owner to boardagent_migrator;
revoke all on function boardagent_advance_audit_head() from public;
grant execute on function boardagent_advance_audit_head() to boardagent_server, boardagent_worker;

create function boardagent_lock_audit_head()
returns table(last_sequence bigint, last_event_sha256 bytea, occurred_at text)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'audit append requires a managed request transaction' using errcode = '25000';
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
grant execute on function boardagent_lock_audit_head() to boardagent_server, boardagent_worker;
