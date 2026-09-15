-- Runtime startup/readiness may inspect immutable migration metadata, but cannot
-- edit history, apply migrations, or make an incompatible database look supported.
grant select on public.schema_migrations to boardagent_server, boardagent_worker;
revoke insert, update, delete, truncate, references, trigger on public.schema_migrations
  from boardagent_server, boardagent_worker;
