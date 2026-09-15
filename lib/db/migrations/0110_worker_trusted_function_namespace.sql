-- Preserve0098's namespace boundary for helpers added/replaced by0103 through0109.
-- PostgreSQL searches temporary relations/types first when pg_temp is omitted.
-- Pin it last; retain every owner, EXECUTE grant and permission check.
alter function public.boardagent_schedule_audit_checkpoint(uuid)
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_schedule_periodic_jobs()
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_guard_checkpoint_cadence()
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_guard_audit_checkpoint_capacity()
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_guard_worker_producer_identity()
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_audit_checkpoint_snapshot(uuid)
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_guard_audit_checkpoint_insert()
  set search_path=pg_catalog,public,pg_temp;
