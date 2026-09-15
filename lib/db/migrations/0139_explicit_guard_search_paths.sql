-- Keep the common function lookup boundary explicit after lifecycle redefinitions.
-- PostgreSQL must not search the session temporary schema before the trusted schemas.
-- Function bodies, ownership, grants and original migrations remain unchanged.
alter function public.boardagent_guard_member_webhook_update()
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_guard_oauth_request_state()
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_guard_onboarding_browser_stage()
  set search_path=pg_catalog,public,pg_temp;
alter function public.boardagent_register_runtime_key(uuid,uuid,text,text,text,jsonb,text)
  set search_path=pg_catalog,public,pg_temp;
