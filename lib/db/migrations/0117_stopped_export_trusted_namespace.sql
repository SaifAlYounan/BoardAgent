-- Keep the temporary namespace explicitly last, matching every runtime-callable
-- security-definer boundary. Preserve the already committed migration ledger.
alter function public.boardagent_stopped_export_requests(uuid)
  set search_path=pg_catalog,public,pg_temp;
