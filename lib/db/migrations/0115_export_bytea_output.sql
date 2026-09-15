-- Keep the directly callable scoped audit projection in postgres-text-v1 hex even
-- under a worker connection configured for escape output. No authority change.
alter function public.boardagent_export_audit_event_rows(uuid) set bytea_output='hex';
