-- Keep the published v1 checkpoint projection independent of internal admission
-- and attestation coordination columns. Future database columns are not export fields.
create or replace function boardagent_export_checkpoint_rows(candidate_request_id uuid)
returns table(table_rows jsonb, row_count bigint)
language plpgsql
stable
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  request_row export_requests%rowtype;
  scope jsonb;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker'
     or current_setting('transaction_isolation') <> 'repeatable read' then
    raise exception 'checkpoint export requires a managed repeatable-read worker transaction'
      using errcode = '25000';
  end if;
  select * into strict request_row from export_requests where id = candidate_request_id;
  scope := convert_from(request_row.scope_manifest, 'UTF8')::jsonb;
  if request_row.state <> 'queued'
     or (request_row.export_type = 'system_data' and not exists (
       select 1 from jsonb_array_elements_text(scope -> 'dataClasses') as class(value)
        where class.value = 'audit'
     )) then
    raise exception 'checkpoint component is outside the frozen request scope'
      using errcode = '42501';
  end if;
  return query
    select coalesce(jsonb_agg(normalized.row_value order by checkpoint.first_sequence),
                    '[]'::jsonb), count(*)::bigint
      from audit_checkpoints as checkpoint
      cross join lateral (
        select checkpoint.id,checkpoint.organization_id,checkpoint.first_sequence,
          checkpoint.last_sequence,checkpoint.first_event_sha256,checkpoint.last_event_sha256,
          checkpoint.canonical_manifest,checkpoint.manifest_sha256,checkpoint.signature,
          checkpoint.signing_key_id,checkpoint.created_at
      ) as exported_checkpoint
      cross join lateral (
        select jsonb_object_agg(item.key,item.value order by item.key) as row_value
          from jsonb_each_text(to_jsonb(exported_checkpoint)) as item(key,value)
      ) as normalized
     where checkpoint.organization_id = request_row.organization_id;
end;
$$;
alter function boardagent_export_checkpoint_rows(uuid) owner to boardagent_migrator;
revoke all on function boardagent_export_checkpoint_rows(uuid) from public;
grant execute on function boardagent_export_checkpoint_rows(uuid) to boardagent_worker;
