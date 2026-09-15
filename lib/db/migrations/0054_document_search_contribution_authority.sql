-- BoardAgent Phase 2: update the contributor-owned search projection without granting
-- a documents:contribute-only request raw read access to canonical search text.

grant select, insert on public.document_search to boardagent_migrator;
grant update(current_version_id, canonical_text_sha256, search_text, indexed_at)
  on public.document_search to boardagent_migrator;

create policy boardagent_migrator_document_search_read on public.document_search
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_document_search_insert on public.document_search
  for insert to boardagent_migrator with check (true);
create policy boardagent_migrator_document_search_update on public.document_search
  for update to boardagent_migrator using (true) with check (true);

create function public.boardagent_commit_document_version_projection(
  candidate_document uuid,
  candidate_board uuid,
  expected_current_version uuid,
  candidate_version uuid,
  candidate_sha256 bytea,
  candidate_text text
)
returns boolean
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  changed integer;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board)
     or octet_length(candidate_sha256) <> 32
     or not boardagent_document_permission(candidate_document, 'contribute') then
    return false;
  end if;

  if not exists (
    select 1
      from public.documents as document
      join public.document_versions as version
        on version.organization_id = document.organization_id
       and version.board_id = document.board_id
       and version.document_id = document.id
       and version.id = candidate_version
     where document.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and document.board_id = candidate_board
       and document.id = candidate_document
       and document.state = 'active'
       and document.current_version_id = expected_current_version
       and version.sha256 = candidate_sha256
       and convert_from(version.canonical_bytes, 'UTF8') = candidate_text
  ) then
    return false;
  end if;
  if exists (
    select 1 from public.document_search
     where document_id = candidate_document and board_id <> candidate_board
  ) then
    return false;
  end if;

  if expected_current_version <> candidate_version then
    update public.documents
       set current_version_id = candidate_version,
           row_version = row_version + 1
     where id = candidate_document
       and organization_id = boardagent_context_uuid('boardagent.organization_id')
       and board_id = candidate_board
       and current_version_id = expected_current_version;
    get diagnostics changed = row_count;
    if changed <> 1 then
      return false;
    end if;
  end if;

  insert into public.document_search(
    document_id,board_id,current_version_id,canonical_text_sha256,search_text,indexed_at
  ) values (
    candidate_document,candidate_board,candidate_version,candidate_sha256,candidate_text,
    transaction_timestamp()
  )
  on conflict (document_id) do update
    set current_version_id = excluded.current_version_id,
        canonical_text_sha256 = excluded.canonical_text_sha256,
        search_text = excluded.search_text,
        indexed_at = transaction_timestamp();

  get diagnostics changed = row_count;
  return changed = 1;
end
$$;

alter function public.boardagent_commit_document_version_projection(uuid,uuid,uuid,uuid,bytea,text)
  owner to boardagent_migrator;
revoke all on function public.boardagent_commit_document_version_projection(uuid,uuid,uuid,uuid,bytea,text)
  from public;
grant execute on function public.boardagent_commit_document_version_projection(uuid,uuid,uuid,uuid,bytea,text)
  to boardagent_server;
