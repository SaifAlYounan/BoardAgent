-- BoardAgent Phase 1 / group 13: SQL-first document authority and ACL-safe policies.

grant select on
  system_instance,
  boards,
  members,
  board_memberships,
  organization_role_assignments,
  access_token_records,
  oauth_clients,
  onboarding_terms_versions,
  secretary_support_versions,
  onboarding_attestations,
  documents,
  document_versions,
  document_access_grants,
  document_exclusions
to boardagent_migrator;
grant update on boards, documents to boardagent_migrator;

do $migrator_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'system_instance', 'boards', 'members', 'board_memberships',
    'organization_role_assignments', 'access_token_records', 'oauth_clients',
    'onboarding_terms_versions', 'secretary_support_versions',
    'onboarding_attestations', 'documents', 'document_versions',
    'document_access_grants', 'document_exclusions'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_transaction_read on %I for select to boardagent_migrator using (true)',
      source_table
    );
  end loop;
end
$migrator_read$;

create policy boardagent_migrator_transaction_update on boards
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_transaction_update on documents
  for update to boardagent_migrator using (true) with check (true);

create function boardagent_actor_ready_for_board(candidate_board uuid, required_scope text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select required_scope in ('documents:read', 'documents:contribute')
     and boardagent_context_board_allowed(candidate_board)
     and exists (
       select 1
         from members as actor
         join board_memberships as membership
           on membership.organization_id = actor.organization_id
          and membership.member_id = actor.id
          and membership.board_id = candidate_board
         join access_token_records as token
           on token.organization_id = actor.organization_id
          and token.member_id = actor.id
          and token.client_id = boardagent_context_uuid('boardagent.client_id')
          and token.jti = boardagent_context_uuid('boardagent.token_jti')
         join oauth_clients as client on client.id = token.client_id
         join system_instance as instance
           on instance.organization_id = actor.organization_id
          and instance.canonical_resource_uri = token.resource_uri
        where actor.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and actor.id = boardagent_context_uuid('boardagent.member_id')
          and actor.state = 'active'
          and membership.state = 'active'
          and membership.active_from <= transaction_timestamp()
          and (membership.active_until is null or membership.active_until > transaction_timestamp())
          and client.organization_id = actor.organization_id
          and client.state = 'active'
          and token.revoked_at is null
          and token.expires_at > transaction_timestamp()
          and required_scope = any(token.scope_set)
          and exists (
            select 1
              from onboarding_attestations as attestation
             where attestation.organization_id = actor.organization_id
               and attestation.member_id = actor.id
               and attestation.board_id = candidate_board
               and attestation.terms_version_id = (
                 select terms.id
                   from onboarding_terms_versions as terms
                  where terms.organization_id = actor.organization_id
                    and terms.seat_role = membership.seat_role
                    and terms.effective_at <= transaction_timestamp()
                  order by terms.effective_at desc, terms.version desc, terms.id desc
                  limit 1
               )
               and attestation.support_version_id = (
                 select support.id
                   from secretary_support_versions as support
                  where support.organization_id = actor.organization_id
                    and (support.board_id = candidate_board or support.board_id is null)
                    and support.effective_at <= transaction_timestamp()
                  order by (support.board_id = candidate_board) desc,
                           support.effective_at desc,
                           support.version desc,
                           support.id desc
                  limit 1
               )
          )
     )
$$;
alter function boardagent_actor_ready_for_board(uuid, text) owner to boardagent_migrator;
revoke all on function boardagent_actor_ready_for_board(uuid, text) from public;
grant execute on function boardagent_actor_ready_for_board(uuid, text) to boardagent_server;

create function boardagent_can_contribute_board(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select boardagent_actor_ready_for_board(candidate_board, 'documents:contribute')
     and exists (
       select 1
         from board_memberships as membership
        where membership.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and membership.board_id = candidate_board
          and membership.member_id = boardagent_context_uuid('boardagent.member_id')
          and membership.state = 'active'
          and membership.active_from <= transaction_timestamp()
          and (membership.active_until is null or membership.active_until > transaction_timestamp())
          and (
            membership.seat_role = 'management'
            or membership.is_secretary
            or exists (
              select 1
                from organization_role_assignments as role_assignment
               where role_assignment.organization_id = membership.organization_id
                 and role_assignment.member_id = membership.member_id
                 and role_assignment.role in ('management', 'secretariat')
                 and role_assignment.active_from <= transaction_timestamp()
                 and (
                   role_assignment.active_until is null
                   or role_assignment.active_until > transaction_timestamp()
                 )
            )
          )
     )
$$;
alter function boardagent_can_contribute_board(uuid) owner to boardagent_migrator;
revoke all on function boardagent_can_contribute_board(uuid) from public;
grant execute on function boardagent_can_contribute_board(uuid) to boardagent_server;

create function boardagent_document_permission(candidate_document uuid, requested_permission text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select requested_permission in ('read', 'contribute')
     and exists (
       select 1
         from documents as document
         join board_memberships as membership
           on membership.organization_id = document.organization_id
          and membership.board_id = document.board_id
          and membership.member_id = boardagent_context_uuid('boardagent.member_id')
        where document.id = candidate_document
          and document.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and membership.state = 'active'
          and membership.active_from <= transaction_timestamp()
          and (membership.active_until is null or membership.active_until > transaction_timestamp())
          and boardagent_actor_ready_for_board(
            document.board_id,
            case requested_permission
              when 'read' then 'documents:read'
              else 'documents:contribute'
            end
          )
          and (
            (requested_permission = 'read' and document.state in ('active', 'archived'))
            or (requested_permission = 'contribute' and document.state = 'active')
          )
          and (
            document.created_by = boardagent_context_uuid('boardagent.member_id')
            or exists (
              select 1
                from document_access_grants as access_grant
               where access_grant.document_id = document.id
                 and access_grant.organization_id = document.organization_id
                 and access_grant.board_id = document.board_id
                 and access_grant.active_from <= transaction_timestamp()
                 and (
                   access_grant.active_until is null
                   or access_grant.active_until > transaction_timestamp()
                 )
                 and (
                   access_grant.grantee_member_id = boardagent_context_uuid('boardagent.member_id')
                   or access_grant.grantee_seat_role = membership.seat_role
                 )
                 and (
                   access_grant.permission = requested_permission
                   or (
                     requested_permission = 'read'
                     and access_grant.permission in ('contribute', 'circulate')
                   )
                 )
            )
          )
          and not exists (
            select 1
              from document_exclusions as exclusion
             where exclusion.document_id = document.id
               and exclusion.organization_id = document.organization_id
               and exclusion.board_id = document.board_id
               and exclusion.member_id = boardagent_context_uuid('boardagent.member_id')
               and exclusion.active_from <= transaction_timestamp()
               and (exclusion.active_until is null or exclusion.active_until > transaction_timestamp())
          )
          and (
            requested_permission <> 'contribute'
            or boardagent_can_contribute_board(document.board_id)
          )
     )
$$;
alter function boardagent_document_permission(uuid, text) owner to boardagent_migrator;
revoke all on function boardagent_document_permission(uuid, text) from public;
grant execute on function boardagent_document_permission(uuid, text) to boardagent_server;

create function boardagent_lock_board_for_document_contribution(candidate_board uuid)
returns boolean
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'document contribution requires a managed request transaction'
      using errcode = '25000';
  end if;
  if not boardagent_can_contribute_board(candidate_board) then
    return false;
  end if;
  perform 1
    from boards as board
   where board.id = candidate_board
     and board.organization_id = boardagent_context_uuid('boardagent.organization_id')
     and board.state = 'active'
     for update;
  return found;
end
$$;
alter function boardagent_lock_board_for_document_contribution(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_board_for_document_contribution(uuid) from public;
grant execute on function boardagent_lock_board_for_document_contribution(uuid) to boardagent_server;

create function boardagent_lock_document_for_contribution(
  candidate_document uuid,
  candidate_board uuid
)
returns table(
  document_id uuid,
  document_title text,
  document_state text,
  current_version_id uuid,
  current_version integer,
  row_version bigint
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'document contribution requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select document.id,
           document.title,
           document.state,
           document.current_version_id,
           version.version,
           document.row_version
      from documents as document
      left join document_versions as version on version.id = document.current_version_id
     where document.id = candidate_document
       and document.board_id = candidate_board
       and document.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_document_permission(document.id, 'contribute')
       for update of document;
end
$$;
alter function boardagent_lock_document_for_contribution(uuid, uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_document_for_contribution(uuid, uuid) from public;
grant execute on function boardagent_lock_document_for_contribution(uuid, uuid)
  to boardagent_server;

drop policy boardagent_server_scope on documents;
create policy boardagent_server_documents_select on documents for select to boardagent_server
  using (boardagent_document_permission(id, 'read'));
create policy boardagent_server_documents_insert on documents for insert to boardagent_server
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by = boardagent_context_uuid('boardagent.member_id')
    and state = 'active'
    and boardagent_can_contribute_board(board_id)
  );
create policy boardagent_server_documents_update on documents for update to boardagent_server
  using (boardagent_document_permission(id, 'contribute'))
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_document_permission(id, 'contribute')
  );
revoke update on documents from boardagent_server;
grant update(current_version_id, row_version, state, hidden_at) on documents to boardagent_server;

drop policy boardagent_server_scope on document_versions;
create policy boardagent_server_document_versions_select on document_versions
  for select to boardagent_server using (boardagent_document_permission(document_id, 'read'));
create policy boardagent_server_document_versions_insert on document_versions
  for insert to boardagent_server with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by = boardagent_context_uuid('boardagent.member_id')
    and boardagent_document_permission(document_id, 'contribute')
  );

create policy boardagent_server_document_search_select on document_search
  for select to boardagent_server using (boardagent_document_permission(document_id, 'read'));
create policy boardagent_server_document_search_insert on document_search
  for insert to boardagent_server with check (boardagent_document_permission(document_id, 'contribute'));
create policy boardagent_server_document_search_update on document_search
  for update to boardagent_server
  using (boardagent_document_permission(document_id, 'contribute'))
  with check (boardagent_document_permission(document_id, 'contribute'));

-- ACL base rows are consumed only through the fixed SECURITY DEFINER predicate until the
-- separately confirmed ACL-management transaction exists.
drop policy boardagent_server_scope on document_access_grants;
drop policy boardagent_server_scope on document_exclusions;
