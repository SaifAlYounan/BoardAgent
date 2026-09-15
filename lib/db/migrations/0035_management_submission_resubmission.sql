-- BoardAgent Phase 1 / group 35: management-owned immutable resubmission and
-- secretary-queue projection authority.

grant select on
  management_submission_threads,
  management_submission_versions,
  management_revision_requests,
  document_validation_attempts
to boardagent_migrator;
grant update on management_submission_threads to boardagent_migrator;

do $migrator_management_submission_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'management_submission_threads',
    'management_submission_versions',
    'management_revision_requests',
    'document_validation_attempts'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_management_submission_read on %I for select to boardagent_migrator using (true)',
      source_table
    );
  end loop;
end
$migrator_management_submission_read$;
create policy boardagent_migrator_management_submission_lock
  on management_submission_threads for update to boardagent_migrator
  using (true) with check (true);

create function boardagent_management_submission_actor_allowed(candidate_thread uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
      from management_submission_threads as thread
      join members as actor
        on actor.organization_id = thread.organization_id
       and actor.id = boardagent_context_uuid('boardagent.member_id')
      join board_memberships as membership
        on membership.organization_id = thread.organization_id
       and membership.board_id = thread.board_id
       and membership.member_id = actor.id
     where thread.id = candidate_thread
       and thread.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and actor.id = any(thread.management_owner_ids)
       and actor.state = 'active'
       and membership.state = 'active'
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role <> 'observer'
       and (
         membership.seat_role = 'management'
         or exists (
           select 1
             from organization_role_assignments as role_assignment
            where role_assignment.organization_id = thread.organization_id
              and role_assignment.member_id = actor.id
              and role_assignment.role = 'management'
              and role_assignment.active_from <= transaction_timestamp()
              and (
                role_assignment.active_until is null
                or role_assignment.active_until > transaction_timestamp()
              )
         )
       )
       and boardagent_actor_ready_for_board(thread.board_id, 'documents:contribute')
  )
$$;
alter function boardagent_management_submission_actor_allowed(uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_management_submission_actor_allowed(uuid) from public;
grant execute on function boardagent_management_submission_actor_allowed(uuid)
  to boardagent_server;

create function boardagent_management_submission_documents_valid(
  candidate_board uuid,
  candidate_references jsonb
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select jsonb_typeof(candidate_references) = 'array'
     and jsonb_array_length(candidate_references) between 1 and 1000
     and jsonb_array_length(candidate_references) = (
       select count(distinct reference.value->>'documentId')
         from jsonb_array_elements(candidate_references) as reference(value)
     )
     and jsonb_array_length(candidate_references) = (
       select count(distinct reference.value->>'versionId')
         from jsonb_array_elements(candidate_references) as reference(value)
     )
     and not exists (
       select 1
         from jsonb_array_elements(candidate_references) as reference(value)
        where jsonb_typeof(reference.value) <> 'object'
           or (select count(*) from jsonb_object_keys(reference.value)) <> 3
           or not (reference.value ?& array['documentId', 'versionId', 'sha256'])
           or not case
             when reference.value->>'documentId'
                    ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
              and reference.value->>'versionId'
                    ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
              and reference.value->>'sha256' ~ '^[0-9a-f]{64}$'
             then exists (
               select 1
                 from documents as document
                 join document_versions as version
                   on version.document_id = document.id
                  and version.id = (reference.value->>'versionId')::uuid
                where document.id = (reference.value->>'documentId')::uuid
                  and document.organization_id = boardagent_context_uuid('boardagent.organization_id')
                  and document.board_id = candidate_board
                  and version.organization_id = document.organization_id
                  and version.board_id = document.board_id
                  and encode(version.sha256, 'hex') = reference.value->>'sha256'
                  and boardagent_document_permission(document.id, 'read')
                  and exists (
                    select 1
                      from document_validation_attempts as validation
                     where validation.organization_id = document.organization_id
                       and validation.board_id = document.board_id
                       and validation.result = 'accepted'
                       and validation.accepted_document_version_id = version.id
                  )
             )
             else false
           end
     )
$$;
alter function boardagent_management_submission_documents_valid(uuid, jsonb)
  owner to boardagent_migrator;
revoke all on function boardagent_management_submission_documents_valid(uuid, jsonb) from public;
grant execute on function boardagent_management_submission_documents_valid(uuid, jsonb)
  to boardagent_server;

create function boardagent_management_submission_version_write_allowed(
  candidate_version_id uuid,
  candidate_thread uuid,
  candidate_board uuid,
  candidate_version integer,
  candidate_payload bytea,
  candidate_references jsonb,
  candidate_author uuid,
  candidate_reason text,
  candidate_supersedes uuid
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select candidate_author = boardagent_context_uuid('boardagent.member_id')
     and exists (
       select 1
         from management_submission_threads as thread
         join management_submission_versions as prior
           on prior.thread_id = thread.id
          and prior.id = thread.current_version_id
         join members as secretary
           on secretary.organization_id = thread.organization_id
          and secretary.id = thread.assigned_secretary_id
         join board_memberships as secretary_membership
           on secretary_membership.organization_id = thread.organization_id
          and secretary_membership.board_id = thread.board_id
          and secretary_membership.member_id = secretary.id
         join lateral (
           select request.id
             from management_revision_requests as request
            where request.thread_id = thread.id
              and request.submission_version_id = prior.id
            order by request.created_at desc, request.id desc
            limit 1
         ) as revision_request on true
        where thread.id = candidate_thread
          and thread.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and thread.board_id = candidate_board
          and thread.state = 'revision_requested'
          and candidate_supersedes = prior.id
          and candidate_version = prior.version + 1
          and secretary.state = 'active'
          and secretary_membership.state = 'active'
          and secretary_membership.active_from <= transaction_timestamp()
          and (
            secretary_membership.active_until is null
            or secretary_membership.active_until > transaction_timestamp()
          )
          and (
            secretary_membership.is_secretary
            or exists (
              select 1
                from organization_role_assignments as role_assignment
               where role_assignment.organization_id = thread.organization_id
                 and role_assignment.member_id = secretary.id
                 and role_assignment.role in ('secretariat', 'admin')
                 and role_assignment.active_from <= transaction_timestamp()
                 and (
                   role_assignment.active_until is null
                   or role_assignment.active_until > transaction_timestamp()
                 )
            )
          )
          and boardagent_management_submission_actor_allowed(thread.id)
          and boardagent_management_submission_documents_valid(
            thread.board_id,
            candidate_references
          )
          and convert_from(candidate_payload, 'UTF8')::jsonb = jsonb_build_object(
            'schemaVersion', 'boardagent.management-submission.v1',
            'submissionId', thread.id,
            'versionId', candidate_version_id,
            'version', candidate_version,
            'documentReferences', candidate_references,
            'changeReason', candidate_reason,
            'supersedesVersionId', prior.id,
            'authorMemberId', candidate_author,
            'revisionRequestId', revision_request.id
          )
     )
$$;
alter function boardagent_management_submission_version_write_allowed(
  uuid, uuid, uuid, integer, bytea, jsonb, uuid, text, uuid
) owner to boardagent_migrator;
revoke all on function boardagent_management_submission_version_write_allowed(
  uuid, uuid, uuid, integer, bytea, jsonb, uuid, text, uuid
) from public;
grant execute on function boardagent_management_submission_version_write_allowed(
  uuid, uuid, uuid, integer, bytea, jsonb, uuid, text, uuid
) to boardagent_server;

create function boardagent_lock_management_submission_for_resubmission(candidate_thread uuid)
returns table(
  organization_id uuid,
  board_id uuid,
  submission_state text,
  current_version_id uuid,
  current_version integer,
  current_payload_sha256 bytea,
  revision_request_id uuid,
  assigned_secretary_id uuid,
  secretary_entitlement_generation bigint,
  thread_row_version bigint
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'management resubmission requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select thread.organization_id,
           thread.board_id,
           thread.state,
           prior.id,
           prior.version,
           prior.payload_sha256,
           revision_request.id,
           secretary.id,
           secretary_membership.entitlement_generation,
           thread.row_version
      from management_submission_threads as thread
      join management_submission_versions as prior
        on prior.thread_id = thread.id
       and prior.id = thread.current_version_id
      join members as secretary
        on secretary.organization_id = thread.organization_id
       and secretary.id = thread.assigned_secretary_id
      join board_memberships as secretary_membership
        on secretary_membership.organization_id = thread.organization_id
       and secretary_membership.board_id = thread.board_id
       and secretary_membership.member_id = secretary.id
      left join lateral (
        select request.id
          from management_revision_requests as request
         where request.thread_id = thread.id
           and request.submission_version_id = prior.id
         order by request.created_at desc, request.id desc
         limit 1
      ) as revision_request on true
     where thread.id = candidate_thread
       and thread.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and secretary.state = 'active'
       and secretary_membership.state = 'active'
       and secretary_membership.active_from <= transaction_timestamp()
       and (
         secretary_membership.active_until is null
         or secretary_membership.active_until > transaction_timestamp()
       )
       and (
         secretary_membership.is_secretary
         or exists (
           select 1
             from organization_role_assignments as role_assignment
            where role_assignment.organization_id = thread.organization_id
              and role_assignment.member_id = secretary.id
              and role_assignment.role in ('secretariat', 'admin')
              and role_assignment.active_from <= transaction_timestamp()
              and (
                role_assignment.active_until is null
                or role_assignment.active_until > transaction_timestamp()
              )
         )
       )
       and boardagent_management_submission_actor_allowed(thread.id)
     for update of thread, secretary_membership;
end
$$;
alter function boardagent_lock_management_submission_for_resubmission(uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_management_submission_for_resubmission(uuid) from public;
grant execute on function boardagent_lock_management_submission_for_resubmission(uuid)
  to boardagent_server;

create function boardagent_management_submission_projection_integrity()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  prior_version integer;
  candidate_version management_submission_versions%rowtype;
begin
  if old.state <> 'revision_requested'
     or new.state <> 'resubmitted'
     or old.current_version_id is null
     or new.current_version_id is null
     or new.current_version_id = old.current_version_id
     or new.queue_entered_at is distinct from transaction_timestamp()
     or new.row_version <> old.row_version + 1 then
    raise exception 'management resubmission projection requires one exact version advance'
      using errcode = '23514';
  end if;

  select version into prior_version
    from management_submission_versions
   where thread_id = old.id and id = old.current_version_id;
  select * into candidate_version
    from management_submission_versions
   where thread_id = new.id and id = new.current_version_id;
  if prior_version is null
     or candidate_version.id is null
     or candidate_version.version <> prior_version + 1
     or candidate_version.supersedes_id is distinct from old.current_version_id
     or candidate_version.author_member_id
          is distinct from boardagent_context_uuid('boardagent.member_id') then
    raise exception 'management resubmission projection is not backed by its next immutable version'
      using errcode = '23514';
  end if;
  return new;
end
$$;
alter function boardagent_management_submission_projection_integrity()
  owner to boardagent_migrator;
revoke all on function boardagent_management_submission_projection_integrity() from public;
grant execute on function boardagent_management_submission_projection_integrity()
  to boardagent_server;
create trigger boardagent_management_submission_projection
  before update of state, current_version_id, queue_entered_at, row_version
  on management_submission_threads
  for each row execute function boardagent_management_submission_projection_integrity();

create function boardagent_apply_management_resubmission(
  candidate_thread uuid,
  expected_row_version bigint,
  expected_prior_version uuid,
  candidate_version uuid
)
returns bigint
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  next_row_version bigint;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'management resubmission requires a managed request transaction'
      using errcode = '25000';
  end if;
  if not boardagent_management_submission_actor_allowed(candidate_thread) then
    return null;
  end if;
  update management_submission_threads as thread
     set state = 'resubmitted',
         current_version_id = candidate_version,
         queue_entered_at = transaction_timestamp(),
         row_version = thread.row_version + 1
   where thread.id = candidate_thread
     and thread.state = 'revision_requested'
     and thread.current_version_id = expected_prior_version
     and thread.row_version = expected_row_version
  returning thread.row_version into next_row_version;
  return next_row_version;
end
$$;
alter function boardagent_apply_management_resubmission(uuid, bigint, uuid, uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_management_resubmission(uuid, bigint, uuid, uuid)
  from public;
grant execute on function boardagent_apply_management_resubmission(uuid, bigint, uuid, uuid)
  to boardagent_server;

drop policy boardagent_server_scope on management_submission_threads;
create policy boardagent_server_management_submission_threads_select
  on management_submission_threads for select to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  );
drop policy boardagent_server_scope on management_submission_versions;
create policy boardagent_server_management_submission_versions_select
  on management_submission_versions for select to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
  );
create policy boardagent_server_management_submission_versions_insert
  on management_submission_versions for insert to boardagent_server
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and schema_version = 'boardagent.management-submission.v1'
    and boardagent_management_submission_version_write_allowed(
      id,
      thread_id,
      board_id,
      version,
      canonical_payload,
      document_references,
      author_member_id,
      change_reason,
      supersedes_id
    )
  );

grant insert on management_submission_versions to boardagent_server;
