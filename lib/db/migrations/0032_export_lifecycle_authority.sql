-- BoardAgent Phase 1 / group 32: confirmed frozen-scope export and worker artifact authority.

alter table export_requests
  add column snapshot_manifest bytea,
  add column snapshot_sha256 bytea,
  add column started_at timestamptz(6),
  add column failure_class text,
  add constraint export_requests_snapshot_ck check (
    (state in ('running', 'succeeded', 'failed')
      and snapshot_manifest is not null
      and octet_length(snapshot_manifest) between 2 and 10485760
      and boardagent_hash_is_sha256(snapshot_sha256)
      and started_at is not null)
    or state not in ('running', 'succeeded', 'failed')
  ),
  add constraint export_requests_completion_ck check (
    (state in ('succeeded', 'failed', 'deleted') and completed_at is not null)
    or state not in ('succeeded', 'failed', 'deleted')
  ),
  add constraint export_requests_failure_ck check (
    (state = 'failed' and failure_class is not null
      and failure_class ~ '^[a-z][a-z0-9_]{1,127}$')
    or (state <> 'failed' and failure_class is null)
  );

grant insert on export_requests to boardagent_server;
grant update(state, consent_record_id, row_version, completed_at)
  on export_requests to boardagent_server;

grant select, insert on export_artifacts, export_chunks to boardagent_worker;
grant update(state, row_version, snapshot_manifest, snapshot_sha256, started_at,
             completed_at, failure_class)
  on export_requests to boardagent_worker;
grant update(state, deleted_at) on export_artifacts to boardagent_worker;

grant select on auth_sessions, oauth_clients, organization_role_assignments, export_requests
  to boardagent_migrator;
grant update on export_requests to boardagent_migrator;
create policy boardagent_migrator_export_read on auth_sessions
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_export_read on oauth_clients
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_export_read on organization_role_assignments
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_export_read on export_requests
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_export_lock on export_requests
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_export_lock on access_token_records
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_export_lock on auth_sessions
  for update to boardagent_migrator using (true) with check (true);

create policy boardagent_worker_export_chunks on export_chunks for all to boardagent_worker
  using (true) with check (true);

create trigger boardagent_immutable before update or delete on export_chunks
  for each row execute function boardagent_reject_evidence_mutation();
revoke update, delete on export_chunks from boardagent_server, boardagent_worker;

create function boardagent_assert_export_authority(
  candidate_export_type text,
  candidate_board_id uuid,
  candidate_exact_origin text
)
returns table(
  organization_id uuid,
  member_id uuid,
  client_id uuid,
  token_jti uuid,
  recent_auth_at text
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  context_organization uuid;
  context_member uuid;
  context_client uuid;
  context_token uuid;
  authenticated_at timestamptz;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request'
     or candidate_export_type not in ('audit_chain','system_data') then
    raise exception 'export authority requires a managed request transaction and export type'
      using errcode = '25000';
  end if;
  context_organization := boardagent_context_uuid('boardagent.organization_id');
  context_member := boardagent_context_uuid('boardagent.member_id');
  context_client := boardagent_context_uuid('boardagent.client_id');
  context_token := boardagent_context_uuid('boardagent.token_jti');
  select session.last_authenticated_at
    into strict authenticated_at
    from access_token_records as token
    join oauth_clients as oauth_client on oauth_client.id=token.client_id
    join auth_sessions as session on session.id=token.session_id
    join members as actor on actor.id=token.member_id
    join system_instance as instance on instance.organization_id=token.organization_id
   where token.organization_id=context_organization
     and token.member_id=context_member
     and token.client_id=context_client
     and token.jti=context_token
     and token.revoked_at is null and token.expires_at>transaction_timestamp()
     and (case candidate_export_type
            when 'audit_chain' then 'audit:read'
            else 'secretariat:admin'
          end)=any(token.scope_set)
     and oauth_client.state='active' and actor.state='active'
     and instance.canonical_resource_uri=token.resource_uri
     and session.organization_id=token.organization_id
     and session.member_id=token.member_id
     and session.client_id=token.client_id
     and session.state='authenticated'
     and session.exact_origin=candidate_exact_origin
     and session.expires_at>transaction_timestamp()
     and session.last_authenticated_at>=transaction_timestamp()-interval '15 minutes'
   for update of token,session;

  if candidate_export_type = 'system_data' then
    if candidate_board_id is not null
       or not exists (
         select 1 from organization_role_assignments as assignment
          where assignment.organization_id=context_organization
            and assignment.member_id=context_member and assignment.role='admin'
            and assignment.active_from<=transaction_timestamp()
            and (assignment.active_until is null
                 or assignment.active_until>transaction_timestamp())
       ) or exists (
         select 1 from board_memberships as membership
          where membership.organization_id=context_organization
            and membership.member_id=context_member and membership.seat_role='observer'
            and membership.state='active' and membership.active_from<=transaction_timestamp()
            and (membership.active_until is null
                 or membership.active_until>transaction_timestamp())
       ) then
      raise exception 'system export requires a nonobserver organization administrator'
        using errcode = '42501';
    end if;
  elsif candidate_board_id is not null then
    if not boardagent_context_board_allowed(candidate_board_id)
       or not exists (
         select 1 from board_memberships as membership
          where membership.organization_id=context_organization
            and membership.board_id=candidate_board_id
            and membership.member_id=context_member and membership.seat_role<>'observer'
            and membership.state='active' and membership.active_from<=transaction_timestamp()
            and (membership.active_until is null
                 or membership.active_until>transaction_timestamp())
       ) then
      raise exception 'board audit export requires a current nonobserver seat'
        using errcode = '42501';
    end if;
  elsif not exists (
    select 1 from organization_role_assignments as assignment
     where assignment.organization_id=context_organization
       and assignment.member_id=context_member and assignment.role in ('admin','secretariat')
       and assignment.active_from<=transaction_timestamp()
       and (assignment.active_until is null or assignment.active_until>transaction_timestamp())
  ) then
    raise exception 'organization audit export requires current organization authority'
      using errcode = '42501';
  end if;

  return query select
    context_organization,
    context_member,
    context_client,
    context_token,
    to_char(authenticated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
exception
  when no_data_found then
    raise exception 'export requires a live token and authentication no older than 15 minutes'
      using errcode = '42501';
end;
$$;
alter function boardagent_assert_export_authority(text, uuid, text)
  owner to boardagent_migrator;
revoke all on function boardagent_assert_export_authority(text, uuid, text) from public;
grant execute on function boardagent_assert_export_authority(text, uuid, text)
  to boardagent_server;

create function boardagent_guard_export_request_update()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  consent consent_records%rowtype;
begin
  if old.state = 'staged' and new.state = 'confirmed' then
    select * into strict consent from consent_records where id = new.consent_record_id;
    if consent.organization_id <> new.organization_id
       or consent.board_id is distinct from new.board_id
       or consent.actor_member_id <> new.requester_member_id
       or consent.action_code <> (case new.export_type
            when 'audit_chain' then 'export_audit_chain'
            else 'export_system_data'
          end)
       or consent.target_type <> 'export_request'
       or consent.target_id is distinct from new.id
       or consent.package_sha256 is distinct from new.scope_sha256 then
      raise exception 'export confirmation does not bind the exact requester and frozen scope'
        using errcode = '23514';
    end if;
  end if;
  if old.scope_manifest is distinct from new.scope_manifest
     or old.scope_sha256 is distinct from new.scope_sha256
     or old.export_type <> new.export_type
     or old.organization_id <> new.organization_id
     or old.board_id is distinct from new.board_id
     or old.requester_member_id <> new.requester_member_id
     or old.recent_auth_at <> new.recent_auth_at
     or old.expires_at <> new.expires_at then
    raise exception 'frozen export request fields are immutable' using errcode = '55000';
  end if;
  return new;
end;
$$;
alter function boardagent_guard_export_request_update() owner to boardagent_migrator;
revoke all on function boardagent_guard_export_request_update() from public;
create trigger boardagent_export_request_update_guard
  before update on export_requests
  for each row execute function boardagent_guard_export_request_update();

create function boardagent_guard_export_artifact_insert()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  request_row export_requests%rowtype;
  evidence_key crypto_key_registry%rowtype;
  artifact_manifest jsonb;
begin
  begin
    artifact_manifest := convert_from(new.manifest, 'UTF8')::jsonb;
  exception when others then
    raise exception 'export artifact manifest is not valid UTF-8 JSON evidence'
      using errcode = '23514';
  end;
  select * into strict request_row from export_requests where id = new.export_request_id for update;
  select * into strict evidence_key from crypto_key_registry where id = new.encryption_key_id;
  if request_row.state <> 'running'
     or request_row.expires_at <= transaction_timestamp()
     or artifact_manifest ->> 'schemaVersion' <> 'boardagent.export-artifact.v1'
     or artifact_manifest ->> 'artifactId' <> new.id::text
     or artifact_manifest ->> 'exportRequestId' <> request_row.id::text
     or artifact_manifest ->> 'scopeSha256' <> encode(request_row.scope_sha256, 'hex')
     or artifact_manifest ->> 'snapshotSha256' <> encode(request_row.snapshot_sha256, 'hex')
     or artifact_manifest ->> 'encryptedContentSetSha256' <> encode(new.content_set_sha256, 'hex')
     or artifact_manifest ->> 'encryptedStorageLocator' <> new.encrypted_storage_locator
     or artifact_manifest ->> 'encryptionKeyId' <> new.encryption_key_id::text
     or (artifact_manifest ->> 'byteLength')::bigint <> new.byte_length
     or evidence_key.organization_id <> request_row.organization_id
     or evidence_key.purpose <> 'data_kek'
     or evidence_key.algorithm <> 'A256GCM'
     or evidence_key.public_jwk is not null
     or evidence_key.activated_at > transaction_timestamp()
     or (evidence_key.retired_at is not null
         and evidence_key.retired_at <= transaction_timestamp())
     or evidence_key.compromised_at is not null then
    raise exception 'export artifact does not bind the exact running request and active data key'
      using errcode = '23514';
  end if;
  return new;
end;
$$;
alter function boardagent_guard_export_artifact_insert() owner to boardagent_migrator;
revoke all on function boardagent_guard_export_artifact_insert() from public;
create trigger boardagent_export_artifact_insert_guard
  before insert on export_artifacts
  for each row execute function boardagent_guard_export_artifact_insert();

create function boardagent_export_encryption_key(
  candidate_request_id uuid,
  candidate_key_id uuid
)
returns table(organization_id uuid, key_id uuid)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'export key lookup requires a managed worker transaction'
      using errcode = '25000';
  end if;
  return query
    select request.organization_id, key.id
      from export_requests as request
      join crypto_key_registry as key
        on key.id = candidate_key_id
       and key.organization_id = request.organization_id
       and key.purpose = 'data_kek'
       and key.algorithm = 'A256GCM'
       and key.public_jwk is null
       and key.activated_at <= transaction_timestamp()
       and (key.retired_at is null or key.retired_at > transaction_timestamp())
       and key.compromised_at is null
     where request.id = candidate_request_id
       and request.state = 'running'
       and request.expires_at > transaction_timestamp();
end;
$$;
alter function boardagent_export_encryption_key(uuid, uuid) owner to boardagent_migrator;
revoke all on function boardagent_export_encryption_key(uuid, uuid) from public;
grant execute on function boardagent_export_encryption_key(uuid, uuid) to boardagent_worker;

create function boardagent_export_snapshot_root(candidate_request_id uuid)
returns table(
  organization_id uuid,
  board_id uuid,
  export_type text,
  scope_manifest bytea,
  scope_sha256 bytea,
  transaction_snapshot text,
  audit_head_sequence bigint,
  audit_head_sha256 bytea,
  latest_checkpoint_sha256 bytea,
  migration_ledger jsonb,
  captured_at text
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  request_row export_requests%rowtype;
  head audit_chain_head%rowtype;
  checkpoint_row audit_checkpoints%rowtype;
  first_uncovered_at timestamptz;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker'
     or current_setting('transaction_isolation') <> 'repeatable read' then
    raise exception 'export snapshot requires a managed repeatable-read worker transaction'
      using errcode = '25000';
  end if;
  select * into strict request_row from export_requests where id = candidate_request_id for update;
  if request_row.state <> 'queued' or request_row.expires_at <= transaction_timestamp() then
    raise exception 'export request is not a live queued snapshot target' using errcode = '55000';
  end if;
  select * into strict head from audit_chain_head where singleton_key;
  select * into checkpoint_row
    from audit_checkpoints
   order by last_sequence desc
   limit 1;
  if checkpoint_row.id is null then
    raise exception 'export snapshot requires a current signed audit checkpoint'
      using errcode = '55000';
  end if;
  select min(event.occurred_at)
    into first_uncovered_at
    from audit_events as event
   where event.sequence > checkpoint_row.last_sequence;
  if head.last_sequence - checkpoint_row.last_sequence > 1000
     or (first_uncovered_at is not null
         and first_uncovered_at < transaction_timestamp() - interval '15 minutes') then
    raise exception 'export snapshot refuses an overdue audit checkpoint tail'
      using errcode = '55000';
  end if;
  return query select
    request_row.organization_id,
    request_row.board_id,
    request_row.export_type,
    request_row.scope_manifest,
    request_row.scope_sha256,
    txid_current_snapshot()::text,
    head.last_sequence,
    head.last_event_sha256,
    checkpoint_row.manifest_sha256,
    coalesce((
      select jsonb_agg(jsonb_build_object(
        'version', migration.version::text,
        'name', migration.name,
        'sha256', migration.sha256,
        'appliedAt', to_char(
          migration.applied_at at time zone 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        ),
        'appBuild', migration.app_build
      ) order by migration.version)
        from schema_migrations as migration
    ), '[]'::jsonb),
    to_char(
      transaction_timestamp() at time zone 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );
end;
$$;
alter function boardagent_export_snapshot_root(uuid) owner to boardagent_migrator;
revoke all on function boardagent_export_snapshot_root(uuid) from public;
grant execute on function boardagent_export_snapshot_root(uuid) to boardagent_worker;

create function boardagent_export_system_table_rows(
  candidate_request_id uuid,
  candidate_class text,
  candidate_table text
)
returns table(table_rows jsonb, row_count bigint)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
declare
  request_row export_requests%rowtype;
  scope jsonb;
  allowed boolean := false;
  organization_scoped boolean := false;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker'
     or current_setting('transaction_isolation') <> 'repeatable read' then
    raise exception 'system export reads require a managed repeatable-read worker transaction'
      using errcode = '25000';
  end if;
  select * into strict request_row from export_requests where id = candidate_request_id;
  scope := convert_from(request_row.scope_manifest, 'UTF8')::jsonb;
  if request_row.state <> 'queued'
     or request_row.export_type <> 'system_data'
     or request_row.board_id is not null
     or not exists (
       select 1 from jsonb_array_elements_text(scope -> 'dataClasses') as class(value)
        where class.value = candidate_class
     ) then
    raise exception 'system export component is outside the frozen request scope'
      using errcode = '42501';
  end if;

  allowed := case candidate_class
    when 'identity_authority' then candidate_table = any(array[
      'accountable_principals','members','organization_role_assignments','board_memberships',
      'membership_versions','onboarding_terms_versions','onboarding_attestations',
      'secretary_support_versions'
    ])
    when 'governance' then candidate_table = any(array[
      'organizations','system_instance','boards','board_versions','governance_profiles',
      'governance_seat_rules','governance_rule_templates','governance_citations','rulesets',
      'matter_types','ruleset_rules','rule_citations','rule_overrides','matter_evaluations'
    ])
    when 'documents' then candidate_table = any(array[
      'documents','document_versions','document_access_grants','document_circulations',
      'circulation_recipients','document_exclusions','document_validation_attempts'
    ])
    when 'management' then candidate_table = any(array[
      'management_submission_threads','management_submission_versions',
      'management_revision_requests','management_revision_replies',
      'management_submission_dispositions','management_questions',
      'management_question_turns','management_question_answers','question_visibility',
      'question_decision_links'
    ])
    when 'meetings' then candidate_table = any(array[
      'meetings','meeting_versions','agenda_versions','agenda_items','meeting_rsvps',
      'meeting_attendance','meeting_transcripts','meeting_transcript_versions',
      'transcript_turns','transcript_verifications','transcript_question_links',
      'transcript_challenges','transcript_challenge_dispositions'
    ])
    when 'minutes_tasks' then candidate_table = any(array[
      'minutes','minutes_versions','minutes_diffs','minutes_review_items',
      'minutes_review_withdrawals','minutes_review_dispositions',
      'minutes_action_declarations','minutes_action_item_dispositions',
      'minutes_signature_packages','minutes_signature_requirements','minutes_signatures',
      'minutes_signature_supersessions','minutes_resign_requirements',
      'minutes_correction_cycles','tasks','task_evidence','task_evidence_reviews',
      'task_closures','task_correction_cycles'
    ])
    when 'decisions' then candidate_table = any(array[
      'approval_rules','resolution_versions','decision_packages',
      'decision_package_components','votes','vote_electorate','vote_exclusions',
      'vote_source_update_causes','vote_source_update_dispositions','ballots',
      'ballot_dispositions','proxy_grants','proxy_revocations','vote_outcomes',
      'vote_certificates','vote_supersessions'
    ])
    when 'audit' then candidate_table = 'audit_checkpoints'
    when 'operations' then candidate_table = any(array[
      'config_receipts','clock_health_samples','retention_snapshots','deletion_tombstones',
      'notices','pending_action_feed','feed_tombstones'
    ])
    else false
  end;
  if not allowed then
    raise exception 'system export table is not on the secret-free allowlist'
      using errcode = '42501';
  end if;

  select exists (
    select 1 from information_schema.columns as column_definition
     where column_definition.table_schema = 'public'
       and column_definition.table_name = candidate_table
       and column_definition.column_name = 'organization_id'
  ) into organization_scoped;
  if organization_scoped then
    return query execute format(
      'select coalesce(jsonb_agg(normalized.row_value order by normalized.row_value::text), ''[]''::jsonb), count(*)::bigint
         from %I as source_row
         cross join lateral (
           select jsonb_object_agg(item.key,item.value order by item.key) as row_value
             from jsonb_each_text(to_jsonb(source_row)) as item(key,value)
         ) as normalized
        where source_row.organization_id=$1',
      candidate_table
    ) using request_row.organization_id;
  else
    return query execute format(
      'select coalesce(jsonb_agg(normalized.row_value order by normalized.row_value::text), ''[]''::jsonb), count(*)::bigint
         from %I as source_row
         cross join lateral (
           select jsonb_object_agg(item.key,item.value order by item.key) as row_value
             from jsonb_each_text(to_jsonb(source_row)) as item(key,value)
         ) as normalized',
      candidate_table
    );
  end if;
end;
$$;
alter function boardagent_export_system_table_rows(uuid, text, text)
  owner to boardagent_migrator;
revoke all on function boardagent_export_system_table_rows(uuid, text, text) from public;
grant execute on function boardagent_export_system_table_rows(uuid, text, text)
  to boardagent_worker;

create function boardagent_export_audit_event_rows(candidate_request_id uuid)
returns table(table_rows jsonb, row_count bigint)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
declare
  request_row export_requests%rowtype;
  scope jsonb;
  range_first bigint;
  range_last bigint;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker'
     or current_setting('transaction_isolation') <> 'repeatable read' then
    raise exception 'audit export reads require a managed repeatable-read worker transaction'
      using errcode = '25000';
  end if;
  select * into strict request_row from export_requests where id = candidate_request_id;
  scope := convert_from(request_row.scope_manifest, 'UTF8')::jsonb;
  if request_row.state <> 'queued'
     or (request_row.export_type = 'system_data' and not exists (
       select 1 from jsonb_array_elements_text(scope -> 'dataClasses') as class(value)
        where class.value = 'audit'
     )) then
    raise exception 'audit component is outside the frozen request scope' using errcode = '42501';
  end if;
  if request_row.export_type = 'audit_chain' then
    range_first := (scope ->> 'firstSequence')::bigint;
    range_last := (scope ->> 'lastSequence')::bigint;
  else
    range_first := 1;
    select head.last_sequence into range_last
      from audit_chain_head as head where head.singleton_key;
  end if;

  return query
    select coalesce(jsonb_agg(
      case
        when request_row.board_id is null or event.board_id = request_row.board_id then normalized.row_value
        else jsonb_build_object(
          'sequence', event.sequence::text,
          'previous_event_sha256', encode(event.previous_event_sha256, 'hex'),
          'event_sha256', encode(event.event_sha256, 'hex'),
          'redacted', 'true'
        )
      end order by event.sequence
    ), '[]'::jsonb), count(*)::bigint
      from audit_events as event
      cross join lateral (
        select jsonb_object_agg(item.key,item.value order by item.key) as row_value
          from jsonb_each_text(to_jsonb(event)) as item(key,value)
      ) as normalized
     where event.organization_id = request_row.organization_id
       and event.sequence between range_first and range_last;
end;
$$;
alter function boardagent_export_audit_event_rows(uuid) owner to boardagent_migrator;
revoke all on function boardagent_export_audit_event_rows(uuid) from public;
grant execute on function boardagent_export_audit_event_rows(uuid) to boardagent_worker;

create function boardagent_export_public_key_rows(candidate_request_id uuid)
returns table(table_rows jsonb, row_count bigint)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
declare
  request_row export_requests%rowtype;
  scope jsonb;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker'
     or current_setting('transaction_isolation') <> 'repeatable read' then
    raise exception 'public-key export requires a managed repeatable-read worker transaction'
      using errcode = '25000';
  end if;
  select * into strict request_row from export_requests where id = candidate_request_id;
  scope := convert_from(request_row.scope_manifest, 'UTF8')::jsonb;
  if request_row.state <> 'queued'
     or (request_row.export_type = 'system_data' and not exists (
       select 1 from jsonb_array_elements_text(scope -> 'dataClasses') as class(value)
        where class.value = 'audit'
     )) then
    raise exception 'public-key component is outside the frozen request scope'
      using errcode = '42501';
  end if;
  return query
    select coalesce(jsonb_agg(jsonb_build_object(
      'id', key.id::text,
      'kid', key.kid,
      'purpose', key.purpose,
      'algorithm', key.algorithm,
      'publicJwk', key.public_jwk,
      'activatedAt', to_char(key.activated_at at time zone 'UTC',
                             'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'retiredAt', case when key.retired_at is null then null else
        to_char(key.retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end,
      'compromisedAt', case when key.compromised_at is null then null else
        to_char(key.compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
    ) order by key.activated_at,key.id), '[]'::jsonb), count(*)::bigint
      from crypto_key_registry as key
     where key.organization_id = request_row.organization_id
       and key.purpose in ('oauth_signing','evidence_signing');
end;
$$;
alter function boardagent_export_public_key_rows(uuid) owner to boardagent_migrator;
revoke all on function boardagent_export_public_key_rows(uuid) from public;
grant execute on function boardagent_export_public_key_rows(uuid) to boardagent_worker;

create function boardagent_export_checkpoint_rows(candidate_request_id uuid)
returns table(table_rows jsonb, row_count bigint)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
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
        select jsonb_object_agg(item.key,item.value order by item.key) as row_value
          from jsonb_each_text(to_jsonb(checkpoint)) as item(key,value)
      ) as normalized
     where checkpoint.organization_id = request_row.organization_id;
end;
$$;
alter function boardagent_export_checkpoint_rows(uuid) owner to boardagent_migrator;
revoke all on function boardagent_export_checkpoint_rows(uuid) from public;
grant execute on function boardagent_export_checkpoint_rows(uuid) to boardagent_worker;
