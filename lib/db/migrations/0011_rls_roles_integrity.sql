-- BoardAgent Phase 1 / group 11: database role separation, forced RLS, and evidence walls.

do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'boardagent_migrator') then
    create role boardagent_migrator nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'boardagent_server') then
    create role boardagent_server nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'boardagent_worker') then
    create role boardagent_worker nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'boardagent_backup') then
    create role boardagent_backup nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;
  end if;
end
$roles$;

revoke create on schema public from public;
revoke all on all tables in schema public from public;
revoke all on all tables in schema public from boardagent_server, boardagent_worker, boardagent_backup;
grant usage on schema public to boardagent_server, boardagent_worker, boardagent_backup;
grant select, insert, update on all tables in schema public to boardagent_server;
revoke delete, truncate, references, trigger on all tables in schema public from boardagent_server;
grant select on all tables in schema public to boardagent_backup;
grant select, insert, update on jobs, notification_jobs, export_requests, export_artifacts
  to boardagent_worker;
grant select, insert on notification_attempts, audit_events, audit_checkpoints, backup_receipts
  to boardagent_worker;

create function boardagent_context_uuid(setting_name text)
returns uuid
language plpgsql
stable
security invoker
set search_path = pg_catalog
as $$
declare
  raw_value text;
begin
  raw_value := current_setting(setting_name, true);
  if raw_value is null or raw_value = ''
     or raw_value !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    return null;
  end if;
  return raw_value::uuid;
exception when others then
  return null;
end
$$;

create function boardagent_context_board_allowed(candidate uuid)
returns boolean
language plpgsql
stable
security invoker
set search_path = pg_catalog
as $$
declare
  raw_value text;
begin
  if candidate is null then
    return false;
  end if;
  raw_value := current_setting('boardagent.board_ids', true);
  if raw_value is null or raw_value = '' or jsonb_typeof(raw_value::jsonb) <> 'array' then
    return false;
  end if;
  return exists (
    select 1 from jsonb_array_elements_text(raw_value::jsonb) as allowed(value)
     where allowed.value = candidate::text
  );
exception when others then
  return false;
end
$$;

do $rls$
declare
  product_table record;
  scope_expression text;
begin
  for product_table in
    select c.table_name,
           bool_or(c.column_name = 'organization_id') as has_organization,
           bool_or(c.column_name = 'board_id') as has_board
      from information_schema.columns c
     where c.table_schema = 'public' and c.table_name <> 'schema_migrations'
     group by c.table_name
     order by c.table_name
  loop
    execute format('alter table %I enable row level security', product_table.table_name);
    execute format('alter table %I force row level security', product_table.table_name);
    execute format(
      'create policy boardagent_backup_read on %I for select to boardagent_backup using (true)',
      product_table.table_name
    );
    if product_table.has_organization then
      scope_expression := 'organization_id = boardagent_context_uuid(''boardagent.organization_id'')';
      if product_table.has_board then
        scope_expression := scope_expression
          || ' and (board_id is null or boardagent_context_board_allowed(board_id))';
      end if;
      execute format(
        'create policy boardagent_server_scope on %I for all to boardagent_server using (%s) with check (%s)',
        product_table.table_name,
        scope_expression,
        scope_expression
      );
    end if;
  end loop;
end
$rls$;

-- Singleton and organization roots do not expose a board_id column.
create policy boardagent_server_organization on organizations for all to boardagent_server
  using (id = boardagent_context_uuid('boardagent.organization_id'))
  with check (id = boardagent_context_uuid('boardagent.organization_id'));
create policy boardagent_server_instance on system_instance for select to boardagent_server
  using (organization_id = boardagent_context_uuid('boardagent.organization_id'));
drop policy boardagent_server_scope on boards;
create policy boardagent_server_scope on boards for all to boardagent_server
  using (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(id)
  )
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(id)
  );

-- Worker access is intentionally limited to its durable queues and evidence append path.
create policy boardagent_worker_jobs on jobs for all to boardagent_worker using (true) with check (true);
create policy boardagent_worker_notifications on notification_jobs for all to boardagent_worker
  using (true) with check (true);
create policy boardagent_worker_notification_attempts on notification_attempts for insert to boardagent_worker
  with check (true);
create policy boardagent_worker_exports on export_requests for all to boardagent_worker
  using (true) with check (true);
create policy boardagent_worker_export_artifacts on export_artifacts for all to boardagent_worker
  using (true) with check (true);
create policy boardagent_worker_audit_events on audit_events for insert to boardagent_worker
  with check (true);
create policy boardagent_worker_audit_checkpoints on audit_checkpoints for insert to boardagent_worker
  with check (true);
create policy boardagent_worker_backup_receipts on backup_receipts for insert to boardagent_worker
  with check (true);

create function boardagent_reject_evidence_mutation()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  raise exception 'immutable evidence table % rejects %', tg_table_name, tg_op
    using errcode = '55000';
end
$$;

do $immutable$
declare
  evidence_table text;
begin
  foreach evidence_table in array array[
    'approval_rules', 'audit_checkpoints', 'audit_events', 'ballot_dispositions', 'ballots',
    'board_versions', 'circulation_recipients', 'config_receipts', 'consent_records',
    'decision_package_components', 'decision_packages', 'deletion_tombstones',
    'document_circulations', 'document_validation_attempts', 'document_versions',
    'feed_tombstones', 'governance_citations', 'governance_rule_templates',
    'governance_seat_rules', 'management_question_answers', 'management_question_turns',
    'management_revision_replies', 'management_revision_requests',
    'management_submission_dispositions', 'management_submission_versions', 'matter_evaluations',
    'meeting_attendance', 'meeting_transcript_versions', 'meeting_versions',
    'membership_versions', 'minutes_action_declarations', 'minutes_action_item_dispositions',
    'minutes_correction_cycles', 'minutes_diffs', 'minutes_resign_requirements',
    'minutes_review_dispositions', 'minutes_review_items', 'minutes_review_withdrawals',
    'minutes_signature_requirements', 'minutes_signature_supersessions', 'minutes_signatures',
    'minutes_versions', 'notification_attempts', 'onboarding_attestations',
    'onboarding_terms_versions', 'proxy_grants', 'proxy_revocations', 'question_decision_links',
    'resolution_versions', 'retention_snapshots', 'rule_citations', 'ruleset_rules',
    'secretary_support_versions', 'task_closures', 'task_correction_cycles',
    'task_evidence_reviews', 'transcript_challenge_dispositions', 'transcript_question_links',
    'transcript_turns', 'transcript_verifications', 'vote_certificates', 'vote_electorate',
    'vote_outcomes', 'vote_supersessions', 'wizard_steps'
  ]
  loop
    execute format(
      'create trigger boardagent_immutable before update or delete on %I for each row execute function boardagent_reject_evidence_mutation()',
      evidence_table
    );
    execute format('revoke update, delete on %I from boardagent_server, boardagent_worker', evidence_table);
  end loop;
end
$immutable$;

create function boardagent_guard_row_version()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if new.row_version <> old.row_version + 1 then
    raise exception 'row_version must increment exactly once for %', tg_table_name
      using errcode = '40001';
  end if;
  return new;
end
$$;

do $row_versions$
declare
  aggregate_table text;
begin
  foreach aggregate_table in array array[
    'boards', 'members', 'documents', 'management_submission_threads', 'management_questions',
    'meetings', 'meeting_transcripts', 'minutes', 'tasks', 'task_evidence', 'votes',
    'wizard_drafts', 'export_requests'
  ]
  loop
    execute format(
      'create trigger boardagent_row_version before update on %I for each row execute function boardagent_guard_row_version()',
      aggregate_table
    );
  end loop;
end
$row_versions$;

create function boardagent_guard_state_transition()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
declare
  allowed boolean := false;
begin
  if new.state = old.state then
    return new;
  end if;
  allowed := case tg_table_name
    when 'members' then
      (old.state = 'invited' and new.state in ('enrollment_pending', 'removed'))
      or (old.state = 'enrollment_pending' and new.state in ('pending_activation', 'removed'))
      or (old.state = 'pending_activation' and new.state in ('active', 'removed'))
      or (old.state = 'active' and new.state in ('suspended', 'removed'))
      or (old.state = 'suspended' and new.state in ('active', 'removed'))
    when 'boards' then old.state = 'active' and new.state = 'archived'
    when 'documents' then
      (old.state = 'active' and new.state in ('archived', 'soft_deleted'))
      or (old.state = 'archived' and new.state = 'soft_deleted')
    when 'management_submission_threads' then
      (old.state = 'submitted' and new.state in ('revision_requested', 'approved_to_draft', 'rejected'))
      or (old.state = 'revision_requested' and new.state in ('resubmitted', 'rejected'))
      or (old.state = 'resubmitted' and new.state in ('revision_requested', 'approved_to_draft', 'rejected'))
    when 'management_questions' then
      (old.state = 'pending' and new.state in ('overdue', 'answered'))
      or (old.state = 'overdue' and new.state = 'answered')
      or (old.state = 'answered' and new.state = 'pending')
    when 'meetings' then
      (old.state = 'draft' and new.state in ('called', 'cancelled'))
      or (old.state = 'called' and new.state in ('completed', 'cancelled'))
    when 'meeting_transcripts' then old.state = 'unverified' and new.state = 'secretary_verified'
    when 'transcript_challenges' then old.state = 'pending' and new.state in ('accepted', 'rejected')
    when 'minutes' then
      (old.state = 'unpublished_draft' and new.state in ('published_review', 'cancelled'))
      or (old.state = 'published_review' and new.state in ('signature_ready', 'cancelled'))
      or (old.state = 'signature_ready' and new.state in ('published_review', 'finalized', 'cancelled'))
    when 'tasks' then
      (old.state = 'draft' and new.state in ('open', 'superseded'))
      or (old.state = 'open' and new.state in ('in_progress', 'evidence_submitted', 'cancelled'))
      or (old.state = 'in_progress' and new.state in ('open', 'evidence_submitted', 'cancelled'))
      or (old.state = 'evidence_submitted' and new.state in ('open', 'completed'))
    when 'votes' then
      (old.state = 'draft' and new.state in ('open', 'cancelled'))
      or (old.state = 'open' and new.state in ('source_update_pending', 'superseded', 'closing', 'cancelled'))
      or (old.state = 'source_update_pending' and new.state in ('open', 'superseded', 'cancelled'))
      or (old.state = 'closing' and new.state = 'closed')
    when 'action_stages' then
      old.state = 'active' and new.state in ('replaced', 'confirmed', 'rejected', 'expired', 'cancelled')
    when 'wizard_drafts' then
      (old.state = 'active' and new.state in ('ready_to_confirm', 'expired', 'cancelled'))
      or (old.state = 'ready_to_confirm' and new.state in ('posted', 'expired', 'cancelled'))
    when 'governance_profiles' then
      (old.state = 'draft' and new.state = 'active') or (old.state = 'active' and new.state = 'superseded')
    when 'rulesets' then
      (old.state = 'draft' and new.state = 'active') or (old.state = 'active' and new.state = 'superseded')
    when 'export_requests' then
      (old.state = 'staged' and new.state in ('confirmed', 'expired', 'cancelled'))
      or (old.state = 'confirmed' and new.state in ('queued', 'expired', 'cancelled'))
      or (old.state = 'queued' and new.state in ('running', 'failed', 'expired', 'cancelled'))
      or (old.state = 'running' and new.state in ('succeeded', 'failed', 'cancelled'))
      or (old.state = 'succeeded' and new.state in ('expired', 'deleted'))
      or (old.state = 'expired' and new.state = 'deleted')
    when 'jobs' then
      (old.state = 'queued' and new.state in ('leased', 'cancelled'))
      or (old.state = 'leased' and new.state in ('succeeded', 'retry', 'dead', 'cancelled'))
      or (old.state = 'retry' and new.state in ('leased', 'dead', 'cancelled'))
    when 'notification_jobs' then
      (old.state = 'queued' and new.state in ('leased', 'cancelled'))
      or (old.state = 'leased' and new.state in ('delivered', 'retry', 'dead', 'cancelled'))
      or (old.state = 'retry' and new.state in ('leased', 'dead', 'cancelled'))
    else false
  end;
  if not allowed then
    raise exception 'illegal % state transition: % -> %', tg_table_name, old.state, new.state
      using errcode = '23514';
  end if;
  return new;
end
$$;

do $states$
declare
  state_table text;
begin
  foreach state_table in array array[
    'action_stages', 'boards', 'documents', 'export_requests', 'governance_profiles', 'jobs',
    'management_questions', 'management_submission_threads', 'meeting_transcripts', 'meetings',
    'members', 'minutes', 'notification_jobs', 'rulesets', 'tasks', 'transcript_challenges',
    'votes', 'wizard_drafts'
  ]
  loop
    execute format(
      'create trigger boardagent_state_transition before update of state on %I for each row execute function boardagent_guard_state_transition()',
      state_table
    );
  end loop;
end
$states$;

create function boardagent_advance_audit_head()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  head audit_chain_head%rowtype;
begin
  select * into strict head from audit_chain_head where singleton_key for update;
  if new.sequence <> head.last_sequence + 1 then
    raise exception 'audit sequence must be contiguous' using errcode = '23514';
  end if;
  if new.previous_event_sha256 is distinct from head.last_event_sha256 then
    raise exception 'audit previous hash mismatch' using errcode = '23514';
  end if;
  update audit_chain_head
     set last_sequence = new.sequence,
         last_event_sha256 = new.event_sha256,
         row_version = row_version + 1
   where singleton_key;
  return new;
end
$$;
revoke all on function boardagent_advance_audit_head() from public;
grant execute on function boardagent_advance_audit_head() to boardagent_server, boardagent_worker;
create trigger boardagent_audit_chain before insert on audit_events
  for each row execute function boardagent_advance_audit_head();
