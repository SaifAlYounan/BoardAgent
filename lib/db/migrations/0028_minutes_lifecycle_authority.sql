-- BoardAgent Phase 1 / group 28: least authority for confirmed minutes lifecycle acts.

grant insert on
  minutes,
  minutes_action_declarations,
  minutes_action_item_dispositions,
  minutes_correction_cycles,
  minutes_diffs,
  minutes_resign_requirements,
  minutes_review_dispositions,
  minutes_signature_packages,
  minutes_signature_requirements,
  minutes_signature_supersessions,
  minutes_signatures,
  minutes_versions,
  tasks
to boardagent_server;

grant update(state, current_version_id, current_signature_package_id, row_version,
             finalized_at, cancelled_at)
  on minutes to boardagent_server;
grant update(current_minutes_id, row_version)
  on meetings to boardagent_server;
grant update(state, resolution, resolved_signature_id, resolved_at)
  on minutes_resign_requirements to boardagent_server;
grant update(state)
  on minutes_signature_packages to boardagent_server;
grant update(state, row_version, completed_at, cancelled_at)
  on tasks to boardagent_server;

-- Terminal minutes projections are never writable by the raw request role. The guarded
-- function below verifies the exact confirmed act and performs the terminal state change
-- as the non-login migrator, matching the task terminal-authority pattern.
drop trigger boardagent_state_transition on minutes;
create function boardagent_guard_minutes_state_transition()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if new.state=old.state then
    return new;
  end if;
  if new.state in ('finalized','cancelled') and current_user<>'boardagent_migrator' then
    raise exception 'terminal minutes transition requires the guarded minutes authority'
      using errcode = '42501';
  end if;
  if (old.state='unpublished_draft' and new.state in ('published_review','cancelled'))
     or (old.state='published_review' and new.state in ('signature_ready','cancelled'))
     or (old.state='signature_ready' and new.state in ('published_review','finalized','cancelled')) then
    return new;
  end if;
  raise exception 'invalid state transition on minutes: % -> %',old.state,new.state
    using errcode = '23514';
end
$$;
revoke all on function boardagent_guard_minutes_state_transition() from public;
create trigger boardagent_minutes_state_transition
before update of state on minutes
for each row execute function boardagent_guard_minutes_state_transition();

grant select on
  meetings,
  minutes,
  minutes_versions,
  minutes_action_declarations,
  minutes_correction_cycles,
  minutes_signature_packages,
  minutes_signature_requirements,
  minutes_signatures,
  minutes_resign_requirements,
  tasks
to boardagent_migrator;
grant update on minutes,minutes_signature_packages,minutes_resign_requirements,tasks
  to boardagent_migrator;

do $migrator_minutes_terminal_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'meetings','minutes','minutes_versions','minutes_action_declarations',
    'minutes_correction_cycles',
    'minutes_signature_packages','minutes_signature_requirements','minutes_signatures',
    'minutes_resign_requirements','tasks'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_minutes_terminal_read on %I for select to boardagent_migrator using (true)',
      source_table
    );
  end loop;
end
$migrator_minutes_terminal_read$;
create policy boardagent_migrator_minutes_terminal_update on minutes
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_minutes_terminal_update on minutes_signature_packages
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_minutes_terminal_update on minutes_resign_requirements
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_minutes_terminal_update on tasks
  for update to boardagent_migrator using (true) with check (true);

create function boardagent_apply_minutes_terminal_transition(
  candidate_minutes_id uuid,
  expected_row_version bigint,
  candidate_state text,
  candidate_consent_record_id uuid
)
returns table(next_row_version bigint,superseded_task_ids uuid[])
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  locked_minutes minutes%rowtype;
  current_version minutes_versions%rowtype;
  current_package minutes_signature_packages%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_state not in ('finalized','cancelled') then
    raise exception 'terminal minutes transition requires a managed request transaction'
      using errcode = '25000';
  end if;
  select minutes.* into locked_minutes
    from minutes
   where minutes.id=candidate_minutes_id
     and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(minutes.board_id)
   for update of minutes;
  if not found or locked_minutes.row_version<>expected_row_version then
    return;
  end if;
  select version.* into current_version
    from minutes_versions as version
   where version.id=locked_minutes.current_version_id
     and version.minutes_id=locked_minutes.id;
  if not found then
    return;
  end if;
  if locked_minutes.current_signature_package_id is not null then
    select package.* into current_package
      from minutes_signature_packages as package
     where package.id=locked_minutes.current_signature_package_id
       and package.minutes_id=locked_minutes.id
     for update of package;
    if not found then
      return;
    end if;
  end if;
  if not exists (
    select 1 from board_memberships as membership
     where membership.organization_id=locked_minutes.organization_id
       and membership.board_id=locked_minutes.board_id
       and membership.member_id=boardagent_context_uuid('boardagent.member_id')
       and membership.is_secretary
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
  ) then
    return;
  end if;
  if not exists (
    select 1
      from consent_records as consent
      join action_stages as stage on stage.id=consent.stage_id
      join input_required_attempts as attempt
        on attempt.id=consent.input_required_attempt_id
     where consent.id=candidate_consent_record_id
       and consent.organization_id=locked_minutes.organization_id
       and consent.board_id=locked_minutes.board_id
       and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
       and consent.client_id=boardagent_context_uuid('boardagent.client_id')
       and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
       and consent.action_code=case candidate_state
         when 'finalized' then 'finalize_minutes' else 'cancel_minutes' end
       and consent.target_type='minutes'
       and consent.target_id=locked_minutes.id
       and consent.package_sha256=case candidate_state
         when 'finalized' then current_package.package_sha256
         else current_version.canonical_sha256 end
       and stage.state='active'
       and stage.payload_sha256=consent.payload_sha256
       and stage.package_sha256=consent.package_sha256
       and attempt.stage_id=stage.id
       and attempt.state='prepared'
       and attempt.original_name=consent.action_code
  ) then
    return;
  end if;

  if candidate_state='finalized' then
    if locked_minutes.state<>'signature_ready'
       or locked_minutes.current_signature_package_id is null
       or current_package.state<>'current'
       or not exists (
         select 1 from minutes_action_declarations as declaration
          where declaration.minutes_id=locked_minutes.id
            and declaration.minutes_version_id=locked_minutes.current_version_id
       )
       or exists (
         select 1
           from minutes_signature_requirements as requirement
           left join minutes_signatures as signature
             on signature.package_id=requirement.package_id
            and signature.signer_member_id=requirement.member_id
          where requirement.package_id=locked_minutes.current_signature_package_id
            and requirement.requirement='required'
            and signature.id is null
       )
       or exists (
         select 1 from tasks as task
          where task.source_minutes_id=locked_minutes.id
            and task.source_minutes_version_id=locked_minutes.current_version_id
            and task.state='draft'
       ) then
      return;
    end if;
    update minutes_signature_packages
       set state='terminal'
     where id=locked_minutes.current_signature_package_id and state='current';
    update minutes_resign_requirements
       set state='resolved',resolution='package_terminal',resolved_at=transaction_timestamp()
     where minutes_id=locked_minutes.id and state='pending';
    superseded_task_ids:=array[]::uuid[];
    update minutes
       set state='finalized',finalized_at=transaction_timestamp(),row_version=row_version+1
     where id=locked_minutes.id and row_version=expected_row_version
    returning row_version into next_row_version;
  else
    if locked_minutes.state not in ('unpublished_draft','published_review','signature_ready') then
      return;
    end if;
    if locked_minutes.current_signature_package_id is not null then
      update minutes_signature_packages
         set state='terminal'
       where id=locked_minutes.current_signature_package_id and state='current';
    end if;
    update minutes_resign_requirements
       set state='resolved',resolution='package_terminal',resolved_at=transaction_timestamp()
     where minutes_id=locked_minutes.id and state='pending';
    with superseded as (
      update tasks
         set state='superseded',row_version=row_version+1
       where source_minutes_id=locked_minutes.id and state='draft'
      returning id
    )
    select coalesce(array_agg(id order by id),array[]::uuid[])
      into superseded_task_ids
      from superseded;
    update minutes
       set state='cancelled',cancelled_at=transaction_timestamp(),row_version=row_version+1
     where id=locked_minutes.id and row_version=expected_row_version
    returning row_version into next_row_version;
  end if;
  return next;
end
$$;
alter function boardagent_apply_minutes_terminal_transition(uuid,bigint,text,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_minutes_terminal_transition(uuid,bigint,text,uuid)
  from public;
grant execute on function boardagent_apply_minutes_terminal_transition(uuid,bigint,text,uuid)
  to boardagent_server;

alter table minutes_action_item_dispositions
  alter constraint minutes_action_dispositions_audit_event_fk
  deferrable initially deferred;

alter table minutes_signature_supersessions
  alter constraint minutes_signature_supersessions_audit_event_fk
  deferrable initially deferred;

-- Re-sign requirements are permanent records with a narrow mutable projection. The
-- original blanket immutable trigger contradicted their frozen pending -> resolved state.
drop trigger boardagent_immutable on minutes_resign_requirements;

create function boardagent_guard_minutes_resign_resolution()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if old.state <> 'pending' or new.state <> 'resolved'
     or new.minutes_id is distinct from old.minutes_id
     or new.signer_member_id is distinct from old.signer_member_id
     or new.from_package_id is distinct from old.from_package_id
     or new.to_package_id is distinct from old.to_package_id
     or new.created_at is distinct from old.created_at
     or new.resolution is null or new.resolved_at is null then
    raise exception 'minutes re-sign requirement permits only pending to resolved projection'
      using errcode = '55000';
  end if;
  return new;
end
$$;

create trigger boardagent_minutes_resign_resolution
before update on minutes_resign_requirements
for each row execute function boardagent_guard_minutes_resign_resolution();

-- A finalized correction is a new aggregate for the same meeting; current_minutes_id
-- identifies the live aggregate while all prior aggregates remain permanent.
alter table minutes drop constraint minutes_meeting_id_key;

create unique index minutes_one_root_per_meeting_uq
  on minutes(meeting_id)
  where correction_of_minutes_id is null;
create unique index minutes_one_direct_correction_uq
  on minutes(correction_of_minutes_id)
  where correction_of_minutes_id is not null;
create unique index minutes_correction_cycles_one_successor_uq
  on minutes_correction_cycles(original_minutes_id);
alter table minutes
  add constraint minutes_correction_same_meeting_fk
  foreign key(meeting_id,correction_of_minutes_id)
  references minutes(meeting_id,id)
  on delete restrict;

create function boardagent_guard_minutes_correction_cycle()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
begin
  if not exists (
    select 1
      from minutes as original
      join minutes as replacement
        on replacement.id=new.replacement_minutes_id
       and replacement.organization_id=original.organization_id
       and replacement.board_id=original.board_id
       and replacement.meeting_id=original.meeting_id
       and replacement.correction_of_minutes_id=original.id
     where original.id=new.original_minutes_id
       and original.organization_id=new.organization_id
       and original.board_id=new.board_id
       and original.state='finalized'
       and replacement.state='published_review'
  ) then
    raise exception 'minutes correction cycle must bind one exact published successor to a finalized original'
      using errcode = '23514';
  end if;
  return new;
end
$$;
revoke all on function boardagent_guard_minutes_correction_cycle() from public;
create trigger boardagent_minutes_correction_cycle_binding
before insert on minutes_correction_cycles
for each row execute function boardagent_guard_minutes_correction_cycle();

create function boardagent_guard_meeting_current_minutes()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
declare
  prior_state text;
  replacement_state text;
  replacement_parent uuid;
begin
  if new.current_minutes_id is not distinct from old.current_minutes_id then
    return new;
  end if;
  if new.current_minutes_id is null then
    raise exception 'meeting current minutes cannot move back to null'
      using errcode = '23514';
  end if;
  select minutes.state,minutes.correction_of_minutes_id
    into replacement_state,replacement_parent
    from minutes
   where minutes.id=new.current_minutes_id and minutes.meeting_id=new.id;
  if not found then
    raise exception 'meeting current minutes must reference its own aggregate'
      using errcode = '23514';
  end if;
  if old.current_minutes_id is null then
    if replacement_parent is not null then
      raise exception 'meeting initial minutes must be the lineage root'
        using errcode = '23514';
    end if;
    return new;
  end if;
  select minutes.state into prior_state
    from minutes
   where minutes.id=old.current_minutes_id and minutes.meeting_id=old.id;
  if prior_state<>'finalized'
     or replacement_state<>'published_review'
     or replacement_parent is distinct from old.current_minutes_id
     or not exists (
       select 1 from minutes_correction_cycles as cycle
        where cycle.original_minutes_id=old.current_minutes_id
          and cycle.replacement_minutes_id=new.current_minutes_id
     ) then
    raise exception 'meeting current minutes may advance only to its exact finalized correction tip'
      using errcode = '23514';
  end if;
  return new;
end
$$;
revoke all on function boardagent_guard_meeting_current_minutes() from public;
create trigger boardagent_meeting_current_minutes_tip
before update of current_minutes_id on meetings
for each row execute function boardagent_guard_meeting_current_minutes();

-- A correction is assembled across several statements, so its complete lineage cannot
-- be checked by an immediate row trigger. At commit every meeting with minutes must have
-- one root, one reachable current tip, an exact cycle for every child, and only finalized
-- ancestors. This closes raw-role orphan inserts without constraining statement order in
-- the confirmed lifecycle transaction.
create function boardagent_assert_minutes_lineage()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, public
as $$
declare
  candidate_meetings uuid[];
  candidate_meeting uuid;
  current_tip uuid;
  total_minutes bigint;
  root_count bigint;
  reachable_minutes bigint;
  current_reachable boolean;
begin
  if tg_table_name='meetings' then
    candidate_meetings := array[new.id];
  elsif tg_table_name='minutes_correction_cycles' then
    select array_agg(distinct minutes.meeting_id)
      into candidate_meetings
      from minutes
     where minutes.id in (new.original_minutes_id,new.replacement_minutes_id);
  else
    candidate_meetings := array[new.meeting_id];
    if tg_op='UPDATE' and old.meeting_id is distinct from new.meeting_id then
      candidate_meetings := candidate_meetings || old.meeting_id;
    end if;
  end if;

  foreach candidate_meeting in array coalesce(candidate_meetings,array[]::uuid[])
  loop
    select count(*) into total_minutes
      from minutes
     where meeting_id=candidate_meeting;
    if total_minutes=0 then
      continue;
    end if;

    select meetings.current_minutes_id into current_tip
      from meetings
     where meetings.id=candidate_meeting;
    if not found or current_tip is null then
      raise exception 'meeting with minutes must identify one current lineage tip'
        using errcode = '23514';
    end if;

    select count(*) into root_count
      from minutes
     where meeting_id=candidate_meeting
       and correction_of_minutes_id is null;
    if root_count<>1 then
      raise exception 'minutes lineage must contain exactly one root'
        using errcode = '23514';
    end if;

    if not exists (
      select 1 from minutes
       where id=current_tip and meeting_id=candidate_meeting
    ) then
      raise exception 'meeting current minutes must belong to its lineage'
        using errcode = '23514';
    end if;

    if exists (
      select 1
        from minutes as child
       where child.meeting_id=candidate_meeting
         and child.correction_of_minutes_id is not null
         and not exists (
           select 1
             from minutes_correction_cycles as cycle
            where cycle.original_minutes_id=child.correction_of_minutes_id
              and cycle.replacement_minutes_id=child.id
              and cycle.organization_id=child.organization_id
              and cycle.board_id=child.board_id
         )
    ) then
      raise exception 'every minutes correction child must have one exact correction cycle'
        using errcode = '23514';
    end if;

    if exists (
      select 1
        from minutes as ancestor
       where ancestor.meeting_id=candidate_meeting
         and ancestor.id<>current_tip
         and (
           ancestor.state<>'finalized'
           or not exists (
             select 1 from minutes as child
              where child.correction_of_minutes_id=ancestor.id
           )
         )
    ) then
      raise exception 'every noncurrent minutes aggregate must be a finalized ancestor with one successor'
        using errcode = '23514';
    end if;

    if exists (
      select 1 from minutes
       where correction_of_minutes_id=current_tip
    ) then
      raise exception 'meeting current minutes must be the correction lineage tip'
        using errcode = '23514';
    end if;

    with recursive lineage(id) as (
      select id
        from minutes
       where meeting_id=candidate_meeting
         and correction_of_minutes_id is null
      union
      select child.id
        from minutes as child
        join lineage on child.correction_of_minutes_id=lineage.id
       where child.meeting_id=candidate_meeting
    )
    select count(*),coalesce(bool_or(id=current_tip),false)
      into reachable_minutes,current_reachable
      from lineage;
    if reachable_minutes<>total_minutes or not current_reachable then
      raise exception 'meeting current minutes must be reachable from the complete correction lineage'
        using errcode = '23514';
    end if;
  end loop;
  return null;
end
$$;
revoke all on function boardagent_assert_minutes_lineage() from public;

create constraint trigger boardagent_minutes_lineage_from_minutes
after insert or update on minutes
deferrable initially deferred
for each row execute function boardagent_assert_minutes_lineage();

create constraint trigger boardagent_minutes_lineage_from_cycles
after insert on minutes_correction_cycles
deferrable initially deferred
for each row execute function boardagent_assert_minutes_lineage();

create constraint trigger boardagent_minutes_lineage_from_meeting
after update on meetings
deferrable initially deferred
for each row execute function boardagent_assert_minutes_lineage();

create unique index minutes_review_dispositions_consent_uq
  on minutes_review_dispositions(consent_record_id);
create unique index minutes_action_declarations_consent_uq
  on minutes_action_declarations(consent_record_id);
create unique index minutes_signature_packages_consent_uq
  on minutes_signature_packages(consent_record_id);
create unique index minutes_correction_cycles_consent_uq
  on minutes_correction_cycles(consent_record_id);

create policy boardagent_server_minutes_diffs_scope on minutes_diffs
  for all to boardagent_server
  using (exists (
    select 1 from minutes
     where minutes.id=minutes_diffs.minutes_id
       and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(minutes.board_id)
  ))
  with check (exists (
    select 1 from minutes
     where minutes.id=minutes_diffs.minutes_id
       and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(minutes.board_id)
  ));

create policy boardagent_server_minutes_action_dispositions_scope
  on minutes_action_item_dispositions
  for all to boardagent_server
  using (exists (
    select 1 from tasks
     where tasks.id=minutes_action_item_dispositions.task_id
       and tasks.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(tasks.board_id)
  ))
  with check (exists (
    select 1 from tasks
     where tasks.id=minutes_action_item_dispositions.task_id
       and tasks.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(tasks.board_id)
  ));

create policy boardagent_server_minutes_signature_requirements_scope
  on minutes_signature_requirements
  for all to boardagent_server
  using (exists (
    select 1 from minutes_signature_packages as package
     where package.id=minutes_signature_requirements.package_id
       and package.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(package.board_id)
  ))
  with check (exists (
    select 1 from minutes_signature_packages as package
     where package.id=minutes_signature_requirements.package_id
       and package.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(package.board_id)
  ));

create policy boardagent_server_minutes_signature_supersessions_scope
  on minutes_signature_supersessions
  for all to boardagent_server
  using (exists (
    select 1 from minutes_signature_packages as package
     where package.id=minutes_signature_supersessions.old_package_id
       and package.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(package.board_id)
  ))
  with check (exists (
    select 1 from minutes_signature_packages as package
     where package.id=minutes_signature_supersessions.old_package_id
       and package.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(package.board_id)
  ));

create policy boardagent_server_minutes_resign_requirements_scope
  on minutes_resign_requirements
  for all to boardagent_server
  using (exists (
    select 1 from minutes
     where minutes.id=minutes_resign_requirements.minutes_id
       and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(minutes.board_id)
  ))
  with check (exists (
    select 1 from minutes
     where minutes.id=minutes_resign_requirements.minutes_id
       and minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and boardagent_context_board_allowed(minutes.board_id)
  ));
