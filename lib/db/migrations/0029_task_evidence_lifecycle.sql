-- BoardAgent Phase 1 / group 29: owner evidence and confirmed task closure authority.

grant insert on
  task_closures,
  task_correction_cycles,
  task_evidence,
  task_evidence_reviews
to boardagent_server;

grant update(state, row_version) on task_evidence to boardagent_server;

create unique index task_evidence_one_submitted_per_task_uq
  on task_evidence(task_id)
  where state='submitted';
create unique index task_evidence_reviews_consent_uq
  on task_evidence_reviews(consent_record_id);
create unique index task_closures_consent_uq
  on task_closures(consent_record_id);
create unique index task_correction_cycles_consent_uq
  on task_correction_cycles(consent_record_id);

drop trigger boardagent_state_transition on tasks;
create function boardagent_guard_task_state_transition()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if new.state=old.state then
    return new;
  end if;
  if new.state in ('completed','cancelled')
     and current_user<>'boardagent_migrator' then
    raise exception 'terminal task transition requires the guarded task authority'
      using errcode = '42501';
  end if;
  if (old.state='draft' and new.state in ('open','cancelled','superseded'))
     or (old.state='open' and new.state in ('in_progress','evidence_submitted','cancelled'))
     or (old.state='in_progress' and new.state in ('open','evidence_submitted','cancelled'))
     or (old.state='evidence_submitted' and new.state in ('open','completed','cancelled')) then
    return new;
  end if;
  raise exception 'invalid state transition on tasks: % -> %',old.state,new.state
    using errcode = '23514';
end
$$;
revoke all on function boardagent_guard_task_state_transition() from public;
create trigger boardagent_task_state_transition
before update of state on tasks
for each row execute function boardagent_guard_task_state_transition();

create policy boardagent_migrator_task_terminal_read on tasks
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_task_terminal_lock on tasks
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_task_terminal_read on task_closures
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_task_terminal_read on task_evidence
  for select to boardagent_migrator using (true);
create policy boardagent_migrator_task_terminal_read on task_evidence_reviews
  for select to boardagent_migrator using (true);

create function boardagent_apply_task_terminal_transition(
  candidate_task_id uuid,
  expected_row_version bigint,
  candidate_state text,
  candidate_consent_record_id uuid
)
returns bigint
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  locked_task tasks%rowtype;
  closure_row task_closures%rowtype;
  next_row_version bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_state not in ('completed','cancelled') then
    raise exception 'terminal task transition requires a managed request transaction'
      using errcode = '25000';
  end if;
  select task.* into locked_task
    from tasks as task
   where task.id=candidate_task_id
     and task.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(task.board_id)
   for update of task;
  if not found or locked_task.row_version<>expected_row_version then
    return null;
  end if;
  if not exists (
    select 1 from board_memberships as membership
     where membership.organization_id=locked_task.organization_id
       and membership.board_id=locked_task.board_id
       and membership.member_id=boardagent_context_uuid('boardagent.member_id')
       and membership.is_secretary
       and membership.state='active'
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null or membership.active_until>transaction_timestamp())
  ) then
    return null;
  end if;
  if not exists (
    select 1
      from consent_records as consent
      join action_stages as stage on stage.id=consent.stage_id
      join input_required_attempts as attempt
        on attempt.id=consent.input_required_attempt_id
     where consent.id=candidate_consent_record_id
       and consent.organization_id=locked_task.organization_id
       and consent.board_id=locked_task.board_id
       and consent.actor_member_id=boardagent_context_uuid('boardagent.member_id')
       and consent.client_id=boardagent_context_uuid('boardagent.client_id')
       and consent.token_jti=boardagent_context_uuid('boardagent.token_jti')
       and consent.action_code=case candidate_state
         when 'completed' then 'complete_task' else 'cancel_task' end
       and consent.target_type='task'
       and consent.target_id=locked_task.id
       and consent.package_sha256=locked_task.task_sha256
       and stage.state='active'
       and attempt.state='prepared'
  ) then
    return null;
  end if;
  if candidate_state='completed' then
    if locked_task.state<>'evidence_submitted'
       or exists (
         select 1 from task_evidence as evidence
          where evidence.task_id=locked_task.id and evidence.state='submitted'
       ) then
      return null;
    end if;
    select closure.* into closure_row
      from task_closures as closure
     where closure.task_id=locked_task.id
       and closure.consent_record_id=candidate_consent_record_id
       and closure.secretary_member_id=boardagent_context_uuid('boardagent.member_id');
    if not found
       or jsonb_array_length(closure_row.accepted_evidence_manifest)=0
       or not exists (
         select 1 from task_evidence as primary_evidence
          where primary_evidence.id=closure_row.primary_evidence_id
            and primary_evidence.task_id=locked_task.id
            and primary_evidence.state='accepted'
       )
       or jsonb_array_length(closure_row.accepted_evidence_manifest)<>(
         select count(*) from task_evidence as evidence
          where evidence.task_id=locked_task.id and evidence.state='accepted'
       )
       or exists (
         select 1
           from task_evidence as evidence
           join task_evidence_reviews as review
             on review.evidence_id=evidence.id and review.decision='accepted'
          where evidence.task_id=locked_task.id and evidence.state='accepted'
            and not exists (
              select 1
                from jsonb_array_elements(closure_row.accepted_evidence_manifest) as item(value)
               where item.value->>'evidenceId'=evidence.id::text
                 and item.value->>'evidenceSha256'=encode(evidence.canonical_sha256,'hex')
                 and item.value->>'reviewId'=review.id::text
            )
       ) then
      return null;
    end if;
    update tasks as task
       set state='completed',completed_at=transaction_timestamp(),
           row_version=task.row_version+1
     where task.id=locked_task.id and task.row_version=expected_row_version
    returning task.row_version into next_row_version;
  else
    if locked_task.state not in ('draft','open','in_progress','evidence_submitted') then
      return null;
    end if;
    update tasks as task
       set state='cancelled',cancelled_at=transaction_timestamp(),
           row_version=task.row_version+1
     where task.id=locked_task.id and task.row_version=expected_row_version
    returning task.row_version into next_row_version;
  end if;
  return next_row_version;
end
$$;
alter function boardagent_apply_task_terminal_transition(uuid,bigint,text,uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_task_terminal_transition(uuid,bigint,text,uuid)
  from public;
grant execute on function boardagent_apply_task_terminal_transition(uuid,bigint,text,uuid)
  to boardagent_server;
