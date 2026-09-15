-- Refuse a NULL terminal task state instead of cancelling, bind minutes-linked task
-- creation to the exact finalized current minutes version, and make the automatic vote
-- close scanner select only votes the typed-job guard will accept (bound package and a
-- current healthy clock sample) so an ineligible vote defers instead of raising 23514.
-- Existing role grants, canonical evidence, histories and all other behavior remain.

CREATE OR REPLACE FUNCTION public.boardagent_lock_task_source(candidate_board_id uuid, candidate_minutes_id uuid, candidate_minutes_version_id uuid)
 RETURNS TABLE(meeting_id uuid, minutes_sha256 bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board_id)
     or not boardagent_secretariat_for_board(candidate_board_id) then
    raise exception 'task source lock requires the managed secretariat request context'
      using errcode = '25000';
  end if;
  return query
    select minutes.meeting_id,version.canonical_sha256
      from minutes
      join minutes_versions as version
        on version.minutes_id=minutes.id
       and version.id=candidate_minutes_version_id
     where minutes.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and minutes.board_id=candidate_board_id
       and minutes.id=candidate_minutes_id
       -- A minutes-linked action item may bind only the exact signed, finalized source.
       -- Draft items for unfinished minutes come from log_minutes_action_items and open
       -- only when those minutes finalize (DATA-STATE-TRANSACTIONS 157, 263-264).
       and minutes.state='finalized'
       and minutes.current_version_id=version.id
 and not public.boardagent_member_record_recused('minutes',minutes.id,public.boardagent_context_uuid('boardagent.member_id'))
     -- The minutes version is immutable. Lock the mutable minutes root while reading the
     -- version hash; attempting to row-lock the immutable version would require an UPDATE
     -- policy that the request boundary deliberately does not possess.
     for key share of minutes;
end
$function$
;

CREATE OR REPLACE FUNCTION public.boardagent_apply_task_terminal_transition(candidate_task_id uuid, expected_row_version bigint, candidate_state text, candidate_consent_record_id uuid)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  locked_task tasks%rowtype;
  closure_row task_closures%rowtype;
  next_row_version bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_state is null
     or candidate_state not in ('completed','cancelled') then
    raise exception 'terminal task transition requires a managed request transaction'
      using errcode = '25000';
  end if;
  select task.* into locked_task
    from tasks as task
   where task.id=candidate_task_id
     and task.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(task.board_id)
 and not public.boardagent_member_record_recused('task',task.id,public.boardagent_context_uuid('boardagent.member_id'))
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
$function$
;

-- The scanner and the enqueue kernel now apply the exact eligibility the typed-job guard
-- enforces on insert: a bound current decision package and a current healthy clock
-- sample. A vote that is due but not yet eligible is left for a later scan.
create or replace function public.boardagent_automatic_vote_close_eligible(
  candidate_vote public.votes
)
returns boolean
language sql
stable
security definer
set search_path=pg_catalog,public,pg_temp
as $$
  select candidate_vote.state='open'
     and candidate_vote.close_mode='automatic'
     and candidate_vote.current_decision_package_id is not null
     and candidate_vote.deadline_at<=pg_catalog.clock_timestamp()
     and coalesce((
       select sample.healthy and sample.valid_until>pg_catalog.clock_timestamp()
         from public.clock_health_samples as sample
        where sample.organization_id=candidate_vote.organization_id
          and sample.measured_at<=pg_catalog.clock_timestamp()
        order by sample.measured_at desc,sample.id desc
        limit 1
     ),false);
$$;
alter function public.boardagent_automatic_vote_close_eligible(public.votes) owner to boardagent_migrator;
revoke all on function public.boardagent_automatic_vote_close_eligible(public.votes) from public;
grant execute on function public.boardagent_automatic_vote_close_eligible(public.votes) to boardagent_worker;

create or replace function public.boardagent_due_automatic_vote_candidates(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_through timestamptz,
  candidate_limit integer
)
returns table(vote_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or candidate_board_id is null
     or not public.boardagent_is_uuid_v7(candidate_board_id)
     or candidate_through is null
     or candidate_through>transaction_timestamp()
     or candidate_limit is null
     or candidate_limit not between 1 and 1000 then
    raise exception 'vote deadline scan scope, watermark, or limit is invalid' using errcode='22023';
  end if;
  if not exists (
    select 1
      from public.system_instance as instance
      join public.boards as board
        on board.organization_id=instance.organization_id
       and board.id=candidate_board_id
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
       and board.state='active'
  ) then
    raise exception 'vote deadline scan target is unavailable' using errcode='42501';
  end if;

  return query
    select vote.id
      from public.votes as vote
     where vote.organization_id=candidate_organization_id
       and vote.board_id=candidate_board_id
       and vote.state='open'
       and vote.close_mode='automatic'
       and vote.deadline_at<=candidate_through
       and public.boardagent_automatic_vote_close_eligible(vote)
       and not exists (
         select 1
           from public.jobs as job
          where job.organization_id=vote.organization_id
            and job.job_type='automatic_vote_close'
            and job.idempotency_key='automatic-vote-close:'||vote.id::text
       )
     order by vote.deadline_at,vote.id
     for update skip locked
     limit candidate_limit;
end
$$;

create or replace function public.boardagent_enqueue_due_automatic_vote_close(
  candidate_job_id uuid,
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_vote_id uuid,
  candidate_through timestamptz
)
returns table(vote_id uuid,job_id uuid,replayed boolean)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  target public.votes%rowtype;
  payload_bytes bytea;
  target_key text;
  stored public.jobs%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_job_id is null
     or not public.boardagent_is_uuid_v7(candidate_job_id)
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or candidate_board_id is null
     or not public.boardagent_is_uuid_v7(candidate_board_id)
     or candidate_vote_id is null
     or not public.boardagent_is_uuid_v7(candidate_vote_id)
     or candidate_through is null
     or candidate_through>transaction_timestamp() then
    raise exception 'automatic vote close enqueue input is invalid' using errcode='22023';
  end if;

  select vote.* into target
    from public.votes as vote
    join public.boards as board
      on board.organization_id=vote.organization_id
     and board.id=vote.board_id
     and board.state='active'
    join public.system_instance as instance
      on instance.singleton_key
     and instance.organization_id=vote.organization_id
   where vote.id=candidate_vote_id
     and vote.organization_id=candidate_organization_id
     and vote.board_id=candidate_board_id
     and vote.state='open'
     and vote.close_mode='automatic'
     and vote.deadline_at<=candidate_through
   for update of vote;
  if not found or not public.boardagent_automatic_vote_close_eligible(target) then
    -- Not yet eligible under the typed-job guard: defer to a later scan without raising.
    return;
  end if;

  payload_bytes := convert_to(
    '{"boardId":'||to_jsonb(target.board_id::text)::text||
    ',"jobType":"automatic_vote_close"'||
    ',"organizationId":'||to_jsonb(target.organization_id::text)::text||
    ',"parameters":{"voteId":'||to_jsonb(target.id::text)::text||'}'||
    ',"schemaVersion":"boardagent.job.automatic_vote_close.v1"'||
    ',"subjectId":'||to_jsonb(target.id::text)::text||
    ',"subjectType":"vote"}',
    'UTF8'
  );
  target_key := 'automatic-vote-close:'||target.id::text;

  insert into public.jobs(
    id,organization_id,board_id,job_type,schema_version,subject_type,subject_id,
    canonical_payload,payload_sha256,idempotency_key
  ) values (
    candidate_job_id,target.organization_id,target.board_id,'automatic_vote_close',
    'boardagent.job.automatic_vote_close.v1','vote',target.id,payload_bytes,
    pg_catalog.sha256(payload_bytes),target_key
  ) on conflict (organization_id,job_type,idempotency_key) do nothing
  returning * into stored;

  if found then
    vote_id := target.id;
    job_id := stored.id;
    replayed := false;
    return next;
    return;
  end if;

  select * into stored
    from public.jobs as job
   where job.organization_id=target.organization_id
     and job.job_type='automatic_vote_close'
     and job.idempotency_key=target_key;
  if not found
     or stored.board_id is distinct from target.board_id
     or stored.subject_type<>'vote'
     or stored.subject_id is distinct from target.id
     or stored.schema_version<>'boardagent.job.automatic_vote_close.v1'
     or stored.canonical_payload<>payload_bytes
     or stored.payload_sha256<>pg_catalog.sha256(payload_bytes) then
    raise exception 'automatic vote close idempotency binding conflicts' using errcode='23505';
  end if;
  vote_id := target.id;
  job_id := stored.id;
  replayed := true;
  return next;
end
$$;
