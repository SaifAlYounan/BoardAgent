-- BoardAgent Phase 1 / group 15: deterministic Q&A scheduler projection and
-- persisted linked-question vote-close guard.

create function boardagent_mark_due_questions_overdue(candidate_limit integer)
returns table(
  question_id uuid,
  board_id uuid,
  row_version bigint
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'worker' then
    raise exception 'question overdue transition requires a managed worker transaction'
      using errcode = '25000';
  end if;
  if candidate_limit is null or candidate_limit not between 1 and 1000 then
    raise exception 'question overdue batch limit must be between 1 and 1000'
      using errcode = '22023';
  end if;
  return query
    with locked as materialized (
      select question.id
        from management_questions as question
       where question.state = 'pending'
         and question.due_at <= transaction_timestamp()
       order by question.id
       for update skip locked
       limit candidate_limit
    ), updated as (
      update management_questions as question
         set state = 'overdue',
             row_version = question.row_version + 1
        from locked
       where question.id = locked.id
         and question.state = 'pending'
      returning question.id, question.board_id, question.row_version
    )
    select updated.id, updated.board_id, updated.row_version
      from updated
     order by updated.id;
end
$$;
alter function boardagent_mark_due_questions_overdue(integer) owner to boardagent_migrator;
revoke all on function boardagent_mark_due_questions_overdue(integer) from public;
grant execute on function boardagent_mark_due_questions_overdue(integer) to boardagent_worker;

-- This predicate is deliberately not callable by the application role. The vote
-- transition trigger invokes it as the migrator so a future close path cannot skip
-- the persisted Q&A precondition with a direct state update.
create function boardagent_vote_qna_close_ready(candidate_vote uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
      from votes as vote
      join decision_packages as package
        on package.id = vote.current_decision_package_id
       and package.vote_id = vote.id
     where vote.id = candidate_vote
       and vote.state = 'open'
       and jsonb_typeof(package.question_cutoff_manifest) = 'array'
       and jsonb_array_length(package.question_cutoff_manifest) = (
         select count(*)::integer
           from question_decision_links as link
          where link.decision_package_id = package.id
       )
       and jsonb_array_length(package.question_cutoff_manifest) = (
         select count(distinct component.value->>'ordinal')::integer
           from jsonb_array_elements(package.question_cutoff_manifest) as component(value)
       )
       and not exists (
         select 1
          from jsonb_array_elements(package.question_cutoff_manifest) as component(value)
          where jsonb_typeof(component.value) is distinct from 'object'
             or component.value - array['type', 'ordinal', 'id', 'version', 'sha256']::text[]
                  is distinct from '{}'::jsonb
             or component.value->>'type' is distinct from 'question_cutoff'
             or jsonb_typeof(component.value->'ordinal') is distinct from 'number'
             or coalesce(component.value->>'ordinal', '') !~ '^[1-9][0-9]*$'
             or jsonb_typeof(component.value->'id') is distinct from 'string'
             or jsonb_typeof(component.value->'version') is distinct from 'number'
             or coalesce(component.value->>'version', '') !~ '^[1-9][0-9]*$'
             or jsonb_typeof(component.value->'sha256') is distinct from 'string'
             or coalesce(component.value->>'sha256', '') !~ '^[0-9a-f]{64}$'
       )
       and not exists (
         select 1
           from question_decision_links as link
          where link.decision_package_id = package.id
            and (
              link.organization_id is distinct from package.organization_id
              or link.board_id is distinct from package.board_id
              or link.decision_package_version is distinct from package.version
              or link.decision_package_sha256 is distinct from package.package_sha256
              or not exists (
                select 1
                  from management_questions as question
                  join management_question_turns as cutoff
                    on cutoff.question_id = question.id
                   and cutoff.ordinal = link.inclusive_turn_ordinal
                  join management_question_answers as answer
                    on answer.question_id = question.id
                   and answer.answer_turn_id = cutoff.id
                 where question.id = link.question_id
                   and question.organization_id = package.organization_id
                   and question.board_id = package.board_id
                   and cutoff.turn_kind = 'answer'
                   and cutoff.text_sha256 = link.inclusive_turn_sha256
                   and answer.management_author_id = cutoff.author_member_id
              )
              or not exists (
                select 1
                  from jsonb_array_elements(package.question_cutoff_manifest)
                    as component(value)
                 where component.value->>'type' = 'question_cutoff'
                   and component.value->>'id' = link.question_id::text
                   and component.value->>'version' = link.inclusive_turn_ordinal::text
                   and component.value->>'sha256' = encode(link.inclusive_turn_sha256, 'hex')
              )
            )
       )
       and not exists (
         select 1
           from jsonb_array_elements(package.question_cutoff_manifest) as component(value)
          where not exists (
            select 1
              from question_decision_links as link
             where link.decision_package_id = package.id
               and component.value->>'type' = 'question_cutoff'
               and component.value->>'id' = link.question_id::text
               and component.value->>'version' = link.inclusive_turn_ordinal::text
               and component.value->>'sha256' = encode(link.inclusive_turn_sha256, 'hex')
          )
       )
  )
$$;
alter function boardagent_vote_qna_close_ready(uuid) owner to boardagent_migrator;
revoke all on function boardagent_vote_qna_close_ready(uuid) from public;

create function boardagent_guard_vote_qna_close()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if old.state = 'open' and new.state = 'closing' then
    if new.current_decision_package_id is distinct from old.current_decision_package_id then
      raise exception 'vote close cannot replace its decision package'
        using errcode = '23514';
    end if;
    if not boardagent_vote_qna_close_ready(old.id) then
      raise exception 'vote close requires an exact current package and a recorded management answer at every linked Q&A cutoff'
        using errcode = '23514';
    end if;
  end if;
  return new;
end
$$;
alter function boardagent_guard_vote_qna_close() owner to boardagent_migrator;
revoke all on function boardagent_guard_vote_qna_close() from public;
create trigger boardagent_vote_qna_close_guard
  before update of state, current_decision_package_id on votes
  for each row execute function boardagent_guard_vote_qna_close();
