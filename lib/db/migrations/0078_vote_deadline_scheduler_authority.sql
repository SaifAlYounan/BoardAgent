-- BoardAgent Phase 4 / group 78: a deadline scanner may enqueue only the
-- already-defined automatic close kernel for an exact due open vote.

create function public.boardagent_due_automatic_vote_candidates(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_through timestamptz,
  candidate_limit integer
)
returns table(vote_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
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

create function public.boardagent_enqueue_due_automatic_vote_close(
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
set search_path=pg_catalog,public
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
  if not found then
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

alter function public.boardagent_due_automatic_vote_candidates(uuid,uuid,timestamptz,integer)
  owner to boardagent_migrator;
alter function public.boardagent_enqueue_due_automatic_vote_close(uuid,uuid,uuid,uuid,timestamptz)
  owner to boardagent_migrator;

revoke all on function public.boardagent_due_automatic_vote_candidates(uuid,uuid,timestamptz,integer)
  from public;
revoke all on function public.boardagent_enqueue_due_automatic_vote_close(uuid,uuid,uuid,uuid,timestamptz)
  from public;

grant execute on function public.boardagent_due_automatic_vote_candidates(uuid,uuid,timestamptz,integer)
  to boardagent_worker;
grant execute on function public.boardagent_enqueue_due_automatic_vote_close(uuid,uuid,uuid,uuid,timestamptz)
  to boardagent_worker;
