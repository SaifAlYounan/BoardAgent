-- BoardAgent Phase 1 / group 14: permanent Q&A authority, projection integrity, and
-- feed-before-audit foreign-key deferral required by the global lock order.

alter table notices alter constraint notices_audit_event_id_fkey
  deferrable initially deferred;
alter table pending_action_feed alter constraint pending_action_feed_audit_event_id_fkey
  deferrable initially deferred;
alter table feed_tombstones alter constraint feed_tombstones_audit_event_id_fkey
  deferrable initially deferred;

alter table management_question_answers
  add constraint management_question_answers_turn_question_fk
  foreign key (question_id, answer_turn_id)
  references management_question_turns(question_id, id) on delete restrict;

grant select on
  management_questions,
  management_question_turns,
  management_question_answers,
  question_visibility,
  question_decision_links,
  decision_packages,
  votes
to boardagent_migrator;
grant update on management_questions, votes to boardagent_migrator;

do $migrator_question_read$
declare
  source_table text;
begin
  foreach source_table in array array[
    'management_questions', 'management_question_turns', 'management_question_answers',
    'question_visibility', 'question_decision_links', 'decision_packages', 'votes'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_question_read on %I for select to boardagent_migrator using (true)',
      source_table
    );
  end loop;
end
$migrator_question_read$;
create policy boardagent_migrator_question_update on management_questions
  for update to boardagent_migrator using (true) with check (true);
create policy boardagent_migrator_question_update on votes
  for update to boardagent_migrator using (true) with check (true);

create function boardagent_question_actor_ready(candidate_board uuid, required_scope text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select required_scope in ('management:question', 'governance:read')
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
alter function boardagent_question_actor_ready(uuid, text) owner to boardagent_migrator;
revoke all on function boardagent_question_actor_ready(uuid, text) from public;
grant execute on function boardagent_question_actor_ready(uuid, text) to boardagent_server;

create function boardagent_can_ask_question(candidate_board uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select boardagent_question_actor_ready(candidate_board, 'management:question')
     and exists (
       select 1
         from board_memberships as membership
        where membership.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and membership.board_id = candidate_board
          and membership.member_id = boardagent_context_uuid('boardagent.member_id')
          and membership.state = 'active'
          and membership.active_from <= transaction_timestamp()
          and (membership.active_until is null or membership.active_until > transaction_timestamp())
          and membership.seat_role in ('voting_member', 'observer')
     )
$$;
alter function boardagent_can_ask_question(uuid) owner to boardagent_migrator;
revoke all on function boardagent_can_ask_question(uuid) from public;
grant execute on function boardagent_can_ask_question(uuid) to boardagent_server;

create function boardagent_question_owners_valid(candidate_board uuid, candidate_owners uuid[])
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select cardinality(candidate_owners) between 1 and 1000
     and cardinality(candidate_owners) = cardinality(array(select distinct unnest(candidate_owners)))
     and not exists (
       select owner_id
         from unnest(candidate_owners) as requested(owner_id)
        where not exists (
          select 1
            from members as owner
            join board_memberships as membership
              on membership.organization_id = owner.organization_id
             and membership.member_id = owner.id
             and membership.board_id = candidate_board
           where owner.id = requested.owner_id
             and owner.organization_id = boardagent_context_uuid('boardagent.organization_id')
             and owner.state = 'active'
             and membership.state = 'active'
             and membership.active_from <= transaction_timestamp()
             and (membership.active_until is null or membership.active_until > transaction_timestamp())
             and (
               membership.seat_role = 'management'
               or (membership.seat_role <> 'observer' and exists (
                 select 1
                   from organization_role_assignments as role_assignment
                  where role_assignment.organization_id = owner.organization_id
                    and role_assignment.member_id = owner.id
                    and role_assignment.role = 'management'
                    and role_assignment.active_from <= transaction_timestamp()
                    and (
                      role_assignment.active_until is null
                      or role_assignment.active_until > transaction_timestamp()
                    )
               ))
             )
        )
     )
$$;
alter function boardagent_question_owners_valid(uuid, uuid[]) owner to boardagent_migrator;
revoke all on function boardagent_question_owners_valid(uuid, uuid[]) from public;
grant execute on function boardagent_question_owners_valid(uuid, uuid[]) to boardagent_server;

create function boardagent_question_permission(candidate_question uuid, requested_permission text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select requested_permission in ('read', 'answer', 'follow_up', 'mutate')
     and exists (
       select 1
         from management_questions as question
         join board_memberships as membership
           on membership.organization_id = question.organization_id
          and membership.board_id = question.board_id
          and membership.member_id = boardagent_context_uuid('boardagent.member_id')
        where question.id = candidate_question
          and question.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and membership.state = 'active'
          and membership.active_from <= transaction_timestamp()
          and (membership.active_until is null or membership.active_until > transaction_timestamp())
          and boardagent_question_actor_ready(
            question.board_id,
            case requested_permission
              when 'read' then 'governance:read'
              else 'management:question'
            end
          )
          and (
            question.asker_member_id = boardagent_context_uuid('boardagent.member_id')
            or boardagent_context_uuid('boardagent.member_id') = any(question.assigned_owner_ids)
            or exists (
              select 1
                from question_visibility as visibility_grant
               where visibility_grant.question_id = question.id
                 and visibility_grant.effect = 'grant'
                 and visibility_grant.active_from <= transaction_timestamp()
                 and (
                   visibility_grant.active_until is null
                   or visibility_grant.active_until > transaction_timestamp()
                 )
                 and (
                   visibility_grant.grantee_member_id = boardagent_context_uuid('boardagent.member_id')
                   or visibility_grant.grantee_seat_role = membership.seat_role
                 )
            )
          )
          and not exists (
            select 1
              from question_visibility as visibility_exclusion
             where visibility_exclusion.question_id = question.id
               and visibility_exclusion.effect = 'exclude'
               and visibility_exclusion.active_from <= transaction_timestamp()
               and (
                 visibility_exclusion.active_until is null
                 or visibility_exclusion.active_until > transaction_timestamp()
               )
               and (
                 visibility_exclusion.grantee_member_id = boardagent_context_uuid('boardagent.member_id')
                 or visibility_exclusion.grantee_seat_role = membership.seat_role
               )
          )
          and jsonb_typeof(question.acl_policy->'inheritedDocumentIds') = 'array'
          and not exists (
            select 1
              from jsonb_array_elements_text(question.acl_policy->'inheritedDocumentIds') as inherited(value)
             where not case
               when inherited.value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                 then boardagent_document_permission(inherited.value::uuid, 'read')
               else false
             end
          )
          and (
            requested_permission = 'read'
            or (
              requested_permission = 'answer'
              and question.state in ('pending', 'overdue')
              and boardagent_context_uuid('boardagent.member_id') = any(question.assigned_owner_ids)
              and (
                membership.seat_role = 'management'
                or (membership.seat_role <> 'observer' and exists (
                  select 1
                    from organization_role_assignments as role_assignment
                   where role_assignment.organization_id = question.organization_id
                     and role_assignment.member_id = membership.member_id
                     and role_assignment.role = 'management'
                     and role_assignment.active_from <= transaction_timestamp()
                     and (
                       role_assignment.active_until is null
                       or role_assignment.active_until > transaction_timestamp()
                     )
                ))
              )
            )
            or (
              requested_permission = 'follow_up'
              and membership.seat_role in ('voting_member', 'observer')
            )
            or (
              requested_permission = 'mutate'
              and (
                (
                  boardagent_context_uuid('boardagent.member_id') = any(question.assigned_owner_ids)
                  and (
                    membership.seat_role = 'management'
                    or (membership.seat_role <> 'observer' and exists (
                      select 1
                        from organization_role_assignments as role_assignment
                       where role_assignment.organization_id = question.organization_id
                         and role_assignment.member_id = membership.member_id
                         and role_assignment.role = 'management'
                         and role_assignment.active_from <= transaction_timestamp()
                         and (
                           role_assignment.active_until is null
                           or role_assignment.active_until > transaction_timestamp()
                         )
                    ))
                  )
                )
                or membership.seat_role in ('voting_member', 'observer')
              )
            )
          )
     )
$$;
alter function boardagent_question_permission(uuid, text) owner to boardagent_migrator;
revoke all on function boardagent_question_permission(uuid, text) from public;
grant execute on function boardagent_question_permission(uuid, text) to boardagent_server;

create function boardagent_lock_board_for_question(candidate_board uuid)
returns boolean
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'question creation requires a managed request transaction'
      using errcode = '25000';
  end if;
  if not boardagent_can_ask_question(candidate_board) then
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
alter function boardagent_lock_board_for_question(uuid) owner to boardagent_migrator;
revoke all on function boardagent_lock_board_for_question(uuid) from public;
grant execute on function boardagent_lock_board_for_question(uuid) to boardagent_server;

create function boardagent_lock_question_for_turn(
  candidate_question uuid,
  candidate_permission text
)
returns table(
  organization_id uuid,
  board_id uuid,
  asker_member_id uuid,
  assigned_owner_ids uuid[],
  due_at timestamptz,
  acl_policy jsonb,
  question_state text,
  current_turn_id uuid,
  current_ordinal integer,
  row_version bigint
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'question turn mutation requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_permission not in ('answer', 'follow_up', 'mutate') then
    raise exception 'invalid question turn permission' using errcode = '22023';
  end if;
  return query
    select question.organization_id,
           question.board_id,
           question.asker_member_id,
           question.assigned_owner_ids,
           question.due_at,
           question.acl_policy,
           question.state,
           question.current_turn_id,
           current_turn.ordinal,
           question.row_version
      from management_questions as question
      join management_question_turns as current_turn
        on current_turn.question_id = question.id
       and current_turn.id = question.current_turn_id
     where question.id = candidate_question
       and question.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and boardagent_question_permission(question.id, candidate_permission)
     for update of question;
end
$$;
alter function boardagent_lock_question_for_turn(uuid, text) owner to boardagent_migrator;
revoke all on function boardagent_lock_question_for_turn(uuid, text) from public;
grant execute on function boardagent_lock_question_for_turn(uuid, text) to boardagent_server;

create function boardagent_lock_linked_question_votes(
  candidate_question uuid,
  candidate_next_ordinal integer
)
returns table(
  vote_id uuid,
  vote_row_version bigint,
  vote_state text,
  decision_package_id uuid,
  decision_package_sha256 bytea,
  inclusive_turn_ordinal integer
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'linked question vote lock requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_next_ordinal is null or candidate_next_ordinal < 2 then
    raise exception 'linked question next ordinal is invalid' using errcode = '22023';
  end if;
  if not boardagent_question_permission(candidate_question, 'mutate') then
    return;
  end if;
  return query
    select vote.id,
           vote.row_version,
           vote.state,
           package.id,
           package.package_sha256,
           link.inclusive_turn_ordinal
      from question_decision_links as link
      join decision_packages as package on package.id = link.decision_package_id
      join votes as vote
        on vote.id = package.vote_id
       and vote.current_decision_package_id = package.id
     where link.question_id = candidate_question
       and candidate_next_ordinal > link.inclusive_turn_ordinal
       and vote.state in ('open', 'source_update_pending')
     order by vote.id
     for update of vote;
end
$$;
alter function boardagent_lock_linked_question_votes(uuid, integer)
  owner to boardagent_migrator;
revoke all on function boardagent_lock_linked_question_votes(uuid, integer) from public;
grant execute on function boardagent_lock_linked_question_votes(uuid, integer)
  to boardagent_server;

create function boardagent_lock_visible_question_citations(candidate_versions uuid[])
returns table(
  id uuid,
  document_id uuid,
  board_id uuid,
  sha256 bytea
)
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'question citation lock requires a managed request transaction'
      using errcode = '25000';
  end if;
  if candidate_versions is null or cardinality(candidate_versions) not between 1 and 64 then
    raise exception 'question citation version count is invalid' using errcode = '22023';
  end if;
  return query
    select version.id,
           version.document_id,
           document.board_id,
           version.sha256
      from document_versions as version
      join documents as document on document.id = version.document_id
     where version.id = any(candidate_versions)
       and boardagent_document_permission(document.id, 'read')
     order by document.id, version.id
     for share of document;
end
$$;
alter function boardagent_lock_visible_question_citations(uuid[])
  owner to boardagent_migrator;
revoke all on function boardagent_lock_visible_question_citations(uuid[]) from public;
grant execute on function boardagent_lock_visible_question_citations(uuid[])
  to boardagent_server;

create function boardagent_question_recipients_entitled(
  candidate_board uuid,
  candidate_members uuid[],
  candidate_documents uuid[]
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select cardinality(candidate_members) > 0
     and cardinality(candidate_members) = cardinality(array(select distinct unnest(candidate_members)))
     and cardinality(candidate_documents) = cardinality(array(select distinct unnest(candidate_documents)))
     and not exists (
       select 1
         from unnest(candidate_members) as requested_member(member_id)
        where not exists (
          select 1
            from members as member
            join board_memberships as membership
              on membership.organization_id = member.organization_id
             and membership.member_id = member.id
             and membership.board_id = candidate_board
           where member.id = requested_member.member_id
             and member.organization_id = boardagent_context_uuid('boardagent.organization_id')
             and member.state = 'active'
             and membership.state = 'active'
             and membership.active_from <= transaction_timestamp()
             and (membership.active_until is null or membership.active_until > transaction_timestamp())
        )
     )
     and not exists (
       select 1
         from unnest(candidate_documents) as requested_document(document_id)
         cross join unnest(candidate_members) as requested_member(member_id)
        where not exists (
          select 1
            from documents as document
            join board_memberships as membership
              on membership.organization_id = document.organization_id
             and membership.board_id = document.board_id
             and membership.member_id = requested_member.member_id
           where document.id = requested_document.document_id
             and document.organization_id = boardagent_context_uuid('boardagent.organization_id')
             and document.board_id = candidate_board
             and document.state in ('active', 'archived')
             and membership.state = 'active'
             and membership.active_from <= transaction_timestamp()
             and (membership.active_until is null or membership.active_until > transaction_timestamp())
             and (
               document.created_by = requested_member.member_id
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
                      access_grant.grantee_member_id = requested_member.member_id
                      or access_grant.grantee_seat_role = membership.seat_role
                    )
                    and access_grant.permission in ('read', 'contribute', 'circulate')
               )
             )
             and not exists (
               select 1
                 from document_exclusions as exclusion
                where exclusion.document_id = document.id
                  and exclusion.organization_id = document.organization_id
                  and exclusion.board_id = document.board_id
                  and exclusion.member_id = requested_member.member_id
                  and exclusion.active_from <= transaction_timestamp()
                  and (
                    exclusion.active_until is null
                    or exclusion.active_until > transaction_timestamp()
                  )
             )
        )
     )
$$;
alter function boardagent_question_recipients_entitled(uuid, uuid[], uuid[])
  owner to boardagent_migrator;
revoke all on function boardagent_question_recipients_entitled(uuid, uuid[], uuid[]) from public;
grant execute on function boardagent_question_recipients_entitled(uuid, uuid[], uuid[])
  to boardagent_server;

create function boardagent_question_turn_write_allowed(
  candidate_question uuid,
  candidate_kind text,
  candidate_author uuid
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
         from management_questions as question
        where question.id = candidate_question
          and (
            (
              candidate_kind = 'question'
              and question.asker_member_id = candidate_author
              and boardagent_can_ask_question(question.board_id)
            )
            or (
              candidate_kind = 'answer'
              and boardagent_question_permission(question.id, 'answer')
            )
            or (
              candidate_kind = 'follow_up'
              and question.state = 'answered'
              and boardagent_question_permission(question.id, 'follow_up')
            )
          )
     )
$$;
alter function boardagent_question_turn_write_allowed(uuid, text, uuid)
  owner to boardagent_migrator;
revoke all on function boardagent_question_turn_write_allowed(uuid, text, uuid) from public;
grant execute on function boardagent_question_turn_write_allowed(uuid, text, uuid)
  to boardagent_server;

create function boardagent_question_owned_by_actor(candidate_question uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1
      from management_questions as question
     where question.id = candidate_question
       and question.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and question.asker_member_id = boardagent_context_uuid('boardagent.member_id')
       and boardagent_can_ask_question(question.board_id)
  )
$$;
alter function boardagent_question_owned_by_actor(uuid) owner to boardagent_migrator;
revoke all on function boardagent_question_owned_by_actor(uuid) from public;
grant execute on function boardagent_question_owned_by_actor(uuid) to boardagent_server;

create function boardagent_question_projection_integrity()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  current_kind text;
  current_ordinal integer;
  prior_ordinal integer;
begin
  if new.current_turn_id is null then
    raise exception 'management question requires a current turn' using errcode = '23514';
  end if;
  select turn.turn_kind,turn.ordinal into current_kind,current_ordinal
    from management_question_turns as turn
   where turn.question_id = new.id and turn.id = new.current_turn_id;
  if current_kind is null then
    raise exception 'management question current turn is unavailable' using errcode = '23514';
  end if;
  if new.state = 'answered' then
    if current_kind <> 'answer' or not exists (
      select 1
        from management_question_answers as answer
       where answer.question_id = new.id and answer.answer_turn_id = new.current_turn_id
    ) then
      raise exception 'answered management question requires its recorded answer turn'
        using errcode = '23514';
    end if;
  elsif current_kind = 'answer' then
    raise exception 'non-answered management question cannot project an answer turn'
      using errcode = '23514';
  end if;
  if old.state = 'answered' and new.state = 'pending' and current_kind <> 'follow_up' then
    raise exception 'answered management question reopens only through a follow-up turn'
      using errcode = '23514';
  end if;
  if new.current_turn_id is distinct from old.current_turn_id then
    select turn.ordinal into prior_ordinal
      from management_question_turns as turn
     where turn.question_id = old.id and turn.id = old.current_turn_id;
    if prior_ordinal is null or current_ordinal <> prior_ordinal + 1 then
      raise exception 'management question turns must advance by one immutable ordinal'
        using errcode = '23514';
    end if;
  end if;
  if new.due_at is distinct from old.due_at then
    if new.current_turn_id is not distinct from old.current_turn_id
       or current_kind <> 'follow_up'
       or new.due_at <= transaction_timestamp() then
      raise exception 'management question due time changes only through a future-due follow-up'
        using errcode = '23514';
    end if;
  end if;
  if new.acl_policy is distinct from old.acl_policy
     and (
       new.current_turn_id is not distinct from old.current_turn_id
       or current_kind not in ('answer', 'follow_up')
     ) then
    raise exception 'management question ACL changes require an appended answer or follow-up'
      using errcode = '23514';
  end if;
  return new;
end
$$;
alter function boardagent_question_projection_integrity() owner to boardagent_migrator;
revoke all on function boardagent_question_projection_integrity() from public;
grant execute on function boardagent_question_projection_integrity() to boardagent_server;
create trigger boardagent_management_question_projection
  before update of state, current_turn_id, due_at, acl_policy on management_questions
  for each row execute function boardagent_question_projection_integrity();

drop trigger boardagent_state_transition on management_questions;
create function boardagent_guard_question_state_transition()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if old.state = new.state
     or (old.state = 'pending' and new.state in ('overdue', 'answered'))
     or (old.state = 'overdue' and new.state in ('pending', 'answered'))
     or (old.state = 'answered' and new.state = 'pending') then
    return new;
  end if;
  raise exception 'invalid state transition on management_questions: % -> %', old.state, new.state
    using errcode = '23514';
end
$$;
alter function boardagent_guard_question_state_transition() owner to boardagent_migrator;
revoke all on function boardagent_guard_question_state_transition() from public;
grant execute on function boardagent_guard_question_state_transition() to boardagent_server;
create trigger boardagent_state_transition
  before update of state on management_questions
  for each row execute function boardagent_guard_question_state_transition();

create function boardagent_apply_question_turn(
  candidate_question uuid,
  expected_row_version bigint,
  candidate_turn uuid,
  candidate_state text,
  candidate_due_at timestamptz,
  candidate_acl_policy jsonb
)
returns bigint
language plpgsql
volatile
security definer
set search_path = pg_catalog, public
as $$
declare
  current_question management_questions%rowtype;
  candidate_kind text;
  next_row_version bigint;
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'question turn projection requires a managed request transaction'
      using errcode = '25000';
  end if;
  if expected_row_version is null or expected_row_version < 1
     or jsonb_typeof(candidate_acl_policy) <> 'object' then
    return null;
  end if;
  select * into current_question
    from management_questions as question
   where question.id = candidate_question
     and question.organization_id = boardagent_context_uuid('boardagent.organization_id');
  if not found or current_question.row_version <> expected_row_version then
    return null;
  end if;
  select turn.turn_kind into candidate_kind
    from management_question_turns as turn
   where turn.question_id = candidate_question
     and turn.id = candidate_turn
     and turn.author_member_id = boardagent_context_uuid('boardagent.member_id');
  if candidate_kind = 'answer' then
    if candidate_state <> 'answered'
       or current_question.state not in ('pending', 'overdue')
       or candidate_due_at is distinct from current_question.due_at
       or not boardagent_question_permission(candidate_question, 'answer') then
      return null;
    end if;
  elsif candidate_kind = 'follow_up' then
    if candidate_state <> 'pending'
       or current_question.state <> 'answered'
       or candidate_due_at <= transaction_timestamp()
       or not boardagent_question_permission(candidate_question, 'follow_up') then
      return null;
    end if;
  else
    return null;
  end if;
  update management_questions as question
     set state = candidate_state,
         current_turn_id = candidate_turn,
         due_at = candidate_due_at,
         acl_policy = candidate_acl_policy,
         row_version = question.row_version + 1
   where question.id = candidate_question
     and question.row_version = expected_row_version
  returning question.row_version into next_row_version;
  return next_row_version;
end
$$;
alter function boardagent_apply_question_turn(uuid, bigint, uuid, text, timestamptz, jsonb)
  owner to boardagent_migrator;
revoke all on function boardagent_apply_question_turn(uuid, bigint, uuid, text, timestamptz, jsonb)
  from public;
grant execute on function boardagent_apply_question_turn(uuid, bigint, uuid, text, timestamptz, jsonb)
  to boardagent_server;

drop policy boardagent_server_scope on management_questions;
create policy boardagent_server_questions_select on management_questions
  for select to boardagent_server using (boardagent_question_permission(id, 'read'));
create policy boardagent_server_questions_insert on management_questions
  for insert to boardagent_server with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and asker_member_id = boardagent_context_uuid('boardagent.member_id')
    and state = 'pending'
    and boardagent_can_ask_question(board_id)
    and boardagent_question_owners_valid(board_id, assigned_owner_ids)
  );
create policy boardagent_server_questions_update on management_questions
  for update to boardagent_server
  using (boardagent_question_permission(id, 'mutate'))
  with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_question_permission(id, 'mutate')
  );
revoke update on management_questions from boardagent_server;
grant update(state, current_turn_id, due_at, acl_policy, row_version)
  on management_questions to boardagent_server;

drop policy boardagent_server_scope on management_question_turns;
create policy boardagent_server_question_turns_select on management_question_turns
  for select to boardagent_server using (boardagent_question_permission(question_id, 'read'));
create policy boardagent_server_question_turns_insert on management_question_turns
  for insert to boardagent_server with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and boardagent_question_turn_write_allowed(question_id, turn_kind, author_member_id)
  );

drop policy boardagent_server_scope on management_question_answers;
create policy boardagent_server_question_answers_select on management_question_answers
  for select to boardagent_server using (boardagent_question_permission(question_id, 'read'));
create policy boardagent_server_question_answers_insert on management_question_answers
  for insert to boardagent_server with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and management_author_id = boardagent_context_uuid('boardagent.member_id')
    and boardagent_question_permission(question_id, 'answer')
  );

drop policy boardagent_server_scope on question_visibility;
create policy boardagent_server_question_visibility_select on question_visibility
  for select to boardagent_server using (boardagent_question_permission(question_id, 'read'));
create policy boardagent_server_question_visibility_insert on question_visibility
  for insert to boardagent_server with check (
    organization_id = boardagent_context_uuid('boardagent.organization_id')
    and boardagent_context_board_allowed(board_id)
    and created_by = boardagent_context_uuid('boardagent.member_id')
    and boardagent_question_owned_by_actor(question_id)
  );

drop policy boardagent_server_scope on question_decision_links;
create policy boardagent_server_question_links_select on question_decision_links
  for select to boardagent_server using (boardagent_question_permission(question_id, 'read'));
