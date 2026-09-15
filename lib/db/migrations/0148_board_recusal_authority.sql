-- Versioned board-wide recusals preserve membership and all historical records.
-- Only the exact confirmed action can append an exclusion. Runtime has no table write grant.
create table public.board_exclusions (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  organization_id uuid not null,
  board_id uuid not null,
  member_id uuid not null,
  version integer not null check (version>0),
  state text not null check (state in ('excluded','lifted')),
  reason text not null check (length(reason) between 1 and 65536),
  actor_member_id uuid not null,
  consent_record_id uuid not null unique references public.consent_records(id),
  audit_event_id uuid not null unique references public.audit_events(id),
  created_at timestamptz(6) not null default transaction_timestamp(),
  unique(board_id,member_id,version),
  foreign key(organization_id,board_id) references public.boards(organization_id,id),
  foreign key(organization_id,member_id) references public.members(organization_id,id),
  foreign key(organization_id,actor_member_id) references public.members(organization_id,id)
);
alter table public.board_exclusions enable row level security;
alter table public.board_exclusions force row level security;
grant select on public.board_exclusions to boardagent_server,boardagent_backup;
grant select,insert on public.board_exclusions to boardagent_migrator;
create policy boardagent_migrator_board_exclusions_read on public.board_exclusions
  for select to boardagent_migrator using(true);
create policy boardagent_migrator_board_exclusions_insert on public.board_exclusions
  for insert to boardagent_migrator with check (
    current_setting('boardagent.transaction_scope',true)='request'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and actor_member_id=public.boardagent_context_uuid('boardagent.member_id'));
create policy boardagent_backup_read on public.board_exclusions for select to boardagent_backup using(true);
-- An excluded person may read their own exclusion history; no governance content is returned.
create policy boardagent_server_board_exclusions_read on public.board_exclusions
  for select to boardagent_server using (
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and (member_id=public.boardagent_context_uuid('boardagent.member_id')
      or public.boardagent_secretariat_for_board(board_id)));

create function public.boardagent_member_board_recused(candidate_board uuid,candidate_member uuid)
returns boolean language sql stable security definer
set search_path=pg_catalog,public,pg_temp as $$
  select coalesce((select exclusion.state='excluded' from public.board_exclusions exclusion
    where exclusion.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
      and exclusion.board_id=candidate_board and exclusion.member_id=candidate_member
    order by exclusion.version desc limit 1),false)
$$;
alter function public.boardagent_member_board_recused(uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_member_board_recused(uuid,uuid) from public;
grant execute on function public.boardagent_member_board_recused(uuid,uuid) to boardagent_server,boardagent_worker;

CREATE OR REPLACE FUNCTION public.boardagent_context_board_allowed(candidate uuid)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
  return not public.boardagent_member_board_recused(candidate,public.boardagent_context_uuid('boardagent.member_id')) and exists (
    select 1 from jsonb_array_elements_text(raw_value::jsonb) as allowed(value)
     where allowed.value = candidate::text
  );
exception when others then
  return false;
end
$function$
;
alter function public.boardagent_context_board_allowed(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_context_board_allowed(uuid) from public;
grant execute on function public.boardagent_context_board_allowed(uuid) to boardagent_server,boardagent_worker,boardagent_backup;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_vote_creation_electorate(candidate_board uuid)
 RETURNS TABLE(member_id uuid, membership_version_id uuid, is_chair boolean, voting_weight bigint, authority_snapshot jsonb, authority_snapshot_sha256 bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board) then
    raise exception 'vote creation electorate requires the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           version.id,
           membership.is_chair,
           membership.voting_weight,
           version.authority_snapshot,
           version.snapshot_sha256
      from boards as board
      join board_memberships as membership
        on membership.organization_id = board.organization_id
       and membership.board_id = board.id
      join lateral (
        select candidate.id,
               candidate.seat_role,
               candidate.is_chair,
               candidate.voting_weight,
               candidate.authority_snapshot,
               candidate.snapshot_sha256
          from membership_versions as candidate
         where candidate.membership_id = membership.id
         order by candidate.version desc, candidate.id desc
         limit 1
      ) as version on true
     where board.id = candidate_board
       and board.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and board.state = 'active'
       and boardagent_vote_actor_ready(board.id)
       and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role = 'voting_member'
       and version.seat_role = membership.seat_role
       and version.is_chair = membership.is_chair
       and version.voting_weight = membership.voting_weight
     order by membership.member_id
     for update of membership
     for share of version;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_vote_creation_recipients(candidate_board uuid)
 RETURNS TABLE(member_id uuid, seat_role text, entitlement_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request'
     or not boardagent_context_board_allowed(candidate_board) then
    raise exception 'vote creation recipients require the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.seat_role,
           membership.entitlement_generation
      from boards as board
      join board_memberships as membership
        on membership.organization_id = board.organization_id
       and membership.board_id = board.id
      join members as recipient
        on recipient.organization_id = membership.organization_id
       and recipient.id = membership.member_id
     where board.id = candidate_board
       and board.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and board.state = 'active'
       and boardagent_vote_actor_ready(board.id)
       and recipient.state = 'active'
       and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and exists (
         select 1
           from onboarding_attestations as attestation
          where attestation.organization_id = membership.organization_id
            and attestation.member_id = membership.member_id
            and attestation.board_id = membership.board_id
            and attestation.terms_version_id = (
              select terms.id
                from onboarding_terms_versions as terms
               where terms.organization_id = membership.organization_id
                 and terms.seat_role = membership.seat_role
                 and terms.effective_at <= transaction_timestamp()
               order by terms.effective_at desc, terms.version desc, terms.id desc
               limit 1
            )
            and attestation.support_version_id = (
              select support.id
                from secretary_support_versions as support
               where support.organization_id = membership.organization_id
                 and (support.board_id = membership.board_id or support.board_id is null)
                 and support.effective_at <= transaction_timestamp()
               order by (support.board_id = membership.board_id) desc,
                        support.effective_at desc,
                        support.version desc,
                        support.id desc
               limit 1
            )
       )
     order by membership.member_id
     for update of membership
     for share of recipient;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_vote_electorate(candidate_vote uuid)
 RETURNS TABLE(member_id uuid, membership_id uuid, membership_version_id uuid, membership_version integer, is_chair boolean, voting_weight bigint, authority_snapshot jsonb, authority_snapshot_sha256 bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote electorate freeze requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.id,
           version.id,
           version.version,
           membership.is_chair,
           membership.voting_weight,
           version.authority_snapshot,
           version.snapshot_sha256
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join lateral (
        select candidate.id,
               candidate.version,
               candidate.seat_role,
               candidate.is_chair,
               candidate.voting_weight,
               candidate.authority_snapshot,
               candidate.snapshot_sha256
          from membership_versions as candidate
         where candidate.membership_id = membership.id
         order by candidate.version desc, candidate.id desc
         limit 1
      ) as version on true
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state = 'draft'
       and boardagent_vote_actor_ready(vote.board_id)
       and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role = 'voting_member'
       and version.seat_role = membership.seat_role
       and version.is_chair = membership.is_chair
       and version.voting_weight = membership.voting_weight
       and not exists (
         select 1 from vote_exclusions as exclusion
          where exclusion.vote_id = vote.id
            and exclusion.member_id = membership.member_id
            and exclusion.state = 'excluded'
       )
     order by membership.member_id
     for update of membership
     for share of version;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_vote_recipients(candidate_vote uuid)
 RETURNS TABLE(member_id uuid, seat_role text, entitlement_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote recipient freeze requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.seat_role,
           membership.entitlement_generation
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join members as recipient
        on recipient.organization_id = membership.organization_id
       and recipient.id = membership.member_id
     where vote.id = candidate_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state = 'draft'
       and boardagent_vote_actor_ready(vote.board_id)
       and recipient.state = 'active'
       and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and exists (
         select 1
           from onboarding_attestations as attestation
          where attestation.organization_id = membership.organization_id
            and attestation.member_id = membership.member_id
            and attestation.board_id = membership.board_id
            and attestation.terms_version_id = (
              select terms.id
                from onboarding_terms_versions as terms
               where terms.organization_id = membership.organization_id
                 and terms.seat_role = membership.seat_role
                 and terms.effective_at <= transaction_timestamp()
               order by terms.effective_at desc, terms.version desc, terms.id desc
               limit 1
            )
            and attestation.support_version_id = (
              select support.id
                from secretary_support_versions as support
               where support.organization_id = membership.organization_id
                 and (support.board_id = membership.board_id or support.board_id is null)
                 and support.effective_at <= transaction_timestamp()
               order by (support.board_id = membership.board_id) desc,
                        support.effective_at desc,
                        support.version desc,
                        support.id desc
               limit 1
            )
       )
     order by membership.member_id
     for update of membership
     for share of recipient;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_replacement_electorate(candidate_old_vote uuid)
 RETURNS TABLE(member_id uuid, membership_id uuid, membership_version_id uuid, membership_version integer, is_chair boolean, voting_weight bigint, authority_snapshot jsonb, authority_snapshot_sha256 bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement electorate requires a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.id,
           version.id,
           version.version,
           membership.is_chair,
           membership.voting_weight,
           version.authority_snapshot,
           version.snapshot_sha256
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join lateral (
        select candidate.id,
               candidate.version,
               candidate.seat_role,
               candidate.is_chair,
               candidate.voting_weight,
               candidate.authority_snapshot,
               candidate.snapshot_sha256
          from membership_versions as candidate
         where candidate.membership_id = membership.id
         order by candidate.version desc, candidate.id desc
         limit 1
      ) as version on true
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state in ('open', 'source_update_pending')
       and boardagent_vote_actor_ready(vote.board_id)
       and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and membership.seat_role = 'voting_member'
       and version.seat_role = membership.seat_role
       and version.is_chair = membership.is_chair
       and version.voting_weight = membership.voting_weight
       and not exists (
         select 1
           from vote_exclusions as exclusion
          where exclusion.vote_id = vote.id
            and exclusion.member_id = membership.member_id
            and exclusion.state = 'excluded'
       )
     order by membership.member_id
     for update of membership
     for share of version;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_replacement_recipients(candidate_old_vote uuid)
 RETURNS TABLE(member_id uuid, seat_role text, entitlement_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope', true) is distinct from 'request' then
    raise exception 'vote replacement recipients require a managed request transaction'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,
           membership.seat_role,
           membership.entitlement_generation
      from votes as vote
      join board_memberships as membership
        on membership.organization_id = vote.organization_id
       and membership.board_id = vote.board_id
      join members as recipient
        on recipient.organization_id = membership.organization_id
       and recipient.id = membership.member_id
     where vote.id = candidate_old_vote
       and vote.organization_id = boardagent_context_uuid('boardagent.organization_id')
       and vote.state in ('open', 'source_update_pending')
       and boardagent_vote_actor_ready(vote.board_id)
       and recipient.state = 'active'
       and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from <= transaction_timestamp()
       and (membership.active_until is null or membership.active_until > transaction_timestamp())
       and exists (
         select 1
           from onboarding_attestations as attestation
          where attestation.organization_id = membership.organization_id
            and attestation.member_id = membership.member_id
            and attestation.board_id = membership.board_id
            and attestation.terms_version_id = (
              select terms.id
                from onboarding_terms_versions as terms
               where terms.organization_id = membership.organization_id
                 and terms.seat_role = membership.seat_role
                 and terms.effective_at <= transaction_timestamp()
               order by terms.effective_at desc, terms.version desc, terms.id desc
               limit 1
            )
            and attestation.support_version_id = (
              select support.id
                from secretary_support_versions as support
               where support.organization_id = membership.organization_id
                 and (support.board_id = membership.board_id or support.board_id is null)
                 and support.effective_at <= transaction_timestamp()
               order by (support.board_id = membership.board_id) desc,
                        support.effective_at desc,
                        support.version desc,
                        support.id desc
               limit 1
            )
       )
     order by membership.member_id
     for update of membership
     for share of recipient;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_meeting_recipients(candidate_board uuid, candidate_member_ids uuid[])
 RETURNS TABLE(member_id uuid, entitlement_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_member_ids is null
     or cardinality(candidate_member_ids) not between 1 and 1000
     or exists (select 1 from unnest(candidate_member_ids) as requested(id) where id is null)
     or (select count(distinct id) from unnest(candidate_member_ids) as requested(id))
          <> cardinality(candidate_member_ids)
     or not boardagent_meeting_secretary_for_board(candidate_board) then
    raise exception 'meeting recipient lock requires exact secretary authority and recipients'
      using errcode='42501';
  end if;
  return query
    select membership.member_id,membership.entitlement_generation
      from boards as board
      join board_memberships as membership
        on membership.organization_id=board.organization_id
       and membership.board_id=board.id
      join members as member
        on member.organization_id=membership.organization_id
       and member.id=membership.member_id
     where board.id=candidate_board
       and board.organization_id=boardagent_context_uuid('boardagent.organization_id')
       and board.state='active'
       and membership.member_id=any(candidate_member_ids)
       and member.state='active'
       and membership.state='active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null
            or membership.active_until>transaction_timestamp())
     order by membership.member_id
     for update of membership,member;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_document_recipients(candidate_document_id uuid, candidate_version_id uuid, candidate_member_ids uuid[])
 RETURNS TABLE(member_id uuid, entitlement_generation bigint, can_read boolean, already_circulated boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
declare
  source_board_id uuid;
  source_organization_id uuid;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_member_ids is null
     or cardinality(candidate_member_ids) not between 1 and 1000
     or exists (select 1 from unnest(candidate_member_ids) as requested(id) where id is null)
     or (select count(distinct id) from unnest(candidate_member_ids) as requested(id))
          <> cardinality(candidate_member_ids) then
    raise exception 'document recipient lock requires one through 1000 exact recipients'
      using errcode='22023';
  end if;
  select document.organization_id,document.board_id
    into source_organization_id,source_board_id
    from documents as document
    join document_versions as version
      on version.document_id=document.id and version.id=candidate_version_id
   where document.id=candidate_document_id
     and document.organization_id=boardagent_context_uuid('boardagent.organization_id')
     and boardagent_context_board_allowed(document.board_id)
     and boardagent_document_secretary_for_board(document.board_id)
     and document.state='active';
  if source_board_id is null then
    return;
  end if;
  return query
    select membership.member_id,
           membership.entitlement_generation,
           member.state='active'
             and membership.state='active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
             and membership.active_from<=transaction_timestamp()
             and (membership.active_until is null
                  or membership.active_until>transaction_timestamp())
             and (
               document.created_by=membership.member_id
               or exists (
                 select 1 from document_access_grants as access_grant
                  where access_grant.document_id=document.id
                    and access_grant.organization_id=document.organization_id
                    and access_grant.board_id=document.board_id
                    and access_grant.active_from<=transaction_timestamp()
                    and (access_grant.active_until is null
                         or access_grant.active_until>transaction_timestamp())
                    and (access_grant.grantee_member_id=membership.member_id
                         or access_grant.grantee_seat_role=membership.seat_role)
                    and access_grant.permission in ('read','contribute','circulate')
               )
             )
             and not exists (
               select 1 from document_exclusions as exclusion
                where exclusion.document_id=document.id
                  and exclusion.organization_id=document.organization_id
                  and exclusion.board_id=document.board_id
                  and exclusion.member_id=membership.member_id
                  and exclusion.active_from<=transaction_timestamp()
                  and (exclusion.active_until is null
                       or exclusion.active_until>transaction_timestamp())
             ),
           exists (
             select 1 from circulation_recipients as prior_recipient
             join document_circulations as prior_circulation
               on prior_circulation.id=prior_recipient.circulation_id
              and prior_circulation.document_id=candidate_document_id
              and prior_circulation.document_version_id=candidate_version_id
              and prior_circulation.state='committed'
            where prior_recipient.member_id=membership.member_id
           )
      from documents as document
      join board_memberships as membership
        on membership.organization_id=document.organization_id
       and membership.board_id=document.board_id
      join members as member
        on member.organization_id=membership.organization_id
       and member.id=membership.member_id
     where document.id=candidate_document_id
       and document.organization_id=source_organization_id
       and document.board_id=source_board_id
       and membership.member_id=any(candidate_member_ids)
     order by membership.member_id
     for update of membership,member;
end
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_question_owners_valid(candidate_board uuid, candidate_owners uuid[])
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
             and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
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
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_question_recipients_entitled(candidate_board uuid, candidate_members uuid[], candidate_documents uuid[])
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
             and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
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
             and membership.state = 'active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
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
$function$
;

-- Preserve the existing authority and lock checks; omit recused recipients.
CREATE OR REPLACE FUNCTION public.boardagent_lock_minutes_review_secretaries(candidate_organization_id uuid, candidate_board_id uuid)
 RETURNS TABLE(member_id uuid, entitlement_generation bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
     or candidate_organization_id
          is distinct from boardagent_context_uuid('boardagent.organization_id')
     or not boardagent_context_board_allowed(candidate_board_id) then
    raise exception 'minutes secretary lock requires the managed request board context'
      using errcode = '25000';
  end if;
  return query
    select membership.member_id,membership.entitlement_generation
      from board_memberships as membership
     where membership.organization_id=candidate_organization_id
       and membership.board_id=candidate_board_id
       and membership.is_secretary
       and membership.state='active' and not public.boardagent_member_board_recused(membership.board_id,membership.member_id)
       and membership.active_from<=transaction_timestamp()
       and (membership.active_until is null
            or membership.active_until>transaction_timestamp())
     order by membership.member_id
       for update;
end
$function$
;

-- Snapshot is recomputed under the board and target member locks at confirmation.
create function public.boardagent_prepare_board_recusal(candidate_request jsonb)
returns jsonb language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare
  org uuid:=public.boardagent_context_uuid('boardagent.organization_id');
  b uuid; m uuid; board_version bigint; member_name text;
  prior public.board_exclusions%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'request'
    or jsonb_typeof(candidate_request) is distinct from 'object'
    or not candidate_request ?& array['boardId','memberId','operation','reason','idempotencyKey']
    or exists(select 1 from jsonb_object_keys(candidate_request) k where k not in ('boardId','memberId','operation','reason','idempotencyKey'))
    or candidate_request->>'operation' not in ('add','lift')
    or length(candidate_request->>'reason') not between 1 and 65536
    or length(candidate_request->>'idempotencyKey') not between 16 and 256 then
    raise exception 'board recusal is unavailable' using errcode='42501';
  end if;
  b:=(candidate_request->>'boardId')::uuid; m:=(candidate_request->>'memberId')::uuid;
  if not public.boardagent_secretariat_for_board(b) then
    raise exception 'board recusal is unavailable' using errcode='42501';
  end if;
  select row_version into board_version from public.boards
    where id=b and organization_id=org and state='active' for update;
  select member.display_name into member_name
    from public.members member join public.board_memberships membership
      on membership.organization_id=member.organization_id and membership.member_id=member.id
    where member.organization_id=org and member.id=m and member.state='active'
      and membership.board_id=b and membership.state='active'
      and membership.active_from<=transaction_timestamp()
      and (membership.active_until is null or membership.active_until>transaction_timestamp())
    for update of membership,member;
  if board_version is null or member_name is null then
    raise exception 'board recusal is unavailable' using errcode='42501';
  end if;
  -- Feed state triggers allocate positions; take that per-person lock before the audit head.
  perform 1 from public.member_feed_sync_counters where organization_id=org and member_id=m for update;
  select * into prior from public.board_exclusions
    where organization_id=org and board_id=b and member_id=m order by version desc limit 1;
  if (candidate_request->>'operation'='add' and prior.state='excluded')
    or (candidate_request->>'operation'='lift' and prior.state is distinct from 'excluded') then
    raise exception 'board recusal transition is unavailable' using errcode='42501';
  end if;
  -- This fail-closed guard remains until the separate open-vote cascade slice is implemented.
  if exists(select 1 from public.votes v where v.organization_id=org and v.board_id=b
    and v.state in ('open','source_update_pending','closing')) then
    raise exception 'board recusal with active votes requires the pending cascade implementation' using errcode='55000';
  end if;
  return jsonb_build_object('schemaVersion','boardagent.board-recusal-consent.v1',
    'request',candidate_request,'boardVersion',board_version::text,'memberDisplayName',member_name,
    'priorExclusionId',prior.id,'priorVersion',coalesce(prior.version,0));
end
$$;
alter function public.boardagent_prepare_board_recusal(jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_board_recusal(jsonb) from public;
grant execute on function public.boardagent_prepare_board_recusal(jsonb) to boardagent_server;

create function public.boardagent_apply_board_recusal(candidate_consent uuid,candidate_exclusion uuid,candidate_audit uuid)
returns void language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare
  consent public.consent_records%rowtype;
  stage public.action_stages%rowtype;
  payload jsonb;
  snapshot jsonb;
  request jsonb;
begin
  select * into consent from public.consent_records c where c.id=candidate_consent;
  select * into stage from public.action_stages s where s.id=consent.stage_id;
  if (current_setting('boardagent.transaction_scope',true)='request'
    and consent.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and consent.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
    and consent.client_id=public.boardagent_context_uuid('boardagent.client_id')
    and consent.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
    and consent.confirmed_at=transaction_timestamp()
    and consent.action_code='manage_recusal' and consent.target_type='board'
    and consent.board_id=consent.target_id and consent.package_sha256 is null
    and stage.state='confirmed' and stage.confirmed_at=consent.confirmed_at
    and stage.action_code=consent.action_code and stage.target_type=consent.target_type
    and stage.target_id=consent.target_id and stage.board_id=consent.board_id
    and stage.actor_member_id=consent.actor_member_id and stage.client_id=consent.client_id
    and stage.token_jti=consent.token_jti and stage.payload_sha256=consent.payload_sha256
    and stage.payload_sha256=pg_catalog.sha256(stage.canonical_payload)
    and stage.canonical_schema='boardagent.board-recusal-consent.v1'
    and exists(select 1 from public.input_required_attempts a where a.id=consent.input_required_attempt_id
      and a.stage_id=stage.id and a.state='confirmed' and a.response_action='accept'
      and a.original_name='manage_recusal')
    and public.boardagent_is_uuid_v7(candidate_exclusion)) is distinct from true then
    raise exception 'board recusal lacks exact confirmed authority' using errcode='42501';
  end if;
  payload:=convert_from(stage.canonical_payload,'UTF8')::jsonb;
  request:=payload->'request';
  snapshot:=public.boardagent_prepare_board_recusal(request);
  if payload is distinct from snapshot or (request->>'boardId')::uuid<>consent.board_id
    or not exists(select 1 from public.audit_events a
      where a.id=candidate_audit and a.organization_id=consent.organization_id
        and a.board_id=consent.board_id and a.object_type='board' and a.object_id=consent.board_id
        and a.event_type='recusal_changed' and a.actor_member_id=consent.actor_member_id
        and a.client_id=consent.client_id and a.token_jti=consent.token_jti
        and a.consent_record_id=consent.id
        and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'->>'exclusionId'=candidate_exclusion::text
        and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'->'request'=request) then
    raise exception 'board recusal lacks exact confirmed evidence' using errcode='42501';
  end if;
  insert into public.board_exclusions(id,organization_id,board_id,member_id,version,state,reason,
    actor_member_id,consent_record_id,audit_event_id)
    values(candidate_exclusion,consent.organization_id,consent.board_id,(request->>'memberId')::uuid,
      (payload->>'priorVersion')::integer+1,case request->>'operation' when 'add' then 'excluded' else 'lifted' end,
      request->>'reason',consent.actor_member_id,consent.id,candidate_audit);
end
$$;
alter function public.boardagent_apply_board_recusal(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_apply_board_recusal(uuid,uuid,uuid) from public;
grant execute on function public.boardagent_apply_board_recusal(uuid,uuid,uuid) to boardagent_server;

-- Defence in depth: a forgotten recipient filter must fail, never enqueue hidden board activity.
create function public.boardagent_guard_recused_board_recipient()
returns trigger language plpgsql set search_path=pg_catalog,public,pg_temp as $$
declare recipient uuid;
begin
  recipient:=(to_jsonb(new)->>case when tg_table_name='notices' then 'recipient_member_id' else 'member_id' end)::uuid;
  if current_user in ('boardagent_server','boardagent_worker','boardagent_migrator')
    and new.board_id is not null and public.boardagent_member_board_recused(new.board_id,recipient) then
    raise exception 'board recipient is unavailable' using errcode='42501';
  end if;
  return new;
end
$$;
revoke all on function public.boardagent_guard_recused_board_recipient() from public;
create trigger boardagent_recused_board_recipient before insert on public.notices
  for each row execute function public.boardagent_guard_recused_board_recipient();
create trigger boardagent_recused_board_recipient before insert on public.pending_action_feed
  for each row execute function public.boardagent_guard_recused_board_recipient();
