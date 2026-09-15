-- Map existing question projection vocabulary to its exact management-question
-- audit evidence. Historical canonical payloads, hashes and rows are not rewritten.
-- Same-type bindings and the existing onboarding exception remain unchanged.
-- Question mappings additionally bind the known action/event relationship and an
-- exact organization, board and permanent question. Revocation retains its original
-- source audit; an answer audit may justify only a resolved question tombstone.

create or replace function public.boardagent_feed_reconcile_candidates(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_member_id uuid,
  candidate_limit integer
)
returns table(
  feed_id uuid,
  board_id uuid,
  member_id uuid,
  action_type text,
  object_type text,
  object_id uuid,
  object_version bigint,
  prior_entitlement_generation bigint,
  current_entitlement_generation bigint,
  feed_sequence bigint,
  canonical_payload bytea,
  payload_sha256 text,
  audit_event_id uuid,
  existing_tombstones bigint,
  audit_binding_valid boolean
)
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
     or candidate_member_id is null
     or not public.boardagent_is_uuid_v7(candidate_member_id)
     or candidate_limit is null
     or candidate_limit not between 1 and 1000 then
    raise exception 'feed reconciliation scope or limit is invalid' using errcode='22023';
  end if;
  if not exists (
    select 1
      from public.system_instance as instance
      join public.members as member
        on member.organization_id=instance.organization_id
       and member.id=candidate_member_id
      join public.board_memberships as membership
        on membership.organization_id=instance.organization_id
       and membership.member_id=member.id
       and membership.board_id=candidate_board_id
      join public.boards as board
        on board.organization_id=instance.organization_id
       and board.id=membership.board_id
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'feed reconciliation target is unavailable' using errcode='42501';
  end if;

  return query
    select feed.id,
           feed.board_id,
           feed.member_id,
           feed.action_type,
           feed.object_type,
           feed.object_id,
           feed.object_version,
           feed.entitlement_generation,
           membership.entitlement_generation,
           feed.feed_sequence,
           feed.canonical_payload,
           encode(feed.payload_sha256,'hex'),
           feed.audit_event_id,
           (select count(*)
              from public.feed_tombstones as tombstone
             where tombstone.removed_feed_id=feed.id),
           exists (
             select 1
               from public.audit_events as audit
              where audit.id=feed.audit_event_id
                and audit.organization_id=feed.organization_id
                and (audit.board_id is null or audit.board_id=feed.board_id)
                and (audit.object_type=feed.object_type
                 or (feed.object_type='question' and audit.object_type='management_question'
                   and audit.board_id=feed.board_id
                   and ((feed.action_type='management_question_due'
                         and audit.event_type in ('management_question_asked','management_question_followed_up'))
                     or (feed.action_type='management_question_answered'
                         and audit.event_type='management_question_answered'))
                   and exists (select 1 from public.management_questions question
                     where question.organization_id=feed.organization_id
                       and question.board_id=feed.board_id and question.id=feed.object_id)))
                and audit.object_id=feed.object_id
           )
      from public.pending_action_feed as feed
      join public.board_memberships as membership
        on membership.organization_id=feed.organization_id
       and membership.board_id=feed.board_id
       and membership.member_id=feed.member_id
      join public.members as member
        on member.organization_id=feed.organization_id
       and member.id=feed.member_id
      join public.boards as board
        on board.organization_id=feed.organization_id
       and board.id=feed.board_id
     where feed.organization_id=candidate_organization_id
       and feed.board_id=candidate_board_id
       and feed.member_id=candidate_member_id
       and feed.state='pending'
       and not (
         board.state='active'
         and member.state='active'
         and membership.state='active'
         and membership.active_from<=transaction_timestamp()
         and (membership.active_until is null
              or membership.active_until>transaction_timestamp())
         and membership.entitlement_generation=feed.entitlement_generation
       )
     order by feed.feed_sequence,feed.id
     for update of feed
     limit candidate_limit;
end
$$;

create or replace function public.boardagent_commit_feed_revocation(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_member_id uuid,
  candidate_feed_id uuid,
  candidate_tombstone_id uuid,
  candidate_tombstone_sha256 bytea
)
returns table(feed_id uuid,tombstone_id uuid)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  target record;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id)
     or candidate_board_id is null
     or not public.boardagent_is_uuid_v7(candidate_board_id)
     or candidate_member_id is null
     or not public.boardagent_is_uuid_v7(candidate_member_id)
     or candidate_feed_id is null
     or not public.boardagent_is_uuid_v7(candidate_feed_id)
     or candidate_tombstone_id is null
     or not public.boardagent_is_uuid_v7(candidate_tombstone_id)
     or candidate_feed_id=candidate_tombstone_id
     or not public.boardagent_hash_is_sha256(candidate_tombstone_sha256) then
    raise exception 'feed revocation commit input is invalid' using errcode='22023';
  end if;

  select feed.*,
         membership.entitlement_generation as current_entitlement_generation,
         board.state as board_state,
         member.state as member_state,
         membership.state as membership_state,
         membership.active_from as membership_active_from,
         membership.active_until as membership_active_until
    into target
    from public.pending_action_feed as feed
    join public.board_memberships as membership
      on membership.organization_id=feed.organization_id
     and membership.board_id=feed.board_id
     and membership.member_id=feed.member_id
    join public.members as member
      on member.organization_id=feed.organization_id
     and member.id=feed.member_id
    join public.boards as board
      on board.organization_id=feed.organization_id
     and board.id=feed.board_id
   where feed.id=candidate_feed_id
     and feed.organization_id=candidate_organization_id
     and feed.board_id=candidate_board_id
     and feed.member_id=candidate_member_id
     and feed.state='pending'
   for update of feed;
  if not found then
    return;
  end if;
  if target.board_state='active'
     and target.member_state='active'
     and target.membership_state='active'
     and target.membership_active_from<=transaction_timestamp()
     and (target.membership_active_until is null
          or target.membership_active_until>transaction_timestamp())
     and target.current_entitlement_generation=target.entitlement_generation then
    return;
  end if;
  if exists (
    select 1 from public.feed_tombstones as tombstone
     where tombstone.removed_feed_id=target.id
  ) then
    raise exception 'feed revocation found conflicting prior tombstone' using errcode='23514';
  end if;
  if not exists (
    select 1 from public.audit_events as audit
     where audit.id=target.audit_event_id
       and audit.organization_id=target.organization_id
       and (audit.board_id is null or audit.board_id=target.board_id)
       and (audit.object_type=target.object_type
        or (target.object_type='question' and audit.object_type='management_question'
          and audit.board_id=target.board_id
          and ((target.action_type='management_question_due'
                and audit.event_type in ('management_question_asked','management_question_followed_up'))
            or (target.action_type='management_question_answered'
                and audit.event_type='management_question_answered'))
          and exists (select 1 from public.management_questions question
            where question.organization_id=target.organization_id
              and question.board_id=target.board_id and question.id=target.object_id)))
       and audit.object_id=target.object_id
  ) then
    raise exception 'feed revocation source audit binding is invalid' using errcode='23514';
  end if;

  update public.pending_action_feed as changed
     set state='superseded',resolved_at=transaction_timestamp()
   where changed.id=target.id and changed.state='pending';
  if not found then
    raise exception 'feed revocation target changed before projection' using errcode='40001';
  end if;

  insert into public.feed_tombstones(
    id,organization_id,board_id,member_id,entitlement_generation,feed_sequence,
    removed_feed_id,object_type,object_id,reason_class,tombstone_sha256,audit_event_id
  ) values (
    candidate_tombstone_id,target.organization_id,target.board_id,target.member_id,
    target.current_entitlement_generation,target.feed_sequence,target.id,target.object_type,
    target.object_id,'revoked',candidate_tombstone_sha256,target.audit_event_id
  );

  feed_id := target.id;
  tombstone_id := candidate_tombstone_id;
  return next;
end
$$;

create or replace function public.boardagent_feed_consistency_relations(candidate_organization_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  checked_feed_rows bigint;
  checked_tombstone_rows bigint;
  membership_stale_pending_rows bigint;
  notice_binding_mismatches bigint;
  audit_binding_mismatches bigint;
  tombstone_binding_mismatches bigint;
  duplicate_removal_tombstones bigint;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker'
     or candidate_organization_id is null
     or not public.boardagent_is_uuid_v7(candidate_organization_id) then
    raise exception 'feed consistency relation scope is invalid' using errcode='22023';
  end if;
  if not exists (
    select 1 from public.system_instance as instance
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'feed consistency organization is unavailable' using errcode='42501';
  end if;

  select count(*) into checked_feed_rows
    from public.pending_action_feed as feed
   where feed.organization_id=candidate_organization_id;
  select count(*) into checked_tombstone_rows
    from public.feed_tombstones as tombstone
   where tombstone.organization_id=candidate_organization_id;
  select count(*) into membership_stale_pending_rows
    from public.pending_action_feed as feed
   where feed.organization_id=candidate_organization_id
     and feed.state='pending'
     and not exists (
       select 1
         from public.board_memberships as membership
         join public.members as member
           on member.organization_id=membership.organization_id
          and member.id=membership.member_id
          and member.state='active'
         join public.boards as board
           on board.organization_id=membership.organization_id
          and board.id=membership.board_id
          and board.state='active'
        where membership.organization_id=feed.organization_id
          and membership.board_id=feed.board_id
          and membership.member_id=feed.member_id
          and membership.state='active'
          and membership.active_from<=transaction_timestamp()
          and (membership.active_until is null
               or membership.active_until>transaction_timestamp())
          and membership.entitlement_generation=feed.entitlement_generation
     );
  select count(*) into notice_binding_mismatches
    from public.pending_action_feed as feed
   where feed.organization_id=candidate_organization_id
     and feed.notice_id is not null
     and not exists (
       select 1 from public.notices as notice
        where notice.id=feed.notice_id
          and notice.organization_id=feed.organization_id
          and notice.board_id=feed.board_id
          and notice.recipient_member_id=feed.member_id
          and notice.object_type=feed.object_type
          and notice.object_id=feed.object_id
          and notice.object_version=feed.object_version
          and notice.feed_sequence=feed.feed_sequence
          and notice.audit_event_id=feed.audit_event_id
     );
  select count(*) into audit_binding_mismatches
    from public.pending_action_feed as feed
   where feed.organization_id=candidate_organization_id
     and not exists (
       select 1 from public.audit_events as audit
        where audit.id=feed.audit_event_id
          and audit.organization_id=feed.organization_id
          and (audit.board_id is null or audit.board_id=feed.board_id)
          and (audit.object_type=feed.object_type
           or (feed.object_type='question' and audit.object_type='management_question'
             and audit.board_id=feed.board_id
             and ((feed.action_type='management_question_due'
                   and audit.event_type in ('management_question_asked','management_question_followed_up'))
               or (feed.action_type='management_question_answered'
                   and audit.event_type='management_question_answered'))
             and exists (select 1 from public.management_questions question
               where question.organization_id=feed.organization_id
                 and question.board_id=feed.board_id and question.id=feed.object_id)))
          and audit.object_id=feed.object_id
     );
  select count(*) into tombstone_binding_mismatches
    from public.feed_tombstones as tombstone
   where tombstone.organization_id=candidate_organization_id
     and (
       tombstone.removed_feed_id is null
       or not exists (
         select 1
           from public.pending_action_feed as removed
           left join public.board_memberships as membership
             on membership.organization_id=removed.organization_id
            and membership.board_id=removed.board_id
            and membership.member_id=removed.member_id
          where removed.id=tombstone.removed_feed_id
            and removed.organization_id=tombstone.organization_id
            and removed.board_id=tombstone.board_id
            and removed.member_id=tombstone.member_id
            and removed.object_type=tombstone.object_type
            and removed.object_id=tombstone.object_id
            and removed.state<>'pending'
            and tombstone.feed_sequence>=removed.feed_sequence
            and tombstone.entitlement_generation in (
              removed.entitlement_generation,
              coalesce(membership.entitlement_generation,removed.entitlement_generation)
            )
       )
       or not exists (
         select 1 from public.audit_events as audit
          where audit.id=tombstone.audit_event_id
            and audit.organization_id=tombstone.organization_id
            and (audit.board_id is null or audit.board_id=tombstone.board_id)
            and ((audit.object_type=tombstone.object_type and audit.object_id=tombstone.object_id)
              or (tombstone.object_type='question' and audit.object_type='management_question'
                and audit.board_id=tombstone.board_id and audit.object_id=tombstone.object_id
                and exists (select 1 from public.management_questions question
                  where question.organization_id=tombstone.organization_id
                    and question.board_id=tombstone.board_id and question.id=tombstone.object_id)
                and exists (select 1 from public.pending_action_feed removed
                  where removed.id=tombstone.removed_feed_id
                    and removed.organization_id=tombstone.organization_id
                    and removed.board_id=tombstone.board_id and removed.member_id=tombstone.member_id
                    and removed.object_type='question' and removed.object_id=tombstone.object_id
                    and removed.action_type='management_question_due'
                    and ((tombstone.reason_class='resolved' and removed.state='resolved'
                          and audit.event_type='management_question_answered')
                      or (tombstone.reason_class='revoked' and removed.state='superseded'
                          and audit.id=removed.audit_event_id
                          and audit.event_type in ('management_question_asked',
                                                   'management_question_followed_up')))))
              or (tombstone.object_type='member' and tombstone.object_id=tombstone.member_id
                and tombstone.reason_class='resolved' and audit.event_type='onboarding_attested'
                and audit.object_type='onboarding_attestation'
                and audit.actor_member_id=tombstone.member_id
                and exists(select 1 from public.onboarding_attestations attestation
                  where attestation.id=audit.object_id
                    and attestation.organization_id=tombstone.organization_id
                    and attestation.board_id=tombstone.board_id
                    and attestation.member_id=tombstone.member_id)
                and exists(select 1 from public.pending_action_feed removed
                  where removed.id=tombstone.removed_feed_id
                    and removed.action_type='complete_onboarding' and removed.state='resolved')))
       )
     );
  select count(*) into duplicate_removal_tombstones
    from (
      select tombstone.removed_feed_id
        from public.feed_tombstones as tombstone
       where tombstone.organization_id=candidate_organization_id
         and tombstone.removed_feed_id is not null
       group by tombstone.removed_feed_id
      having count(*)>1
    ) as duplicate;

  return jsonb_build_object(
    'checkedFeedRows',checked_feed_rows,
    'checkedTombstoneRows',checked_tombstone_rows,
    'membershipStalePendingRows',membership_stale_pending_rows,
    'noticeBindingMismatches',notice_binding_mismatches,
    'auditBindingMismatches',audit_binding_mismatches,
    'tombstoneBindingMismatches',tombstone_binding_mismatches,
    'duplicateRemovalTombstones',duplicate_removal_tombstones,
    'relationMismatches',notice_binding_mismatches+audit_binding_mismatches+
      tombstone_binding_mismatches+duplicate_removal_tombstones
  );
end
$$;

alter function public.boardagent_feed_consistency_relations(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_feed_consistency_relations(uuid) from public;
grant execute on function public.boardagent_feed_consistency_relations(uuid) to boardagent_worker;

alter function public.boardagent_feed_reconcile_candidates(uuid,uuid,uuid,integer)
  owner to boardagent_migrator;
alter function public.boardagent_commit_feed_revocation(uuid,uuid,uuid,uuid,uuid,bytea)
  owner to boardagent_migrator;
revoke all on function public.boardagent_feed_reconcile_candidates(uuid,uuid,uuid,integer) from public;
revoke all on function public.boardagent_commit_feed_revocation(uuid,uuid,uuid,uuid,uuid,bytea) from public;
grant execute on function public.boardagent_feed_reconcile_candidates(uuid,uuid,uuid,integer) to boardagent_worker;
grant execute on function public.boardagent_commit_feed_revocation(uuid,uuid,uuid,uuid,uuid,bytea) to boardagent_worker;
