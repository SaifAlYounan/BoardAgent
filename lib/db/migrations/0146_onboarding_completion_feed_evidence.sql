-- Onboarding completion removes a member action; its audit identifies the exact
-- attestation. Validate that relationship instead of requiring identical object IDs.
-- Preserve every other feed, generation, membership and audit binding check.
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
          and audit.object_type=feed.object_type
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
