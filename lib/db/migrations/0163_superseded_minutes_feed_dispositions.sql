-- Retire only provably superseded historical signature-package projections.
-- Canonical feed bytes, notices, audit events and signatures remain unchanged.
-- The existing feed-sync trigger records each changed disposition.
do $migration_scope$
begin
  if current_user<>'boardagent_migrator' then
    raise exception 'minutes feed cleanup requires the managed migrator' using errcode='42501';
  end if;
  perform set_config('boardagent.transaction_scope','migration',true);
end
$migration_scope$;

lock table public.minutes,public.minutes_signature_packages,public.pending_action_feed
  in share row exclusive mode;

-- FORCE RLS applies to the owner. These policies exist only in this migration
-- transaction and add no authority to a runtime role or later transaction.
create policy boardagent_minutes_feed_cleanup_read on public.pending_action_feed
  for select to boardagent_migrator using (
    current_setting('boardagent.transaction_scope',true)='migration'
    and object_type='minutes'
    and action_type in ('minutes_signature_required','minutes_resign_required')
  );
create policy boardagent_minutes_feed_cleanup_update on public.pending_action_feed
  for update to boardagent_migrator using (
    current_setting('boardagent.transaction_scope',true)='migration'
    and object_type='minutes' and state='pending'
    and action_type in ('minutes_signature_required','minutes_resign_required')
  ) with check (
    current_setting('boardagent.transaction_scope',true)='migration'
    and object_type='minutes' and state='superseded' and resolved_at is not null
    and action_type in ('minutes_signature_required','minutes_resign_required')
  );
create policy boardagent_minutes_feed_cleanup_audit_read on public.audit_events
  for select to boardagent_migrator using (
    current_setting('boardagent.transaction_scope',true)='migration'
    and event_type='notice_delivered' and object_type='minutes_signature_package'
  );

update public.pending_action_feed as feed
   set state='superseded',resolved_at=transaction_timestamp()
  from public.audit_events as audit
  join public.minutes_signature_packages as package
    on package.id=audit.object_id and package.organization_id=audit.organization_id
   and package.board_id=audit.board_id and package.state='superseded'
  join public.minutes as minutes
    on minutes.id=package.minutes_id and minutes.organization_id=package.organization_id
   and minutes.board_id=package.board_id
   and minutes.current_signature_package_id is distinct from package.id
 where feed.state='pending' and feed.object_type='minutes'
   and feed.action_type in ('minutes_signature_required','minutes_resign_required')
   and feed.organization_id=package.organization_id and feed.board_id=package.board_id
   and feed.object_id=package.minutes_id and feed.audit_event_id=audit.id
   and sha256(feed.canonical_payload)=feed.payload_sha256
   and public.boardagent_minutes_feed_audit_binding(feed,audit)
   and exists (
     select 1 from public.notices as notice
      where notice.id=feed.notice_id and notice.organization_id=feed.organization_id
        and notice.board_id=feed.board_id and notice.recipient_member_id=feed.member_id
        and notice.notice_type=feed.action_type and notice.object_type=feed.object_type
        and notice.object_id=feed.object_id and notice.object_version=feed.object_version
        and notice.feed_sequence=feed.feed_sequence and notice.audit_event_id=feed.audit_event_id
   );

drop policy boardagent_minutes_feed_cleanup_read on public.pending_action_feed;
drop policy boardagent_minutes_feed_cleanup_update on public.pending_action_feed;
drop policy boardagent_minutes_feed_cleanup_audit_read on public.audit_events;
