-- BoardAgent Phase 1 / group 40: entitlement-bound cross-board briefing reads.

-- A removed board no longer appears in boardagent.board_ids, but the affected member
-- must still receive their own safe tombstone so a cooperative client can discard
-- previously fetched material. This policy exposes only the caller's tombstones; the
-- ordinary board-scoped policy remains the authority for every other principal.
grant select on public.feed_tombstones to boardagent_server;
create policy boardagent_server_own_feed_tombstone_read on public.feed_tombstones
  for select to boardagent_server
  using (
    organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    and member_id=public.boardagent_context_uuid('boardagent.member_id')
  );

-- The daily briefing is cross-board and ordered by member position. The original
-- board-first indexes remain useful for board snapshots; these exact indexes prevent
-- the global member briefing from degrading into a full feed scan at the D2-054
-- envelope.
create index pending_action_feed_member_sequence_idx
  on public.pending_action_feed(member_id,feed_sequence,board_id,id);
create index pending_action_feed_pending_member_sequence_idx
  on public.pending_action_feed(member_id,feed_sequence,board_id,id)
  where state='pending';
create index feed_tombstones_member_sequence_idx
  on public.feed_tombstones(member_id,feed_sequence,board_id,id);
