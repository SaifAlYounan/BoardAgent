-- BoardAgent Phase 1 / group 41: frozen-envelope read-path indexes.

-- The existing board/state/id index cannot satisfy the signed-cursor ordering used by
-- list_documents. At the D2-054 envelope PostgreSQL must otherwise authorize and sort
-- every active document on the board before applying the 500-row page bound. Keep the
-- visibility predicate in FORCE RLS; this index only makes the already-authorized
-- created_at/id order directly scannable.
create index documents_board_active_created_idx
  on public.documents(board_id,created_at desc,id desc)
  where state='active';
