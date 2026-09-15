-- BoardAgent Phase 1 / group 27: author-only immutable minutes comment withdrawal.

grant insert on minutes_review_withdrawals to boardagent_server;

create unique index minutes_review_withdrawals_idempotency_uq
  on minutes_review_withdrawals(idempotency_record_id);
