# 16 — Tasks, proposals, and management workflow

**Owners:** secretariat, assigned management, and entitled members according to the tool
registry. **Purpose:** keep work, proposals, submissions, and communications inside the
immutable MCP record.

## Management submissions and questions

1. Management uses `submit_document_to_secretariat` with canonical material.
2. Secretariat reads the immutable submission and uses `request_management_revision`,
   `approve_management_submission`, or `reject_management_submission`. Approval creates
   only a separately confirmable draft; it does not open a vote.
3. Management uses `reply_to_management_revision` and `resubmit_management_materials`.
4. Questions use `ask_management`; assigned management uses
   `answer_management_question`; follow-up appends through
   `follow_up_management_question`. Preserve owner, citations, due state, and every turn.

## Tasks, proposals, and secretariat requests

1. Secretariat uses `create_task`; owner uses `start_task` and
   `submit_task_evidence`; secretariat uses `review_task_evidence` and `complete_task`.
2. A correction to completed work uses `create_task_correction_cycle`; do not overwrite
   prior evidence. Use `cancel_task` only under the exact lifecycle.
3. Entitled people use `propose_action`/`withdraw_proposal`; secretariat uses
   `approve_proposal`/`reject_proposal`. A proposal is not an action until accepted and
   instantiated through the governed flow.
4. Use `ask_secretariat`, `reply_secretariat_request`, and
   `close_secretariat_request` for permanent scoped communications.

BoardAgent sends no governance email. Record object/version IDs, owners/due dates, evidence
hashes, review/disposition receipts, linked vote/minutes/task, and terminal/correction
lineage.
