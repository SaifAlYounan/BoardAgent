# 11 — Meetings and attendance

**Owner:** secretariat. **Purpose:** create and maintain a meeting/agenda/attendance record
without rewriting history or bypassing confirmation.

1. Read the board, current member set, governance profile, documents, open questions, and
   scheduling constraints.
2. Run `call-meeting` or build exact input for `create_meeting`: title, timezone-aware start
   and end, location/medium, agenda, entitled participants, and cited source versions.
3. Present the full schedule/agenda and complete the H-action confirmation.
4. Members use `rsvp`; the secretariat reads responses and uses `record_attendance` after
   the meeting based on accountable evidence.
5. Use `amend_meeting` for a material schedule/agenda change and obtain fresh confirmation.
   Do not mutate a completed/cancelled meeting or imply prior notices were updated.
6. Use `correct_attendance` with reason/evidence for a genuine correction. Preserve the
   original and correction link.
7. Use `complete_meeting` only after attendance and expected annex status are settled, or
   `cancel_meeting` with the exact reason. Verify pending actions and notices.

Record meeting/version IDs, canonical agenda hash, confirmation receipt, notice outcomes,
RSVP/attendance versions, corrections, completion/cancellation state, and downstream
minutes/transcript owners.
