# 12 — Transcripts and Q&A

**Owners:** secretariat for transcript record; members/observers and assigned management for
questions. **Purpose:** preserve an optional machine-readable transcript annex and permanent
question/answer threads.

1. Accept only the declared transcript JSON schema with exact meeting, speaker, turn order,
   timestamps/labels, and source-accountability metadata. BoardAgent does not ingest audio,
   video, scans, or generated free-form transcripts.
2. Use `create_meeting_transcript_version`; read it back with
   `get_meeting_transcript`, compare canonical hash, then use `verify_meeting_transcript`
   under the approved evidence process.
3. A participant uses `challenge_transcript_turn` for a disputed exact turn. The
   secretariat uses `resolve_transcript_challenge`; preserve both challenge and disposition.
4. Use `link_meeting_qna` to map exact transcript turns into permanent management threads.
   Alternatively, entitled members/observers use the `ask-management` prompt or
   `ask_management` with exact citations, owner, and due time.
5. Assigned management uses `answer_management_question` with a nonblank permanent answer.
   Status alone cannot close it. `follow_up_management_question` appends a turn and reopens
   the management action.
6. Before vote close, verify every explicitly included Q&A thread has an answer through its
   frozen cutoff. Later linked turns trigger the source-update process.

Record transcript/version/hash, verification, challenges/dispositions, linked question and
turn cutoffs, owners/deadlines, answers/follow-ups, overdue state, and any affected vote.
