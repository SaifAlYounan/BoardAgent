# Secretary manual

You organize board business through your own agent. The server records canonical
documents, decisions, review history and the acts each person confirms. Your
secretary appointment does not automatically confer company administration,
infrastructure access or a board vote. Read the [user manual](../MANUAL.md) first.

BoardAgent is an open-source beta for use with synthetic data. Check the installed
release before using the procedures. The [Mining Exploration Co fixture](../../demo/mining-exploration-co)
is a synthetic exercise for one secretary and three directors; inspect the actual
account and scenario receipts before assuming setup is complete.

## Start with your own authority

Receive your private invitation, register your own passkey, complete identity
proof/activation with the authorized issuer, then complete onboarding through
your own MCP connection. Until you attest, the server issues an `onboarding:read`
token only; after attestation the next token refresh or reconnect carries your
ordinary scopes. If your secretary assignment was added after enrollment, reconnect so
the current connection reflects that authority.

Arrange the issuer's verified handoff before passkey registration and complete
activation within ten minutes. If the code expires or is exhausted, keep the pending
account and ask the issuer for an activation restart: they hand you a one-use link,
you prove it is you with the passkey you already registered, and a fresh ten-minute
code appears for them to confirm.

Ask the agent to show `whoami`, `list_my_boards`, the board snapshot and your
pending work. Use `list_administrative_access` to inspect any delegated member
administration. An ordinary secretary can handle enrollment within their authority;
creating or changing directors also requires company-admin authority or an explicit
current delegation for that board. See [administrator handoff](administrator.md).

## Prepare and circulate board papers

Ask your agent:

> Prepare these reviewed papers for the next meeting. Show the canonical versions,
> hashes, intended recipients and access restrictions. Flag missing authority or
> source information before proposing circulation.

BoardAgent accepts canonical Markdown, text and its declared strict JSON formats.
Do not upload PDF, DOCX, PPTX, images, scans or archives, even as an annex. Have an
accountable person verify a text/JSON version prepared outside BoardAgent.

Create the reviewed canonical source with `create_document_version`, then compare
`read_document` and `get_document_hash` with the intended text. Keep a stable
document identity for later versions; refetch its current version before reuse.

Management submits material through `submit_document_to_secretariat`. Read
`list_management_submissions` and `get_management_submission`, then use
`request_management_revision` for a correction. The submitting manager replies
through `reply_to_management_revision` and submits the new material through
`resubmit_management_materials`; the old version and thread remain. Read the revised
source before `approve_management_submission` or `reject_management_submission`.
Approval creates a draft for a separate action; it does not automatically open a
vote. If you are the assigned management owner of a question, answer through
`answer_management_question`; a secretary appointment alone does not assign it.
Read `get_management_question` before answering to confirm the current question,
source references and your assignment. After saving, read it again to verify the
answer is recorded. A follow-up keeps the previous exchange and requires its own
answer; do not treat your earlier answer as resolving new wording automatically.

Use `circulate-document` to prepare the exact supported circulation tool. Confirm
recipients, board, exclusions and versions before any binding act. Inspect the
saved circulation/notice state afterward. A notice in a feed does not prove that
a member received, read or understood the paper. See
[documents](../runbooks/09-documents-content-rejection.md) and
[management submissions](../runbooks/16-tasks-proposals-management.md).

## Arrange a meeting and record its context

Run `call-meeting` to prepare the schedule, agenda and entitled participants from
current records. Review the exact `create_meeting` confirmation and refetch the
saved meeting. Record attendance and agenda changes through their supported tools;
do not use a document edit to rewrite the meeting history.

Read members' `rsvp` responses, then use `record_attendance` for what actually
happened. Correct the schedule or agenda with `amend_meeting`; correct a mistaken
attendance record with `correct_attendance` and its reason/evidence. Use
`complete_meeting` when its prerequisites are met, or `cancel_meeting` for a
cancelled meeting. Refetch the state and resulting notices after each change.

Transcripts are optional annexes in canonical Markdown or the declared strict JSON
schema. The server records their declared verification state; it does not transcribe audio.
Preserve challenges,
responses and source references. Questions and answers remain in their permanent
threads with the assigned owner and due time. An unresolved included question or
new linked source may block a related vote. Follow
[meetings](../runbooks/11-meetings-attendance.md) and
[transcripts/Q&A](../runbooks/12-transcripts-qna.md).

## Open and close a resolution vote

1. Read the current governance profile, ruleset, appointed voting seats, recusals,
   sources and included management answers. Use `evaluate_matter` only as the
   deterministic evaluation of the supplied facts/rules.
2. Run `set-vote`. Review the resolution, exact package/hash, electorate/weights,
   approval rule, deadline and close mode before confirming `create_vote`.
3. Refetch the open vote and verify its notices and pending actions. Each eligible
   member independently reads the package, chooses a ballot and confirms through
   `stage_ballot`. Do not cast a director's ballot using your connection.
4. If the package changes, inspect its source hold and prepare the supported
   `exclude_pending_vote_source` or `replace_open_vote` disposition.
   `amend_resolution_text` and `extend_vote_deadline` also follow their governed
   replacement flow. A replacement is a new vote with no carried assent; show
   prior voters the required revote. Inspect `get_vote_lineage` afterward.
5. For `secretariat_confirmed` close mode, inspect the current close conditions and
   personally confirm `close_vote`. An automatic close uses its configured worker
   path. A `closing` result still needs completion; inspect it rather than repeatedly
   sending close requests.
6. Fetch `get_vote_certificate` after closure and verify the recorded outcome and
   evidence. Certificate validity is not a claim of legal effectiveness or human
   comprehension. Retain the vote/package and verification references.

Proxy, deadline-extension, cancellation and close rules are explained in
[votes/proxies/certificates](../runbooks/14-votes-proxies-certificates.md). A stuck
certificate/worker is an operator issue, not a reason to bypass the governed close.

If you are recused from a vote, you cannot lift that recusal yourself. Another
currently eligible secretary or administrator with authority for that vote must
review the full `manage_recusal` confirmation and lift it. Refetch afterward;
old ballots, proxies and pending confirmations are not restored.

## Draft, review and finalize minutes

Ask your agent:

> Prepare minutes from the meeting's canonical records. Separate recorded facts
> from proposed wording. Show every action's owner, due date and evidence criteria.
> Prepare publication for my review; do not sign for any member.

1. Read the meeting, attendance, agenda, sources, transcript/Q&A and prior minutes
   lineage. Use `record-minutes` or `create_minutes_version` for an unpublished draft.
2. Log the structured action manifest with `log_minutes_action_items`, or explicitly
   use `declare_no_minutes_action_items`. Actions hidden only in prose are insufficient.
3. Use `publish_minutes` to open the exact version for review. Members submit comments
   or anchored strict JSON redlines; a Word file with tracked changes is not accepted.
4. Read `list_minutes_review_items` and record every disposition with
   `resolve_minutes_review_item`. Apply supported package/version corrections and
   republish as required. Do not silently edit the base under a pending review.
5. Once review and action structure are settled, use `prepare_minutes_for_signature`.
   Each required person signs the exact package through their own
   `stage_minutes_signature` confirmation.
6. Use `finalize_minutes` only when the configured requirements are satisfied.
   Refetch the final version, signer set, action links and hashes. Published or
   partly signed minutes are not finalized minutes.

Correct finalized minutes through `create_minutes_correction_cycle`; preserve the
old signed record and obtain fresh review/signatures where required. See
[minutes runbook](../runbooks/13-minutes-redlines-signatures.md).

## Follow actions through evidence and closure

Show current obligations with `list_pending_actions`, `list_action_items` and
`list_my_tasks`. Check ownership, due time and acceptance criteria. Assigned people
read `get_task` or `get_action_item`, use `start_task` and submit evidence with
`submit_task_evidence`; submission alone does not close the work. Use
`review_task_evidence` to accept or reject each evidence item with the actual reason,
then personally confirm `complete_task` with the accepted evidence IDs. For completed
work needing correction, use `create_task_correction_cycle` instead of replacing
its old evidence. The [task procedure](../runbooks/16-tasks-proposals-management.md)
also covers standalone `create_task` and eligible `cancel_task` actions.

After a completion or supersession delta, remove the obsolete obligation from
the agent's pending list. Preserve separate opaque cursors for updates and pending
actions, and follow a returned resynchronization instruction after an upgrade.
The [agent guide](../AGENT_GUIDE.md) explains these client responsibilities.

## Handle proposals and requests to the secretariat

Read `list_proposals` for the exact board and inspect the proposed content and
references. Use `approve_proposal` to create its separate draft, or
`reject_proposal` with the actual reason. Review that draft through
`list_my_drafts`/`resume_draft` before preparing the eventual meeting, vote or task.
Approval and resumption do not perform the proposed business action; the applicable
action still needs its own confirmation.

Read `list_secretariat_requests`, append the accountable response with
`reply_secretariat_request`, then use `close_secretariat_request` when the request
is settled. Keep the conversation in that permanent thread. A response in the
agent's private chat is not a reply to the requester. These flows and their retained
history are covered in [the communications procedure](../runbooks/16-tasks-proposals-management.md).

## Support, refusals and handover

Publish changed board support details with `publish_secretary_support`, reviewing
the version and effect before confirmation. Each affected person accepts current
terms/support again; publication is not their acceptance. Organization-wide terms
publication belongs to the company administrator. See
[terms and support](../runbooks/30-onboarding-terms-and-support.md).

On missing access, check account, board, current onboarding, recusal and effective
delegation. On stale content, refetch and prepare a new exact confirmation. On a
lost reply, inspect the canonical record before retrying. Record nonsecret IDs,
versions, hashes and status; keep invitation URLs, activation codes and access
tokens out of meeting minutes, shared chats and support reports.

For identity recovery contact the authorized administrator and follow
[the recovery procedure](../runbooks/04-identity-recovery.md). For service failures
contact the technical operator. A secretary cannot fix service state by SQL,
borrow another person's credentials or treat a restart as evidence of completion.
