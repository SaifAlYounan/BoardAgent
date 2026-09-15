# Board-member manual

Use your own connected agent to review entitled board material, ask questions and
personally confirm your votes and signatures. BoardAgent keeps the canonical
record; your agent may explain it but cannot supply your judgment. Begin with the
[user manual](../MANUAL.md) and the private service address from your administrator.

BoardAgent is an open-source beta for use with synthetic data. The
[Mining Exploration Co pack](../../demo/mining-exploration-co) provides synthetic
exercises for three separate board members and a secretary. Test accounts and
automated confirmations are not actual human enrollment or acceptance.

## Connect as yourself

1. Receive your own private enrollment link through the declared verified channel.
   Open the exact BoardAgent origin and register your passkey in the browser.
2. Complete the issuer's identity-proof/activation step. Keep the displayed
   activation reference and code private; hand them to the authorized issuer
   through the verified route within ten minutes of registration. Arrange that
   handoff first, and never paste the code into a shared agent conversation.
3. Connect your MCP client to the operator's exact HTTPS `/mcp` resource and log in.
   Until your onboarding is current you receive an `onboarding:read` token only. Ask
   for `whoami`, your boards, complete role terms and secretary support details.
4. Choose your presentation/local-memory preferences, then personally complete
   the private browser/passkey onboarding attestation. After current onboarding,
   authorize the ordinary scopes required by your role.
5. Verify your name and board. A new chat window or a changed assistant persona
   does not create a separate authenticated connection.

If activation expires or exhausts its permitted attempts, contact the issuer and
keep the pending account: they can restart it. You receive a one-use link, prove it
is you with the passkey you already registered, and get a fresh ten-minute code for
the issuer to confirm. Never create a second identity to work around a lapsed code.

Your client needs the supported current MCP confirmation capability for binding
acts. Legacy compatibility is read-only. If the client hides or automatically
answers the confirmation, do not use that configuration for a personal vote or
signature. The server cannot establish who answered a client-side form.

## Read before deciding

Ask your agent:

> Show my current board briefing and pending actions. For this meeting or vote,
> show the exact current sources and their versions. Label your summaries as
> summaries, identify missing information and do not act until I decide.

The agent should read `get_my_board_snapshot`, `list_my_updates` and
`list_pending_actions`, then fetch the relevant documents or vote/minutes package.
Check the board, dates, canonical versions/hashes and lifecycle state. A remembered
summary or downloaded copy may be stale. An unavailable item is not permission
to obtain it through another person's account.

You can ask management a scoped question through `ask-management`/`ask_management`
and append a follow-up with `follow_up_management_question`. Review the exact
wording, assigned owner, source citation and due time before submission. The saved
question/answer thread is a board record; a conversation with your agent alone is not.
After each submission, read `get_management_question` and check the saved wording,
owner, due time and ordered turns. Review the recorded answer before following up;
the follow-up adds a turn and preserves the earlier question and answer. Your agent
can also read the question resource URI returned by the service.

For a meeting, inspect its current agenda and schedule and submit your `rsvp`.
That response records your intention; the secretary records actual attendance.
Report an attendance error for correction. If a transcript misattributes an exact
turn, use `challenge_transcript_turn` and inspect the secretary's recorded
disposition, as described in [transcripts/Q&A](../runbooks/12-transcripts-qna.md).

For an administrative question, use `ask_secretariat` and read its permanent reply
through `list_secretariat_requests`. To suggest a meeting, vote or task, use
`propose_action` with reviewed content/references and inspect `list_proposals`.
Use `withdraw_proposal` if your pending proposal is no longer intended. A proposal
does not itself schedule a meeting, open a vote or assign a task.

## Cast your own ballot

1. Read `get_vote` and its decision-package sources. Check the resolution, governing
   rule/profile, eligible electorate, your recusal state, deadline and proxy status.
2. Ask the agent to explain the choices and uncertainties. Choose your own ballot;
   the agent must not infer your choice from a discussion or an old vote.
3. The agent prepares `stage_ballot`. Read the entire server confirmation, including
   exact board, vote/package, principal and ballot choice. Approve or cancel and
   enter the displayed code yourself.
4. Inspect the successful canonical ballot receipt. If the response was lost, ask
   the agent to read the saved state before making another attempt.
5. If a source/package changed or the vote was replaced, read the new package and
   decide again. Your old ballot does not carry into a replacement vote.

A confirmation stage is a proposal, not a counted ballot. A deadline or eligibility
refusal is not fixed by repeatedly clicking approve. Raise an actual permission
or record issue with the secretary. After closure, use `get_vote_certificate` and
the supported verification route; the certificate records the outcome and evidence,
not the quality of the decision or its legal effect.

## Use a proxy only when permitted

Inspect `get_proxy_status` and the profile's rule for the exact vote. A proxy
delegates a bounded voting act to an eligible member; it does not transfer your
account, passkey or general authority. Review the principal, recipient, vote and
scope before `grant_proxy` or `revoke_proxy` confirmation. Ask the agent to explain
the configured precedence between a principal's own ballot and a proxy ballot.
Verify the resulting state; do not assume two submissions create two counted votes.
See [vote/proxy procedure](../runbooks/14-votes-proxies-certificates.md).

## Review and sign minutes

Ask the agent to show the current published minutes, meeting context, action
manifest and unresolved review items. Prepare a comment with `comment_minutes`
or a specific anchored redline with `propose_minutes_redline`. Redlines are strict
versioned JSON with exact base/anchors; BoardAgent rejects DOCX tracked changes,
binary patches and fuzzy edits. Review the proposed text before submitting it.

Read `list_minutes_review_items` for the saved item and its disposition. Use
`withdraw_minutes_comment` for your own eligible comment if you withdraw it;
withdrawal preserves the history. For a changed base, refetch and prepare fresh
anchors rather than reusing a redline against another version.

The secretary dispositions review items and prepares the final signature package.
Before `stage_minutes_signature`, refetch the exact package and inspect what your
signature will attest. Personally approve/cancel the server confirmation. A
signature on an earlier draft cannot silently cover changed minutes. Check your
saved signature and the minutes' actual finalization state afterward.

For an error in finalized minutes, ask for a linked correction cycle. The signed
history remains intact. An observer may be entitled to attest minutes under the
configured rules; that signature does not turn an observer into a voting member.
See [minutes procedure](../runbooks/13-minutes-redlines-signatures.md).

## Manage assigned work and your connection

For an assigned action or task, use `list_my_tasks`, then `get_task` or
`get_action_item` to read its owner, due date and evidence criteria. Use `start_task`
when beginning the work, and `submit_task_evidence` with reviewed canonical text
or entitled immutable document references. The secretary reviews each evidence
item and completes the task separately. Read the disposition, supply corrected
evidence if requested, and inspect the final state before treating the item as
closed. Follow [the task procedure](../runbooks/16-tasks-proposals-management.md).

Use `list_my_sessions` to inspect your own connections. Revoking a connection
requires the supported recent-auth proof and exact `revoke_my_session`
confirmation; the [agent guide](../AGENT_GUIDE.md) explains the sequence. Revoke
a lost/unused connection through that flow rather than sharing or editing tokens.
If you lose an authenticator, contact the secretary/authorized administrator and
follow [identity recovery](../runbooks/04-identity-recovery.md). Do not accept an
unverified replacement login link or send someone your private key.

If you become recused or lose access, stop reading that matter and have your
agent apply the returned exclusions/tombstones to its local state. Local copies
remain your responsibility; BoardAgent cannot prove the agent deleted them.
Optional local memory must retain source/version/hash references and be refetched
before decisions, as explained in the [memory boundary](../adr/0005-agent-owned-derived-memory.md).

If the operator has enabled optional webhooks, use only your own endpoint and the
[webhook procedure](../runbooks/18-webhooks.md). A webhook is a signed contentless
wake-up: your agent must refetch current entitled state. It does not carry the
papers or prove that you received or read a notice. Polling the update feed remains
the ordinary way to discover changes when webhooks are unavailable.

## Ask for help safely

Tell support the approximate time, affected task, displayed error and nonsecret
request/object reference. Do not include board content in a public issue, or
include enrollment URLs, codes, passwords, bearer tokens or passkey material in
a support report. Governance/access issues go to the secretary; service issues
go to the technical operator; suspected compromise follows the installation's
private [security route](../../SECURITY.md).
