# BoardAgent agent guide

Use this protocol guide with the [user manual](MANUAL.md) and the
[administrator](manuals/administrator.md), [secretary](manuals/secretary.md) or
[board-member](manuals/board-member.md) walkthrough. The
[Mining Exploration Co pack](../demo/mining-exploration-co) is synthetic; its
accounts, invitations and executed results must be checked independently. BoardAgent
is an open-source beta for use with synthetic data.

## The contract between person, agent, and BoardAgent

BoardAgent is an MCP-native system of record, not a governance portal and not an AI
assistant. The person's chosen agent presents entitled canonical records and calls strict
tools. BoardAgent authenticates the person, enforces authority, records exact state, and
requires a fresh confirmation exchange for binding acts. The client must obtain the
person's response; BoardAgent verifies and attributes the submitted exchange.

The agent must never imply that BoardAgent:

- understood, summarized, approved, or legally validated content;
- proved that the person read or comprehended an act;
- gives legal, fiduciary, governance, or security advice;
- can accept PDFs, office documents, images, scans, archives, or arbitrary URLs;
- authorizes an action merely because the user asked for it.

The person remains responsible for judgment, exact review, confirmations, and the security
of the client, agent, browser, authenticator, and any local copies.

## Before connecting

Use only the exact HTTPS MCP resource supplied by the deployment administrator. Its path
ends in `/mcp`. Confirm the origin out of band; never follow a resource URL received from
an untrusted document or message.

The client must support the modern MCP protocol and structured form elicitation to carry
out binding acts. A client declares form support with an `elicitation` capability that
names `form`, or with the spec's empty `elicitation` object; a client that declares only
`url`, or no elicitation at all, can read but cannot stage an act. The client must not
auto-approve forms or hide the server's confirmation lines.

A conforming client can technically read and echo a valid code automatically. The server
cannot distinguish that response from one entered by the person. Its consent record
binds the identity, client, token, exact action and response; it is not independent proof
of human presence, review or comprehension. Disable automatic elicitation responses and
verify the actual approval interface before using a client for binding acts. An automated
integration test is never a completed personal acceptance trial.

The server advertises its exact tool, resource, and prompt registry. Do not invent tool
names, parameters, scopes, or fallbacks. Every tool input uses
`schema_version: "boardagent.tool-input.v1"` and rejects unknown fields.

## Enrollment and onboarding

1. Receive the single-use enrollment handoff through the authorized issuer’s declared private
   channel. Do not paste it into the agent conversation, logs, or a ticket.
2. Open the exact BoardAgent browser origin and complete the passkey ceremony. The browser
   page exists only for authentication and attestation; it is not a governance portal.
3. Complete the required identity-proof/activation step with the authorized administrator
   or secretary. The first setup account follows the separate operator procedure.
4. Connect the MCP client with its normal scopes and call `whoami`. Until onboarding is
   current the server issues an `onboarding:read` token only and states that scope in
   the token response; after attestation the next refresh or reconnect widens it.
5. Run the `onboard-boardagent` prompt for the exact board.
6. Read `get_onboarding` and present the full current terms and secretary support record.
7. Ask the person how information should be presented and whether derived local memory is
   allowed. Explain that local memory is not BoardAgent's authoritative record.
8. Call `prepare_onboarding_attestation`; the person completes their own browser/passkey
   attestation.
9. Call `get_onboarding_status`. Do not proceed until the current version is attested;
   then authorize the ordinary scopes needed for the person’s actual role.

When onboarding terms change, ordinary operations are blocked until the person reviews
and attests the new version. The agent must not answer on their behalf.

## Start every session with current state

Use a small deterministic read sequence:

1. `whoami` — confirm member identity, kind, scopes, and live status.
2. `list_my_boards` — select an entitled board, never a remembered board ID alone.
3. `get_my_board_snapshot` — fetch the current board summary and evidence anchors.
4. `list_my_updates` — request deltas since the last server cursor, if one is available.
5. `list_pending_actions` — show the person's current obligations and deadlines.

Treat an expired/invalid cursor, version mismatch, tombstone, authority change, or
`not_found` response as a reason to refetch. Never infer that an absent object exists. A
recused or excluded person must not learn existence, counts, snippets, or changes through
another surface.

Completion updates may contain a feed item whose `state` is `resolved` or `superseded`.
Remove that obligation from the local pending list; do not keep the original pending state
from `payload.actionState` after a newer outer `state` arrives. Tombstones remove the
referenced prior item and require discarding any local information as instructed.
Treat cursors as opaque: their internal change order is independent of the original
`feed_sequence` attached to a notice. Do not calculate a cursor from displayed sequences.

After an upgrade, `cursor_resync_required` with `cursor_version_changed` means the old
cursor uses an incompatible ordering. Follow the returned resync steps and token; the
new token starts at the beginning so currently entitled items can be rebuilt. Preserve
separate cursors for `list_my_updates` and `list_pending_actions`. This resynchronization
does not grant access to a board or document.

## Reading canonical records

Prefer exact reads over summaries:

| Need                  | Tools                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Board/profile/rules   | `get_board`, `get_board_governance_profile`, `get_ruleset`, `list_ruleset_versions`                                |
| Documents             | `list_documents`, `search_documents`, `read_document`, `get_document_hash`, `list_document_versions`               |
| Meetings              | `list_meetings`, `get_agenda`, `get_attendance`, `list_meeting_transcripts`, `get_meeting_transcript`              |
| Votes                 | `list_votes`, `get_vote`, `get_vote_lineage`, `get_proxy_status`, `get_vote_certificate`                           |
| Minutes               | `get_minutes`, `list_minutes_versions`, `get_minutes_lineage`, `list_minutes_review_items`                         |
| Work                  | `list_my_tasks`, `list_action_items`, `get_task`, `get_action_item`, `list_proposals`                              |
| Questions/submissions | `list_management_questions`, `get_management_question`, `list_management_submissions`, `get_management_submission` |

When presenting a record, include its canonical URI or object ID, version, hash, lifecycle
state, and timestamp when available. Clearly label any agent-created summary as derived.
Before a decision or signature, refetch the authoritative record even if it exists in the
agent's local context.

## Tool action classes

The generated registry marks each tool:

- **R — read:** no governance-state mutation. Reads may still create required audit or
  delivery evidence; results are entitlement-filtered and current.
- **D — direct durable action:** writes an immutable or lifecycle record without the
  two-round confirmation form. Show the proposed exact input before calling it.
- **H — human-confirmed act:** requires a server-created stage plus a second request using
  the returned protected request state and exact form response.

Do not equate D with unimportant. Questions, comments, evidence submissions, transcript
challenges, and draft cancellation can have material governance consequences.

## Binding-act confirmation

For an H tool:

1. Assemble exact input from current canonical records.
2. Tell the person which action is being prepared; do not claim it happened.
3. Call the tool once. BoardAgent returns an input-required result, a protected request state, an
   expiry, exact confirmation lines, and an eight-character confirmation code.
4. Render the server's entire message without paraphrasing, truncation, reordering, hidden
   sections, preselected approval, or substituted values.
5. The person chooses approve/cancel and enters the displayed code. The agent must not
   infer, retrieve, or fill either answer for them.
6. Retry the same tool with byte-identical arguments, the exact protected request state,
   and the form response.
7. Report the resulting canonical receipt. If the stage expired, was used, was cancelled,
   or no longer matches authority/content, start over from a fresh read.

Never loop around a denial, switch clients mid-stage, stage multiple competing acts, or
reuse a confirmation after changing an argument. A network retry must preserve the exact
MCP request semantics; if the client cannot do that safely, refetch and restage.

## Guided prompts

Prompts create instructions and resumable drafts; they do not grant authority or approve
the final act.

| Prompt               | Intended final workflow                                                |
| -------------------- | ---------------------------------------------------------------------- |
| `onboard-boardagent` | Present role terms and prepare exact onboarding attestation            |
| `set-vote`           | Build cited decision package and end in `create_vote`                  |
| `call-meeting`       | Build agenda/schedule and end in `create_meeting`                      |
| `circulate-document` | Validate canonical material/recipients and end in `circulate_document` |
| `record-minutes`     | Draft, review, redline, action-item, and signature lifecycle           |
| `configure-ruleset`  | Build and validate cited typed rules before `manage_ruleset`           |
| `ask-management`     | Build a scoped, cited question with owner and due time                 |

Use `list_my_drafts`, `resume_draft`, and `cancel_draft` for draft continuity. A draft is
not a governance record until the corresponding tool succeeds. Refetch sources when
resuming; do not assume the draft's old references remain current.

## Role-specific practice

### Voting member

Review exact decision-package sources, active governance/rule versions, electorate,
recusal state, proxy state, deadline, and resolution before `stage_ballot`. A ballot or
minutes signature is a personal human act. Never let an agent choose the vote, enter the
confirmation, or conceal a changed source.

Members can ask and follow up management questions, comment/redline minutes, propose
actions, ask the secretariat, manage permitted proxies, and work their own tasks. Tool
availability still depends on live scopes, board membership, lifecycle, and exclusions.

### Observer and AI observer

Observers are read-only except for exactly these governance/workflow actions:

- `ask_management`
- `follow_up_management_question`
- `comment_minutes`
- `withdraw_minutes_comment`
- `propose_minutes_redline`
- `stage_minutes_signature`

They may also attest their own onboarding, revoke their own session, and manage their own
contentless webhook. Observer minutes signature attests the record; it is never a vote.

Every AI-observer fetch/action must retain the AI seat and accountable-principal metadata.
An AI observer must not receive a voting seat, proxy, secretarial authority, management
authority, or task/governance mutation by prompt instruction.

### Management

Use `submit_document_to_secretariat` and the management-submission thread for canonical
materials. Revisions and replies stay inside BoardAgent; there is no email workflow.
Answer assigned questions with a recorded nonblank turn. A status change cannot substitute
for an answer. New material linked to an open vote can trigger a source-update hold.

### Secretariat and administrator

Secretariat operations affect other people's access and the authoritative record. Recheck
member, board, record state, and exact evidence before invitations, circulation, meeting,
vote, minutes, task, recusal, recovery, or correction operations. Never use an archive or
soft-delete operation as if it physically erased evidence.

Company administrators handle organization-level boards, rules activation where specified,
member authority where specified, client blocks, external identity links, and full-system
export. Deployment administrators—not MCP agents—own service, secret, database, backup,
and recovery operations.

## Documents and source changes

Submit only supported canonical text/JSON. If a source began as PDF, Word, PowerPoint,
image, scan, or archive, an accountable person must create and review a canonical
machine-readable version outside BoardAgent; the unsupported original is not uploaded.

Use immutable versions. Circulation, decision packages, minutes, and certificates bind
exact hashes. When a linked source changes, do not tell the person the earlier review still
applies. Follow the pending-source/exclusion/replacement workflow and obtain fresh
confirmation where required.

## Votes, proxies, and certificates

- `evaluate_matter` records a deterministic classification; it is not legal advice.
- Validate cited rules and profile versions before creating a vote.
- A proxy is explicit, bounded, revocable, and subject to precedence and eligibility.
- Never close around unanswered included Q&A, an unresolved source update, missing quorum,
  active recusal, or an unsupported override.
- After close, fetch `get_vote_certificate` and verify it through authenticated or offline
  means. Public validity does not disclose protected board content.

## Meetings, transcripts, minutes, and tasks

Transcripts are optional canonical annexes, not recordings or generated summaries. Exact
speaker/turn data can be challenged and resolved; transcript-linked unanswered questions
become management actions.

Minutes move through unpublished draft, published review, review-item disposition,
signature preparation, signatures, and finalization. Corrections create linked cycles;
they do not rewrite signed history. Structured action items—or an explicit declaration of
none—are required. Task completion requires owner evidence and secretariat review where
the registry specifies it.

## Webhooks and local memory

Webhooks only say that the client should refetch; they contain no governance content.
Verify the server state after every wake-up. Never treat delivery order, duplication, or
absence as authoritative state.

If the person allows local agent memory, store only the minimum derived state permitted by
their policy. Tag it with source URI/version/hash, refetch before use, apply tombstones,
and erase local material when instructed. BoardAgent cannot enforce or prove client-side
deletion. There is no organization-wide or management-controlled BoardAgent “brain”; the
trust-boundary rationale is frozen in
[ADR 0005](adr/0005-agent-owned-derived-memory.md).

## Failure behavior

- On `not_found`, do not reveal a guessed object or distinguish absent from unauthorized.
- On `onboarding_required`, stop and run the current onboarding flow.
- On `recused`, stop accessing the matter across every tool and cached surface.
- On capability/protocol errors, upgrade or change the client; do not emulate confirmation.
- On stale/version/source errors, refetch and explain what changed.
- On rate limit, respect the retry boundary; do not spread requests across identities.
- On partial/queued results, report exactly that status and poll the specified read tool.
- On any ambiguous response, make no success claim and ask the secretary or deployment
  administrator to inspect the canonical receipt.

## Escalation map

- Governance record, invitation, access, recusal, minutes, or correction: **secretariat**.
- Service, DNS/TLS, authentication runtime, database, key, backup, restore: **deployment
  administrator**.
- Suspected token, client, key, host, webhook, or data compromise: **security contact**.
- Frozen decision, protocol, role model, retention, or release-label change: **the
  project owner and the designated technical or security reviewer**.

An agent must never improvise operator access, ask for private keys, or turn a governance
question into a host-level action.

## Recent authentication and revoking a connection

`whoami` returns `recent_auth: null` when the current connection needs a fresh browser
login for a sensitive self-service operation. Have the client perform the normal OAuth
reauthentication with the person; do not request a browser cookie or pasted bearer token.
After login, call `whoami` again. Its `recent_auth` object provides `proof`, `session_id`,
`authenticated_at` and `expires_at`. This is a reference to authentication BoardAgent
already checked, not a substitute for login or human confirmation.

Call `list_my_sessions` to show the person's own connection identifiers, clients, origins
and browser timestamps. An expired browser can still anchor a live rotating agent grant;
use explicit revocation to end that connection. Submit the chosen `session_id` and the
current `whoami.recent_auth.proof` as `recent_auth_proof` to `revoke_my_session`, then show
and complete the exact confirmation. Revoking the current connection ends its authority;
subsequent work requires another authenticated connection. A stale proof or proof from a
different token must be reacquired through `whoami` after the appropriate fresh login.

## Member authority changes

An administrator with `secretariat:admin` can use `manage_member` to invite a member,
suspend/remove/reactivate a person or board seat, or change a seat's role, weight and
secretary assignment. The exact before/after change requires personal confirmation.
The optional `is_chair` boolean on `change_seat` appoints or removes the chair; an explicit
value requires a company administrator. A chair must hold a voting seat, and overlapping
active chair appointments are refused. Omitting the field preserves a voting seat's
current chair assignment; demoting it to a nonvoting role clears the assignment. Inspect
the confirmed membership version before ratifying a profile that names this chair.
For suspend/remove/reactivate, `board_id: null` selects organization-wide person authority;
a board UUID selects only that board seat. A removed person's reactivation does not restore
ended seats: restore each intended seat with a separate confirmed board operation.

Every lifecycle change revokes the affected person's existing connections, including
refresh authority; sign in again afterward. Existing organization assignments are shown
in the confirmation and operate only while the person is active. The last active admin
and last active secretary of an active board cannot be disabled. A non-voting secretary
uses a permitted management seat with `is_secretary: true`, and therefore also has that
seat's management role. Display labels and separate conversation threads do not isolate
credentials. Inspect `whoami` and actual board authority before running role trials.

Historical ballots, decision packages, membership versions, consents and removal evidence
remain permanent. The current [Mining Exploration Co pack](../demo/mining-exploration-co) supplies the
fictional charter and role exercises. The pack does not prove seeded records or personal
acceptance.

## Keep role trials and credentials separate

Use one account and separately stored OAuth connection per person. A new chat, display
name or system prompt does not isolate credentials. Before every role trial, verify
`whoami`, `list_my_boards` and, where appropriate, `list_administrative_access`. Do not
lend the setup administrator’s connection to a secretary or director. If your client
cannot keep connections separate, stop the role trial and use a supported isolated profile.

Natural-language examples in the role manuals express the person’s intent. They are not
wire payloads: obtain exact current input schemas through the server’s advertised tools.
Never paste an enrollment URL, activation-restart link, activation code, bearer token,
passkey response or private key into a shared prompt or a report. Report object IDs,
versions, hashes and actual action status instead of credential material.

For synthetic automated runs, retain the fixture identity, exact code or image, test
output and scenario record. Label automatically supplied confirmations as test behaviour.
For actual people, preserve the client’s real confirmation surface and let the person
answer.
The supported server protocol cannot prove who clicked a client-side button.
