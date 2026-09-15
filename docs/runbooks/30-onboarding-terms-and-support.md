# 30 — Update onboarding terms or secretary support contacts

**Owners:** the board secretary publishes that board's support contacts; the company
administrator publishes organization-wide terms for a particular seat role. Each affected
person accepts the resulting current versions themselves. Check the installed release
before using it on a deployment.

**Purpose:** publish current role terms and board support contacts, preserve prior versions,
and guide each affected person through their own renewed acceptance.

Before publishing, connect your own agent, check `whoami` and the relevant board, and
complete any outstanding onboarding. Use an active authorized human account with
`secretariat:admin`. A secretary must currently serve the target board and must not be
recused from it. Company administration alone does not appoint a board secretary.

For an additional board, the company administrator first uses `create_board`, then
`publish_secretary_support` to initialize its first support version, and then arranges
separate member enrollment. Initialize support before taking a seat yourself. This
one-time setup exception grants no board seat or right to update existing support.
The board secretary handles subsequent changes. If a version already exists, an
administrator without secretary authority cannot replace it.

## Update the secretary's contact details

Tell your secretary agent:

> Publish these updated secretary support details for this board. Show me the complete
> contact information, the version being replaced and the effect before asking me to confirm.

The agent calls `publish_secretary_support` with `board_id`, a new UUIDv7 `version_id`,
`support_name`, `contact_methods` (one to 32 JSON contact descriptions), `reason`,
`idempotency_key` and `schema_version: boardagent.tool-input.v1`. A contact description can
be `{"kind":"phone","value":"+971555010000"}`; replace the example with the actual
approved contact. The service records those supplied details; it does not verify the
phone number or send a message. Organization-wide default support publication is not exposed.

## Update role terms

Tell your company administrator agent:

> Publish the following reviewed onboarding terms for voting members. Show me the exact
> text and which people will need to accept it before asking me to confirm.

The agent calls `publish_onboarding_terms` with `seat_role` (`voting_member`, `management`
or `observer`), a new UUIDv7 `version_id`, `canonical_text`, `reason`, `idempotency_key`
and the same schema version. Terms apply to that seat role throughout this organization.
Publishing board-secretary support does not give the secretary authority to change terms.
The administrator's publisher role fills the previously unspecified authorship responsibility;
its recorded implementation decision is in the additive onboarding-publication amendment.

For either action, `expected_version_id` is optional. Supply the known preceding version ID
to insist on it; supply `null` only when there should be no preceding version. If omitted,
the server captures the current version and hash in the confirmation. The confirmation
always identifies the exact new content, preceding version, new version and content hash.
If the current version changes before approval completes, start a fresh confirmation and
review it again. An old approval cannot overwrite a newer version.

## What happens after confirmation

The confirmed version becomes effective immediately. Earlier versions and acceptance
records remain intact. Every terms change is treated as material. Affected people must
accept the exact current terms and support version before ordinary board work resumes;
this can include the publisher. Nobody is marked as accepting merely because an
administrator or secretary published something.

Each affected person tells their own agent:

> Show me my current onboarding terms and secretary support details and help me accept them.

The agent uses `get_onboarding` for the person's board, then
`prepare_onboarding_attestation` with the returned terms/support version IDs and the
person's presentation and local-memory choices. The person follows the private one-use
browser link and completes the passkey ceremony. `get_onboarding_status` must then report
`current`; ordinary authorized work can resume. A support-only update follows the same
procedure even when the terms themselves have not changed. Repeat for any other affected
board. The server cannot attest that a person understood the text.

## Failure, retry and evidence

- If authority is denied, check the account, board, scope, recusal and current onboarding.
  Ask the company administrator to correct an actual appointment problem; do not use a
  different person's credentials or ask an operator to insert database rows.
- If confirmation is stale, obtain the latest version and review a new confirmation.
  If the agent lost the successful response, inspect the current onboarding view and
  audit record before starting another publication. Reusing an already published version
  ID will not create another version.
- If the acceptance link expired or a newer version was published while it was open,
  ask the agent to start a fresh ceremony. Never paste a passkey response, token or private
  one-use link into a support ticket.
- Record the publication version ID, content hash, board/role, reason and nonsecret action
  reference. Audit events are `secretary_support_published` or
  `onboarding_terms_published`, linked to the publisher's confirmed action. The later
  `onboarding_attested` record is a separate person's acceptance of exact version IDs.

Publishing does not grant a seat, change voting rights or replace account activation.
