# 03 — Members and AI observers

**Owner:** secretariat/admin. **Purpose:** add, change, suspend, or end a member seat without
granting unintended board authority.

## Who can administer people

Company administrator is an application role. It is separate from the VPS operator,
database owner and board secretary. Giving someone this role grants no board vote or
secretary seat. A secretary normally handles enrollment and board administration; the
secretary title or `secretariat:admin` OAuth scope alone does not confer director-account
creation authority.

A company administrator may use the human-confirmed `manage_member_admin_delegation`
grant to give an active human secretary limited power on one named board, citing readable
immutable appointment authority and setting an expiry no later than 90 days. The holder
can register a newly appointed ordinary human voting director, suspend/end/restore that
board seat or change its voting weight. Each action needs its own reason, appointment
citations and exact human confirmation. Registration records the appointment made under
the company's governance rules; it does not itself establish that appointment's authority.

The holder cannot administer their own seat, another board, company admins, secretaries,
other delegation holders, AI/observer or management seats, organization-wide suspension,
or further delegation. Adding another seat to an already registered person remains a
company-admin operation. Expiry, revocation or loss of the secretary role ends use;
restoring the title does not restore an old grant. A fresh confirmed grant is required.

Use `list_administrative_access` with its default `mode: mine` to discover your current
admin assignment, effective board grants and pending offers involving you. Only a current
company admin can request `mode: organization`. A `board_id` filter lists that exact
board's grants; company-wide admin assignments/offers have no board ID. Citations are
returned only while the caller can read their source documents. Restart the list if a
cursor becomes stale after an authority change.

For administrator succession, A confirms a `manage_company_admin` grant/transfer offer,
then the named recipient B discovers it and personally confirms acceptance before its
24-hour deadline. A transfer grants B and ends A's assignment atomically. Role changes
invalidate affected connections; reconnect each affected person's agent with that person's
own OAuth login. The system protects the last effective human administrator.

## Add or change a member

1. Read your administrative access, `list_members`, the target board, governance profile,
   and current onboarding terms. Check whether you hold company-admin authority or a
   current delegation for the exact board.
2. Establish the person's legal/display identity, `member_kind`, seat role, voting weight,
   exact board set, dates, scopes, support path, and invitation handoff method.
3. Call `manage_member` with the exact intended state and complete its human confirmation.
4. Call `issue_enrollment`; deliver the one-use result out of band. The secretariat never
   completes the member's browser/passkey ceremony.
5. The person gives you both the **activation reference** and private **activation code**
   shown after passkey registration, through the agreed verified channel. Use the known
   member/invitation IDs from issuance, the reference as `challenge_id`, the code as
   `confirmation_code`, and the matching `proofing_method` in
   `confirm_enrollment_activation`. `list_enrollments` shows enrollment progress; it does
   not supply the private code or substitute for identity proof.
6. The person connects their own agent with its normal scopes; until onboarding is
   current the server issues only an `onboarding:read` token and states that scope in
   the token response. They call `get_onboarding`, then `prepare_onboarding_attestation`
   with those exact terms/support version IDs and their presentation/local-memory
   choices, open the returned one-use onboarding link and personally attest with their
   passkey. Ordinary scopes are never issued before this completes; the next token
   refresh (within fifteen minutes) or reconnect carries the normal scopes for their
   role. A scope grants no role by itself.
7. Verify `get_member`, expected board visibility, onboarding status, and denied controls.

Complete step 5 within ten minutes of passkey registration. If the code expires or twenty
confirmations fail, the person stays pending with their registered passkey: do not issue a
new invitation and do not create a second identity. Restart the activation instead — call
`reissue_activation` for the exact member and stale challenge, complete its confirmation,
and hand the returned one-use ten-minute link to the verified person. They prove it is them
with their existing passkey on the restart page and receive a fresh reference and code,
which you confirm with `confirm_enrollment_activation` exactly as in step 5. See
[runbook 32](32-activation-restart.md). Identity recovery's replacement-passkey procedure
still applies only to active people.

Each person uses their own passkey and OAuth connection from their own MCP client. Completing registration creates an invited identity/seat; it does not mean the
human has activated, accepted onboarding or connected their agent. Keep those milestones
separate. Do not reuse a departed director's identity for a replacement.

## Hand off from the initial setup account

The initial setup person first completes bootstrap activation and onboarding. That person
then registers the appointed ordinary secretary through the procedure above. `invite`
creates an ordinary seat; after activation, the company administrator uses `manage_member`
with `change.operation: change_seat` and `is_secretary: true` for the exact board. Reconnect
the affected secretary's agent after the permission change.

If the secretary will register directors, give them the explicit board delegation described
above, with readable appointment evidence and expiry. They reconnect and repeat enrollment
for each appointed director, each using their own passkey and agent. The ordinary secretary
receives no organization administrator or infrastructure account from this delegation.

Once the ordinary secretary is working, the company administrator ends the initial setup
person's extra board seat with `manage_member`, `change.operation: remove`, the exact
`board_id` and a reason. Reconnect the affected setup agent, verify its organization admin
assignment remains, and verify the board's active voters contain only the intended people.
Ending a board seat is distinct from suspending the identity or revoking company admin.

For suspension/removal, read active sessions/proxies/tasks first, confirm the exact
effective time/state, use `manage_member`, and verify stale sessions and authority fail.
Historical records remain; removal is not erasure.

## AI observer invariant

Set `member_kind: ai_observer` and `seat_role: observer`; identify one accountable principal
in the governed record. Verify the identity has no vote, proxy, management, secretariat,
task, member-admin, or governance-admin authority. Its only governance/workflow writes are
questions/follow-ups, minutes comment/withdraw/redline, and minutes attestation signature;
platform self-service is limited to onboarding, own-session revocation, and own contentless
webhook management.

## Evidence

Record before/after member versions, invitation ID/expiry but never its secret, activation
and onboarding receipts, exact scopes/boards/role, AI accountable-principal metadata, and
positive/negative authorization checks.
