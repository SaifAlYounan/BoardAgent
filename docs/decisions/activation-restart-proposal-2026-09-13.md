# Pending-activation restart — approved proposal (checkpoint A)

This record restates, in formal terms, a project-owner instruction originally given
privately. Original SHA-256:
ea5d40247287f4da54b2195794dc1b926a4a0effb2d452d4bb71410ea9e0238d. The project owner
approved this restatement on 16 September 2026.

Status: **approved by the project owner on 13 September 2026** as written. Drafted the
same day by an AI coding agent under the plan the project owner approved; implementation
follows this record exactly.

## The authorization this proposal rests on

In the 13 September plan review, the builder requested authority to design an
activation-restart ceremony, noting that it touches the frozen bootstrap rules under
`planning/` and would be written as an amendment proposal for approval before
implementation, as earlier amendments were handled. The project owner granted that
authority.

That grant covers **design and proposal**. Implementation followed only the project
owner's approval of this document (checkpoint A). This record is the owner's instruction
and the builder's interpretation, not a fabricated signature or an independent review.

## The gap being closed

A person registers a passkey from their one-use enrollment link and receives a private
activation code that lasts ten minutes and allows twenty attempts. If that code expires or
is exhausted, nothing in the product can continue: `confirm_enrollment_activation` and
`bootstrap activate-first` require an issued, unexpired challenge; `issue_enrollment`
serves only `invited` members; `renew-first-invitation` serves only an untouched
invitation; identity recovery serves only active people. The member stays
`pending_activation` forever with a registered passkey and no way in
(`docs/KNOWN_LIMITATIONS.md`, activation rows; `ordinary-activation-review/REPORT.md`).

The frozen authority defines no restart: the challenge machine is
`issued → consumed | expired | revoked`, "terminal corrections use a new linked object"
(DATA-STATE-TRANSACTIONS 232, 244), and D2-013 requires "an expiring 10-minute human
code plus fresh secretary confirmation … before any grant". A restart is therefore a new
capability under a recorded amendment, not a repair.

## The ceremony (what changes for the people involved)

1. **The issuer asks for a restart.** The company administrator, or the current board
   secretary for a pending seat on their board, calls the new human-confirmed tool
   `reissue_activation` for the exact member, stating the proofing method they will use.
   The confirmation form shows the member, the stale challenge and the method. For the
   first setup administrator there is no issuer yet, so the operator runs
   `bootstrap reissue-first-activation REQUEST.json` from the release checkout, exactly
   like the existing `renew-first-invitation`.
2. **The server issues a one-use restart handoff.** It marks the stale challenge
   `revoked` (reason `restart`), records an `activation_restart_grants` row bound to the
   member, the issuer, the method and that challenge, and returns a one-use link
   `https://<origin>/enroll/restart#<token>` valid for ten minutes. The link is returned
   once in structured content only, exactly as `issue_enrollment` does. The invitation
   stays consumed; no new invitation is created.
3. **The person proves it is still them.** They open the link and complete a
   user-verified WebAuthn **assertion with the passkey they already registered**. No new
   passkey is registered and the old one is not replaced.
4. **The server issues a fresh code.** On a valid assertion it inserts a **new**
   activation challenge (`issued`, ten minutes, attempt count zero, same proofing method),
   marks the handoff `consumed`, and the page shows the new activation reference and code
   in the same way the enrollment page does.
5. **Activation proceeds exactly as today.** The person gives the reference and code to
   the issuer over the verified channel; the issuer completes
   `confirm_enrollment_activation` (or the operator runs `bootstrap activate-first`).
   Nothing downstream changes: onboarding, scopes and seats are untouched.

## What is preserved (the frozen rules the design keeps)

- Ten-minute code, twenty attempts, one use, fresh issuer confirmation before any grant
  (D2-013). The restart never activates anyone by itself.
- Fresh human proof: a user-verified assertion with the registered passkey is required to
  mint the new code; possession of the link alone mints nothing (matrix row 235: "never
  approves link possession alone").
- Challenge state machine unchanged: the stale challenge ends `revoked`; the fresh code
  is a new linked object. Append-only history: no row is deleted or rewritten.
- Role separation: the issuer must hold the same authority `issue_enrollment` requires
  for that member; the person cannot issue their own restart; the operator CLI serves
  only the singleton first administrator, as the renewal CLI does.
- No password, no administrator recovery alternative, no passkey replacement (that stays
  the active-person recovery ceremony in SQL 0096).

## Refusals the tests will prove

Valid restart and activation; old code refused after restart; restart link replayed;
restart link expired (ten minutes); wrong issuer (another board's secretary, an
observer, the person themselves); assertion with a different passkey; member `active`,
`invited`, `suspended` or `removed`; a member whose current challenge is still valid
(no restart while a live code exists); expired invitation never revived; attempt
limits on the new code; audit rows `activation_restart_issued` and
`activation_restart_completed` with the linked challenge ids; first-administrator
CLI path with its receipt and refusal cases.

## Registry amendment (additive)

- Tool `reissue_activation` — class H, section "Identity and onboarding".
- Events `activation_restart_issued`, `activation_restart_completed`.
- Counts: tools 153 → 154, human-confirmed tools 65 → 66, events 139 → 141. No new
  resource, prompt, HTTP authority family, CLI row, security requirement, threat or
  acceptance scenario; evidence lands under SR-021 and SR-102 in `docs/VERIFICATION.md`.
- Mechanism: `docs/decisions/activation-restart-amendment-v1.json` pinned in
  `lib/contracts/src/registry/amendment.ts` and composed by
  `scripts/src/compose-activation-amendment.ts`, ordered after the onboarding amendment.
  Frozen `planning/` bytes and the three earlier amendments are untouched.

## Implementation footprint (after approval)

Migration 0170: table `activation_restart_grants`; functions
`boardagent_issue_activation_restart`, `boardagent_prepare_activation_restart`,
`boardagent_complete_activation_restart` (the second legitimate challenge insert site
besides SQL 0048). Server: `enrollment-browser.ts` routes `/enroll/restart` and
`/enroll/restart/passkey/{begin,complete}`; `surface-service.ts` tool
`reissue_activation`; `scripts/src/{operator,bootstrap}.ts` mode
`reissue-first-activation`; the wrong `next_action: "reissue_enrollment"` hint becomes
`reissue_activation`. Runbook 33, KNOWN_LIMITATIONS, runbooks 02/03/31, manuals and the
agent guide updated. Tests as listed above.

## Decision

The project owner approved this ceremony as written on 13 September 2026, and
implementation proceeded on that approval.
