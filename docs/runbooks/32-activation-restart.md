# 32 — Restart a pending activation

**Owner:** the issuer who verifies the person's identity — the company administrator, or
the current board secretary for a pending seat on their own board. For the first setup
administrator (nobody else exists yet) the installation operator runs the CLI mode.

**Purpose:** give a person who registered their passkey but lost their ten-minute
activation code (expired, or twenty failed confirmations) a fresh code without a new
invitation, a second identity, a replaced passkey or any activation by the restart itself.
Approved ceremony: `docs/decisions/activation-restart-proposal-2026-09-13.md`.

## When this applies

- The member is `pending_activation` with an active registered passkey.
- Their latest activation challenge is expired, or shows twenty attempts, and was never
  consumed. `list_enrollments` and the activation refusal (`next_action:
"reissue_activation"`) show this state. A challenge that is still valid cannot be
  restarted; confirm it instead.
- If nobody completed passkey registration, use runbook 31 (invitation renewal).
- If the person is already `active` and lost every passkey, use runbook 04 (recovery).

## Procedure — ordinary member (issuer's agent)

1. Read `get_member` and `list_enrollments` for the exact member; note the stale
   challenge id. Verify the person over the same trusted channel you will use for the
   code (in person or a verified-number call).
2. Call `reissue_activation` with `member_id`, `challenge_id` (the stale one) and the
   `proofing_method` the person chose when they registered (`in_person` or
   `verified_number_call`; a different method is refused). Review the confirmation form:
   member, seats, the stale challenge and its state, the proofing method. Complete the
   confirmation yourself.
3. The response carries `restart_link` once (`secret_once: true`). Hand it to the person
   through the trusted channel within ten minutes. BoardAgent keeps only its hash.
4. The person opens the link, checks the organization and their name, and proves it is
   them with the passkey they already registered. The page then shows a new activation
   reference and code; both last ten minutes.
5. They give you the reference and code over the trusted channel. Complete
   `confirm_enrollment_activation` with the new `challenge_id` and code exactly as in
   runbook 03. Onboarding and scopes follow unchanged.

## Procedure — first setup administrator (operator)

1. Confirm with `inspect-pilot-state` that exactly one person exists, is
   `pending_activation`, and has a registered passkey; `renew-first-invitation` refuses
   this state by design.
2. Prepare an owner-only regular JSON file outside the repository with the exact
   installation values (no secret):

   ```json
   {
     "instanceId": "…",
     "organizationId": "…",
     "memberId": "…",
     "canonicalResourceUri": "https://your-host.example/mcp",
     "proofingMethod": "in_person",
     "reason": "The first activation code expired before the operator could confirm it"
   }
   ```

3. Run, with `umask 077` and output redirected to a new private file:

   ```sh
   docker compose -f compose.yaml -f compose.production.yaml \
     --profile operator run --rm -T operator \
     bootstrap reissue-first-activation /operator-input/restart-first.json
   ```

   Require exit 0, `status: restart_issued`, `secretOnce: true`, `grantId`,
   `staleChallengeId` and `expiresAt`. The `restartUrl` is the one-use link; hand it to
   the person now and never keep it in a ticket or shell history.

4. The person completes the restart page as above; then run `bootstrap activate-first`
   with the fresh code exactly as runbook 02 describes.

## Refusals you will see

Active, invited, suspended or removed members; a member without a passkey; a challenge
still valid or already consumed; a second live restart for the same person; the person
issuing their own restart; a secretary of another board; a link older than ten minutes
or already used; an assertion with a different passkey. None of these change any record.

## Evidence

Record the member id, the stale and fresh challenge ids, the grant id, the issuer, the
proofing method and the audit events `activation_restart_issued` and
`activation_restart_completed`, then the ordinary `member_activated` event. Never record
the link or the code. A restart that never completes leaves a consumed-or-expired grant
and a `revoked` stale challenge; issue another restart only after verifying the person
again.
