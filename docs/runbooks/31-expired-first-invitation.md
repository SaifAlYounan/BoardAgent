# 31 — The first administrator's invitation expired

**Owner:** the installation operator who already holds the protected operator
credentials. A secretary or an agent with ordinary board access cannot run it.

**Purpose:** renew the expired first invitation while preserving the untouched setup.
Use this only when nobody has completed the first administrator's passkey registration,
and their initial invitation has expired. This replaces the invitation for the same
person. It preserves the organization, board, roles, keys and audit history. It does not
create or activate an account, accept terms, or reset an existing person's credentials.

## Procedure

1. Confirm that the installed, qualified image supports `bootstrap renew-first-invitation`.
   Use the read-only `inspect-pilot-state` command and the original private bootstrap
   receipt to identify the instance, organization, member and invitation. The database must
   still contain exactly one person in `invited` state, with no passkey or activation
   challenge. Opening an enrollment page without completing registration does not prevent
   renewal. If registration was completed and its code remains valid, complete first
   activation. If registration was completed and the code expired or was exhausted, use
   [runbook 32](32-activation-restart.md) (`bootstrap reissue-first-activation`) instead of
   this renewal.
2. Prepare an owner-only, regular JSON file outside the repository. Replace every example
   value with the exact IDs from that installation; never guess them. The request contains
   no secret. State the reason and the trusted method you will use to give the link to the
   same person:

   ```json
   {
     "instanceId": "<original instance UUID>",
     "organizationId": "<original organization UUID>",
     "memberId": "<first administrator UUID>",
     "previousInvitationId": "<latest expired invitation UUID>",
     "canonicalResourceUri": "https://your-host.example/mcp",
     "handoffMethod": "in-person replacement QR",
     "reason": "The first invitation expired before registration"
   }
   ```

3. Mount the input directory read-only into the operator container, as for bootstrap in
   `DEPLOY.md`. Use the installed Compose configuration and existing protected operator
   environment. Set `umask 077` before redirecting the command's output to a **new private
   file**; use shell noclobber or an exclusive file creator to avoid overwriting an earlier
   handoff. Do not run this in a recorded terminal, CI log or agent chat. The command is:

   ```sh
   docker compose -f compose.yaml -f compose.production.yaml \
     --profile operator run --rm -T operator \
     bootstrap renew-first-invitation /operator-input/renew-first.json
   ```

   The output contains the new secret link once. The deployment-specific helper should
   redirect it directly into your private handoff file. Require exit zero, `status: renewed`,
   `secretOnce: true`, the expected `previousInvitationId`, and a new `invitationId`.
   Record the displayed `invitationExpiresAt`; the replacement lasts 24 hours.

4. Give the private `enrollmentUrl` to that same person through the recorded trusted method.
   The old link is revoked. Preserve a redacted receipt and the two audit events as renewal evidence:
   `enrollment_revoked` for the predecessor and `enrollment_issued` for its replacement.
   Their details name the previous and new IDs, reason, method and instance. Do not place
   the URL or its fragment token in ordinary logs or the manual.
5. The person opens the new link, registers their own passkey, and receives a private
   activation code. Complete the proofing and `bootstrap activate-first` steps in
   [02 — Bootstrap](02-bootstrap.md), then let the person attest onboarding and connect
   their own agent. Renewal does none of those personal steps for them.

## If it refuses or the output is lost

- **The link is still live:** use the existing private handoff; renewal does not shorten or
  replace a live invitation. If that handoff was lost, inspect the state and wait for its
  recorded expiry before preparing a new request against its exact ID.
- **The person registered already:** finish activation only while the original code is
  valid. If it expired or was exhausted, preserve the setup and evidence; the first-account
  recovery extension is not implemented. Do not change database state to enable renewal.
- **The instance, member or previous ID differs:** inspect the original receipts and
  current installation. Correct the request only after identifying the discrepancy.
- **Two operators ran it:** exactly one succeeds. The other must use the successful
  operator's private handoff; it cannot replay the secret by retrying the old request.
- **The process ended without a reliable receipt:** inspect current state before retrying.
  A successful commit may already have replaced the invitation. Never reset the instance
  or run bootstrap again to recover a lost output. If the new handoff is unrecoverable,
  wait for that successor's expiry, then renew using its exact ID and a documented reason.

This narrow procedure permanently stops being available once initial registration has
completed or another person exists. It is not a general administrator recovery command.
