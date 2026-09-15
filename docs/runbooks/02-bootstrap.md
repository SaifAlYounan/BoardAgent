# 02 — Bootstrap

**Owners:** deployment administrator and first secretary, with two-person observation.
**Purpose:** create exactly one organization, first board, first secretary, support record,
onboarding terms, runtime-key registrations, and one-use enrollment handoff.

## Prerequisites

- Approved release images and configuration; empty initialized database.
- Separate production principals and all four application-purpose keys.
- Reviewed `docs/examples/bootstrap.example.json` copied to a private regular file.
- Exact HTTPS origin, legal/display names, timezone, canonical board payload, support route,
  onboarding terms, and out-of-band invitation method.

## Procedure

1. Run the production database initializer and require the migration/principal receipt.
2. Hash and peer-review the bootstrap file. Do not include a secret token in the input.
3. Mount only that file/directory read-only into the operator container.
4. Run `operator bootstrap /operator-input/bootstrap.json` once as shown in `DEPLOY.md`.
5. Require `operatorStatus: succeeded`, `status: created`, `secretOnce: true`, and four
   runtime keys registered. A partial result is not bootstrap completion.
6. Record the returned organization/board/member IDs and canonical hashes. Insert the
   organization ID into the non-secret application environment.
7. Hand the enrollment URL/token directly to the first secretary through the declared
   method. Do not copy it into the receipt.
8. The secretary redeems it and registers their own passkey. They remain pending activation.
   Follow the operator/human steps below, then attest current onboarding and verify `whoami`
   plus the board snapshot.
9. Run bootstrap again only as an idempotency check if required by the release ceremony;
   it must report already initialized and must not return another enrollment secret.

## First activation: separate operator and human steps

Deploy only an image that has completed its own qualification. Do not mistake the
operator step for completed human enrollment.

1. **Person:** open the one-use handoff on the exact configured HTTPS origin and register
   your own passkey. Keep the resulting short activation code private. An invitation alone
   does not activate the account.
2. **Operator:** complete the declared identity proof in person or by a call to an already
   verified number. The method must match the pending ceremony. Receive the person's code
   over that trusted channel. Ordinary directors and secretaries do not receive this
   infrastructure account or database password.
3. **Operator:** supply a JSON object containing only `activationCode` and `proofingMethod`
   (`in_person` or `verified_number_call`) on standard input. The complete input is at most
   1024 UTF-8 bytes. Never put the code in command arguments, environment variables, shell
   history or a retained log. If using a temporary input file, keep it owner-only outside
   the repository and remove it after the attempt. With the configured production Compose
   environment, redirect that file directly:

   ```sh
   docker compose -f compose.yaml -f compose.production.yaml \
     --profile operator run --rm -T operator bootstrap activate-first \
     < /private/activation-input.json
   ```

   The mode verifies the exact configured HTTPS resource against this database's instance,
   assumes the migrator role and calls the existing serializable activation transaction.
   It performs no migration or direct account-state edit. Extra fields/arguments, malformed
   JSON, duplicate names, wrong origin, expired/missing ceremony and replay refuse. A wrong
   code uses the existing audited attempt limit; do not repeatedly guess.

4. **Operator:** require exit zero and a receipt with `activated: true`, `mode: activate-first`
   and `nextHumanStep: complete_onboarding`. Retain this safe receipt. A lost successful
   output does not authorize resetting or recreating the identity; inspect the activation
   record. Repeating a consumed ceremony refuses without creating another account. If the
   person's code expired or was exhausted after their passkey was registered, restart it
   with `bootstrap reissue-first-activation` ([runbook 32](32-activation-restart.md)) and
   return to step 3 with the fresh code.
5. **Person:** start/restart the agent's OAuth connection on the same HTTPS origin and use
   your passkey. Request your normal scopes; until current onboarding is complete the
   server issues only an `onboarding:read` token (the token response states the issued
   scope), and a request without `onboarding:read` refuses. Read `get_onboarding`, prepare
   the exact attestation, open its one-use link and personally attest with your passkey.
   The next token refresh or reconnect then carries the normal scopes for your role.
   Complete the current onboarding terms and support acknowledgement. The
   activation command does not accept terms, mint agent tokens or confirm governance acts
   on your behalf. The enrollment page does not automatically continue after operator
   activation; a stale pending page is not a failed activation receipt.

Use the member-administration handoff runbook for the ordinary secretary and each separate
director. Initial activation is the sole preidentity exception, not a general recovery or
director-account promotion command.

## Evidence and refusal

Preserve the input hash, operator JSON receipt with secret redacted, runtime-key IDs, first
secretary activation/attestation receipts, and synthetic read result. Refuse to repair a
wrong legal name, board payload, or initial person by database editing; use supported
governance correction or rebuild before real use.

## If the untouched first invitation expires

Use [31 — Expired first invitation](31-expired-first-invitation.md) to replace only that
expired invitation, preserving the original instance and person. Do not reset the database
or rerun bootstrap. Registration, proofing, activation and personal onboarding still follow.
