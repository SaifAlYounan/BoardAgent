# Company administrator manual

You administer people and organization-level authority through your own connected
agent. This is an application role: it gives no VPS login, database password or
automatic board vote. The technical operator installs and maintains the service.
Use the [user manual](../MANUAL.md) for ordinary connection and confirmation steps.

BoardAgent is an open-source beta for use with synthetic data. Verify the installed
release before using a procedure. The [Mining Exploration Co pack](../../demo/mining-exploration-co)
is a synthetic example with one nonvoting secretary and three equal-weight board
members, plus a separate setup administrator. Its files do not prove that an instance,
enrolled person or accepted act exists.

## Before the first account

The technical operator follows [DEPLOY.md](../../DEPLOY.md), records the exact
release/images, initializes the database and uses the one-use
[bootstrap procedure](../runbooks/02-bootstrap.md). Production initialization uses
the operator principal, not the server's runtime credential. The operator supplies
the exact HTTPS origin and privately hands over the first enrollment invitation.

The bootstrap input fields are named `firstSecretary*` for historical reasons. The initial
setup person has the roles/seat created by bootstrap; this is not the final
ordinary-secretary account. Inspect the returned records rather than interpreting
the field name as the desired long-term role arrangement.

You register your own passkey in the browser, complete identity proof with the
operator and supply the private activation code through the agreed verified route.
The operator uses `bootstrap activate-first`; that exception activates only the
initial account. It does not accept onboarding, enroll directors or grant permission
for later recovery. An expired untouched first invitation uses the
[supported renewal procedure](../runbooks/31-expired-first-invitation.md), not another
bootstrap or a database reset.

Arrange the operator's identity-proof handoff before registering the first passkey:
activation must finish within ten minutes. If your code expires or is exhausted after
the passkey is registered, the operator runs `bootstrap reissue-first-activation` and
hands you a one-use restart link: you prove it is you with the passkey you already
registered and receive a fresh ten-minute code for the operator to confirm. Keep the
setup; never register a second identity. See [runbook 32](../runbooks/32-activation-restart.md).

Connect your own MCP client to the supplied `/mcp` resource and log in; until your
onboarding is current the server issues an `onboarding:read` token only. Ask the agent
to show `whoami`, your boards and current terms/support details. Complete your
browser/passkey onboarding attestation; the next token refresh or reconnect carries the
ordinary scopes appropriate to your role. A scope alone grants no administrator assignment.

## Establish the intended people and seats

Ask your agent:

> Show my administrative access and the current people and seats on this board.
> Prepare separate accounts for the appointed secretary and each director. Show
> their roles, weights and appointment evidence before any confirmation. Do not
> share my connection or give anyone infrastructure access.

Use `list_administrative_access` in its own-access mode first. An effective company
administrator may use `mode: organization` for the authorized organization view.
Read `list_members`, the board and the appointments before `manage_member`.

1. Register the appointed ordinary secretary and directors as separate human
   identities using `manage_member`. Every mutation has its own exact confirmation.
2. Issue a separate one-use enrollment for each person through `issue_enrollment`.
   Transfer it through the private route; BoardAgent sends no invitation email.
3. Each person registers their own passkey. The authorized issuer verifies identity
   and uses the person's private activation reference/code in
   `confirm_enrollment_activation` within ten minutes. Arrange that handoff before
   registration. Registration alone is not activation.
4. Each activated person connects their own client, completes onboarding and obtains
   ordinary role scopes. Do not reuse your OAuth connection for these trials.
5. Appoint the ordinary secretary using `manage_member` with
   `change.operation: change_seat` and `is_secretary: true` for the exact board.
   A nonvoting secretary uses a management seat with zero voting weight and also
   holds that seat's management authority. Confirm that this matches the appointment.
6. If the governing documents appoint a chair, confirm that appointment through the
   member-management seat change before ratifying the governance profile. Only a company
   administrator may explicitly appoint or remove a chair. The chair must have a voting
   seat; end an overlapping chair appointment before assigning another person. Ask the
   agent to show the resulting membership version against the appointment evidence.
7. Reconnect anyone whose authority changed. Verify their `whoami`, board visibility,
   current onboarding and effective rights before ordinary work.

The final voting electorate must contain only the intended directors and weights.
Once the ordinary secretary is working, end the setup person's extra board seat
through a confirmed `manage_member` removal for that `board_id`, retaining their
company-admin assignment if intended. Board-seat removal, person suspension and
company-admin revocation are different operations. Check the resulting records.
The [member handoff runbook](../runbooks/03-members-and-ai-observers.md) gives the
full ceremony and refusal cases.

Inspect progress through `list_enrollments`; it never supplies a lost activation
code. When a pending person's code expires or twenty confirmations fail, confirm
`reissue_activation` for that member and stale challenge and hand them the one-use
restart link; they re-prove with their existing passkey and you confirm the fresh
code. Never instruct the person to repeat registration or create a duplicate
identity. Identity recovery's replacement passkey stays reserved for active people.

## Delegate only the work the secretary needs

If the secretary must register ordinary directors, use
`manage_member_admin_delegation` to grant one exact board, an expiry of at most
90 days, a reason and readable immutable appointment citations. Confirm the
package, then have the secretary reconnect and verify their grant.

This delegation cannot grant company administration, administer the holder's own
seat, appoint another secretary or explicitly change the chair, cross boards,
manage privileged/observer/AI seats,
suspend a person organization-wide or create further delegations. For those
operations the appropriate administrator must act. Revocation, expiry or loss of
secretary authority ends the grant; restoring the title does not revive it.

## Configure the charter and governing rules

Ask your agent:

> Read this reviewed charter and the appointments. For every proposed setting,
> show the source clause, document version and hash. Identify missing or ambiguous
> rules before proposing the profile and ruleset. Wait for my exact confirmation.

Supply canonical Markdown/text or supported versioned JSON. BoardAgent rejects
PDF/DOCX uploads and does not interpret the charter with AI. Review any external
conversion against the original. Uploading a charter never grants account authority.

Read `get_board_governance_profile`, `get_ruleset`, `list_ruleset_versions`,
`list_approval_rule_templates` and `list_matter_types`. Compare the proposed
electorate, weights, quorum, thresholds, abstentions, tie handling, proxy rules,
notice periods and close modes against cited authority. Do not infer missing
rules from the example company's charter or invent a legal default.

Use `configure-ruleset` and `validate_ruleset_draft`; validation does not activate
anything or certify the interpretation. Rehearse boundary matters through
`evaluate_matter`, then confirm the authorized profile/ruleset changes. Refetch
the resulting versions and citations. If the source cannot be represented by
the supported model, record the gap and stop that configuration. See
[rules and profiles](../runbooks/15-rulesets-governance-profile.md).

For an additional board, `create_board` creates no automatic administrator seat.
Initialize its first support version before taking a seat yourself; subsequent
support updates belong to its secretary. The company administrator publishes
organization-wide role terms with `publish_onboarding_terms`. Every affected
person accepts the resulting current versions themselves. Follow
[terms and support](../runbooks/30-onboarding-terms-and-support.md).

## Authority changes and succession

Before suspending/removing a member, inspect their current seats, administrative
assignments, proxies and outstanding work. `board_id: null` in the appropriate
member lifecycle action addresses the person organization-wide; a board ID
addresses that seat. Reactivating a removed person does not restore ended seats.
Authority changes invalidate affected connections, so refetch through a fresh
login. Keep historical votes, signatures and records; do not reuse the old identity.

If you are recused from a vote, administrator status does not let you lift that
recusal yourself. Another currently eligible secretary or administrator with
authority for that vote must review and confirm `manage_recusal`. Refetch after
the lift; old ballots, proxies and pending confirmations are not restored.

For administrator succession, use `manage_company_admin` to propose a grant or
transfer to one named eligible person. That person discovers the offer through
their own account and personally accepts before its deadline. A pending offer
confers no powers; a completed transfer grants the recipient and ends the
transferor's assignment together. Record the actual before/after state and
reconnect affected clients. The last effective human administrator is protected.

External identity linking and client restrictions require their designated
administrator tools. Do not match an OIDC identity by display name or email alone;
use the exact verified issuer/subject and the supported identity procedure.

## Export and retain organization records

For an authorized system export, agree the exact scope, recipient, destination and
key custodian with the operator before `export_system_data`. Personally confirm
that package, then inspect `get_export_status` until the artifact is ready. The
client must retrieve all `read_export_chunk` chunks and verify the declared length
and hash; a queued request or one downloaded chunk is not a completed export.
Use the [system export procedure](../runbooks/20-system-export.md) for encrypted
custody and isolated verification. Keep keys out of agent chats and export receipts.

Use `cancel_export` for an eligible pending request. `delete_export_artifact`
removes the temporary export artifact after custody is confirmed; it does not erase
board records. Read `get_retention_policy` before making any deletion commitment.
For scoped audit evidence, follow the separate
[audit verification procedure](../runbooks/19-audit-certificate-export-verification.md).

## Keep the installation maintainable

The technical operator owns these procedures and their private inputs. Your
application account does not run them:

| Need                         | Procedure and required outcome                                                                                                                                                              |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Install locally or on a VPS  | [DEPLOY.md](../../DEPLOY.md): exact topology, images, configuration, separate principals, first account and readiness.                                                                      |
| Upgrade                      | [Migration/upgrade runbook](../runbooks/23-migrations-upgrade-rollback.md): exact candidate evidence, backup, isolated rehearsal and preserving update; inspect actual version afterward.   |
| Backup or restore            | [Recovery runbook](../runbooks/22-backup-pitr-restore.md): encrypted data/WAL, protected key custody and a verified isolated restore; a copied file alone is insufficient.                  |
| Lost authenticator or access | [Identity recovery](../runbooks/04-identity-recovery.md): verified people, exact credential/session effects and the person's fresh ceremony.                                                |
| Service or signing failure   | [Outage](../runbooks/24-outage-capacity.md) and [audit recovery](../runbooks/29-audit-signing-recovery.md): preserve the failure, restore current service and disclose any missed interval. |
| Suspected compromise         | [Security policy](../../SECURITY.md) and [incident runbook](../runbooks/26-incident-response.md): private reporting and preserved evidence.                                                 |

Before handover, record the named operator/security contacts and actual accepted
custody of backups and recovery keys. Verify a normal secretary workflow and
each director's separate connection. Automated synthetic results are separate
from the real people's first login, review and acceptance.
