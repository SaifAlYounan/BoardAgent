# Administrative authority implementation contract — revision 1

The project owner's explicit finish instruction resumes implementation of the delivered plan.
The [actual instruction record](access-control-implementation-authorization.md) explains
its scope. The [machine-readable amendment](access-control-amendment-v1.json) fixes the
exact additive inventory, action fields, limits, state machines, events and SR/test map.
This is local build authority, not a manufactured deployment receipt or human consent.

## Resulting behavior

An organization administrator can propose another eligible human administrator, transfer
their own role, cancel an offer or revoke an assignment. The named recipient personally
accepts or declines. An administrator can separately give a human secretary an expiring
right to manage ordinary voting directors on exactly one board. Other secretary staff
retain their existing onboarding and routine board work. Nobody receives VPS/root rights.

Implement decisions D01–D06 with these precise implementation details:

- New tools: `manage_company_admin` (H), `manage_member_admin_delegation` (H),
  `list_administrative_access` (R). The existing `manage_member` gains only its explicitly
  bounded delegate branch and optional cited basis. Old admin inputs remain valid.
- Preserve observer exclusion, including human observers. They cannot be administrator
  recipients through this extension; no new observer H exception is introduced. Admins
  handle an actual role change separately before making an eligible offer.
- All new actions need the existing S:A ceiling and a live eligible human identity.
  Action-specific authorization lets the named non-admin recipient accept/decline only
  their own offer. It does not expose the other admin actions to them.
- Grant/transfer proposals expire after 24 hours. Each terminal transition binds exact
  proposal and identity versions. A transfer creates the new admin and ends the prior
  assignment atomically. The last active human administrator cannot be lost through any
  old or new path, including concurrent member suspension/removal.
- Delegations last at most 90 days; current secretary status on the exact board is
  required. Loss/reinstatement of secretary status cannot revive an old grant. Delegates
  cannot administer themselves, privileged identities, other boards or the organization.
- Delegate actions need 1–8 immutable readable appointment citations and a 1–2,000
  character reason. Invite gains optional `change.reason`; other actions retain their
  existing reason field. `authority_evidence` is an optional top-level field, mandatory
  for the delegate branch. Supplied citations are always validated and H-bound.
- Changing authority invalidates affected access/refresh/browser credentials, unused
  authorization codes and pending H stages. A token acquired before elevation cannot
  gain new rights silently. A completed offer requires reconnect before using new rights.
- Own administrative reads expose only own effective rights and offers. Organization
  reads require admin. Cursors bind actor, organization/board filter and generations.
  Output never reveals private cross-board roles or credentials.
- Extend the existing operator-only `bootstrap` command with an explicit first-activation
  mode if needed; bounded stdin calls the existing `activateFirstSecretary` operation.
  No extra CLI, HTTP route, governance UI, provider, egress, dependency, role or scope.

## Concrete data and transaction ownership

Append migrations 0087 onward. `organization_role_assignments` remains the source of
active admin roles. Add organization-bound admin-proposal and board-delegation tables
with immutable creation/authority lineage, exact version, expiry and terminal evidence.
Use composite organization/member/board references, FORCE RLS, narrow definer ownership
and fixed search paths. No runtime login receives direct role/proposal write authority.

Each prepare/finalize operation locks and checks the same authoritative aggregates.
Use the existing organization administrative advisory lock before board/member locks,
with stable UUID ordering across peers. Reuse that lock in all paths that can end an
administrator or secretary. Recheck effective identity, token, onboarding, grant, target,
source evidence and versions inside the commit transaction, after human confirmation.

The prepared canonical payload contains original strict arguments plus before/after
snapshots and effects. Its digest must match the exact current stage and fresh consent.
Append the matching event and idempotency record, then finalize state/history and
revocation in the same transaction. Audit failure rolls everything back. Old governance
records and signatures retain their original actor IDs and source versions.

## Registry and evidence

The original 148-tool / 128-event / SR94 / TH63 / AC22 matrix stays byte-frozen. A
hash-pinned additive composition yields **151 tools, 136 events, SR102, TH71 and AC25**.
R/direct/H counts become 58/30/63. Other counts and all original thresholds stay intact.
Only `manage_member` has a changed existing authority row. No other old row may drift.

The amendment adds SR095–102, TH64–71 and AC23–25 with exact planned paths. Their control
statements are not PROVEN until production code and executing tests support them.
AC01–AC30 in the execution worksheet are separate planning IDs; the amendment maps them
to the existing/new SRs. AC30 additionally needs the separate website's actual evidence;
a core SR reference alone does not qualify live K2.

Build checks must reject changed base bytes, changed amendment bytes, changed instruction
record, extra/duplicate/conflicting rows and unexpected resulting counts. Do not replace
original frozen counts with whatever a generated registry happens to emit.

## First private login and final release are distinct

The frozen T10 rule explicitly permits private beta without external production review.
An earlier qualified build can support the early synthetic login milestone on an exact
reviewed host configuration under the project owner's instruction to make those logins
available. This does not mark E09 (new extension qualification), E10
(independent closure), E11 (complete operational commissioning), E12 or E14 complete.

Record the actual pilot candidate/configuration and limitations separately. Bootstrap
creates a setup administrator first; the person must really enroll and prove identity.
Then register ordinary secretary and appointed directors through supported actions.
No consent, passkey, appointment, ballot, signature or manual result is synthesized.
