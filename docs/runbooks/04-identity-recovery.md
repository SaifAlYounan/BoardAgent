# 04 — Identity recovery

**Owners:** secretariat/admin plus the affected person; security contact if compromise is
suspected. **Purpose:** replace or restore credentials without silently preserving attacker
access.

1. Open an incident if loss, theft, phishing, or token exposure is possible. Record the
   identity-proof method without storing unnecessary personal evidence.
2. Read `get_member`, `list_my_sessions` where the person can participate, active clients,
   external identity links, pending enrollments, and current authority.
3. Decide explicitly whether to revoke every passkey/TOTP credential or preserve exact
   named credentials that the person still controls. `preserve_named` requires their
   nonsecret internal credential IDs. An existing organization admin or organization
   secretariat with `secretariat:admin` obtains these from
   `get_member(member_id).data.member.recovery_credentials.items`. Select the exact
   `credential_record_id` values after independently verifying what the person controls.
   This metadata contains type, state and timestamps, never key material or secrets.
   An ordinary board secretary or delegated member administrator cannot read this
   inventory or perform identity recovery through delegation alone. If `complete` is
   false, the inventory exceeds the 128-record bound: do not guess missing credentials
   or treat this partial list as exhaustive. `preserve_named` accepts at most 32 IDs.
   The recovery action revokes the person's browser/access/refresh connections in either
   mode. It disables all unselected active authenticator-app (TOTP) credentials and all
   unfinished TOTP enrollments. A selected active TOTP keeps its existing replay counter
   and temporary lockout; recovery does not clear a lock. Client blocking and external-link
   removal are separate confirmed actions.
4. Call `initiate_identity_recovery` with the reviewed package and complete human
   confirmation.
5. Require the safe `state: initiated` receipt and the new identity generation. With
   a known retained passkey, the person starts a fresh OAuth login themselves. A linked
   identity remains a separate configured path subject to its current checks.
6. For another active human, `in_person` or `verified_number_call` proof also returns
   `replacement_enrollment.url` and its exact expiry. Deliver that one-use handoff
   through the separately trusted channel. It expires after ten minutes. Only its hash
   is stored. The URL secret is in a fragment, which the browser removes immediately.
   If the tool response is lost, start a new confirmed recovery; the old handoff cannot
   be retrieved or replayed. A new recovery invalidates the previous generation's grant.
7. The person opens `/recover`, checks their organization and name, then creates their
   replacement passkey. Registration requires user verification and the exact RP,
   origin and recovery challenge. This creates a **pending candidate**, not a credential
   that can sign in. No account, seat, role or onboarding status is changed.
8. The browser displays a ten-minute human code plus member, recovery and challenge
   references. Obtain those directly from the verified person, in person or through
   their verified phone number. The original recovery issuer invokes
   `confirm_enrollment_activation` using the displayed member ID, recovery reference
   as `invitation_id`, challenge reference as `challenge_id`, human code, same proofing
   method and a new idempotency key. Review and freshly confirm the exact replacement
   credential shown in the form. Link possession alone is insufficient.
9. A successful confirmation returns `activated: true`, zero onboarding tasks and
   `next_action: fresh_sign_in`. The person returns to their agent and starts a fresh
   OAuth login. The same account retains its history and current roles. Wrong codes
   consume a twenty-attempt budget. Cancellation, expiry or lost issuer/target authority
   cannot activate a candidate. After expiry or lockout, begin a newly confirmed recovery.
10. Verify old connections fail, the preserved or replacement credential authenticates,
    onboarding is current and `whoami` returns the same member and correct authority.
    Pending administrator offers issued before the recovered identity generation cannot
    be accepted afterward; make still-needed appointments as fresh confirmed offers.
11. Review actions performed during the exposure window and escalate anomalies.

Self-recovery remains containment or retained-credential recovery: it issues no replacement
handoff. Other proof descriptions also issue none. Replacement activation requires the
original issuer's continuing organization admin/secretariat authority, active human
eligibility and unchanged identity generation. A delegated board secretary cannot use
delegation to recover identities. The server database role cannot directly insert a
passkey; initial enrollment and confirmed recovery use their bounded functions.

Do not match identity by email alone, auto-link an OIDC subject, disclose whether an
unknown person exists, or use direct database updates. Record recovery ID, proof category,
revocation set, activation receipt, verification outcomes and incident link. Keep raw
handoffs and human codes out of screenshots, shared notes, logs and audit exports.

Scripted authenticators and browser tests do not substitute for the actual person's
identity proof or a manual trial.

## When every authorized human loses access

1. Open an incident and preserve the current audit, configuration and encrypted backups.
   Stop onboarding and administrative mutations until human authority is verified.
2. The deployment operator coordinates identity proof with the organization's existing
   accountable humans, using its independently held appointment and contact records.
   A database admin login, restored backup or possession of an old invitation is not
   identity proof or authorization to appoint a new company administrator.
3. Do not rerun initial activation, insert roles/credentials, reset a member's state, or
   revive old tokens. Initial bootstrap refuses an already initialized identity. No
   hidden emergency-promotion endpoint is provided.
4. Record the verified person, exact affected identity, approved recovery procedure and
   evidence before executing a supported recovery path. If no such path exists for the
   loss scenario, keep the service in incident status while that path is specified and
   verified. A restore can recover data; it cannot authenticate the replacement human.
