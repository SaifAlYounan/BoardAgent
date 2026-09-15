# ADR 0006: Identity, OAuth, and client boundary

- Status: accepted at Gate 2
- Date: 2026-08-28
- Authority: D2-008 through D2-018

## Context

BoardAgent must let people use different MCP clients without treating software branding,
email, a bearer token, or an invitation link as civil identity or board authority. It also
needs a usable self-hosted path and an optional external-identity path with identical local
authorization semantics.

## Decision

- Prefer verified Client ID Metadata Documents while retaining audited, rate-limited DCR
  for compatibility. Persist both an internal client UUID and the exact protocol client ID;
  an optional allowlist uses only those exact identifiers (D2-008).
- Use the pinned `oidc-provider` implementation with PostgreSQL state rather than a
  hand-written authorization server (D2-009).
- BoardAgent always mints its own exact-resource-bound MCP tokens. External OIDC/UAE Pass
  authenticates only; upstream tokens stay server-side (D2-010).
- Access tokens are 15-minute ES256 JWTs with persisted JTI and exact issuer/audience/
  resource/client/member/scope claims. Opaque 256-bit refresh tokens rotate on every use,
  expire at bounded idle/absolute ages, and revoke the family on reuse; DPoP is not v1
  (D2-011).
- Permit only authorization code with S256 PKCE. Codes are one-use and live 60 seconds;
  implicit, password, device, client-credentials, and plain-PKCE grants are absent (D2-012).
- Built-in enrollment starts from a precreated seat and hashed 24-hour one-use invitation,
  requires UV passkey, pending activation, and a separate 10-minute secretary-confirmed
  human code (D2-013).
- Invitation delivery is out of band; BoardAgent has no email/SMS sender and no secretary
  ever hands over an OAuth token (D2-014).
- Daily use relies on rotating refresh and direct reauthentication; the secretary returns
  only for recovery/identity/authority change. Multiple passkeys are allowed (D2-015).
- Passkeys bind exact RP/origin/challenge with required UV. TOTP is an explicit encrypted,
  throttled, replay-protected fallback; passwords are absent (D2-016).
- OIDC links only exact prelinked `(issuer, subject)` to an existing member. No email match
  or auto-provisioning; UAE Pass needs deployment-specific verification (D2-017).
- One deployment holds one organization. Observer/AI-observer identities cannot combine
  with mutating roles; their self-service and six workflow exceptions are enumerated
  closed sets (D2-018).

## Consequences and rejected alternatives

BoardAgent owns a security-critical authorization service and requires careful token,
browser, client, and key tests. Bearer theft remains useful until expiry or persisted
revocation. TOTP remains phishable and is labeled fallback. The design rejects brand-based
trust, email identity, instant self-signup, upstream bearer authority, passwords, broad
OAuth grants, and silent capability fallback.

Provider, grant, lifetime, DPoP, client identity, observer-role, or enrollment-proofing
changes require an ADR and full identity/protocol/client regression lanes.

## 2026-09-06 implementation correction — browser, refresh and own security

Migrations 084/085 correct implementation of D2-011/D2-015 and the frozen own-security
exception. They do not change grant lifetimes, roles, scopes or confirmation authority.
Browser expiration leaves a valid refresh family usable until idle/absolute expiry or
explicit revocation. Access resolution requires exact token/session/family bindings;
expired browser cookies are never renewed by refresh. Explicit revocation can close an
expired browser anchor, while authentication and cookie/time metadata remain immutable.

`whoami.recent_auth` is null unless the current bearer anchor is authenticated within
15 minutes and all token/member/client/family/browser conditions remain live. Otherwise it
contains a purpose-tagged, token/session/authentication-time-bound reference and its
expiry. This is a public evidence selector, not an authentication secret, MAC, new login,
additional privilege or standing act token. The database independently rechecks the
actual recent authentication; knowing or computing a reference alone grants nothing.
The reference uses the existing canonical opaque-input/hash representation. It never
exposes a browser cookie. Fresh reauthentication or a different token changes the reference.

The existing `revoke_my_session` tool checks this reference under the same request context
and freshly confirms one owned target. The target may be a different or older connection.
Safe own-session listing uses a bounded SECURITY DEFINER projection; raw identity-table
request access stays closed. These functions do not accept a caller-selected member ID.

Execution: OAuth provider, refresh lifetime, surface-read, identity-administration,
refresh-reuse race and upgrade-rollback integration tests. Manual tests with the actual
agent applications and fresh release-image qualification remain required.
