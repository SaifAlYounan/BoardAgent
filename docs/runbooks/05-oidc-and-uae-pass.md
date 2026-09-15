# 05 — OIDC and UAE Pass assessment

**Owners:** deployment administrator, secretariat, security contact, and the project owner for a new
provider. **Purpose:** commission pre-linked OIDC without email matching or auto-provisioning.

## Provider assessment

1. Obtain authoritative provider discovery/registration material through the deployment's
   trusted procurement/security process.
2. Verify exact issuer, authorization/token/JWKS endpoints, signing algorithms, subject
   stability, MFA/account recovery, key rotation, outage behavior, privacy terms, and
   incident route.
3. Register only the exact BoardAgent HTTPS redirect/origin required by the runtime. Store
   the client secret in its own owner-controlled file.
4. Document how the provider's immutable `(issuer, subject)` is verified for a known invited
   person. Email, name, phone, or display claims are never identity keys.
5. Test unknown subject, wrong issuer/audience/nonce/state, stale key, provider outage,
   unlink, recovery, and revoked member behavior with synthetic accounts.

## Activation

1. Keep the member precreated through `manage_member` and enrolled under the normal board
   authority process.
2. Use `link_external_identity` with exact issuer/subject and human confirmation.
3. Switch `BOARDAGENT_AUTHORIZATION_MODE` only in a controlled maintenance window, then
   verify built-in recovery remains available according to the approved plan.
4. Verify an unknown subject never creates or links a member and external tokens remain
   server-side; BoardAgent mints the resource-bound MCP token.

**UAE Pass is not pre-certified by this repository.** Treat it as a provider-specific
variant requiring the full assessment above plus applicable UAE legal/privacy review.
Record evidence and the project owner's acceptance before claiming support.
