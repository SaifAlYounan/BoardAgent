# 07 — Token or client incident

**Owners:** security contact and deployment administrator; admin/affected member for scoped
revocation. **Purpose:** contain an exposed token, session, refresh grant, or malicious MCP
client while preserving evidence.

1. Record detection time, principal/client/session identifiers, suspected window, and
   source without copying the secret itself.
2. If one session is affected, have the member inspect `list_my_sessions` and use
   `revoke_my_session`. If a client is affected, admin reads `list_oauth_clients` and uses
   `block_oauth_client`. If identity/authenticator compromise is possible, use the identity
   recovery runbook.
3. Verify access and refresh using the revoked state fail immediately, including a token
   that has not reached its nominal expiry. Check other organizations/boards cannot be
   probed through changed resource or audience values.
4. Preserve audit, HTTP-security, client, and session receipts for the exposure window.
   Review binding acts and durable writes by canonical actor/client/token identifiers.
5. Replace affected client configuration or credentials; do not unblock until the exact
   version passes client-registration checks.
6. Notify governance owners of potentially affected acts without disclosing protected
   content to unauthorized people.

Escalate to the full incident/key-compromise runbooks if signing keys, host, database, or
multiple principals may be affected. Record containment time, revoked objects, denied
verification, reviewed acts, corrective action, and residual uncertainty.
