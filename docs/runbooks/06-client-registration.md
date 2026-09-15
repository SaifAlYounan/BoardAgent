# 06 — Client registration and allowlisting

**Owner:** deployment administrator; admin for block/unblock. **Purpose:** admit exact MCP
clients without trusting a self-asserted product name.

Allowlisting a metadata URL does not establish that the metadata transport checks
(requirement SR-013 in the [verification register](../VERIFICATION.md)) have passed for
your deployment's network; see [known limitations](../KNOWN_LIMITATIONS.md).

1. Identify whether the client uses a server-issued client ID or a Client ID Metadata
   Document URL. Inspect exact redirect URIs, authentication method, grant behavior, and
   protocol/form-elicitation capability.
2. For metadata documents, require HTTPS, bounded fetch, cryptographic verification, and
   the runtime's redirect/SSRF rules. A logo, domain label, or vendor assertion is not proof.
3. Test read-only behavior, modern protocol negotiation, one H-action cancellation, exact
   form rendering, byte-identical retry, token refresh, session revocation, and absence of
   auto-approval with a synthetic account.
4. If using `BOARDAGENT_CLIENT_ALLOWLIST`, enter exact IDs/verified metadata URLs separated
   by commas. Restart through the runtime runbook and verify unlisted clients fail closed.
5. Use `list_oauth_clients` to inspect persisted state. Use `block_oauth_client` or
   `unblock_oauth_client` only with exact target and human confirmation.

## Evidence

Record client ID/metadata digest, version, redirect set, test results, allowlist change,
block state, and responsible owner. Any client that hides confirmation lines, submits the
person's answer, cannot preserve protected request state, or leaks tokens is prohibited.
