# ADR 0011: Onboarding-narrowed token issuance and spec-compatible form elicitation

- Status: accepted for the private hardened beta
- Date: 2026-09-13
- Authority: D2-013 (pending activation and confirmed onboarding), D2-023 (scopes are
  ceilings, rechecked per request); ADR 0006 reconsideration trigger for grant/lifetime
  changes; the project owner's 13 September plan approval (client acceptance with Claude Code).

## Context

No real MCP client had ever authenticated to BoardAgent. Inspection of Claude Code 2.1.270
(the first client) showed two behaviours the server refused:

1. It requests the scopes advertised in the protected-resource metadata (all fifteen) and
   offers no way to pin the first login to `onboarding:read`. The token endpoint refused
   any ordinary scope before onboarding with `invalid_grant`, so a new person could never
   reach `get_onboarding` from that client.
2. It declares its elicitation capability as the empty object `elicitation: {}`. The MCP
   capability rules make the empty object the backwards-compatible form-mode declaration
   (the reference SDK's `getSupportedElicitationModes` does the same); BoardAgent required
   an explicit `form` key and refused every binding act with `-32021`.

The frozen rules that matter are unchanged: ordinary scopes are never usable before the
person attests current onboarding, and no binding act is staged for a client that cannot
present the confirmation form.

## Decision

- **Token issuance narrows instead of refusing.** When a member's onboarding is not
  current on every active board, the authorization-code and refresh grants issue an
  access token whose scope is exactly `onboarding:read` (RFC 6749 §3.3; the token
  response's `scope` states it). A request that carries no `onboarding:read` at all still
  refuses with `invalid_grant`. The refresh family records the granted scope set
  (`refresh_families.granted_scope_set`, migration 0169) so the next refresh after
  attestation widens the token to the granted set without a new browser login. The
  authorization request, consent, code and family keep their exact granted scopes; only
  the issued access token is bounded, and the `token_issued` / `token_refreshed` audit
  events record `grantedScopes` and `onboardingNarrowed`. Per-request authorization
  (D2-023) is untouched.
- **Form elicitation follows the capability rules.** A declared `elicitation` object
  supports form mode when it names `form`, or when it names neither `form` nor `url`.
  A client that declares only `url`, or no `elicitation` at all, is still refused before
  any stage is created (`-32021`, and the database-layer capability schema). One
  predicate (`supportsFormElicitation`) serves the HTTP pre-dispatch guard and the tool
  handlers; the consent transaction schema applies the same rule.

## Consequences

- A person may add BoardAgent to Claude Code once, log in with their normal scopes,
  complete onboarding, and gain their ordinary scopes on the next refresh (at most
  fifteen minutes) or on any reconnect. Documentation drops the "request only
  `onboarding:read` first" instruction and states the narrowing behaviour instead.
- `tests/protocol/secretary-handoff.postgres.test.ts` proves narrowing, refusal without
  `onboarding:read`, and refresh widening; `tests/protocol/protocol-downgrade.spec.ts`,
  `tests/unit/client-capabilities.test.ts` and
  `tests/integration/consent-transactions.postgres.test.ts` prove the capability rule.
- Reconsider if a client is found that reads the requested scope back from its own
  request instead of the token response, or if the MCP capability rules change the
  meaning of the empty elicitation object.
