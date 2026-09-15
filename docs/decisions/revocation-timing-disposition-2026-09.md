# Revocation timing disposition — September 2026

Status: recorded 13 September 2026. No requirement label
or threshold changes. This note states what SR-023's "rechecked per request" means in the
running product, what is proven, and what is deliberately not claimed.

## What "per request" means

Every MCP tool call and resource read runs inside one request transaction
(`withRequestTransaction` in `lib/db/src/context.ts`). Inside it, before any surface work,
the server re-resolves the principal through `boardagent_resolve_access_token` (the
`liveActor` query in `artifacts/server/src/surface-read.ts`): the token record must be
unrevoked and unexpired, the client and the member active, and roles and board seats are
recomputed from the seats active at the transaction timestamp. A token that resolves to
nothing, or to a principal different from the one the HTTP layer authenticated, refuses.
Board-scoped reads then run under row policies keyed to that admitted context. This is
the guarantee SR-023 states.

## What happens to a request already admitted

A request admitted at time T keeps working under the authority it was admitted with until
it commits or fails. If the token is revoked or the seat ended at T+ε while that request is
still running, the in-flight request completes; the **next** request from the same token
refuses. Row-level policies inside the request use the admitted context (organization,
member, seat) rather than re-joining live membership on every statement, so a mid-request
loss of authority does not tear an admitted request in half. This is the behaviour the
Known Limitations page describes for list projections and management retries.

Why it stays this way for the beta:

- Statement-fresh re-evaluation would require every read predicate to re-join live
  membership, which is exactly the class of predicate the search and projection work
  bounded for cost reasons.
- A request runs for milliseconds; revocation is a governance act whose effect is defined
  at the next request boundary. No board record can be written by a request that was not
  admitted with the authority to write it.

## Evidence

- Next-request refusal after the seat ends or the token is revoked, with no new effects:
  `tests/integration/management-workflow.postgres.test.ts` ("refuses a completed submission
  retry after revoked_token / ended_membership without new effects").
- Exclusion effective at the next request, not the running one:
  `tests/integration/question-projection-admission.postgres.test.ts` (already-effective
  versus later-default exclusion).
- In-flight completion under the admitted context, then refusal of the next request:
  `tests/integration/revocation-in-flight.postgres.test.ts` (added 13 September 2026).

## Not claimed

- No statement-fresh or all-principal revocation timing.
- No public-token revocation timing beyond the request boundary.
- No change to any access policy; `docs/KNOWN_LIMITATIONS.md` keeps its wording.
