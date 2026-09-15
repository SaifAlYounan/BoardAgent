# ADR 0008: Governance state and human confirmation

- Status: accepted at Gate 2
- Date: 2026-08-28
- Authority: D2-030 through D2-040, D2-062 through D2-069

## Context

Votes, rules, meetings, minutes, management questions, and tasks need exact lineage. Agent
convenience cannot permit ambiguous rules, in-place source changes, carried assent, or
machine-supplied human confirmation.

## Decision

- Admin activates cited immutable governance profiles; the deterministic rules engine uses
  typed facts, priority/specificity, and fails on missing/no/ambiguous matches (D2-030–031).
- Vote open freezes resolution, electorate, positive integer weights, profile/ruleset,
  close mode, and one BigInt tally kernel (D2-032).
- Live recusal invalidates stages/ballots/proxies and recomputes eligibility; lifting it
  never restores an old act (D2-033).
- An open package never changes in place. Material resolution/source/rule/deadline change
  atomically supersedes it with a linked new vote and carries no acts (D2-034).
- Proxies cannot chain/cycle; eligibility and precedence are frozen per vote (D2-035).
- Every post-onboarding H act uses modern two-round MCP form elicitation: exact headers,
  capability, stage, canonical confirmation lines, protected request state, byte-identical
  arguments, user-entered approve/code, fresh request ID, and final policy recheck
  (D2-036).
- The eight-character CSPRNG code has one attempt; wrong/cancel/timeout consumes or ends the
  stage without an act. One active stage per actor/target has a 10-minute TTL; legacy
  clients cannot list or invoke H tools (D2-037–038).
- Vote close mode is explicit. Closing persists one outcome/certificate payload and cannot
  become `closed` until the signature is verified (D2-039).
- Meetings/minutes use immutable noticed versions, finite review/disposition, exact
  signature packages, fresh re-sign, and linked correction cycles; no waiver or final
  rewrite (D2-040).
- Member/observer management questions are permanent, assigned, due, and require a recorded
  answer; status cannot stand in for one (D2-062).
- Decision packages bind exact submissions, documents, Q&A cutoffs, resolution, rules, and
  electorate; only explicitly linked unanswered in-window questions block close (D2-063).
- New linked source/turn places an open vote on hold until exact exclusion or zero-carry
  replacement; materiality is never inferred by the server (D2-064).
- Transcript annexes are strict machine-readable versions with challenge/Q&A links; no
  media/transcription enters BoardAgent (D2-065).
- Replacement emits exact notices and revote actions only to the appropriate current
  principals; webhook is merely a contentless wake-up (D2-066).
- Minutes action items are structured, package-bound, inactive until finalization, evidence-
  reviewed, and corrected through linked cycles (D2-067).
- Comments/redlines are strict anchored JSON in published review with immutable withdrawal
  and explicit disposition (D2-068).
- Minutes signatures bind the exact full package and actor/client/origin evidence; there is
  no invented minutes certificate and observer signature is not a vote (D2-069).

## Consequences and rejected alternatives

The design adds versions, locks, re-notices, revotes, dispositions, and human friction. It
rejects free-form rules, floats, in-place vote/minutes edits, carried ballots/signatures,
proxy chains, multiple code attempts, browser-only/client-signed shortcuts, status-only
answers, automatic semantic materiality, transcript media, and extracted tasks.

Changing any act transport, tally/rule semantics, source lineage, correction model, or
signature package requires versioned evidence design, an ADR, and new attack/acceptance
coverage.

## Confirmation evidence limit clarified — 7 September 2026

Under frozen D2-037, code echo is not human-view proof. The requirement that the person
enter approval and the code is a client behavior requirement. A capable authenticated
client can technically automate a valid response; the server can verify its exact
identity/action/protocol binding but cannot independently establish human involvement.
The actual TLS/OAuth/MCP test in
`tests/protocol/administrative-client-consent.postgres.test.ts` demonstrates that limit,
alongside capability, cancellation and callback refusals. This clarifies the existing
evidence model and does not change the approved act transport or authority contract.
