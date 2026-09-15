# Browser key maintenance — 9 September 2026

Migration 0134 adds replacement, retirement and compromise reporting for the browser
session key. All three invalidate existing browser sessions, active refresh families,
pending or approved OAuth requests, active action approvals and active browser onboarding
stages. People sign in again with their existing passkeys. Completed attestations and
governance records are preserved. If terms changed, normal scopes still require acceptance;
the onboarding-only connection lets the person complete that ceremony.

Session records do not identify which browser key created them. Maintenance therefore
invalidates the current installation's sessions and grants, including when reporting an
older browser key compromised. It does not guess which sessions are safe. Exact replay of
a completed operation returns its original receipt and leaves subsequent logins intact.

The immutable `key_lifecycle_browser_effects` ledger identifies each affected session,
OAuth request, action stage or onboarding stage through an enforced foreign key and type
binding. Its trigger derives the complete before/after row digests under the real current
operator transaction. Existing family records cover refresh revocations. Audit, completion
and deferred commit checks require every prepared effect and its actual complete row.
Runtime roles cannot insert effects. Missing audit/completion and post-receipt row changes
roll back the operation.

The existing sixteen-group inventory is retained. `browser_action_stages` now includes
both action and onboarding stages with explicit source-type tags in its row hashes.
`cancelledStages` counts both types. Old request timestamps and completed receipts are not
rewritten. The OAuth and onboarding state guards permit early invalidation only for an
exact recorded browser-key operation in the operator transaction; ordinary application
permissions and immutable stage fields remain unchanged.

Tests in `tests/integration/browser-key-lifecycle.postgres.test.ts` cover retirement,
missing-completion rollback, complete-row integrity and denied effect writes. The deliberate
post-receipt metadata fault uses the disposable database owner; this is integrity testing,
not a claim that the system can withstand its database owner disabling its controls.

`tests/protocol/browser-key-maintenance.postgres.test.ts` exercises all three operations
through a real HTTPS application: initial passkey login, pending authorization code,
pending action/onboarding stages, protected database maintenance, application restart,
old access/code/refresh rejection, unchanged passkeys, immediate new onboarding and safe
operation replay. The shared helper uses fixture-owned private files and matching injected
key material. It is not proof of the unfinished production file installer or operator CLI.

Failing-first and intermediate failures are retained. Tests caught the previously unsupported
approved-request and early-onboarding invalidations; both received narrow operation-bound
transitions. The expanded run passed fifty tests before typecheck caught a negative-test
fixture typing error. The later broader run passed fifty-five tests, including secretary
handoff and OAuth history; three added assertions compared cancellation time to receipt
completion rather than operation time. After correcting those assertions, all nine affected
tests across three files plus typecheck/lint passed. Production bytes were unchanged during
these final runs. This is local affected proof, not full/native qualification.

Data and backup key lifecycle, protected retained files and custody, operator commands,
service fencing, deployment restart/restore and qualification remain unfinished. A separate
follow-up must check routine worker expiry of an already-approved OAuth request: the old
guard appears to refuse that worker transition too. No worker-permission change is claimed
by this migration.

Follow-up resolution: the suspected ordinary worker issue above was ruled out. SQL0074
filters pending requests and revokes expired authorization codes. The real HTTPS regression
in `tests/protocol/approved-oauth-expiry.postgres.test.ts` verifies expired-code refusal,
valid-code success and unchanged approved request rows. Two affected tests and static
checks passed; no production authority change was needed.
